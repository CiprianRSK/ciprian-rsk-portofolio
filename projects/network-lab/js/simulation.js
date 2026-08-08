/* simulation.js — the attack engine.
   Resolves a scenario to a source/target, routes packets over the topology graph,
   evaluates firewall rules + IPS/IDS/EDR/proxy placement, animates and narrates the result. */
(function () {
  const { SCENARIOS, NODE_TYPES } = window.NET;
  const SVGNS = 'http://www.w3.org/2000/svg';

  let consoleEl, verdictEl, running = false;
  let activeScenario = null;

  /* ---------- IP / CIDR helpers ---------- */
  function ipToInt(ip) {
    const p = String(ip).split('.').map(Number);
    if (p.length !== 4 || p.some(function (x) { return isNaN(x); })) return null;
    return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
  }
  function ipInCidr(ip, cidr) {
    cidr = String(cidr).trim();
    if (cidr === 'any' || cidr === '*' || cidr === '0.0.0.0/0') return true;
    let base = cidr, bits = 32;
    if (cidr.indexOf('/') >= 0) { const s = cidr.split('/'); base = s[0]; bits = parseInt(s[1], 10); }
    const a = ipToInt(ip), b = ipToInt(base);
    if (a == null || b == null) return false;
    if (bits === 0) return true;
    const mask = (0xffffffff << (32 - bits)) >>> 0;
    return (a & mask) === (b & mask);
  }

  // parse one firewall rule line -> { action, src, dst, port } | null
  function parseRule(line) {
    line = line.replace(/#.*$/, '').trim();
    if (!line) return null;
    const m = line.match(/^(ALLOW|DENY|PERMIT|BLOCK)\s+(\S+)\s*->\s*(\S+)(?:\s*:\s*(\d+))?/i);
    if (!m) return null;
    const act = m[1].toUpperCase();
    return {
      action: (act === 'PERMIT') ? 'ALLOW' : (act === 'BLOCK') ? 'DENY' : act,
      src: m[2], dst: m[3], port: m[4] ? parseInt(m[4], 10) : null,
    };
  }
  // evaluate a firewall node -> { action:'ALLOW'|'DENY', rule:string }
  function evalFirewall(node, srcIP, dstIP, port) {
    const lines = String(node.props.rules || '').split('\n');
    for (let i = 0; i < lines.length; i++) {
      const r = parseRule(lines[i]);
      if (!r) continue;
      if (!ipInCidr(srcIP, r.src)) continue;
      if (!ipInCidr(dstIP, r.dst)) continue;
      if (r.port != null) { if (port === 0 || port !== r.port) continue; }
      return { action: r.action, rule: lines[i].replace(/#.*$/, '').trim() };
    }
    return { action: 'DENY', rule: 'implicit deny-all' };
  }

  /* ---------- graph ---------- */
  function neighbors(id) {
    const out = [];
    Lab.state.edges.forEach(function (e) {
      if (e.from === id) out.push(e.to);
      else if (e.to === id) out.push(e.from);
    });
    return out;
  }
  function findPath(fromId, toId) {
    if (fromId === toId) return [fromId];
    const q = [fromId], prev = {}; prev[fromId] = null;
    while (q.length) {
      const cur = q.shift();
      const ns = neighbors(cur);
      for (let i = 0; i < ns.length; i++) {
        if (prev[ns[i]] === undefined) {
          prev[ns[i]] = cur;
          if (ns[i] === toId) {
            const path = [toId]; let c = toId;
            while (prev[c] != null) { c = prev[c]; path.unshift(c); }
            return path;
          }
          q.push(ns[i]);
        }
      }
    }
    return null;
  }
  function hasAdjacent(nodeId, role) {
    return neighbors(nodeId).some(function (id) {
      const n = Lab.getNode(id); return n && NODE_TYPES[n.type].role === role;
    });
  }
  function nodesByRole(role) {
    return Lab.state.nodes.filter(function (n) { return NODE_TYPES[n.type].role === role; });
  }
  function reachableFrom(fromId, filter) {
    return Lab.state.nodes.filter(function (n) {
      return n.id !== fromId && filter(n) && findPath(fromId, n.id);
    });
  }

  /* ---------- console ---------- */
  function clearConsole() { consoleEl.innerHTML = ''; }
  function log(text, cls) {
    const d = document.createElement('div');
    d.className = 'line ' + (cls || 'info');
    d.textContent = text;
    consoleEl.appendChild(d);
    consoleEl.scrollTop = consoleEl.scrollHeight;
  }
  function showVerdict(blocked, msg) {
    verdictEl.className = 'verdict show ' + (blocked ? 'blocked' : 'success');
    verdictEl.textContent = (blocked ? '🛡  DEFENDED: ' : '⚠  COMPROMISED: ') + msg;
  }

  /* ---------- resolve source & target ---------- */
  function resolve(sc) {
    let source = null, srcIP = null;

    if (sc.srcKind === 'external') {
      source = nodesByRole('attacker').find(function (n) { return n.props.placement !== 'internal'; })
             || nodesByRole('attacker')[0] || nodesByRole('internet')[0];
      srcIP = source ? (source.props.ip && source.props.ip !== '0.0.0.0/0' ? source.props.ip : '203.0.113.66') : null;
    } else { // internal
      source = nodesByRole('attacker').find(function (n) { return n.props.placement === 'internal'; });
      if (!source) {
        // pick a workstation as "patient zero" (most realistic), else any host
        const hosts = Lab.state.nodes.filter(function (n) {
          return NODE_TYPES[n.type].role === 'host';
        });
        source = hosts.find(function (n) { return n.type === 'pc'; }) || hosts[0] || null;
      }
      srcIP = source ? (source.props.ip || '10.0.1.20') : null;
    }
    if (!source) return { error: sc.srcKind === 'external'
      ? 'No Attacker or Internet node on the canvas to launch from.'
      : 'No internal host (or internal Attacker) to act as the compromised origin.' };

    // target
    let target = null;
    if (sc.targetRole === 'internet') {
      target = nodesByRole('internet')[0];
      if (!target) return { error: 'No Internet/WAN node to exfiltrate to. Add one and wire your egress path.' };
      return { source, srcIP, target, dstIP: '8.8.8.8' };
    }
    if (sc.targetRole === 'dc' || sc.targetRole === 'db') {
      const cands = reachableFrom(source.id, function (n) { return NODE_TYPES[n.type].role === sc.targetRole; });
      target = cands[0] || nodesByRole(sc.targetRole)[0];
      if (!target) return { error: 'No ' + (sc.targetRole === 'dc' ? 'Domain Controller' : 'Database') + ' on the canvas.' };
    } else { // any-host
      const cands = reachableFrom(source.id, function (n) {
        const r = NODE_TYPES[n.type].role;
        if (!['host', 'db', 'dc'].includes(r)) return false;
        if (sc.needsOpenPort) return (n.props.ports || []).includes(sc.port);
        return true;
      });
      // prefer a host that actually exposes something interesting
      target = cands[0] || reachableFrom(source.id, function (n) {
        return ['host', 'db', 'dc'].includes(NODE_TYPES[n.type].role);
      })[0];
      if (!target) return { error: 'No reachable target host for this scenario. Wire the attacker to the network.' };
    }
    return { source, srcIP, target, dstIP: target.props.ip || '10.0.0.10' };
  }

  /* ---------- segmentation ---------- */
  // the (most specific) zone a node's centre falls inside, or null
  function segmentOf(node) {
    const zs = Lab.state.zones.filter(function (z) {
      const cx = node.x + node.w / 2, cy = node.y + node.h / 2;
      return cx >= z.x && cx <= z.x + z.w && cy >= z.y && cy <= z.y + z.h;
    });
    if (!zs.length) return null;
    zs.sort(function (a, b) { return (a.w * a.h) - (b.w * b.h); });
    return zs[0];
  }

  function finalize(path, dropIndex, blocked, reason, events) {
    return { path: path, dropIndex: dropIndex, blocked: blocked, reason: reason, events: events };
  }

  // host-based controls on the target (micro-seg host firewall, then EDR)
  function targetHostControls(sc, r, path) {
    const last = path.length - 1;
    if (sc.direction !== 'egress' && r.target.props.hostFirewall) {
      return { idx: last, reason: 'Host-based firewall / micro-segmentation on the target denied the inbound connection.',
        events: [{ idx: last, text: '[Host FW] inbound' + (sc.port ? ' :' + sc.port : '') +
          ' denied by host firewall / micro-seg on ' + r.dstIP, cls: 'drop' }] };
    }
    if (sc.endpointDetectable && hasAdjacent(r.target.id, 'edr')) {
      return { idx: last, reason: 'EDR on the target host stopped the intrusion.',
        events: [{ idx: last, text: '[EDR] endpoint agent on ' + r.dstIP + ' blocked the intrusion', cls: 'drop' }] };
    }
    return null;
  }

  // volumetric DDoS is an availability attack — different logic: on-prem firewall/IPS can't help,
  // only upstream scrubbing / CDN absorbs the flood before it saturates your link.
  function decideDDoS(sc, r) {
    const path = findPath(r.source.id, r.target.id);
    if (!path) {
      return finalize(null, -1, true, 'Target is not publicly reachable — there is no exposed path to flood.', []);
    }
    const events = [];
    for (let i = 0; i < path.length; i++) {
      const role = NODE_TYPES[Lab.getNode(path[i]).type].role;
      if (role === 'scrubbing') {
        events.push({ idx: i, text: '[SCRUBBING] volumetric flood absorbed upstream (CDN / anti-DDoS) → only clean traffic forwarded', cls: 'drop' });
        return finalize(path, i, true, 'Flood absorbed by upstream DDoS scrubbing / CDN before it reached your link.', events);
      }
      if (role === 'firewall' || role === 'ips') {
        events.push({ idx: i, text: '[' + (role === 'ips' ? 'IPS' : 'FW') + '] link saturated by the flood — an on-prem device cannot mitigate a volumetric DDoS', cls: 'warn' });
      }
    }
    return finalize(path, path.length - 1, false,
      'Service overwhelmed — the target is knocked offline. Volumetric DDoS must be mitigated UPSTREAM (CDN / scrubbing), not at your firewall.', events);
  }

  /* ---------- decide the outcome along the path ---------- */
  function decide(sc, r) {
    if (sc.ddos) return decideDDoS(sc, r);
    const path = findPath(r.source.id, r.target.id);
    const srcSeg = segmentOf(r.source), tgtSeg = segmentOf(r.target);
    const sameSeg = !!(srcSeg && tgtSeg && srcSeg.id === tgtSeg.id);

    // truly unreachable (different segments, no wired route)
    if (!path && !sameSeg) {
      return finalize(null, -1, true,
        'No route to target — segmentation leaves the packet nowhere to go.', []);
    }
    const animPath = path || [r.source.id, r.target.id];
    const events = [];

    // 0) target must expose the port (port-based scenarios)
    if (sc.needsOpenPort && NODE_TYPES[r.target.type].role !== 'internet') {
      const ports = r.target.props.ports || [];
      if (!ports.includes(sc.port)) {
        return finalize(animPath, animPath.length - 1, true,
          'Target is not listening on port ' + sc.port + ' — connection refused.',
          [{ idx: animPath.length - 1, text: 'Port ' + sc.port + ' closed on ' + r.dstIP + ' → RST', cls: 'ok' }]);
      }
    }

    // 1) EDR on the SOURCE host catches malware before it leaves
    if (sc.endpointDetectable && hasAdjacent(r.source.id, 'edr')) {
      return finalize(animPath, 0, true,
        'EDR on the origin host detected and killed the malicious process.',
        [{ idx: 0, text: '[EDR] malicious behaviour on ' + r.srcIP + ' → process terminated', cls: 'drop' }]);
    }

    // 2a) SAME L2 SEGMENT — traffic is switched locally; network controls never see it
    if (sameSeg) {
      events.push({ idx: 0, text: '[L2] same segment ' + (srcSeg.cidr || '') +
        ' — switched directly; perimeter & zone controls are bypassed', cls: 'warn' });
      const hs = targetHostControls(sc, r, animPath);
      if (hs) return finalize(animPath, hs.idx, true, hs.reason, events.concat(hs.events));
      return finalize(animPath, animPath.length - 1, false,
        'Same-subnet traffic is not inspected by network controls — only host-based defense (micro-seg / EDR) could stop it.', events);
    }

    // 2b) DIFFERENT SEGMENTS — walk the routed path
    let firewallAllowed = false;
    for (let i = 0; i < path.length; i++) {
      const role = NODE_TYPES[Lab.getNode(path[i]).type].role;
      if (role === 'firewall') {
        const res = evalFirewall(Lab.getNode(path[i]), r.srcIP, r.dstIP, sc.port);
        if (res.action === 'DENY') {
          events.push({ idx: i, text: '[FW] ' + r.srcIP + ' -> ' + r.dstIP + (sc.port ? ':' + sc.port : '') +
            ' matched "' + res.rule + '" → DROP', cls: 'drop' });
          return finalize(path, i, true, 'Firewall rule dropped the packet ("' + res.rule + '").', events);
        }
        firewallAllowed = true;
        events.push({ idx: i, text: '[FW] ' + r.srcIP + ' -> ' + r.dstIP + (sc.port ? ':' + sc.port : '') +
          ' matched "' + res.rule + '" → allow', cls: 'warn' });
      } else if (role === 'ips') {
        if (sc.networkDetectable) {
          events.push({ idx: i, text: '[IPS] signature match for ' + sc.name + ' → packet dropped inline', cls: 'drop' });
          return finalize(path, i, true, 'IPS matched the attack signature inline and dropped it.', events);
        }
        events.push({ idx: i, text: '[IPS] traffic is encrypted / no signature → passed', cls: 'warn' });
      } else if (role === 'proxy') {
        if (sc.proxyStops) {
          events.push({ idx: i, text: '[PROXY/DLP] outbound content inspected → blocked', cls: 'drop' });
          return finalize(path, i, true, 'Outbound proxy / DLP inspected and blocked the transfer.', events);
        }
        events.push({ idx: i, text: '[PROXY] request allowed', cls: 'warn' });
      } else if (role === 'ids') {
        if (sc.networkDetectable) events.push({ idx: i, text: '[IDS] ALERT — ' + sc.name + ' observed (passive, not blocked)', cls: 'warn' });
      }
    }

    // 2c) zone ACL — target segment default-deny (unless a firewall explicitly permitted the flow)
    if (tgtSeg && tgtSeg.isolation === 'deny-inter-zone' && !firewallAllowed && sc.direction !== 'egress') {
      const last = path.length - 1;
      events.push({ idx: last, text: '[ACL] segment "' + (tgtSeg.label || tgtSeg.cidr) +
        '" is default-deny — inter-zone flow not permitted → DROP', cls: 'drop' });
      return finalize(path, last, true,
        'Target segment is isolated (default-deny) and no firewall permitted this flow.', events);
    }

    // 3) host controls on the target
    const hs = targetHostControls(sc, r, path);
    if (hs) return finalize(path, hs.idx, true, hs.reason, events.concat(hs.events));

    return finalize(path, path.length - 1, false,
      'No control on the path could stop it — the attacker reached the target.', events);
  }

  /* ---------- animation ---------- */
  function center(n) { return { x: n.x + n.w / 2, y: n.y + n.h / 2 }; }

  function animate(path, dropIndex, blocked, onDone) {
    const fx = Lab.el ? null : document.querySelector('#labCanvas #fxLayer');
    const layer = document.querySelector('#labCanvas #fxLayer');
    if (!layer) { onDone(); return; }
    const pts = path.slice(0, dropIndex + 1).map(function (id) { return center(Lab.getNode(id)); });
    if (pts.length === 1) { flash(pts[0], blocked); setTimeout(onDone, 400); return; }

    const dot = document.createElementNS(SVGNS, 'circle');
    dot.setAttribute('r', 6);
    dot.setAttribute('class', 'packet');
    dot.setAttribute('cx', pts[0].x); dot.setAttribute('cy', pts[0].y);
    layer.appendChild(dot);

    let seg = 0;
    const segMs = 520;
    let segStart = performance.now();

    function step(now) {
      let t = (now - segStart) / segMs;
      if (t >= 1) { t = 0; seg++; segStart = now;
        if (seg >= pts.length - 1) {
          dot.setAttribute('cx', pts[pts.length - 1].x);
          dot.setAttribute('cy', pts[pts.length - 1].y);
          if (blocked) dot.setAttribute('class', 'packet blocked');
          flash(pts[pts.length - 1], blocked);
          setTimeout(function () { if (dot.parentNode) dot.parentNode.removeChild(dot); onDone(); }, blocked ? 500 : 650);
          return;
        }
      }
      const a = pts[seg], b = pts[seg + 1];
      dot.setAttribute('cx', a.x + (b.x - a.x) * t);
      dot.setAttribute('cy', a.y + (b.y - a.y) * t);
      requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  function flash(pt, blocked) {
    const layer = document.querySelector('#labCanvas #fxLayer');
    if (!layer) return;
    const ring = document.createElementNS(SVGNS, 'circle');
    ring.setAttribute('cx', pt.x); ring.setAttribute('cy', pt.y);
    ring.setAttribute('r', 8); ring.setAttribute('fill', 'none');
    ring.setAttribute('stroke', blocked ? 'var(--red)' : 'var(--green)');
    ring.setAttribute('stroke-width', 2.5);
    layer.appendChild(ring);
    let r = 8, o = 1;
    (function grow() {
      r += 2.5; o -= 0.06;
      ring.setAttribute('r', r); ring.setAttribute('opacity', Math.max(0, o));
      if (o > 0) requestAnimationFrame(grow); else if (ring.parentNode) ring.parentNode.removeChild(ring);
    })();
  }

  /* ---------- run ---------- */
  function run() {
    if (running || !activeScenario) return;
    const sc = SCENARIOS[activeScenario];
    running = true;
    document.querySelector('#simRun').disabled = true;
    verdictEl.className = 'verdict';
    clearConsole();
    log('$ launch ' + sc.name.toLowerCase().replace(/[^a-z0-9]+/g, '-'), 'hop');
    log('// ' + sc.desc, 'info');

    const r = resolve(sc);
    if (r.error) {
      log('[!] ' + r.error, 'drop');
      showVerdict(false, r.error);
      finish();
      return;
    }
    log('source  : ' + labelOf(r.source) + '  (' + r.srcIP + ')', 'info');
    log('target  : ' + labelOf(r.target) + '  (' + r.dstIP + (sc.port ? ':' + sc.port : '') + ')', 'info');

    const d = decide(sc, r);
    if (!d.path) {
      log('[route] ' + d.reason, 'ok');
      showVerdict(true, d.reason);
      finish();
      return;
    }
    log('route   : ' + d.path.map(function (id) { return labelOf(Lab.getNode(id)); }).join(' → '), 'hop');

    // reveal events in sync with the packet crossing each node
    const revealAt = {};
    d.events.forEach(function (ev) { (revealAt[ev.idx] = revealAt[ev.idx] || []).push(ev); });
    let shown = -1;
    const total = d.dropIndex + 1;
    const perNode = 520;
    for (let i = 0; i <= d.dropIndex; i++) {
      (function (idx) {
        setTimeout(function () {
          (revealAt[idx] || []).forEach(function (ev) { log(ev.text, ev.cls); });
        }, idx * perNode + 120);
      })(i);
    }

    animate(d.path, d.dropIndex, d.blocked, function () {
      if (d.blocked) log('>> packet dropped. attack did not reach its objective.', 'ok');
      else log('>> attacker reached ' + labelOf(r.target) + '. objective achieved.', 'drop');
      showVerdict(d.blocked, d.reason);
      finish();
    });
  }

  function finish() {
    running = false;
    const btn = document.querySelector('#simRun');
    btn.disabled = false;
  }

  function labelOf(n) {
    return NODE_TYPES[n.type].label + (n.props && n.props.ip && n.props.ip !== '0.0.0.0/0' ? '' : '');
  }

  function setScenario(id) {
    activeScenario = id;
    const btn = document.querySelector('#simRun');
    if (id) { btn.disabled = false; btn.textContent = '▶  Run: ' + SCENARIOS[id].name; }
    else { btn.disabled = true; btn.textContent = 'Select a scenario to run'; }
  }

  function init(consoleElement, verdictElement) {
    consoleEl = consoleElement; verdictEl = verdictElement;
  }

  window.Sim = { init, setScenario, run };
})();
