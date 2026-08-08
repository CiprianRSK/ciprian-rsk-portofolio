/* canvas.js — SVG topology editor: nodes, links, drag, connect, pan/zoom, selection.
   Exposes window.Lab used by main.js (palette/toolbar) and simulation.js. */
(function () {
  const { NODE_TYPES } = window.NET;
  const SVGNS = 'http://www.w3.org/2000/svg';

  let svg, hintEl, changeCb = function () {};
  let uid = 1;

  const state = {
    nodes: [],            // { id, type, cat, x, y, w, h, props }
    edges: [],            // { id, from, to }
    zones: [],            // { id, x, y, w, h, label, cidr }
    selected: null,       // { kind:'node'|'edge'|'zone', id }
    tool: 'select',
  };
  const view = { tx: 0, ty: 0, k: 1 };

  // transient drag/connect state
  let drag = null;        // { id, dx, dy, moved }
  let panning = null;     // { sx, sy, tx, ty }
  let connecting = null;  // { from, tempEl }
  let zoneDraw = null;    // { x0, y0, el }
  let zoneDrag = null;    // { id, sx, sy, ox, oy, nodes, moved }
  let zoneResize = null;  // { id, sx, sy, ow, oh }

  /* ---------- coordinate helpers ---------- */
  function toWorld(clientX, clientY) {
    const r = svg.getBoundingClientRect();
    return { x: (clientX - r.left - view.tx) / view.k, y: (clientY - r.top - view.ty) / view.k };
  }
  function applyView() {
    const vp = svg.querySelector('#vp');
    if (vp) vp.setAttribute('transform', `translate(${view.tx},${view.ty}) scale(${view.k})`);
  }

  /* ---------- element creation ---------- */
  function el(tag, attrs, html) {
    const e = document.createElementNS(SVGNS, tag);
    for (const k in attrs) e.setAttribute(k, attrs[k]);
    if (html != null) e.innerHTML = html;
    return e;
  }

  function iconColor(cat) {
    return cat === 'security' ? 'var(--green)' : cat === 'threat' ? 'var(--red)' : 'var(--accent)';
  }

  function nodeSummary(n) {
    const t = NODE_TYPES[n.type];
    if (n.props.ip && (t.role === 'router' || t.role === 'internet' || t.role === 'attacker')) return n.props.ip;
    if (n.props.ports && n.props.ports.length) return n.props.ip ? n.props.ip : ':' + n.props.ports.join(',');
    if (n.props.ip) return n.props.ip;
    if (n.props.note) return '';
    return '';
  }

  function buildNode(n) {
    const t = NODE_TYPES[n.type];
    const g = el('g', { class: 'node-group', 'data-id': n.id, 'data-cat': n.cat,
      transform: `translate(${n.x},${n.y})` });
    if (state.selected && state.selected.kind === 'node' && state.selected.id === n.id) g.classList.add('selected');

    g.appendChild(el('rect', { class: 'node-body', x: 0, y: 0, width: n.w, height: n.h, rx: 7 }));

    // icon
    const ig = el('g', { class: 'node-icon', transform: `translate(${n.w / 2 - 11},9) scale(0.92)`,
      fill: 'none', stroke: iconColor(n.cat), 'stroke-width': 1.8,
      'stroke-linecap': 'round', 'stroke-linejoin': 'round' }, window.ICONS[t.icon] || '');
    g.appendChild(ig);

    // label + sub — use textContent (never innerHTML) for user-controlled values (XSS-safe)
    const labEl = el('text', { class: 'node-label', x: n.w / 2, y: n.h - 17 }); labEl.textContent = t.label;
    g.appendChild(labEl);
    const sub = nodeSummary(n);
    if (sub) { const subEl = el('text', { class: 'node-sub', x: n.w / 2, y: n.h - 5 }); subEl.textContent = sub; g.appendChild(subEl); }

    // host firewall / micro-seg indicator
    if (n.props.hostFirewall) {
      g.appendChild(el('circle', { cx: n.w - 11, cy: 11, r: 4.5, fill: 'var(--green)', stroke: 'var(--bg-card)', 'stroke-width': 1.5 }));
    }

    // connection ports (4 sides)
    const ports = [[n.w / 2, 0], [n.w, n.h / 2], [n.w / 2, n.h], [0, n.h / 2]];
    ports.forEach(function (p) {
      g.appendChild(el('circle', { class: 'node-port', cx: p[0], cy: p[1], r: 5 }));
    });
    return g;
  }

  // border point of node n on the ray toward (tx,ty)
  function borderPoint(n, tx, ty) {
    const cx = n.x + n.w / 2, cy = n.y + n.h / 2;
    let dx = tx - cx, dy = ty - cy;
    if (dx === 0 && dy === 0) return { x: cx, y: cy };
    const hw = n.w / 2 + 2, hh = n.h / 2 + 2;
    const sx = dx === 0 ? Infinity : hw / Math.abs(dx);
    const sy = dy === 0 ? Infinity : hh / Math.abs(dy);
    const s = Math.min(sx, sy);
    return { x: cx + dx * s, y: cy + dy * s };
  }

  function edgePath(a, b) {
    const ac = { x: a.x + a.w / 2, y: a.y + a.h / 2 };
    const bc = { x: b.x + b.w / 2, y: b.y + b.h / 2 };
    const p1 = borderPoint(a, bc.x, bc.y);
    const p2 = borderPoint(b, ac.x, ac.y);
    return { p1, p2 };
  }

  function buildEdge(e) {
    const a = getNode(e.from), b = getNode(e.to);
    if (!a || !b) return null;
    const { p1, p2 } = edgePath(a, b);
    const d = `M ${p1.x} ${p1.y} L ${p2.x} ${p2.y}`;
    const g = el('g', { 'data-edge': e.id });
    g.appendChild(el('path', { class: 'edge-hit', d: d }));
    const sel = state.selected && state.selected.kind === 'edge' && state.selected.id === e.id;
    g.appendChild(el('path', { class: 'edge' + (sel ? ' selected' : ''), d: d, 'data-edge-line': e.id }));
    return g;
  }

  function buildZone(z) {
    const g = el('g', { class: 'zone-group', 'data-zone': z.id, transform: `translate(${z.x},${z.y})` });
    if (state.selected && state.selected.kind === 'zone' && state.selected.id === z.id) g.classList.add('selected');
    if (z.isolation === 'deny-inter-zone') g.classList.add('isolated');
    g.appendChild(el('rect', { class: 'zone-rect', x: 0, y: 0, width: z.w, height: z.h, rx: 8 }));
    const lab = el('text', { class: 'zone-label', x: 12, y: 21 }); lab.textContent = z.label || 'Segment';
    g.appendChild(lab);
    if (z.cidr) { const c = el('text', { class: 'zone-cidr', x: 12, y: 34 }); c.textContent = z.cidr; g.appendChild(c); }
    if (z.isolation === 'deny-inter-zone') {
      const iso = el('text', { class: 'zone-iso', x: 12, y: z.h - 10 }); iso.textContent = '🔒 default-deny · isolated';
      g.appendChild(iso);
    }
    g.appendChild(el('rect', { class: 'zone-handle', x: z.w - 13, y: z.h - 13, width: 13, height: 13, rx: 2 }));
    return g;
  }

  function updateZoneVisual(z) {
    const g = svg.querySelector(`.zone-group[data-zone="${z.id}"]`);
    if (!g) return;
    g.setAttribute('transform', `translate(${z.x},${z.y})`);
    const rect = g.querySelector('.zone-rect'); rect.setAttribute('width', z.w); rect.setAttribute('height', z.h);
    const h = g.querySelector('.zone-handle'); h.setAttribute('x', z.w - 13); h.setAttribute('y', z.h - 13);
  }

  function getZone(id) { return state.zones.find(function (z) { return z.id === id; }); }
  function nodesInsideZone(z) {
    return state.nodes.filter(function (n) {
      const cx = n.x + n.w / 2, cy = n.y + n.h / 2;
      return cx >= z.x && cx <= z.x + z.w && cy >= z.y && cy <= z.y + z.h;
    });
  }
  function addZone(x, y, w, h) {
    const z = { id: 'z' + (uid++), x: Math.round(x), y: Math.round(y),
      w: Math.round(w), h: Math.round(h), label: 'Segment', cidr: '10.0.0.0/24', isolation: 'none' };
    state.zones.push(z); render(); changeCb();
    return z;
  }

  /* ---------- full render ---------- */
  function render() {
    svg.innerHTML =
      '<defs>' +
      '<marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">' +
      '<path d="M0 0 L10 5 L0 10 z" fill="var(--text-muted)"/></marker></defs>' +
      '<g id="vp"><g id="zoneLayer"></g><g id="edgeLayer"></g><g id="nodeLayer"></g><g id="fxLayer"></g></g>';
    applyView();
    const zoneLayer = svg.querySelector('#zoneLayer');
    const edgeLayer = svg.querySelector('#edgeLayer');
    const nodeLayer = svg.querySelector('#nodeLayer');
    state.zones.forEach(function (z) { zoneLayer.appendChild(buildZone(z)); });
    state.edges.forEach(function (e) { const g = buildEdge(e); if (g) edgeLayer.appendChild(g); });
    state.nodes.forEach(function (n) { nodeLayer.appendChild(buildNode(n)); });
    if (hintEl) hintEl.style.display = state.nodes.length ? 'none' : '';
    if (svg.classList) svg.classList.toggle('connect-mode', state.tool === 'connect');
  }

  // lightweight update while dragging one node
  function updateNodePos(n) {
    const g = svg.querySelector(`.node-group[data-id="${n.id}"]`);
    if (g) g.setAttribute('transform', `translate(${n.x},${n.y})`);
    state.edges.forEach(function (e) {
      if (e.from !== n.id && e.to !== n.id) return;
      const a = getNode(e.from), b = getNode(e.to);
      const { p1, p2 } = edgePath(a, b);
      const d = `M ${p1.x} ${p1.y} L ${p2.x} ${p2.y}`;
      svg.querySelectorAll(`[data-edge="${e.id}"] path`).forEach(function (pt) { pt.setAttribute('d', d); });
    });
  }

  /* ---------- model ops ---------- */
  function getNode(id) { return state.nodes.find(function (n) { return n.id === id; }); }

  function addNode(type, x, y, props) {
    const t = NODE_TYPES[type];
    if (!t) return null;
    const n = {
      id: 'n' + (uid++), type: type, cat: t.cat, w: t.w, h: t.h,
      x: Math.round(x - t.w / 2), y: Math.round(y - t.h / 2),
      props: Object.assign({}, JSON.parse(JSON.stringify(t.defaults || {})), props || {}),
    };
    if (n.props.ports) n.props.ports = n.props.ports.slice();
    state.nodes.push(n);
    render();
    changeCb();
    return n;
  }

  function addEdge(from, to) {
    if (from === to) return;
    if (state.edges.some(function (e) {
      return (e.from === from && e.to === to) || (e.from === to && e.to === from);
    })) return;
    state.edges.push({ id: 'e' + (uid++), from: from, to: to });
    render();
    changeCb();
  }

  function deleteSelected() {
    if (!state.selected) return;
    const id = state.selected.id;
    if (state.selected.kind === 'node') {
      state.nodes = state.nodes.filter(function (n) { return n.id !== id; });
      state.edges = state.edges.filter(function (e) { return e.from !== id && e.to !== id; });
    } else if (state.selected.kind === 'edge') {
      state.edges = state.edges.filter(function (e) { return e.id !== id; });
    } else if (state.selected.kind === 'zone') {
      state.zones = state.zones.filter(function (z) { return z.id !== id; });
    }
    state.selected = null;
    render(); changeCb();
  }

  function clearAll() {
    state.nodes = []; state.edges = []; state.zones = []; state.selected = null;
    render(); changeCb();
  }

  function select(kind, id) {
    state.selected = id ? { kind: kind, id: id } : null;
    render(); changeCb();
  }

  /* ---------- import / export ---------- */
  function exportTopology() {
    return {
      nodes: state.nodes.map(function (n) {
        return { id: n.id, type: n.type, x: n.x, y: n.y, props: n.props };
      }),
      edges: state.edges.map(function (e) { return { id: e.id, from: e.from, to: e.to }; }),
      zones: state.zones.map(function (z) {
        return { id: z.id, x: z.x, y: z.y, w: z.w, h: z.h, label: z.label, cidr: z.cidr, isolation: z.isolation || 'none' };
      }),
      view: { tx: view.tx, ty: view.ty, k: view.k },
    };
  }

  function loadTopology(data) {
    state.nodes = []; state.edges = []; state.zones = []; state.selected = null;
    let max = 0;
    (data.nodes || []).forEach(function (nd) {
      const t = NODE_TYPES[nd.type]; if (!t) return;
      const id = nd.id || ('n' + (uid++));
      const num = parseInt(String(id).replace(/\D/g, ''), 10); if (num > max) max = num;
      state.nodes.push({
        id: id, type: nd.type, cat: t.cat, w: t.w, h: t.h,
        x: nd.x, y: nd.y,
        props: Object.assign({}, JSON.parse(JSON.stringify(t.defaults || {})), nd.props || {}),
      });
    });
    (data.edges || []).forEach(function (ed) {
      const id = ed.id || ('e' + (uid++));
      const num = parseInt(String(id).replace(/\D/g, ''), 10); if (num > max) max = num;
      state.edges.push({ id: id, from: ed.from, to: ed.to });
    });
    (data.zones || []).forEach(function (zd) {
      const id = zd.id || ('z' + (uid++));
      const num = parseInt(String(id).replace(/\D/g, ''), 10); if (num > max) max = num;
      state.zones.push({ id: id, x: zd.x, y: zd.y, w: zd.w, h: zd.h,
        label: zd.label || 'Segment', cidr: zd.cidr || '', isolation: zd.isolation || 'none' });
    });
    uid = max + 1;
    if (data.view) { view.tx = data.view.tx; view.ty = data.view.ty; view.k = data.view.k; }
    render(); changeCb();
  }

  // build a demo (indexes -> ids)
  function loadDemo(demo) {
    const built = { nodes: [], edges: [], zones: [] };
    const ids = [];
    demo.nodes.forEach(function (nd, i) {
      const id = 'n' + (i + 1); ids[i] = id;
      built.nodes.push({ id: id, type: nd.type, x: nd.x, y: nd.y, props: nd.props || {} });
    });
    demo.edges.forEach(function (pair, i) {
      built.edges.push({ id: 'e' + (i + 1), from: ids[pair[0]], to: ids[pair[1]] });
    });
    (demo.zones || []).forEach(function (zd, i) {
      built.zones.push(Object.assign({ id: 'z' + (i + 1) }, zd));
    });
    loadTopology(built);
    fit();
  }

  /* ---------- view: fit / zoom ---------- */
  function fit() {
    if (!state.nodes.length) { view.tx = 0; view.ty = 0; view.k = 1; applyView(); return; }
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    state.nodes.forEach(function (n) {
      minX = Math.min(minX, n.x); minY = Math.min(minY, n.y);
      maxX = Math.max(maxX, n.x + n.w); maxY = Math.max(maxY, n.y + n.h);
    });
    const pad = 60;
    const rect = svg.getBoundingClientRect();
    const cw = rect.width, ch = rect.height;
    const bw = (maxX - minX) + pad * 2, bh = (maxY - minY) + pad * 2;
    const k = Math.min(cw / bw, ch / bh, 1.4);
    view.k = k;
    view.tx = (cw - (maxX + minX) * k) / 2;
    view.ty = (ch - (maxY + minY) * k) / 2;
    applyView();
  }

  function zoomAt(clientX, clientY, factor) {
    const w = toWorld(clientX, clientY);
    view.k = Math.max(0.35, Math.min(2.2, view.k * factor));
    const r = svg.getBoundingClientRect();
    view.tx = (clientX - r.left) - w.x * view.k;
    view.ty = (clientY - r.top) - w.y * view.k;
    applyView();
  }

  /* ---------- pointer handling ---------- */
  function nodeIdFromEvent(e) {
    const g = e.target.closest ? e.target.closest('.node-group') : null;
    return g ? g.getAttribute('data-id') : null;
  }
  function edgeIdFromEvent(e) {
    const g = e.target.closest ? e.target.closest('[data-edge]') : null;
    return g ? g.getAttribute('data-edge') : null;
  }
  function zoneIdFromEvent(e) {
    const g = e.target.closest ? e.target.closest('.zone-group') : null;
    return g ? g.getAttribute('data-zone') : null;
  }
  // pointer-capture makes e.target the SVG on pointerup, so resolve the real node by hit-testing.
  function nodeIdFromPoint(clientX, clientY) {
    const t = document.elementFromPoint(clientX, clientY);
    const g = t && t.closest ? t.closest('.node-group') : null;
    return g ? g.getAttribute('data-id') : null;
  }

  function onDown(e) {
    if (e.button === 1 || e.button === 2) return;
    const isPort = e.target.classList && e.target.classList.contains('node-port');
    const isHandle = e.target.classList && e.target.classList.contains('zone-handle');
    const nodeId = nodeIdFromEvent(e);

    // start a connection (connect tool anywhere on node, OR any-tool on a port)
    if (nodeId && (isPort || state.tool === 'connect')) {
      const from = getNode(nodeId);
      const cx = from.x + from.w / 2, cy = from.y + from.h / 2;
      const tempEl = el('path', { class: 'temp-edge', d: `M ${cx} ${cy} L ${cx} ${cy}` });
      svg.querySelector('#fxLayer').appendChild(tempEl);
      connecting = { from: nodeId, tempEl: tempEl };
      e.preventDefault();
      return;
    }

    // select + drag node
    if (nodeId) {
      const n = getNode(nodeId);
      select('node', nodeId);
      const w = toWorld(e.clientX, e.clientY);
      drag = { id: nodeId, dx: w.x - n.x, dy: w.y - n.y, moved: false };
      e.preventDefault();
      return;
    }

    // select edge
    const edgeId = edgeIdFromEvent(e);
    if (edgeId) { select('edge', edgeId); e.preventDefault(); return; }

    // resize a zone via its corner handle
    if (isHandle) {
      const zid = zoneIdFromEvent(e); const z = getZone(zid);
      if (z) { select('zone', zid); zoneResize = { id: zid, sx: e.clientX, sy: e.clientY, ow: z.w, oh: z.h }; e.preventDefault(); return; }
    }

    // draw a new zone (segment tool) from empty space
    if (state.tool === 'zone') {
      const w = toWorld(e.clientX, e.clientY);
      const rect = el('rect', { class: 'temp-zone', x: w.x, y: w.y, width: 0, height: 0, rx: 8 });
      svg.querySelector('#fxLayer').appendChild(rect);
      zoneDraw = { x0: w.x, y0: w.y, el: rect };
      e.preventDefault();
      return;
    }

    // select + drag an existing zone (moves the nodes it encloses)
    const zoneId = zoneIdFromEvent(e);
    if (zoneId) {
      const z = getZone(zoneId);
      select('zone', zoneId);
      const inside = nodesInsideZone(z).map(function (n) { return { id: n.id, ox: n.x, oy: n.y }; });
      zoneDrag = { id: zoneId, sx: e.clientX, sy: e.clientY, ox: z.x, oy: z.y, nodes: inside, moved: false };
      e.preventDefault();
      return;
    }

    // empty space → pan (and deselect)
    if (state.selected) select(null);
    panning = { sx: e.clientX, sy: e.clientY, tx: view.tx, ty: view.ty };
  }

  function onMove(e) {
    if (zoneResize) {
      const z = getZone(zoneResize.id);
      z.w = Math.max(90, Math.round(zoneResize.ow + (e.clientX - zoneResize.sx) / view.k));
      z.h = Math.max(70, Math.round(zoneResize.oh + (e.clientY - zoneResize.sy) / view.k));
      updateZoneVisual(z);
      return;
    }
    if (zoneDraw) {
      const w = toWorld(e.clientX, e.clientY);
      zoneDraw.el.setAttribute('x', Math.min(w.x, zoneDraw.x0));
      zoneDraw.el.setAttribute('y', Math.min(w.y, zoneDraw.y0));
      zoneDraw.el.setAttribute('width', Math.abs(w.x - zoneDraw.x0));
      zoneDraw.el.setAttribute('height', Math.abs(w.y - zoneDraw.y0));
      return;
    }
    if (zoneDrag) {
      const dx = (e.clientX - zoneDrag.sx) / view.k, dy = (e.clientY - zoneDrag.sy) / view.k;
      const z = getZone(zoneDrag.id);
      z.x = Math.round(zoneDrag.ox + dx); z.y = Math.round(zoneDrag.oy + dy);
      updateZoneVisual(z);
      zoneDrag.nodes.forEach(function (nd) {
        const n = getNode(nd.id); if (!n) return;
        n.x = Math.round(nd.ox + dx); n.y = Math.round(nd.oy + dy);
        updateNodePos(n);
      });
      zoneDrag.moved = true;
      return;
    }
    if (drag) {
      const w = toWorld(e.clientX, e.clientY);
      const n = getNode(drag.id);
      n.x = Math.round(w.x - drag.dx);
      n.y = Math.round(w.y - drag.dy);
      drag.moved = true;
      updateNodePos(n);
      return;
    }
    if (connecting) {
      const from = getNode(connecting.from);
      const w = toWorld(e.clientX, e.clientY);
      const bp = borderPoint(from, w.x, w.y);
      connecting.tempEl.setAttribute('d', `M ${bp.x} ${bp.y} L ${w.x} ${w.y}`);
      return;
    }
    if (panning) {
      view.tx = panning.tx + (e.clientX - panning.sx);
      view.ty = panning.ty + (e.clientY - panning.sy);
      applyView();
    }
  }

  function onUp(e) {
    if (connecting) {
      const targetId = nodeIdFromPoint(e.clientX, e.clientY);
      if (targetId && targetId !== connecting.from) addEdge(connecting.from, targetId);
      if (connecting.tempEl && connecting.tempEl.parentNode) connecting.tempEl.parentNode.removeChild(connecting.tempEl);
      connecting = null;
      return;
    }
    if (zoneDraw) {
      const x = +zoneDraw.el.getAttribute('x'), y = +zoneDraw.el.getAttribute('y');
      const w = +zoneDraw.el.getAttribute('width'), h = +zoneDraw.el.getAttribute('height');
      if (zoneDraw.el.parentNode) zoneDraw.el.parentNode.removeChild(zoneDraw.el);
      zoneDraw = null;
      if (w > 40 && h > 40) { const z = addZone(x, y, w, h); setTool('select'); select('zone', z.id); }
      else render();
      return;
    }
    if (zoneResize) { changeCb(); zoneResize = null; return; }
    if (zoneDrag) { if (zoneDrag.moved) changeCb(); zoneDrag = null; return; }
    if (drag) {
      if (drag.moved) changeCb();
      drag = null;
      return;
    }
    panning = null;
  }

  /* ---------- init ---------- */
  function init(svgEl, hint, onChange) {
    svg = svgEl; hintEl = hint; changeCb = onChange || function () {};
    render();

    svg.addEventListener('pointerdown', function (e) { onDown(e); if (drag || connecting || panning || zoneDraw || zoneDrag || zoneResize) svg.setPointerCapture(e.pointerId); });
    svg.addEventListener('pointermove', onMove);
    svg.addEventListener('pointerup', onUp);
    svg.addEventListener('pointercancel', onUp);
    svg.addEventListener('contextmenu', function (e) { e.preventDefault(); });
    svg.addEventListener('wheel', function (e) {
      e.preventDefault();
      zoomAt(e.clientX, e.clientY, e.deltaY < 0 ? 1.12 : 0.89);
    }, { passive: false });

    // drop from palette (HTML5 DnD)
    const wrap = svg.parentNode;
    wrap.addEventListener('dragover', function (e) { e.preventDefault(); e.dataTransfer.dropEffect = 'copy'; });
    wrap.addEventListener('drop', function (e) {
      e.preventDefault();
      const type = e.dataTransfer.getData('text/node-type');
      if (!type) return;
      const w = toWorld(e.clientX, e.clientY);
      const n = addNode(type, w.x, w.y);
      if (n) select('node', n.id);
    });

    document.addEventListener('keydown', function (e) {
      if (e.target.matches && e.target.matches('input,textarea,select')) return;
      if ((e.key === 'Delete' || e.key === 'Backspace') && state.selected) { e.preventDefault(); deleteSelected(); }
      if (e.key === 'v' || e.key === 'V') setTool('select');
      if (e.key === 'c' || e.key === 'C') setTool('connect');
      if (e.key === 'z' || e.key === 'Z') setTool('zone');
      if (e.key === 'Escape') select(null);
    });
  }

  function setTool(t) {
    state.tool = t;
    if (svg && svg.classList) {
      svg.classList.toggle('connect-mode', t === 'connect');
      svg.classList.toggle('zone-mode', t === 'zone');
    }
    document.querySelectorAll('.tool-btn[data-tool]').forEach(function (b) {
      b.classList.toggle('active', b.getAttribute('data-tool') === t);
    });
  }

  window.Lab = {
    state, view, init, render, addNode, addEdge, addZone, deleteSelected, clearAll,
    select, getNode, getZone, exportTopology, loadTopology, loadDemo, fit, setTool,
    onChange: function (cb) { changeCb = cb; },
  };
})();
