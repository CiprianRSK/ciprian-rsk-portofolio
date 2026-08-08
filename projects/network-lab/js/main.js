/* main.js — wires the UI: palette, toolbar, inspector, scenarios, persistence, reveal. */
(function () {
  const { NODE_TYPES, PALETTE, SCENARIOS, DEMO } = window.NET;
  const STORE_KEY = 'netlab-topology-v1';

  document.addEventListener('DOMContentLoaded', function () {
    renderStaticIcons();
    initReveal();
    buildPalette();
    buildScenarios();

    const svg = document.getElementById('labCanvas');
    const hint = document.getElementById('canvasHint');
    const inspector = document.getElementById('labInspector');

    Lab.init(svg, hint, onLabChange);
    Sim.init(document.getElementById('simConsole'), document.getElementById('simVerdict'));
    Lab.setTool('select');
    wireToolbar();

    // load saved topology, else the demo
    const saved = loadLocal();
    if (saved && saved.nodes && saved.nodes.length) { Lab.loadTopology(saved); setTimeout(Lab.fit, 30); }
    else { Lab.loadDemo(DEMO); }

    onLabChange();

    // -------- inspector rendering --------
    function onLabChange() {
      renderInspector();
      saveLocal();
    }

    function renderInspector() {
      const sel = Lab.state.selected;
      if (!sel) {
        inspector.classList.remove('open');
        inspector.innerHTML = '<div class="insp-empty">Select a node or connection to inspect and edit its properties.</div>';
        return;
      }
      inspector.classList.add('open');

      if (sel.kind === 'edge') {
        inspector.innerHTML =
          '<div class="insp-title">' + svgIcon('link', 16) + ' Connection</div>' +
          '<p style="color:var(--text-muted);font-size:.8rem">A network link. Packets can travel across it in the simulation.</p>';
        addDeleteBtn('Delete link');
        return;
      }

      if (sel.kind === 'zone') {
        const z = Lab.getZone(sel.id);
        if (!z) return;
        inspector.innerHTML = '<div class="insp-title"><span style="color:var(--accent-2)">' +
          svgIcon('layout', 16) + '</span> Network Segment</div>';

        const f1 = document.createElement('div'); f1.className = 'field';
        f1.innerHTML = '<label>Segment name</label>';
        const i1 = mkInput(z.label || '', 'e.g. Internal LAN, DMZ');
        i1.addEventListener('input', function () { z.label = i1.value; Lab.render(); saveLocal(); });
        f1.appendChild(i1); inspector.appendChild(f1);

        const f2 = document.createElement('div'); f2.className = 'field';
        f2.innerHTML = '<label>Subnet / CIDR</label>';
        const i2 = mkInput(z.cidr || '', 'e.g. 10.0.1.0/24');
        i2.addEventListener('input', function () { z.cidr = i2.value.trim(); Lab.render(); saveLocal(); });
        f2.appendChild(i2); inspector.appendChild(f2);

        const f3 = document.createElement('div'); f3.className = 'field';
        f3.appendChild(mkCheckbox(z.isolation === 'deny-inter-zone', 'Isolate segment (default-deny)', function (v) {
          z.isolation = v ? 'deny-inter-zone' : 'none'; Lab.render(); saveLocal();
        }));
        f3.appendChild(hintEl('Zone ACL: blocks traffic from OTHER segments unless a firewall on the path explicitly allows it. Same-subnet traffic is unaffected.'));
        inspector.appendChild(f3);

        inspector.appendChild(hintEl('Drag the segment to move everything inside it. Drag the corner handle to resize.'));

        addDeleteBtn('Delete segment');
        return;
      }

      const n = Lab.getNode(sel.id);
      if (!n) return;
      const t = NODE_TYPES[n.type];
      let html = '<div class="insp-title"><span style="color:' +
        (n.cat === 'security' ? 'var(--green)' : n.cat === 'threat' ? 'var(--red)' : 'var(--accent)') +
        '">' + svgIcon(t.icon, 16) + '</span> ' + t.label + '</div>';
      inspector.innerHTML = html;

      (t.fields || []).forEach(function (f) { inspector.appendChild(buildField(n, f)); });
      addDeleteBtn('Delete node');
    }

    function buildField(n, f) {
      const wrap = document.createElement('div');
      wrap.className = 'field';
      if (f === 'ip') {
        wrap.innerHTML = '<label>IP address / CIDR</label>';
        const inp = mkInput(n.props.ip || '', 'e.g. 10.0.1.20');
        inp.addEventListener('input', function () { n.props.ip = inp.value.trim(); refresh(n); });
        wrap.appendChild(inp);
      } else if (f === 'ports') {
        wrap.innerHTML = '<label>Open ports</label>';
        const inp = mkInput((n.props.ports || []).join(', '), 'e.g. 445, 3389, 443');
        inp.addEventListener('input', function () {
          n.props.ports = inp.value.split(/[\s,]+/).map(function (x) { return parseInt(x, 10); }).filter(function (x) { return !isNaN(x); });
          refresh(n);
        });
        wrap.appendChild(inp);
        wrap.appendChild(hintEl('Comma-separated. Open ports are what attacks can target.'));
      } else if (f === 'placement') {
        wrap.innerHTML = '<label>Attacker placement</label>';
        const sel = document.createElement('select');
        ['external', 'internal'].forEach(function (o) {
          const opt = document.createElement('option'); opt.value = o;
          opt.textContent = o === 'external' ? 'External (internet)' : 'Internal (compromised host)';
          if ((n.props.placement || 'external') === o) opt.selected = true;
          sel.appendChild(opt);
        });
        sel.addEventListener('change', function () { n.props.placement = sel.value; refresh(n); });
        wrap.appendChild(sel);
      } else if (f === 'rules') {
        wrap.innerHTML = '<label>Firewall rules</label>';
        const ta = document.createElement('textarea');
        ta.value = n.props.rules || '';
        ta.spellcheck = false;
        ta.style.minHeight = '150px';
        ta.addEventListener('input', function () { n.props.rules = ta.value; saveLocal(); });
        wrap.appendChild(ta);
        wrap.appendChild(hintEl('Syntax:  ALLOW|DENY  <src> -> <dst> : <port>\nTop-down, first match wins. Ends with implicit deny-all.'));
      } else if (f === 'note') {
        wrap.innerHTML = '<label>Role</label>';
        const inp = mkInput(n.props.note || '', '');
        inp.addEventListener('input', function () { n.props.note = inp.value; saveLocal(); });
        wrap.appendChild(inp);
      } else if (f === 'hostfw') {
        const row = mkCheckbox(!!n.props.hostFirewall, 'Host firewall / micro-seg', function (v) {
          n.props.hostFirewall = v; refresh(n);
        });
        wrap.appendChild(row);
        wrap.appendChild(hintEl('Denies inbound attack ports on this host — stops lateral movement even inside the same subnet.'));
      }
      return wrap;
    }

    function refresh(n) { Lab.render(); saveLocal(); }

    function mkInput(val, ph) {
      const i = document.createElement('input');
      i.type = 'text'; i.value = val; i.placeholder = ph || ''; i.spellcheck = false;
      return i;
    }
    function hintEl(text) { const d = document.createElement('div'); d.className = 'hint'; d.textContent = text; return d; }
    function mkCheckbox(checked, label, onChange) {
      const row = document.createElement('label');
      row.className = 'check-row';
      const cb = document.createElement('input');
      cb.type = 'checkbox'; cb.checked = checked;
      cb.addEventListener('change', function () { onChange(cb.checked); });
      const span = document.createElement('span'); span.textContent = label;
      row.appendChild(cb); row.appendChild(span);
      return row;
    }
    function addDeleteBtn(label) {
      const b = document.createElement('button');
      b.className = 'insp-btn'; b.textContent = label;
      b.addEventListener('click', function () { Lab.deleteSelected(); });
      inspector.appendChild(b);
    }

    // expose save/local to toolbar closure
    window.__netlabSave = saveLocal;
  });

  /* ---------- palette ---------- */
  function buildPalette() {
    const wrap = document.getElementById('labPalette');
    let html = '';
    PALETTE.forEach(function (grp) {
      html += '<div class="palette-group-title">' + grp.group + '</div>';
      grp.items.forEach(function (type) {
        const t = NODE_TYPES[type];
        html += '<div class="palette-item" draggable="true" data-type="' + type + '" data-cat="' + t.cat + '">' +
          '<span class="pi-ico">' + svgIcon(t.icon, 20) + '</span>' +
          '<span class="pi-label">' + t.label + '</span></div>';
      });
    });
    wrap.innerHTML = html;

    wrap.querySelectorAll('.palette-item').forEach(function (item) {
      item.addEventListener('dragstart', function (e) {
        e.dataTransfer.setData('text/node-type', item.getAttribute('data-type'));
        e.dataTransfer.effectAllowed = 'copy';
      });
      // click / tap to add at canvas centre (mobile-friendly)
      item.addEventListener('click', function () {
        const svg = document.getElementById('labCanvas');
        const r = svg.getBoundingClientRect();
        const w = { x: (r.width / 2 - Lab.view.tx) / Lab.view.k, y: (r.height / 2 - Lab.view.ty) / Lab.view.k };
        const n = Lab.addNode(item.getAttribute('data-type'), w.x, w.y);
        if (n) Lab.select('node', n.id);
      });
    });
  }

  /* ---------- scenarios ---------- */
  function buildScenarios() {
    const list = document.getElementById('scenarioList');
    let html = '';
    Object.keys(SCENARIOS).forEach(function (id) {
      const s = SCENARIOS[id];
      html += '<div class="scenario" data-sc="' + id + '">' +
        '<span class="sc-ico">' + svgIcon(s.icon, 18) + '</span>' +
        '<div><div class="sc-name">' + s.name + '</div><div class="sc-desc">' + s.desc + '</div></div></div>';
    });
    list.innerHTML = html;
    list.querySelectorAll('.scenario').forEach(function (el) {
      el.addEventListener('click', function () {
        list.querySelectorAll('.scenario').forEach(function (x) { x.classList.remove('active'); });
        el.classList.add('active');
        Sim.setScenario(el.getAttribute('data-sc'));
      });
    });
    document.getElementById('simRun').addEventListener('click', function () { Sim.run(); });
  }

  /* ---------- toolbar ---------- */
  function wireToolbar() {
    document.querySelectorAll('.tool-btn[data-tool]').forEach(function (b) {
      b.addEventListener('click', function () { Lab.setTool(b.getAttribute('data-tool')); });
    });
    document.querySelectorAll('.tool-btn[data-action]').forEach(function (b) {
      b.addEventListener('click', function () {
        const a = b.getAttribute('data-action');
        if (a === 'fit') Lab.fit();
        else if (a === 'clear') { if (confirm('Clear the whole canvas?')) Lab.clearAll(); }
        else if (a === 'demo') Lab.loadDemo(NET.DEMO);
        else if (a === 'save') { saveLocal(); flashBtn(b, 'Saved ✓'); }
      });
    });
  }
  function flashBtn(b, txt) {
    const orig = b.innerHTML; b.textContent = txt;
    setTimeout(function () { b.innerHTML = orig; }, 1200);
  }

  /* ---------- persistence ---------- */
  function saveLocal() {
    try { localStorage.setItem(STORE_KEY, JSON.stringify(Lab.exportTopology())); } catch (e) {}
  }
  function loadLocal() {
    try { return JSON.parse(localStorage.getItem(STORE_KEY)); } catch (e) { return null; }
  }

  /* ---------- reveal ---------- */
  function initReveal() {
    const obs = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) { if (en.isIntersecting) { en.target.classList.add('visible'); obs.unobserve(en.target); } });
    }, { threshold: 0.08 });
    document.querySelectorAll('.reveal').forEach(function (el) { obs.observe(el); });
  }
})();
