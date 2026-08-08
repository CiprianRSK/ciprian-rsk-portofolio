/* icons.js — inline SVG icon set (Lucide-style, stroke = currentColor).
   ICONS[name] returns the inner markup of a 24x24 stroked icon.
   svgIcon(name, size) wraps it into a full <svg> string. */
(function () {
  const S = {
    // --- toolbar / ui ---
    cursor:   '<path d="m3 3 7.07 16.97 2.51-7.39 7.39-2.51L3 3z"/><path d="m13 13 6 6"/>',
    link:     '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
    maximize: '<path d="M8 3H5a2 2 0 0 0-2 2v3"/><path d="M21 8V5a2 2 0 0 0-2-2h-3"/><path d="M3 16v3a2 2 0 0 0 2 2h3"/><path d="M16 21h3a2 2 0 0 0 2-2v-3"/>',
    trash:    '<path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>',
    layout:   '<rect width="18" height="18" x="3" y="3" rx="2"/><path d="M9 3v18M3 9h6"/>',
    save:     '<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><path d="M17 21v-8H7v8M7 3v5h8"/>',
    crosshair:'<circle cx="12" cy="12" r="9"/><path d="M22 12h-4M6 12H2M12 6V2M12 22v-4"/>',
    terminal: '<path d="m4 17 6-6-6-6"/><path d="M12 19h8"/>',
    x:        '<path d="M18 6 6 18M6 6l12 12"/>',

    // --- endpoints ---
    pc:       '<rect width="18" height="12" x="3" y="4" rx="1"/><path d="M2 20h20M8 20v-4h8v4"/>',
    server:   '<rect width="18" height="8" x="3" y="3" rx="1"/><rect width="18" height="8" x="3" y="13" rx="1"/><path d="M7 7h.01M7 17h.01"/>',
    dc:       '<path d="M6 22V4a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v18"/><path d="M2 22h20M10 6h4M10 10h4M10 14h4M10 18h4"/>',
    web:      '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18"/>',
    db:       '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v6c0 1.66 3.58 3 8 3s8-1.34 8-3V5M4 11v6c0 1.66 3.58 3 8 3s8-1.34 8-3v-6"/>',
    router:   '<rect width="20" height="8" x="2" y="14" rx="2"/><path d="M6.01 18H6M10 18h.01"/><path d="m12 14 3-7 3 3M15 3v4"/>',
    switch:   '<rect width="20" height="8" x="2" y="8" rx="2"/><path d="M6 12h.01M10 12h.01M14 12h.01M18 12h.01"/>',
    internet: '<path d="M17.5 19a4.5 4.5 0 0 0 0-9h-1.8A7 7 0 1 0 4 16.7"/><path d="M12 12v9M8 17l4 4 4-4"/>',
    attacker: '<circle cx="12" cy="8" r="4"/><path d="M5.5 21a7.5 7.5 0 0 1 13 0"/><path d="m15 2-1.5 2M9 2l1.5 2"/>',

    // --- security controls ---
    firewall: '<rect width="18" height="18" x="3" y="3" rx="1"/><path d="M3 9h18M3 15h18M9 3v6M15 9v6M9 15v6"/>',
    ids:      '<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/>',
    ips:      '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4M12 16h.01"/>',
    edr:      '<rect width="16" height="11" x="4" y="4" rx="1"/><path d="M2 19h20M10 15l2 2 4-4"/>',
    proxy:    '<path d="m17 2 4 4-4 4"/><path d="M3 11v-1a4 4 0 0 1 4-4h14"/><path d="m7 22-4-4 4-4"/><path d="M21 13v1a4 4 0 0 1-4 4H3"/>',
    scrub:    '<path d="M3 4h18l-7 8.5V19l-4 2v-8.5z"/>',
    ddos:     '<path d="M22 12h-4l-3 8-6-16-3 8H2"/>',
  };

  window.ICONS = S;
  window.svgIcon = function (name, size) {
    size = size || 24;
    const inner = S[name] || '';
    return '<svg xmlns="http://www.w3.org/2000/svg" width="' + size + '" height="' + size +
      '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" ' +
      'stroke-linecap="round" stroke-linejoin="round">' + inner + '</svg>';
  };

  // render all [data-ic] placeholders in the static HTML (toolbar, headers)
  window.renderStaticIcons = function () {
    document.querySelectorAll('[data-ic]').forEach(function (el) {
      el.innerHTML = svgIcon(el.getAttribute('data-ic'), 15);
    });
  };
})();
