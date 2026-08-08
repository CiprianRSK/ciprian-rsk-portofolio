/* data.js — declarative definitions for node types, attack scenarios and the demo topology.
   The canvas (canvas.js) renders these; the engine (simulation.js) reasons over them. */
(function () {

  /* ---- Node types ----
     cat:      endpoint | security | threat  (drives colour + behaviour)
     icon:     key into ICONS
     w/h:      node box size on the SVG canvas
     defaults: seed values dropped onto a new instance
     role:     semantic tag the simulation matches scenarios against
     fields:   which inspector fields to show */
  const NODE_TYPES = {
    internet: { cat:'endpoint', label:'Internet / WAN', icon:'internet', role:'internet',
      w:120, h:64, fields:['ip'], defaults:{ ip:'0.0.0.0/0', ports:[], note:'Untrusted external network' } },
    attacker: { cat:'threat', label:'Attacker', icon:'attacker', role:'attacker',
      w:110, h:64, fields:['ip','placement'], defaults:{ ip:'203.0.113.66', placement:'external', ports:[] } },
    router:   { cat:'endpoint', label:'Router', icon:'router', role:'router',
      w:110, h:64, fields:['ip'], defaults:{ ip:'10.0.1.1', ports:[] } },
    switch:   { cat:'endpoint', label:'Switch', icon:'switch', role:'switch',
      w:110, h:60, fields:[], defaults:{ ip:'', ports:[] } },
    pc:       { cat:'endpoint', label:'Workstation', icon:'pc', role:'host',
      w:120, h:64, fields:['ip','ports','hostfw'], defaults:{ ip:'10.0.1.20', ports:[445,139], hostFirewall:false } },
    server:   { cat:'endpoint', label:'Server', icon:'server', role:'host',
      w:120, h:64, fields:['ip','ports','hostfw'], defaults:{ ip:'10.0.1.30', ports:[445,3389,22], hostFirewall:false } },
    web:      { cat:'endpoint', label:'Web Server', icon:'web', role:'host',
      w:120, h:64, fields:['ip','ports','hostfw'], defaults:{ ip:'10.0.9.10', ports:[80,443], hostFirewall:false } },
    db:       { cat:'endpoint', label:'Database', icon:'db', role:'db',
      w:120, h:64, fields:['ip','ports','hostfw'], defaults:{ ip:'10.0.5.10', ports:[1433,3306], hostFirewall:false } },
    dc:       { cat:'endpoint', label:'Domain Controller', icon:'dc', role:'dc',
      w:140, h:64, fields:['ip','ports','hostfw'], defaults:{ ip:'10.0.1.5', ports:[88,389,445,3389], hostFirewall:false } },

    firewall: { cat:'security', label:'Firewall', icon:'firewall', role:'firewall',
      w:120, h:64, fields:['rules'],
      defaults:{ ip:'', ports:[], rules:'ALLOW 10.0.1.0/24 -> 10.0.9.10 : 443\nDENY any -> any : 445\nDENY any -> any : 3389\nDENY any -> any' } },
    ips:      { cat:'security', label:'IPS', icon:'ips', role:'ips',
      w:100, h:60, fields:['note'], defaults:{ ip:'', ports:[], note:'Inline · blocks known signatures' } },
    ids:      { cat:'security', label:'IDS', icon:'ids', role:'ids',
      w:100, h:60, fields:['note'], defaults:{ ip:'', ports:[], note:'Passive · alerts only' } },
    edr:      { cat:'security', label:'EDR Agent', icon:'edr', role:'edr',
      w:110, h:60, fields:['note'], defaults:{ ip:'', ports:[], note:'Protects the host it is wired to' } },
    proxy:    { cat:'security', label:'Proxy / DLP', icon:'proxy', role:'proxy',
      w:110, h:60, fields:['note'], defaults:{ ip:'', ports:[], note:'Inspects outbound web / exfil' } },
    scrubbing:{ cat:'security', label:'DDoS Scrubbing / CDN', icon:'scrub', role:'scrubbing',
      w:140, h:60, fields:['note'], defaults:{ ip:'', ports:[], note:'Upstream · absorbs volumetric floods' } },
  };

  // Palette layout (groups + order)
  const PALETTE = [
    { group:'Endpoints', items:['internet','router','switch','pc','server','web','db','dc'] },
    { group:'Security Controls', items:['firewall','ips','ids','edr','proxy','scrubbing'] },
    { group:'Threat', items:['attacker'] },
  ];

  /* ---- Attack scenarios ----
     srcKind:            external (from internet/attacker) | internal (compromised host)
     targetRole:         which node the attack aims for
     port:               destination port the attack rides on (0 = outbound/any)
     direction:          inbound | east-west | egress
     networkDetectable:  can an inline IPS see & block it?
     endpointDetectable: can EDR on an endpoint see & block it?
     proxyStops:         does an outbound proxy/DLP stop it?
     needsOpenPort:      must the target actually expose `port`? */
  const SCENARIOS = {
    'port-scan': {
      name:'External Port Scan', icon:'crosshair', srcKind:'external', targetRole:'any-host',
      port:0, direction:'inbound', networkDetectable:true, endpointDetectable:false,
      proxyStops:false, needsOpenPort:false,
      desc:'Attacker probes your hosts from the internet for open ports.' },
    'smb-lateral': {
      name:'SMB Lateral Movement', icon:'switch', srcKind:'internal', targetRole:'any-host',
      port:445, direction:'east-west', networkDetectable:true, endpointDetectable:true,
      proxyStops:false, needsOpenPort:true,
      desc:'A compromised host spreads to others over SMB (445).' },
    'rdp-brute': {
      name:'RDP Brute Force', icon:'server', srcKind:'external', targetRole:'any-host',
      port:3389, direction:'inbound', networkDetectable:true, endpointDetectable:true,
      proxyStops:false, needsOpenPort:true,
      desc:'Attacker hammers RDP (3389) to guess credentials.' },
    'kerberoast': {
      name:'AD / Kerberoast', icon:'dc', srcKind:'internal', targetRole:'dc',
      port:88, direction:'east-west', networkDetectable:true, endpointDetectable:false,
      proxyStops:false, needsOpenPort:true,
      desc:'Attacker enumerates the Domain Controller to crack service accounts.' },
    'c2-callback': {
      name:'Ransomware C2 Callback', icon:'crosshair', srcKind:'internal', targetRole:'internet',
      port:443, direction:'egress', networkDetectable:false, endpointDetectable:true,
      proxyStops:true, needsOpenPort:false,
      desc:'Malware on a host beacons out to a command server (hidden in TLS).' },
    'exfil': {
      name:'Data Exfiltration', icon:'db', srcKind:'internal', targetRole:'internet',
      port:443, direction:'egress', networkDetectable:false, endpointDetectable:true,
      proxyStops:true, needsOpenPort:false,
      desc:'Attacker pushes stolen data out to the internet.' },
    'ddos': {
      name:'Volumetric DDoS', icon:'ddos', srcKind:'external', targetRole:'any-host',
      port:0, direction:'inbound', ddos:true, networkDetectable:false, endpointDetectable:false,
      proxyStops:false, needsOpenPort:false,
      desc:'A botnet floods your public host with traffic to knock it offline.' },
  };

  /* ---- Demo topology (a deliberately SOUND, segmented design) ----
     Coordinates are in canvas space; the sim should DROP most attacks here. */
  const DEMO = {
    nodes: [
      { type:'internet', x:80,  y:60,  props:{ ip:'0.0.0.0/0' } },
      { type:'attacker', x:80,  y:200, props:{ ip:'203.0.113.66', placement:'external' } },
      { type:'firewall', x:300, y:120, props:{ rules:'ALLOW any -> 10.0.9.10 : 443\nDENY any -> 10.0.1.0/24\nDENY any -> any : 445\nDENY any -> any : 3389\nDENY any -> any' } },
      { type:'ips',      x:300, y:260, props:{} },
      { type:'web',      x:520, y:60,  props:{ ip:'10.0.9.10', ports:[443] } },
      { type:'router',   x:520, y:200, props:{ ip:'10.0.1.1' } },
      { type:'switch',   x:720, y:200, props:{} },
      { type:'pc',       x:920, y:80,  props:{ ip:'10.0.1.20', ports:[445] } },
      { type:'edr',      x:1080,y:80,  props:{} },
      { type:'dc',       x:920, y:200, props:{ ip:'10.0.1.5', ports:[88,389,445] } },
      { type:'db',       x:920, y:320, props:{ ip:'10.0.5.10', ports:[1433], hostFirewall:true } },
    ],
    // edges reference node indexes above
    edges: [ [0,2],[1,0],[2,3],[3,4],[3,5],[5,6],[6,7],[7,8],[6,9],[6,10] ],
    zones: [
      { label:'DMZ',            cidr:'10.0.9.0/24', x:470, y:20,  w:170, h:96,  isolation:'none' },
      { label:'Internal LAN',   cidr:'10.0.1.0/24', x:690, y:40,  w:470, h:210, isolation:'none' },
      { label:'Restricted DB', cidr:'10.0.5.0/24', x:875, y:288, w:200, h:96,  isolation:'deny-inter-zone' },
    ],
  };

  window.NET = { NODE_TYPES, PALETTE, SCENARIOS, DEMO };
})();
