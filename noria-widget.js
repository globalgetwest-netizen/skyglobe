/* SkyGlobe Group — shared NORIA identity strip widget.
   One file, included on any page with:
     <script src="/noria-widget.js"></script>
   Replaces the ~470-line inline copy that used to be duplicated on every
   page that carries NORIA (conferences.html, work-permit.html,
   digitalization.html, packages.html, and now the SkyGlobe Academy pages) —
   same look, same behaviour, one source of truth, far less page weight. */
(function () {
  var css =
    '@keyframes nSlide{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}' +
    '@keyframes nGp{0%,100%{filter:drop-shadow(0 0 0 rgba(212,167,58,0))}50%{filter:drop-shadow(0 0 9px rgba(212,167,58,.55))}}' +
    '@keyframes aiDot{0%,80%,100%{transform:scale(.6);opacity:.4}40%{transform:scale(1);opacity:1}}' +
    '.noria-strip{background:linear-gradient(180deg,#06101d,#0d1a2e);border-bottom:1px solid rgba(212,167,58,.18);padding:9px 20px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;animation:nSlide .6s .2s both}' +
    '.noria-strip-brand{display:flex;align-items:center;gap:8px;flex-shrink:0}' +
    '.noria-strip-brand svg{animation:nGp 3s ease-in-out 1s 2}' +
    '.noria-strip-wm{font-family:Inter,system-ui,sans-serif;font-size:.8rem;font-weight:800;letter-spacing:.22em;background:linear-gradient(135deg,#D4A73A,#F4D77A 50%,#0ea5e9);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;text-transform:uppercase}' +
    '.noria-strip-tag{font-size:.48rem;letter-spacing:.14em;color:rgba(180,200,230,.35);text-transform:uppercase;margin-top:1px}' +
    '.noria-strip-row{flex:1;display:flex;align-items:center;gap:7px;background:rgba(255,255,255,.05);border:1px solid rgba(212,167,58,.2);border-radius:100px;padding:6px 6px 6px 16px;max-width:600px;min-width:0}' +
    '.noria-strip-row:focus-within{border-color:rgba(212,167,58,.5);box-shadow:0 0 0 2px rgba(212,167,58,.1)}' +
    '.noria-strip-input{flex:1;border:none;outline:none;background:transparent;font-size:.82rem;color:#dce8ff;font-family:Inter,system-ui,sans-serif;min-width:0}' +
    '.noria-strip-input::placeholder{color:rgba(180,200,230,.38)}' +
    '.noria-strip-btn{background:linear-gradient(135deg,#D4A73A,#F4D77A);border:none;border-radius:100px;width:28px;height:28px;cursor:pointer;display:flex;align-items:center;justify-content:center;flex-shrink:0;transition:opacity .2s}' +
    '.noria-strip-btn:hover{opacity:.85}' +
    '.noria-strip-live{font-size:.58rem;color:#22c55e;letter-spacing:.1em;text-transform:uppercase;display:flex;align-items:center;gap:4px;flex-shrink:0;margin-left:auto}' +
    '.noria-strip-live::before{content:"";width:5px;height:5px;border-radius:50%;background:#22c55e;animation:pulse 2s infinite}' +
    '@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(1.4)}}' +
    '.noria-overlay{display:none;position:fixed;inset:0;z-index:9800;background:rgba(4,16,34,.88);backdrop-filter:blur(12px);align-items:flex-start;padding-top:10vh}' +
    '.noria-overlay.open{display:flex;justify-content:center}' +
    '.noria-overlay-panel{width:min(680px,92vw);background:#0d1a2e;border:1px solid rgba(212,167,58,.25);border-radius:20px;overflow:hidden;box-shadow:0 32px 80px rgba(0,0,0,.7)}' +
    '.noria-ov-header{display:flex;align-items:center;gap:10px;padding:14px 18px;border-bottom:1px solid rgba(255,255,255,.07)}' +
    '.noria-ov-title{font-family:Inter,system-ui;font-size:.85rem;font-weight:700;letter-spacing:.18em;background:linear-gradient(135deg,#D4A73A,#F4D77A 50%,#0ea5e9);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;text-transform:uppercase}' +
    '.noria-ov-tag{font-size:.5rem;letter-spacing:.12em;color:rgba(180,200,230,.38);text-transform:uppercase}' +
    '.noria-ov-close{margin-left:auto;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);color:rgba(200,214,240,.55);border-radius:100px;padding:5px 12px;font-size:.75rem;cursor:pointer;font-family:Inter,sans-serif}' +
    '.noria-ov-msgs{height:40vh;overflow-y:auto;padding:14px 18px;display:flex;flex-direction:column;gap:10px}' +
    '.noria-ov-msgs::-webkit-scrollbar{width:3px}' +
    '.noria-ov-msgs::-webkit-scrollbar-thumb{background:rgba(212,167,58,.3);border-radius:2px}' +
    '.noria-ov-msg{max-width:78%;padding:9px 14px;border-radius:12px;font-size:.84rem;line-height:1.56;font-family:Inter,system-ui;animation:nSlide .3s ease both}' +
    '.noria-ov-msg.user{align-self:flex-end;background:rgba(212,167,58,.14);border:1px solid rgba(212,167,58,.26);color:#f0e6c0}' +
    '.noria-ov-msg.bot{align-self:flex-start;background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.09);color:#d4e2ff}' +
    '.noria-ov-foot{display:flex;gap:7px;padding:10px 18px;border-top:1px solid rgba(255,255,255,.07)}' +
    '.noria-ov-inp{flex:1;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.12);border-radius:100px;padding:8px 16px;color:#dce8ff;font-size:.85rem;outline:none;font-family:Inter,system-ui}' +
    '.noria-ov-inp:focus{border-color:rgba(212,167,58,.45)}' +
    '.noria-ov-inp::placeholder{color:rgba(180,200,230,.38)}';
  document.head.insertAdjacentHTML('beforeend', '<style>' + css + '</style>');

  // Real NORIA logo — four-pointed compass-star, gold fading to blue.
  var logoSvg =
    '<svg width="32" height="32" viewBox="0 0 40 40">' +
    '<defs><linearGradient id="nWidgetGrad" x1="0.72" y1="0.12" x2="0.28" y2="0.88">' +
    '<stop offset="0%" stop-color="#FDBE2D"/><stop offset="34%" stop-color="#F77F1B"/>' +
    '<stop offset="62%" stop-color="#2E7FD4"/><stop offset="100%" stop-color="#1B57C8"/></linearGradient>' +
    '<linearGradient id="nWidgetGold" x1="0" y1="0" x2="0" y2="1">' +
    '<stop offset="0%" stop-color="#FFD968"/><stop offset="100%" stop-color="#F39A1B"/></linearGradient></defs>' +
    '<path d="M20 0.8 C21.2 15.2,24.8 18.8,39.2 20 C24.8 21.2,21.2 24.8,20 39.2 C18.8 24.8,15.2 21.2,0.8 20 C15.2 18.8,18.8 15.2,20 0.8 Z" fill="url(#nWidgetGrad)"/>' +
    '<path d="M20 14.4 C20.48 18.8,21.2 19.52,25.6 20 C21.2 20.48,20.48 21.2,20 25.6 C19.52 21.2,18.8 20.48,14.4 20 C18.8 19.52,19.52 18.8,20 14.4 Z" fill="url(#nWidgetGold)"/>' +
    '</svg>';
  var sendIcon = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#041022" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>';

  var stripHtml =
    '<div class="noria-strip"><div class="noria-strip-brand">' + logoSvg +
    '<div><div class="noria-strip-wm">NORIA</div><div class="noria-strip-tag">Intelligence \xB7 Innovation \xB7 Impact</div></div></div>' +
    '<div class="noria-strip-row"><input class="noria-strip-input" id="noriaStripInput" type="text" autocomplete="off" placeholder="Ask NORIA — visas, work permits, study abroad, travel..." onkeydown="if(event.key===\'Enter\')window.noriaStripAsk()"/>' +
    '<button class="noria-strip-btn" onclick="window.noriaStripAsk()">' + sendIcon + '</button></div>' +
    '<div class="noria-strip-live">LIVE</div></div>' +
    '<div class="noria-overlay" id="noriaOverlay" onclick="if(event.target===this)window.noriaOvClose()">' +
    '<div class="noria-overlay-panel"><div class="noria-ov-header">' + logoSvg +
    '<div><div class="noria-ov-title">NORIA</div><div class="noria-ov-tag">AI Intelligence \xB7 SkyGlobe Group</div></div>' +
    '<button class="noria-ov-close" onclick="window.noriaOvClose()">✕ Close</button></div>' +
    '<div class="noria-ov-msgs" id="noriaOvMsgs"></div>' +
    '<div class="noria-ov-foot"><input class="noria-ov-inp" id="noriaOvInput" type="text" autocomplete="off" placeholder="Ask NORIA anything..." onkeydown="if(event.key===\'Enter\')window.noriaOvSend()"/>' +
    '<button class="noria-strip-btn" onclick="window.noriaOvSend()">' + sendIcon + '</button></div></div></div>';

  function mount() {
    var anchor = document.querySelector('.topnav') || document.querySelector('header') || document.body;
    anchor.insertAdjacentHTML('afterend', stripHtml);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount);
  else mount();

  var _nh = [], _nb = false;
  function _addMsg(t, r, id) {
    var c = document.getElementById('noriaOvMsgs');
    if (!c) return;
    var d = document.createElement('div');
    d.className = 'noria-ov-msg ' + r;
    if (id) d.id = id;
    d.innerHTML = t.replace(/\n/g, '<br>').replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    c.appendChild(d);
    c.scrollTop = c.scrollHeight;
  }
  function _open() {
    var o = document.getElementById('noriaOverlay');
    if (!o) return;
    o.classList.add('open');
    if (!_nh.length) _addMsg('👋 Hello! I\'m <strong>NORIA</strong> — SkyGlobe Group\'s AI Intelligence Assistant. Ask me about visas, work permits, university admissions, conferences, scholarships, travel documentation and all our services.', 'bot');
  }
  window.noriaOvOpen = _open; // public hook — ecosystem cards & links can open NORIA
  window.noriaOvClose = function () {
    var o = document.getElementById('noriaOverlay');
    if (o) o.classList.remove('open');
  };
  async function _ask(q) {
    if (!q || _nb) return;
    _nb = true; _open(); _addMsg(q, 'user');
    _addMsg('<span style="display:inline-flex;gap:3px"><span style="width:6px;height:6px;border-radius:50%;background:#D4A73A;animation:aiDot 1.2s infinite 0s"></span><span style="width:6px;height:6px;border-radius:50%;background:#D4A73A;animation:aiDot 1.2s infinite .2s"></span><span style="width:6px;height:6px;border-radius:50%;background:#D4A73A;animation:aiDot 1.2s infinite .4s"></span></span>', 'bot', 'noriaOvTyping');
    try {
      var r = await fetch('/api/noria', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ message: q, history: _nh.slice(-10) }) });
      var d = await r.json();
      document.getElementById('noriaOvTyping')?.remove();
      var rep = d.reply || 'Please WhatsApp us at +1 737-399-8522.';
      _addMsg(rep, 'bot');
      _nh.push({ role: 'user', parts: [{ text: q }] }, { role: 'model', parts: [{ text: rep }] });
      if (_nh.length > 30) _nh = _nh.slice(-30);
    } catch (e) {
      document.getElementById('noriaOvTyping')?.remove();
      _addMsg('⚡ Reconnecting — please try again.', 'bot');
    }
    _nb = false;
  }
  window.noriaStripAsk = function () {
    var i = document.getElementById('noriaStripInput');
    var q = (i?.value || '').trim();
    if (!q) return;
    i.value = ''; _ask(q);
  };
  window.noriaOvSend = function () {
    var i = document.getElementById('noriaOvInput');
    var q = (i?.value || '').trim();
    if (!q) return;
    i.value = ''; _ask(q);
  };
})();
