/* SkyGlobe Group — Premium Announcement Widget
   One script, dropped into every public page. Fetches live announcements,
   renders them as an elegant top banner or a slide-in toast (CEO's choice
   per announcement), remembers what each visitor dismissed, reports
   impressions / clicks / dismissals back for the admin analytics panel,
   and quietly re-checks every 2 minutes so new announcements appear
   without a page reload. */
(function () {
  'use strict';
  if (window.__sgAnnLoaded) return; window.__sgAnnLoaded = true;

  var LS_KEY = 'sg_ann_dismissed';
  var SS_SEEN = 'sg_ann_seen';
  var MAX_BANNERS = 2, MAX_TOASTS = 2, POLL_MS = 120000;

  function lsGet(k, fb) { try { return JSON.parse(localStorage.getItem(k)) || fb; } catch (e) { return fb; } }
  function lsSet(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} }
  function ssGet(k, fb) { try { return JSON.parse(sessionStorage.getItem(k)) || fb; } catch (e) { return fb; } }
  function ssSet(k, v) { try { sessionStorage.setItem(k, JSON.stringify(v)); } catch (e) {} }
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]; }); }
  function track(id, action) {
    try {
      var body = JSON.stringify({ action: action });
      if (navigator.sendBeacon) navigator.sendBeacon('/api/announcements/' + id + '/track', new Blob([body], { type: 'application/json' }));
      else fetch('/api/announcements/' + id + '/track', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body, keepalive: true }).catch(function () {});
    } catch (e) {}
  }

  /* Type palettes — info (sapphire), success (emerald), warning (amber),
     urgent (crimson). Dark glass, gold-family accents, readable everywhere. */
  var TYPES = {
    info:    { edge: '#4f8ef7', glow: 'rgba(79,142,247,.32)',  chipBg: 'rgba(79,142,247,.16)',  chipTx: '#9cc0ff', label: 'Update'    },
    success: { edge: '#2ecc8f', glow: 'rgba(46,204,143,.30)',  chipBg: 'rgba(46,204,143,.15)',  chipTx: '#8fe8c5', label: 'Good news' },
    warning: { edge: '#f5b942', glow: 'rgba(245,185,66,.30)',  chipBg: 'rgba(245,185,66,.16)',  chipTx: '#ffd98a', label: 'Notice'    },
    urgent:  { edge: '#f0564f', glow: 'rgba(240,86,79,.34)',   chipBg: 'rgba(240,86,79,.16)',   chipTx: '#ffa39e', label: 'Important' }
  };

  var css = ''
    + '.sgann-wrap{position:fixed;top:16px;left:50%;transform:translateX(-50%);z-index:99990;display:flex;flex-direction:column;gap:12px;width:min(720px,calc(100vw - 28px));pointer-events:none}'
    + '.sgann-toastwrap{position:fixed;bottom:22px;right:22px;z-index:99990;display:flex;flex-direction:column;gap:12px;width:min(400px,calc(100vw - 28px));pointer-events:none}'
    + '@media(max-width:520px){.sgann-toastwrap{right:14px;bottom:14px}}'
    + '.sgann{pointer-events:auto;position:relative;display:flex;align-items:center;gap:14px;padding:15px 18px 15px 20px;border-radius:16px;'
    +   'background:linear-gradient(135deg,rgba(16,22,38,.94),rgba(24,32,54,.94));backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);'
    +   'border:1px solid rgba(255,255,255,.09);box-shadow:0 18px 48px rgba(0,0,0,.45),0 2px 10px rgba(0,0,0,.28);'
    +   'color:#eef2fb;font-family:"Segoe UI",system-ui,-apple-system,sans-serif;overflow:hidden}'
    + '.sgann::before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;border-radius:4px 0 0 4px;background:var(--sgann-edge)}'
    + '.sgann::after{content:"";position:absolute;inset:0;pointer-events:none;background:radial-gradient(120% 160% at 0% 0%,var(--sgann-glow),transparent 55%)}'
    + '.sgann-banner{animation:sgannDrop .55s cubic-bezier(.22,1.2,.36,1) both}'
    + '.sgann-toast{animation:sgannSlide .5s cubic-bezier(.22,1.2,.36,1) both}'
    + '@keyframes sgannDrop{from{opacity:0;transform:translateY(-26px) scale(.97)}to{opacity:1;transform:translateY(0) scale(1)}}'
    + '@keyframes sgannSlide{from{opacity:0;transform:translateX(46px) scale(.97)}to{opacity:1;transform:translateX(0) scale(1)}}'
    + '.sgann-leave{transition:opacity .3s ease,transform .3s ease;opacity:0!important;transform:translateY(-14px) scale(.97)!important}'
    + '.sgann-ico{flex:0 0 auto;width:46px;height:46px;display:flex;align-items:center;justify-content:center;font-size:1.45rem;'
    +   'background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.10);border-radius:13px;position:relative;z-index:1}'
    + '.sgann-body{flex:1 1 auto;min-width:0;position:relative;z-index:1}'
    + '.sgann-tagrow{display:flex;align-items:center;gap:8px;margin-bottom:4px;flex-wrap:wrap}'
    + '.sgann-chip{display:inline-flex;align-items:center;gap:5px;font-size:.62rem;font-weight:800;letter-spacing:.09em;text-transform:uppercase;'
    +   'padding:3px 9px;border-radius:999px;background:var(--sgann-chipbg);color:var(--sgann-chiptx)}'
    + '.sgann-dot{width:6px;height:6px;border-radius:50%;background:var(--sgann-edge);animation:sgannPulse 1.8s ease-in-out infinite}'
    + '@keyframes sgannPulse{0%,100%{opacity:1;box-shadow:0 0 0 0 var(--sgann-glow)}50%{opacity:.55;box-shadow:0 0 0 5px transparent}}'
    + '.sgann-title{font-size:.95rem;font-weight:700;line-height:1.35;letter-spacing:.01em}'
    + '.sgann-sub{font-size:.8rem;color:#aab6d0;line-height:1.45;margin-top:2px}'
    + '.sgann-cta{flex:0 0 auto;position:relative;z-index:1;display:inline-block;padding:9px 16px;border-radius:10px;border:none;cursor:pointer;'
    +   'font-size:.78rem;font-weight:800;letter-spacing:.02em;color:#181000;background:linear-gradient(135deg,#f7d774,#e4b132);'
    +   'box-shadow:0 4px 14px rgba(228,177,50,.35);transition:transform .18s ease,box-shadow .18s ease;white-space:nowrap;text-decoration:none}'
    + '.sgann-cta:hover{transform:translateY(-1px);box-shadow:0 7px 20px rgba(228,177,50,.5)}'
    + '.sgann-x{flex:0 0 auto;position:relative;z-index:1;width:28px;height:28px;display:flex;align-items:center;justify-content:center;'
    +   'border-radius:50%;border:1px solid rgba(255,255,255,.14);background:rgba(255,255,255,.05);color:#8f9bb5;cursor:pointer;'
    +   'font-size:.8rem;line-height:1;transition:all .18s ease;padding:0}'
    + '.sgann-x:hover{background:rgba(255,255,255,.13);color:#fff;transform:rotate(90deg)}'
    + '.sgann-urgentbar{position:absolute;top:0;left:0;right:0;height:2px;overflow:hidden;z-index:1}'
    + '.sgann-urgentbar span{display:block;height:100%;width:40%;background:linear-gradient(90deg,transparent,var(--sgann-edge),transparent);animation:sgannSheen 2.4s linear infinite}'
    + '@keyframes sgannSheen{from{transform:translateX(-120%)}to{transform:translateX(360%)}}'
    + '@media(max-width:560px){.sgann{flex-wrap:wrap;padding:14px 15px}.sgann-ico{width:40px;height:40px;font-size:1.25rem;border-radius:11px}'
    +   '.sgann-cta{flex-basis:100%;text-align:center;margin-top:2px}.sgann-title{font-size:.88rem}.sgann-sub{font-size:.76rem}}'
    + '@media(prefers-reduced-motion:reduce){.sgann-banner,.sgann-toast,.sgann-dot,.sgann-urgentbar span{animation:none}}';

  var styleEl = document.createElement('style'); styleEl.textContent = css;
  var bannerWrap, toastWrap, rendered = {};

  function ensureRoots() {
    if (!document.head.contains(styleEl)) document.head.appendChild(styleEl);
    if (!bannerWrap) { bannerWrap = document.createElement('div'); bannerWrap.className = 'sgann-wrap'; }
    if (!toastWrap) { toastWrap = document.createElement('div'); toastWrap.className = 'sgann-toastwrap'; }
    if (!document.body.contains(bannerWrap)) document.body.appendChild(bannerWrap);
    if (!document.body.contains(toastWrap)) document.body.appendChild(toastWrap);
  }

  function buildCard(a, mode) {
    var t = TYPES[a.type] || TYPES.info;
    var el = document.createElement('div');
    el.className = 'sgann ' + (mode === 'toast' ? 'sgann-toast' : 'sgann-banner');
    el.style.setProperty('--sgann-edge', t.edge);
    el.style.setProperty('--sgann-glow', t.glow);
    el.style.setProperty('--sgann-chipbg', t.chipBg);
    el.style.setProperty('--sgann-chiptx', t.chipTx);
    var chipText = a.tag ? a.tag : t.label;
    el.innerHTML =
      (a.type === 'urgent' ? '<div class="sgann-urgentbar"><span></span></div>' : '')
      + '<div class="sgann-ico">' + esc(a.icon || '📣') + '</div>'
      + '<div class="sgann-body">'
      +   '<div class="sgann-tagrow"><span class="sgann-chip"><span class="sgann-dot"></span>' + esc(chipText) + '</span></div>'
      +   '<div class="sgann-title">' + esc(a.headline) + '</div>'
      +   (a.subtext ? '<div class="sgann-sub">' + esc(a.subtext) + '</div>' : '')
      + '</div>'
      + (a.button_text ? '<a class="sgann-cta" href="' + esc(a.button_link || '#') + '">' + esc(a.button_text) + ' →</a>' : '')
      + '<button class="sgann-x" aria-label="Dismiss">✕</button>';

    var cta = el.querySelector('.sgann-cta');
    if (cta) cta.addEventListener('click', function () { track(a.id, 'click'); });
    el.querySelector('.sgann-x').addEventListener('click', function () {
      var dismissed = lsGet(LS_KEY, []);
      if (dismissed.indexOf(a.id) === -1) { dismissed.push(a.id); lsSet(LS_KEY, dismissed.slice(-80)); }
      track(a.id, 'dismiss');
      el.classList.add('sgann-leave');
      setTimeout(function () { el.remove(); delete rendered[a.id]; }, 320);
    });
    return el;
  }

  function render(list) {
    ensureRoots();
    var dismissed = lsGet(LS_KEY, []);
    var seen = ssGet(SS_SEEN, []);
    var banners = 0, toasts = 0;
    list.forEach(function (a) {
      if (!a || a.id == null || rendered[a.id]) return;
      if (dismissed.indexOf(a.id) !== -1) return;
      var mode = a.display_mode === 'toast' ? 'toast' : 'banner';
      if (mode === 'banner' && banners >= MAX_BANNERS) return;
      if (mode === 'toast' && toasts >= MAX_TOASTS) return;
      if (mode === 'banner') banners++; else toasts++;
      var el = buildCard(a, mode);
      (mode === 'toast' ? toastWrap : bannerWrap).appendChild(el);
      rendered[a.id] = true;
      if (seen.indexOf(a.id) === -1) { seen.push(a.id); track(a.id, 'view'); }
    });
    ssSet(SS_SEEN, seen.slice(-120));
  }

  function refresh() {
    fetch('/api/announcements').then(function (r) { return r.json(); }).then(function (list) {
      if (Array.isArray(list)) render(list);
    }).catch(function () {});
  }

  function start() { refresh(); setInterval(refresh, POLL_MS); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
