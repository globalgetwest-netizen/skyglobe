/* SkyGlobe Group — Department Contact Strip + On-Site Message Form
   Every public page shows the professional email of the department that owns
   it. The "Message this department" button opens a premium ON-SITE form (no
   mail app involved) that feeds straight into the AI Reception — answered by
   AI within minutes or escalated to the department's specialists. The address
   itself is click-to-copy for clients who prefer their own email. */
(function () {
  'use strict';
  if (window.__sgDeptContact) return; window.__sgDeptContact = true;

  var DEPTS = {
    travel:    { icon: '🌐', label: 'Global Mobility',           email: 'mobility@skyglobegroup.com' },
    education: { icon: '🎓', label: 'SkyGlobe Academy',          email: 'education@skyglobegroup.com' },
    legal:     { icon: '📜', label: 'Legal & Trust Services',    email: 'legal@skyglobegroup.com' },
    identity:  { icon: '🪪', label: 'Digital Identity',          email: 'id@skyglobegroup.com' },
    finance:   { icon: '💳', label: 'Finance & Payments',        email: 'finance@skyglobegroup.com' },
    innovation:{ icon: '🚀', label: 'Innovation & Technology',   email: 'innovation@skyglobegroup.com' },
    general:   { icon: '📨', label: 'SkyGlobe Group',            email: 'support@skyglobegroup.com' },
  };
  var PAGE_DEPT = {
    'work-permit': 'travel', 'conferences': 'travel', 'packages': 'travel',
    'courses': 'education', 'course-learn': 'education', 'academy-admission': 'education',
    'academy-portal': 'education', 'skyglobe-kids-academy': 'education',
    'legal-documents': 'legal',
    'digital-id': 'identity', 'digitalization': 'innovation', 'id-verify': 'identity',
    'payments': 'finance', 'pay': 'finance',
    'more-services': 'general', 'index': 'general', '': 'general',
  };

  function pageKey() {
    var p = location.pathname.replace(/^\/+|\/+$/g, '').replace(/\.html$/i, '');
    return PAGE_DEPT.hasOwnProperty(p) ? PAGE_DEPT[p] : 'general';
  }

  // Services offered by each department — shown as a selector in the form so
  // the message arrives pre-classified ("according to the system of services
  // of that particular email").
  var SERVICES = {
    travel:    ['Student Visa', 'Work Visa / Permit', 'Tourist / Visit Visa', 'Flight & Hotel Letters', 'Travel Insurance', 'Conference Invitation', 'Other'],
    education: ['Certificate Programs', 'SkyGlobe Academy Admission', 'University Admission', 'Scholarship Support', 'Other'],
    legal:     ['AI Legal Document', 'Notarisation / Apostille', 'Document Verification', 'Other'],
    identity:  ['Premium Digital ID', 'ID Verification', 'Digitalization Services', 'Other'],
    finance:   ['Payment Issue', 'Refund Request', 'Invoice / Receipt', 'Other'],
    innovation:['Digitalization Services', 'Technology Partnership', 'Developer / API Enquiry', 'Product Idea', 'Other'],
    general:   ['General Enquiry', 'Complaint', 'Partnership', 'Other'],
  };
  var EMAIL_DEPT = { 'visas@skyglobegroup.com': 'travel' }; // legacy alias — old address works forever
  Object.keys(DEPTS).forEach(function (k) { EMAIL_DEPT[DEPTS[k].email] = k; });

  var deptKey = null, dept = null;

  function copyAddress(el) {
    var done = function () {
      var old = el.textContent;
      el.textContent = '✓ Copied to clipboard';
      setTimeout(function () { el.textContent = old; }, 1600);
    };
    try { navigator.clipboard.writeText(dept.email).then(done, done); }
    catch (e) { done(); }
  }

  function openForm(forKey) {
    var k = (forKey && DEPTS[forKey]) ? forKey : deptKey;
    var d = DEPTS[k] || DEPTS.general;
    var svcOptions = (SERVICES[k] || SERVICES.general)
      .map(function (sv) { return '<option>' + sv + '</option>'; }).join('');
    var existing = document.getElementById('sgdcModal');
    if (existing) existing.remove();
    var m = document.createElement('div');
    m.id = 'sgdcModal';
    m.style.cssText = 'position:fixed;inset:0;z-index:99995;background:rgba(4,8,18,.78);backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);display:flex;align-items:center;justify-content:center;padding:18px';
    m.innerHTML =
      '<div style="position:relative;width:min(480px,96vw);background:linear-gradient(160deg,#0e1730,#0b1120);border:1px solid rgba(212,167,58,.35);border-radius:18px;padding:26px 24px;box-shadow:0 30px 80px rgba(0,0,0,.6);font-family:\'Segoe UI\',system-ui,sans-serif;color:#eef2fb">' +
      '<button id="sgdcX" aria-label="Close" style="position:absolute;top:12px;right:12px;width:32px;height:32px;border-radius:50%;border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.05);color:#8fa0c0;cursor:pointer;font-size:.85rem;line-height:1">✕</button>' +
      '<div style="font-size:.64rem;font-weight:800;letter-spacing:.24em;text-transform:uppercase;color:#e9c86a;margin-bottom:4px">' + d.icon + ' ' + d.label + '</div>' +
      '<h3 style="margin:0 0 4px;font-size:1.2rem">Message this department</h3>' +
      '<p style="margin:0 0 16px;font-size:.78rem;color:#8fa0c0;line-height:1.5">Delivered instantly to our AI concierge — you\'ll get a reply by email within minutes, and a specialist follows up personally when needed.</p>' +
      '<div id="sgdcBody">' +
      '<input id="sgdcName" placeholder="Your full name" style="width:100%;margin-bottom:10px;padding:12px 14px;border-radius:10px;border:1px solid rgba(255,255,255,.14);background:rgba(255,255,255,.05);color:#eef2fb;font-size:.9rem;font-family:inherit;box-sizing:border-box">' +
      '<input id="sgdcEmail" type="email" placeholder="Your email address" style="width:100%;margin-bottom:10px;padding:12px 14px;border-radius:10px;border:1px solid rgba(255,255,255,.14);background:rgba(255,255,255,.05);color:#eef2fb;font-size:.9rem;font-family:inherit;box-sizing:border-box">' +
      '<select id="sgdcSvc" style="width:100%;margin-bottom:10px;padding:12px 14px;border-radius:10px;border:1px solid rgba(255,255,255,.14);background:#141d36;color:#eef2fb;font-size:.9rem;font-family:inherit;box-sizing:border-box">' +
      '<option value="">— Which service is this about? —</option>' + svcOptions + '</select>' +
      '<textarea id="sgdcMsg" placeholder="How can we help? Include your application reference if you have one." style="width:100%;min-height:110px;margin-bottom:6px;padding:12px 14px;border-radius:10px;border:1px solid rgba(255,255,255,.14);background:rgba(255,255,255,.05);color:#eef2fb;font-size:.9rem;font-family:inherit;line-height:1.5;box-sizing:border-box;resize:vertical"></textarea>' +
      '<div id="sgdcErr" style="display:none;color:#ff9c9c;font-size:.78rem;margin-bottom:8px"></div>' +
      '<button id="sgdcSend" style="width:100%;padding:13px;border:none;border-radius:11px;background:linear-gradient(135deg,#f7d774,#e4b132);color:#181000;font-weight:800;font-size:.9rem;cursor:pointer;box-shadow:0 8px 22px rgba(228,177,50,.35);font-family:inherit">Send message</button>' +
      '<div style="text-align:center;margin-top:12px;font-size:.72rem;color:#8fa0c0">or write from your own email: <b class="sgdc-copyonly" data-mail="' + d.email + '" title="Click to copy" style="color:#c9d4ea;cursor:copy">' + d.email + '</b></div>' +
      '</div></div>';
    m.addEventListener('click', function (e) { if (e.target === m) m.remove(); });
    document.body.appendChild(m);
    document.getElementById('sgdcX').onclick = function () { m.remove(); };
    document.getElementById('sgdcSend').onclick = function () {
      var name = document.getElementById('sgdcName').value.trim();
      var email = document.getElementById('sgdcEmail').value.trim();
      var msg = document.getElementById('sgdcMsg').value.trim();
      var err = document.getElementById('sgdcErr');
      if (!name || !email || !msg) { err.textContent = 'Please fill in your name, email and message.'; err.style.display = 'block'; return; }
      var btn = document.getElementById('sgdcSend');
      btn.disabled = true; btn.textContent = 'Sending…';
      fetch('/api/dept-message', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ dept: k, name: name, email: email,
          message: (document.getElementById('sgdcSvc').value ? 'Service: ' + document.getElementById('sgdcSvc').value + '\n\n' : '') + msg }),
      }).then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
        .then(function (res) {
          if (!res.ok) throw new Error((res.d && res.d.error) || 'Could not send. Please try again.');
          document.getElementById('sgdcBody').innerHTML =
            '<div style="text-align:center;padding:26px 6px">' +
            '<div style="font-size:2.4rem;margin-bottom:10px">✅</div>' +
            '<div style="font-weight:700;font-size:1.02rem;margin-bottom:6px">Message received</div>' +
            '<div style="font-size:.8rem;color:#8fa0c0;line-height:1.6">Our AI concierge is already reading it — check <b style="color:#c9d4ea">' + email.replace(/</g, '&lt;') + '</b> for a reply within minutes. A ' + d.label + ' specialist follows up personally if your case needs one.</div>' +
            '</div>';
        })
        .catch(function (e) { err.textContent = e.message; err.style.display = 'block'; btn.disabled = false; btn.textContent = 'Send message'; });
    };
  }

  function mount() {
    deptKey = pageKey(); dept = DEPTS[deptKey] || DEPTS.general;
    var footer = document.querySelector('footer');
    var strip = document.createElement('div');
    strip.setAttribute('role', 'complementary');
    strip.style.cssText = 'background:linear-gradient(135deg,#0b1120,#131c33);border-top:1px solid rgba(212,167,58,.25);padding:26px 20px;text-align:center;font-family:"Segoe UI",system-ui,sans-serif';
    strip.innerHTML =
      '<div style="max-width:820px;margin:0 auto;display:flex;align-items:center;justify-content:center;gap:14px;flex-wrap:wrap">' +
      '<span style="font-size:1.5rem">' + dept.icon + '</span>' +
      '<div style="text-align:left;min-width:0">' +
        '<div style="font-size:.66rem;font-weight:800;letter-spacing:.22em;text-transform:uppercase;color:#e9c86a">' + dept.label + ' · Direct line</div>' +
        '<span id="sgdcAddr" title="Click to copy" style="color:#eef2fb;font-weight:700;font-size:1.02rem;cursor:copy;word-break:break-all">' + dept.email + '</span>' +
        '<div style="font-size:.72rem;color:#8fa0c0;margin-top:2px">AI-assisted inbox — answered 24/7, escalated to our specialists when needed. Click any address to message that department right here.</div>' +
      '</div>' +
      '<button id="sgdcOpen" style="flex-shrink:0;border:none;background:linear-gradient(135deg,#f7d774,#e4b132);color:#181000;font-size:.8rem;font-weight:800;padding:11px 20px;border-radius:999px;cursor:pointer;box-shadow:0 6px 18px rgba(228,177,50,.35);font-family:inherit">💬 Message this department</button>' +
      '</div>' +
      '<button id="sgdcAllBtn" style="margin-top:14px;background:none;border:none;color:#8fa0c0;font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;cursor:pointer;font-family:inherit">▾ View all department contacts</button>' +
      '<div id="sgdcAll" style="display:none;max-width:820px;margin:12px auto 0;display:none;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:8px">' +
      Object.keys(DEPTS).map(function (k) {
        var d2 = DEPTS[k];
        return '<div class="sgdc-chip" data-mail="' + d2.email + '" title="Click to copy" style="cursor:copy;display:flex;align-items:center;gap:8px;padding:10px 13px;border-radius:11px;background:#182342;border:1px solid rgba(212,167,58,.4);text-align:left;box-shadow:0 3px 10px rgba(0,0,0,.3)">' +
          '<span style="font-size:1.05rem">' + d2.icon + '</span><div style="min-width:0"><div style="font-size:.62rem;font-weight:800;letter-spacing:.1em;text-transform:uppercase;color:#f0c75e">' + d2.label + '</div>' +
          '<div style="font-size:.8rem;color:#ffffff;font-weight:700;word-break:break-all">' + d2.email + '</div></div></div>';
      }).join('') +
      '</div>';
    if (footer && footer.parentNode) footer.parentNode.insertBefore(strip, footer);
    else document.body.appendChild(strip);
    document.getElementById('sgdcOpen').addEventListener('click', function () { openForm(); });
    var addr = document.getElementById('sgdcAddr');
    addr.setAttribute('title', 'Click to message this department');
    addr.style.cursor = 'pointer';
    addr.addEventListener('click', function () { openForm(); });
    // Full directory toggle + click-to-copy chips
    var allBtn = document.getElementById('sgdcAllBtn'), all = document.getElementById('sgdcAll');
    allBtn.addEventListener('click', function () {
      var open = all.style.display !== 'none';
      all.style.display = open ? 'none' : 'grid';
      allBtn.textContent = open ? '▾ View all department contacts' : '▴ Hide department contacts';
    });
    // chips are handled by the delegated click handler (opens that dept's form)
  }

  // Site-wide behavior for every listed address & number — all inside the
  // website, never an app chooser:
  //  · click a department EMAIL  → that department's message form opens here
  //  · click the copy-only line inside the form → address copied
  //  · click the PHONE number    → dials on mobile, copies on desktop
  document.addEventListener('click', function (e) {
    if (!e.target.closest) return;
    var copyEl = e.target.closest('.sgdc-copyonly[data-mail]');
    if (copyEl) {
      e.preventDefault();
      var mail0 = copyEl.getAttribute('data-mail');
      var done0 = function () {
        var old0 = copyEl.textContent;
        copyEl.textContent = '✓ Copied';
        setTimeout(function () { copyEl.textContent = old0; }, 1400);
      };
      try { navigator.clipboard.writeText(mail0).then(done0, done0); } catch (err) { done0(); }
      return;
    }
    var el = e.target.closest('.sg-copy[data-mail], .sgdc-chip[data-mail]');
    if (el) {
      e.preventDefault();
      var mail = el.getAttribute('data-mail');
      openForm(EMAIL_DEPT[mail] || 'general');
      return;
    }
    var tel = e.target.closest('.sg-tel[data-tel]');
    if (tel) {
      var num = tel.getAttribute('data-tel');
      if (window.matchMedia && window.matchMedia('(pointer:coarse)').matches) {
        location.href = 'tel:' + num; // phones: place the call
        return;
      }
      e.preventDefault(); // desktops: copy, never an app chooser
      var done = function () {
        var old = tel.textContent;
        tel.textContent = '✓ Copied: ' + num;
        setTimeout(function () { tel.textContent = old; }, 1600);
      };
      try { navigator.clipboard.writeText(num).then(done, done); } catch (err) { done(); }
    }
  });

  // ── PAGE NAVIGATION — Back / Next on every page ─────────────────────────
  // Premium floating pair (bottom-left): ‹ returns to the previous page,
  // › goes forward again. Works with the browser history, so it respects
  // both real page changes and in-page navigation.
  function mountNav() {
    if (document.getElementById('sgNavPair')) return;
    if (document.querySelector('.nav-arrows')) return; // page has its own site-wide pair
    var wrap = document.createElement('div');
    wrap.id = 'sgNavPair';
    wrap.style.cssText = 'position:fixed;left:14px;bottom:14px;z-index:99990;display:flex;gap:8px';
    function mkBtn(label, title, fn) {
      var b = document.createElement('button');
      b.textContent = label;
      b.setAttribute('aria-label', title); b.title = title;
      b.style.cssText = 'width:42px;height:42px;border-radius:50%;border:1px solid rgba(212,167,58,.45);background:rgba(7,17,35,.88);backdrop-filter:blur(6px);color:#e9c86a;font-size:1.15rem;font-weight:700;cursor:pointer;box-shadow:0 6px 18px rgba(0,0,0,.4);line-height:1;transition:transform .15s';
      b.onmouseover = function(){ b.style.transform='scale(1.08)'; };
      b.onmouseout = function(){ b.style.transform=''; };
      b.onclick = fn;
      return b;
    }
    wrap.appendChild(mkBtn('‹', 'Back to previous page', function(){ history.back(); }));
    wrap.appendChild(mkBtn('›', 'Forward', function(){ history.forward(); }));
    document.body.appendChild(wrap);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function(){ mount(); mountNav(); });
  else { mount(); mountNav(); }
})();
