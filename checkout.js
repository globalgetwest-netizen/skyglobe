/* ═══════════════════════════════════════════════════════════════════════
   SkyGlobe Group — shared checkout widget
   ───────────────────────────────────────────────────────────────────────
   Drop <script src="/checkout.js"></script> on any page, then call:

     SGCheckout.open({
       product: 'work_permit_standard',   // a key from server.js PRICING
       email:   'client@email.com',       // required
       appRef:  'SKY-2026-ABCD',          // optional — links payment to an application
       currency: 'USD'                    // optional, defaults to USD
     });

   This calls the SAME /api/pay/init your card providers already use.
   Today the only always-on provider is "grey" (bank transfer / USDC / USDT via
   SkyGlobe's Grey account) — the user is redirected to /pay.html, pre-filled
   with their reference, amount, currency and the service they're paying for.
   The moment Stripe/Wise/Paystack/Flutterwave keys are added on the server,
   they appear here automatically — no page needs to change.
   ═══════════════════════════════════════════════════════════════════════ */
(function (global) {
  var PROVIDER_LABELS = {
    grey: '🏦 Bank Transfer / USDC / USDT',
    paystack: '💳 Card (Paystack)',
    stripe: '💳 Card (Stripe)',
    flutterwave: '💳 Card (Flutterwave)',
  };

  function el(tag, attrs, html) {
    var e = document.createElement(tag);
    if (attrs) for (var k in attrs) e.setAttribute(k, attrs[k]);
    if (html != null) e.innerHTML = html;
    return e;
  }

  function ensureModal() {
    if (document.getElementById('sgcoModal')) return;
    var css = document.createElement('style');
    css.textContent =
      '#sgcoModal{position:fixed;inset:0;z-index:99990;background:rgba(8,15,30,.55);' +
      'backdrop-filter:blur(4px);display:none;align-items:center;justify-content:center;padding:18px}' +
      '#sgcoModal.open{display:flex}' +
      '#sgcoBox{background:#fff;border-radius:20px;max-width:420px;width:100%;padding:26px;' +
      'font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",Roboto,sans-serif;' +
      'box-shadow:0 30px 70px rgba(0,0,0,.25);color:#0b1220}' +
      '#sgcoBox h3{font-size:1.15rem;font-weight:700;letter-spacing:-.02em;margin-bottom:4px}' +
      '#sgcoBox p{color:#5b6573;font-size:.88rem;margin-bottom:16px}' +
      '.sgco-opt{display:flex;align-items:center;justify-content:space-between;gap:10px;' +
      'border:1px solid #e7e9ee;border-radius:14px;padding:13px 16px;margin-bottom:10px;' +
      'cursor:pointer;font-weight:600;font-size:.92rem;transition:.15s}' +
      '.sgco-opt:hover{border-color:#C8962A;background:#fffaf0}' +
      '.sgco-close{float:right;background:none;border:none;font-size:1.3rem;cursor:pointer;color:#99a}' +
      '.sgco-err{color:#a02020;font-size:.85rem;margin-top:8px}' +
      '.sgco-loading{text-align:center;padding:20px;color:#5b6573;font-size:.9rem}';
    document.head.appendChild(css);

    var modal = el('div', { id: 'sgcoModal' },
      '<div id="sgcoBox">' +
      '<button class="sgco-close" onclick="SGCheckout.close()">×</button>' +
      '<h3>Choose how to pay</h3>' +
      '<p id="sgcoLabel">Select a payment method to continue.</p>' +
      '<div id="sgcoOpts"></div>' +
      '<div class="sgco-err" id="sgcoErr" style="display:none"></div>' +
      '</div>');
    document.body.appendChild(modal);
    modal.addEventListener('click', function (e) { if (e.target === modal) global.SGCheckout.close(); });
  }

  var _pending = null;

  async function open(opts) {
    ensureModal();
    _pending = opts || {};
    var box = document.getElementById('sgcoOpts');
    var err = document.getElementById('sgcoErr');
    var label = document.getElementById('sgcoLabel');
    err.style.display = 'none';
    box.innerHTML = '<div class="sgco-loading">Loading payment options…</div>';
    label.textContent = opts.label ? ('Paying for: ' + opts.label) : 'Select a payment method to continue.';
    document.getElementById('sgcoModal').classList.add('open');

    try {
      var cfgRes = await fetch('/api/pay/config');
      var cfg = await cfgRes.json();
      var providers = (cfg.providers || []).filter(function (p) {
        var prod = (cfg.pricing || {})[opts.product];
        if (!prod) return false;
        return p.currencies.includes((opts.currency || 'USD').toUpperCase());
      });
      if (!providers.length) {
        box.innerHTML = '<div class="sgco-loading">No payment method available for this currency yet. Please contact us on WhatsApp.</div>';
        return;
      }
      box.innerHTML = providers.map(function (p) {
        return '<div class="sgco-opt" data-provider="' + p.name + '">' +
          (PROVIDER_LABELS[p.name] || p.name) + '<span>→</span></div>';
      }).join('');
      Array.prototype.forEach.call(box.querySelectorAll('.sgco-opt'), function (node) {
        node.addEventListener('click', function () { choose(node.getAttribute('data-provider')); });
      });
    } catch (e) {
      box.innerHTML = '';
      err.textContent = 'Could not load payment options. Please try again or contact us on WhatsApp.';
      err.style.display = 'block';
    }
  }

  async function choose(provider) {
    var opts = _pending || {};
    var err = document.getElementById('sgcoErr');
    err.style.display = 'none';
    try {
      var r = await fetch('/api/pay/init', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          product: opts.product, provider: provider, email: opts.email,
          currency: (opts.currency || 'USD').toUpperCase(),
          app_ref: opts.appRef || null, meta: opts.meta || {},
        }),
      });
      var d = await r.json();
      if (!r.ok) throw new Error(d.error || 'Could not start payment.');
      location.href = d.authorization_url;
    } catch (e) {
      err.textContent = e.message;
      err.style.display = 'block';
    }
  }

  function close() {
    var m = document.getElementById('sgcoModal');
    if (m) m.classList.remove('open');
  }

  global.SGCheckout = { open: open, close: close };
})(window);
