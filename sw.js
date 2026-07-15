/* SkyGlobe Group — Service Worker (merged)
 * Network-first for navigation & API (always fresh content),
 * cache-first for static assets (fast repeat loads, offline-friendly),
 * + offline fallback page, + controlled update so the in-app
 *   "Update available" banner in index.html works.
 *
 * ▶ ON EACH DEPLOY: bump the version in CACHE (e.g. v7 → v8) so old caches purge.
 * NOTE: we do NOT call skipWaiting() on install — the page asks the user first,
 *       then posts {type:'SKIP_WAITING'} when they tap "Update".
 */
const CACHE = 'skyglobe-v22';
const STATIC_ASSETS = [
  '/', '/index.html', '/offline.html',
  '/icon.svg?v=3', '/icon-192.png?v=3', '/icon-512.png?v=3', '/apple-touch-icon.png?v=3', '/favicon-32.png?v=3',
  '/stamp.svg', '/signature.png', '/manifest.json?v=3'
];

self.addEventListener('install', (e) => {
  // Precache best-effort: one missing file must NOT abort the whole precache.
  e.waitUntil(
    caches.open(CACHE).then((c) =>
      Promise.allSettled(STATIC_ASSETS.map((u) => c.add(u)))
    )
  );
  // Auto-update: new versions activate immediately so every installed app
  // (old or new) picks up each deploy on its next load — no user action needed.
  self.skipWaiting();
});

self.addEventListener('message', (e) => {
  if (e.data && e.data.type === 'SKIP_WAITING') self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;

  let url;
  try { url = new URL(req.url); } catch (_) { return; }

  // Never cache API / engine calls — always live.
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/v1/')) {
    e.respondWith(
      fetch(req).catch(() =>
        new Response('{"error":"offline"}', { headers: { 'Content-Type': 'application/json' } })
      )
    );
    return;
  }

  // Navigation: network-first → newest deploy wins; cached shell / offline page when offline.
  if (req.mode === 'navigate') {
    e.respondWith(
      fetch(req).then((res) => {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put('/index.html', copy));
        return res;
      }).catch(() =>
        caches.match('/index.html').then((shell) => shell || caches.match('/offline.html'))
      )
    );
    return;
  }

  // Scripts & styles: NETWORK-FIRST — code updates must reach every installed
  // app immediately (a stale cached .js once kept users on an old UI). The
  // cached copy is only a fallback for offline.
  if (/\.(js|css)$/i.test(url.pathname) && url.origin === self.location.origin) {
    e.respondWith(
      fetch(req).then((res) => {
        if (res.ok) { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(req, copy)); }
        return res;
      }).catch(() => caches.match(req))
    );
    return;
  }

  // Other static assets (images, fonts): cache-first, then network.
  e.respondWith(
    caches.match(req).then((hit) =>
      hit || fetch(req).then((res) => {
        if (res.ok && url.origin === self.location.origin) {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(req, copy));
        }
        return res;
      }).catch(() => hit)
    )
  );
});
