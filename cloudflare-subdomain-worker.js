/**
 * SkyGlobe Platform Subdomains Worker
 * ------------------------------------
 * Serves terra.skyglobegroup.com, yunex.skyglobegroup.com (and any future
 * platform subdomain, e.g. noria.) straight from the main site — no Render
 * custom-domain slots needed. The visitor keeps the subdomain in their
 * address bar; behind the scenes every request is fetched from
 * https://skyglobegroup.com with the same path, except the root, which maps
 * to the platform's founding page (/terra, /yunex, …).
 *
 * SETUP (once):
 *  1. Cloudflare → Workers & Pages → Create → Worker → name: skyglobe-subdomains
 *     → paste this file → Deploy.
 *  2. Worker → Settings → Domains & Routes → Add route:
 *        terra.skyglobegroup.com/*   (zone: skyglobegroup.com)
 *        yunex.skyglobegroup.com/*   (zone: skyglobegroup.com)
 *  3. Cloudflare → skyglobegroup.com → DNS → Add record (one per subdomain):
 *        Type: AAAA   Name: terra   IPv6 address: 100::   Proxy: ON (orange)
 *        Type: AAAA   Name: yunex   IPv6 address: 100::   Proxy: ON (orange)
 *     (100:: is a standard placeholder — the Worker intercepts all traffic,
 *      so the address is never actually used.)
 *
 * To add a future platform (e.g. noria): add its route + AAAA record, and if
 * it has a dedicated page, add it to PAGE_MAP below.
 */

const ORIGIN = 'https://skyglobegroup.com';

// subdomain → founding page served at the subdomain's root
const PAGE_MAP = {
  terra: '/terra',
  yunex: '/yunex',
  noria: '/noria',
};

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const sub = url.hostname.split('.')[0].toLowerCase();

    let path = url.pathname;
    if (path === '/' || path === '/index.html') {
      path = PAGE_MAP[sub] || '/';
    }

    const upstream = new Request(ORIGIN + path + url.search, request);
    return fetch(upstream);
  },
};
