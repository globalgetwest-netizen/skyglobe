// SkyGlobe Group — Cloudflare Email Worker (Phase D)
// Receives every email sent to a department address (visas@, legal@, id@,
// education@, finance@, support@ ...skyglobegroup.com), keeps a copy in the
// human inbox, then hands the message to SkyGlobe's AI Reception.
//
// SETUP (see PHASE-A-D-GUIDE.md for the full click-by-click):
//   1. Cloudflare dashboard → Workers & Pages → Create → Worker,
//      name it  skyglobe-inbound , paste this whole file, Deploy.
//   2. Worker → Settings → Variables and Secrets — add:
//        INBOUND_URL    = https://skyglobegroup.com/api/email/inbound
//        INBOUND_SECRET = (same long random string as EMAIL_INBOUND_SECRET on Render)
//        FORWARD_TO     = insights.skyglobe@gmail.com   (a VERIFIED destination)
//   3. Email → Email Routing → Routing rules: for each custom address,
//      set Action = "Send to a Worker" → skyglobe-inbound.

export default {
  // Health check for web requests (the dashboard preview and curl hit this).
  // The real work happens in the email() handler below.
  async fetch() {
    return new Response('SkyGlobe inbound email worker · OK', { status: 200 });
  },

  async email(message, env, ctx) {
    // LOOP GUARD — never hand SkyGlobe's own mail back to SkyGlobe.
    // (Notifications the platform sends to its own addresses would otherwise
    // circle forever: platform → address → worker → platform → …)
    const headerFrom = (message.headers.get('from') || '').toLowerCase();
    const origin = message.headers.get('x-skyglobe-origin') || '';
    const isOwn = origin === 'platform' || headerFrom.includes('@skyglobegroup.com');

    // 1) Safety first: always deliver the original to the human inbox.
    //    The AI is additive — if anything below fails, no mail is lost.
    try {
      if (env.FORWARD_TO) await message.forward(env.FORWARD_TO);
    } catch (e) {
      // forward() throws if FORWARD_TO isn't a verified destination — fix in
      // Email Routing → Destination addresses.
    }
    if (isOwn) return; // keep the copy, never re-inject into the platform

    // 2) Hand the message to SkyGlobe's AI Reception.
    try {
      const raw = await new Response(message.raw).text();
      await fetch(env.INBOUND_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-inbound-secret': env.INBOUND_SECRET,
        },
        body: JSON.stringify({
          from: message.from,
          to: message.to,
          subject: message.headers.get('subject') || '',
          raw: raw.slice(0, 60000),
        }),
      });
    } catch (e) {
      // Server unreachable — the human copy above already went through.
    }
  },
};
