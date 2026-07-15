# SkyGlobe — Phase A (Department Emails) + Phase D (Inbound Email AI)
Complete click-by-click. All the code is already deployed — these steps are the
only thing between you and the full system. No Gmail accounts, no phone
verification needed anywhere.

---

## PART 1 — Put skyglobegroup.com on Cloudflare (one-time, ~15 min)

Skip to Part 2 if the domain is already on Cloudflare.

1. Go to **dash.cloudflare.com** → Sign up (email + password only).
2. Click **Add a domain** → type `skyglobegroup.com` → choose the **Free** plan.
3. Cloudflare scans and shows your existing DNS records — check that the
   records pointing your site at Render are listed (they will be). **Do not
   delete anything.**
4. Cloudflare gives you **2 nameservers** (like `ana.ns.cloudflare.com`).
5. Log in at your **domain registrar** (where you bought skyglobegroup.com) →
   find **Nameservers** → replace the current ones with Cloudflare's two.
6. Wait for Cloudflare's email "skyglobegroup.com is now active"
   (minutes to a few hours). **Your website keeps working the whole time** —
   the same DNS records are served, just from Cloudflare now.

> ⚠️ One setting to check after activation: DNS → your site's A/CNAME record —
> set the cloud icon to **DNS only (grey)** for now, so nothing changes about
> how Render serves the site.

## PART 2 — Phase A: create the 6 department addresses (~10 min)

In the Cloudflare dashboard, with skyglobegroup.com selected:

1. Left menu → **Email** → **Email Routing** → **Get started / Enable**.
   Cloudflare adds the required MX records automatically — accept.
2. **Destination addresses** → Add: `insights.skyglobe@gmail.com`
   → Cloudflare emails it a verification link → click it. ✅
   (Later, when you have more inboxes, add them here the same way and point
   any department at any inbox — no code changes ever.)
3. **Routing rules → Custom addresses** → create these six, each with
   Action **Send to an email** → `insights.skyglobe@gmail.com` (for now):
   - `support@skyglobegroup.com`
   - `visas@skyglobegroup.com`
   - `education@skyglobegroup.com`
   - `legal@skyglobegroup.com`
   - `id@skyglobegroup.com`
   - `finance@skyglobegroup.com`
4. Send a test email to `visas@skyglobegroup.com` from any account →
   confirm it lands in the Gmail. **Phase A done.**

### Turn on department-branded sending
On **Render** → your service → Environment → add:
```
DEPT_EMAILS_LIVE=all
```
Save (Render redeploys). From now on, every department's outgoing mail is sent
FROM its real address (visas@, legal@, …) and client replies come back through
the routing you just created.

## PART 3 — Phase D: the AI reads and answers the emails (~10 min)

1. Generate a long random secret (e.g. at passwordsgenerator.net — 40+ chars,
   letters+digits). You'll paste it in TWO places.
2. **Render** → Environment → add:
   ```
   EMAIL_INBOUND_SECRET=<your long random secret>
   ```
3. **Cloudflare** → Workers & Pages → **Create** → Worker → name it
   `skyglobe-inbound` → paste the entire contents of
   `cloudflare-email-worker.js` (in your repo) → **Deploy**.
4. Worker → **Settings → Variables and Secrets** → add:
   ```
   INBOUND_URL    = https://skyglobegroup.com/api/email/inbound
   INBOUND_SECRET = <the same secret as step 2>
   FORWARD_TO     = insights.skyglobe@gmail.com
   ```
5. Back in **Email → Email Routing → Routing rules**: edit each of the six
   custom addresses → change Action to **Send to a Worker** →
   `skyglobe-inbound` → Save.

**That's Phase D live.** Every email to a department address now:
1. is copied to your Gmail (never lost, even if the site is down), and
2. is read by the AI, which classifies it, and either **answers the client
   by email immediately** (from the department's own address) or **queues it
   in 🛎️ Reception** flagged for a human.

## PART 4 — Verify everything (5 min)

1. From a personal (non-SkyGlobe) email, send to `education@skyglobegroup.com`:
   *"What certificate courses do you offer?"*
   → Expect an AI answer back within ~a minute, sent from
   `SkyGlobe Education & Academy <education@skyglobegroup.com>`.
2. Send to `finance@skyglobegroup.com`: *"I want a refund on my payment."*
   → Expect NO auto-answer; instead it appears in admin → 🛎️ AI Reception,
   flagged HUMAN NEEDED, department Finance & Payments.
3. Both emails also arrive in the Gmail inbox (the safety copy).

## Troubleshooting

| Symptom | Fix |
|---|---|
| Emails to visas@ bounce | Custom address not created, or Email Routing not enabled (Part 2) |
| Copies reach Gmail but no AI reaction | Worker route not set to "Send to a Worker" (Part 3 step 5), or secrets don't match |
| AI reacts but replies come from support@ | `DEPT_EMAILS_LIVE=all` not set on Render |
| Nothing in 🛎️ Reception | `ai_reception` table missing in Supabase (run the setup SQL) |
