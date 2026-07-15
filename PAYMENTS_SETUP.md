💳 Payments & Conference Sourcing — Setup Guide
Everything is built and deployed-ready. It stays dormant until you add your
keys, so you can turn it on the moment your accounts are live — nothing else
needs changing.
---
1. Create the two Supabase tables (one-time)
Open Supabase → SQL Editor, paste this, and click Run:
```sql
-- Every payment attempt and its status
create table if not exists payments (
  id           uuid primary key default gen_random_uuid(),
  reference    text unique not null,         -- our payment reference (PAY-...)
  provider_ref text,                         -- provider's own id (e.g. Stripe session id)
  product      text not null,                -- interview_prep | conference_sourcing | ...
  app_ref      text,                         -- linked application (SKY-...) if any
  email        text,
  provider     text,                         -- paystack | stripe | flutterwave
  currency     text,
  amount       numeric,
  status       text default 'pending',       -- pending | paid
  meta         jsonb default '{}'::jsonb,
  paid_at      timestamptz,
  created_at   timestamptz default now()
);

-- Curated conferences shown on /conferences (you manage these)
create table if not exists conferences (
  id           uuid primary key default gen_random_uuid(),
  title        text not null,
  organization text,
  country      text not null,
  city         text,
  date         text,           -- free text e.g. "12–14 Oct 2026"
  field        text,           -- e.g. Health, Tech, Education
  summary      text,
  source_url   text,           -- the real organiser's page (your private reference)
  active       boolean default true,
  created_at   timestamptz default now()
);

-- Mark which applications are paid
alter table applications add column if not exists paid boolean default false;
```
---
2. Add your payment keys to Render (when each account is ready)
In Render → your service → Environment, add only the ones you have.
A provider with no key simply won't appear as an option — nothing breaks.
Provider	Env vars
Paystack (start here)	`PAYSTACK_SECRET_KEY`, `PAYSTACK_PUBLIC_KEY`
Stripe (UK/international)	`STRIPE_SECRET_KEY`, `STRIPE_PUBLIC_KEY`
Flutterwave (pan-African)	`FLUTTERWAVE_SECRET_KEY`, `FLUTTERWAVE_PUBLIC_KEY`
Then Manual Deploy → Clear cache & deploy (or just save — Render redeploys).
Paystack webhook (recommended, reliable confirmation)
In your Paystack Dashboard → Settings → API Keys & Webhooks, set the
webhook URL to:
```
https://YOUR-DOMAIN/api/pay/webhook/paystack
```
---
3. Set your prices
Prices live in `server.js` near the top of the payments section
(`const PRICING = { ... }`). We charge in USD / EUR / GBP only — premium,
international and professional (no local currency). USD is the default.
Edit the amounts to your real prices and redeploy. The client can never change
the price — the server always decides.
> 💡 For USD/EUR/GBP card payments, **Stripe** is the best fit (built for
> international cards). **Flutterwave** also supports USD/EUR/GBP. Paystack is
> kept for USD only. Add whichever provider's keys you have.
---
4. How customers reach it
Public page: `/conferences` (browse → request → pay).
Conference requests appear automatically in your CEO portal queue as
applications (status flows: `Awaiting Payment` → `Paid — Sourcing in Progress` → you deliver → `Completed`).
Payments are visible via `GET /api/admin/payments` (your password header).
---
5. Optional: paywall the AI Interview Prep
Instant digital product (pay → unlock immediately). Off by default so the
current free version is unchanged. To require payment, add to Render:
```
PAYWALL_INTERVIEW=on
```
---
6. The golden rule (legal safety)
The SKYGLOBE stamp on a sourced document means “facilitated & verified by
SKYGLOBE LIMITED” — never “issued by us.” We only deliver genuine
documents obtained from the real organiser. Never fabricate an invitation
or impersonate an institution. This keeps clients safe at embassies and keeps
the company clean.
---
What's wired right now
✅ Provider-agnostic engine: Paystack, Stripe, Flutterwave
✅ Server-authoritative pricing (tamper-proof)
✅ `/api/pay/init`, `/api/pay/verify/:ref`, Paystack webhook
✅ `/conferences` public marketplace + secure checkout + callback page
✅ Conference sourcing requests flow into the CEO queue with paid status
✅ CEO endpoints to manage conferences (`/api/admin/conferences`)
✅ Optional interview-prep paywall (env flag)
