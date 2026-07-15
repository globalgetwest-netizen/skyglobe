SkyGlobe Group — Platform
One World. One Mission.
The premium global platform for SkyGlobe Group — covering global mobility,
education, AI, and digital innovation. Built and led by Saleh Shuaibu,
Founder & Chief Executive Officer.
> **Brand rule:** The name is always **SkyGlobe Group** — never "SKYGLOBE LIMITED"
> or any regional registration claim.
---
1. What this is
A single Node.js/Express application that serves:
The public site (`index.html`) — hero globe, services, blog, applications, client accounts
Specialist portals — Conferences, Work Permit, Legal Documents, Digitalization, Packages
SkyGlobe Kids Academy — admissions, parent portal, AI tutors, student records
The CEO / Admin portal (`admin.html`) — applications, messaging, staff, payroll, analytics, error logs, IP registry
A staff portal (`staff.html`) — attendance, tasks, department channels
An AI engine — text generation with an Ollama → Groq → Gemini fallback chain
Self-hosted analytics & error monitoring — no third-party trackers, no Sentry
---
2. Technology — deliberately simple
Layer	Choice	Why
Backend	Express.js 4 (`server.js`)	One well-understood runtime, easy to host
Frontend	Vanilla JavaScript + custom CSS	No framework lock-in. No React, Vue, Flutter, React Native, or Tailwind.
Database	Supabase (PostgreSQL) via REST	Managed Postgres, simple HTTP access
Auth	HMAC-signed tokens (clients/parents) + role keys (admin/staff)	No heavy auth dependency
Realtime	Server-Sent Events (`/api/sse`)	Push without a WebSocket library
AI	Ollama → Groq → Gemini fallback	Free/local first, cloud as backup
Payments	Paystack / Flutterwave / Stripe	Region-flexible
Offline / install	Service Worker v6 + PWA manifest	Installable, works offline
Charts	Hand-written SVG	No Chart.js — zero chart dependencies
Tests	Node built-in test runner (`node --test`)	Zero extra packages
Dependencies are kept to a minimum — see `package.json`. New npm packages
are only added when genuinely unavoidable.
---
3. Project structure
```
SKYGLOBE-LIMITED/
├── server.js              # The whole backend (sectioned §1–§14 + numbered features)
├── lib/
│   └── utils.js           # Pure, unit-tested helpers (sanitize, tokens, hashing, esc)
├── test/
│   └── utils.test.js      # Node built-in tests for lib/utils.js
├── index.html             # Public site (single-page, vanilla JS)
├── admin.html             # CEO / Admin portal
├── staff.html             # Staff portal
├── academy-*.html         # Kids Academy portal, learning, admission
├── conferences.html …     # Specialist portals
├── offline.html           # Branded offline fallback (served by the SW)
├── blog-data.js           # Blog content, lazy-loaded on first Blog visit
├── sw.js                  # Service Worker (v6) — network-first nav, cache-first static
├── manifest.json          # PWA manifest (shortcuts, maskable icons)
├── skyglobe-ds.css        # Custom design system
└── *.md                   # Documentation (this file + the ones below)
```
Related documentation
`SKYGLOBE-ARCHITECTURE.md` — brand identity, design system, the Four Anchors
`API.md` — full HTTP endpoint reference
`RUN-LOCALLY.md` — local development setup
`PAYMENTS_SETUP.md` — payment provider configuration
`CONFERENCES_SEED.md` — seeding conference data
---
4. Running locally
```bash
npm install        # install dependencies
npm start          # start the server (default http://localhost:3000)
npm test           # run the unit test suite
```
See `RUN-LOCALLY.md` for the full walkthrough. The server self-pings
`/api/health` every 13 minutes to stay awake on free hosting tiers.
---
5. Environment variables
Create a `.env` file (loaded via `dotenv`). None are required to boot, but
features stay dormant until their keys are set.
Variable	Purpose
`PORT`	Server port (default `3000`)
`SESSION_SECRET`	Secret for HMAC session tokens (falls back to `SUPABASE_KEY`)
`SUPABASE_URL`, `SUPABASE_KEY`	Database access
`ADMIN_PASSWORD` / `ADMIN_PASSWORDS`	CEO/admin portal login
`STAFF_PASSWORDS`	Staff portal logins
`OLLAMA_URL`, `OLLAMA_MODEL`	Local AI (tried first)
`GROQ_API_KEY`, `GROQ_MODEL`	Cloud AI fallback
`GEMINI_API_KEY`	Final AI fallback
`ANTHROPIC_API_KEY`	Optional Claude access
`PAYSTACK_SECRET_KEY`, `PAYSTACK_PUBLIC_KEY`	Paystack payments
`FLUTTERWAVE_SECRET_KEY`, `FLUTTERWAVE_PUBLIC_KEY`	Flutterwave payments
`STRIPE_SECRET_KEY`, `STRIPE_PUBLIC_KEY`	Stripe payments
`RESEND_API_KEY`, `RECIPIENT_EMAIL`	Outbound email
`PAYWALL_INTERVIEW`	Toggle interview-prep paywall
`WORK_START_MIN`, `WORK_TZ_OFFSET`	Staff attendance rules
`RENDER_EXTERNAL_URL`	Public URL for keep-alive self-ping
---
6. How `server.js` is organised
The backend is a single file by design (one deploy, one process), but it is
sectioned and labelled so any area is quick to find:
A table of contents (§1–§14) sits at the top
Feature work is tagged with its improvement number, e.g. `#12 ANALYTICS`,
`#21 PWA`, `#23 ERROR MONITORING`, `#24 SHARED PURE HELPERS`
Pure, reusable logic lives in `lib/utils.js` so it can be unit-tested
without starting the server
---
7. Quality features
Analytics (#12) — first-party event tracking in Supabase, no cookies
PWA (#21) — installable, offline page, app shortcuts
Code splitting (#22) — blog content lazy-loaded on demand
Error monitoring (#23) — client `window.onerror` + server error handler → `/api/admin/errors`
Testing (#24) — `npm test` runs the built-in Node test suite
Documentation (#25) — this README + `API.md` + the architecture doc
---
© SkyGlobe Group. One World. One Mission.
