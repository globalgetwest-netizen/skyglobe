# SKYGLOBE GROUP — Architecture Specification

**The founding reference for every product, design, and engineering decision in the ecosystem.**

> *“We don’t build applications. We build the infrastructure upon which Africa builds its future.”*

- **Status:** Living constitution — Part I is permanent; Part II is revised as the ecosystem grows.
- **Owner:** Office of the CEO, SkyGlobe Group.
- **Rule of use:** When any future decision conflicts with this document, either the decision changes or this document is *deliberately* amended — never silently ignored.

---

# PART I — THE CONSTITUTION (permanent)

## 1. Mission

SkyGlobe Group is a **digital ecosystem**, not a travel company. Travel is one service the Group renders; it does not define the Group.

The Group builds **foundational digital infrastructure** — trust, economy, and intelligence — designed uniquely for Africa’s needs, while serving clients globally through its service verticals.

We separate **vision from claims**: we do not claim to be the first in the world. Large-scale digital public infrastructure exists elsewhere (India’s Aadhaar/UPI, Estonia’s X-Road, Brazil’s Pix). Our claim — defensible in any room — is a **new architecture uniquely designed for Africa, African-owned and African-governed.**

## 2. The Ecosystem Architecture

```
                        SKYGLOBE GROUP
              Global Innovation & Infrastructure
                               │
            ┌──────────────────┴──────────────────┐
            ▼                                     ▼
         TERRA                                 YUNEX
   Trust Infrastructure               Economic Infrastructure
   identity · verification            payments · commerce
   records · security                 trade · finance
            └──────────────────┬──────────────────┘
                               ▼
                            NORIA ✦
                     The Intelligence Layer
        (not a product beside the platforms — the intelligence
         that runs WITHIN every platform and every vertical)
                               │
    ───────────────────────────────────────────────────────────
      SECTOR VERTICALS (thin applications on the layers above)
      Travel & Mobility · Education (Academy) · Legal · Digital
      Identity · Finance · future: Health, Agriculture, Justice…
    ───────────────────────────────────────────────────────────
                               │
        Governments · Banks · Businesses · NGOs · Individuals
```

**Level definitions**

| Level | Name | Role |
|---|---|---|
| 1 | **SKYGLOBE GROUP** | The architect of the ecosystem. Research, innovation, governance, investment, partnerships. Global. |
| 2 | **TERRA** — Africa Trust Infrastructure | *Who are you? Is this real? Can this be trusted?* Identity, business identity, authentication, verification, certificates, documents, signatures, compliance, fraud intelligence, security, data exchange, APIs. |
| 2 | **YUNEX** — Africa Economic Infrastructure | *Now that we trust each other, let us transact.* Payments, wallets, banking integration, cross-border commerce, marketplace, SME & supply-chain infrastructure, logistics, investment, merchant platform. |
| 3 | **NORIA** — The Intelligence Layer | Embedded intelligence powering every layer: triage, verification, fraud detection, drafting, tutoring, advising, conversation. NORIA is **not a chatbot product**; it is the mind inside every SkyGlobe surface. |
| 4 | National Integration Layer | Per-country adapters (identity, payments, government services, tax). Countries keep control of their systems; we provide the bridges. **Horizon phase.** |
| 5 | Developer Platform | Public APIs/SDKs exposing identity, payments, AI, verification, notifications. **Horizon phase.** |
| 6 | Sector Solutions | Thin vertical applications reusing the layers: Travel, Education, Legal, ID, Finance today; Health, Agriculture, Justice, Tourism, Energy tomorrow. |

**Dependency rule:** economy runs on trust; both run on intelligence. `Terra verifies, YUNEX moves, NORIA thinks.`

**Global vs. Africa-only:** SKYGLOBE GROUP and NORIA are global. TERRA and YUNEX are Africa-only by mission. Products live *inside* the platforms as sub-brands — never as new sibling companies.

**The YUNEX product family (naming law):** two clean words, no geographic suffix — YUNEX already means Africa.

| Product | Scope |
|---|---|
| **YUNEX Pay** | Payments, wallets, settlement |
| **YUNEX Trade** | Cross-border B2B commerce — the flagship. Tagline: *“Africa’s gateway to global commerce.”* |
| **YUNEX Market** | Consumer marketplace (later) |
| **YUNEX Logistics · YUNEX Capital** | As the family grows |

**Corridors are features, never brands:** inside YUNEX Trade, trade corridors are launched as features — **China Corridor** first (verified suppliers, sourcing, settlement, NORIA translation & negotiation), then Gulf, Europe, and the deepest one: the **Africa Corridor** (AfCFTA — the continent trading with itself). A corridor name must never appear in a product or company name; corridors change, infrastructure does not.

**The canonical user story (reuse in every pitch):** a Ghanaian business owner finds a verified supplier through YUNEX Trade → TERRA verifies the supplier → YUNEX handles payment → NORIA negotiates, translates and analyzes → logistics partners deliver.

**Brand protection (governance requirement):** before YUNEX or TERRA take money or sign partners, run trademark searches and register the marks (Ghana/ARIPO first, then key markets). Known collisions to navigate: “Yunex Traffic” (Siemens spin-off, different industry) and the many existing “Terra” marks — TERRA always rides with “A SkyGlobe Group Platform.”

## 3. Governance & Brand Law

1. **Masterbrand:** SKYGLOBE GROUP stands *above* all products, never beside them. Every platform carries “A SkyGlobe Group Platform.”
2. **TERRA and YUNEX are Africa-only** by mission: built for Africa, by Africans, access reserved for the continent (geo, device, and identity gating when they launch as products). SkyGlobe Group and its service verticals remain global.
3. **The NORIA Star (✦):** a small orange four-point star appears on every SkyGlobe Group logo and platform mark, at the **upper-right of the emblem** (“the star above the globe”). Defined once, never moved. It honors NORIA and declares: *intelligence lives inside everything we build.*
4. **Office of the CEO is sacred:** ceo@ is never listed publicly, never AI-auto-answered, never re-classified by the AI. Public submissions addressed to it reroute to General.
5. **Data dignity:** no real person’s religion or private attributes visible on public surfaces; machine-readable layers only where operationally required. No sample data based on real nationalities or names of any group we serve.
6. **Zero-silent-failure:** any automated action that fails (an email, a delivery, a payment fulfilment) must surface — to the human queue, the error log, or both. Silence is forbidden by architecture.

## 4. Design Constitution

**Philosophy:** Elegant · Calm · Intelligent · Premium · Fast · Accessible · Consistent · Human-centered · Scalable. Every interaction intentional. This is a Digital Operating System, not “an app.”

**Ecosystem palette (the corrected law — honoring the real logos):**

| Surface | Colors |
|---|---|
| **SkyGlobe Group (parent)** | Deep navy `#041022 / #0A2E65` + premium gold `#D4A73A / #c9a84c` — the signature, unchanged |
| **TERRA** | Green accent `#3fae6a` (+ globe blues) on the shared navy — secure, alive, grounded |
| **YUNEX** | Blue → purple accent `#3d5af1 → #b326d9` on the shared navy — dynamic, modern, economic |
| **NORIA** | The orange star `#ff9f1c → #e65100` + gold — reserved; orange elsewhere appears **only** for live activity/progress (i.e., where the intelligence is working) |

**Color rules:** blue = structure/trust/navigation · gold = premium moments, used sparingly so it keeps its power · green = TERRA/trust states & success · orange = NORIA + live activity only. Color is never the sole carrier of meaning (icon + word always accompany it).

**Type:** one family per surface (system stack: `'Segoe UI', system-ui, -apple-system, sans-serif`; Georgia serif reserved for display/manifesto headlines). Scale: Display → Heading → Body → Caption. No decorative fonts.

**Spacing:** 8-point system (8 / 16 / 24 / 32 / 48 / 64).

**Components:** premium cards (soft radius, comfortable spacing, one primary action, minimal noise); buttons — primary filled (gold or context accent), secondary outlined, tertiary text; one rounded icon family; pill CTAs.

**Motion:** nothing appears instantly — cards rise gently, pages slide, buttons respond subtly; motion reinforces understanding, never distracts.

**Text:** short, clear, imperative. “Continue”, “Verify Identity” — never “Click here to…”.

**Accessibility from the start:** high contrast, adjustable text, screen-reader labels, focus states, keyboard paths.

The living implementation of this section is **`skyglobe-ds.css`** — the ecosystem design tokens and components. Every new page imports it.

---

# PART II — THE ROLLING TECHNICAL BLUEPRINT (revised as we grow)

## 5. What exists today (Phase 0 — in production)

The Group is **not** a paper vision. The shared-services layer that usually takes years is live:

| Shared service | Implementation today |
|---|---|
| **Authentication** | One client account system (scrypt-hashed, signed sessions) serving all verticals; role-based CEO/staff auth with department attribution |
| **Payments (proto-YUNEX)** | One engine: initialize → verify → fulfil, products across travel, legal, ID, education; CEO complimentary grants with signed claim links |
| **Trust (proto-TERRA)** | Digital ID issuance & public verification; legal document generation; signed, expiring unlock links; document delivery vault |
| **Intelligence (NORIA)** | AI triage of all 9 department inboxes; auto-answer with confidence gating; human escalation with CEO assignment; conversational loop in client Messages; AI legal drafting; CEO command-centre assistant |
| **Notifications** | Email with automatic failover (Resend → Brevo), portal-first in-app delivery (zero quota), SSE live push, weekly provider keep-alive |
| **Communications** | 9 professional addresses on Cloudflare Email Routing → worker → inbound AI pipeline with 4-layer loop immunity |
| **Presence** | skyglobegroup.com (global portal) · terra.skyglobegroup.com · yunex.skyglobegroup.com (worker-served sovereign subdomains) |

**Stack reality:** Node/Express monolith (`server.js`) + static HTML surfaces + Supabase (Postgres/storage) + Render hosting + Cloudflare (DNS, email routing, workers). Single repo. No build pipeline — by design, for operational simplicity at this stage.

## 6. The evolution path (evolve, never rebuild)

The engine is renamed in our thinking: `server.js` and its services are the **SkyGlobe Core**. Every experience — public site, TERRA, YUNEX, dashboards, portals — is a *face* on that core. Travel keeps every URL and function; it is re-homed as the first vertical, never diminished (it funds the mission).

| Phase | Deliverable | Status |
|---|---|---|
| 1 | This specification | ✅ |
| 2 | `skyglobe-ds.css` design tokens & components | ✅ |
| 3 | Admin portal → **Command Bridge**: ecosystem-layer navigation (Group / NORIA / TERRA / YUNEX / Verticals / Operations), morning briefing greeting | ✅ |
| 4 | Role-scoped staff portal: department-scoped reception queues; foundation for full permissions | ✅ first increment |
| 5 | Public portal rebalance: Group-first hero + ecosystem section; travel first-among-equals | ✅ first increment |
| 6 | Unified client dashboard: module gateway (“Good morning” → Travel / Documents / Payments / Messages) | ✅ first increment |
| 7 | NORIA founding page + full repositioning of all copy to “intelligence layer” | Next |
| 8 | Full roles & permissions matrix (visa officer, admissions, finance, support, AI supervisor…) with audit trail | Next |
| 9 | TERRA/YUNEX first real products (candidate: TERRA credential verification API; YUNEX unified merchant checkout) | Planned |
| 10 | Developer platform (public APIs), national adapters, sector verticals (health first, under the strictest privacy rules we have ever written) | Horizon |

## 7. Security & privacy model (current increment)

- Roles: `ceo` (master key — everything), `staff` (operational tools; reception queues scoped to their department when one is set; CEO-only surfaces return 401).
- All admin/staff actions attributed by name in the activity log.
- Client data: clients see only their own records (session-scoped queries).
- Secrets live in environment variables only; never in the repo.
- Public forms are rate-limited, sanitized, and CEO-rerouted (see §3.4).

## 8. Amendment log

| Date | Change |
|---|---|
| 2026-07 | Founding version: constitution, palette law, ecosystem levels, Phase 0 inventory, phases 1–6 executed. |
| 2026-07 | Amendment 1: YUNEX product family naming law (Pay · Trade · Market), corridors-as-features doctrine (China Corridor first, Africa Corridor as the AfCFTA mission), canonical user story, brand-protection requirement. |
| 2026-07 | Amendment 2 — Division realignment & the ecosystem gateway. Departments renamed to division level: **Global Mobility** (🌐 mobility@, everything travel — visas, permits, migration, flights, hotels, insurance, recruitment, conferences; legacy visas@ aliased forever), **SkyGlobe Academy** (🎓 education for every age — /academy is the proud address, /kids-academy redirects), **Legal & Trust Services** (📜, TERRA-shadow), **Digital Identity** (🪪, TERRA-shadow), **Finance & Payments** (💳, YUNEX-shadow), and the new **Innovation & Technology** (🚀 innovation@ — digitalization, partnerships, developer enquiries, R&D). Public portal becomes the ecosystem gateway: dark navy hero ("Building the Intelligent Foundation of Tomorrow"), honest stats, Explore Ecosystem / Partner With Us, Solutions-for-Every-World audience doors (Individuals · Businesses · Governments & Institutions · Developers), principles strip (Security · Transparency · Innovation · Human Progress). Every page carries Back/Next navigation. Backend target architecture recorded: one unified foundation (identity, payments, notifications, AI — already shared) with platform services that grow independently; API gateway, separated data domains, and container infrastructure are Phase 4 tools, adopted only when scale demands — never before. |
| 2026-07 | **Amendment 4 — SKYGLOBE ID, Terra Trust Marks & the YUNEX pillars.** **(a) SKYGLOBE ID — the layered identity model.** One account for the whole ecosystem; the account evolves, never multiplies. Signup stays simple (name, email, phone, country, password). Capabilities unlock through layers: **Identity** (core profile: photo, names, DOB where required, nationality, residence, language, contacts) → **Verification via TERRA** (identity: national ID/passport/licence + liveness where implemented; address: utility/bank/government document; business: registration + tax + licence — each with statuses Not Started / Pending Review / Verified / Rejected / Expired) → **Roles** (multiple simultaneously: student, traveller, buyer, seller, business owner, investor, developer, employer, employee, partner) → **Service enrollment** (each service onboards separately: Travel terms + travel profile; YUNEX seller = policies + business verification + payout method; buyer = policies + delivery + payment) → **Credentials** (one SKYGLOBE ID backed by TERRA carrying verifiable credentials — Identity Verified, Student Verified, Traveller Verified, Buyer/Seller Verified, Business Verified — never separate ID cards per role) → **Permissions** (role-derived, not identical to roles) → **Security** (password, 2FA, active sessions) → **Settings**. **(b) Terra Trust Marks.** All verification badges belong to TERRA ("Terra Verified"): Identity (blue+gold shield ✔), Business (gold), Organization, Merchant (orange), Professional, Institution (emerald), Government (deep blue+gold, reserved), Developer (purple), Partner (silver), Ambassador. Unique mark design (shield/orbit — never another platform's checkmark); statuses always icon+word, never color alone; credentials follow the user across every service; recognition is earned by transparent, consistently-enforced verification policy — not appearance. **(c) Business law:** anyone engaging in ANY business activity in the ecosystem must be legally and strictly verified regardless of country; verified sellers and buyers see products, quantity and quality, negotiate, bargain and arrange shipping — in real time, between real people. **(d) YUNEX five pillars:** Trade · Investment (verified project/opportunity marketplace) · Assets (land, farms, property, machinery — verified participant, listed asset clearly distinguished) · Business (verified profiles, sourcing, distribution, expansion) · Finance (only with licensed partners, per each country's law). **(e) Partner-not-replace principle:** YUNEX never becomes a bank, customs authority, shipping company, regulator or land registry — it is the trusted platform that connects participants and integrates licensed specialists. **(f) NORIA is a platform, not a widget:** /noria is its home (assistant, reception, drafting, teachers live; translation, fraud-intelligence, business-intelligence growing; APIs horizon); opening NORIA opens the platform — the assistant answers when asked. |
| 2026-07 | Amendment 3 — The YUNEX Trade trust doctrine. Identity-verified marketplace, no exceptions: individuals register with real national identity (KYC verified through TERRA); businesses register with government-issued business registration **plus** the legal identity of every owner and partner, from their own country. End-to-end encryption. Real-time buyer–seller communication between verified humans only. Zero tolerance for illegal activity — detection, blocking and reporting built in, with full platform control over every user interface. Applies to all corridors and all continents. **No verification, no trade.** |
