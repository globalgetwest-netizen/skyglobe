# SKYGLOBE GROUP — DESIGN SYSTEM v1.0

The visual constitution of the ecosystem. Every new product, screen and feature reuses these
standards so users always recognise they are inside the SKYGLOBE GROUP family.
Companion to `ARCHITECTURE.md` (§4 Design Constitution) and implemented in `skyglobe-ds.css`.

## 1. Brand philosophy
Premium · Professional · Elegant · Modern · Intelligent · Trustworthy · Innovative · Calm ·
Fast · Human-centered · Accessible · Scalable. Every interaction intentional.

## 2. Color law

| Token | Hex | Use |
|---|---|---|
| Deep Royal Blue | `#0A2E65` | Trust, navigation, brand structure, hero & CTA sections |
| Premium Gold | `#D4A73A` (hi `#F4D77A`) | Premium actions, highlights, key metrics — **scarce by law** |
| Vibrant Orange | `#ff9f1c → #e65100` | **Reserved: the NORIA ✦ + live activity only.** Never errors. |
| Midnight Navy | `#041022 / #071B3B` | Command centers (CEO & staff portals), footers, dark immersive sections |
| Soft White | `#F8FAFC / #f7f8fb` | Content, forms, documentation |
| Charcoal | `#111827 / #041022` | Primary text on light |
| Grays | `#D1D5DB` secondary-on-dark · `#9CA3AF` muted · `#4B5563` secondary-on-light | text scale |

**Usage ratio target:** ~60% light surfaces · 25% blue · 10% gold · 5% orange.

**The two-world rule (ruled by the CEO's eye, 2026-07):** royal blue lights the public stage;
**midnight navy powers the command center** — dashboards and portals stay deep and quiet so gold
data glows and eyes rest. Never repaint globally; tune surfaces individually.

**Platform identities (constitutional — follows the real logos, overrides any advisory doc):**

| Platform | Primary | Secondary | Identity |
|---|---|---|---|
| SKYGLOBE GROUP | Deep Royal Blue | Gold | The ecosystem |
| NORIA | Orange ✦ | Gold | Intelligence |
| TERRA | Green `#3fae6a` | Deep blue | Trust |
| YUNEX | Blue→Purple `#3d5af1→#b326d9` | Gold | Economy |
| Global Mobility | Deep blue | White | Mobility |
| Academy | Blue | Gold | Learning |
| Health (future) | Blue | Green | Care |

## 3. Typography
**Inter** everywhere (loaded with system fallback). Georgia serif reserved for display/manifesto
headlines. Hierarchy: Display → Heading → Subheading → Body → Caption. Few weights. Large
headlines, short sentences, confident language (“Continue”, “Verify Identity”).

## 4. Layout & shape
8-point spacing (8/16/24/32/48/64/80/96). Radii: buttons & inputs 12px · cards 14–16px ·
dialogs 18–20px. Shadows soft and layered — never heavy.

## 5. Icons
One family per surface. Today the ecosystem speaks emoji (consistent, zero-weight);
**the migration to a single stroke icon family (Lucide-style) is law for the progressive
rebuild** — applied layer by layer as each service is rebuilt, never as a big bang.
Icon colors: navigation blue · primary gold · commerce/live orange · success green ·
warning amber · danger red · inactive gray. Color never the only signal.

## 6. Navigation
Desktop: top navigation — Home · **Platforms ✦ (NORIA / TERRA / YUNEX, featured with authority)** ·
Global Mobility · Academy · Solutions · Company · Dashboard · CTA.
Mobile: **bottom navigation** — Home · Discover · **NORIA ✦ (elevated center)** · Services · Profile.
Every page carries Back/Next navigation.

## 7. Backgrounds per section
Hero deep blue · content white · feature strips light gray · CTA blue · footer midnight.

## 8. Motion
Fade, slide, gentle scale, soft glow. Nothing appears instantly; nothing distracts.
`prefers-reduced-motion` always respected.

## 9. Accessibility
High contrast (per the text scale above), 48px touch targets, focus states, screen-reader
labels, keyboard paths. Dark/light theming: Horizon phase.

## 10. Native experience
The layout adapts per device; the language never changes. Phone = single column + bottom nav.
Tablet = two columns. Desktop = workspace. TV/watch: Horizon phase.
