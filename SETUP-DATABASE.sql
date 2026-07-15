-- ═══════════════════════════════════════════════════════════════════════════
--  SKYGLOBE GROUP — COMPLETE DATABASE SETUP (Supabase / PostgreSQL)
--  Safe to run repeatedly: every statement is IF NOT EXISTS, so tables you
--  already have are left completely untouched. Run in Supabase → SQL Editor.
--  Storage: also make sure a public bucket named  documents  exists
--  (Supabase → Storage → New bucket → "documents" → Public).
-- ═══════════════════════════════════════════════════════════════════════════

-- ── CORE: clients, applications, payments ───────────────────────────────────
create table if not exists clients (
  id bigint generated always as identity primary key,
  email text unique, name text, password_hash text,
  created_at timestamptz default now()
);

create table if not exists applications (
  id bigint generated always as identity primary key,
  ref text unique, service text, fname text, lname text, email text, phone text,
  destination text, message text, status text default 'new',
  client_email text, data jsonb,
  created_at timestamptz default now()
);

create table if not exists payments (
  id bigint generated always as identity primary key,
  ref text unique, product text, label text, amount numeric, currency text,
  email text, name text, status text default 'initiated', provider text,
  provider_ref text, meta jsonb,
  created_at timestamptz default now()
);

create table if not exists messages (
  id bigint generated always as identity primary key,
  client_email text, sender text, body text, read boolean default false,
  created_at timestamptz default now()
);
create index if not exists idx_messages_client on messages (client_email, created_at);

create table if not exists documents (
  id bigint generated always as identity primary key,
  ref text, filename text, path text, uploaded_by text,
  created_at timestamptz default now()
);

create table if not exists document_tokens (
  id bigint generated always as identity primary key,
  token text unique, doc_id bigint, doc_path text, filename text,
  client_email text, app_ref text, expires_at timestamptz,
  created_at timestamptz default now()
);

create table if not exists client_files (
  id bigint generated always as identity primary key,
  client_email text, ref text, filename text, path text, kind text,
  uploaded_by text, created_at timestamptz default now()
);

-- ── AI RECEPTION & COMMUNICATIONS ────────────────────────────────────────────
create table if not exists ai_reception (
  id bigint generated always as identity primary key,
  source text, ref text, client_name text, client_email text,
  service text, department text, urgency text, intent text,
  sentiment text, suggested_reply text, needs_human boolean,
  status text default 'new', assigned_to text, raw jsonb,
  created_at timestamptz default now()
);
create index if not exists idx_reception_created on ai_reception (created_at desc);

create table if not exists dept_messages (
  id bigint generated always as identity primary key,
  dept text, name text, email text, message text,
  created_at timestamptz default now()
);

create table if not exists error_logs (
  id bigint generated always as identity primary key,
  source text, message text, stack text, url text, meta jsonb,
  created_at timestamptz default now()
);

create table if not exists announcements (
  id bigint generated always as identity primary key,
  icon text, tag text, headline text, subtext text,
  button_text text, button_link text, live boolean default false,
  type text, display_mode text,
  impressions integer default 0, clicks integer default 0, dismissals integer default 0,
  created_at timestamptz default now()
);

create table if not exists featured_videos (
  id bigint generated always as identity primary key,
  title text, url text, is_live boolean default false, active boolean default true,
  created_at timestamptz default now()
);

create table if not exists analytics_events (
  id bigint generated always as identity primary key,
  event text, page text, meta jsonb, created_at timestamptz default now()
);

create table if not exists session_logs (
  id bigint generated always as identity primary key,
  who text, role text, action text, meta jsonb, created_at timestamptz default now()
);

create table if not exists activity_log (
  id bigint generated always as identity primary key,
  actor text, actor_role text, action text, detail text, target text,
  created_at timestamptz default now()
);

-- ── TEAM / ORGANISATION (CEO & staff portals) ────────────────────────────────
create table if not exists staff_members (
  id bigint generated always as identity primary key,
  name text, password text, department text, role_title text, email text,
  salary numeric, status text default 'active', meta jsonb,
  created_at timestamptz default now()
);

create table if not exists team_messages (
  id bigint generated always as identity primary key,
  author text, role text, body text, channel text,
  created_at timestamptz default now()
);

create table if not exists tasks (
  id bigint generated always as identity primary key,
  title text, detail text, assigned_to text, status text default 'open',
  due_date date, created_by text, created_at timestamptz default now()
);

create table if not exists attendance (
  id bigint generated always as identity primary key,
  staff_name text, department text, work_date date, clock_in timestamptz,
  clock_out timestamptz, late boolean default false,
  created_at timestamptz default now()
);

create table if not exists payroll (
  id bigint generated always as identity primary key,
  staff_name text, department text, amount numeric, currency text,
  period text, status text default 'pending', meta jsonb,
  created_at timestamptz default now()
);

create table if not exists brand_assets (
  id bigint generated always as identity primary key,
  name text, kind text, path text, meta jsonb, created_at timestamptz default now()
);

-- ── COMMERCE CONFIG (CEO-editable, no code) ──────────────────────────────────
create table if not exists pricing_overrides (
  id bigint generated always as identity primary key,
  product text unique, usd numeric, eur numeric, gbp numeric,
  updated_by text, updated_at timestamptz default now()
);

create table if not exists work_permit_rates (
  id bigint generated always as identity primary key,
  country text, flag text, open boolean default true,
  standard_usd numeric, express_usd numeric, notes text, meta jsonb,
  created_at timestamptz default now()
);

create table if not exists custom_offerings (
  id bigint generated always as identity primary key,
  title text, description text, icon text, price_usd numeric,
  active boolean default true, meta jsonb, created_at timestamptz default now()
);

create table if not exists conferences (
  id bigint generated always as identity primary key,
  title text, location text, dates text, url text, meta jsonb,
  active boolean default true, created_at timestamptz default now()
);

create table if not exists conference_requests (
  id bigint generated always as identity primary key,
  ref text, fname text, lname text, email text, phone text, country text,
  conference text, field text, travel_date text, notes text,
  status text default 'received', created_at timestamptz default now()
);

-- ── DIGITAL IDENTITY (proto-TERRA) ───────────────────────────────────────────
create table if not exists identity_cards (
  id bigint generated always as identity primary key,
  card_ref text unique, full_name text, email text, nationality text,
  dob text, photo_url text, machine_layer jsonb, status text default 'valid',
  payment_ref text, created_at timestamptz default now()
);

-- ── ACADEMY: CERTIFICATE PROGRAMMES (courses engine) ─────────────────────────
create table if not exists course_enrollments (
  id uuid primary key default gen_random_uuid(),
  ref text unique, track_id text, tier_id text, full_name text, email text,
  dob text, nationality text, address text, graduation_year integer,
  steps jsonb, status text default 'in_progress',
  final_exam jsonb, final_score integer, cert_ref text,
  created_at timestamptz default now()
);
-- If course_enrollments already exists, make sure the exam columns are present:
alter table course_enrollments add column if not exists final_exam  jsonb;
alter table course_enrollments add column if not exists final_score integer;
alter table course_enrollments add column if not exists cert_ref    text;
alter table course_enrollments add column if not exists exam_next_at timestamptz;

create table if not exists certificates (
  id bigint generated always as identity primary key,
  cert_ref text unique, enrollment_id uuid, full_name text,
  track_id text, tier_id text, graduation_year integer,
  photo_url text, nationality text, status text default 'valid',
  created_at timestamptz default now()
);

create table if not exists academy_bank (
  id bigint generated always as identity primary key,
  kind text, track_id text, step_title text, content jsonb,
  created_at timestamptz default now()
);
create index if not exists idx_bank_lookup on academy_bank (kind, track_id, step_title);

create table if not exists academy_tracks (
  id text primary key, name text, emoji text, description text,
  active boolean default true, created_at timestamptz default now()
);

-- ── ACADEMY: FAMILY CAMPUS (students of every age) ───────────────────────────
create table if not exists academy_parents (
  id bigint generated always as identity primary key,
  email text unique, name text, password_hash text,
  created_at timestamptz default now()
);

create table if not exists academy_students (
  id bigint generated always as identity primary key,
  parent_email text, name text, age integer, level text,
  admission_status text, enrollment_date timestamptz, meta jsonb,
  created_at timestamptz default now()
);

create table if not exists academy_guardians (
  id bigint generated always as identity primary key,
  student_id bigint, name text, relationship text, phone text, email text,
  created_at timestamptz default now()
);

create table if not exists academy_teachers (
  id bigint generated always as identity primary key,
  subject_key text unique, name text, emoji text,
  subject text, color text,
  created_at timestamptz default now()
);
-- If the table already existed with an older shape, add the columns the code uses:
alter table academy_teachers add column if not exists subject_key text;
alter table academy_teachers add column if not exists name text;
alter table academy_teachers add column if not exists emoji text;

create table if not exists academy_sessions (
  id bigint generated always as identity primary key,
  student_id bigint, subject text, transcript jsonb, summary text,
  created_at timestamptz default now()
);

create table if not exists academy_materials (
  id bigint generated always as identity primary key,
  student_id bigint, subject text, title text, content text, path text,
  created_at timestamptz default now()
);

create table if not exists academy_assessments (
  id bigint generated always as identity primary key,
  student_id bigint, subject text, score numeric, total numeric,
  detail jsonb, created_at timestamptz default now()
);

create table if not exists academy_academic_records (
  id bigint generated always as identity primary key,
  student_id bigint, term text, record jsonb, created_at timestamptz default now()
);

-- ═══════════════════════════════════════════════════════════════════════════
--  Done. "Success. No rows returned." means everything is in place.
-- ═══════════════════════════════════════════════════════════════════════════

-- Academy completion layer (teachers with subjects, honorary certificates)
alter table academy_teachers add column if not exists subject text;
alter table academy_teachers add column if not exists color text;
alter table certificates add column if not exists issued_by text;

-- Certificate verification repair (root-cause fix):
-- 1. unlock the FK (the cert stores its own copy of all data), then retype;
-- 2. guarantee every column the certificate writes exists.
alter table certificates drop constraint if exists certificates_enrollment_id_fkey;
alter table certificates alter column enrollment_id type text using enrollment_id::text;
alter table certificates add column if not exists full_name       text;
alter table certificates add column if not exists track_id        text;
alter table certificates add column if not exists tier_id         text;
alter table certificates add column if not exists graduation_year integer;
alter table certificates add column if not exists photo_url       text;
alter table certificates add column if not exists details jsonb;
alter table certificates add column if not exists nationality     text;
alter table certificates add column if not exists status          text default 'valid';
alter table certificates add column if not exists issued_by       text;
alter table certificates add column if not exists region  text;
alter table certificates add column if not exists address text;

-- ══════════════════════════════════════════════════════════════════════════
-- YUNEX LAYER 1 — SKYGLOBE ID (layered identity) + TERRA verification gate
-- One account for the whole ecosystem; capabilities unlock through layers.
-- ══════════════════════════════════════════════════════════════════════════
-- SKYGLOBE ID profile fields on the existing clients table (one account, evolves)
alter table clients add column if not exists phone       text;
alter table clients add column if not exists country     text;
alter table clients add column if not exists roles       jsonb default '[]'::jsonb;  -- e.g. ["buyer","seller","business"]
alter table clients add column if not exists id_verified boolean default false;      -- identity verified via TERRA
alter table clients add column if not exists biz_verified boolean default false;     -- business verified via TERRA
alter table clients add column if not exists profile     jsonb default '{}'::jsonb;   -- extended identity (dob, residence, language...)

-- TERRA verification submissions — the trust gate. No verification, no trade.
create table if not exists terra_verifications (
  id bigint generated always as identity primary key,
  ref text unique,
  client_email text,
  kind text,                     -- 'identity' | 'business' | 'address'
  status text default 'pending', -- 'pending' | 'verified' | 'rejected'
  full_name text,
  country text,
  document_type text,            -- passport | national_id | drivers_license | business_registration | tax | utility
  document_ref text,             -- reference / number provided
  business_name text,
  business_reg_no text,
  details jsonb default '{}'::jsonb,
  reviewed_by text,
  review_note text,
  created_at timestamptz default now(),
  reviewed_at timestamptz
);
create index if not exists idx_terra_ver_email on terra_verifications (client_email, kind);
create index if not exists idx_terra_ver_status on terra_verifications (status);

-- YUNEX marketplace listings (created here for Layer 2; harmless if unused now)
create table if not exists yunex_listings (
  id bigint generated always as identity primary key,
  ref text unique,
  seller_email text,
  pillar text,                   -- trade | investment | assets | business | finance | consumer | services | digital
  category text,
  title text,
  description text,
  price numeric,
  currency text default 'USD',
  quantity text,
  location text,
  images jsonb default '[]'::jsonb,
  status text default 'active',  -- active | paused | removed
  created_at timestamptz default now()
);
create index if not exists idx_yunex_listings_seller on yunex_listings (seller_email);
create index if not exists idx_yunex_listings_pillar on yunex_listings (pillar, status);

-- Delegation: responsibilities the CEO assigns to a staff member (Layer: staff/admin shared duties)
alter table staff_members add column if not exists responsibilities jsonb default '[]'::jsonb;

-- ══════════════════════════════════════════════════════════════════════════
-- YUNEX LAYER 3 — Deal Room (verified buyer <-> seller negotiation + escrow)
-- ══════════════════════════════════════════════════════════════════════════
create table if not exists yunex_deals (
  id bigint generated always as identity primary key,
  ref text unique,
  listing_ref text,
  listing_title text,
  buyer_email text,
  seller_email text,
  status text default 'open',       -- open | offer | accepted | paid | shipped | completed | cancelled
  offer_price numeric,
  currency text default 'USD',
  quantity text,
  payment_ref text,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);
create index if not exists idx_yunex_deals_buyer on yunex_deals (buyer_email);
create index if not exists idx_yunex_deals_seller on yunex_deals (seller_email);

create table if not exists yunex_deal_messages (
  id bigint generated always as identity primary key,
  deal_ref text,
  sender_email text,
  sender_role text,                 -- buyer | seller | system
  kind text default 'message',      -- message | offer | system
  body text,
  meta jsonb default '{}'::jsonb,
  created_at timestamptz default now()
);
create index if not exists idx_yunex_dmsg_deal on yunex_deal_messages (deal_ref, created_at);

-- ══════════════════════════════════════════════════════════════════════════
-- TRUST & SECURITY FOUNDATION — email verification, password recovery, KYC
-- ══════════════════════════════════════════════════════════════════════════
alter table clients add column if not exists email_verified boolean default false;

-- Short-lived one-time codes for email verification & password reset.
-- Codes are stored HASHED (sha256) — never in plain text. Auto-expire.
create table if not exists auth_codes (
  id bigint generated always as identity primary key,
  email text,
  kind text,                       -- 'verify_email' | 'reset_password'
  code_hash text,
  expires_at timestamptz,
  used boolean default false,
  attempts int default 0,
  created_at timestamptz default now()
);
create index if not exists idx_auth_codes on auth_codes (email, kind, used);

-- KYC evidence for TERRA verification — private, retained for dispute/compliance.
-- Images live in PRIVATE Supabase storage; only the paths are stored here and
-- served to reviewers through short-lived signed URLs (never public).
alter table terra_verifications add column if not exists doc_image_path text;
alter table terra_verifications add column if not exists selfie_image_path text;
alter table terra_verifications add column if not exists ip text;

-- User moderation: suspend or remove accounts that violate the rules.
alter table clients add column if not exists status text default 'active';   -- active | suspended | removed
alter table clients add column if not exists status_reason text;
alter table clients add column if not exists preferred_currency text;

-- Rich product details (brand, origin, condition, warranty, specs…) for premium listings
alter table yunex_listings add column if not exists details jsonb default '{}'::jsonb;

-- Trade corridors (features, not brands): China · Gulf · Europe · America · Oceania · Africa
alter table yunex_listings add column if not exists corridor text;

-- YUNEX Business Centre — company profiles (public business page per verified owner)
create table if not exists business_profiles (
  id bigint generated always as identity primary key,
  owner_email text unique,
  name text, tagline text, description text, sector text, location text,
  established text, website text, logo_url text,
  is_public boolean default true,
  created_at timestamptz default now(), updated_at timestamptz default now()
);
create index if not exists idx_biz_profiles_owner on business_profiles (owner_email);
alter table business_profiles add column if not exists handle text;
create index if not exists idx_biz_profiles_handle on business_profiles (handle);

-- YUNEX Deal Centre — RFQ (Request for Quotation): buyers post needs, sellers quote
create table if not exists yunex_rfqs (
  id bigint generated always as identity primary key,
  ref text unique, buyer_email text,
  title text, pillar text, category text, quantity text,
  budget numeric, currency text default 'USD', corridor text,
  location text, description text,
  status text default 'open',        -- open | awarded | closed
  created_at timestamptz default now(), updated_at timestamptz default now()
);
create index if not exists idx_rfqs_status on yunex_rfqs (status, created_at);
create index if not exists idx_rfqs_buyer on yunex_rfqs (buyer_email);

create table if not exists yunex_quotes (
  id bigint generated always as identity primary key,
  ref text unique, rfq_ref text, seller_email text,
  price numeric, currency text default 'USD', lead_time text, message text,
  status text default 'pending',     -- pending | accepted | declined
  deal_ref text,
  created_at timestamptz default now()
);
create index if not exists idx_quotes_rfq on yunex_quotes (rfq_ref);
create index if not exists idx_quotes_seller on yunex_quotes (seller_email);

-- YUNEX Complaint & Resolution Centre — disputes on escrow deals
create table if not exists yunex_disputes (
  id bigint generated always as identity primary key,
  ref text unique, deal_ref text,
  raised_by text, against_email text, buyer_email text, seller_email text,
  category text, reason text,
  status text default 'open',       -- open | responded | mediation | resolved
  resolution text,                  -- refund_buyer | release_seller | replace
  resolution_note text, resolved_by text,
  created_at timestamptz default now(), updated_at timestamptz default now()
);
create index if not exists idx_disputes_status on yunex_disputes (status, created_at);
create index if not exists idx_disputes_deal on yunex_disputes (deal_ref);

create table if not exists yunex_dispute_messages (
  id bigint generated always as identity primary key,
  dispute_ref text, sender_email text, sender_role text,  -- buyer | seller | mediator | system
  body text, evidence_url text,
  created_at timestamptz default now()
);
create index if not exists idx_dispute_msgs on yunex_dispute_messages (dispute_ref, created_at);

-- YUNEX Community — professional network (posts, comments, likes)
create table if not exists yunex_posts (
  id bigint generated always as identity primary key,
  ref text unique, author_email text, category text,
  body text, image_url text, likes int default 0, comments int default 0,
  created_at timestamptz default now()
);
create index if not exists idx_posts_cat on yunex_posts (category, created_at);
create table if not exists yunex_post_comments (
  id bigint generated always as identity primary key,
  ref text unique, post_ref text, author_email text, body text,
  created_at timestamptz default now()
);
create index if not exists idx_post_comments on yunex_post_comments (post_ref, created_at);
create table if not exists yunex_post_likes (
  id bigint generated always as identity primary key,
  post_ref text, user_email text, created_at timestamptz default now()
);
create index if not exists idx_post_likes on yunex_post_likes (post_ref, user_email);

-- YUNEX Events & Opportunities — the verified business calendar
create table if not exists yunex_events (
  id bigint generated always as identity primary key,
  ref text unique, host_email text, type text,
  title text, description text, location text, corridor text,
  starts_at text, link text, rsvps int default 0,
  status text default 'open',      -- open | closed
  created_at timestamptz default now()
);
create index if not exists idx_events_type on yunex_events (type, created_at);
create table if not exists yunex_event_rsvps (
  id bigint generated always as identity primary key,
  event_ref text, user_email text, created_at timestamptz default now()
);
create index if not exists idx_event_rsvps on yunex_event_rsvps (event_ref, user_email);

-- YUNEX Reviews & Ratings — earned only through completed deals
create table if not exists yunex_reviews (
  id bigint generated always as identity primary key,
  ref text unique, deal_ref text unique, seller_email text, buyer_email text,
  listing_ref text, listing_title text,
  rating int, comment text,
  created_at timestamptz default now()
);
create index if not exists idx_reviews_seller on yunex_reviews (seller_email);

-- YUNEX Saved / Watchlist
create table if not exists yunex_saved (
  id bigint generated always as identity primary key,
  user_email text, listing_ref text, created_at timestamptz default now()
);
create index if not exists idx_saved_user on yunex_saved (user_email, listing_ref);
