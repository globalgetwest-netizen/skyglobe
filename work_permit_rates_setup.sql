-- Run this ONCE in the Supabase SQL editor for the SkyGlobe project.
-- Stores per-country, per-occupation work permit service fees, with an
-- "active" flag so the CEO portal can open/close a country or role without
-- any code change or redeploy. The server auto-seeds a starter set of rows
-- the first time it boots against an empty table (see server.js).

create table if not exists work_permit_rates (
  id bigint generated always as identity primary key,
  country_code text not null,
  country_name text not null,
  flag text default '',
  occupation text not null,
  skill_level text default '',   -- e.g. Unskilled / Skilled / Professional
  active boolean default true,
  usd numeric,
  eur numeric,
  gbp numeric,
  processing_weeks text default '',
  notes text default '',
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

create index if not exists work_permit_rates_country_idx on work_permit_rates (country_code);
create index if not exists work_permit_rates_active_idx on work_permit_rates (active);

alter table work_permit_rates disable row level security;
