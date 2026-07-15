-- Run this ONCE in the Supabase SQL editor for the SkyGlobe project.
-- It creates the table that stores CEO-portal price changes so they
-- survive server restarts/redeploys. Without this table, price edits
-- from the Pricing tab still work live but reset next restart.

create table if not exists pricing_overrides (
  product text primary key,
  usd numeric,
  eur numeric,
  gbp numeric,
  label text,
  updated_at timestamptz default now()
);

-- Optional: allow the service-role key (used by server.js) full access.
-- If you already have RLS disabled for backend tables, skip this.
alter table pricing_overrides disable row level security;
