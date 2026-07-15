-- Run this ONCE in the Supabase SQL editor for the SkyGlobe project.
-- Powers the CEO-editable homepage announcement slide — push a new country
-- opening, a deadline, or an offer live instantly, no code change, no
-- redeploy.

create table if not exists announcements (
  id bigint generated always as identity primary key,
  icon text default '📣',
  tag text default '',
  headline text not null,
  subtext text default '',
  button_text text default '',
  button_link text default '',
  active boolean default true,
  priority int default 0,          -- lower shows first
  starts_at timestamptz,           -- optional scheduling window
  ends_at timestamptz,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

create index if not exists announcements_active_idx on announcements (active);

alter table announcements disable row level security;
