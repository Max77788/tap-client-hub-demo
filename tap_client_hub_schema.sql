-- =====================================================================
-- TAP Client Hub — Supabase schema + access control (starter)
-- Postgres 15+. Paste into the Supabase SQL editor and run ONCE.
--
-- Design goals
--   1. One source of truth: clients -> client_services -> work_periods.
--   2. Sensitive fields (fees, amounts, portal logins, tax IDs) live in
--      their own tables so they can be hidden at the COLUMN level and
--      shown only to a "select few" (admin / manager).
--   3. Everything protected by Row-Level Security (deny-by-default).
--   4. Portal logins store a POINTER to a password manager, never the
--      real secret. Bank logins are not stored here at all.
-- =====================================================================

-- ---------- 0. Enumerated types -------------------------------------
create type app_role    as enum ('admin','manager','staff','offshore');
create type client_type as enum ('business','personal');
create type svc_freq    as enum ('weekly','bi_weekly','semi_monthly',
                                  'monthly','quarterly','yearly','annual');
create type work_stage  as enum ('not_started','done','billed','paid','na');

-- ---------- 1. Profiles (1:1 with auth.users) -----------------------
-- Who can log in, their role, and where they sit (US / India).
create table profiles (
  id         uuid primary key references auth.users(id) on delete cascade,
  full_name  text not null,
  role       app_role not null default 'staff',
  location   text,                       -- 'US' or 'India'
  active     boolean not null default true,
  created_at timestamptz not null default now()
);

-- Helper functions. SECURITY DEFINER so the role lookup itself isn't
-- blocked by RLS (avoids recursive policy evaluation).
create or replace function auth_role() returns app_role
  language sql stable security definer set search_path = public as $$
    select role from profiles where id = auth.uid()
$$;

create or replace function is_privileged() returns boolean   -- admin OR manager
  language sql stable security definer set search_path = public as $$
    select coalesce((select role in ('admin','manager')
                     from profiles where id = auth.uid()), false)
$$;

create or replace function is_admin() returns boolean
  language sql stable security definer set search_path = public as $$
    select coalesce((select role = 'admin'
                     from profiles where id = auth.uid()), false)
$$;

-- ---------- 2. Core (non-sensitive) operational data ----------------
create table clients (
  id          uuid primary key default gen_random_uuid(),
  name        text not null,
  type        client_type not null default 'business',
  entity_type text,                       -- single-member LLC, S-corp, ...
  group_owner text,
  status      text not null default 'active',
  city text, state text, zip text, address text,
  notes       text,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create table contacts (
  id         uuid primary key default gen_random_uuid(),
  client_id  uuid not null references clients(id) on delete cascade,
  name text, email text, phone text,
  is_primary boolean not null default false
);

create table services (
  id     uuid primary key default gen_random_uuid(),
  code   text unique not null,            -- FIN, PR, STX, T9, REND, TAX, RENEWAL
  name   text not null,
  active boolean not null default true
);

-- The heart of the model: one row per (client x service).
-- Turning a service "on" = insert/activate a row; "off" = active=false.
-- Every worklist is just a filter on this table.
create table client_services (
  id          uuid primary key default gen_random_uuid(),
  client_id   uuid not null references clients(id) on delete cascade,
  service_id  uuid not null references services(id),
  assigned_to uuid references profiles(id),
  active      boolean not null default true,
  frequency   svc_freq,
  processor   text,                       -- ADP, Toast, QuickBooks, ...
  software    text,
  started_on  date, ended_on date,
  notes       text,
  unique (client_id, service_id)
);

-- One row per client_service per month. Powers the monthly grid,
-- the billed/paid cycle, and the workload rollups.
create table work_periods (
  id                uuid primary key default gen_random_uuid(),
  client_service_id uuid not null references client_services(id) on delete cascade,
  period            text not null,        -- 'YYYY-MM'
  stage             work_stage not null default 'not_started',
  done_by           uuid references profiles(id),
  done_at timestamptz, billed_at timestamptz, paid_at timestamptz,
  notes             text,
  unique (client_service_id, period)
);

-- ---------- 3. Sensitive data (isolated tables) ---------------------
-- These columns are split out so RLS can restrict them to the few.
create table client_tax_ids (             -- PII: EIN / SSN last 4
  client_id uuid primary key references clients(id) on delete cascade,
  ein text, ssn_last4 text
);

create table client_service_billing (     -- the monthly fee
  client_service_id uuid primary key references client_services(id) on delete cascade,
  monthly_fee numeric(12,2)
);

create table work_period_billing (        -- billed/paid amount per month
  work_period_id uuid primary key references work_periods(id) on delete cascade,
  amount numeric(12,2)
);

create table credentials (                -- portal logins (NOT bank, NOT raw secrets)
  id        uuid primary key default gen_random_uuid(),
  client_id uuid references clients(id) on delete cascade,
  portal    text not null,                -- Toast, ADP, TX Comptroller, EFTPS...
  username  text,
  vault_ref text,                         -- pointer to 1Password/Bitwarden item
  notes     text
  -- NOTE: never store the actual password here. Bank logins stay in TAP Bank.
);

create table audit_log (                   -- who changed what, when
  id       bigserial primary key,
  actor    uuid references profiles(id),
  action   text, entity text, entity_id text,
  detail   jsonb,
  at       timestamptz not null default now()
);

-- ---------- 4. Row-Level Security -----------------------------------
alter table profiles               enable row level security;
alter table clients                enable row level security;
alter table contacts               enable row level security;
alter table services               enable row level security;
alter table client_services        enable row level security;
alter table work_periods           enable row level security;
alter table client_tax_ids         enable row level security;
alter table client_service_billing enable row level security;
alter table work_period_billing    enable row level security;
alter table credentials            enable row level security;
alter table audit_log              enable row level security;

-- Profiles: see your own; admins see/manage all.
create policy profiles_self_read  on profiles for select using (id = auth.uid() or is_admin());
create policy profiles_admin_write on profiles for all   using (is_admin()) with check (is_admin());

-- Core operational tables: any signed-in user may READ.
create policy read_clients  on clients         for select using (auth.uid() is not null);
create policy read_contacts on contacts        for select using (auth.uid() is not null);
create policy read_services on services        for select using (auth.uid() is not null);
create policy read_cs       on client_services for select using (auth.uid() is not null);
create policy read_wp       on work_periods    for select using (auth.uid() is not null);

-- Operational writes: admin / manager / staff may add & edit.
create policy write_clients  on clients         for all
  using (auth_role() in ('admin','manager','staff')) with check (auth_role() in ('admin','manager','staff'));
create policy write_contacts on contacts        for all
  using (auth_role() in ('admin','manager','staff')) with check (auth_role() in ('admin','manager','staff'));
create policy write_cs       on client_services for all
  using (auth_role() in ('admin','manager','staff')) with check (auth_role() in ('admin','manager','staff'));

-- Work status: staff edit freely; OFFSHORE can update only THEIR assigned rows.
create policy write_wp_staff on work_periods for all
  using (auth_role() in ('admin','manager','staff')) with check (auth_role() in ('admin','manager','staff'));
create policy write_wp_offshore on work_periods for update
  using (auth_role() = 'offshore' and exists (
    select 1 from client_services cs
    where cs.id = work_periods.client_service_id and cs.assigned_to = auth.uid()))
  with check (true);

-- Service catalog: admin only.
create policy write_services on services for all using (is_admin()) with check (is_admin());

-- SENSITIVE tables: privileged (admin/manager) only, read AND write.
create policy priv_taxids    on client_tax_ids         for all using (is_privileged()) with check (is_privileged());
create policy priv_csbilling on client_service_billing for all using (is_privileged()) with check (is_privileged());
create policy priv_wpbilling on work_period_billing    for all using (is_privileged()) with check (is_privileged());
create policy priv_creds     on credentials            for all using (is_privileged()) with check (is_privileged());

-- Audit log: privileged can read; any signed-in user may append.
create policy audit_read   on audit_log for select using (is_privileged());
create policy audit_insert on audit_log for insert with check (auth.uid() is not null);

-- ---------- 5. Seed the service catalog ----------------------------
insert into services (code, name) values
  ('FIN','Monthly Financials'), ('PR','Payroll'), ('STX','Sales Tax'),
  ('T9','1099s'), ('REND','Renditions'), ('TAX','Tax Return'), ('RENEWAL','State Renewal')
on conflict (code) do nothing;

-- ---------- 6. Example view the app reads --------------------------
-- security_invoker = on  -> the view respects the caller's RLS, so
-- non-privileged users still can't reach sensitive tables through it.
create view v_worklist with (security_invoker = on) as
  select cs.id, s.code as service, c.name as client, c.type,
         p.full_name as assigned_to, cs.frequency, cs.active
  from client_services cs
  join clients  c on c.id = cs.client_id
  join services s on s.id = cs.service_id
  left join profiles p on p.id = cs.assigned_to
  where cs.active;

-- =====================================================================
-- HARDENING CHECKLIST (configure in the Supabase dashboard, not SQL)
--   [ ] Auth: email + password for the 10 users; require email confirm.
--   [ ] Enable MFA (TOTP / authenticator app) for every account.
--   [ ] Enable leaked-password protection (HaveIBeenPwned check).
--   [ ] NEVER expose the service_role key to the browser (server-side only).
--   [ ] Keep RLS enabled on every table (above). New tables = new policies.
--   [ ] Turn on Point-in-Time Recovery / verify daily backups.
--   [ ] Store any real secret values in Supabase Vault, not plain columns.
--   [ ] After creating each user in Auth, insert their profiles row with
--       the correct role ('admin' | 'manager' | 'staff' | 'offshore').
-- =====================================================================
