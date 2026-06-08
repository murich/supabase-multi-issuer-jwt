-- Installs the public-key registry from @murich/supabase-multi-issuer-jwt.
-- Source: ../../../migrations/001_jwt_public_keys.sql

create table if not exists public.jwt_public_keys (
  issuer       text primary key,
  public_key   text not null,
  algorithm    text not null default 'RS256'
               check (algorithm in ('RS256','RS384','RS512','ES256','ES384')),
  is_active    boolean not null default true,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

alter table public.jwt_public_keys enable row level security;

-- No public policies. Only the service_role (used by the proxy and the
-- registration tooling) bypasses RLS and can read or write this table.

create index if not exists jwt_public_keys_active_idx
  on public.jwt_public_keys (issuer)
  where is_active = true;

comment on table public.jwt_public_keys is
  'Registry of public keys trusted by the JWT swap proxy. One row per issuing service.';
