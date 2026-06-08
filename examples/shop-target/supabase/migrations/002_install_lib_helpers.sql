-- Installs the auth helper functions from @murich/supabase-multi-issuer-jwt.
-- Source: ../../../migrations/002_auth_helpers.sql

create or replace function auth.issuer()
  returns text
  language sql stable
as $$
  select nullif(current_setting('request.jwt.claims', true)::jsonb ->> 'iss', '')
$$;

create or replace function auth.is_issuer(expected text)
  returns boolean
  language sql stable
as $$
  select auth.issuer() = expected
$$;

create or replace function auth.has_role(expected text)
  returns boolean
  language sql stable
as $$
  select nullif(current_setting('request.jwt.claims', true)::jsonb ->> 'role', '') = expected
$$;

comment on function auth.issuer() is
  'Returns the iss claim from the current JWT, or null if absent.';
comment on function auth.is_issuer(text) is
  'Returns true when the JWT iss claim equals the argument.';
comment on function auth.has_role(text) is
  'Returns true when the JWT role claim equals the argument.';
