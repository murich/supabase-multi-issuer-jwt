-- @murich/supabase-multi-issuer-jwt
-- Migration 002: auth.* convenience helpers for RLS policies
--
-- These helpers wrap the standard `auth.jwt()` extractor so RLS policies stay
-- readable. They are intentionally tiny and STABLE so the planner can fold
-- them into policy predicates without extra overhead.
--
-- All helpers are SECURITY DEFINER and run as the function owner; they only
-- read the JWT claims set by PostgREST/GoTrue on the current request, so
-- they cannot escalate privilege.
--
-- Idempotent: uses CREATE OR REPLACE.
-- Upstream: https://github.com/murich/supabase-multi-issuer-jwt

-- auth.issuer() — current request's `iss` claim, or NULL.
CREATE OR REPLACE FUNCTION auth.issuer()
RETURNS TEXT
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT NULLIF(auth.jwt() ->> 'iss', '')::text;
$$;

COMMENT ON FUNCTION auth.issuer() IS
  'Returns the `iss` claim of the current request JWT, or NULL. '
  'Provided by @murich/supabase-multi-issuer-jwt.';

-- auth.jwt_role() — current request's `role` claim, or NULL.
CREATE OR REPLACE FUNCTION auth.jwt_role()
RETURNS TEXT
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT NULLIF(auth.jwt() ->> 'role', '')::text;
$$;

COMMENT ON FUNCTION auth.jwt_role() IS
  'Returns the `role` claim of the current request JWT, or NULL. '
  'Distinct from the Postgres session role exposed by current_user / current_role. '
  'Provided by @murich/supabase-multi-issuer-jwt.';

-- auth.is_issuer(text) — convenience equality check for RLS policies.
CREATE OR REPLACE FUNCTION auth.is_issuer(expected TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT (auth.jwt() ->> 'iss') = expected;
$$;

COMMENT ON FUNCTION auth.is_issuer(TEXT) IS
  'Returns TRUE when the current JWT `iss` claim equals the argument. '
  'Use in RLS policies: USING (auth.is_issuer(''depot-stack'')). '
  'Provided by @murich/supabase-multi-issuer-jwt.';

-- auth.has_role(text) — convenience equality check for the `role` claim.
CREATE OR REPLACE FUNCTION auth.has_role(expected TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT (auth.jwt() ->> 'role') = expected;
$$;

COMMENT ON FUNCTION auth.has_role(TEXT) IS
  'Returns TRUE when the current JWT `role` claim equals the argument. '
  'Use in RLS policies: USING (auth.has_role(''depots_sync_writer'')). '
  'Provided by @murich/supabase-multi-issuer-jwt.';

-- Grants: PostgREST-mapped roles need EXECUTE so policies can invoke them.
GRANT EXECUTE ON FUNCTION auth.issuer()             TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION auth.jwt_role()           TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION auth.is_issuer(TEXT)      TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION auth.has_role(TEXT)       TO anon, authenticated, service_role;
