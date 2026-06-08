-- @murich/supabase-multi-issuer-jwt
-- Migration 001: jwt_public_keys registry
--
-- Creates the public-key registry that lets a target Supabase project accept
-- RS256 (or ES*) JWTs signed by multiple external issuers. Each row maps an
-- issuer (`iss` claim) to its PEM-encoded SPKI public key. The library and the
-- Edge Function proxy read this table via the service-role key to verify
-- inbound JWT signatures before re-signing them as HS256 for PostgREST.
--
-- Idempotent: safe to apply repeatedly.
-- Upstream: https://github.com/murich/supabase-multi-issuer-jwt

CREATE TABLE IF NOT EXISTS public.jwt_public_keys (
  issuer       TEXT        PRIMARY KEY,
  public_key   TEXT        NOT NULL,
  algorithm    TEXT        NOT NULL DEFAULT 'RS256'
               CHECK (algorithm IN ('RS256', 'RS384', 'RS512', 'ES256', 'ES384')),
  is_active    BOOLEAN     NOT NULL DEFAULT TRUE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE public.jwt_public_keys IS
  'Registry of public keys (PEM SPKI) for federated multi-issuer JWT auth. '
  'Each row authorizes one external issuer to sign RS256/ES* JWTs accepted by '
  'this Supabase project. Managed by @murich/supabase-multi-issuer-jwt. '
  'See: https://github.com/murich/supabase-multi-issuer-jwt';

COMMENT ON COLUMN public.jwt_public_keys.issuer     IS 'Issuer identifier — must match the `iss` claim on inbound JWTs.';
COMMENT ON COLUMN public.jwt_public_keys.public_key IS 'PEM-encoded SubjectPublicKeyInfo (SPKI) public key.';
COMMENT ON COLUMN public.jwt_public_keys.algorithm  IS 'JWT signing algorithm. One of: RS256, RS384, RS512, ES256, ES384.';
COMMENT ON COLUMN public.jwt_public_keys.is_active  IS 'Set to FALSE to revoke an issuer without losing audit history.';

-- updated_at trigger
CREATE OR REPLACE FUNCTION public.jwt_public_keys_set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := NOW();
  RETURN NEW;
END;
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_trigger
    WHERE tgname = 'jwt_public_keys_set_updated_at'
      AND tgrelid = 'public.jwt_public_keys'::regclass
  ) THEN
    CREATE TRIGGER jwt_public_keys_set_updated_at
      BEFORE UPDATE ON public.jwt_public_keys
      FOR EACH ROW
      EXECUTE FUNCTION public.jwt_public_keys_set_updated_at();
  END IF;
END
$$;

-- RLS: service_role only. The library reads this table via the service-role
-- key; no PostgREST client (anon / authenticated) should ever see public keys
-- via the API, even though they are technically public-by-design — exposing
-- the registry would leak the topology of who can write to this project.
ALTER TABLE public.jwt_public_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.jwt_public_keys FORCE ROW LEVEL SECURITY;

-- Drop any pre-existing policies so re-running the migration produces a
-- clean, predictable state.
DO $$
DECLARE
  pol RECORD;
BEGIN
  FOR pol IN
    SELECT policyname
    FROM pg_policies
    WHERE schemaname = 'public'
      AND tablename = 'jwt_public_keys'
  LOOP
    EXECUTE format('DROP POLICY %I ON public.jwt_public_keys', pol.policyname);
  END LOOP;
END
$$;

CREATE POLICY jwt_public_keys_service_role_all
  ON public.jwt_public_keys
  AS PERMISSIVE
  FOR ALL
  TO service_role
  USING (TRUE)
  WITH CHECK (TRUE);

-- Belt-and-suspenders: revoke any default grants to anon/authenticated.
REVOKE ALL ON public.jwt_public_keys FROM PUBLIC;
REVOKE ALL ON public.jwt_public_keys FROM anon;
REVOKE ALL ON public.jwt_public_keys FROM authenticated;
GRANT  ALL ON public.jwt_public_keys TO   service_role;
