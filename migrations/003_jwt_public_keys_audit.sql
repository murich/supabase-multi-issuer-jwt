-- @murich/supabase-multi-issuer-jwt
-- Migration 003: audit log for jwt_public_keys mutations
--
-- Appends one row to jwt_public_keys_audit on every INSERT, UPDATE, or DELETE
-- on jwt_public_keys. The audit table is append-only — no UPDATE or DELETE is
-- granted even to service_role — so past records cannot be erased.
--
-- Idempotent: safe to apply repeatedly.
-- Upstream: https://github.com/murich/supabase-multi-issuer-jwt

CREATE TABLE IF NOT EXISTS public.jwt_public_keys_audit (
  id          BIGSERIAL   PRIMARY KEY,
  action      TEXT        NOT NULL CHECK (action IN ('INSERT', 'UPDATE', 'DELETE')),
  issuer      TEXT        NOT NULL,
  old_row     JSONB,
  new_row     JSONB,
  changed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  changed_by  TEXT        NOT NULL DEFAULT current_user
);

COMMENT ON TABLE public.jwt_public_keys_audit IS
  'Append-only audit log for jwt_public_keys mutations. '
  'Records every INSERT, UPDATE, and DELETE with old/new row snapshots. '
  'Provided by @murich/supabase-multi-issuer-jwt.';

CREATE OR REPLACE FUNCTION public.jwt_public_keys_audit_fn()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  INSERT INTO public.jwt_public_keys_audit (action, issuer, old_row, new_row)
  VALUES (
    TG_OP,
    COALESCE(NEW.issuer, OLD.issuer),
    CASE WHEN TG_OP = 'INSERT' THEN NULL ELSE to_jsonb(OLD) END,
    CASE WHEN TG_OP = 'DELETE' THEN NULL ELSE to_jsonb(NEW) END
  );
  RETURN COALESCE(NEW, OLD);
END;
$$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger
    WHERE tgname = 'jwt_public_keys_audit'
      AND tgrelid = 'public.jwt_public_keys'::regclass
  ) THEN
    CREATE TRIGGER jwt_public_keys_audit
      AFTER INSERT OR UPDATE OR DELETE ON public.jwt_public_keys
      FOR EACH ROW EXECUTE FUNCTION public.jwt_public_keys_audit_fn();
  END IF;
END
$$;

ALTER TABLE public.jwt_public_keys_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.jwt_public_keys_audit FORCE ROW LEVEL SECURITY;

DO $$
DECLARE
  pol RECORD;
BEGIN
  FOR pol IN
    SELECT policyname FROM pg_policies
    WHERE schemaname = 'public' AND tablename = 'jwt_public_keys_audit'
  LOOP
    EXECUTE format('DROP POLICY %I ON public.jwt_public_keys_audit', pol.policyname);
  END LOOP;
END
$$;

-- service_role can read and append; no UPDATE or DELETE for anyone.
CREATE POLICY jwt_public_keys_audit_service_role_read
  ON public.jwt_public_keys_audit
  AS PERMISSIVE FOR SELECT
  TO service_role
  USING (TRUE);

CREATE POLICY jwt_public_keys_audit_service_role_insert
  ON public.jwt_public_keys_audit
  AS PERMISSIVE FOR INSERT
  TO service_role
  WITH CHECK (TRUE);

REVOKE ALL  ON public.jwt_public_keys_audit FROM PUBLIC;
REVOKE ALL  ON public.jwt_public_keys_audit FROM anon;
REVOKE ALL  ON public.jwt_public_keys_audit FROM authenticated;
GRANT  SELECT, INSERT ON public.jwt_public_keys_audit TO service_role;
