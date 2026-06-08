# Migrations

SQL migrations for the target Supabase project — i.e. the project that will
_receive_ writes from multiple federated issuers.

Apply them **in numbered order**:

1. `001_jwt_public_keys.sql` — creates the `public.jwt_public_keys` registry
   (issuer → PEM public key), with an `updated_at` trigger and service-role-only
   RLS.
2. `002_auth_helpers.sql` — installs `auth.issuer()`, `auth.jwt_role()`,
   `auth.is_issuer(text)` and `auth.has_role(text)` for use in your RLS
   policies.

## How to apply

### Supabase CLI

Copy these files into your project's `supabase/migrations/` directory (keep the
leading numeric prefix) and run:

```bash
supabase db push
```

The CLI will apply them in lexicographic order alongside any of your own
migrations.

### Manual (psql)

Run them directly against your database — typically the pooled connection string
from the Supabase dashboard:

```bash
psql "$DATABASE_URL" -f migrations/001_jwt_public_keys.sql
psql "$DATABASE_URL" -f migrations/002_auth_helpers.sql
```

Both files are idempotent and safe to re-run.

## What next

Once these are applied, register one or more issuer public keys with the
[`cli/register.ts`](../cli/register.ts) tool, deploy the
[`templates/jwt-proxy/`](../templates/jwt-proxy/) Edge Function, and start
writing RLS policies that use `auth.is_issuer(...)` / `auth.has_role(...)`.

See the [top-level README](../README.md) for the full quickstart.
