# `jwt-proxy` — Supabase Edge Function template

This is the Edge Function that target operators deploy on the **receiving**
Supabase project. It verifies inbound RS256 (or ES*) JWTs against the
`jwt_public_keys` registry and re-signs them as HS256 so PostgREST accepts them
natively.

## 1. Prerequisites

- Migrations `001_jwt_public_keys.sql` and `002_auth_helpers.sql` applied to the
  target project (see [`../../migrations/`](../../migrations/)).
- At least one issuer public key registered (`cli/register.ts`).
- Supabase CLI installed and linked to the project (`supabase link`).

## 2. Copy the function into your Supabase project

Supabase expects functions under `supabase/functions/<name>/`. Conventionally
this proxy lives at `supabase/functions/rest/`:

```bash
mkdir -p supabase/functions/rest
cp templates/jwt-proxy/index.ts supabase/functions/rest/index.ts
```

## 3. Set the function secrets

The function refuses to start if any of these is missing. Set them with the
Supabase CLI (they become `Deno.env.get(...)` at runtime):

```bash
supabase secrets set \
  SUPABASE_URL="https://<your-project-ref>.supabase.co" \
  SUPABASE_SERVICE_ROLE_KEY="<service-role-key>" \
  SUPABASE_JWT_SECRET="<jwt-secret-from-project-settings>"

# Optional — restrict to a specific set of issuers (comma-separated):
supabase secrets set ALLOWED_ISSUERS="depot-stack,supplier-stack"
```

`SUPABASE_JWT_SECRET` is the HS256 secret found under _Project Settings → API →
JWT Settings_ in the Supabase dashboard. It is the same secret PostgREST uses to
validate the _native_ anon / service-role tokens — the proxy re-signs with it so
PostgREST treats our request as a first-class Supabase JWT.

## 4. Deploy

```bash
supabase functions deploy rest --no-verify-jwt
```

### Why `--no-verify-jwt` is mandatory

By default Supabase's Edge Functions gateway validates the inbound
`Authorization: Bearer <jwt>` header against the project's HS256 JWT secret
_before_ invoking your function. Our inbound tokens are RS256-signed by external
issuers — they will **always** fail that gateway check, and your function never
runs.

`--no-verify-jwt` disables that gateway hop. The proxy then does its own,
stricter verification:

1. Decode JWT header → require RS256/RS384/RS512/ES256/ES384.
2. Look up `iss` in `jwt_public_keys`.
3. Reject if absent, inactive, or (optionally) not in `ALLOWED_ISSUERS`.
4. Cryptographically verify the signature with the registered public key.
5. Mint a fresh HS256 JWT with the _same_ claims, signed with
   `SUPABASE_JWT_SECRET`.
6. Forward the request to `${SUPABASE_URL}/rest/v1/...` with the new token.

PostgREST sees a normal HS256 Supabase JWT and applies RLS using whatever claims
you minted (`role`, `iss`, `sub`, plus any custom claims your policies reference
via `auth.jwt() ->> '...'` or the helpers in `migrations/002_auth_helpers.sql`).

## 5. Smoke-test

```bash
# Health endpoint — does not require auth:
curl https://<project-ref>.supabase.co/functions/v1/rest/health
# => {"ok":true,"version":"0.1.0"}

# Real call — mint a JWT with cli/mint.ts then:
JWT=$(deno run -A cli/mod.ts mint \
  --private-key ./keys/depot-stack.key \
  --issuer depot-stack \
  --claims '{"role":"depots_sync_writer","sub":"sync-cron"}')

curl -H "Authorization: Bearer $JWT" \
  https://<project-ref>.supabase.co/functions/v1/rest/depots?select=id
```

## 6. Observability

Every request logs one line:

```
[2026-06-08T12:34:56.789Z] POST /functions/v1/rest/depots iss=depot-stack
```

`iss` is the inbound `iss` claim (best-effort decode for the log only — the
proxy still verifies the signature). `iss=?` means the header was missing or
malformed; the proxy will reject such requests with `401`.

Tail logs with:

```bash
supabase functions logs rest --follow
```
