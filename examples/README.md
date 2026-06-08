# Examples

End-to-end demonstration of `@murich/supabase-multi-issuer-jwt` running locally
via Docker Compose. Two services:

- **shop-target** — a Supabase project with the library installed (migrations +
  proxy Edge Function) and a demo `widgets` table guarded by RLS.
- **depot-issuer** — an external service that holds an RS256 private key and
  writes one widget every 30 seconds.

## Prerequisites

- Docker Desktop or compatible engine with Docker Compose v2.
- A local Deno installation (only needed to run the CLI for keygen +
  registration).

## Steps

### 1. Generate a keypair for the demo issuer

From the `examples/` directory:

```sh
mkdir -p keys
deno run -A ../cli/mod.ts keygen --issuer depot-demo --out ./keys
```

This writes `keys/depot-demo.key` (private) and `keys/depot-demo.pub` (public).
Both are mounted into the `depot-issuer` container at `/app/keys/`.

### 2. Configure environment variables

Create `examples/.env` with the values Docker Compose substitutes into the
stack:

```
POSTGRES_PASSWORD=postgres
SUPABASE_JWT_SECRET=super-secret-jwt-token-with-at-least-32-characters
SUPABASE_ANON_KEY=<jwt minted from SUPABASE_JWT_SECRET as role=anon>
SUPABASE_SERVICE_ROLE_KEY=<jwt minted from SUPABASE_JWT_SECRET as role=service_role>
```

The two JWT values can be minted with any HS256 helper — for development the
Supabase team publishes a small generator at
https://supabase.com/docs/guides/self-hosting. Treat all four as secrets even in
a local stack.

### 3. Bring the stack up

```sh
docker compose up -d
```

Wait for `shop-target` to report healthy:

```sh
docker compose ps
```

The first time this runs, the migrations under
`shop-target/supabase/migrations/` apply automatically: `jwt_public_keys` is
created, the `auth.is_issuer` / `auth.has_role` / `auth.issuer` helpers are
installed, and the demo `widgets` table is provisioned with its RLS policies.

### 4. Register the demo issuer's public key (one-time)

The issuer's key is on disk but the target has not been told to trust it yet.
Run the registration helper inside the container:

```sh
docker compose exec depot-issuer \
  deno run --allow-net --allow-read --allow-env /app/src/register.ts
```

Expected output:

```
[register] registered issuer=depot-demo active=true algorithm=RS256
```

This calls `registerPublicKey` against the target's PostgREST using the
`SUPABASE_SERVICE_ROLE_KEY` from the environment. After it succeeds, the row
exists in `jwt_public_keys` and the proxy will accept tokens signed by
`keys/depot-demo.key`.

### 5. Watch widgets get inserted

```sh
docker compose logs -f depot-issuer
```

Every 30 seconds you should see lines like:

```
[depot-issuer] inserted widget [{"id":1,"name":"widget-1717800000000","owner_issuer":"depot-demo","created_at":"..."}]
```

### 6. Inspect the database

Via psql:

```sh
docker compose exec supabase-target \
  psql -U postgres -c \
  "select id, name, owner_issuer, created_at from public.widgets order by id desc limit 10;"
```

Or via Supabase Studio at http://localhost:54323 — the `widgets` table will show
the inserted rows.

### 7. Verify RLS is doing its job

Register a second issuer (`shop-demo`) and try to UPDATE a widget owned by
`depot-demo`. The update will be rejected by the `widgets_update` policy,
because `auth.is_issuer(owner_issuer)` returns false.

```sh
deno run -A ../cli/mod.ts keygen --issuer shop-demo --out ./keys
docker compose exec depot-issuer env ISSUER=shop-demo PUBLIC_KEY_PATH=/app/keys/shop-demo.pub \
  deno run --allow-net --allow-read --allow-env /app/src/register.ts
```

Then mint a `shop-demo` token and attempt an UPDATE — see
[`docs/threat-model.md`](../docs/threat-model.md) for the security guarantees
this exercises.

## Tearing down

```sh
docker compose down -v
rm -rf keys
```

The `-v` removes the Postgres volume so the next `up` starts from a clean
schema.
