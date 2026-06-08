# Example: shop-target

A target Supabase project that accepts writes from multiple issuing services via
`@murich/supabase-multi-issuer-jwt`.

## What this example demonstrates

- The library's migrations applied as a clean Supabase install
  (`001_install_lib.sql`, `002_install_lib_helpers.sql`).
- A demo `widgets` table with RLS policies scoped by issuer and role
  (`003_demo_widgets_table.sql`).
- The proxy Edge Function deployed as `rest`
  (`supabase/functions/rest/index.ts`).

## Layout

```
shop-target/
  supabase/
    config.toml
    migrations/
      001_install_lib.sql
      002_install_lib_helpers.sql
      003_demo_widgets_table.sql
    functions/
      rest/
        index.ts
```

## Running standalone

This example is normally driven from the parent `examples/docker-compose.yml`.
To run it standalone:

```sh
cd examples/shop-target
supabase start
supabase functions serve rest --no-verify-jwt --env-file ../.env.local
```

`../.env.local` (not committed) must contain:

```
SUPABASE_URL=http://localhost:54321
SUPABASE_SERVICE_ROLE_KEY=<from `supabase status` output>
SUPABASE_JWT_SECRET=<from `supabase status` output>
```

## Registering an issuer

From the parent examples directory, with a generated keypair under `./keys/`:

```sh
deno run -A ../../cli/mod.ts register \
  --target http://localhost:54321 \
  --service-role "$SUPABASE_SERVICE_ROLE_KEY" \
  --issuer depot-demo \
  --public-key ./keys/depot-demo.pub
```

## Verifying writes

After the depot-issuer example has run for a minute, query the widgets table:

```sh
supabase db remote psql -c "select id, name, owner_issuer, created_at from public.widgets order by id desc limit 10;"
```

You should see rows with `owner_issuer = 'depot-demo'` being inserted every 30
seconds.

## Trying RLS

The policies in `003_demo_widgets_table.sql` enforce:

- INSERTs require `auth.has_role('widgets_writer')` and
  `owner_issuer = auth.issuer()`.
- UPDATE and DELETE require `auth.is_issuer(owner_issuer)`.

Try registering a second issuer (`shop-demo`), mint a token for it, and attempt
to UPDATE a widget owned by `depot-demo`. The request will be rejected by RLS.
