# Example: depot-issuer

An issuing service that mints RS256 JWTs and writes widgets to the `shop-target`
example every 30 seconds.

## What this example demonstrates

- Loading an RS256 private key from disk.
- Minting JWTs with `signMultiIssuerJwt`, including a `role` claim consumed by
  RLS.
- Hitting the target's proxy Edge Function (`/functions/v1/rest/...`) the same
  way a real client would.

## Layout

```
depot-issuer/
  src/
    sync.ts       — the main loop: mint, POST, log, sleep, repeat
    register.ts   — one-time public-key registration helper
  Dockerfile
```

## Running standalone

Generate a keypair somewhere accessible:

```sh
deno run -A ../../cli/mod.ts keygen --issuer depot-demo --out ./keys
```

Register the public key on the target (you need the target's service-role key):

```sh
SERVICE_ROLE_KEY=<service-role-key> \
TARGET_URL=http://localhost:54321 \
deno run --allow-net --allow-read --allow-env src/register.ts
```

Run the sync loop:

```sh
TARGET_URL=http://localhost:54321 \
PRIVATE_KEY_PATH=./keys/depot-demo.key \
deno run --allow-net --allow-read --allow-env src/sync.ts
```

## Running via docker-compose

See [`../README.md`](../README.md) for the full integrated walkthrough.
