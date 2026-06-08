# Architecture

This document explains what happens on each request through
`@murich/supabase-multi-issuer-jwt`, why the design uses two JWT algorithms,
what the registry table is for, and the alternatives that were rejected.

## Request lifecycle

A single write from an issuing service to the target Supabase project flows
through four trust boundaries: the issuer process, the public network, the proxy
Edge Function, and PostgREST + Postgres.

1. **Issuer mints the token.** The issuing service calls
   `signMultiIssuerJwt({ privateKey, issuer, claims })`. The function constructs
   the JWT header (`alg: "RS256"`, `typ: "JWT"`), assembles the claim set (the
   caller-provided claims plus `iat`, `exp` derived from `expiresIn`), and signs
   the encoded `header.payload` with the issuer's private key using `jose`. The
   resulting token's `iss` claim identifies which row in the registry should
   validate it.

2. **HTTP request to the proxy.** The issuer sends a normal PostgREST request —
   for example `POST /functions/v1/rest/widgets` — with the RS256 JWT in the
   `Authorization: Bearer` header. The body is whatever PostgREST expects (the
   proxy does not interpret it).

3. **Proxy verification.** The Edge Function (built from `templates/jwt-proxy/`)
   wraps the handler returned by `createJwtSwapProxy`. For each inbound request
   the handler:
   - Extracts the bearer token, decodes the header, and pulls out `iss` from the
     payload without verifying the signature.
   - Queries `jwt_public_keys` using a Supabase client constructed with the
     proxy's `service_role` key. The query selects `public_key`, `algorithm`,
     and `is_active` for that issuer.
   - Rejects with `JwtVerificationError("unknown_issuer")` if no row matches, or
     `JwtVerificationError("inactive_issuer")` if `is_active = false`.
   - Verifies the signature against the registered public key using
     `jose.jwtVerify`, with `clockToleranceSec` applied to `exp` and `iat`
     checks.
   - Rejects with `JwtVerificationError("issuer_not_allowed")` if
     `allowedIssuers` is configured and the token's `iss` is not in the list.

4. **Re-sign as HS256.** Once verification succeeds, the proxy assembles a new
   JWT with the same claim set plus any platform-required claims (notably
   `role`, defaulting to `authenticated` if the original token did not specify
   one, and `aud: "authenticated"`). It signs this token with HS256 using the
   target Supabase project's JWT secret (`supabaseJwtSecret`). The new token is
   byte-for-byte indistinguishable from a token Supabase's own `gotrue` would
   emit, except for the additional custom claims that survive from the original.

5. **Forward to PostgREST.** The proxy rewrites the inbound URL by stripping
   `mountPath` (default `/functions/v1/rest`) and prepending
   `${supabaseUrl}/rest/v1`. It forwards method, body, and most headers, but
   replaces `Authorization` with the new HS256 token and injects the `apikey`
   header with the same. PostgREST sees a plain Supabase JWT, validates the
   HS256 signature with the secret it already has, calls `SET LOCAL ROLE` to the
   role claim, sets `request.jwt.claims` for the session, and executes the
   request.

6. **RLS in Postgres.** Policies on the target table read
   `auth.jwt() ->> 'iss'`, `auth.jwt() ->> 'role'`, and any other custom claims
   via the helper functions in `migrations/002_auth_helpers.sql`. The query runs
   under the JWT role with RLS applied. The response flows back up through
   PostgREST and the proxy to the issuer.

The key property: PostgREST never sees the RS256 token. The registry is read
only by the proxy, never by PostgREST or Postgres directly during a request. The
`service_role` key never crosses the network beyond the proxy.

## Why two JWT formats

The library mints and verifies RS256 (asymmetric), then re-issues HS256
(symmetric) before talking to PostgREST. Each choice is forced.

**RS256 between issuers and the proxy.** Issuers must be able to produce JWTs
the target accepts, but should not be able to forge tokens claiming to be a
different issuer. With asymmetric keys, each issuer holds only its own private
key. The target holds public keys, which are by definition non-sensitive — they
verify but cannot sign. A compromised issuer leaks only its own signing
capability, not the ability to impersonate others. A compromised target registry
leaks only public keys, which grant nothing.

**HS256 between the proxy and PostgREST.** PostgREST validates JWTs using the
algorithm and key configured for the Supabase project, which is HS256 with the
project's JWT secret. Changing that would require running a forked PostgREST,
intercepting and patching the upstream request handler, or convincing the
Supabase platform to support per-project asymmetric verification. None of those
are tractable for a drop-in library. Re-signing with the target's native HS256
secret inside the trusted proxy avoids modifying PostgREST and keeps the moving
parts inside a single Edge Function the user owns.

The trust boundary is precisely the proxy: an attacker who controls the proxy's
environment (the Edge Function's secrets) can mint arbitrary HS256 tokens and
bypass the registry entirely. That is the same blast radius as someone with
direct access to the target's JWT secret, and is the same security posture as
native Supabase.

## The `jwt_public_keys` registry

`migrations/001_jwt_public_keys.sql` creates the registry table:

```sql
create table public.jwt_public_keys (
  issuer       text primary key,
  public_key   text not null,
  algorithm    text not null default 'RS256'
               check (algorithm in ('RS256','RS384','RS512','ES256','ES384')),
  is_active    boolean not null default true,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);
```

Row Level Security is enabled with no public policies. The proxy reads through
the `service_role` key, which bypasses RLS. The CLI's `register` and
`deactivate` commands likewise require the service-role key. There is
intentionally no anon-readable view: leaking the set of registered issuers would
help an attacker target specific keys, and there is no legitimate caller that
needs the list other than operators with full access.

The table is keyed by issuer name. Issuer names should be stable identifiers
(`depot-padigital`, `shop-sync-worker`) and used as foreign keys from
application tables — RLS policies reference them by string equality with
`auth.jwt() ->> 'iss'`.

`is_active = false` is the revocation mechanism. The proxy treats inactive rows
as if the issuer were unknown, so existing tokens become unusable on their next
request. There is no token blocklist by `jti` — revocation is at the issuer
level, not the individual JWT level. This is a deliberate simplification: in
this model, tokens are short-lived and issuers are the unit of trust.

## Why not a custom PostgREST middleware

An alternative considered and rejected was to write a small middleware in front
of PostgREST that validates RS256 directly, then either passes the token through
(requiring patched PostgREST) or sets `request.jwt.claims` via `SET LOCAL` on a
pooled connection (bypassing PostgREST's own JWT handling).

This was rejected for three reasons. First, it requires running and operating a
separate process — not a one-shot Edge Function — which makes the library a
service to deploy rather than a function to copy. Second, it duplicates
PostgREST's JWT logic; staying close to native HS256 means everything PostgREST
does with the JWT (audience, role mapping, expiry, claim propagation) continues
to work without re-implementation. Third, future Supabase platform changes to
JWT handling would silently diverge from a forked code path; re-signing means
the library benefits from upstream improvements for free.

The Edge Function approach has one cost: an extra hop, with the associated
latency. In practice this is a single-region call inside the Supabase project,
on the order of a few milliseconds.

## Relationship to the Contract Farming auth model

This library generalises the auth pattern documented in Padigital's Contract
Farming wiki
(https://redmine.blessthis.software/projects/padigital/wiki/Contract-Farming-Auth-Architecture).
The pattern was developed for one ecosystem and one specific cross-app
integration; this package extracts the reusable parts — registry table,
RS256/HS256 swap proxy, RLS helpers, key management CLI — so the same pattern
can be applied to any Supabase project that needs to accept writes from multiple
independent services.
