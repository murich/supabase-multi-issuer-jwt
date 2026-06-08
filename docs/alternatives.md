# Alternatives

Five approaches solve the same underlying problem: letting multiple backend
services write to a shared Supabase project. This library is one of them. The
others are sometimes the right answer; this document records the tradeoffs so
the choice is informed.

## Comparison

| Approach                             | Per-service scoping                             | Revocation granularity              | Operational complexity                                 | Service-role exposure                            | Fits stock Supabase               |
| ------------------------------------ | ----------------------------------------------- | ----------------------------------- | ------------------------------------------------------ | ------------------------------------------------ | --------------------------------- |
| **This library**                     | Per-issuer, via RLS on `iss` and `role`         | Per-issuer, by `is_active = false`  | Low — one migration set, one Edge Function             | Held only by the proxy and the registration tool | Yes                               |
| **Shared `service_role` everywhere** | None                                            | Rotate the secret (breaks everyone) | None                                                   | Held by every service                            | Yes                               |
| **Anon key + permissive RLS**        | Coarse, by claim values issuers can self-assert | Edit RLS or rotate anon key         | Low                                                    | Not used                                         | Yes                               |
| **Supabase Auth users for services** | Per-user, via `auth.uid()`                      | Disable user                        | Low–medium                                             | Not used directly                                | Yes                               |
| **Custom PostgREST middleware**      | Arbitrary, fully programmable                   | Whatever the middleware implements  | High — extra service to operate                        | Held by the middleware                           | No — requires forking or proxying |
| **Per-service Supabase project**     | Each service has its own project                | Drop the project                    | High — many projects, federated reads/joins are manual | One key per project                              | Yes                               |

## Detail

### Shared `service_role` key

Every service holds the target's `service_role` key. Writes work because the key
bypasses RLS.

**Pros.** Zero infrastructure. Native Supabase.

**Cons.** One compromise compromises everything. No per-service audit trail in
the database — every write appears to come from "the service role." Revocation
rotates the secret for every consumer simultaneously. RLS can never be used to
scope writers because they bypass it.

**Choose this when.** A single team operates every service that touches the
project, and you accept that any one of those services being compromised means
the whole project is.

### Anon key + permissive RLS

Every service holds the `anon` key. RLS policies grant the writes those services
need, usually by checking values inside the request body or a custom claim
issuers self-assert.

**Pros.** Native Supabase. No proxy.

**Cons.** Issuers self-identify; nothing stops one service from claiming to be
another, so RLS can only safely restrict based on data shape, not on identity.
The `anon` key is also used by the public web client, so leaking it from one
service exposes it to the world. Often this approach silently degrades to
"everything is open to anyone with the key."

**Choose this when.** Writers are entirely trusted and the policy is genuinely
about data shape, not identity.

### Supabase Auth users for services

Each service signs in via Supabase Auth (`signInWithPassword` or similar) and
gets a session JWT. RLS policies check `auth.uid()`.

**Pros.** Fully native — uses the same authentication system as your end users.
Per-service revocation by disabling the user. Audit trail via the `auth.users`
table.

**Cons.** Conflates machine identities with human-user identities in the same
table. Service "users" have email addresses, password reset flows, MFA fields,
etc., that do not apply. Sessions expire and must be refreshed, adding an auth
dance in front of every write. No native concept of "this service can issue
tokens for many sub-identities" — each sub-identity needs its own auth user.

**Choose this when.** You have a small fixed number of service accounts and no
per-sub-identity claims to surface to RLS.

### Custom PostgREST middleware

A separate service sits in front of PostgREST, validates RS256 (or any other
scheme) directly, and either re-signs or sets `request.jwt.claims` on a pooled
connection. The Supabase project is configured (via a fork or a proxy) to trust
this middleware.

**Pros.** Maximum flexibility — arbitrary authentication schemes, arbitrary
claim transformations, arbitrary policy evaluation.

**Cons.** Significant operational complexity. No longer "stock Supabase" — you
maintain your own service, handle its scaling, and own its security posture.
Diverges from upstream PostgREST improvements over time.

**Choose this when.** You have requirements this library cannot satisfy: e.g.
you need to enforce policies before the request hits Postgres at all, or you
need to integrate with an existing identity system Supabase Auth does not
support.

### Per-service Supabase project

Each writer gets its own Supabase project, with its own `service_role` key.
Cross-service reads happen via API calls between projects, or via `dblink` /
`postgres_fdw` between Postgres instances.

**Pros.** Hardest isolation possible. A compromised service only affects its own
project. Per-service backups, scaling, and quotas.

**Cons.** Joins across services become application-level concerns. The Supabase
free tier limits per project apply N times over (or N billing relationships).
Schema changes that touch multiple services must be coordinated by hand. Edge
Function-to-database latency cannot be optimised across projects.

**Choose this when.** Strict regulatory or compliance boundaries require
physical separation, or services are run by different organisations that cannot
share infrastructure.

## When this library is the right answer

This library is the right answer when:

- One Supabase project is the source of truth for data that several backend
  services need to write to.
- Those services are operated by parties that trust the project owner but should
  not trust each other.
- RLS is the natural place to express which service can do what.
- The operational appetite is for one Edge Function and a few SQL migrations,
  not a full custom auth stack.

If your situation matches all four, the comparison is between this library and
"shared `service_role` everywhere" — and the library exists precisely because
the latter has nothing keeping it honest.
