# Threat model

This document enumerates the threats relevant to a deployment of
`@murich/supabase-multi-issuer-jwt` and the mitigations the library provides or
assumes. Threats are listed by attacker capability, not by ranked severity.

## Stolen issuer private key

**Capability gained.** The attacker can mint arbitrary RS256 JWTs for that
issuer, with any `sub`, `role`, and custom claims. Any RLS policy that trusts
`auth.is_issuer('<that-issuer>')` is fully bypassed within the scope that issuer
is permitted.

**Mitigation.** Revoke the issuer by setting `is_active = false` on its
`jwt_public_keys` row:

```sh
npx supabase-multi-issuer-jwt deactivate \
  --target https://your-project.supabase.co \
  --service-role "$SUPABASE_SERVICE_ROLE_KEY" \
  --issuer my-service
```

Or directly via SQL:

```sql
update public.jwt_public_keys
  set is_active = false, updated_at = now()
  where issuer = 'my-service';
```

After revocation, the proxy rejects every subsequent request from that issuer
with `JwtVerificationError("inactive_issuer")`, regardless of whether the
underlying token signature is still valid. Tokens already in flight at the time
of revocation are rejected on their next call.

Recovery: generate a new keypair (`keygen`), register it under the same or a
fresh issuer name, redeploy the issuing service with the new private key. See
[`key-rotation.md`](./key-rotation.md).

## Stolen JWT (still within expiry)

**Capability gained.** The attacker can replay the exact captured token until it
expires. They cannot change claims, cannot extend the lifetime, and cannot mint
additional tokens.

**Mitigation.** Three layers:

1. **Short expiries.** Default `expiresIn` in `signMultiIssuerJwt` is `"1h"`.
   Issuers minting per-call rather than per-session can use seconds-to-minutes
   lifetimes, bounding the replay window to the same.
2. **Issuer-level revocation.** Deactivating the issuer invalidates every
   outstanding token from that issuer, not just future ones. This is a coarse
   hammer — it kills the legitimate issuer too — but it works when speed matters
   and the legitimate caller can rotate to a new issuer name.
3. **Optional `jti`.** Callers may include a `jti` claim. The library does not
   maintain a replay-detection cache by default (doing so requires shared state
   with strong consistency, which Edge Functions do not provide cheaply), but
   `jti` is preserved end-to-end and is available to RLS policies for
   application-level replay tracking if needed.

## Compromised target `service_role` key

**Capability gained.** Full database access on the target Supabase project,
bypassing all RLS. This is the same blast radius as in a stock Supabase
deployment.

**Library impact.** Zero — this library does not increase the surface for this
threat. The proxy holds the `service_role` key as a function secret, the same
way any other Supabase Edge Function with elevated needs would. The library does
not require additional copies of the key, does not expose it to issuers, and
does not log it.

**Mitigation.** Rotate the key via the Supabase dashboard, redeploy the proxy
with the new secret, and audit access logs. Standard Supabase incident response
applies.

## Compromised target HS256 JWT secret

**Capability gained.** The attacker can mint HS256 JWTs that PostgREST accepts
natively. They bypass the proxy entirely by calling
`https://<project>.supabase.co/rest/v1/...` directly with their forged token,
and PostgREST validates the signature with no awareness that the proxy exists.

**Library impact.** Zero — same as a stock Supabase deployment. PostgREST trusts
whatever HS256 token validates against the configured secret. This library
cannot defend against attackers who hold that secret because PostgREST is the
trust root for HS256.

**Mitigation.** Rotate the JWT secret via the Supabase dashboard. The proxy must
be redeployed with the new secret simultaneously, otherwise legitimate inbound
RS256 tokens will be re-signed with a stale secret and rejected by PostgREST.
Treat the JWT secret with the same operational care as the `service_role` key.

## Compromised proxy environment

**Capability gained.** The attacker controls the Edge Function and can read both
the `service_role` key (used to read the registry) and the HS256 JWT secret
(used to re-sign tokens). From there they can mint arbitrary HS256 tokens and
call PostgREST directly, or modify the registry to insert their own public keys
and accept arbitrary RS256 tokens.

**Library impact.** This is the worst-case scenario for the library. The proxy's
secrets together equal the impact of "compromised JWT secret + compromised
service_role" above.

**Mitigation.** Treat the proxy Edge Function as a high-value asset. Use the
Supabase platform's secrets management (`supabase secrets set`), avoid printing
the secrets in logs, and audit deploys. The proxy code is intentionally small (a
few hundred lines including the imported library) so it can be reviewed in full
before deployment.

## Replay across boundaries

**Capability gained.** A token minted for one operation could in principle be
reused for a different operation, since the library does not bind tokens to
specific PostgREST paths or HTTP methods.

**Mitigation.** RLS policies are the binding layer. A token with
`role: widgets_writer` only authorises operations RLS grants to that role. If
finer binding is required (this token only authorises POST to `/widgets/42`),
encode the constraint as a custom claim and check it in policies, or mint
per-request tokens with appropriate `sub`/custom claims and short expiries.

## Clock skew

**Capability gained.** Not an attack — but a misconfiguration. If the issuer's
clock is ahead of the proxy's, freshly minted tokens may be rejected with
`JwtVerificationError("not_yet_valid")`. If behind, tokens may appear expired on
arrival.

**Mitigation.** `verifyMultiIssuerJwt` and the proxy accept a
`clockToleranceSec` option, default 5 seconds. Increase if you observe spurious
rejections across cooperating hosts whose NTP synchronisation is loose. Do not
set extreme values — tolerance widens the replay window proportionally.

## Public key tampering at registration

**Capability gained.** An attacker who can write to `jwt_public_keys` (i.e., has
the `service_role` key or a SQL session as a privileged role) can register their
own public key for an existing issuer name and immediately mint tokens that the
proxy accepts.

**Mitigation.** The same as for any privileged write to the target database —
protect the `service_role` key, restrict who can run migrations, and audit
changes to `jwt_public_keys`. The table's `updated_at` column makes recent
modifications easy to detect; consider a database trigger that emits to an audit
log on any change.

## Out of scope

The library does not attempt to defend against:

- Compromise of the target's underlying infrastructure (Postgres cluster,
  network).
- Side-channel attacks against the proxy's signing operations.
- Misuse of legitimately granted permissions by a compromised issuer process
  (e.g., an issuer with `widgets_writer` deleting all its own widgets). Limit
  blast radius via RLS scoping.
