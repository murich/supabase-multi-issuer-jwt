# Key rotation

This is the operational procedure for rotating an issuer's signing key with zero
downtime. It assumes the issuer name is `my-service` and that the new key should
fully replace the old key once in-flight tokens have expired.

## Procedure

### 1. Generate the new keypair

```sh
npx supabase-multi-issuer-jwt keygen --issuer my-service --out ./new-keys
```

This writes `./new-keys/my-service.key` and `./new-keys/my-service.pub`. Treat
the private key with the same care as the existing one — store it in your
secrets manager, do not commit it.

### 2. Register the new public key under a temporary issuer name

The old key remains active under `my-service`. The new key gets registered under
a parallel name — by convention `my-service-v2` — so both keys are
simultaneously valid for the duration of the rotation:

```sh
npx supabase-multi-issuer-jwt register \
  --target https://your-project.supabase.co \
  --service-role "$SUPABASE_SERVICE_ROLE_KEY" \
  --issuer my-service-v2 \
  --public-key ./new-keys/my-service.pub
```

At this point the registry contains both issuers, both `is_active = true`.

### 3. Deploy the issuing service with the new key

Update the issuing service's secrets to hold the new private key, and change the
`issuer` argument passed to `signMultiIssuerJwt` from `"my-service"` to
`"my-service-v2"`. Deploy.

After deployment, all new tokens minted by the issuing service carry
`iss: "my-service-v2"`. Tokens already in flight still carry `iss: "my-service"`
and continue to verify against the old key.

### 4. Drain or revoke the old issuer

Two choices, depending on how aggressive the rotation needs to be:

**Drain (preferred).** Wait for the longest plausible token lifetime to elapse.
With the default `expiresIn: "1h"`, an hour after the last token was minted with
the old key, no valid `iss: "my-service"` tokens remain. At that point
deactivate the old issuer:

```sh
npx supabase-multi-issuer-jwt deactivate \
  --target https://your-project.supabase.co \
  --service-role "$SUPABASE_SERVICE_ROLE_KEY" \
  --issuer my-service
```

**Immediate revoke.** If the rotation is in response to a suspected compromise,
do not drain. Deactivate `my-service` immediately, accepting that any legitimate
in-flight tokens will fail on their next request. Idempotent callers retry and
succeed under `my-service-v2`; non-idempotent callers see one wave of errors.

### 5. (Optional) Rename `my-service-v2` back to `my-service`

If RLS policies, dashboards, or downstream systems reference the issuer name as
a string literal (`auth.is_issuer('my-service')`,
`owner_issuer = 'my-service'`), they all break when the active issuer is renamed
to `my-service-v2`. There are two ways to handle this:

**Leave the new name in place.** Update every reference to `my-service-v2`.
Going forward, future rotations use `my-service-v3`, `v4`, etc. This is the
cleanest path for greenfield projects.

**Rename in the registry.** After the old issuer is deactivated and no
`my-service-v2` tokens are in flight, delete the inactive `my-service` row and
update `my-service-v2`'s row to set `issuer = 'my-service'`:

```sql
delete from public.jwt_public_keys where issuer = 'my-service';
update public.jwt_public_keys
  set issuer = 'my-service', updated_at = now()
  where issuer = 'my-service-v2';
```

This requires a brief outage window — neither issuer name validates while the
rename is in progress — and it is fragile because every existing token under the
old name continues to fail. It is not generally recommended; prefer the "leave
the new name in place" approach and version your RLS policies alongside your
issuer names.

## Rotation cadence

There is no hard requirement to rotate on a schedule. Rotate when:

- A signing key is suspected of compromise.
- An employee with key access leaves.
- A periodic security review prescribes it (annual is a reasonable default).
- The cryptographic recommendation for the algorithm changes.

For high-assurance environments, schedule routine rotations via CI: a job that
runs steps 1–4 unattended every N months. The issuer name versioning (`v2`,
`v3`, …) makes this fully automatable.

## Emergency revocation

If a private key is known to be compromised, the only correct first action is to
deactivate the affected issuer immediately:

```sql
update public.jwt_public_keys
  set is_active = false, updated_at = now()
  where issuer = 'compromised-service';
```

Then follow steps 1–3 above to bring a replacement online. Do not wait for the
rotation procedure to "drain" — the attacker also benefits from the drain
window.
