/**
 * Verify a multi-issuer JWT against the target Supabase's `jwt_public_keys` registry.
 *
 * Used by the swap-proxy before re-signing the claims with HS256. Also exported
 * for callers that want to verify tokens server-side without the proxy.
 */

import * as jose from "jose";
import { getPublicKey } from "./registry.ts";
import {
  JwtVerificationError,
  type MultiIssuerJwtClaims,
  type VerifyOptions,
  type VerifyResult,
} from "./types.ts";

/**
 * Decode header.payload without verifying the signature. Throws `malformed`
 * on any structural problem.
 */
function decodeUnverified(jwt: string): {
  header: jose.ProtectedHeaderParameters;
  payload: jose.JWTPayload & MultiIssuerJwtClaims;
} {
  if (typeof jwt !== "string" || jwt.length === 0) {
    throw new JwtVerificationError("malformed", "verify: jwt is required");
  }
  let header: jose.ProtectedHeaderParameters;
  let payload: jose.JWTPayload;
  try {
    header = jose.decodeProtectedHeader(jwt);
    payload = jose.decodeJwt(jwt);
  } catch (err) {
    throw new JwtVerificationError(
      "malformed",
      `verify: malformed jwt: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  if (!payload || typeof payload !== "object") {
    throw new JwtVerificationError(
      "malformed",
      "verify: jwt payload is not an object",
    );
  }
  if (typeof payload.iss !== "string" || payload.iss.length === 0) {
    throw new JwtVerificationError(
      "malformed",
      "verify: jwt is missing `iss` claim",
    );
  }
  if (typeof payload.sub !== "string" || payload.sub.length === 0) {
    throw new JwtVerificationError(
      "malformed",
      "verify: jwt is missing `sub` claim",
    );
  }
  return {
    header,
    payload: payload as jose.JWTPayload & MultiIssuerJwtClaims,
  };
}

function mapJoseError(err: unknown): JwtVerificationError {
  const code = (err as { code?: string } | undefined)?.code;
  const msg = err instanceof Error ? err.message : String(err);
  switch (code) {
    case "ERR_JWT_EXPIRED":
      return new JwtVerificationError("expired", `verify: jwt expired: ${msg}`);
    case "ERR_JWT_CLAIM_VALIDATION_FAILED": {
      const claim = (err as { claim?: string } | undefined)?.claim;
      if (claim === "nbf") {
        return new JwtVerificationError(
          "not_yet_valid",
          `verify: jwt not yet valid: ${msg}`,
        );
      }
      if (claim === "exp") {
        return new JwtVerificationError(
          "expired",
          `verify: jwt expired: ${msg}`,
        );
      }
      if (claim === "iss") {
        return new JwtVerificationError(
          "issuer_not_allowed",
          `verify: jwt issuer mismatch: ${msg}`,
        );
      }
      return new JwtVerificationError(
        "bad_signature",
        `verify: jwt claim invalid: ${msg}`,
      );
    }
    case "ERR_JWS_SIGNATURE_VERIFICATION_FAILED":
    case "ERR_JWS_INVALID":
    case "ERR_JWT_INVALID":
      return new JwtVerificationError(
        "bad_signature",
        `verify: bad signature: ${msg}`,
      );
    default:
      // joseError without code — treat as bad signature unless message says otherwise.
      if (/expired/i.test(msg)) {
        return new JwtVerificationError(
          "expired",
          `verify: jwt expired: ${msg}`,
        );
      }
      if (/not yet valid|nbf/i.test(msg)) {
        return new JwtVerificationError(
          "not_yet_valid",
          `verify: jwt not yet valid: ${msg}`,
        );
      }
      return new JwtVerificationError("bad_signature", `verify: ${msg}`);
  }
}

export async function verifyMultiIssuerJwt(
  jwt: string,
  opts: VerifyOptions,
): Promise<VerifyResult> {
  if (!opts || !opts.supabaseUrl || !opts.serviceRoleKey) {
    throw new JwtVerificationError(
      "registry_unavailable",
      "verify: supabaseUrl and serviceRoleKey are required",
    );
  }

  const { payload } = decodeUnverified(jwt);
  const iss = payload.iss;

  if (opts.allowedIssuers && opts.allowedIssuers.length > 0) {
    if (!opts.allowedIssuers.includes(iss)) {
      throw new JwtVerificationError(
        "issuer_not_allowed",
        `verify: issuer "${iss}" is not in allowedIssuers`,
      );
    }
  }

  let row: Awaited<ReturnType<typeof getPublicKey>>;
  try {
    row = await getPublicKey({
      supabaseUrl: opts.supabaseUrl,
      serviceRoleKey: opts.serviceRoleKey,
      issuer: iss,
    });
  } catch (err) {
    const e = new JwtVerificationError(
      "registry_unavailable",
      `verify: registry unavailable: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
    (e as Error & { cause?: unknown }).cause = err;
    throw e;
  }

  if (!row) {
    throw new JwtVerificationError(
      "unknown_issuer",
      `verify: no registry row for issuer "${iss}"`,
    );
  }
  if (!row.is_active) {
    throw new JwtVerificationError(
      "inactive_issuer",
      `verify: issuer "${iss}" is marked inactive`,
    );
  }

  let key: jose.KeyLike;
  try {
    key = await jose.importSPKI(row.public_key, row.algorithm);
  } catch (err) {
    throw new JwtVerificationError(
      "bad_signature",
      `verify: failed to import public key for "${iss}": ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }

  let verified: jose.JWTVerifyResult;
  try {
    verified = await jose.jwtVerify(jwt, key, {
      issuer: iss,
      audience: opts.audience,
      algorithms: [row.algorithm],
      clockTolerance: opts.clockToleranceSec ?? 5,
    });
  } catch (err) {
    throw mapJoseError(err);
  }

  return {
    claims: verified.payload as MultiIssuerJwtClaims,
    matchedKey: {
      issuer: row.issuer,
      algorithm: row.algorithm,
      is_active: row.is_active,
    },
  };
}
