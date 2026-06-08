/**
 * Public type surface for @murich/supabase-multi-issuer-jwt.
 *
 * The library lets multiple backend services write to a shared Supabase
 * project using RS256-signed JWTs validated against a public-key registry
 * (`jwt_public_keys` table). Inspired by the Contract Farming auth model:
 *   https://redmine.blessthis.software/projects/padigital/wiki/Contract-Farming-Auth-Architecture
 */

/** A JWT signing algorithm supported by this library. */
export type Algorithm = "RS256" | "RS384" | "RS512" | "ES256" | "ES384";

/** Standard JWT claims plus library-relevant fields. */
export interface MultiIssuerJwtClaims {
  /** Issuer — MUST match a row in target Supabase's `jwt_public_keys.issuer`. */
  iss: string;
  /** Subject — free-form identifier for the principal inside the issuing service. */
  sub: string;
  /** Issued-at, Unix seconds. */
  iat: number;
  /** Expiry, Unix seconds. */
  exp: number;
  /**
   * Optional Postgres role for PostgREST to `SET ROLE` on the request. Must be a
   * role that exists in the target Postgres with appropriate grants.
   */
  role?: string;
  /** Any additional custom claims the issuer wants to surface to RLS policies. */
  [key: string]: unknown;
}

/** Row shape of the `jwt_public_keys` registry table. */
export interface PublicKeyRow {
  issuer: string;
  public_key: string; // PEM-encoded
  algorithm: Algorithm;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

/** Input to `signMultiIssuerJwt`. */
export interface SignOptions {
  /** PEM-encoded private key matching the public key registered on target. */
  privateKey: string;
  /** Must match a registered issuer on target. */
  issuer: string;
  /** Required custom claims plus optional `role`, `sub`, etc. */
  claims: Partial<MultiIssuerJwtClaims> & { sub: string };
  /**
   * Lifetime. Accepts duration strings ("5y", "30d", "1h") or seconds.
   * Defaults to `"1h"`.
   */
  expiresIn?: string | number;
  /** Defaults to `"RS256"`. */
  algorithm?: Algorithm;
}

/** Input to `verifyMultiIssuerJwt`. */
export interface VerifyOptions {
  /** Target Supabase URL (e.g. https://your-project.supabase.co). */
  supabaseUrl: string;
  /** Service role key — used ONLY to read the public-key registry. */
  serviceRoleKey: string;
  /**
   * Optional clock skew tolerance in seconds. Defaults to 5.
   */
  clockToleranceSec?: number;
  /**
   * Optional allowlist of acceptable issuers. If provided, JWTs whose `iss`
   * is not in this list are rejected even before the signature check. Default:
   * any issuer present in the registry is accepted.
   */
  allowedIssuers?: string[];
}

/** Result of a successful verification. */
export interface VerifyResult {
  claims: MultiIssuerJwtClaims;
  /** The registry row that was matched (audit / logging). */
  matchedKey: Pick<PublicKeyRow, "issuer" | "algorithm" | "is_active">;
}

/** Thrown by verifyMultiIssuerJwt on any validation failure. */
export class JwtVerificationError extends Error {
  constructor(
    public readonly reason:
      | "malformed"
      | "unknown_issuer"
      | "inactive_issuer"
      | "issuer_not_allowed"
      | "bad_signature"
      | "expired"
      | "not_yet_valid"
      | "registry_unavailable",
    message: string,
  ) {
    super(message);
    this.name = "JwtVerificationError";
  }
}

/** Input to `createJwtSwapProxy`. */
export interface ProxyOptions {
  /** Target Supabase URL. PostgREST lives at `${supabaseUrl}/rest/v1`. */
  supabaseUrl: string;
  /** Used to read `jwt_public_keys`. */
  serviceRoleKey: string;
  /**
   * The target Supabase's JWT secret. After verifying the inbound RS256 JWT,
   * the proxy re-signs the same claims using HS256 with this secret so PostgREST
   * accepts the request natively.
   */
  supabaseJwtSecret: string;
  /** Optional allowlist of issuers (passed through to verifyMultiIssuerJwt). */
  allowedIssuers?: string[];
  /**
   * Optional path-prefix to strip from the inbound request before forwarding
   * to PostgREST. E.g. if the Edge Function is mounted at `/functions/v1/rest`
   * and proxies to `/rest/v1`, the inbound `/functions/v1/rest/depots` becomes
   * `${supabaseUrl}/rest/v1/depots`. Defaults to "/functions/v1/rest".
   */
  mountPath?: string;
}

/** Input to `registerPublicKey`. */
export interface RegisterOptions {
  supabaseUrl: string;
  serviceRoleKey: string;
  issuer: string;
  publicKey: string; // PEM
  algorithm?: Algorithm;
}
