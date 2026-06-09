/**
 * RS256/ES* JWT signing for multi-issuer Supabase setups.
 *
 * Each issuing backend service holds its own private key. The matching public
 * key is registered on the target Supabase via `registerPublicKey`. The
 * swap-proxy verifies tokens against that registry.
 */

import * as jose from "jose";
import type { Algorithm, MultiIssuerJwtClaims, SignOptions } from "./types.ts";

const DURATION_RE = /^(\d+)([smhdy])$/i;

const UNIT_SECONDS: Record<string, number> = {
  s: 1,
  m: 60,
  h: 60 * 60,
  d: 60 * 60 * 24,
  // 365d/year is intentional — JWT lifetimes are not calendar-aware.
  y: 60 * 60 * 24 * 365,
};

/**
 * Parse a duration into seconds.
 *
 * Accepts:
 *   - a positive integer number (interpreted as seconds)
 *   - a string of the form `<digits><unit>` where unit ∈ {s,m,h,d,y}
 *
 * Throws on any other input.
 */
export function parseDurationSeconds(input: string | number): number {
  if (typeof input === "number") {
    if (!Number.isFinite(input) || input <= 0 || !Number.isInteger(input)) {
      throw new Error(
        `signMultiIssuerJwt: invalid numeric duration ${input} — expected positive integer seconds`,
      );
    }
    return input;
  }
  if (typeof input !== "string") {
    throw new Error(
      `signMultiIssuerJwt: invalid duration type ${typeof input} — expected string or number`,
    );
  }
  const trimmed = input.trim();
  // Allow a bare integer string ("3600") as seconds.
  if (/^\d+$/.test(trimmed)) {
    const n = Number(trimmed);
    if (n <= 0) {
      throw new Error(
        `signMultiIssuerJwt: invalid duration "${input}" — must be positive`,
      );
    }
    return n;
  }
  const m = DURATION_RE.exec(trimmed);
  if (!m) {
    throw new Error(
      `signMultiIssuerJwt: invalid duration "${input}" — expected formats like "30s", "5m", "1h", "30d", "5y"`,
    );
  }
  const value = Number(m[1]);
  const unit = m[2].toLowerCase();
  const mult = UNIT_SECONDS[unit];
  if (!mult) {
    // Unreachable given the regex; defensive only.
    throw new Error(`signMultiIssuerJwt: unknown duration unit "${m[2]}"`);
  }
  if (value <= 0) {
    throw new Error(
      `signMultiIssuerJwt: invalid duration "${input}" — must be positive`,
    );
  }
  return value * mult;
}

const PEM_HEADERS: Array<
  { marker: string; format: "pkcs8" | "sec1" | "pkcs1" }
> = [
  { marker: "-----BEGIN PRIVATE KEY-----", format: "pkcs8" },
  { marker: "-----BEGIN EC PRIVATE KEY-----", format: "sec1" },
  { marker: "-----BEGIN RSA PRIVATE KEY-----", format: "pkcs1" },
];

async function importPrivateKey(
  pem: string,
  alg: Algorithm,
): Promise<jose.KeyLike | Uint8Array> {
  const trimmed = pem.trim();
  for (const { marker, format } of PEM_HEADERS) {
    if (trimmed.includes(marker)) {
      try {
        if (format === "pkcs8") {
          return await jose.importPKCS8(trimmed, alg);
        }
        // SEC1 and PKCS1 are not first-class in WebCrypto. jose only ships
        // an importer for PKCS8/SPKI/X509/JWK. Tell the caller to convert.
        throw new Error(
          `signMultiIssuerJwt: private key is in ${format.toUpperCase()} format — ` +
            `convert to PKCS8 (e.g. \`openssl pkcs8 -topk8 -nocrypt -in key.pem\`) before signing`,
        );
      } catch (err) {
        if (
          err instanceof Error && err.message.startsWith("signMultiIssuerJwt:")
        ) {
          throw err;
        }
        throw new Error(
          `signMultiIssuerJwt: failed to import private key (${format}, alg=${alg}): ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
      }
    }
  }
  throw new Error(
    `signMultiIssuerJwt: privateKey does not look like a PEM-encoded private key ` +
      `(expected one of: "BEGIN PRIVATE KEY", "BEGIN EC PRIVATE KEY", "BEGIN RSA PRIVATE KEY")`,
  );
}

/**
 * Sign a JWT for the multi-issuer Supabase swap-proxy flow.
 *
 * `iat` and `exp` are set by this function and any caller-supplied values
 * for those fields are stripped — lifetime is controlled by `expiresIn`.
 */
export async function signMultiIssuerJwt(opts: SignOptions): Promise<string> {
  if (!opts.privateKey || typeof opts.privateKey !== "string") {
    throw new Error(
      "signMultiIssuerJwt: privateKey is required and must be a PEM string",
    );
  }
  if (!opts.issuer || typeof opts.issuer !== "string") {
    throw new Error("signMultiIssuerJwt: issuer is required");
  }
  if (
    !opts.claims || typeof opts.claims.sub !== "string" ||
    opts.claims.sub.length === 0
  ) {
    throw new Error("signMultiIssuerJwt: claims.sub is required");
  }

  const algorithm: Algorithm = opts.algorithm ?? "RS256";
  const lifetimeSec = parseDurationSeconds(opts.expiresIn ?? "60s");
  const now = Math.floor(Date.now() / 1000);

  // Strip server-set claims from caller-supplied claims.
  const { iat: _iat, exp: _exp, iss: _issFromClaims, ...rest } = opts
    .claims as Record<
      string,
      unknown
    >;
  void _iat;
  void _exp;
  void _issFromClaims;

  const payload: Record<string, unknown> = {
    ...rest,
    iss: opts.issuer,
    iat: now,
    exp: now + lifetimeSec,
  };

  const key = await importPrivateKey(opts.privateKey, algorithm);

  const jwt = await new jose.SignJWT(payload as jose.JWTPayload)
    .setProtectedHeader({ alg: algorithm, typ: "JWT" })
    .sign(key);

  return jwt;
}

// Re-export the claims type for convenience.
export type { MultiIssuerJwtClaims };
