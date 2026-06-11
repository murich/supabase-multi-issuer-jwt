/**
 * JWT-swap proxy — verifies an inbound RS256 JWT against the registry, then
 * re-signs the same claims with HS256 using the target Supabase's JWT secret
 * and forwards the request to PostgREST.
 *
 * Deploy as a Supabase Edge Function. PostgREST then validates the HS256 JWT
 * natively and applies RLS using `auth.jwt()->>'iss'`.
 */

import * as jose from "jose";
import { verifyMultiIssuerJwt } from "./verify.ts";
import { JwtVerificationError, type ProxyOptions } from "./types.ts";

const DEFAULT_MOUNT_PATH = "/functions/v1/rest";

const PRIVILEGED_ROLES = new Set([
  "service_role",
  "postgres",
  "supabase_admin",
  "supabase_replication_admin",
  "supabase_read_only_user",
]);

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, PUT, OPTIONS",
  "Access-Control-Allow-Headers":
    "authorization, apikey, content-type, content-profile, accept-profile, prefer, range, x-client-info",
  "Access-Control-Expose-Headers": "content-range, content-profile, prefer",
  "Access-Control-Max-Age": "86400",
};

function jsonResponse(
  status: number,
  body: unknown,
  extraHeaders?: HeadersInit,
): Response {
  const headers = new Headers({
    "content-type": "application/json; charset=utf-8",
    ...CORS_HEADERS,
  });
  if (extraHeaders) {
    const extra = new Headers(extraHeaders);
    extra.forEach((v, k) => headers.set(k, v));
  }
  return new Response(JSON.stringify(body), { status, headers });
}

function buildForwardUrl(
  req: Request,
  supabaseUrl: string,
  mountPath: string,
): string {
  const inbound = new URL(req.url);
  let path = inbound.pathname;
  if (mountPath && path.startsWith(mountPath)) {
    path = path.slice(mountPath.length);
  }
  if (!path.startsWith("/")) path = "/" + path;
  const target = new URL(supabaseUrl.replace(/\/$/, "") + "/rest/v1" + path);
  // Preserve query string.
  inbound.searchParams.forEach((v, k) => target.searchParams.append(k, v));
  return target.toString();
}

function stripHopHeaders(src: Headers): Headers {
  // Headers that must not be blindly forwarded.
  const banned = new Set([
    "authorization",
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "keep-alive",
    "upgrade",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "forwarded",
  ]);
  const out = new Headers();
  src.forEach((v, k) => {
    if (!banned.has(k.toLowerCase())) {
      out.set(k, v);
    }
  });
  return out;
}

function addCorsHeaders(res: Response): Response {
  const headers = new Headers(res.headers);
  for (const [k, v] of Object.entries(CORS_HEADERS)) {
    if (!headers.has(k)) headers.set(k, v);
  }
  return new Response(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers,
  });
}

export function createJwtSwapProxy(
  opts: ProxyOptions,
): (req: Request) => Promise<Response> {
  if (!opts.supabaseUrl) {
    throw new Error("createJwtSwapProxy: supabaseUrl is required");
  }
  if (!opts.serviceRoleKey) {
    throw new Error("createJwtSwapProxy: serviceRoleKey is required");
  }
  if (!opts.supabaseJwtSecret) {
    throw new Error("createJwtSwapProxy: supabaseJwtSecret is required");
  }
  try {
    const _u = new URL(opts.supabaseUrl);
    if (_u.protocol !== "https:" && _u.protocol !== "http:") {
      throw new Error(
        `createJwtSwapProxy: supabaseUrl must use http or https, got "${_u.protocol}"`,
      );
    }
  } catch (err) {
    if (err instanceof Error && err.message.startsWith("createJwtSwapProxy:")) {
      throw err;
    }
    throw new Error(
      `createJwtSwapProxy: supabaseUrl is not a valid URL: "${opts.supabaseUrl}"`,
    );
  }
  const mountPath = opts.mountPath ?? DEFAULT_MOUNT_PATH;
  const hsSecret = new TextEncoder().encode(opts.supabaseJwtSecret);

  return async function handler(req: Request): Promise<Response> {
    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const auth = req.headers.get("authorization") ??
      req.headers.get("Authorization");
    if (!auth) {
      return jsonResponse(401, { error: "missing_authorization" });
    }
    const m = /^Bearer\s+(.+)$/i.exec(auth.trim());
    if (!m) {
      return jsonResponse(401, { error: "missing_authorization" });
    }
    const inboundJwt = m[1].trim();

    // 1. Verify inbound RS256 JWT against registry.
    let claims: Record<string, unknown>;
    try {
      const result = await verifyMultiIssuerJwt(inboundJwt, {
        supabaseUrl: opts.supabaseUrl,
        serviceRoleKey: opts.serviceRoleKey,
        allowedIssuers: opts.allowedIssuers,
        audience: opts.audience,
        maxTokenLifetimeSec: opts.maxTokenLifetimeSec,
      });
      claims = { ...result.claims };
      if (typeof claims.role === "string" && PRIVILEGED_ROLES.has(claims.role)) {
        return jsonResponse(401, { error: "role_not_allowed" });
      }
    } catch (err) {
      if (err instanceof JwtVerificationError) {
        if (err.reason === "registry_unavailable") {
          return jsonResponse(503, { error: "registry_unavailable" });
        }
        const publicReason =
          err.reason === "malformed" || err.reason === "expired" || err.reason === "not_yet_valid"
            ? err.reason
            : "unauthorized";
        return jsonResponse(401, { error: publicReason });
      }
      return jsonResponse(500, {
        error: "internal_error",
        detail: err instanceof Error ? err.message : String(err),
      });
    }

    // 2. Re-sign the SAME claims with HS256. Preserve iat/exp/iss/sub/role/custom.
    if (typeof claims.iat !== "number" || typeof claims.exp !== "number") {
      // Defensive — verifyMultiIssuerJwt rejects malformed payloads, but if exp/iat
      // were missing the upstream verify would have errored. Re-issue conservatively.
      return jsonResponse(401, { error: "malformed" });
    }
    let hsJwt: string;
    try {
      const builder = new jose.SignJWT(claims as jose.JWTPayload)
        .setProtectedHeader({
          alg: "HS256",
          typ: "JWT",
        });
      hsJwt = await builder.sign(hsSecret);
    } catch (err) {
      return jsonResponse(500, {
        error: "signing_failed",
        detail: err instanceof Error ? err.message : String(err),
      });
    }

    // 3. Forward to PostgREST.
    const forwardUrl = buildForwardUrl(req, opts.supabaseUrl, mountPath);
    const forwardHeaders = stripHopHeaders(req.headers);
    forwardHeaders.set("Authorization", `Bearer ${hsJwt}`);

    // PostgREST requires both `apikey` and `Authorization`. Pass the inbound
    // apikey through if the caller sent one (typically the target's anon key);
    // otherwise fall back to the HS256 JWT we just minted, which PostgREST
    // accepts for the `apikey` header too.
    const inboundApiKey = req.headers.get("apikey");
    forwardHeaders.set("apikey", inboundApiKey ?? hsJwt);

    const init: RequestInit = {
      method: req.method,
      headers: forwardHeaders,
    };
    if (req.method !== "GET" && req.method !== "HEAD") {
      init.body = req.body;
      // Required for streaming a Request body in Deno/undici.
      (init as RequestInit & { duplex?: string }).duplex = "half";
    }

    let upstream: Response;
    try {
      upstream = await fetch(forwardUrl, init);
    } catch (err) {
      return jsonResponse(502, {
        error: "upstream_unreachable",
        detail: err instanceof Error ? err.message : String(err),
      });
    }

    return addCorsHeaders(upstream);
  };
}
