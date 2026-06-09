/**
 * Edge Function template — RS256 → HS256 JWT swap proxy for Supabase PostgREST.
 *
 * Deploy this as a Supabase Edge Function. It accepts inbound requests bearing
 * a multi-issuer RS256 JWT, verifies the signature against the
 * `jwt_public_keys` registry, re-signs the same claims as HS256 using the
 * project's native JWT secret, and forwards the request to PostgREST.
 *
 * Deploy with:
 *   supabase functions deploy rest --no-verify-jwt
 *
 * The `--no-verify-jwt` flag is REQUIRED — Supabase's gateway must not try to
 * validate the inbound RS256 token with its native HS256 secret. We verify
 * explicitly inside this function, then mint a fresh HS256 JWT for PostgREST.
 *
 * Source: https://github.com/murich/supabase-multi-issuer-jwt
 */

import { createJwtSwapProxy } from "jsr:@murich/supabase-multi-issuer-jwt";

function requireEnv(name: string): string {
  const value = Deno.env.get(name);
  if (!value) {
    throw new Error(
      `Missing required environment variable: ${name}. ` +
        `Set it with: supabase secrets set ${name}=...`,
    );
  }
  return value;
}

const SUPABASE_URL = requireEnv("SUPABASE_URL");
const SUPABASE_SERVICE_ROLE_KEY = requireEnv("SUPABASE_SERVICE_ROLE_KEY");
const SUPABASE_JWT_SECRET = requireEnv("SUPABASE_JWT_SECRET");

const allowedIssuersRaw = Deno.env.get("ALLOWED_ISSUERS");
const allowedIssuers = allowedIssuersRaw
  ? allowedIssuersRaw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
  : undefined;

const proxy = createJwtSwapProxy({
  supabaseUrl: SUPABASE_URL,
  serviceRoleKey: SUPABASE_SERVICE_ROLE_KEY,
  supabaseJwtSecret: SUPABASE_JWT_SECRET,
  allowedIssuers,
});

/**
 * Best-effort extraction of the `iss` claim for logging only. Never throws,
 * never validates — verification still happens inside the proxy.
 */
function peekIssuer(authHeader: string | null): string {
  if (!authHeader) return "?";
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) return "?";
  const parts = match[1].split(".");
  if (parts.length < 2) return "?";
  try {
    const padded = parts[1] + "=".repeat((4 - (parts[1].length % 4)) % 4);
    const json = atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
    const payload = JSON.parse(json) as { iss?: unknown };
    return typeof payload.iss === "string" && payload.iss.length > 0
      ? payload.iss
      : "?";
  } catch {
    return "?";
  }
}

async function handler(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const iss = peekIssuer(req.headers.get("authorization"));
  const ts = new Date().toISOString();
  const safeIss = String(iss).replace(/[^\w\-.:/@ ]/g, "_").slice(0, 128);
  console.log(`[${ts}] ${req.method} ${url.pathname} iss=${safeIss}`);

  if (req.method === "GET" && url.pathname.endsWith("/health")) {
    return new Response(
      JSON.stringify({ ok: true }),
      {
        status: 200,
        headers: { "content-type": "application/json; charset=utf-8" },
      },
    );
  }

  return await proxy(req);
}

Deno.serve(handler);
