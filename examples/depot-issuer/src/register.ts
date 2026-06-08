// One-time registration helper for the depot-issuer example.
//
// Reads the depot-demo public key from /app/keys/depot-demo.pub and inserts
// it into the target's jwt_public_keys table using the service-role key.
//
// Environment:
//   PUBLIC_KEY_PATH   — PEM-encoded public key (default: /app/keys/depot-demo.pub)
//   ISSUER            — issuer name (default: depot-demo)
//   TARGET_URL        — target Supabase URL (default: http://supabase-target:54321)
//   SERVICE_ROLE_KEY  — target Supabase service-role key (required)

import { registerPublicKey } from "jsr:@murich/supabase-multi-issuer-jwt";

const PUBLIC_KEY_PATH = Deno.env.get("PUBLIC_KEY_PATH") ??
  "/app/keys/depot-demo.pub";
const ISSUER = Deno.env.get("ISSUER") ?? "depot-demo";
const TARGET_URL = Deno.env.get("TARGET_URL") ?? "http://supabase-target:54321";
const SERVICE_ROLE_KEY = Deno.env.get("SERVICE_ROLE_KEY");

if (!SERVICE_ROLE_KEY) {
  console.error("[register] SERVICE_ROLE_KEY env var is required");
  Deno.exit(1);
}

const publicKey = await Deno.readTextFile(PUBLIC_KEY_PATH);

const row = await registerPublicKey({
  supabaseUrl: TARGET_URL,
  serviceRoleKey: SERVICE_ROLE_KEY,
  issuer: ISSUER,
  publicKey,
  algorithm: "RS256",
});

console.log(
  `[register] registered issuer=${row.issuer} active=${row.is_active} algorithm=${row.algorithm}`,
);
