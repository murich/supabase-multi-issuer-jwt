// Edge Function: RS256-to-HS256 JWT swap proxy in front of PostgREST.
// Source template: ../../../../templates/jwt-proxy/index.ts
//
// Deploy with: supabase functions deploy rest --no-verify-jwt
//
// Required secrets (set via `supabase secrets set`):
//   SUPABASE_URL              — the target Supabase URL
//   SUPABASE_SERVICE_ROLE_KEY — used only to read jwt_public_keys
//   SUPABASE_JWT_SECRET       — used to re-sign verified tokens as HS256

import { createJwtSwapProxy } from "jsr:@murich/supabase-multi-issuer-jwt";

const handler = createJwtSwapProxy({
  supabaseUrl: Deno.env.get("SUPABASE_URL")!,
  serviceRoleKey: Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  supabaseJwtSecret: Deno.env.get("SUPABASE_JWT_SECRET")!,
  mountPath: "/functions/v1/rest",
});

Deno.serve(handler);
