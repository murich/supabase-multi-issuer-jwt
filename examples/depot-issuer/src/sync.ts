// depot-issuer demo service.
//
// Every 30 seconds, mints a fresh RS256 JWT for issuer `depot-demo` and POSTs
// a new widget to the shop-target Supabase project through the proxy.
//
// Environment:
//   PRIVATE_KEY_PATH  — PEM-encoded RS256 private key (default: /app/keys/depot-demo.key)
//   ISSUER            — issuer name as registered on the target (default: depot-demo)
//   TARGET_URL        — base URL of the target Supabase, including scheme and port
//                        (default: http://supabase-target:54321)
//   SYNC_INTERVAL_MS  — milliseconds between writes (default: 30000)

import { signMultiIssuerJwt } from "jsr:@murich/supabase-multi-issuer-jwt";

const PRIVATE_KEY_PATH = Deno.env.get("PRIVATE_KEY_PATH") ??
  "/app/keys/depot-demo.key";
const ISSUER = Deno.env.get("ISSUER") ?? "depot-demo";
const TARGET_URL = Deno.env.get("TARGET_URL") ?? "http://supabase-target:54321";
const SYNC_INTERVAL_MS = Number(Deno.env.get("SYNC_INTERVAL_MS") ?? "30000");

const privateKey = await Deno.readTextFile(PRIVATE_KEY_PATH);

async function writeWidget(): Promise<void> {
  const widgetName = `widget-${Date.now()}`;

  const token = await signMultiIssuerJwt({
    privateKey,
    issuer: ISSUER,
    claims: {
      sub: `${ISSUER}:sync-loop`,
      role: "widgets_writer",
    },
    expiresIn: "5m",
  });

  const url = `${TARGET_URL}/functions/v1/rest/widgets`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      Prefer: "return=representation",
    },
    body: JSON.stringify({
      name: widgetName,
      owner_issuer: ISSUER,
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    console.error(
      `[depot-issuer] write failed: ${res.status} ${res.statusText}\n${body}`,
    );
    return;
  }

  const inserted = await res.json();
  console.log(
    `[depot-issuer] inserted widget ${JSON.stringify(inserted)}`,
  );
}

console.log(
  `[depot-issuer] starting sync loop issuer=${ISSUER} target=${TARGET_URL} interval=${SYNC_INTERVAL_MS}ms`,
);

// First write immediately, then on the interval.
await writeWidget();
setInterval(() => {
  writeWidget().catch((err) => {
    console.error("[depot-issuer] sync error:", err);
  });
}, SYNC_INTERVAL_MS);

// Keep the process alive.
await new Promise(() => {});
