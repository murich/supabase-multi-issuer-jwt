import { assert, assertEquals } from "@std/assert";
import * as jose from "jose";
import { createJwtSwapProxy } from "../src/proxy.ts";
import { __setClientFactoryForTests } from "../src/registry.ts";
import { freshState, makeFakeClient, makeRow } from "./_fake_supabase.ts";

const SUPABASE_URL = "https://example.supabase.co";
const SERVICE_ROLE_KEY = "service-role-key";
const HS_SECRET = "super-secret-jwt-secret-please-change-me-32-bytes";

async function makeKeypairPems() {
  const { privateKey, publicKey } = await jose.generateKeyPair("RS256", {
    extractable: true,
  });
  return {
    privatePem: await jose.exportPKCS8(privateKey),
    publicPem: await jose.exportSPKI(publicKey),
  };
}

async function signRs256(
  privatePem: string,
  payload: Record<string, unknown>,
): Promise<string> {
  const key = await jose.importPKCS8(privatePem, "RS256");
  return new jose.SignJWT(payload as jose.JWTPayload)
    .setProtectedHeader({ alg: "RS256", typ: "JWT" })
    .sign(key);
}

function setupRegistry(rows: ReturnType<typeof makeRow>[]) {
  const state = freshState(rows);
  __setClientFactoryForTests(() => makeFakeClient(state) as never);
  return state;
}

function resetRegistry() {
  __setClientFactoryForTests(null);
}

interface CapturedRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string | null;
}

function installFetchStub(
  upstreamResponse: () => Response,
): { captured: CapturedRequest[]; restore: () => void } {
  const captured: CapturedRequest[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (
    input: Request | URL | string,
    init?: RequestInit,
  ) => {
    let url: string;
    let method: string;
    const headers: Record<string, string> = {};
    let body: string | null = null;
    if (input instanceof Request) {
      url = input.url;
      method = input.method;
      input.headers.forEach((v, k) => headers[k] = v);
      body = await input.text();
    } else {
      url = String(input);
      method = init?.method ?? "GET";
      if (init?.headers) {
        const h = new Headers(init.headers);
        h.forEach((v, k) => headers[k] = v);
      }
      if (init?.body) {
        if (init.body instanceof ReadableStream) {
          const reader = init.body.getReader();
          const chunks: Uint8Array[] = [];
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (value) chunks.push(value);
          }
          const total = chunks.reduce((s, c) => s + c.byteLength, 0);
          const merged = new Uint8Array(total);
          let offset = 0;
          for (const c of chunks) {
            merged.set(c, offset);
            offset += c.byteLength;
          }
          body = new TextDecoder().decode(merged);
        } else if (typeof init.body === "string") {
          body = init.body;
        } else {
          body = String(init.body);
        }
      }
    }
    captured.push({ url, method, headers, body });
    return upstreamResponse();
  };
  return {
    captured,
    restore: () => {
      globalThis.fetch = originalFetch;
    },
  };
}

Deno.test("createJwtSwapProxy: OPTIONS returns CORS preflight", async () => {
  const handler = createJwtSwapProxy({
    supabaseUrl: SUPABASE_URL,
    serviceRoleKey: SERVICE_ROLE_KEY,
    supabaseJwtSecret: HS_SECRET,
  });
  const res = await handler(
    new Request("https://edge.example.com/functions/v1/rest/depots", {
      method: "OPTIONS",
    }),
  );
  assertEquals(res.status, 204);
  assertEquals(res.headers.get("Access-Control-Allow-Origin"), "*");
});

Deno.test("createJwtSwapProxy: missing Authorization → 401 missing_authorization", async () => {
  const handler = createJwtSwapProxy({
    supabaseUrl: SUPABASE_URL,
    serviceRoleKey: SERVICE_ROLE_KEY,
    supabaseJwtSecret: HS_SECRET,
  });
  const res = await handler(
    new Request("https://edge.example.com/functions/v1/rest/depots", {
      method: "GET",
    }),
  );
  assertEquals(res.status, 401);
  const body = await res.json();
  assertEquals(body.error, "missing_authorization");
});

Deno.test("createJwtSwapProxy: malformed Authorization header → 401", async () => {
  const handler = createJwtSwapProxy({
    supabaseUrl: SUPABASE_URL,
    serviceRoleKey: SERVICE_ROLE_KEY,
    supabaseJwtSecret: HS_SECRET,
  });
  const res = await handler(
    new Request("https://edge.example.com/functions/v1/rest/depots", {
      method: "GET",
      headers: { Authorization: "Basic xyz" },
    }),
  );
  assertEquals(res.status, 401);
});

Deno.test("createJwtSwapProxy: happy path — swaps RS256 → HS256, forwards to PostgREST", async () => {
  const { privatePem, publicPem } = await makeKeypairPems();
  setupRegistry([makeRow({ issuer: "svc-depot", public_key: publicPem })]);
  const stub = installFetchStub(
    () =>
      new Response('{"ok":true}', {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
  );

  try {
    const now = Math.floor(Date.now() / 1000);
    const inboundClaims = {
      iss: "svc-depot",
      sub: "user-99",
      role: "authenticated",
      tenant: "depot-east",
      iat: now,
      exp: now + 3600,
    };
    const inboundJwt = await signRs256(privatePem, inboundClaims);

    const handler = createJwtSwapProxy({
      supabaseUrl: SUPABASE_URL,
      serviceRoleKey: SERVICE_ROLE_KEY,
      supabaseJwtSecret: HS_SECRET,
    });
    const req = new Request(
      "https://edge.example.com/functions/v1/rest/depots?select=*&id=eq.1",
      {
        method: "GET",
        headers: {
          Authorization: `Bearer ${inboundJwt}`,
          apikey: "anon-key-passthrough",
          "content-type": "application/json",
          "x-client-info": "test",
        },
      },
    );
    const res = await handler(req);
    assertEquals(res.status, 200);
    const body = await res.json();
    assertEquals(body.ok, true);

    assertEquals(stub.captured.length, 1);
    const fwd = stub.captured[0];
    // URL rewriting
    assert(
      fwd.url.startsWith(`${SUPABASE_URL}/rest/v1/depots`),
      `unexpected forwarded URL: ${fwd.url}`,
    );
    assert(fwd.url.includes("select=%2A") || fwd.url.includes("select=*"));
    assert(fwd.url.includes("id=eq.1"));
    assertEquals(fwd.method, "GET");

    // apikey passthrough
    assertEquals(fwd.headers["apikey"], "anon-key-passthrough");

    // HS256 swap
    const auth = fwd.headers["authorization"] ?? fwd.headers["Authorization"];
    assert(auth);
    const hsJwt = auth.replace(/^Bearer\s+/i, "");
    const { payload, protectedHeader } = await jose.jwtVerify(
      hsJwt,
      new TextEncoder().encode(HS_SECRET),
    );
    assertEquals(protectedHeader.alg, "HS256");
    assertEquals(payload.iss, "svc-depot");
    assertEquals(payload.sub, "user-99");
    assertEquals(payload.role, "authenticated");
    assertEquals(payload.tenant, "depot-east");
    assertEquals(payload.iat, inboundClaims.iat);
    assertEquals(payload.exp, inboundClaims.exp);

    // CORS headers on response
    assertEquals(res.headers.get("Access-Control-Allow-Origin"), "*");
  } finally {
    stub.restore();
    resetRegistry();
  }
});

Deno.test("createJwtSwapProxy: falls back apikey to HS JWT when inbound apikey missing", async () => {
  const { privatePem, publicPem } = await makeKeypairPems();
  setupRegistry([makeRow({ issuer: "svc", public_key: publicPem })]);
  const stub = installFetchStub(() => new Response("[]", { status: 200 }));
  try {
    const now = Math.floor(Date.now() / 1000);
    const jwt = await signRs256(privatePem, {
      iss: "svc",
      sub: "u",
      iat: now,
      exp: now + 60,
    });
    const handler = createJwtSwapProxy({
      supabaseUrl: SUPABASE_URL,
      serviceRoleKey: SERVICE_ROLE_KEY,
      supabaseJwtSecret: HS_SECRET,
    });
    await handler(
      new Request("https://edge.example.com/functions/v1/rest/things", {
        method: "GET",
        headers: { Authorization: `Bearer ${jwt}` },
      }),
    );
    const fwd = stub.captured[0];
    const auth = (fwd.headers["authorization"] ?? "").replace(
      /^Bearer\s+/i,
      "",
    );
    assertEquals(fwd.headers["apikey"], auth);
  } finally {
    stub.restore();
    resetRegistry();
  }
});

Deno.test("createJwtSwapProxy: unknown issuer → 401 unknown_issuer", async () => {
  const { privatePem } = await makeKeypairPems();
  setupRegistry([]); // no rows
  try {
    const now = Math.floor(Date.now() / 1000);
    const jwt = await signRs256(privatePem, {
      iss: "ghost",
      sub: "u",
      iat: now,
      exp: now + 60,
    });
    const handler = createJwtSwapProxy({
      supabaseUrl: SUPABASE_URL,
      serviceRoleKey: SERVICE_ROLE_KEY,
      supabaseJwtSecret: HS_SECRET,
    });
    const res = await handler(
      new Request("https://edge.example.com/functions/v1/rest/depots", {
        method: "GET",
        headers: { Authorization: `Bearer ${jwt}` },
      }),
    );
    assertEquals(res.status, 401);
    const body = await res.json();
    assertEquals(body.error, "unauthorized");
  } finally {
    resetRegistry();
  }
});

Deno.test("createJwtSwapProxy: forwards POST body to PostgREST", async () => {
  const { privatePem, publicPem } = await makeKeypairPems();
  setupRegistry([makeRow({ issuer: "svc", public_key: publicPem })]);
  const stub = installFetchStub(() => new Response("[]", { status: 201 }));
  try {
    const now = Math.floor(Date.now() / 1000);
    const jwt = await signRs256(privatePem, {
      iss: "svc",
      sub: "u",
      iat: now,
      exp: now + 60,
    });
    const handler = createJwtSwapProxy({
      supabaseUrl: SUPABASE_URL,
      serviceRoleKey: SERVICE_ROLE_KEY,
      supabaseJwtSecret: HS_SECRET,
    });
    const res = await handler(
      new Request("https://edge.example.com/functions/v1/rest/depots", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${jwt}`,
          "content-type": "application/json",
          Prefer: "return=representation",
        },
        body: JSON.stringify({ name: "Depot East" }),
      }),
    );
    assertEquals(res.status, 201);
    const fwd = stub.captured[0];
    assertEquals(fwd.method, "POST");
    assertEquals(fwd.body, '{"name":"Depot East"}');
    assertEquals(fwd.headers["content-type"], "application/json");
    // Prefer header forwarded (case-insensitive Header storage).
    const prefer = fwd.headers["prefer"] ?? fwd.headers["Prefer"];
    assertEquals(prefer, "return=representation");
  } finally {
    stub.restore();
    resetRegistry();
  }
});

Deno.test("createJwtSwapProxy: custom mountPath strips correctly", async () => {
  const { privatePem, publicPem } = await makeKeypairPems();
  setupRegistry([makeRow({ issuer: "svc", public_key: publicPem })]);
  const stub = installFetchStub(() => new Response("[]", { status: 200 }));
  try {
    const now = Math.floor(Date.now() / 1000);
    const jwt = await signRs256(privatePem, {
      iss: "svc",
      sub: "u",
      iat: now,
      exp: now + 60,
    });
    const handler = createJwtSwapProxy({
      supabaseUrl: SUPABASE_URL,
      serviceRoleKey: SERVICE_ROLE_KEY,
      supabaseJwtSecret: HS_SECRET,
      mountPath: "/api/proxy",
    });
    await handler(
      new Request("https://edge.example.com/api/proxy/things/123", {
        method: "GET",
        headers: { Authorization: `Bearer ${jwt}` },
      }),
    );
    const fwd = stub.captured[0];
    assertEquals(
      new URL(fwd.url).pathname,
      "/rest/v1/things/123",
    );
  } finally {
    stub.restore();
    resetRegistry();
  }
});

Deno.test("createJwtSwapProxy: rejects when allowedIssuers excludes inbound iss", async () => {
  const { privatePem, publicPem } = await makeKeypairPems();
  setupRegistry([makeRow({ issuer: "svc-a", public_key: publicPem })]);
  try {
    const now = Math.floor(Date.now() / 1000);
    const jwt = await signRs256(privatePem, {
      iss: "svc-a",
      sub: "u",
      iat: now,
      exp: now + 60,
    });
    const handler = createJwtSwapProxy({
      supabaseUrl: SUPABASE_URL,
      serviceRoleKey: SERVICE_ROLE_KEY,
      supabaseJwtSecret: HS_SECRET,
      allowedIssuers: ["svc-b"],
    });
    const res = await handler(
      new Request("https://edge.example.com/functions/v1/rest/x", {
        method: "GET",
        headers: { Authorization: `Bearer ${jwt}` },
      }),
    );
    assertEquals(res.status, 401);
    assertEquals((await res.json()).error, "unauthorized");
  } finally {
    resetRegistry();
  }
});

Deno.test("createJwtSwapProxy: 503 when registry is unavailable", async () => {
  __setClientFactoryForTests(() =>
    ({
      from() {
        return {
          select() {
            return this;
          },
          eq() {
            return this;
          },
          maybeSingle() {
            return Promise.reject(new Error("ECONNREFUSED"));
          },
        };
      },
    }) as never
  );
  try {
    const { privatePem } = await makeKeypairPems();
    const now = Math.floor(Date.now() / 1000);
    const jwt = await signRs256(privatePem, {
      iss: "svc",
      sub: "u",
      iat: now,
      exp: now + 60,
    });
    const handler = createJwtSwapProxy({
      supabaseUrl: SUPABASE_URL,
      serviceRoleKey: SERVICE_ROLE_KEY,
      supabaseJwtSecret: HS_SECRET,
    });
    const res = await handler(
      new Request("https://edge.example.com/functions/v1/rest/x", {
        method: "GET",
        headers: { Authorization: `Bearer ${jwt}` },
      }),
    );
    assertEquals(res.status, 503);
    assertEquals((await res.json()).error, "registry_unavailable");
  } finally {
    resetRegistry();
  }
});

// --- maxTokenLifetimeSec proxy test (F-07) ---

Deno.test("createJwtSwapProxy: 401 expired when token lifetime exceeds maxTokenLifetimeSec", async () => {
  const { privatePem, publicPem } = await makeKeypairPems();
  setupRegistry([makeRow({ issuer: "svc-proxy-maxlife-f07", public_key: publicPem })]);
  try {
    const now = Math.floor(Date.now() / 1000);
    const jwt = await signRs256(privatePem, {
      iss: "svc-proxy-maxlife-f07",
      sub: "u",
      iat: now,
      exp: now + 3600,
    });
    const handler = createJwtSwapProxy({
      supabaseUrl: SUPABASE_URL,
      serviceRoleKey: SERVICE_ROLE_KEY,
      supabaseJwtSecret: HS_SECRET,
      maxTokenLifetimeSec: 60,
    });
    const res = await handler(
      new Request("https://edge.example.com/functions/v1/rest/x", {
        method: "GET",
        headers: { Authorization: `Bearer ${jwt}` },
      }),
    );
    assertEquals(res.status, 401);
    assertEquals((await res.json()).error, "expired");
  } finally {
    resetRegistry();
  }
});

// --- supabaseUrl validation tests (F-09) ---

Deno.test("createJwtSwapProxy: throws on non-URL supabaseUrl", () => {
  let threw = false;
  try {
    createJwtSwapProxy({
      supabaseUrl: "not a url",
      serviceRoleKey: SERVICE_ROLE_KEY,
      supabaseJwtSecret: HS_SECRET,
    });
  } catch (err) {
    threw = true;
    assert(err instanceof Error);
    assert(
      err.message.includes("not a valid URL"),
      `unexpected message: ${err.message}`,
    );
  }
  assert(threw, "expected createJwtSwapProxy to throw");
});

Deno.test("createJwtSwapProxy: throws on non-http(s) supabaseUrl", () => {
  let threw = false;
  try {
    createJwtSwapProxy({
      supabaseUrl: "ftp://example.com",
      serviceRoleKey: SERVICE_ROLE_KEY,
      supabaseJwtSecret: HS_SECRET,
    });
  } catch (err) {
    threw = true;
    assert(err instanceof Error);
    assert(
      err.message.includes("must use http or https"),
      `unexpected message: ${err.message}`,
    );
  }
  assert(threw, "expected createJwtSwapProxy to throw");
});

Deno.test("createJwtSwapProxy: accepts https supabaseUrl without throwing", () => {
  createJwtSwapProxy({
    supabaseUrl: "https://example.supabase.co",
    serviceRoleKey: SERVICE_ROLE_KEY,
    supabaseJwtSecret: HS_SECRET,
  });
});

Deno.test("createJwtSwapProxy: accepts http supabaseUrl without throwing", () => {
  createJwtSwapProxy({
    supabaseUrl: "http://localhost:54321",
    serviceRoleKey: SERVICE_ROLE_KEY,
    supabaseJwtSecret: HS_SECRET,
  });
});
