import {
  assert,
  assertEquals,
  assertRejects,
} from "@std/assert";
import * as jose from "jose";
import { verifyMultiIssuerJwt } from "../src/verify.ts";
import { __setClientFactoryForTests } from "../src/registry.ts";
import { JwtVerificationError } from "../src/types.ts";
import { freshState, makeFakeClient, makeRow } from "./_fake_supabase.ts";

const URL = "https://example.supabase.co";
const KEY = "service-role-key";

async function makeKeypairPems(): Promise<{
  privatePem: string;
  publicPem: string;
}> {
  const { privateKey, publicKey } = await jose.generateKeyPair("RS256", {
    extractable: true,
  });
  return {
    privatePem: await jose.exportPKCS8(privateKey),
    publicPem: await jose.exportSPKI(publicKey),
  };
}

async function signWith(
  privatePem: string,
  payload: Record<string, unknown>,
  alg: "RS256" = "RS256",
): Promise<string> {
  const key = await jose.importPKCS8(privatePem, alg);
  return await new jose.SignJWT(payload as jose.JWTPayload)
    .setProtectedHeader({ alg, typ: "JWT" })
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

Deno.test("verifyMultiIssuerJwt: happy path", async () => {
  const { privatePem, publicPem } = await makeKeypairPems();
  setupRegistry([makeRow({ issuer: "svc-depot", public_key: publicPem })]);
  try {
    const now = Math.floor(Date.now() / 1000);
    const jwt = await signWith(privatePem, {
      iss: "svc-depot",
      sub: "user-1",
      role: "authenticated",
      iat: now,
      exp: now + 3600,
    });
    const result = await verifyMultiIssuerJwt(jwt, {
      supabaseUrl: URL,
      serviceRoleKey: KEY,
    });
    assertEquals(result.claims.iss, "svc-depot");
    assertEquals(result.claims.sub, "user-1");
    assertEquals(result.claims.role, "authenticated");
    assertEquals(result.matchedKey.issuer, "svc-depot");
    assertEquals(result.matchedKey.is_active, true);
  } finally {
    resetRegistry();
  }
});

Deno.test("verifyMultiIssuerJwt: unknown issuer (registry miss)", async () => {
  const { privatePem } = await makeKeypairPems();
  setupRegistry([]); // empty
  try {
    const now = Math.floor(Date.now() / 1000);
    const jwt = await signWith(privatePem, {
      iss: "ghost",
      sub: "u",
      iat: now,
      exp: now + 60,
    });
    await assertRejects(
      () =>
        verifyMultiIssuerJwt(jwt, { supabaseUrl: URL, serviceRoleKey: KEY }),
      JwtVerificationError,
      "ghost",
    );
  } finally {
    resetRegistry();
  }
});

Deno.test("verifyMultiIssuerJwt: inactive issuer", async () => {
  const { privatePem, publicPem } = await makeKeypairPems();
  setupRegistry([
    makeRow({ issuer: "svc-x", public_key: publicPem, is_active: false }),
  ]);
  try {
    const now = Math.floor(Date.now() / 1000);
    const jwt = await signWith(privatePem, {
      iss: "svc-x",
      sub: "u",
      iat: now,
      exp: now + 60,
    });
    const err = await assertRejects(
      () =>
        verifyMultiIssuerJwt(jwt, { supabaseUrl: URL, serviceRoleKey: KEY }),
      JwtVerificationError,
    );
    assertEquals(err.reason, "inactive_issuer");
  } finally {
    resetRegistry();
  }
});

Deno.test("verifyMultiIssuerJwt: bad signature (key mismatch)", async () => {
  const { privatePem: signingPriv } = await makeKeypairPems();
  const { publicPem: registeredPub } = await makeKeypairPems(); // different key
  setupRegistry([makeRow({ issuer: "svc", public_key: registeredPub })]);
  try {
    const now = Math.floor(Date.now() / 1000);
    const jwt = await signWith(signingPriv, {
      iss: "svc",
      sub: "u",
      iat: now,
      exp: now + 60,
    });
    const err = await assertRejects(
      () =>
        verifyMultiIssuerJwt(jwt, { supabaseUrl: URL, serviceRoleKey: KEY }),
      JwtVerificationError,
    );
    assertEquals(err.reason, "bad_signature");
  } finally {
    resetRegistry();
  }
});

Deno.test("verifyMultiIssuerJwt: expired JWT", async () => {
  const { privatePem, publicPem } = await makeKeypairPems();
  setupRegistry([makeRow({ issuer: "svc", public_key: publicPem })]);
  try {
    const now = Math.floor(Date.now() / 1000);
    const jwt = await signWith(privatePem, {
      iss: "svc",
      sub: "u",
      iat: now - 7200,
      exp: now - 3600, // expired one hour ago, well beyond default tolerance of 5s
    });
    const err = await assertRejects(
      () =>
        verifyMultiIssuerJwt(jwt, { supabaseUrl: URL, serviceRoleKey: KEY }),
      JwtVerificationError,
    );
    assertEquals(err.reason, "expired");
  } finally {
    resetRegistry();
  }
});

Deno.test("verifyMultiIssuerJwt: not yet valid (nbf in future)", async () => {
  const { privatePem, publicPem } = await makeKeypairPems();
  setupRegistry([makeRow({ issuer: "svc", public_key: publicPem })]);
  try {
    const now = Math.floor(Date.now() / 1000);
    const jwt = await signWith(privatePem, {
      iss: "svc",
      sub: "u",
      iat: now,
      nbf: now + 3600,
      exp: now + 7200,
    });
    const err = await assertRejects(
      () =>
        verifyMultiIssuerJwt(jwt, { supabaseUrl: URL, serviceRoleKey: KEY }),
      JwtVerificationError,
    );
    assertEquals(err.reason, "not_yet_valid");
  } finally {
    resetRegistry();
  }
});

Deno.test("verifyMultiIssuerJwt: issuer not in allowedIssuers", async () => {
  const { privatePem, publicPem } = await makeKeypairPems();
  setupRegistry([makeRow({ issuer: "svc-a", public_key: publicPem })]);
  try {
    const now = Math.floor(Date.now() / 1000);
    const jwt = await signWith(privatePem, {
      iss: "svc-a",
      sub: "u",
      iat: now,
      exp: now + 60,
    });
    const err = await assertRejects(
      () =>
        verifyMultiIssuerJwt(jwt, {
          supabaseUrl: URL,
          serviceRoleKey: KEY,
          allowedIssuers: ["svc-b"],
        }),
      JwtVerificationError,
    );
    assertEquals(err.reason, "issuer_not_allowed");
  } finally {
    resetRegistry();
  }
});

Deno.test("verifyMultiIssuerJwt: malformed JWT", async () => {
  setupRegistry([]);
  try {
    const err = await assertRejects(
      () =>
        verifyMultiIssuerJwt("not.a.jwt", {
          supabaseUrl: URL,
          serviceRoleKey: KEY,
        }),
      JwtVerificationError,
    );
    assertEquals(err.reason, "malformed");
  } finally {
    resetRegistry();
  }
});

Deno.test("verifyMultiIssuerJwt: registry network failure", async () => {
  // Inject a factory whose maybeSingle throws.
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
    const jwt = await signWith(privatePem, {
      iss: "svc",
      sub: "u",
      iat: now,
      exp: now + 60,
    });
    const err = await assertRejects(
      () =>
        verifyMultiIssuerJwt(jwt, { supabaseUrl: URL, serviceRoleKey: KEY }),
      JwtVerificationError,
    );
    assertEquals(err.reason, "registry_unavailable");
    assert((err as Error & { cause?: unknown }).cause);
  } finally {
    resetRegistry();
  }
});

Deno.test("verifyMultiIssuerJwt: respects clockToleranceSec for slightly-expired tokens", async () => {
  const { privatePem, publicPem } = await makeKeypairPems();
  setupRegistry([makeRow({ issuer: "svc", public_key: publicPem })]);
  try {
    const now = Math.floor(Date.now() / 1000);
    // expired 30s ago — should pass with tolerance=60
    const jwt = await signWith(privatePem, {
      iss: "svc",
      sub: "u",
      iat: now - 120,
      exp: now - 30,
    });
    const result = await verifyMultiIssuerJwt(jwt, {
      supabaseUrl: URL,
      serviceRoleKey: KEY,
      clockToleranceSec: 60,
    });
    assertEquals(result.claims.iss, "svc");
  } finally {
    resetRegistry();
  }
});
