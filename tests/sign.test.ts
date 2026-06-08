import {
  assert,
  assertEquals,
  assertRejects,
  assertThrows,
} from "@std/assert";
import * as jose from "jose";
import { parseDurationSeconds, signMultiIssuerJwt } from "../src/sign.ts";

async function genRsaPem(): Promise<{ privatePem: string; publicPem: string }> {
  const { privateKey, publicKey } = await jose.generateKeyPair("RS256", {
    extractable: true,
  });
  const privatePem = await jose.exportPKCS8(privateKey);
  const publicPem = await jose.exportSPKI(publicKey);
  return { privatePem, publicPem };
}

Deno.test("parseDurationSeconds: handles suffixed units", () => {
  assertEquals(parseDurationSeconds("30s"), 30);
  assertEquals(parseDurationSeconds("5m"), 5 * 60);
  assertEquals(parseDurationSeconds("1h"), 3600);
  assertEquals(parseDurationSeconds("30d"), 30 * 86400);
  assertEquals(parseDurationSeconds("5y"), 5 * 365 * 86400);
});

Deno.test("parseDurationSeconds: handles plain numbers and numeric strings", () => {
  assertEquals(parseDurationSeconds(3600), 3600);
  assertEquals(parseDurationSeconds("3600"), 3600);
});

Deno.test("parseDurationSeconds: case insensitive on unit letter", () => {
  assertEquals(parseDurationSeconds("1H"), 3600);
  assertEquals(parseDurationSeconds("30D"), 30 * 86400);
});

Deno.test("parseDurationSeconds: rejects invalid input", () => {
  assertThrows(() => parseDurationSeconds("forever"));
  assertThrows(() => parseDurationSeconds("1week"));
  assertThrows(() => parseDurationSeconds("-5"));
  assertThrows(() => parseDurationSeconds(0));
  assertThrows(() => parseDurationSeconds(-1));
  assertThrows(() => parseDurationSeconds(1.5));
  assertThrows(() => parseDurationSeconds(""));
  assertThrows(() => parseDurationSeconds("0s"));
});

Deno.test("signMultiIssuerJwt: signs a valid RS256 token with expected claims", async () => {
  const { privatePem, publicPem } = await genRsaPem();
  const before = Math.floor(Date.now() / 1000);
  const jwt = await signMultiIssuerJwt({
    privateKey: privatePem,
    issuer: "svc-depot",
    claims: { sub: "user-42", role: "authenticated", tenant: "depot-east" },
    expiresIn: "1h",
  });
  const after = Math.floor(Date.now() / 1000);

  const pubKey = await jose.importSPKI(publicPem, "RS256");
  const { payload, protectedHeader } = await jose.jwtVerify(jwt, pubKey, {
    issuer: "svc-depot",
    algorithms: ["RS256"],
  });

  assertEquals(protectedHeader.alg, "RS256");
  assertEquals(protectedHeader.typ, "JWT");
  assertEquals(payload.iss, "svc-depot");
  assertEquals(payload.sub, "user-42");
  assertEquals(payload.role, "authenticated");
  assertEquals(payload.tenant, "depot-east");

  assert(typeof payload.iat === "number");
  assert(typeof payload.exp === "number");
  assert((payload.iat as number) >= before);
  assert((payload.iat as number) <= after);
  assertEquals((payload.exp as number) - (payload.iat as number), 3600);
});

Deno.test("signMultiIssuerJwt: respects expiresIn as plain number (seconds)", async () => {
  const { privatePem, publicPem } = await genRsaPem();
  const jwt = await signMultiIssuerJwt({
    privateKey: privatePem,
    issuer: "svc-depot",
    claims: { sub: "user-1" },
    expiresIn: 120,
  });
  const pubKey = await jose.importSPKI(publicPem, "RS256");
  const { payload } = await jose.jwtVerify(jwt, pubKey);
  assertEquals((payload.exp as number) - (payload.iat as number), 120);
});

Deno.test("signMultiIssuerJwt: defaults to 1h when expiresIn omitted", async () => {
  const { privatePem, publicPem } = await genRsaPem();
  const jwt = await signMultiIssuerJwt({
    privateKey: privatePem,
    issuer: "svc",
    claims: { sub: "u" },
  });
  const pubKey = await jose.importSPKI(publicPem, "RS256");
  const { payload } = await jose.jwtVerify(jwt, pubKey);
  assertEquals((payload.exp as number) - (payload.iat as number), 3600);
});

Deno.test("signMultiIssuerJwt: caller-supplied iat/exp are stripped", async () => {
  const { privatePem, publicPem } = await genRsaPem();
  const ancient = 1_000_000_000;
  const jwt = await signMultiIssuerJwt({
    privateKey: privatePem,
    issuer: "svc",
    claims: {
      sub: "u",
      // Spec says these MUST be ignored.
      iat: ancient,
      exp: ancient + 1,
    } as never,
    expiresIn: "1h",
  });
  const pubKey = await jose.importSPKI(publicPem, "RS256");
  const { payload } = await jose.jwtVerify(jwt, pubKey);
  assert((payload.iat as number) > ancient + 1);
  assert((payload.exp as number) > ancient + 1);
});

Deno.test("signMultiIssuerJwt: caller-supplied iss in claims is overridden by opts.issuer", async () => {
  const { privatePem, publicPem } = await genRsaPem();
  const jwt = await signMultiIssuerJwt({
    privateKey: privatePem,
    issuer: "real-issuer",
    claims: { sub: "u", iss: "spoofed-issuer" } as never,
  });
  const pubKey = await jose.importSPKI(publicPem, "RS256");
  const { payload } = await jose.jwtVerify(jwt, pubKey);
  assertEquals(payload.iss, "real-issuer");
});

Deno.test("signMultiIssuerJwt: rejects non-PEM private key", async () => {
  await assertRejects(
    () =>
      signMultiIssuerJwt({
        privateKey: "not-a-pem",
        issuer: "svc",
        claims: { sub: "u" },
      }),
    Error,
    "PEM-encoded",
  );
});

Deno.test("signMultiIssuerJwt: rejects PKCS1/SEC1 private key with conversion hint", async () => {
  const fakePkcs1 =
    "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----";
  await assertRejects(
    () =>
      signMultiIssuerJwt({
        privateKey: fakePkcs1,
        issuer: "svc",
        claims: { sub: "u" },
      }),
    Error,
    "PKCS8",
  );
});

Deno.test("signMultiIssuerJwt: requires sub", async () => {
  const { privatePem } = await genRsaPem();
  await assertRejects(
    () =>
      signMultiIssuerJwt({
        privateKey: privatePem,
        issuer: "svc",
        // deno-lint-ignore no-explicit-any
        claims: {} as any,
      }),
    Error,
    "sub",
  );
});

Deno.test("signMultiIssuerJwt: rejects invalid duration string", async () => {
  const { privatePem } = await genRsaPem();
  await assertRejects(
    () =>
      signMultiIssuerJwt({
        privateKey: privatePem,
        issuer: "svc",
        claims: { sub: "u" },
        expiresIn: "forever",
      }),
    Error,
    "invalid duration",
  );
});
