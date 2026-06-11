import { assert, assertEquals, assertRejects } from "@std/assert";
import {
  __setClientFactoryForTests,
  deactivateIssuer,
  getPublicKey,
  listPublicKeys,
  registerPublicKey,
} from "../src/registry.ts";
import { freshState, makeFakeClient, makeRow } from "./_fake_supabase.ts";

const URL = "https://example.supabase.co";
const KEY = "service-role-key";

function withFake<T>(
  state: ReturnType<typeof freshState>,
  fn: () => Promise<T> | T,
): Promise<T> {
  // deno-lint-ignore no-explicit-any
  __setClientFactoryForTests(() => makeFakeClient(state) as any);
  return Promise.resolve(fn()).finally(() => {
    __setClientFactoryForTests(null);
  });
}

Deno.test("registerPublicKey: upserts row with onConflict=issuer", async () => {
  const state = freshState();
  await withFake(state, async () => {
    await registerPublicKey({
      supabaseUrl: URL,
      serviceRoleKey: KEY,
      issuer: "svc-depot",
      publicKey: "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----",
      algorithm: "RS256",
    });
  });
  const upsert = state.calls.find((c) => c.op === "upsert");
  assert(upsert, "expected an upsert call");
  assertEquals(upsert!.table, "jwt_public_keys");
  const [row, opts] = upsert!.args as [
    Record<string, unknown>,
    { onConflict?: string },
  ];
  assertEquals(row.issuer, "svc-depot");
  assertEquals(row.algorithm, "RS256");
  assertEquals(row.is_active, true);
  assert(typeof row.updated_at === "string");
  assertEquals(opts.onConflict, "issuer");
  assertEquals(state.rows.length, 1);
});

Deno.test("registerPublicKey: defaults algorithm to RS256", async () => {
  const state = freshState();
  await withFake(state, async () => {
    await registerPublicKey({
      supabaseUrl: URL,
      serviceRoleKey: KEY,
      issuer: "svc",
      publicKey: "pem",
    });
  });
  assertEquals(state.rows[0].algorithm, "RS256");
});

Deno.test("registerPublicKey: requires issuer and publicKey", async () => {
  await withFake(freshState(), async () => {
    await assertRejects(
      () =>
        registerPublicKey({
          supabaseUrl: URL,
          serviceRoleKey: KEY,
          // deno-lint-ignore no-explicit-any
          issuer: "" as any,
          publicKey: "pem",
        }),
      Error,
      "issuer",
    );
    await assertRejects(
      () =>
        registerPublicKey({
          supabaseUrl: URL,
          serviceRoleKey: KEY,
          issuer: "svc",
          // deno-lint-ignore no-explicit-any
          publicKey: "" as any,
        }),
      Error,
      "publicKey",
    );
  });
});

Deno.test("registerPublicKey: surfaces DB errors", async () => {
  const state = freshState();
  state.errorOnNext = { op: "upsert", message: "permission denied" };
  await withFake(state, async () => {
    await assertRejects(
      () =>
        registerPublicKey({
          supabaseUrl: URL,
          serviceRoleKey: KEY,
          issuer: "svc",
          publicKey: "pem",
        }),
      Error,
      "permission denied",
    );
  });
});

Deno.test("getPublicKey: returns row when present", async () => {
  const state = freshState([
    makeRow({ issuer: "svc-depot", public_key: "pem" }),
  ]);
  const row = await withFake(
    state,
    () =>
      getPublicKey({
        supabaseUrl: URL,
        serviceRoleKey: KEY,
        issuer: "svc-depot",
      }),
  );
  assert(row);
  assertEquals(row!.issuer, "svc-depot");
  // Assert the select chain.
  const ops = state.calls.map((c) => c.op);
  assertEquals(ops, ["select", "eq", "maybeSingle"]);
  const eq = state.calls.find((c) => c.op === "eq")!;
  assertEquals(eq.args, ["issuer", "svc-depot"]);
});

Deno.test("getPublicKey: returns null when absent", async () => {
  const state = freshState();
  const row = await withFake(
    state,
    () =>
      getPublicKey({
        supabaseUrl: URL,
        serviceRoleKey: KEY,
        issuer: "missing",
      }),
  );
  assertEquals(row, null);
});

Deno.test("getPublicKey: surfaces DB errors", async () => {
  const state = freshState();
  state.errorOnNext = { op: "maybeSingle", message: "connection refused" };
  await withFake(state, async () => {
    await assertRejects(
      () =>
        getPublicKey({ supabaseUrl: URL, serviceRoleKey: KEY, issuer: "svc" }),
      Error,
      "connection refused",
    );
  });
});

Deno.test("listPublicKeys: returns rows sorted ASC by issuer", async () => {
  const state = freshState([
    makeRow({ issuer: "z-svc", public_key: "z" }),
    makeRow({ issuer: "a-svc", public_key: "a" }),
    makeRow({ issuer: "m-svc", public_key: "m" }),
  ]);
  const rows = await withFake(
    state,
    () => listPublicKeys({ supabaseUrl: URL, serviceRoleKey: KEY }),
  );
  assertEquals(rows.map((r) => r.issuer), ["a-svc", "m-svc", "z-svc"]);
  const order = state.calls.find((c) => c.op === "order")!;
  assertEquals(order.args[0], "issuer");
  assertEquals((order.args[1] as { ascending: boolean }).ascending, true);
});

Deno.test("deactivateIssuer: flips is_active=false for the matching row", async () => {
  const state = freshState([
    makeRow({ issuer: "svc-a", public_key: "a", is_active: true }),
    makeRow({ issuer: "svc-b", public_key: "b", is_active: true }),
  ]);
  await withFake(
    state,
    () =>
      deactivateIssuer({
        supabaseUrl: URL,
        serviceRoleKey: KEY,
        issuer: "svc-a",
      }),
  );
  assertEquals(state.rows.find((r) => r.issuer === "svc-a")!.is_active, false);
  assertEquals(state.rows.find((r) => r.issuer === "svc-b")!.is_active, true);

  const update = state.calls.find((c) => c.op === "update")!;
  const updatedRow = update.args[0] as Record<string, unknown>;
  assertEquals(updatedRow.is_active, false);
  assert(typeof updatedRow.updated_at === "string");

  const eq = state.calls.find((c) => c.op === "eq")!;
  assertEquals(eq.args, ["issuer", "svc-a"]);
});

Deno.test("deactivateIssuer: surfaces DB errors", async () => {
  const state = freshState([makeRow({ issuer: "svc-a", public_key: "a" })]);
  state.errorOnNext = { op: "update", message: "row level security violation" };
  await withFake(state, async () => {
    await assertRejects(
      () =>
        deactivateIssuer({
          supabaseUrl: URL,
          serviceRoleKey: KEY,
          issuer: "svc-a",
        }),
      Error,
      "row level security violation",
    );
  });
});

// --- Cache tests (F-04) ---

Deno.test("getPublicKey: second call returns cached row without hitting DB", async () => {
  const state = freshState([makeRow({ issuer: "cache-hit-f04", public_key: "pem" })]);
  await withFake(state, async () => {
    const row1 = await getPublicKey({ supabaseUrl: URL, serviceRoleKey: KEY, issuer: "cache-hit-f04" });
    const callsAfterFirst = state.calls.length;
    assert(callsAfterFirst > 0, "expected DB calls on first fetch");

    const row2 = await getPublicKey({ supabaseUrl: URL, serviceRoleKey: KEY, issuer: "cache-hit-f04" });
    assertEquals(state.calls.length, callsAfterFirst, "expected no new DB calls on cache hit");
    assertEquals(row1, row2);
  });
});

Deno.test("registerPublicKey: evicts cache so next getPublicKey re-fetches from DB", async () => {
  const state = freshState([makeRow({ issuer: "evict-on-register-f04", public_key: "old-pem" })]);
  await withFake(state, async () => {
    // Populate cache.
    await getPublicKey({ supabaseUrl: URL, serviceRoleKey: KEY, issuer: "evict-on-register-f04" });
    const callsAfterFirst = state.calls.length;

    // Re-register (evicts cache entry).
    await registerPublicKey({
      supabaseUrl: URL,
      serviceRoleKey: KEY,
      issuer: "evict-on-register-f04",
      publicKey: "new-pem",
    });

    // Next getPublicKey must hit DB again.
    const row = await getPublicKey({ supabaseUrl: URL, serviceRoleKey: KEY, issuer: "evict-on-register-f04" });
    assert(state.calls.length > callsAfterFirst, "expected new DB calls after cache eviction");
    assertEquals(row!.public_key, "new-pem");
  });
});

Deno.test("deactivateIssuer: evicts cache so next getPublicKey re-fetches from DB", async () => {
  const state = freshState([makeRow({ issuer: "evict-on-deactivate-f04", public_key: "pem", is_active: true })]);
  await withFake(state, async () => {
    // Populate cache with active row.
    const cached = await getPublicKey({ supabaseUrl: URL, serviceRoleKey: KEY, issuer: "evict-on-deactivate-f04" });
    assertEquals(cached!.is_active, true);
    const callsAfterFirst = state.calls.length;

    // Deactivate (evicts cache).
    await deactivateIssuer({ supabaseUrl: URL, serviceRoleKey: KEY, issuer: "evict-on-deactivate-f04" });

    // Next getPublicKey must hit DB and see is_active=false.
    const row = await getPublicKey({ supabaseUrl: URL, serviceRoleKey: KEY, issuer: "evict-on-deactivate-f04" });
    assert(state.calls.length > callsAfterFirst, "expected new DB calls after cache eviction");
    assertEquals(row!.is_active, false);
  });
});
