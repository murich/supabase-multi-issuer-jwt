/**
 * `jwt_public_keys` registry CRUD.
 *
 * The registry table lives on the *target* Supabase. Issuing services register
 * their public key here once; the swap-proxy reads from it on every request.
 */

import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import type { Algorithm, PublicKeyRow, RegisterOptions } from "./types.ts";

const TABLE = "jwt_public_keys";

const _keyCache = new Map<string, { row: PublicKeyRow; expiresAt: number }>();
const KEY_CACHE_TTL_MS = 60_000;

/** Factory hook — tests override this to inject a fake client. */
type ClientFactory = (url: string, key: string) => SupabaseClient;
let _factory: ClientFactory = (url, key) =>
  createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
    global: { headers: { "X-Client-Info": "supabase-multi-issuer-jwt" } },
  });

/**
 * Test seam. Pass a factory to swap in a fake client; pass `null` to restore
 * the default. NOT part of the public API — name is prefixed and unstable.
 */
export function __setClientFactoryForTests(
  factory: ClientFactory | null,
): void {
  _keyCache.clear();
  if (factory === null) {
    _factory = (url, key) =>
      createClient(url, key, {
        auth: { persistSession: false, autoRefreshToken: false },
        global: { headers: { "X-Client-Info": "supabase-multi-issuer-jwt" } },
      });
  } else {
    _factory = factory;
  }
}

/** Build a service-role Supabase client with the storage layer disabled. */
export function getClient(
  supabaseUrl: string,
  serviceRoleKey: string,
): SupabaseClient {
  if (!supabaseUrl) throw new Error("registry: supabaseUrl is required");
  if (!serviceRoleKey) throw new Error("registry: serviceRoleKey is required");
  return _factory(supabaseUrl, serviceRoleKey);
}

function assertAlgorithm(alg: Algorithm | undefined): Algorithm {
  const a = alg ?? "RS256";
  if (!["RS256", "RS384", "RS512", "ES256", "ES384"].includes(a)) {
    throw new Error(`registry: unsupported algorithm "${a}"`);
  }
  return a;
}

/** UPSERT a public key row keyed on `issuer`. */
export async function registerPublicKey(opts: RegisterOptions): Promise<void> {
  if (!opts.issuer) throw new Error("registerPublicKey: issuer is required");
  if (!opts.publicKey) {
    throw new Error("registerPublicKey: publicKey is required");
  }
  const algorithm = assertAlgorithm(opts.algorithm);
  const client = getClient(opts.supabaseUrl, opts.serviceRoleKey);
  const { error } = await client
    .from(TABLE)
    .upsert(
      {
        issuer: opts.issuer,
        public_key: opts.publicKey,
        algorithm,
        is_active: true,
        updated_at: new Date().toISOString(),
      },
      { onConflict: "issuer" },
    );
  if (error) {
    throw new Error(`registerPublicKey: ${error.message}`);
  }
  _keyCache.delete(opts.issuer);
}

/** Fetch a single issuer's row or null if absent. */
export async function getPublicKey(opts: {
  supabaseUrl: string;
  serviceRoleKey: string;
  issuer: string;
}): Promise<PublicKeyRow | null> {
  if (!opts.issuer) throw new Error("getPublicKey: issuer is required");
  const now = Date.now();
  const cached = _keyCache.get(opts.issuer);
  if (cached && cached.expiresAt > now) {
    return cached.row;
  }
  const client = getClient(opts.supabaseUrl, opts.serviceRoleKey);
  const { data, error } = await client
    .from(TABLE)
    .select("issuer,public_key,algorithm,is_active,created_at,updated_at")
    .eq("issuer", opts.issuer)
    .maybeSingle();
  if (error) {
    throw new Error(`getPublicKey: ${error.message}`);
  }
  if (!data) return null;
  const row = data as PublicKeyRow;
  _keyCache.set(opts.issuer, { row, expiresAt: now + KEY_CACHE_TTL_MS });
  return row;
}

/** Return every row. Ordered by issuer ASC for stable output. */
export async function listPublicKeys(opts: {
  supabaseUrl: string;
  serviceRoleKey: string;
}): Promise<PublicKeyRow[]> {
  const client = getClient(opts.supabaseUrl, opts.serviceRoleKey);
  const { data, error } = await client
    .from(TABLE)
    .select("issuer,public_key,algorithm,is_active,created_at,updated_at")
    .order("issuer", { ascending: true });
  if (error) {
    throw new Error(`listPublicKeys: ${error.message}`);
  }
  return (data ?? []) as PublicKeyRow[];
}

/** Soft-delete: flips `is_active=false` so the swap-proxy stops accepting tokens. */
export async function deactivateIssuer(opts: {
  supabaseUrl: string;
  serviceRoleKey: string;
  issuer: string;
}): Promise<void> {
  if (!opts.issuer) throw new Error("deactivateIssuer: issuer is required");
  const client = getClient(opts.supabaseUrl, opts.serviceRoleKey);
  const { error } = await client
    .from(TABLE)
    .update({ is_active: false, updated_at: new Date().toISOString() })
    .eq("issuer", opts.issuer);
  if (error) {
    throw new Error(`deactivateIssuer: ${error.message}`);
  }
  _keyCache.delete(opts.issuer);
}
