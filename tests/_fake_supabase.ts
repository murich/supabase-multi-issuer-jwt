/**
 * Hand-rolled fake of the @supabase/supabase-js client surface used by registry.ts.
 *
 * Only implements the chained methods the registry actually calls:
 *   from(table).upsert(row, { onConflict }) → { error }
 *   from(table).select(cols).eq(col, val).maybeSingle() → { data, error }
 *   from(table).select(cols).order(col, opts) → { data, error }
 *   from(table).update(row).eq(col, val) → { error }
 *
 * Also records every call so tests can assert.
 */

import type { PublicKeyRow } from "../src/types.ts";

export interface FakeCall {
  table: string;
  op: "upsert" | "select" | "eq" | "maybeSingle" | "order" | "update";
  args: unknown[];
}

export interface FakeState {
  rows: PublicKeyRow[];
  calls: FakeCall[];
  errorOnNext?: { op: FakeCall["op"]; message: string };
}

export function makeFakeClient(state: FakeState): {
  // deno-lint-ignore no-explicit-any
  from: (table: string) => any;
} {
  function consumeError(
    op: FakeCall["op"],
  ): { error: { message: string } } | null {
    if (state.errorOnNext && state.errorOnNext.op === op) {
      const m = state.errorOnNext.message;
      state.errorOnNext = undefined;
      return { error: { message: m } };
    }
    return null;
  }

  return {
    from(table: string) {
      const calls = state.calls;
      let pendingFilter: { col: string; val: unknown } | null = null;
      let pendingMode: "select" | "update" | null = null;
      let pendingUpdate: Record<string, unknown> | null = null;

      const api = {
        upsert(
          row: Record<string, unknown>,
          opts?: { onConflict?: string },
        ): Promise<{ error: { message: string } | null }> {
          calls.push({ table, op: "upsert", args: [row, opts] });
          const e = consumeError("upsert");
          if (e) return Promise.resolve(e);
          // Replace-or-insert by issuer.
          const idx = state.rows.findIndex((r) => r.issuer === row.issuer);
          const merged: PublicKeyRow = {
            issuer: row.issuer as string,
            public_key: row.public_key as string,
            algorithm: (row.algorithm as PublicKeyRow["algorithm"]) ?? "RS256",
            is_active: row.is_active as boolean ?? true,
            created_at: (state.rows[idx]?.created_at) ??
              new Date().toISOString(),
            updated_at: (row.updated_at as string) ?? new Date().toISOString(),
          };
          if (idx === -1) state.rows.push(merged);
          else state.rows[idx] = merged;
          return Promise.resolve({ error: null });
        },

        select(cols: string) {
          calls.push({ table, op: "select", args: [cols] });
          pendingMode = "select";
          return api;
        },

        update(row: Record<string, unknown>) {
          calls.push({ table, op: "update", args: [row] });
          pendingMode = "update";
          pendingUpdate = row;
          return api;
        },

        eq(col: string, val: unknown) {
          calls.push({ table, op: "eq", args: [col, val] });
          pendingFilter = { col, val };
          if (pendingMode === "update") {
            const e = consumeError("update");
            if (e) return Promise.resolve(e);
            for (const r of state.rows) {
              if ((r as unknown as Record<string, unknown>)[col] === val) {
                Object.assign(r, pendingUpdate);
              }
            }
            return Promise.resolve({ error: null });
          }
          return api;
        },

        maybeSingle(): Promise<
          { data: PublicKeyRow | null; error: { message: string } | null }
        > {
          calls.push({ table, op: "maybeSingle", args: [] });
          const e = consumeError("maybeSingle");
          if (e) return Promise.resolve({ data: null, ...e });
          if (!pendingFilter) {
            return Promise.resolve({ data: null, error: null });
          }
          const row =
            state.rows.find((r) =>
              (r as unknown as Record<string, unknown>)[pendingFilter!.col] ===
                pendingFilter!.val
            ) ?? null;
          return Promise.resolve({ data: row, error: null });
        },

        order(
          col: string,
          opts?: { ascending?: boolean },
        ): Promise<
          { data: PublicKeyRow[]; error: { message: string } | null }
        > {
          calls.push({ table, op: "order", args: [col, opts] });
          const e = consumeError("order");
          if (e) return Promise.resolve({ data: [], ...e });
          const asc = opts?.ascending ?? true;
          const out = [...state.rows].sort((a, b) => {
            const av = (a as unknown as Record<string, unknown>)[col] as string;
            const bv = (b as unknown as Record<string, unknown>)[col] as string;
            const cmp = String(av).localeCompare(String(bv));
            return asc ? cmp : -cmp;
          });
          return Promise.resolve({ data: out, error: null });
        },
      };
      return api;
    },
  };
}

export function freshState(rows: PublicKeyRow[] = []): FakeState {
  return { rows: [...rows], calls: [] };
}

export function makeRow(
  partial: Partial<PublicKeyRow> & { issuer: string; public_key: string },
): PublicKeyRow {
  return {
    issuer: partial.issuer,
    public_key: partial.public_key,
    algorithm: partial.algorithm ?? "RS256",
    is_active: partial.is_active ?? true,
    created_at: partial.created_at ?? new Date().toISOString(),
    updated_at: partial.updated_at ?? new Date().toISOString(),
  };
}
