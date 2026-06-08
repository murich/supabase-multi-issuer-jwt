/**
 * cli/list.ts — list all registered issuers on a target Supabase.
 *
 * Usage:
 *   deno run -A cli/list.ts \
 *     --target https://<project-ref>.supabase.co \
 *     --service-role <service-role-key>
 *
 * Output:
 *   Table with columns: issuer, algorithm, is_active, updated_at.
 *   --json flag switches to newline-delimited JSON for scripting.
 */

import { parseArgs } from "@std/cli/parse-args";
import { listPublicKeys } from "../src/mod.ts";

interface ListArgs {
  target: string;
  serviceRole: string;
  json: boolean;
  help: boolean;
}

const HELP = `List registered issuers on the target Supabase project.

Usage:
  deno run -A cli/list.ts \\
    --target <supabase-url> \\
    --service-role <service-role-key> \\
    [--json]

Options:
  --target <url>            Target Supabase URL. Required.
  --service-role <key>      Service-role key for the target. Required.
  --json                    Emit newline-delimited JSON, one row per line.
                            Useful for piping into jq.
  --help                    Print this help and exit.
`;

function parse(): ListArgs {
  const flags = parseArgs(Deno.args, {
    string: ["target", "service-role"],
    boolean: ["json", "help"],
    default: { json: false, help: false },
    alias: { h: "help" },
    unknown: (key, _, value) => {
      if (typeof key === "string" && key.startsWith("-")) {
        throw new Error(`Unknown option: ${key}${value ? `=${value}` : ""}`);
      }
      return true;
    },
  });

  if (flags.help) {
    return { target: "", serviceRole: "", json: false, help: true };
  }

  const target = typeof flags.target === "string" ? flags.target : "";
  const serviceRole = typeof flags["service-role"] === "string"
    ? flags["service-role"]
    : "";

  if (!target) throw new Error("Missing required --target <supabase-url>");
  if (!serviceRole) throw new Error("Missing required --service-role <key>");

  let url: URL;
  try {
    url = new URL(target);
  } catch {
    throw new Error(`Invalid --target URL: ${target}`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error(`--target must be http(s):// — got ${url.protocol}`);
  }

  return {
    target: url.origin,
    serviceRole,
    json: Boolean(flags.json),
    help: false,
  };
}

function pad(value: string, width: number): string {
  return value.length >= width
    ? value
    : value + " ".repeat(width - value.length);
}

async function main(): Promise<void> {
  let args: ListArgs;
  try {
    args = parse();
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    console.error("\n" + HELP);
    Deno.exit(2);
  }

  if (args.help) {
    console.log(HELP);
    return;
  }

  let rows;
  try {
    rows = await listPublicKeys({
      supabaseUrl: args.target,
      serviceRoleKey: args.serviceRole,
    });
  } catch (err) {
    console.error(
      `Failed to list issuers on ${args.target}: ` +
        (err instanceof Error ? err.message : String(err)),
    );
    Deno.exit(1);
  }

  if (args.json) {
    for (const row of rows) {
      console.log(JSON.stringify(row));
    }
    return;
  }

  if (rows.length === 0) {
    console.log("No issuers registered.");
    return;
  }

  const widths = {
    issuer: Math.max(6, ...rows.map((r) => r.issuer.length)),
    algorithm: Math.max(9, ...rows.map((r) => r.algorithm.length)),
    is_active: 9,
    updated_at: 24,
  };

  console.log(
    [
      pad("ISSUER", widths.issuer),
      pad("ALGORITHM", widths.algorithm),
      pad("ACTIVE", widths.is_active),
      pad("UPDATED_AT", widths.updated_at),
    ].join("  "),
  );

  for (const row of rows) {
    console.log(
      [
        pad(row.issuer, widths.issuer),
        pad(row.algorithm, widths.algorithm),
        pad(row.is_active ? "true" : "false", widths.is_active),
        pad(row.updated_at, widths.updated_at),
      ].join("  "),
    );
  }
}

if (import.meta.main) {
  await main();
}
