/**
 * cli/deactivate.ts — mark an issuer inactive on a target Supabase.
 *
 * Usage:
 *   deno run -A cli/deactivate.ts \
 *     --target https://<project-ref>.supabase.co \
 *     --service-role <service-role-key> \
 *     --issuer depot-stack
 *
 * After this, any JWT signed by the issuer's private key is rejected by
 * verifyMultiIssuerJwt with reason `inactive_issuer`. Existing JWTs cannot be
 * recovered without re-registering / re-activating; this is the kill switch
 * for a compromised private key.
 */

import { parseArgs } from "@std/cli/parse-args";
import { deactivateIssuer } from "../src/mod.ts";

interface DeactivateArgs {
  target: string;
  serviceRole: string;
  issuer: string;
  yes: boolean;
  help: boolean;
}

const HELP = `Deactivate an issuer on the target Supabase project (kill switch).

Usage:
  deno run -A cli/deactivate.ts \\
    --target <supabase-url> \\
    --service-role <service-role-key> \\
    --issuer <name> \\
    [--yes]

Options:
  --target <url>            Target Supabase URL. Required.
  --service-role <key>      Service-role key for the target. Required.
  --issuer <name>           Issuer to deactivate. Required.
  --yes                     Skip the interactive confirmation prompt.
  --help                    Print this help and exit.

Effect:
  Sets jwt_public_keys.is_active = FALSE for the given issuer. All future
  verification attempts for JWTs with iss=<name> will fail with reason
  "inactive_issuer", regardless of whether the JWT signature would otherwise
  validate. Re-enable by re-running cli/register.ts with the same arguments
  (UPSERT resets is_active to TRUE).
`;

function parse(): DeactivateArgs {
  const flags = parseArgs(Deno.args, {
    string: ["target", "service-role", "issuer"],
    boolean: ["yes", "help"],
    default: { yes: false, help: false },
    alias: { h: "help", y: "yes" },
    unknown: (key, _, value) => {
      if (typeof key === "string" && key.startsWith("-")) {
        throw new Error(`Unknown option: ${key}${value ? `=${value}` : ""}`);
      }
      return true;
    },
  });

  if (flags.help) {
    return {
      target: "",
      serviceRole: "",
      issuer: "",
      yes: false,
      help: true,
    };
  }

  const target = typeof flags.target === "string" ? flags.target : "";
  const serviceRole = typeof flags["service-role"] === "string"
    ? flags["service-role"]
    : "";
  const issuer = typeof flags.issuer === "string" ? flags.issuer : "";

  if (!target) throw new Error("Missing required --target <supabase-url>");
  if (!serviceRole) throw new Error("Missing required --service-role <key>");
  if (!issuer) throw new Error("Missing required --issuer <name>");

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
    issuer,
    yes: Boolean(flags.yes),
    help: false,
  };
}

async function confirm(promptText: string): Promise<boolean> {
  await Deno.stdout.write(new TextEncoder().encode(promptText + " [y/N] "));
  const buf = new Uint8Array(8);
  const n = await Deno.stdin.read(buf);
  if (!n) return false;
  const answer = new TextDecoder().decode(buf.subarray(0, n)).trim()
    .toLowerCase();
  return answer === "y" || answer === "yes";
}

async function main(): Promise<void> {
  let args: DeactivateArgs;
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

  if (!args.yes) {
    const ok = await confirm(
      `Deactivate issuer "${args.issuer}" on ${args.target}? All current JWTs from this issuer will be rejected immediately.`,
    );
    if (!ok) {
      console.error("Aborted.");
      Deno.exit(1);
    }
  }

  try {
    await deactivateIssuer({
      supabaseUrl: args.target,
      serviceRoleKey: args.serviceRole,
      issuer: args.issuer,
    });
  } catch (err) {
    console.error(
      `Failed to deactivate issuer "${args.issuer}" on ${args.target}: ` +
        (err instanceof Error ? err.message : String(err)),
    );
    Deno.exit(1);
  }

  console.log(`Deactivated issuer "${args.issuer}" on ${args.target}.`);
}

if (import.meta.main) {
  await main();
}
