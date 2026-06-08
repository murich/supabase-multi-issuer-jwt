/**
 * cli/register.ts — register an issuer's public key on a target Supabase.
 *
 * Usage:
 *   deno run -A cli/register.ts \
 *     --target https://<project-ref>.supabase.co \
 *     --service-role <service-role-key> \
 *     --issuer depot-stack \
 *     --public-key ./keys/depot-stack.pub \
 *     [--algorithm RS256]
 */

import { parseArgs } from "@std/cli/parse-args";
import { registerPublicKey } from "../src/mod.ts";
import type { Algorithm } from "../src/types.ts";

interface RegisterArgs {
  target: string;
  serviceRole: string;
  issuer: string;
  publicKeyPath: string;
  algorithm: Algorithm;
  help: boolean;
}

const HELP = `Register an issuer's public key on the target Supabase project.

Usage:
  deno run -A cli/register.ts \\
    --target <supabase-url> \\
    --service-role <service-role-key> \\
    --issuer <name> \\
    --public-key <path-to-pub-pem> \\
    [--algorithm RS256|RS384|RS512|ES256|ES384]

Options:
  --target <url>            Target Supabase URL (https://<ref>.supabase.co). Required.
  --service-role <key>      Service-role key for the target project. Required.
  --issuer <name>           Issuer identifier. Required. Must match the \`iss\`
                            claim on JWTs you will mint.
  --public-key <path>       Path to the SPKI PEM public key file. Required.
  --algorithm <alg>         JWT algorithm. Default: RS256.
  --help                    Print this help and exit.

Notes:
  - Idempotent: re-running updates the existing row (UPSERT on \`issuer\`).
  - Service-role key never leaves the local process; it is only used to write
    to \`public.jwt_public_keys\` via PostgREST.
`;

const VALID_ALGS: ReadonlySet<Algorithm> = new Set([
  "RS256",
  "RS384",
  "RS512",
  "ES256",
  "ES384",
]);

function parse(): RegisterArgs {
  const flags = parseArgs(Deno.args, {
    string: ["target", "service-role", "issuer", "public-key", "algorithm"],
    boolean: ["help"],
    default: { algorithm: "RS256", help: false },
    alias: { h: "help" },
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
      publicKeyPath: "",
      algorithm: "RS256",
      help: true,
    };
  }

  const target = typeof flags.target === "string" ? flags.target : "";
  const serviceRole = typeof flags["service-role"] === "string"
    ? flags["service-role"]
    : "";
  const issuer = typeof flags.issuer === "string" ? flags.issuer : "";
  const publicKeyPath = typeof flags["public-key"] === "string"
    ? flags["public-key"]
    : "";
  const algorithm = typeof flags.algorithm === "string"
    ? flags.algorithm
    : "RS256";

  if (!target) throw new Error("Missing required --target <supabase-url>");
  if (!serviceRole) throw new Error("Missing required --service-role <key>");
  if (!issuer) throw new Error("Missing required --issuer <name>");
  if (!publicKeyPath) {
    throw new Error("Missing required --public-key <path-to-pub-pem>");
  }
  if (!VALID_ALGS.has(algorithm as Algorithm)) {
    throw new Error(
      `Invalid --algorithm "${algorithm}". Must be one of: ` +
        [...VALID_ALGS].join(", "),
    );
  }

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
    publicKeyPath,
    algorithm: algorithm as Algorithm,
    help: false,
  };
}

async function main(): Promise<void> {
  let args: RegisterArgs;
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

  let publicKey: string;
  try {
    publicKey = await Deno.readTextFile(args.publicKeyPath);
  } catch (err) {
    console.error(
      `Failed to read public key file ${args.publicKeyPath}: ` +
        (err instanceof Error ? err.message : String(err)),
    );
    Deno.exit(1);
  }

  const trimmed = publicKey.trim();
  if (!trimmed.startsWith("-----BEGIN") || !trimmed.includes("PUBLIC KEY")) {
    console.error(
      `File ${args.publicKeyPath} does not look like a PEM PUBLIC KEY.`,
    );
    Deno.exit(1);
  }

  try {
    await registerPublicKey({
      supabaseUrl: args.target,
      serviceRoleKey: args.serviceRole,
      issuer: args.issuer,
      publicKey,
      algorithm: args.algorithm,
    });
  } catch (err) {
    console.error(
      `Failed to register issuer "${args.issuer}" on ${args.target}: ` +
        (err instanceof Error ? err.message : String(err)),
    );
    Deno.exit(1);
  }

  console.log(
    `Registered issuer "${args.issuer}" (${args.algorithm}) on ${args.target}.`,
  );
}

if (import.meta.main) {
  await main();
}
