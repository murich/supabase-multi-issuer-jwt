/**
 * cli/mint.ts — sign a multi-issuer JWT and print it to stdout.
 *
 * Usage:
 *   deno run -A cli/mint.ts \
 *     --private-key ./keys/depot-stack.key \
 *     --issuer depot-stack \
 *     --claims '{"role":"depots_sync_writer","sub":"sync-cron"}' \
 *     [--expires-in 5y] \
 *     [--algorithm RS256]
 *
 * Output: the signed JWT only — no extra prose — so it's pipe-friendly:
 *   JWT=$(deno run -A cli/mint.ts ...)
 */

import { parseArgs } from "@std/cli/parse-args";
import { signMultiIssuerJwt } from "../src/mod.ts";
import type { Algorithm, MultiIssuerJwtClaims } from "../src/types.ts";

interface MintArgs {
  privateKeyPath: string;
  issuer: string;
  claimsJson: string;
  expiresIn: string;
  algorithm: Algorithm;
  help: boolean;
}

const HELP = `Sign a multi-issuer JWT and print it to stdout.

Usage:
  deno run -A cli/mint.ts \\
    --private-key <path> \\
    --issuer <name> \\
    --claims <json> \\
    [--expires-in <duration>] \\
    [--algorithm RS256|RS384|RS512|ES256|ES384]

Options:
  --private-key <path>   Path to the PKCS8 PEM private key. Required.
  --issuer <name>        Issuer identifier (becomes the \`iss\` claim). Required.
  --claims <json>        JSON object with claims. MUST include \`sub\`.
                         May include \`role\` and any custom claims your RLS
                         policies reference. Required.
  --expires-in <dur>     Lifetime — duration string ("5y", "30d", "1h") or
                         seconds. Default: "1h".
  --algorithm <alg>      Default: RS256.
  --help                 Print this help and exit.

Output:
  The signed JWT, one line, no trailing prose.
`;

const VALID_ALGS: ReadonlySet<Algorithm> = new Set([
  "RS256",
  "RS384",
  "RS512",
  "ES256",
  "ES384",
]);

function parse(): MintArgs {
  const flags = parseArgs(Deno.args, {
    string: ["private-key", "issuer", "claims", "expires-in", "algorithm"],
    boolean: ["help"],
    default: { "expires-in": "1h", algorithm: "RS256", help: false },
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
      privateKeyPath: "",
      issuer: "",
      claimsJson: "",
      expiresIn: "1h",
      algorithm: "RS256",
      help: true,
    };
  }

  const privateKeyPath = typeof flags["private-key"] === "string"
    ? flags["private-key"]
    : "";
  const issuer = typeof flags.issuer === "string" ? flags.issuer : "";
  const claimsJson = typeof flags.claims === "string" ? flags.claims : "";
  const expiresIn = typeof flags["expires-in"] === "string"
    ? flags["expires-in"]
    : "1h";
  const algorithm = typeof flags.algorithm === "string"
    ? flags.algorithm
    : "RS256";

  if (!privateKeyPath) {
    throw new Error("Missing required --private-key <path>");
  }
  if (!issuer) throw new Error("Missing required --issuer <name>");
  if (!claimsJson) throw new Error("Missing required --claims <json>");
  if (!VALID_ALGS.has(algorithm as Algorithm)) {
    throw new Error(
      `Invalid --algorithm "${algorithm}". Must be one of: ` +
        [...VALID_ALGS].join(", "),
    );
  }

  return {
    privateKeyPath,
    issuer,
    claimsJson,
    expiresIn,
    algorithm: algorithm as Algorithm,
    help: false,
  };
}

async function main(): Promise<void> {
  let args: MintArgs;
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

  let privateKey: string;
  try {
    privateKey = await Deno.readTextFile(args.privateKeyPath);
  } catch (err) {
    console.error(
      `Failed to read private key ${args.privateKeyPath}: ` +
        (err instanceof Error ? err.message : String(err)),
    );
    Deno.exit(1);
  }

  const trimmed = privateKey.trim();
  if (!trimmed.startsWith("-----BEGIN") || !trimmed.includes("PRIVATE KEY")) {
    console.error(
      `File ${args.privateKeyPath} does not look like a PEM PRIVATE KEY.`,
    );
    Deno.exit(1);
  }

  let parsedClaims: Record<string, unknown>;
  try {
    const value = JSON.parse(args.claimsJson);
    if (
      value === null || typeof value !== "object" || Array.isArray(value)
    ) {
      throw new Error("Claims must be a JSON object.");
    }
    parsedClaims = value as Record<string, unknown>;
  } catch (err) {
    console.error(
      `Invalid --claims JSON: ` +
        (err instanceof Error ? err.message : String(err)),
    );
    Deno.exit(1);
  }

  if (typeof parsedClaims.sub !== "string" || parsedClaims.sub.length === 0) {
    console.error(`--claims must include a non-empty string \`sub\` field.`);
    Deno.exit(1);
  }

  // Numeric expires-in: respect it; otherwise pass the duration string through.
  const expiresInValue: string | number = /^\d+$/.test(args.expiresIn)
    ? Number(args.expiresIn)
    : args.expiresIn;

  let jwt: string;
  try {
    jwt = await signMultiIssuerJwt({
      privateKey,
      issuer: args.issuer,
      claims: parsedClaims as Partial<MultiIssuerJwtClaims> & { sub: string },
      expiresIn: expiresInValue,
      algorithm: args.algorithm,
    });
  } catch (err) {
    console.error(
      `Failed to sign JWT: ` +
        (err instanceof Error ? err.message : String(err)),
    );
    Deno.exit(1);
  }

  // ONLY the JWT on stdout — pipe-friendly.
  console.log(jwt);
}

if (import.meta.main) {
  await main();
}
