/**
 * cli/keygen.ts — generate an RSA-2048 keypair for a federated issuer.
 *
 * Usage:
 *   deno run -A cli/keygen.ts --issuer depot-stack --out ./keys/
 *
 * Output:
 *   ./keys/<issuer>.key   PKCS8 PEM, mode 0600 (private key — keep secret)
 *   ./keys/<issuer>.pub   SPKI PEM             (public key — register on target)
 *
 * Refuses to overwrite existing files unless --force.
 */

import { parseArgs } from "@std/cli/parse-args";
import { dirname, join, resolve } from "@std/path";

interface KeygenArgs {
  issuer: string;
  out: string;
  target: string;
  force: boolean;
  help: boolean;
}

const HELP = `Generate an RSA-2048 keypair for a federated issuer.

Usage:
  deno run -A cli/keygen.ts --issuer <name> --out <dir> [--force]

Options:
  --issuer <name>   Issuer identifier. Embedded in JWTs as the \`iss\` claim. Required.
  --target <url>    Target Supabase URL. When provided, files are named
                    <issuer>-<target-slug>.key/.pub, making it unambiguous
                    which key belongs to which deployment. Recommended.
  --out <dir>       Directory to write keys into. Created if missing. Required.
  --force           Overwrite existing key files. Default: refuse.
  --help            Print this help and exit.

Files written (with --target):
  <out>/<issuer>-<target-slug>.key   PKCS8 PEM private key (mode 0600)
  <out>/<issuer>-<target-slug>.pub   SPKI PEM public key

Files written (without --target):
  <out>/<issuer>.key   PKCS8 PEM private key (mode 0600)
  <out>/<issuer>.pub   SPKI PEM public key
`;

function parse(): KeygenArgs {
  const flags = parseArgs(Deno.args, {
    string: ["issuer", "out", "target"],
    boolean: ["force", "help"],
    default: { force: false, help: false },
    alias: { h: "help" },
    unknown: (key, _, value) => {
      if (typeof key === "string" && key.startsWith("-")) {
        throw new Error(`Unknown option: ${key}${value ? `=${value}` : ""}`);
      }
      return true;
    },
  });

  if (flags.help) {
    return { issuer: "", out: "", target: "", force: false, help: true };
  }

  if (!flags.issuer || typeof flags.issuer !== "string") {
    throw new Error("Missing required --issuer <name>");
  }
  if (!flags.out || typeof flags.out !== "string") {
    throw new Error("Missing required --out <dir>");
  }

  if (!/^[A-Za-z0-9._-]+$/.test(flags.issuer)) {
    throw new Error(
      `Invalid --issuer "${flags.issuer}". Must match [A-Za-z0-9._-]+.`,
    );
  }

  return {
    issuer: flags.issuer,
    out: flags.out,
    target: typeof flags.target === "string" ? flags.target : "",
    force: flags.force === true,
    help: false,
  };
}

function toBase64(bytes: ArrayBuffer): string {
  const arr = new Uint8Array(bytes);
  let bin = "";
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin);
}

function wrapPem(b64: string, label: "PRIVATE KEY" | "PUBLIC KEY"): string {
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  return `-----BEGIN ${label}-----\n${
    lines.join("\n")
  }\n-----END ${label}-----\n`;
}

async function ensureDir(path: string): Promise<void> {
  await Deno.mkdir(path, { recursive: true });
}

async function exists(path: string): Promise<boolean> {
  try {
    await Deno.stat(path);
    return true;
  } catch (err) {
    if (err instanceof Deno.errors.NotFound) return false;
    throw err;
  }
}

async function writeFileSecret(
  path: string,
  contents: string,
  mode: number,
): Promise<void> {
  await Deno.writeTextFile(path, contents);
  // Deno.chmod is a no-op on Windows; that's fine — the warning is in the docs.
  if (Deno.build.os !== "windows") {
    await Deno.chmod(path, mode);
  }
}

function deriveTargetSlug(rawUrl: string): string {
  try {
    const host = new URL(rawUrl).hostname;
    return host
      .replace(/\.supabase\.co$/, "")
      .replace(/[^A-Za-z0-9_-]/g, "-")
      .slice(0, 40);
  } catch {
    return rawUrl.replace(/[^A-Za-z0-9_-]/g, "-").slice(0, 40);
  }
}

async function main(): Promise<void> {
  let args: KeygenArgs;
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

  const outDir = resolve(args.out);
  await ensureDir(outDir);

  const stem = args.target
    ? `${args.issuer}-${deriveTargetSlug(args.target)}`
    : args.issuer;
  const privPath = join(outDir, `${stem}.key`);
  const pubPath = join(outDir, `${stem}.pub`);

  if (!args.force) {
    for (const p of [privPath, pubPath]) {
      if (await exists(p)) {
        console.error(`Refusing to overwrite existing file: ${p}`);
        console.error("Re-run with --force to replace it.");
        Deno.exit(1);
      }
    }
  }

  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  ) as CryptoKeyPair;

  const pkcs8 = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  const spki = await crypto.subtle.exportKey("spki", keyPair.publicKey);

  const privatePem = wrapPem(toBase64(pkcs8), "PRIVATE KEY");
  const publicPem = wrapPem(toBase64(spki), "PUBLIC KEY");

  // dirname check (no-op when outDir already exists, but keeps the call safe
  // if a user passes a nested non-existent path via --out).
  await ensureDir(dirname(privPath));

  await writeFileSecret(privPath, privatePem, 0o600);
  await Deno.writeTextFile(pubPath, publicPem);
  if (Deno.build.os !== "windows") {
    await Deno.chmod(pubPath, 0o644);
  }

  console.log(`Wrote private key: ${privPath} (mode 0600)`);
  console.log(`Wrote public key:  ${pubPath}`);
  const targetArg = args.target ? `\n    --target ${args.target} \\` : " --target <supabase-url> \\";
  console.log("");
  console.log("Next: register the public key on the target Supabase:");
  console.log(
    `  npx supabase-multi-issuer-jwt register \\${targetArg}`,
  );
  console.log(
    `    --service-role <service-role-key> \\`,
  );
  console.log(
    `    --issuer ${args.issuer} --public-key ${pubPath}`,
  );
}

if (import.meta.main) {
  await main();
}
