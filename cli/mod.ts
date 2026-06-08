/**
 * cli/mod.ts — single dispatch entrypoint for the @murich/supabase-multi-issuer-jwt CLI.
 *
 * Usage:
 *   deno run -A cli/mod.ts <subcommand> [args]
 *
 * Subcommands:
 *   keygen      Generate an RSA-2048 keypair for a new issuer.
 *   register    Register an issuer's public key on a target Supabase.
 *   mint        Sign a JWT and print it to stdout.
 *   list        List all registered issuers on a target.
 *   deactivate  Mark an issuer inactive (kill switch for a compromised key).
 *
 * Run any subcommand with --help for its full option list.
 */

const SUBCOMMANDS = [
  "keygen",
  "register",
  "mint",
  "list",
  "deactivate",
] as const;
type Subcommand = (typeof SUBCOMMANDS)[number];

const HELP = `@murich/supabase-multi-issuer-jwt CLI

Usage:
  deno run -A cli/mod.ts <subcommand> [args]

Subcommands:
  keygen      Generate an RSA-2048 keypair for a new issuer.
  register    Register an issuer's public key on a target Supabase project.
  mint        Sign a multi-issuer JWT and print it to stdout (pipe-friendly).
  list        List all registered issuers on a target.
  deactivate  Mark an issuer inactive (kill switch for a compromised key).

Examples:
  # 1. Generate a keypair for a new issuer:
  deno run -A cli/mod.ts keygen --issuer depot-stack --out ./keys/

  # 2. Register the public key on the target Supabase:
  deno run -A cli/mod.ts register \\
    --target https://shop.supabase.co \\
    --service-role <key> \\
    --issuer depot-stack \\
    --public-key ./keys/depot-stack.pub

  # 3. Mint a long-lived JWT for a sync job:
  JWT=$(deno run -A cli/mod.ts mint \\
    --private-key ./keys/depot-stack.key \\
    --issuer depot-stack \\
    --claims '{"role":"depots_sync_writer","sub":"sync-cron"}' \\
    --expires-in 5y)

  # 4. List all registered issuers (with --json for jq pipelines):
  deno run -A cli/mod.ts list \\
    --target https://shop.supabase.co \\
    --service-role <key>

  # 5. Revoke a compromised issuer (kill switch):
  deno run -A cli/mod.ts deactivate \\
    --target https://shop.supabase.co \\
    --service-role <key> \\
    --issuer depot-stack --yes

Run any subcommand with --help for its full option list:
  deno run -A cli/mod.ts <subcommand> --help
`;

function isSubcommand(value: string): value is Subcommand {
  return (SUBCOMMANDS as readonly string[]).includes(value);
}

async function dispatch(sub: Subcommand): Promise<void> {
  // Strip the subcommand from Deno.args so each sub-module sees its own flags.
  // We rebind Deno.args via a property descriptor since it is read-only by default.
  const subArgs = Deno.args.slice(1);
  Object.defineProperty(Deno, "args", {
    value: subArgs,
    writable: false,
    configurable: true,
  });

  switch (sub) {
    case "keygen":
      await import("./keygen.ts");
      return;
    case "register":
      await import("./register.ts");
      return;
    case "mint":
      await import("./mint.ts");
      return;
    case "list":
      await import("./list.ts");
      return;
    case "deactivate":
      await import("./deactivate.ts");
      return;
  }
}

async function main(): Promise<void> {
  const first = Deno.args[0];

  if (!first || first === "--help" || first === "-h" || first === "help") {
    console.log(HELP);
    return;
  }

  if (!isSubcommand(first)) {
    console.error(`Unknown subcommand: ${first}`);
    console.error("");
    console.error(HELP);
    Deno.exit(2);
  }

  await dispatch(first);
}

if (import.meta.main) {
  await main();
}
