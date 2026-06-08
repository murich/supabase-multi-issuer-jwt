// Builds the npm package from the Deno source using dnt.
//
// Output: ./npm/
//
// Run with: deno run -A scripts/build-npm.ts

import { build, emptyDir } from "jsr:@deno/dnt@^0.42.3";

const OUT_DIR = "./npm";

const pkg = JSON.parse(await Deno.readTextFile("./package.json"));
const deno = JSON.parse(await Deno.readTextFile("./deno.json"));

await emptyDir(OUT_DIR);

await build({
  entryPoints: [
    {
      name: ".",
      path: "./src/mod.ts",
    },
    {
      name: "./cli",
      path: "./cli/mod.ts",
    },
    // `./proxy` is a Deno-only Edge Function (uses `Deno.serve`) — not
    // bundled into the npm package. The source file is still copied into
    // `npm/templates/jwt-proxy/` so consumers can deploy it to their own
    // Supabase Edge Functions directly.
    {
      kind: "bin",
      name: "supabase-multi-issuer-jwt",
      path: "./cli/mod.ts",
    },
  ],
  outDir: OUT_DIR,
  shims: {
    deno: true,
    crypto: true,
  },
  test: false,
  declaration: "separate",
  // ESM-only. CJS is incompatible with top-level await in cli/mod.ts and our
  // engines.node ">=18" guarantees native ESM support.
  scriptModule: false,
  esModule: true,
  // Skip type-checking the dnt-emitted output: our source is already
  // type-checked by Deno during dev/CI, and the dnt-generated Deno-shim
  // polyfills have type glitches we don't want to gate publish on.
  typeCheck: false,
  compilerOptions: {
    lib: ["ES2022", "DOM"],
    target: "ES2022",
  },
  package: {
    name: pkg.name,
    version: pkg.version ?? deno.version,
    description: pkg.description,
    license: pkg.license,
    author: pkg.author,
    repository: pkg.repository,
    bugs: pkg.bugs,
    homepage: pkg.homepage,
    keywords: pkg.keywords,
    engines: {
      node: ">=18",
    },
    dependencies: pkg.dependencies,
  },
  postBuild() {
    // Copy non-code assets the consumer needs at install time.
    Deno.copyFileSync("LICENSE", `${OUT_DIR}/LICENSE`);
    Deno.copyFileSync("README.md", `${OUT_DIR}/README.md`);
    copyDir("migrations", `${OUT_DIR}/migrations`);
    copyDir("templates", `${OUT_DIR}/templates`);
  },
});

function copyDir(src: string, dest: string): void {
  Deno.mkdirSync(dest, { recursive: true });
  for (const entry of Deno.readDirSync(src)) {
    const s = `${src}/${entry.name}`;
    const d = `${dest}/${entry.name}`;
    if (entry.isDirectory) {
      copyDir(s, d);
    } else if (entry.isFile) {
      Deno.copyFileSync(s, d);
    }
  }
}

console.log(`npm package built at ${OUT_DIR}/`);
