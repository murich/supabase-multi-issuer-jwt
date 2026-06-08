// Builds the npm package from the Deno source using dnt.
//
// Output: ./npm/
//
// Run with: deno run -A scripts/build-npm.ts

import { build, emptyDir } from "https://deno.land/x/dnt@0.40.0/mod.ts";

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
    {
      name: "./proxy",
      path: "./templates/jwt-proxy/index.ts",
    },
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
  scriptModule: "cjs",
  esModule: true,
  typeCheck: "single",
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
