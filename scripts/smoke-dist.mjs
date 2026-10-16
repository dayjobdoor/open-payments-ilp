// Smoke test of the built package (run `vp pack` first; plain Node ESM, no dependencies):
//   node packages/open-payments-ilp/scripts/smoke-dist.mjs
//
// 1. Installs dist + package.json next to a symlink to `effect` only and imports every `exports` entry in a fresh
//    Node process: entries without optional peers must load and expose their named exports; `/better-auth` and
//    `/hono` must fail with nothing but a clean "Cannot find package" for their own peer.
// 2. With the peers present, type-checks a consumer file against the built declarations (the `declare module "hono"`
//    augmentation must survive declaration bundling).
import { execFileSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, parse } from "node:path";
import { fileURLToPath } from "node:url";

const packageDir = join(dirname(fileURLToPath(import.meta.url)), "..");

const manifest = JSON.parse(readFileSync(join(packageDir, "package.json"), "utf8"));

if (!existsSync(join(packageDir, "dist"))) throw new Error("dist/ is missing: run `vp pack` in the package first");

/** Names each entry must export; `peer` marks the entries that need an optional peer dependency to load. */
const expected = {
  "./ilp": { names: ["serializePrepare", "deserializePrepare"] },
  "./ildcp": { names: ["serveIldcp"] },
  "./stream": { names: ["buildStreamPrepare", "createStreamReply"] },
  "./http-signatures": { names: ["signRequest", "verifyRequest", "generateEd25519KeyPair"] },
  "./open-payments": { names: ["addAmounts", "createUnauthenticatedClient"] },
  "./gnap": { names: ["computeInteractionHash", "verifyInteractionHash"] },
  "./gnap/server": { names: ["createGnapServer", "memoryGnapStore"] },
  "./gnap/server/testing": { names: ["storeContract"] },
  "./webhooks": { names: ["signWebhook", "verifyWebhookSignature"] },
  "./better-auth/client": { names: ["gnapClient"] },
  "./better-auth": { names: ["gnap", "betterAuthGnapStore"], peer: "better-auth" },
  "./hono": { names: ["gnapAuthMiddleware", "getGnapAuth"], peer: "hono" },
};

const entries = Object.keys(manifest.exports).filter((key) => key !== "./package.json");

const untracked = entries.filter((key) => !(key in expected));

if (untracked.length > 0) throw new Error(`add the new exports entries to smoke-dist.mjs: ${untracked.join(", ")}`);

/** Directory of a dependency installed in this workspace: the nearest `node_modules/<name>` above the package. */
function installed(name) {
  for (let dir = packageDir; dir !== parse(dir).root; dir = dirname(dir)) {
    if (existsSync(join(dir, "node_modules", name, "package.json")))
      return realpathSync(join(dir, "node_modules", name));
  }

  throw new Error(`${name} is not installed: run \`bun install\``);
}

const root = mkdtempSync(join(tmpdir(), "open-payments-ilp-smoke-"));

const failures = [];

/** A project with the built package and the given dependencies (symlinks) in its node_modules. */
function project(name, dependencies) {
  const dir = join(root, name);
  const modules = join(dir, "node_modules");

  mkdirSync(join(modules, "open-payments-ilp"), { recursive: true });
  cpSync(join(packageDir, "dist"), join(modules, "open-payments-ilp", "dist"), { recursive: true });
  cpSync(join(packageDir, "package.json"), join(modules, "open-payments-ilp", "package.json"));
  writeFileSync(join(dir, "package.json"), JSON.stringify({ type: "module" }));

  for (const dependency of dependencies) symlinkSync(installed(dependency), join(modules, dependency), "dir");

  return dir;
}

try {
  // 1. Runtime: only `effect` is installed, so hono and better-auth are absent.
  const bare = project("bare", ["effect"]);

  const probe = `
    const result = {};
    for (const entry of ${JSON.stringify(entries)}) {
      try {
        const module = await import("open-payments-ilp" + entry.slice(1));
        result[entry] = { names: Object.keys(module) };
      } catch (error) {
        result[entry] = { code: error.code, message: String(error.message).split("\\n")[0] };
      }
    }
    console.log(JSON.stringify(result));
  `;

  const imported = JSON.parse(
    execFileSync(process.execPath, ["--input-type=module", "-e", probe], { cwd: bare, encoding: "utf8" }),
  );

  for (const entry of entries) {
    const { names, peer } = expected[entry];
    const got = imported[entry];

    if (peer === undefined) {
      const missing = got.names === undefined ? names : names.filter((name) => !got.names.includes(name));

      if (missing.length > 0) failures.push(`${entry}: ${got.message ?? `missing exports ${missing.join(", ")}`}`);
      else console.log(`ok   ${entry}: loads with effect only (${got.names.length} exports)`);
    } else if (
      got.code === "ERR_MODULE_NOT_FOUND" &&
      new RegExp(`Cannot find package '${peer}(/|')`).test(got.message)
    ) {
      console.log(`ok   ${entry}: without ${peer} fails cleanly (${got.message})`);
    } else {
      failures.push(`${entry}: expected "Cannot find package '${peer}'" without ${peer}, got ${JSON.stringify(got)}`);
    }
  }

  // 2. Types: a consumer with the optional peers present, against the built declarations.
  const typed = project("typed", ["effect", "hono", "better-auth"]);

  writeFileSync(
    join(typed, "consumer.ts"),
    [
      'import { Hono } from "hono";',
      'import { gnapAuthMiddleware, type GnapAuthRefreshErrorHook } from "open-payments-ilp/hono";',
      ...entries.map((entry, index) => `import * as entry${index} from "open-payments-ilp${entry.slice(1)}";`),
      "",
      `export const entries = [${entries.map((_, index) => `entry${index}`).join(", ")}];`,
      "",
      "const hook: GnapAuthRefreshErrorHook = (error) => {",
      "  console.warn(error.status, error.code);",
      "};",
      "",
      "const app = new Hono();",
      "",
      'app.use("*", async (c, next) => {',
      '  c.set("gnapAuthRefreshErrorHook", hook);',
      "  // @ts-expect-error the augmentation types the hook: a number is refused",
      '  c.set("gnapAuthRefreshErrorHook", 1);',
      "  await next();",
      "});",
      "",
      'app.use("*", gnapAuthMiddleware());',
      "",
    ].join("\n"),
  );

  writeFileSync(
    join(typed, "tsconfig.json"),
    JSON.stringify({
      compilerOptions: {
        target: "ES2023",
        lib: ["ES2023", "DOM", "DOM.Iterable"],
        module: "NodeNext",
        moduleResolution: "NodeNext",
        types: [],
        strict: true,
        noEmit: true,
        skipLibCheck: false,
      },
      files: ["consumer.ts"],
    }),
  );

  try {
    execFileSync(process.execPath, [join(installed("typescript"), "bin", "tsc"), "-p", "tsconfig.json"], {
      cwd: typed,
      encoding: "utf8",
      stdio: "pipe",
    });
    console.log("ok   consumer type-checks against dist (hono augmentation, every entry)");
  } catch (error) {
    // Declarations of the peers themselves are not ours (they need Node and DOM types the consumer does not load).
    const ours = String(error.stdout ?? error.message)
      .split("\n")
      .filter((line) => /^consumer\.ts|open-payments-ilp\/dist\//.test(line));

    if (ours.length > 0) failures.push(`consumer type check:\n${ours.join("\n")}`);
    else console.log("ok   consumer type-checks against dist (hono augmentation, every entry)");
  }
} finally {
  rmSync(root, { recursive: true, force: true });
}

if (failures.length > 0) {
  console.error(`\n${failures.length} smoke failure(s):\n${failures.map((failure) => `- ${failure}`).join("\n")}`);
  process.exit(1);
}

console.log("\nsmoke-dist: all good");
