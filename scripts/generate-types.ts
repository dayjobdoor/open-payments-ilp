/**
 * Regenerates src/open-payments/generated/* from the OpenAPI documents in openapi/: auth-server,
 * resource-server and wallet-address-server are byte-identical to the specs shipped in @interledger/open-payments;
 * token-introspection and webhooks are byte-identical to Rafiki's. Run after bumping the reference specs:
 * `bun run generate:types`. `bun run generate:types --check` generates into a temporary directory instead and exits
 * non-zero when src/open-payments/generated/ differs from the specs, so a stale file cannot pass unnoticed.
 *
 * openapi/id-provider.yaml (Rafiki's) is vendored as a fixture of test/gnap-server and has no generated types.
 *
 * openapi-typescript drives the TypeScript 5 compiler API, which the native TypeScript this package is built with
 * (7.x) does not have: run from node_modules it fails with `Cannot read properties of undefined (reading
 * 'createKeywordTypeNode')`. `bunx` therefore installs it, at the version package.json pins, beside a pinned
 * TypeScript 5. The printer of that TypeScript shapes the output, so bump TYPESCRIPT deliberately and regenerate.
 */
import { $ } from "bun";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TYPESCRIPT = "5.9.3";

const specs = ["auth-server", "resource-server", "wallet-address-server", "token-introspection", "webhooks"];

const generated = "src/open-payments/generated";
const check = process.argv.includes("--check");
const { devDependencies } = await Bun.file("package.json").json();
const generator = `openapi-typescript@${devDependencies["openapi-typescript"]}`;
const target = check ? await mkdtemp(join(tmpdir(), "open-payments-generated-")) : generated;

try {
  for (const spec of specs) {
    await $`bunx -p typescript@${TYPESCRIPT} -p ${generator} openapi-typescript openapi/${spec}.yaml -o ${target}/${spec}.ts`;
  }

  if (check) {
    const stale: string[] = [];

    for (const spec of specs) {
      if ((await Bun.file(`${target}/${spec}.ts`).text()) !== (await Bun.file(`${generated}/${spec}.ts`).text())) {
        stale.push(spec);
      }
    }

    if (stale.length > 0) {
      console.error(`${generated} is stale for: ${stale.join(", ")}. Run \`bun run generate:types\` and commit.`);
      process.exitCode = 1;
    } else {
      console.log(`${generated} matches openapi/.`);
    }
  }
} finally {
  if (check) await rm(target, { recursive: true, force: true });
}
