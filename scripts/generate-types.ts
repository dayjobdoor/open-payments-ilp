/**
 * Regenerates src/open-payments/generated/* from the OpenAPI documents in openapi/: auth-server,
 * resource-server and wallet-address-server are byte-identical to the specs shipped in @interledger/open-payments;
 * token-introspection and webhooks are byte-identical to Rafiki's. Run after bumping the reference specs:
 * `bun run generate:types`.
 */
import { $ } from "bun";

const specs = ["auth-server", "resource-server", "wallet-address-server", "token-introspection", "webhooks"];

for (const spec of specs) {
  await $`openapi-typescript openapi/${spec}.yaml -o src/open-payments/generated/${spec}.ts`;
}
