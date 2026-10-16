# open-payments-ilp

Publishable npm toolkit (Apache-2.0): ILP/STREAM codecs, HTTP message signatures, GNAP server and client, Open Payments client, webhooks, a Better Auth plugin and a Hono client middleware. Commit and push only when asked. Workflow (jj, gh, SSH, releases): [docs/workflow.md](docs/workflow.md).

## Boundary

- `src/` uses Web Standards only: no Node APIs, no platform bindings. Peers: `effect` (required), `better-auth` and `hono` (optional, their subpaths only).
- The package reads no file outside its own tree. OpenAPI specs are vendored in `openapi/`; `bun run generate:types` regenerates `src/open-payments/generated/` from them. Never edit generated files by hand.
- Consumers import public subpaths only (`open-payments-ilp/<subpath>`, see `exports` in `package.json`).
- Ports stay here, implementations live in the consumer: `GnapStore` is implemented by a consumer's database adapter and by `src/better-auth/store.ts`. Change a port additively (optional fields or a capability flag such as `extendedRecords`); the contract suite is `storeContract` in `src/gnap/server/testing`.
- The package carries wire contracts and protocol logic. Application behaviour (tenants, accounting, admin) belongs to the consumer.

## Conventions

- Effect-native: I/O returns `Effect`, synchronous codecs return `Result`. Errors are tagged, with a kebab-case `reason`. Anything reading time takes `clock?: () => Date`. Details: the Design section of `README.md`.
- Direction: Rafiki / Open Payments wire compatibility first (short term), RFC 9635 / 9767 conformance as the medium-term goal. Default to the Rafiki wire wherever clients would notice; a stricter RFC behaviour ships behind an option, or only where no Open Payments client can observe it. Every deliberate deviation (stricter or additive, on or off by default) is a row in the README Compatibility tables, with the opt-out where one exists (for example `encryptCookies: false`).
- Each ` ```ts ` block of `README.md` is mirrored by `test/readme-examples.test.ts`; change both together.
- A feature change updates `CHANGELOG.md` and the README Compatibility rows in the same change. A release needs a `package.json` version and a `## <version> ` CHANGELOG heading.

## Verify

`mise run check` (tsc for `src` and `test`, tests, `vp pack` with attw and publint, `scripts/smoke-dist.mjs`). Individually: `npx tsc -p tsconfig.json --noEmit`, `npx tsc -p tsconfig.test.json`, `npx vp test run`.

## Release

Keyless, from CI: [docs/workflow.md](docs/workflow.md#releasing). Agents never run `npm publish`, `npm trust` or any `npm` command that needs the maintainer's 2FA.
