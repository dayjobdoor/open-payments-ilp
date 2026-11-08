# open-payments-ilp

Publishable npm toolkit (Apache-2.0): ILP/STREAM codecs, HTTP message signatures, GNAP server and client, Open Payments client, webhooks, a Better Auth plugin and a Hono client middleware. Commit and push only when asked. Workflow (jj, gh, SSH, releases): [docs/workflow.md](docs/workflow.md). Review rules: [CODING_STANDARDS.md](CODING_STANDARDS.md). Compatibility rows: [docs/compatibility.md](docs/compatibility.md).

## Boundary

- `src/` uses Web Standards only: no Node APIs, no platform bindings. Peers: `effect` (required), `better-auth` and `hono` (optional, their subpaths only).
- The package reads no file outside its own tree. OpenAPI specs are vendored in `openapi/`; `bun run generate:types` regenerates `src/open-payments/generated/` from them. Never edit generated files by hand.
- Consumers import public subpaths only (`open-payments-ilp/<subpath>`, see `exports` in `package.json`).
- Ports stay here, implementations live in the consumer: `GnapStore` is implemented by a consumer's database adapter and by `src/better-auth/store.ts`. Change a port additively (optional fields or a capability flag such as `extendedRecords`); the contract suite is `storeContract` in `src/gnap/server/testing`.
- The package carries wire contracts and protocol logic. Application behaviour (tenants, accounting, admin) belongs to the consumer.

## Conventions

- Effect-native: see the Design section of `README.md` (`Effect` for I/O, `Result` for codecs, tagged errors, `clock?: () => Date`).
- `src/plain/*` (`open-payments-ilp/plain/*`) is a Promise/exception facade over the Effect modules: add behaviour to the Effect module first, then wrap it with `task`/`sync` from `src/internal/plain.ts`. It must not duplicate logic, and it throws the same tagged errors.
- Direction: Rafiki / Open Payments wire compatibility first (short term), RFC 9635 / 9767 conformance as the medium-term goal. Default to the Rafiki wire wherever clients would notice; a stricter RFC behaviour ships behind an option, or only where no Open Payments client can observe it. Every deliberate deviation (stricter or additive, on or off by default) is a row in `docs/compatibility.md`, with the opt-out where one exists (for example `encryptCookies: false`).
- Each ` ```ts ` block of `README.md` is mirrored by `test/readme-examples.test.ts`; change both together.
- A feature change updates `CHANGELOG.md` and `docs/compatibility.md` in the same change. A release needs a `package.json` version and a `## <version> (<date>)` CHANGELOG heading.

## Verify

`mise run check` (`vp fmt --check`, `vp lint --deny-warnings`, `scripts/check-casts.mjs`, tsc for `src` and `test`, tests, `vp pack` with attw and publint, `scripts/smoke-dist.mjs`). Set `GNAP_TEST_POSTGRES_URL` (a server the tests may create schemas in) to include the PostgreSQL store test; CI does. Individually: `npx vp fmt` to format, `npx tsc -p tsconfig.json --noEmit`, `npx tsc -p tsconfig.test.json`, `npx vp test run`.

Test entry points: the GNAP server harness is `test/gnap-server/support.ts` (`createServerHarness`, `startGrant`, `browserStart`, `idp`, `seedGrant`, `unboundStore`); shared helpers (cookies, seeded randomness, the STREAM oracle) are in `test/support/`.

Subagents own disjoint files. Give each a time budget, and have it write its final report to `/tmp/<name>.md` and return the path: long tool output is truncated.

## Release

Keyless, from CI: [docs/workflow.md](docs/workflow.md#releasing). Agents never run `npm publish`, `npm trust` or any `npm` command that needs the maintainer's 2FA.
