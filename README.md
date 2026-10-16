# open-payments-ilp

Web Standards toolkit for [Open Payments](https://openpayments.dev) and [Interledger](https://interledger.org):
ILP, IL-DCP and STREAM codecs, RFC 9421 HTTP message signatures, GNAP, Rafiki-compatible webhooks, an Open Payments
client, a [Better Auth](https://better-auth.com) GNAP plugin, and a [Hono](https://hono.dev) GNAP client middleware. Built on [Effect](https://effect.website).

## Install

```sh
npm i open-payments-ilp effect
# only for the /better-auth subpaths:
npm i better-auth
# only for the /hono subpath:
npm i hono
```

`effect` (`^4.0.0`) is a peer dependency. `better-auth` (`^1.6.19`) is an optional peer dependency used by
`open-payments-ilp/better-auth` only, `hono` (`^4.7.11`) by `open-payments-ilp/hono` only. The package is ESM only and ships TypeScript declarations.

## Runtime support

Only Web Standards are used: `fetch`, `Request`/`Response`/`Headers`, `URL`, `TextEncoder`, and WebCrypto
(`crypto.subtle`, `crypto.getRandomValues`). There are no Node-specific APIs, so the code runs on Cloudflare Workers,
Deno, Bun, browsers, and Node.

HTTP signatures need **Ed25519 in WebCrypto**. In Node it is stable since 20.19.3, 22.13.0 and 23.5.0 (experimental
before that); Workers, Deno, Bun and current browsers support it. The test suite runs on Node 26; older Node versions
are untested. `engines` is not set because the requirement is a runtime feature, not a Node version.

## Design

- **Effect only.** Anything that does I/O, WebCrypto, or needs a clock returns an `Effect`; run it with
  `Effect.runPromise` or compose it into your own program. The framework adapters (`/better-auth`, `/hono`) are the
  exception: they speak the Promises of their framework.
- **`Result` for synchronous codecs.** Parsers and serializers (`/ilp`, `/ildcp`, STREAM packets, amounts, JCS) are pure and
  return `Result<A, E>` from `effect/Result`; they never throw on bad input.
- **`bigint` amounts.** ILP amounts and STREAM counters are `bigint`. Open Payments amounts keep their wire form
  (`value` as a digit string) and are converted with the helpers in `/open-payments`.
- **Tagged errors.** Each subpath fails with its own tagged error, discriminated by a `reason` that is always
  kebab-case (`non-canonical`, `invalid-key`, `unknown-key`, ...): `/ilp` and `/ildcp` with `IlpCodecError`, `/stream`
  with `StreamError | IlpCodecError`, `/http-signatures` with `HttpSignatureError`, `/open-payments` with
  `OpenPaymentsError`, `/gnap` with `GnapClientFieldError` (an unusable `client` field only), `/webhooks` with
  `WebhookError`. `/gnap/server` fails with `GnapRouteError` (the HTTP `status` and GNAP `code` of a failed exchange, no
  `reason`), `/hono` throws `GnapAuthError` (untagged, `status` and `code`), and `/better-auth` throws Better Auth's
  `APIError`. Protocol strings (GNAP error `code`s, ILP error codes) are wire values and keep the protocol's spelling.
- **Explicit time.** Anything that reads the current time takes `clock?: () => Date` (default `new Date()`):
  `verifyRequest`, `signWebhook`, `verifyWebhookSignature`, `isValidWebhookSignature`, the Open Payments clients (the
  `created` of their signatures), `createGnapServer`, the `/better-auth` plugin and `/hono`. Pure codecs and helpers take
  the value itself: `expiresAt`, `serveIldcp({ now })`, `currentAccessIntervalStart(anchor, interval, now)` and
  `SignOptions.created`.
- **Tree-shakeable.** `sideEffects: false`; each subpath is its own entry point.

## Subpaths

### `open-payments-ilp/ilp`

RFC 27 packets (Prepare, Fulfill, Reject), the OER subset of RFC 30, ILP addresses, fulfillment/condition helpers.

```ts
import * as Result from "effect/Result";
import { deserializePrepare, serializePrepare } from "open-payments-ilp/ilp";

const wire = serializePrepare({
  amount: 100n,
  expiresAt: new Date("2030-01-01T00:00:00Z"),
  executionCondition: new Uint8Array(32),
  destination: "g.example.alice",
  data: new Uint8Array(),
});

if (Result.isFailure(wire)) throw wire.failure;
const prepare = deserializePrepare(wire.success);
```

### `open-payments-ilp/ildcp`

IL-DCP request/response codecs and `serveIldcp`, which answers a request with a Fulfill or an `F00` Reject.

```ts
import * as Result from "effect/Result";
import { serializeReply } from "open-payments-ilp/ilp";
import { deserializeIldcpResponse, serializeIldcpRequest, serveIldcp } from "open-payments-ilp/ildcp";

const request = Result.getOrThrow(serializeIldcpRequest({ expiresAt: new Date(Date.now() + 30_000) }));

const reply = serveIldcp({
  requestPacket: request,
  serverAddress: "g.example",
  response: { clientAddress: "g.example.client", assetCode: "USD", assetScale: 2 },
  now: new Date(),
});

const config = deserializeIldcpResponse(Result.getOrThrow(serializeReply(reply)));
```

### `open-payments-ilp/stream`

RFC 29 STREAM: packet and frame codecs, AES-256-GCM packet encryption, SPSP-style credentials (no stored state: the
connection is re-derived from the destination address), a receiver (`createStreamReply`) and sender helpers
(`planStreamChunks`, `buildStreamPrepare`). `buildStreamPrepare` takes `minDestinationAmount` (default `amount`) and
`unfulfillable` (a rate probe: the receiver answers `F05` with the amount it received); `decryptStreamPacket` reads
replies, `decodeStreamReceipt` / `verifyStreamReceipt` handle RFC 39 receipts, and `decodeStreamPaymentTag` reads the
payment tag from a destination address. Imported keys, server-secret derivations and authenticated connection tokens are
cached in small bounded in-memory maps (only authenticated tokens).

```ts
import * as Effect from "effect/Effect";
import { buildStreamPrepare, createStreamReply, generateStreamCredentials } from "open-payments-ilp/stream";

const server = {
  serverSecret: crypto.getRandomValues(new Uint8Array(32)),
  serverAddress: "g.example.receiver",
};

// Receiver: issue credentials for one payment.
const { ilpAddress, sharedSecret } = await Effect.runPromise(
  generateStreamCredentials(server, { asset: { code: "USD", scale: 2 } }),
);

// Sender: build a Prepare for 500 units.
const prepare = await Effect.runPromise(
  buildStreamPrepare({
    destination: ilpAddress,
    sharedSecret,
    amount: 500n,
    sequence: 1n,
    sourceAddress: "g.example.sender",
    expiresAt: new Date(Date.now() + 30_000),
  }),
);

// Receiver: authenticate the Prepare, then decide.
const reply = await Effect.runPromise(createStreamReply(server, prepare));
const fulfill = reply.type === "pending" ? await Effect.runPromise(reply.accept()) : undefined;
```

### `open-payments-ilp/http-signatures`

RFC 9421 Ed25519 signatures as profiled by Open Payments and GNAP, RFC 9530 `Content-Digest`, and a strict RFC 8941
structured-field parser. `verifyRequest` calls `resolveKey` only after every structural check has passed, and reads
the time from its `clock` option (default `new Date()`). `HttpSignatureError` has an optional `cause`: what actually went wrong underneath a `resolveKey` failure.
`importEd25519PrivateKeyPem` imports a PKCS#8 PEM, and `exportPublicJwk(key, { keyId })` returns the publishable
Open Payments JWK (`kid`, `alg: "EdDSA"`, `kty`, `crv`, `x`). A server that enforces once-only `nonce`s must remember
each one for `SIGNATURE_REPLAY_WINDOW_SECONDS` (331 s, exported), the longest a signature can still verify.

```ts
import * as Effect from "effect/Effect";
import { generateEd25519KeyPair, signRequest, verifyRequest } from "open-payments-ilp/http-signatures";

const { privateKey, publicJwk } = await Effect.runPromise(generateEd25519KeyPair());

const signed = await Effect.runPromise(
  signRequest(new Request("https://wallet.example/quotes", { method: "POST", body: '{"hello":"world"}' }), {
    keyId: "key-1",
    privateKey,
  }),
);

const verified = await Effect.runPromise(verifyRequest(signed, { resolveKey: () => Effect.succeed(publicJwk) }));
```

### `open-payments-ilp/open-payments`

Wire types generated from the Open Payments OpenAPI documents, amount helpers, and `createAuthenticatedClient` /
`createUnauthenticatedClient`. Pass your own `fetch` to test or to run behind a proxy. Options: `validateResponses`
(default `true`; bodies are validated and returned unchanged), `requestTimeoutMs` (default 5000), `clock` (the time of the
signatures' `created`, default `new Date()`) and `maxResponseBytes`
(default 1 MiB; a longer response, announced or streamed, is a `transport` error). Retries are opt-in: `retry: { maxAttempts,
baseDelayMs, maxDelayMs, jitter, retryOn, retryNonIdempotent, sleep, random }` retries network errors, timeouts and
`408`/`429`/`502`/`503`/`504` of `GET`/`HEAD`/`PUT`/`DELETE` with exponential backoff and jitter, honours `Retry-After`
(capped by `maxDelayMs`) and signs every attempt again with a fresh `created` and `nonce`. A `POST` may already have been
processed, so it is repeated only with `retryNonIdempotent: true` (client-wide or per request). The last error carries
`attempts`. Without `retry` a failed request fails at once. Get the signing key with `importEd25519PrivateKeyPem(pem)` or
`importEd25519PrivateJwk` from `/http-signatures`, then pass it as `privateKey` to `createAuthenticatedClient`.

```ts
import * as Effect from "effect/Effect";
import { addAmounts, createUnauthenticatedClient } from "open-payments-ilp/open-payments";

const total = addAmounts(
  { value: "100", assetCode: "USD", assetScale: 2 },
  { value: "250", assetCode: "USD", assetScale: 2 },
);

const client = createUnauthenticatedClient({
  fetch: async () =>
    Response.json({
      id: "https://wallet.example/alice",
      assetCode: "USD",
      assetScale: 2,
      authServer: "https://auth.example",
      resourceServer: "https://wallet.example",
    }),
});

const wallet = await Effect.runPromise(client.walletAddress.get({ url: "https://wallet.example/alice" }));
```

### `open-payments-ilp/gnap`

GNAP (RFC 9635) types as profiled by Open Payments, access-item matching and limit checks, error bodies (`gnapErrorBody(code, description)` returns Rafiki's `{ error: { code, description } }`), token helpers,
and the interaction finish `hash`.

```ts
import * as Effect from "effect/Effect";
import { computeInteractionHash, extractGnapToken, verifyInteractionHash } from "open-payments-ilp/gnap";

const input = {
  clientNonce: "client-nonce",
  serverNonce: "server-nonce",
  interactRef: "ref-1",
  grantEndpoint: "https://auth.example/",
};

const hash = await Effect.runPromise(computeInteractionHash(input));
const ok = await Effect.runPromise(verifyInteractionHash({ ...input, hash }));
const token = extractGnapToken("GNAP abc123");
```

### `open-payments-ilp/gnap/server`

A framework-agnostic GNAP authorisation server, wire-compatible with [Rafiki's auth server](https://github.com/interledger/rafiki):
Web `Request` in, Web `Response` out, Effect throughout. It owns the whole protocol (request parsing, body cap, client
key resolution, RFC 9421 verification, grant state machine, `wait`/`too_fast`, token issue/rotation/revocation,
introspection, interaction and finish redirects, Rafiki's `{ error: { code, description } }` bodies); you supply a
`GnapStore` and mount `route` anywhere.

```ts
import * as Effect from "effect/Effect";
import { createGnapServer, memoryGnapStore } from "open-payments-ilp/gnap/server";

const server = createGnapServer({
  baseUrl: "https://auth.example/gnap",
  store: memoryGnapStore(),
  interaction: { consentUrl: "https://app.example/consent" },
  idpSecret: "change-me-to-a-random-secret",
});

const response = await Effect.runPromise(
  server.route(new Request("https://auth.example/gnap/continue/unknown", { method: "POST" })),
);
```

Routes below the path of `baseUrl` (Rafiki's layout): `POST /` grant request, `POST|DELETE /continue/:id`,
`POST|DELETE /token/:id`, `GET /interact/:id/:nonce` and `…/finish`, the identity provider API `GET /grant/:id/:nonce`
and `POST /grant/:id/:nonce/accept|reject` (`x-idp-secret`, only with `idpSecret`, or per tenant), and `POST /introspect` (only with
`introspection.authorize`). `handlers` has each one separately; `getInteraction` and `decideInteraction` serve a
consent page that authenticates the owner itself (they return the `/finish` URL to send the browser to). The wire
behaviour is Rafiki's: subjects, `outgoing-payment` and `list-all` access need interaction (`policy.requiresInteraction`
replaces that), the finish `hash` is padded base64 (`finishHashEncoding: "base64url"` for RFC 9635), accepting or
rejecting only records the decision and the grant is approved (or rejected) when the browser reaches `/finish`, the
continue token is not rotated, a grant without interaction is `APPROVED` (so polling it issues a token), introspection
without `access` reports none, and requests over 64 KiB (`maxBodyBytes`) get `413`.

RFC 9635 / 9767 requirements that Open Payments clients never notice are enforced too: `Cache-Control: no-store` on
every response, `application/json` request bodies, a required `interact.start`, `finish.uri` without fragment and a
non-empty `finish.nonce`, `finish.hash_method` (`sha-256|384|512`), `access_token.label` echoed and `flags` checked
(`invalid_flag`), at most 3 distinct access items and exactly one `sub_ids` entry, `wait` of at least 5 seconds, the
`GNAP` scheme on continuations, `key_rotation_not_supported` for a rotation request that carries a `key`, signatures
under up to three labels per request, a once-only signature `nonce`, introspection `proof` and `invalid_resource_server`,
and no decision by a signed-in user unless `interaction.authorize` allows it. An explicit `alg="ed25519"` signature parameter is
still accepted: RFC 9635 §7.3.1 forbids signers to send it, not verifiers to accept it, and Rafiki and the Open Payments
documentation's example do; this package's signers never send it.

**Consent.** `getInteraction` and `decideInteraction` (and so the Better Auth consent endpoints) serve a consent page that
authenticates the owner itself, which this package cannot do, and being signed in says nothing about who owns the wallet
address a grant names. A decision that comes with a `userId` is therefore refused (`403 request_denied`) unless
`interaction.authorize({ userId, details })` answers `true` (any other answer refuses): implement it as "this user owns
every wallet address in `details.access` and in the requested `subject`" (a grant may carry only a subject). Without the hook only the `x-idp-secret` identity provider API, or a
`decideInteraction` call without `userId` (you authenticated the owner yourself), can decide.

Hardening that compliant Rafiki clients and identity providers do not notice: the client-key lookup refuses
non-`https` URLs, credentials, IP literals and internal host names and never follows redirects. It runs once per request
and is not cached; host names are not resolved and any port is allowed, so pass `resolveClientKeys` with a cache and an
egress policy if DNS rebinding or request volume matters; token management also checks the presented
`GNAP` token; the interaction is looked up (`404`) before `x-idp-secret` is checked, as in Rafiki; the interaction expiry is also checked at
start; the consent URL's `clientName` / `clientUri` come from the stored grant, not from the query; the session cookie
value is the interaction nonce (it ties the browser to the URL, but anyone who knows the nonce can set it; Rafiki's is a signed session); finishing a finalized grant redirects again without reopening it. Not in this server:
wallet address document resolution (keys come from `{walletAddress}/jwks.json`), and Rafiki's separate
introspection port (`/introspect` is served on the same mount, off unless `introspection.authorize` is set; the hook answers
`false` to refuse a caller, `true` to let it ask about any token, or `{ tenantId }` to scope it: tokens of other tenants are `{ active: false }`; any other answer is refused).

**Observing failures.** The server logs nothing: causes can embed SQL parameters. `onError(cause)` is called with the
`Cause` of every unexpected failure answered with a `500` (a store outage, a throwing callback, a bug); it never sees
the request, the host decides what to redact and log, and a failure inside the hook never changes the response. A
client whose keys cannot be fetched gets `400 invalid_client` and does not reach `onError`: wrap the default key fetch
to log why. Its `HttpSignatureError` (`unknown-key`) carries the timeout, status, size or not-a-JWK-set error as
`cause`. Interrupting a request (a client that disconnects, `Effect.timeout`) aborts the key fetch and the body read.

```ts
import * as Cause from "effect/Cause";
import * as Effect from "effect/Effect";
import { createGnapServer, fetchClientKeys, memoryGnapStore } from "open-payments-ilp/gnap/server";

const fetchKeys = fetchClientKeys(globalThis.fetch);

const observed = createGnapServer({
  baseUrl: "https://auth.example/gnap",
  store: memoryGnapStore(),
  onError: (cause) => Effect.sync(() => console.error("gnap failure", Cause.pretty(cause))),
  resolveClientKeys: (walletAddress) =>
    fetchKeys(walletAddress).pipe(
      Effect.tapError((error) => Effect.sync(() => console.warn("gnap keys", walletAddress, error.cause))),
    ),
});
```

**Storage.** `GnapStore` has seven methods, all returning an `Effect` that cannot fail (a database error is a defect),
over two plain JSON-serialisable records (plus the nonce claims), `GrantRecord` and `TokenRecord`:

```ts
interface GnapStore {
  createGrant(grant: GrantRecord): Effect<void>; // `id`, `continueId`, `interactId` unique
  findGrant(by: "id" | "continueId" | "interactId", value: string): Effect<GrantRecord | null>;
  /** Compare-and-set: applies `patch`, increments `version`, and returns true only if `version` still matched. */
  updateGrant(id: string, version: number, patch: GrantPatch): Effect<boolean>;
  createToken(token: TokenRecord): Effect<void>; // `valueHash`, `managementId` unique
  /** A token (revoked or expired too) with its grant: one lookup, as the server needs both. */
  findTokenWithGrant(
    by: "valueHash" | "managementId",
    value: string,
  ): Effect<{ token: TokenRecord; grant: GrantRecord } | null>;
  /** Sets `revokedAt` on the unrevoked tokens of a token or a grant; returns how many it changed. Atomic. */
  revokeTokens(by: "id" | "grantId", value: string, at: number): Effect<number>;
  /** Replay guard for signature nonces: claims `key` until `expiresAt` unless an unexpired claim exists. Atomic. */
  claimNonce(key: string, expiresAt: number, now: number): Effect<boolean>;
}
```

Times are epoch milliseconds, token values are stored as SHA-256 hashes only, and every multi-step change is ordered so
that no transaction is needed. `memoryGnapStore()` is the in-process implementation. A new store is verified with the
contract kit, `storeContract({ describe, it }, name, makeStore)` from `open-payments-ilp/gnap/server/testing`. It is
framework-neutral: pass the `describe` and `it` of your runner (Vitest, `bun:test`, `node:test`). It checks round trips,
uniqueness, the compare-and-set race, nonce claims and the revoke semantics, and the memory store and the Better Auth
store both run it:

```ts
import { describe, it } from "vitest";
import { storeContract } from "open-payments-ilp/gnap/server/testing";

storeContract({ describe, it }, "my database", async () => createMyStore(await freshDatabase()));
```

**Extended records.** Grant modification (`PATCH /continue/:id`), `access_token` arrays and `finish.method: "push"` need
a store that keeps the optional fields `GrantRecord.finishMethod` / `tokenRequests` and `TokenRecord.access` / `label`.
`memoryGnapStore()` does; a custom store opts in with `extendedRecords: true` once it persists them (the contract kit then
checks them). Without the flag the server answers these three requests `501 invalid_request` and everything else is
unchanged. The server's `fetch` also delivers the push, and `onError` receives a failed push.

**Tenants.** Pass `tenants: (tenantId) => Effect<TenantConfig | null>` (`TenantConfig`: `consentUrl?`, `idpSecret?`) for
Rafiki v2 multi-tenancy: grants are requested at `POST {baseUrl}/{tenantId}` (unknown tenant `404` after the signature
check), the consent URL and identity-provider secret are per tenant, and the finish `hash` covers the tenant segment.
A tenant named `introspect` is unreachable: the fixed `POST /introspect` route wins.
Without `tenants`, `interaction.consentUrl` is required and the route is `POST {baseUrl}`. A store keeps
`GrantRecord.tenantId` (nullable). `limits.interval` accepts ISO 8601 repeating intervals (`R12/2030-01-01T00:00:00Z/P1M`,
as Rafiki); a plain duration such as `P1M` is kept as an extension. For a D1/Postgres store, the `GnapStore` JSDoc
carries the SQL DDL for the tables and the conditional `UPDATE` recipes for compare-and-set.

### `open-payments-ilp/webhooks`

Rafiki-compatible webhook signatures (HMAC-SHA256 over `<t>.<canonical JSON>`), RFC 8785 canonicalisation, and event
types generated from Rafiki's webhooks OpenAPI document. The default signature version is `v1`, as in Rafiki;
verification enforces a 5-minute replay window and 30 s future skew. `signWebhook`, `verifyWebhookSignature` and
`isValidWebhookSignature` read the time from the `clock` option of their config (default `new Date()`).

```ts
import * as Effect from "effect/Effect";
import { signWebhook, verifyWebhookSignature } from "open-payments-ilp/webhooks";

const config = { secret: "shared-secret" };
const event = { id: "evt-1", type: "incoming_payment.completed", data: { id: "ip-1" } };
const header = await Effect.runPromise(signWebhook(event, config));

await Effect.runPromise(verifyWebhookSignature(event, header, config));
```

### `open-payments-ilp/better-auth`

A [Better Auth](https://better-auth.com) plugin that turns your Better Auth server into an Open Payments GNAP
authorisation server (RFC 9635 as profiled by Open Payments and Rafiki). It needs the optional peer `better-auth`.

```ts
import * as Effect from "effect/Effect";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { gnap } from "open-payments-ilp/better-auth";

// Yours: whether the user owns the wallet address.
const owns = (userId: string, walletAddress?: string): boolean => walletAddress?.endsWith(`/${userId}`) === true;

const auth = betterAuth({
  // Replace with your database adapter and run the Better Auth migration to create the GNAP tables.
  database: memoryAdapter({
    user: [],
    session: [],
    account: [],
    verification: [],
    gnapGrant: [],
    gnapAccessToken: [],
    gnapNonce: [],
  }),
  baseURL: "https://auth.example",
  secret: "change-me-to-a-random-secret-of-32-or-more-characters",
  emailAndPassword: { enabled: true },
  plugins: [
    gnap({
      interaction: {
        consentUrl: "https://app.example/consent",
        // Required for consent by a signed-in user: without it every decision is refused.
        authorize: ({ userId, details }) => {
          const named = [
            ...details.access.map((item) => ("identifier" in item ? item.identifier : undefined)),
            ...(details.subject?.sub_ids.map((subId) => subId.id) ?? []),
          ];

          return Effect.succeed(named.length > 0 && named.every((address) => owns(userId, address)));
        },
      },
    }),
  ],
});
```

Run the Better Auth CLI migration to create the three tables (`gnapGrant` with a nullable `tenantId`, `gnapAccessToken` and
`gnapNonce`; unique indexes on every lookup column). `gnapNonce` gets a row for each signed request that carries a
`nonce` (every request of this package's own client): delete the rows whose `expiresAt` has passed now and then.
Endpoints live under the Better Auth base path (`/api/auth` by default) and delegate to
[`open-payments-ilp/gnap/server`](#open-payments-ilpgnapserver) with a Better Auth `GnapStore`:

| Endpoint                                                                   | Purpose                                                            |
| -------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `POST /gnap`                                                               | Grant request (HTTP-signed by the client)                          |
| `POST` / `DELETE /gnap/continue/:id`                                       | Continue / cancel a grant                                          |
| `POST` / `DELETE /gnap/token/:id`                                          | Rotate / revoke an access token                                    |
| `GET /gnap/interact/:id/:nonce`, `…/finish`                                | Start interaction (redirects to `consentUrl`) / finish             |
| `GET /gnap/interaction/:id/:nonce`, `POST …/accept`, `…/reject`            | Consent API for the signed-in resource owner (fresh session)       |
| `GET /gnap/grant/:id/:nonce`, `POST …/accept`, `…/reject` (`x-idp-secret`) | Rafiki's identity provider API; only with `idpSecret` or `tenants` |
| `POST /gnap/introspect`                                                    | Token introspection for resource servers (opt-in)                  |

The options of `gnap()` are those of `createGnapServer` without `baseUrl` and `store`: `tenants`, `interaction` (`consentUrl`,
`expiresInSeconds`, `authorize`), `idpSecret`, `introspection` (`authorize`), `policy` (`requiresInteraction`),
`waitSeconds`, `accessTokenExpiresInSeconds`, `resolveClientKeys`, `finishHashEncoding` (`"base64"` default, as Rafiki
sends it; `"base64url"` is the RFC 9635 encoding), `maxBodyBytes`, `fetch`, `clock`, `onError` (as for the core, it
sees the failures of the GNAP routes) and `generateToken`. Grant requests
(20 a minute) and continue requests (30 a minute) are limited per client IP and per URL while Better Auth's rate limiter is
on (by default in production) and knows the client IP: Better Auth keys the bucket by IP and path, so continue requests are
counted per continue URL and, with `tenants`, grant requests per tenant segment; changing the id or tenant segment starts a
new bucket. Volume limiting belongs at the edge. The consent URL carries `interactId`, `nonce`, `clientName` and `clientUri`; the
session consent API takes `interactId` and `nonce`. Server-side,
`auth.api.gnapIntrospect({ body: { access_token, access? } })` returns the in-process introspection result
(`{ active: false }` or `{ active: true, grant, access, client, tenantId, grantAccess }`, with the tenant and the grant's
whole access list), not tenant-scoped; it is not the RFC 9767 response that `POST /gnap/introspect` answers, so do not
forward it as an HTTP response. The
memory adapter in the example needs every table created up front, which is why the GNAP tables are listed; with a real
database the migration creates them. Bring another database layer by implementing `GnapStore` yourself (see
[`/gnap/server`](#open-payments-ilpgnapserver)); `betterAuthGnapStore(adapter)` is the Better Auth implementation.

With `tenants` (Rafiki v2 multi-tenancy) the grant endpoint is `POST /gnap/:tenantId` and the rate limit follows. A
custom `GnapStore` or Better Auth migration needs a nullable `tenantId` column on the grant (`gnapGrant.tenantId`;
the schema field is optional).

**Consent.** The consent endpoints decide for the signed-in user, which proves nothing about who owns the wallet address
a grant names (sign-up is open in the example). They answer `403` until you set `interaction.authorize`: it receives the
`userId` and the grant's `details` and must answer `true` only if that user owns every wallet address the grant names,
in `details.access` and in `details.subject` (a grant may carry only a subject, with no access items). The consent page
has to reach these endpoints with the session cookie: serve it from the same site
as the auth server (a shared parent domain with cross-subdomain cookies), or set up Better Auth's `trustedOrigins`, CORS
and cookie attributes for the cross-site case.

### `open-payments-ilp/better-auth/client`

The client plugin for your consent page: `authClient.gnap.getInteraction(interactId, nonce)`,
`acceptInteraction(interactId, nonce)` and `rejectInteraction(interactId, nonce)` (both values are on the consent URL
your server sends the owner to). Accept and reject resolve to `{ data: { redirect } }`: navigate the browser to `redirect`,
the server's `/finish` step, which approves (or rejects) the grant and sends the browser back to the client.

```ts
import { createAuthClient } from "better-auth/client";
import { gnapClient } from "open-payments-ilp/better-auth/client";

// On the consent page, after sign-in: await authClient.gnap.acceptInteraction(interactId, nonce)
const authClient = createAuthClient({ baseURL: "https://auth.example", plugins: [gnapClient()] });
```

### `open-payments-ilp/hono`

A GNAP **client** middleware for [Hono](https://hono.dev), modelled on
[`@hono/oidc-auth`](https://github.com/honojs/middleware/tree/main/packages/oidc-auth): storage-less login sessions, a
`/callback` route, a refresh interval, a session lifetime, a refresh error hook. It works against a Rafiki / Open
Payments authorisation server and against a generic RFC 9635 one. It needs the optional peer `hono`.

1. No session: a `GET` navigation (`Sec-Fetch-Mode` absent or `navigate`) makes the middleware POST a signed grant
   request (`interact.start: ["redirect"]`, `interact.finish` with a fresh nonce and your callback URL) and redirect
   the user to `interact.redirect`; any other request without a session (an SPA's `fetch`, a `POST`) gets `401`. The
   encrypted, short-lived state (continue URI and token, nonces, the grant endpoint, where to return to) goes into one
   httpOnly cookie scoped to the callback path; next to it a small encrypted pointer to the interaction URL, scoped like
   the session, lets a second navigation made while that login is pending (a second tab, a reload) go to the same
   interaction instead of requesting another grant, so it does not replace the first one's state; after the login both
   return to the page of the first request. The state and the pointer expire after ten minutes, or sooner when the
   server announces a shorter `interact.expires_in`, and the callback clears both. A request with an expired, invalid
   or foreign pointer, or one that asks for other access (`access` is a function of the request), starts a fresh
   grant. The middleware keeps no server-side state, so parallel first requests that carry no cookie yet each start
   their own grant. A grant that needs no interaction creates the session at once. A grant answered with `continue` but
   no `interact.finish` is polled by the browser's later navigations (never before `wait`): `302` to `interact.redirect`
   first (`202` with `Retry-After` when the server offers none), `401` for a denial, the request goes through once approved.
2. The callback checks the state cookie, rejects a failed interaction (`result=…`, Rafiki's convention), verifies the
   `hash` of the finish redirect, waits out `continue.wait` (five seconds when absent), continues the grant (`POST`
   with the one-time `interact_ref`) and, while the server says pending, waits its `wait` and polls without
   `interact_ref` a bounded number of times, then stores the session. An RFC 9635 server reports a denial through the
   same finish redirect and answers the continue call with `user_denied` (or `request_denied`): `401`, like Rafiki's
   `result=grant_rejected`. A bearer token that comes with a key, an `access_token` array and an access token past its
   `expires_in` are refused.
3. The session is an AES-256-GCM encrypted value (key derived from `secret` with HKDF; an HS256 JWT with `encryptCookies: false`) in an httpOnly, Secure, `SameSite=Lax` cookie: the access token, its `manage` and
   `continue` credentials and two times. After the refresh interval (or when the token is about to expire) the
   access token is rotated through its management URI and the cookie re-issued; when the session lifetime is over it is
   revoked and a new grant is requested. A rotation that fails because the server is unavailable (`429`, `5xx`,
   network, timeout) or because a parallel request rotated first (`401`, `404`) keeps the cookie and serves that request
   without a session; only another refusal (`400`, `403`, …) drops the cookie and calls the refresh error hook.

**Open Payments / Rafiki.** The client is a wallet address; the grant endpoint is the `authServer` of that wallet
address document (pass a function to look it up). `privateKeyPem` is the text of an unencrypted PKCS #8 PEM
(`openssl genpkey -algorithm ed25519`).

```ts
import { Hono } from "hono";
import { getGnapAuth, gnapAuthMiddleware, initGnapAuthMiddleware, revokeGnapSession } from "open-payments-ilp/hono";

const app = new Hono();

app.use(
  "*",
  initGnapAuthMiddleware({
    secret: "a-session-secret-of-at-least-32-characters",
    grantEndpoint: "https://auth.wallet.example",
    access: [{ type: "incoming-payment", actions: ["create", "read"] }],
    client: "https://wallet.example/alice",
    keyId: "my-key-1",
    privateKey: privateKeyPem,
  }),
);

app.post("/logout", async (c) => {
  await revokeGnapSession(c);

  return c.text("You have been logged out");
});

app.use("*", gnapAuthMiddleware());

app.get("/", async (c) => {
  const auth = await getGnapAuth(c);

  return c.text(`Access token: ${auth?.accessToken}`);
});
```

**Generic RFC 9635 server.** Leave out `client`: the grant request then carries the public key inline
(`client.key = { proof: "httpsig", jwk }`), so the key must be given as `privateJwk` (a JWK with `d`; the public half and `kid` are
derived from it). The `manage` object of RFC 9635 (a management URI and a separate management token), rotating
continue tokens, `continue.wait` (default 5 s) and a `user_denied` answer to the continue call are handled. Every
request is signed as RFC 9635 §7.3.1 requires: `@method`, `@target-uri`, `authorization` (when a token is presented),
`content-digest` (sha-256, which §7.3.1 fixes for the `proof: "httpsig"` string form) and
`content-length`/`content-type` (with a body), `created`, `keyid`, a fresh `nonce` and `tag="gnap"`. With a wallet-address
`client` the digest is sha-512, like the official Open Payments client.

```ts
import { Hono } from "hono";
import { gnapAuthMiddleware, initGnapAuthMiddleware } from "open-payments-ilp/hono";

const app = new Hono();

app.use(
  "*",
  initGnapAuthMiddleware({
    secret: "a-session-secret-of-at-least-32-characters",
    grantEndpoint: "https://as.example/gnap",
    access: [{ type: "outgoing-payment", actions: ["read"], identifier: "https://wallet.example/alice" }],
    keyId: "my-key-1",
    privateJwk,
  }),
);

app.use("*", gnapAuthMiddleware());
```

Everything but `access` can come from environment variables instead; a value in the config wins over its variable,
except that the private key is resolved as a unit (passing `privateKey` or `privateJwk` ignores both `GNAP_PRIVATE_KEY`
and `GNAP_PRIVATE_JWK`): `GNAP_AUTH_SECRET` (random, at least 32 characters: never this README's placeholders),
`GNAP_GRANT_ENDPOINT`, `GNAP_KEY_ID`, `GNAP_PRIVATE_KEY` (PEM), `GNAP_PRIVATE_JWK` (JWK as JSON), `GNAP_CLIENT`,
`GNAP_REDIRECT_URI` (default `/callback`), `GNAP_COOKIE_NAME` (`gnap-auth`), `GNAP_COOKIE_PATH` (`/`),
`GNAP_COOKIE_DOMAIN`, `GNAP_AUTH_REFRESH_INTERVAL` (seconds, 900), `GNAP_AUTH_EXPIRES` (seconds, 86400, at most
34 560 000) and `GNAP_AUTH_EXTERNAL_URL` (public base URL behind a reverse proxy). `access` and `grantEndpoint` may be
functions of the request context. `fetch`, `clock` and `requestTimeoutMs` (default 10 000 ms: it aborts every call to
the authorisation server and the read of its answer, which is capped at 64 KiB) are set in the config (tests, Workers).

What you pass to `initGnapAuthMiddleware` is checked when it is called, not on the first request: a session secret of
fewer than 32 characters, a negative or non-numeric `refreshInterval`, an `expires` that is not positive or exceeds 34 560 000, a
`requestTimeoutMs` that is not a positive finite number, an `externalUrl` that is no URL, a `redirectUri` that is neither
path nor URL (or that is known to be neither HTTPS/`localhost` nor free of a fragment), a `grantEndpoint` or `client`
that is no http(s) URL, a `privateKey` that is no unencrypted PKCS #8 PEM and a `privateJwk` that is no Ed25519 key with
`d` throw an `Error` at once (the message names the option, never the key). Values that come from the environment
are checked by the same code on the first request they are seen in (`500`, same messages), as is a callback path on the
origin of the request. The private key is imported once and reused for every grant, rotation and revocation (an
environment key again only when its text changes).

The middleware serves the callback itself when mounted on the `redirectUri` path; behind a path-prefixing proxy mount
`app.get("/callback", processGnapCallback)` yourself. With `externalUrl` (or an absolute `redirectUri`) the state cookie
is scoped to the public callback path and the callback is matched on its path alone, so a proxy that strips a prefix
works. A failing callback throws an `HTTPException` (`400` for a missing, forged or expired state or a failed
interaction, `401` for a denied one or a wrong `hash`, `502` for a server that fails the continue request, `502` / `503`
for one that fails or cannot be reached when a login starts; the message never repeats what the callback URL carried);
handle it with `app.onError`. Set a `gnapAuthRefreshErrorHook` with `c.set` to see why a rotation was refused (only a
definitive refusal, see 3 above; it receives a `GnapAuthError` with `status` and `code`, runs after the cookie was
dropped, and may throw to replace the re-login redirect):

```ts
import { Hono } from "hono";
import type { GnapAuthRefreshErrorHook } from "open-payments-ilp/hono";

const app = new Hono();

const gnapAuthRefreshErrorHook: GnapAuthRefreshErrorHook = (error) => {
  console.warn(`GNAP rotation refused: ${error.status} ${error.code}`);
};

app.use("*", async (c, next) => {
  c.set("gnapAuthRefreshErrorHook", gnapAuthRefreshErrorHook);
  await next();
});
```

Security notes:

- The session cookie is **signed, not encrypted**: the user's browser can read the access, management and continue
  tokens in it (httpOnly only hides them from scripts). Use a long random `secret`, serve over HTTPS (cookies are
  `Secure`), and give the grant only the access the user's session needs. Signed state cookies stop a forged or
  replayed callback and bind it to the browser that started the grant (RFC 9635 §11.24); `SameSite=Lax` is needed
  for the cross-site redirect back.
- The `hash` is verified in constant time and accepts padded base64 (Rafiki) and unpadded base64url (RFC 9635).
  `hash_method` is not sent, so the default `sha-256` applies; Rafiki rejects nothing else.
- Waits are never cut short (RFC 9635 §3.1, §5): the continuation URI is not called before the `continue.wait` of the
  response that announced it is over (five seconds when the response has no `wait`), so a user who comes back early
  makes the callback sleep the remainder; a wait over 10 s fails the callback with `504` instead of being cut short.
  The `interact_ref` is one-time-use (§5.1): it is sent in the one first continue request, never again, and a
  `too_fast` answer is an error, not a retry.
- `https:` or `localhost` only for the URIs a browser follows (RFC 9635 §2.5.2.1, §4.1.1): the callback URI (also
  without fragment; a plain-`http` public URL behind a proxy needs `externalUrl`) and `interact.redirect`. The grant
  endpoint and the `continue`/`manage` URIs are used as given, so serve the authorisation server over TLS (§11.1).
- The session is stateless: a copy of the signed cookie stays valid until the next rotation check, up to
  `refreshInterval` (900 s by default) after `revokeGnapSession`, so use a small `refreshInterval` for sensitive apps.
  Log out with a `POST` (`SameSite=Lax` sends the cookie on a cross-site `GET` navigation, so a `GET` logout can be
  triggered by any page). `revokeGnapSession` uses the session of the current request, so it can be mounted before or
  after the middleware; it throws when the server refuses the revocation, but the cookie is deleted either way.
- The whole session lives in one cookie: keep `access` small. A session over 4096 bytes fails with a `500` (browsers
  would drop the cookie silently). An interaction URL too long for the pending-login pointer (over 4096 bytes with the
  cookie name) is left out of it: a second tab then requests its own grant, as it would without the pointer.

Differences from `@hono/oidc-auth`: no discovery document (you name the grant endpoint and the access); the signing key
replaces the client secret; the session holds the GNAP access token and its `manage`/`continue` credentials instead of
ID token claims, so there is no claims hook; the cookie is `SameSite=Lax`; state is one signed cookie instead of
`state`, `nonce`, `code_verifier` and `continue` cookies; refresh and logout call the token management API (`POST` / `DELETE`
the `manage` URI) and cancel the grant (`DELETE` the `continue` URI) instead of OAuth refresh and revocation endpoints.

## Compatibility

The ILP, IL-DCP, STREAM, HTTP-signature and Open Payments client rows were differentially tested against the official
packages (byte for byte, on seeded random input, or against one shared HTTP server). The GNAP server rows are checked by
[`test/gnap-server/rafiki-parity.test.ts`](https://github.com/dayjobdoor/open-payments-ilp/blob/main/test/gnap-server/rafiki-parity.test.ts), a hand-ported table of cases from Rafiki's auth tests (Rafiki `58430af8`,
2026-10-09; nothing links it to Rafiki, so a Rafiki change goes unnoticed) and by the official client's flows; the
webhook rows by a reimplementation of Rafiki's signer. **match** = same observable behaviour; **deviation** =
deliberate, with the reason.

### ILP, IL-DCP, STREAM

| Counterpart                                                                                                                                               | Status    | Notes                                                                                                                                                                                                                                                              |
| --------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `/ilp` vs [`ilp-packet`](https://www.npmjs.com/package/ilp-packet) codec, addresses, OER                                                                  | match     | Byte-identical both directions; accepts nothing `ilp-packet` rejects except an epoch `expiresAt` (`19700101000000000`).                                                                                                                                            |
| `/ilp` leniency                                                                                                                                           | deviation | Rejects calendar-invalid timestamps, non-ASCII in ASCII fields, non-printable reject codes, data over 32767. Years 0000–0099 stay literal (`ilp-packet` maps to 19xx).                                                                                             |
| `/ildcp` vs [`ilp-protocol-ildcp`](https://www.npmjs.com/package/ilp-protocol-ildcp)                                                                      | match     | Byte-identical; `serveIldcp` answers `F00` for bad, foreign or expired requests.                                                                                                                                                                                   |
| `/ildcp` clock and `fetch(sendData)`                                                                                                                      | deviation | The codec never reads the clock (`expiresAt`, `now` are explicit) and there is no transport; compose `serializeIldcpRequest`, `deserializeReply`, `deserializeIldcpResponse`.                                                                                      |
| `/stream` packets, frames, crypto vs [`ilp-protocol-stream`](https://www.npmjs.com/package/ilp-protocol-stream)                                           | match     | Byte-identical, cross-decryptable; receipts (RFC 39) interoperate both ways.                                                                                                                                                                                       |
| `/stream` receiver, credentials, `decodeStreamPaymentTag` vs [`@interledger/stream-receiver`](https://www.npmjs.com/package/@interledger/stream-receiver) | match     | Same decision order and encoding; an empty `paymentTag` means no tag. Pending replies always carry `dataFrames` (possibly empty).                                                                                                                                  |
| `/stream` token decoding                                                                                                                                  | deviation | Exact base64url alphabet; a malformed segment is `F06`.                                                                                                                                                                                                            |
| `/stream` sender vs `@interledger/pay`                                                                                                                    | deviation | No quote, rate probe loop or `pay` loop (they need a transport, timers, congestion state). Primitives are provided: probes, `minDestinationAmount`, `decryptStreamPacket`, receipts, `planStreamChunks`. `minDestinationAmount` defaults to `amount` (same asset). |

### HTTP signatures and webhooks

| Counterpart                                                                                                                          | Status    | Notes                                                                                                                                                                                                                                                                                                                                        |
| ------------------------------------------------------------------------------------------------------------------------------------ | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/http-signatures` signing vs [`@interledger/http-signature-utils`](https://www.npmjs.com/package/@interledger/http-signature-utils) | match     | Same components, `sha-512` digest, `sig1`; both verify each other's signatures. `Content-Digest` is over the exact bytes sent (compact JSON from this client); Rafiki's verifiers digest `JSON.stringify` of the parsed body, so only compact JSON verifies there. Optional `tag`.                                                           |
| `/http-signatures` verification                                                                                                      | deviation | Stricter: strict RFC 8941, `created` required (300 s age, 30 s skew), non-empty body must be digest-covered, `alg` must be `ed25519`. Looser: no content-length/type demand when the digest is covered; the digest is checked over the exact body bytes; signatures under a label other than `sig1` are accepted (Rafiki reads `sig1` only). |
| `/http-signatures` keys                                                                                                              | match     | `importEd25519PrivateKeyPem` (PKCS#8), `exportPublicJwk(key, { keyId })`. Base64-wrapped PEM (`loadBase64Key`): decode first.                                                                                                                                                                                                                |
| `/webhooks` vs Rafiki `generateWebhookSignature`                                                                                     | match     | Same HMAC over `<t>.<JCS body>` and header `t=<ms>, v<N>=<hex>` (the version is only a label in Rafiki); default `v1`; tested against a reimplementation of the signer. JCS and event types from the OpenAPI document.                                                                                                                       |
| `/webhooks` verification                                                                                                             | deviation | Requires the header, enforces a replay window (300 s) and future skew (30 s); Rafiki's POS middleware accepts a missing header and ignores the timestamp.                                                                                                                                                                                    |
| `/webhooks` receiving                                                                                                                | n/a       | Rafiki sends `{ id, type, data }` with a 2 s timeout and counts only HTTP `200` as delivered (up to 10 retries): answer `200`.                                                                                                                                                                                                               |

### Open Payments client

| Counterpart ([`@interledger/open-payments`](https://www.npmjs.com/package/@interledger/open-payments) 7.4) | Status    | Notes                                                                                                                                                                                                      |
| ---------------------------------------------------------------------------------------------------------- | --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Routes, URLs, verbs, query handling, signing rule, headers                                                 | match     | Every route; both clients run against one verifying server.                                                                                                                                                |
| Types, constants, payment invariants, grant-request checks, `OpenPaymentsClientError` fields               | match     | Mutual type assignability asserted; checks return an `invalid-request`/`invalid-amount` error instead of throwing.                                                                                         |
| Response validation                                                                                        | deviation | Effect Schema validation, body returned as received (unknown members kept). Schemas that forbid extra members upstream (quote, outgoing-payment, ilp-payment-method, page-info, JWKS) accept them here.    |
| Factory                                                                                                    | deviation | Synchronous, takes a `CryptoKey` (no filesystem/`Buffer`). No pino logger, no `authenticatedRequestInterceptor` (experimental upstream).                                                                   |
| Retry                                                                                                      | deviation | Opt-in `retry` option (backoff + jitter, `Retry-After`, re-signed per attempt; `POST` only with `retryNonIdempotent`); off by default, `Effect.retry` still composes (errors expose `status`, `attempts`). |

### GNAP

| Counterpart ([Rafiki auth](https://github.com/interledger/rafiki))                    | Status    | Notes                                                                                                                                                                                                                                                                                                                                |
| ------------------------------------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Routes, grant state machine, tokens, interaction, finish hash, reference-client flows | match     | All `@interledger/open-payments` client flows pass against the single- and multi-tenant server. Finish hash is padded base64 by default (Rafiki); `finishHashEncoding: "base64url"` for RFC 9635. `/gnap` `computeInteractionHash` defaults to RFC 9635 unpadded base64url; pass `encoding: "base64"` for Rafiki.                    |
| Multi-tenancy (`POST /:tenantId`, per-tenant `idpConsentUrl`/`idpSecret`)             | match     | Optional via `tenants`; the finish hash covers the tenant segment.                                                                                                                                                                                                                                                                   |
| Introspection access matching, `limits.interval` (`R12/start/P1M`)                    | match     | Same as Rafiki's `compareRequestAndGrantAccessItems` and `getInterval` (expected values recorded from Rafiki's functions). A plain duration is accepted as an extension; unknown members of a requested item are ignored (Rafiki compares the raw item).                                                                             |
| Client key lookup                                                                     | match     | `GET {wallet}/jwks.json` by `kid`, once per request and not cached. `https` only, no credentials, query or fragment, IP literals or internal host names, no redirects, 64 KiB cap, 10 s timeout; host names are not resolved and any port is allowed.                                                                                |
| Wallet address document                                                               | deviation | Only `jwks.json` is fetched; `clientName` is the verified host, `clientName`/`clientUri` come from the stored grant, not the editable query.                                                                                                                                                                                         |
| Receiver and amount limits (RS helpers)                                               | deviation | `validateOutgoingPaymentReceiver` also allows child paths of the limit (not with an encoded `.`, `/` or `\`); `validateOutgoingPaymentAmounts` is a per-payment cap (cumulative sum is yours); both refuse an empty list of matched access.                                                                                          |
| `GET /discovery`, rate limiting                                                       | deviation | Not served; only the `/better-auth` adapter rate-limits.                                                                                                                                                                                                                                                                             |
| Identifier rule                                                                       | deviation | Identifier required for every interactive item (Rafiki checks until the first).                                                                                                                                                                                                                                                      |
| Finish `hash` encoding                                                                | deviation | RFC 9635 §4.2.3: unpadded base64url; Rafiki/Open Payments wire: padded base64 (`finishHashEncoding` picks). `verifyInteractionHash` accepts both.                                                                                                                                                                                    |
| `access_token.manage`                                                                 | deviation | RFC 9635 §3.2.1: object with its own management token; Rafiki/Open Payments wire: a URL string authorised by the access token itself.                                                                                                                                                                                                |
| Continue token                                                                        | deviation | RFC 9635 §5: SHOULD be new on each response; Rafiki/Open Payments wire: unchanged.                                                                                                                                                                                                                                                   |
| `interact.finish` on polling grants                                                   | deviation | RFC 9635 §3.3.5: only when the client sent `finish`; Rafiki/Open Payments wire: always present.                                                                                                                                                                                                                                      |
| Server nonce in the interaction URL                                                   | deviation | RFC 9635 §4.1.1/§4.2.3: `finish` nonce should not be browser-visible; Rafiki/Open Payments wire: one nonce for URL, cookie and `finish`.                                                                                                                                                                                             |
| Denied finish redirect                                                                | deviation | RFC 9635 §4.2.3: `hash` always provided; Rafiki/Open Payments wire: only `result=grant_rejected`.                                                                                                                                                                                                                                    |
| No usable `interact`                                                                  | deviation | RFC 9635 §2.5: `invalid_interaction`; Rafiki/Open Payments wire: `400 invalid_request`.                                                                                                                                                                                                                                              |
| Continuation error codes                                                              | deviation | RFC 9635 §3.6/§5: `too_many_attempts`, `user_denied`; Rafiki/Open Payments wire: `request_denied` / `invalid_request` for those cases (`invalid_continuation` for an unknown, revoked or mismatching grant, as in the RFC).                                                                                                          |
| Inactive interaction start                                                            | deviation | RFC 9635 §4.1.1: no redirect to the client; Rafiki/Open Payments wire: redirect with `result=invalid_interaction`.                                                                                                                                                                                                                   |
| Repeated revocation                                                                   | deviation | RFC 9635 §6.2: SHOULD be honoured; Rafiki/Open Payments wire: `401` for a revoked token.                                                                                                                                                                                                                                             |
| Continuation/management key                                                           | deviation | RFC 9635 §5/§7.3: bound to the request's key; Rafiki/Open Payments wire: any key of the wallet address.                                                                                                                                                                                                                              |
| Token management                                                                      | deviation | RFC 9635 §6: the request must present the managed token (`Authorization: GNAP`), not only a valid signature; Rafiki checks the signature and the management id.                                                                                                                                                                      |
| Interaction start                                                                     | deviation | Writes nothing (the grant is `PENDING` from the start; Rafiki's `markPending` and its failure redirect do not exist), and does not forward an expired interaction to the consent page (Rafiki forwards, the decision then fails).                                                                                                    |
| Repeated finish                                                                       | deviation | Finishing an interaction whose grant is already finalised redirects again but never re-approves it; Rafiki's `approve` sets `APPROVED` unconditionally.                                                                                                                                                                              |
| Introspection endpoint                                                                | deviation | RFC 9767 §3.5: off unless `introspection.authorize` is set (Rafiki: unauthenticated, served at `/` of its own port; a Rafiki backend POSTs to its `AUTH_SERVER_INTROSPECTION_URL` as given, so set that to the full `…/introspect` URL). In-process `introspectToken` also returns `tenantId` and `grantAccess` for an active token. |
| Signature `tag`                                                                       | deviation | RFC 9635 §7.3.1: `tag="gnap"` required; Rafiki/Open Payments wire: not checked (our client sends it).                                                                                                                                                                                                                                |
| Introspection response                                                                | deviation | RFC 9767 §3.3: `iss`, `key`, `exp`, `active:false` for uncovered `access`; Rafiki/Open Payments wire: `grant`, `access`, `client` only.                                                                                                                                                                                              |
| Finalized `continue.wait`                                                             | deviation | RFC 9635 §5.2: SHOULD include `wait`; Rafiki/Open Payments wire: omitted.                                                                                                                                                                                                                                                            |
| `DELETE /continue/:id` after issuance                                                 | deviation | RFC 9635 §5.4: finalized grants never change state; Open Payments extension: it revokes the grant and its tokens.                                                                                                                                                                                                                    |
| `interact.finish.uri` scheme                                                          | deviation | RFC 9635 §2.5.2.1: HTTPS, localhost or an application-specific scheme; Rafiki: any absolute URI. Here `https`, or `http` on `localhost`, `127.0.0.1` or `[::1]`; anything else is `400`.                                                                                                                                             |
| Interaction start is not one-time-use                                                 | deviation | RFC 9635 §4: the AS MUST treat an interact request as one-time-use; here (as in Rafiki) the start URL works until the owner has decided.                                                                                                                                                                                             |
| Interaction session cookie                                                            | deviation | Rafiki: a signed server-side session. Here the cookie value is the interaction nonce: it ties the browser to the URL but proves nothing, since anyone who knows id and nonce can set it.                                                                                                                                             |
| Identity provider back channel                                                        | deviation | Rafiki serves `/grant/:id/:nonce…` on a private interaction port; here they are on the public mount, guarded by `x-idp-secret` alone (no attempt limit). Use a long random secret, or serve `handlers.idpGetGrant` / `handlers.idpDecide` from a private router instead of `route`.                                                  |
| Consent by a signed-in user (`decideInteraction`, Better Auth endpoints)              | deviation | Not in Rafiki (its identity provider is a separate service). Refused (`403`) unless `interaction.authorize` allows the user.                                                                                                                                                                                                         |
| `PATCH /continue/:id`                                                                 | supported | RFC 9635 §5.3: replaces `access_token` / `subject` / `interact` of a `PENDING` or `APPROVED` grant and re-evaluates it. A change that needs consent starts a new interaction and invalidates the old consent URL; earlier tokens are never widened. Needs a store with `extendedRecords`, else `501 invalid_request`.                |
| `access_token` array                                                                  | supported | RFC 9635 §2.1.2, §3.2.2: up to 10 labelled tokens, each with its own access; one consent covers the union; the response is an array whenever the request used one. Needs `extendedRecords`.                                                                                                                                          |
| `finish.method: "push"`                                                               | supported | RFC 9635 §2.5.2.2, §4.2.2: `{ hash, interact_ref }` is POSTed once on approval to a public https URL (no redirects, 5 s timeout); the browser gets `202`; failures go to `onError`. Needs `extendedRecords`.                                                                                                                         |
| Not implemented                                                                       | n/a       | String access references, the `bearer` flag (it would let a resource server skip signature checks; stays `400 invalid_flag`), `user_code` / `app` start, `user` / `display` claims, key proofs other than `httpsig`, subject assertions.                                                                                             |

### GNAP client (`open-payments-ilp/hono`)

RFC 9635 is the standard the middleware follows; where Rafiki / Open Payments servers differ it accepts both.

| RFC 9635 client behaviour                      | Status    | Notes                                                                                                                                                                                                                                                                                                                           |
| ---------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Grant request, continuation, token management  | match     | Signed as §7.3.1 (components, `created`, `keyid`, `nonce`, `tag="gnap"`, no `alg`; sha-256 digest for the inline key, sha-512 for a wallet-address `client` like the official client), `Authorization: GNAP`, `wait` (5 s default) never cut short, one-time `interact_ref`.                                                    |
| Denial                                         | match     | `user_denied` / `request_denied` on the continue call (§3.6, §4.2) and Rafiki's `result=grant_rejected` both end in `401`.                                                                                                                                                                                                      |
| `client` as a wallet address URL               | deviation | §2.3: a string is an instance identifier the AS already knows; Open Payments: the wallet address whose `jwks.json` holds the key. Without `client` the key is sent inline.                                                                                                                                                      |
| `access_token.manage` as a URL string          | deviation | §3.2.1: object with a management token that differs from the access token; Rafiki/Open Payments: a URL authorised by the access token itself. Both are accepted.                                                                                                                                                                |
| Finish `hash` encoding and `result=` redirects | deviation | §4.2.1, §4.2.3: unpadded base64url, `hash` and `interact_ref` always; Rafiki/Open Payments: padded base64, and `result=grant_rejected` without `hash` for a denial. Both are accepted.                                                                                                                                          |
| `http:` grant, continue and manage URIs        | deviation | §11.1: TLS; Rafiki's local environments talk plain HTTP between containers. Callback and interaction URIs must be `https:` or `localhost` (§2.5.2.1, §4.1.1).                                                                                                                                                                   |
| Cookies hold the pending grant and the session | match     | §11.26: the cookies are AES-256-GCM encrypted (key derived from `secret` with HKDF), httpOnly, Secure and `SameSite=Lax`, so the browser's owner cannot read them; still storage-less like `oidc-auth`. `encryptCookies: false` stores them signed only (readable).                                                             |
| Polling without `finish`                       | match     | §5.2, §3.1: a grant with `continue` and no `interact.finish` is polled by the browser's next navigations, never before `wait`. Pending: `302` to `interact.redirect` (`202` + `Retry-After` when none is offered); denial `401`; approval continues the request.                                                                |
| `interact.expires_in`                          | match     | §3.3: shortens the ten minutes of the pending state and pointer (whole seconds); 0 or less is `502`.                                                                                                                                                                                                                            |
| Signing-key rotation                           | n/a       | §6.1.1 (rebinding a token's key with two signatures) is not implemented. Swapping `keyId` and the key keeps sessions when the server accepts the new key for existing grants (Open Payments: publish it in `jwks.json` first; an inline-key RFC server binds the grant to its key, so users log in again at the next rotation). |
| Not implemented                                | n/a       | `push` finish, grant modification (`PATCH`), `user_code`/`app` start, multiple access tokens, subject information, rebinding a token's key (§6.1.1).                                                                                                                                                                            |

Interop tests live in the package's [`test/`](https://github.com/dayjobdoor/open-payments-ilp/tree/main/test) directory and run in CI.

## Versioning

[Semantic versioning](https://semver.org/). While the major version is `0`, minor releases may contain breaking changes;
see [CHANGELOG.md](CHANGELOG.md).

## License

[Apache-2.0](LICENSE). Generated types derive from Interledger Foundation OpenAPI specifications; see [NOTICE](NOTICE).
