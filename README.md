# open-payments-ilp

Web Standards toolkit for [Open Payments](https://openpayments.dev) and [Interledger](https://interledger.org):
ILP, IL-DCP and STREAM codecs, RFC 9421 HTTP message signatures, GNAP, Rafiki-compatible webhooks, an Open Payments
client, a [Better Auth](https://better-auth.com) GNAP plugin, and a [Hono](https://hono.dev) GNAP client middleware. Built on [Effect](https://effect.website).

## Install

```sh
npm i open-payments-ilp@alpha effect
# only for the /better-auth subpaths:
npm i better-auth
# only for the /hono subpath:
npm i hono
```

Releases are prereleases on the `alpha` dist-tag (`latest` still points at `0.1.0-alpha.0`), so install
`open-payments-ilp@alpha`.

`effect` (`^4.0.0`) is a peer dependency. `better-auth` (`^1.6.19`) is an optional peer dependency used by
`open-payments-ilp/better-auth`, `/better-auth/client` and `/plain/better-auth` only, `hono` (`^4.7.11`) by `open-payments-ilp/hono` only. The package is ESM only and ships TypeScript declarations.

## Runtime support

Only Web Standards are used: `fetch`, `Request`/`Response`/`Headers`, `URL`, `TextEncoder`, and WebCrypto
(`crypto.subtle`, `crypto.getRandomValues`). There are no Node-specific APIs, so the code runs on Cloudflare Workers,
Deno, Bun, browsers, and Node.

HTTP signatures need **Ed25519 in WebCrypto**. In Node it is stable since 20.19.3, 22.13.0 and 23.5.0 (experimental
before that); Workers, Deno, Bun and current browsers support it. CI runs the test suite on Node 24; older Node versions
are untested. `engines` is not set because the requirement is a runtime feature, not a Node version.

## Design

- **Effect-native.** Anything that does I/O, WebCrypto, or needs a clock returns an `Effect`; run it with
  `Effect.runPromise` or compose it into your own program. The framework adapters (`/better-auth`, `/hono`) are the
  exception: they speak the Promises of their framework. If you do not want to write Effect, the
  [`/plain/*` entry points](#plain-promises-and-exceptions-open-payments-ilpplain) wrap the same code in Promises and exceptions.
- **`Result` for synchronous codecs.** Parsers and serializers (`/ilp`, `/ildcp`, STREAM packets, amounts, JCS) are pure and
  return `Result<A, E>` from `effect/Result`; they never throw on bad input.
- **`bigint` amounts.** ILP amounts and STREAM counters are `bigint`. Open Payments amounts keep their wire form
  (`value` as a digit string) and are converted with the helpers in `/open-payments`.
- **Tagged errors.** Each subpath fails with its own tagged error, discriminated by a `reason` that is always
  kebab-case (`non-canonical`, `invalid-key`, `unknown-key`, ...): `/ilp` and `/ildcp` with `IlpCodecError` (and `/ilp`'s `postPrepare` with `IlpHttpError`), `/stream`
  with `StreamError | IlpCodecError`, `/http-signatures` with `HttpSignatureError`, `/open-payments` with
  `OpenPaymentsError`, `/gnap` with `GnapClientFieldError` (an unusable `client` field only), `/webhooks` with
  `WebhookError`. `/gnap/server` fails with `GnapRouteError` (the HTTP `status` and GNAP `code` of a failed exchange, no
  `reason`; its default client-key lookup, `fetchClientKeys`, fails with `HttpSignatureError`), `/hono` throws `GnapAuthError` (untagged, `status` and `code`), and `/better-auth` throws Better Auth's
  `APIError` from its consent endpoints (the GNAP protocol routes answer with GNAP error bodies). Protocol strings (GNAP error `code`s, ILP error codes) are wire values and keep the protocol's spelling.
- **Explicit time.** Anything that reads the current time takes `clock?: () => Date` (default `new Date()`):
  `verifyRequest`, `signWebhook`, `verifyWebhookSignature`, `isValidWebhookSignature`, `fetchIldcp`, the Open Payments clients (the
  `created` of their signatures), `createGnapServer`, the `/better-auth` plugin and `/hono`. Pure codecs and helpers take
  the value itself: `expiresAt`, `serveIldcp({ now })`, `currentAccessIntervalStart(anchor, interval, now)` and
  `SignOptions.created` (the last two default to the current time).
- **Tree-shakeable.** `sideEffects: false`; each subpath is its own entry point.

## Plain Promises and exceptions: `open-payments-ilp/plain/*`

**`effect` is still a required peer dependency**: these entry points run the Effect code internally, so only your own
code is free of Effect. npm 7+, pnpm and Bun install required peers on their own, so `npm i open-payments-ilp@alpha` is enough
there; install `effect` yourself on tooling that does not (npm 6, `legacy-peer-deps`).

Every subpath that returns `Effect` or `Result` has a plain counterpart (except the OER primitives `OerReader`,
`OerWriter`, `readOer` and `writeOer` of `/ilp`, which stay `Result`-based) with the same behaviour and no Effect types in
your code, shaped after `ilp-packet`, `ilp-protocol-ildcp`, `@interledger/http-signature-utils` and
`@interledger/open-payments`:

| Plain entry                        | Counterpart                          | What changes                                                                                   |
| ---------------------------------- | ------------------------------------ | ---------------------------------------------------------------------------------------------- |
| `/plain/ilp`, `/plain/ildcp`       | `/ilp`, `/ildcp`                     | Codecs return the value or throw `IlpCodecError`; `postPrepare` returns a `Promise`.            |
| `/plain/stream`                    | `/stream`                            | Crypto and receiver return `Promise`; `accept()` / `temporaryDecline()` / `finalDecline()` too. |
| `/plain/http-signatures`           | `/http-signatures`                   | `Promise`s; `resolveKey` is a plain (async) function; `importPrivateKey` takes key, JWK or PEM. |
| `/plain/open-payments`             | `/open-payments`                     | `await createAuthenticatedClient(...)`; every route returns a `Promise`.                        |
| `/plain/webhooks`                  | `/webhooks`                          | Sign and verify return `Promise`s; `canonicalizeJson` throws `WebhookError`.                    |
| `/plain/gnap`                      | `/gnap`                              | Digest helpers return `Promise`s; client-field parsers throw `GnapClientFieldError`.            |
| `/plain/gnap/server`               | `/gnap/server`                       | `GnapStore` and every hook (`tenants`, `resolveClientKeys`, `authorize`, `onError`, ...) may be `async`; handlers return `Promise`s. |
| `/plain/gnap/server/testing`       | `/gnap/server/testing`               | `storeContract` for a Promise `GnapStore`.                                                      |
| `/plain/better-auth`               | `/better-auth`                       | `gnap({ ...async hooks })` and a Promise `betterAuthGnapStore`.                                 |

`/hono` and `/better-auth/client` never used Effect in their API, so they have no plain entry. The pure helpers that never
returned `Effect` or `Result` (wire types, `/gnap` access helpers) are re-exported unchanged; the `/open-payments` amount
helpers, which return `Result` in the main entry, return their value or throw in `/plain/open-payments`. `revokeUserGrants` (`/better-auth`)
has no plain entry: import it from the main entry, it already returns a `Promise`.

- I/O and WebCrypto functions return a `Promise` that rejects with the tagged error (`HttpSignatureError`,
  `OpenPaymentsError`, `IlpHttpError`, ...).
- Codecs return the value and throw `IlpCodecError`; there is no `Result`.
- Clients are created with `await`. `privateKey` is a `CryptoKey`, a private JWK or a PKCS#8 PEM string; nothing reads a
  file.
- `verifyRequest(request, { resolveKey })` takes a plain, possibly async, function that returns the JWK, or
  `null`/`undefined` for an unknown key (`unknown-key`). A thrown `HttpSignatureError` passes through as it is; any other
  throw is a defect and rejects with that error.
- `ilp-packet` spellings (`serializeIlpPrepare`, `deserializeIlpReply`, ...) are exported next to the short names.
  Amounts stay `bigint`, bytes stay `Uint8Array` and expiries stay `Date`, so this is the same API shape, not a byte-for-byte
  drop-in.

```ts
import { deserializeIlpPrepare, serializeIlpPrepare } from "open-payments-ilp/plain/ilp";

const wire = serializeIlpPrepare({
  amount: 100n,
  expiresAt: new Date("2030-01-01T00:00:00.000Z"),
  executionCondition: new Uint8Array(32),
  destination: "g.alice",
  data: new Uint8Array(0),
});
const prepare = deserializeIlpPrepare(wire); // throws IlpCodecError on malformed bytes
```

```ts
import { createAuthenticatedClient } from "open-payments-ilp/plain/open-payments";

const client = await createAuthenticatedClient({
  walletAddressUrl: "https://wallet.example/alice",
  keyId: "my-key",
  privateKey, // CryptoKey, private JWK or PKCS#8 PEM string
});
const incomingPayment = await client.incomingPayment.create(
  { url: "https://wallet.example/rs", accessToken },
  { walletAddress: "https://wallet.example/alice" },
);
```

The plain entry points are a layer over the Effect implementation, so `effect` is still a required peer dependency and
the thrown errors are the same tagged `Error` classes. A Promise `GnapStore` method that rejects is a defect, as an
Effect store that dies: the request is answered `500` and `onError` receives the original error.

## Subpaths

### `open-payments-ilp/ilp`

RFC 27 packets (Prepare, Fulfill, Reject: `serializePrepare` / `deserializePrepare`, `serializeFulfill` / `deserializeFulfill`,
`serializeReject` / `deserializeReject`, `serializeReply` / `deserializeReply` for a Fulfill or a Reject, `deserializePacket` for any packet,
the guards `isFulfill` and `isReject`, `IlpPacketType`, `IlpErrorCode` and `MAX_ILP_DATA_LENGTH`, 32767; the codecs fail with `IlpCodecError`), the OER subset of RFC 30 (`OerReader`, `OerWriter`, `readOer`,
`writeOer`), ILP addresses (`isValidIlpAddress`), fulfillment/condition helpers (`conditionFromFulfillment`, and
`fulfillmentMatchesCondition`, which compares in constant time), and a synchronous ILP-over-HTTP client for the peer-to-peer profile of RFC 35 (the reply is the response body; the
asynchronous `Request-Id` / `Callback-Url` mode is not implemented). `postPrepare` checks `timeoutMs` (finite, from 0 to 2^31-1
ms; `0` disables the timeout), `maxReplyBytes` (finite, above 0) and `token` (no control characters, nothing above Latin-1); a bad value is `invalid-option` and nothing is sent. A Reject `message` over 8191 bytes cannot be serialized.

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

`postPrepare` POSTs a serialized Prepare to a peer and resolves with the reply bytes (a Fulfill or a Reject; parse them with `deserializeReply`). `token` is sent as `Authorization: Bearer <token>` and `fetch` replaces the global one. It fails with `IlpHttpError` (`reason`: `status` for a `4xx` or `5xx` answer, `too-large`, `timeout`, `network`, which also covers a redirect, as redirects are not followed, and `invalid-option`); the reply is capped (`maxReplyBytes`, default 64 KiB, `DEFAULT_ILP_HTTP_MAX_REPLY_BYTES`) and `timeoutMs` defaults to 30 s (`DEFAULT_ILP_HTTP_TIMEOUT_MS`).

```ts
import * as Effect from "effect/Effect";
import { deserializeReply, postPrepare } from "open-payments-ilp/ilp";

const reply = await Effect.runPromise(postPrepare(wire.success, { url: "https://peer.example/ilp", token }));
const packet = deserializeReply(reply);
```

### `open-payments-ilp/ildcp`

IL-DCP request/response codecs (`serializeIldcpRequest`, `deserializeIldcpRequest`, `serializeIldcpResponse`, `deserializeIldcpResponse`; the request goes to `ILDCP_DESTINATION`, `peer.config`), `serveIldcp`, which answers a request with a Fulfill or an `F00` Reject (it never fails: an invalid, foreign or expired request, or a `response` that cannot be encoded, is an `F00` too, and so is an Invalid Date `now`), and `fetchIldcp(sendData, { clock, ttlMs })`, which asks an upstream connector for this node's address and asset through your `sendData` function (`ttlMs`, how long the request stays valid, defaults to 30 000 ms).

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

RFC 29 STREAM: packet and frame codecs (`encodeStreamPacket` / `decodeStreamPacket`, `encodeStreamFrame` / `decodeStreamFrame`,
`StreamFrameType`, `StreamErrorCode`), AES-256-GCM packet encryption (`encryptStreamData` / `decryptStreamData`, with
`STREAM_ENCRYPTION_OVERHEAD` of 28 bytes, `deriveStreamKeys`, `generateStreamFulfillment` / `generateStreamCondition`), SPSP-style
credentials (`generateStreamCredentials`; no stored state: the connection is re-derived from the destination address), a receiver
(`createStreamReply`) and sender helpers (`planStreamChunks`, `buildStreamPrepare`); crypto, credentials, receipts and reply reading fail with `StreamError`, the codecs with `IlpCodecError`. `generateStreamCredentials(server, options)`
takes `asset` (announced to senders in a `ConnectionAssetDetails` frame), `paymentTag` (ASCII, returned with every accepted packet) and
`receipt` (`{ nonce, secret }` of 16 and 32 bytes, which enables RFC 39 receipts). `buildStreamPrepare` takes
`minDestinationAmount` (default `amount`), `additionalData` (an application payload, sent as a `StreamData` frame on stream 1) and
`unfulfillable` (a rate probe: the receiver answers `F05` with the amount it received); `decryptStreamPacket` reads
replies (pass `{ expect: { sequence, ilpPacketType } }` to refuse a reply that does not belong to its request: a connector
can replay an older encrypted reply, `unexpected-packet`), `decodeStreamReceipt` / `verifyStreamReceipt` handle RFC 39 receipts
(the `secret` lookup may be async), and `decodeStreamPaymentTag` reads the
payment tag from a destination address. `sourceAddress` of `buildStreamPrepare` may be left out: the Prepare of sequence 1 then carries
the empty `ConnectionNewAddress` that `@interledger/pay` sends for asset probes (later sequences carry none). `connectionId` of a pending reply is the
hash of the whole destination address, so trailing segments or another spelling of the token give another id: do not key
per-connection state on it without normalising. Imported keys, server-secret derivations and authenticated connection tokens are
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

RFC 9421 Ed25519 signatures as profiled by Open Payments and GNAP, RFC 9530 `Content-Digest` (`createContentDigest`,
`verifyContentDigest`: sha-256 and sha-512), and a strict RFC 8941 structured-field parser (`parseDictionary`, `serializeItem`,
`serializeInnerList`; `createSignatureBase` and `serializeSignatureParams` build the RFC 9421 pieces). `signRequest(request, { keyId, privateKey }, options)` covers
`@method`, `@target-uri`, `authorization` (when present) and, with a body, `content-digest`, `content-length` and `content-type`
(when present); `options` are `created` (default: now), `tag`, `nonce` and `digest` (`"sha-512"` by default, as the Open Payments
client does, or `"sha-256"`). `verifyRequest` calls `resolveKey` only after every structural check has passed, and reads
the time from its `clock` option (default `new Date()`); its other options are `requiredComponents` (default `@method` and
`@target-uri`), `maxAgeSeconds` (default 300), `label` (default `sig1`), `requireBodyDigest` (default `true`: a non-empty body must be
covered by a matching `Content-Digest`) and `forbidAlg` (default `false`: refuse an explicit `alg` parameter, as RFC 9635 §7.3.1 does for GNAP).
`HttpSignatureError` has an optional `cause`: what actually went wrong underneath a `resolveKey` failure.
`importEd25519PrivateKeyPem` imports a PKCS#8 PEM, `importEd25519PrivateJwk` a private JWK and `importEd25519PublicJwk` a public one;
`exportPublicJwk(key, { keyId })` returns the publishable
Open Payments JWK (`kid`, `alg: "EdDSA"`, `kty`, `crv`, `x`) of a public key or of an extractable private key (from `generateEd25519KeyPair`): the two
private imports are not extractable, so it fails with `malformed` on them, and the JWK of a PEM key has to come from elsewhere. A server that enforces once-only `nonce`s must remember
each one for `SIGNATURE_REPLAY_WINDOW_SECONDS` (331 s, exported), the longest a signature can still verify with the
default `maxAgeSeconds`; `VerifiedSignature.replayWindowSeconds` is the window of the options actually used. The body is
read, capped at `maxBodyBytes` (64 KiB by default), only when a `content-digest` is covered (otherwise it is not read beyond finding out whether it is empty). A verifier option that is not
a finite number of at least 0 (`maxAgeSeconds`, `maxBodyBytes`), or a clock that returns an Invalid Date, fails with reason `invalid-config`.

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

Wire types generated from the Open Payments OpenAPI documents, amount helpers (`parseAmountValue`, `isAmountValue`,
`isPositiveAmountValue`, `isSameAsset`, `compareAmounts`, `addAmounts`, `normalizeAmount`, with the limits `UINT64_MAX` and
`UINT128_MAX`), the grant guards `isPendingGrant`, `isFinalizedGrantWithAccessToken` and `isFinalizedGrantWithSubject`, the access
values `AccessType` and `AccessAction`, and `createAuthenticatedClient` / `createUnauthenticatedClient`. The authenticated client has the routes
`walletAddress` (`get`, `getKeys`, `getDIDDocument`), `incomingPayment` (`get`, `getPublic`, `create`, `complete`, `list`),
`outgoingPayment` (`get`, `list`, `create`, `getGrantSpentAmounts`), `quote` (`get`, `create`), `grant` (`request`, `continue`,
`cancel`) and `token` (`rotate`, `revoke`); the unauthenticated one only `walletAddress` and `incomingPayment.get`. A route fails with
`OpenPaymentsError` (`reason`: `http` for a `4xx` or `5xx` answer, with its `status`, `code` and `description`; `validation`;
`transport`; `invalid-request`; `signing`), the amount helpers with `invalid-amount`. Pass your own `fetch` to test or to run behind a proxy. Options: `validateResponses`
(default `true`; bodies are validated and returned unchanged), `requestTimeoutMs` (default 5000), `clock` (the time of the
signatures' `created`, default `new Date()`) and `maxResponseBytes`
(default 1 MiB; a longer response, announced or streamed, is a `transport` error). Every request URL must be `https:` (`useHttp: true`,
for tests and local servers, sends them over `http:`), without credentials or fragment; a URL that parses but breaks these rules, or that
`urlPolicy: (url) => boolean` refuses, fails with `invalid-request` before anything is sent, and one that does not parse is a `transport` error. A redirect is never followed
(`transport`). Retries are opt-in: `retry: { maxAttempts,
baseDelayMs, maxDelayMs, jitter, retryOn, retryNonIdempotent, sleep, random }` (`maxAttempts` counts the first attempt and is required;
`baseDelayMs` defaults to 200, `maxDelayMs` to 5000 and `jitter` to `"full"`) retries network errors, timeouts and
`408`/`429`/`502`/`503`/`504` of `GET`/`HEAD`/`PUT`/`DELETE` with exponential backoff and jitter, honours `Retry-After`
of `429` and `503` (a longer wait than `maxDelayMs` ends the retries) and signs every attempt again with a fresh `created` and `nonce`. A `POST` or `PATCH` may already have been
processed, so it is repeated only with `retryNonIdempotent: true` (client-wide or per request); `token.rotate` and
`grant.continue` use up what they were given and are repeated only with the per-request flag. The last error carries
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

GNAP (RFC 9635) types as profiled by Open Payments, access-item matching and limit checks (`compareRequestAndGrantAccessItems`,
`validateOutgoingPaymentAmounts`, `validateOutgoingPaymentReceiver`, `parseAccessIntervalMs`, `currentAccessIntervalStart`), error bodies
(`gnapErrorBody(code, description)` returns Rafiki's `{ error: { code, description } }`), token helpers (`extractGnapToken`,
`formatGnapAuthorization`, `hashToken`), the `client` field parsers (`parseClientField`, `getGrantClientIdentity`, `toTokenInfoClient`:
they fail with `GnapClientFieldError`), the grant guards `isPendingGrant`, `isFinalizedGrantWithAccessToken` and `isFinalizedGrantWithSubject`,
the access values `AccessType` and `AccessAction`, and the interaction finish `hash` (`computeInteractionHash`, `verifyInteractionHash`,
`buildFinishUrl`, `buildRejectedFinishUrl`).

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

Beyond `baseUrl` and `store`, the options are `tenants`, `interaction` (`consentUrl`, `expiresInSeconds`, `authorize`), `idpSecret`, `introspection`
(`authorize`), `policy` (`requiresInteraction`), `resolveClientKeys`, `fetch`, `finishHashEncoding`, `maxBodyBytes`, `onError`, and these, which have defaults:
`accessTokenExpiresInSeconds` (lifetime of issued access tokens, 600), `waitSeconds` (`continue.wait`, default and minimum 5), `interaction.expiresInSeconds` (lifetime of an
interaction, 600), `generateToken` (a secret generator, default 256 random bits as base64url) and `clock` (default `new Date()`).
`interaction.consentUrl` is a string, to which the server adds Rafiki's query parameters, or a function that builds the URL from them
(`interactId`, `nonce`, `clientName`, the host name of the wallet address, and `clientUri`, the wallet address itself).
`createGnapServer` throws a `RangeError` for a `baseUrl` that is not an absolute `http(s)` URL without credentials, query or fragment, a
`maxBodyBytes` or `waitSeconds` that is not a finite number of at least 0, an `accessTokenExpiresInSeconds` or `interaction.expiresInSeconds`
that is not a finite number above 0, and a `finishHashEncoding` other than `"base64"` and `"base64url"`; a `clock` that returns an Invalid Date
makes the request fail with `500`. Only `false` from `policy.requiresInteraction` skips the owner: any other answer
(`undefined`, a Promise) needs consent.

Routes below the path of `baseUrl` (Rafiki's layout): `POST /` grant request, `POST|DELETE /continue/:id` (and `PATCH`, see **Extended records**),
`POST|DELETE /token/:id`, `GET /interact/:id/:nonce` and `…/finish`, the identity provider API `GET /grant/:id/:nonce`
and `POST /grant/:id/:nonce/accept|reject` (`x-idp-secret`, only with `idpSecret`, or per tenant), and `POST /introspect` (only with
`introspection.authorize`). `handlers` has each one separately. `getInteraction({ interactId, nonce })` returns what a
consent page shows (the interaction `details`) and `decideInteraction({ interactId, nonce, choice, userId?, binding? })` records the
owner's decision, both for a consent page that authenticates the owner itself; `decideInteraction` returns `{ redirect }`, the `/finish`
URL to send the browser to. `introspectToken(accessToken, access?)` is the in-process introspection (not tenant-scoped; an active answer also
carries the grant's `tenantId` and `grantAccess`). The wire
behaviour is Rafiki's: subjects, `outgoing-payment` and `list-all` access need interaction (`policy.requiresInteraction`
replaces that; the default is exported as `defaultRequiresInteraction`), the finish `hash` is padded base64 (`finishHashEncoding: "base64url"` for RFC 9635), accepting or
rejecting only records the decision and the grant is approved (or rejected) when the browser reaches `/finish`, the
continue token is not rotated, a grant without interaction is `APPROVED` (so polling it issues a token), introspection
without `access` reports none, and requests over 64 KiB (`maxBodyBytes`) get `413`.

RFC 9635 / 9767 requirements that Open Payments clients never notice are enforced too: `Cache-Control: no-store` on
every response, `application/json` request bodies, a required `interact.start`, `finish.uri` without fragment and a
non-empty `finish.nonce`, `finish.hash_method` (`sha-256|384|512`), `access_token.label` echoed and `flags` checked
(`invalid_flag`), at most 3 access items per token (and 10 tokens in an `access_token` array) and exactly one `sub_ids` entry, `wait` of at least 5 seconds (`waitSeconds`), the
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
value is the interaction nonce (it ties the browser to the URL, but anyone who knows the nonce can set it; Rafiki's is a signed session), so a store with `interactionBinding` also binds the interaction to the first browser that opens it (see **Interaction binding**); finishing a finalized grant redirects again without reopening it. Not in this server:
wallet address document resolution (keys come from `{walletAddress}/jwks.json`), and Rafiki's separate
introspection port (`/introspect` is served on the same mount, off unless `introspection.authorize` is set; the hook answers
`false` to refuse a caller, `true` to let it ask about any token, or `{ tenantId }` to scope it: tokens of other tenants are `{ active: false }`; any other answer is refused).

**Observing failures.** The server logs nothing: causes can embed SQL parameters. `onError(cause)` is called with the
`Cause` of every `500` the route answers: a defect (a store outage, a throwing callback, a bug) or the server's own `500`
(three lost optimistic-lock attempts, a grant without a consent URL), whose cause is a `GnapRouteError`; it never sees
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
over two plain JSON-serialisable records (plus the nonce claims), `GrantRecord` and `TokenRecord`, and two optional capability flags:

```ts
interface GnapStore {
  createGrant(grant: GrantRecord): Effect<void>; // `id`, `continueId`, `interactId` unique
  findGrant(by: "id" | "continueId" | "interactId", value: string): Effect<GrantRecord | null>;
  /** Compare-and-set: applies `patch`, increments `version`, and returns true only if `version` still matched. */
  updateGrant(id: string, version: number, patch: GrantPatch): Effect<boolean>;
  createToken(token: TokenRecord): Effect<void>; // `id`, `valueHash`, `managementId` unique
  /** A token (revoked or expired too) with its grant: one lookup, as the server needs both. */
  findTokenWithGrant(
    by: "valueHash" | "managementId",
    value: string,
  ): Effect<{ token: TokenRecord; grant: GrantRecord } | null>;
  /** Sets `revokedAt` on the unrevoked tokens of a token or a grant; returns how many it changed. Atomic. */
  revokeTokens(by: "id" | "grantId", value: string, at: number): Effect<number>;
  /** Replay guard for signature nonces: claims `key` until `expiresAt` unless an unexpired claim exists. Atomic. */
  claimNonce(key: string, expiresAt: number, now: number): Effect<boolean>;
  /** Set to `true` by a store that persists every optional field of the two records (see **Extended records**). */
  extendedRecords?: true;
  /** Set to `true` by a store that persists `GrantRecord.interactBinding` (see **Interaction binding**). */
  interactionBinding?: true;
}
```

Times are epoch milliseconds, token values are stored as SHA-256 hashes only, and every multi-step change is ordered so
that no transaction is needed. `memoryGnapStore()` is the in-process implementation. A new store is verified with the
contract kit, `storeContract({ describe, it }, name, makeStore, options?)` from `open-payments-ilp/gnap/server/testing`. It is
framework-neutral: pass the `describe` and `it` of your runner (Vitest, `bun:test`, `node:test`). It checks round trips,
uniqueness, the compare-and-set race, nonce claims and the revoke semantics (and the optional fields of a store that sets
`extendedRecords` or `interactionBinding`), and the memory store and the Better Auth
store both run it. `options.userId` is a user id the store accepts when it enforces a foreign key to a users table (default `"user-1"`),
and `uniqueConstraints: false` skips the insert races for a store that does not enforce unique columns:

```ts
import { describe, it } from "vitest";
import { storeContract } from "open-payments-ilp/gnap/server/testing";

storeContract({ describe, it }, "my database", async () => createMyStore(await freshDatabase()));
```

**Interaction binding.** The nonce in `/interact/:id/:nonce` and in the consent URL is not a secret, so the cookie Rafiki
sets (whose value is that nonce) cannot tell which browser opened the interaction. A store that persists
`GrantRecord.interactBinding` and sets `interactionBinding: true` (`memoryGnapStore()` and `betterAuthGnapStore()` do; the
contract kit checks it) gets a stronger check: the first visit to `/interact/:id/:nonce` receives a random secret in the
`gnap-binding-<interactId>` cookie (HttpOnly, `SameSite=Lax`, `Secure` under an `https` `baseUrl`, scoped to the server's base path) and only its hash is stored;
a later visit by another browser gets none. `/finish` is refused (`401`) to a browser without that cookie, and
`decideInteraction` with a `userId` is refused (`403`) without `binding` (`bindingFromRequest(request, interactId)`, also
exported by `/plain/gnap/server`; checked again when the decision is stored) once an
interaction is bound, so a user who opens the consent URL in another browser cannot approve a grant that browser's owner
then collects. A replaced interaction (`PATCH`) starts unbound. The first visitor is the one that is bound, so a link scanner or prefetcher that opens the URL before the user locks the user out of `/finish`: the client has to start a new grant. Not covered: the `x-idp-secret` back channel and
`decideInteraction` without `userId`, where your consent page vouches for the browser; and a store without the flag keeps
Rafiki's nonce-cookie check.

**Extended records.** Grant modification (`PATCH /continue/:id`), `access_token` arrays and `finish.method: "push"` need
a store that keeps the optional fields `GrantRecord.finishMethod` / `tokenRequests` and `TokenRecord.access` / `label`.
`memoryGnapStore()` does; a custom store opts in with `extendedRecords: true` once it persists them (the contract kit then
checks them). Without the flag the server answers these three requests `501 invalid_request` and everything else is
unchanged. The server's `fetch` also delivers the push, and `onError` receives a failed push.

**Tenants.** Pass `tenants: (tenantId) => Effect<TenantConfig | null>` (`TenantConfig`: `consentUrl?`, `idpSecret?`) for
Rafiki v2 multi-tenancy: grants are requested at `POST {baseUrl}/{tenantId}` (unknown tenant `404` after the signature
check), the consent URL and identity-provider secret are per tenant, and the finish `hash` covers the tenant segment.
A tenant named `introspect` is unreachable: the fixed `POST /introspect` route wins.
Without `tenants`, `interaction.consentUrl` is required to serve any grant that needs interaction, and the route is `POST {baseUrl}`. A store keeps
`GrantRecord.tenantId` (nullable). `limits.interval` accepts ISO 8601 repeating intervals (`R12/2030-01-01T00:00:00Z/P1M`,
as Rafiki); a plain duration such as `P1M` is kept as an extension. For a D1/Postgres store, the `GnapStore` JSDoc
carries the SQL DDL for the tables and the conditional `UPDATE` recipes for compare-and-set.

### `open-payments-ilp/webhooks`

Rafiki-compatible webhook signatures (HMAC-SHA256 over `<t>.<canonical JSON>`, `t` in Unix milliseconds; `signWebhook`
returns the `Rafiki-Signature` header value `t=<ms>, v1=<hex>`), RFC 8785 canonicalisation (`canonicalizeJson`, a `Result`), and event
types generated from Rafiki's webhooks OpenAPI document; every failure is a `WebhookError`. The default signature version is `v1`, as in Rafiki (`version` in the config);
verification enforces a 5-minute replay window (`maxAgeMs`) and 30 s future skew (`futureSkewMs`), each a finite number of at least 0
or `invalid-config`. `signWebhook`, `verifyWebhookSignature` and
`isValidWebhookSignature` read the time from the `clock` option of their config (default `new Date()`; an Invalid Date is `invalid-config`).

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

Run the Better Auth CLI migration to create the three tables (`gnapGrant` with a nullable `tenantId` and a nullable
`interactBinding`, `gnapAccessToken` and `gnapNonce`; unique indexes on the lookup columns). A database created by an
earlier alpha needs the migration for the new `interactBinding` column before the plugin runs. Deleting a user deletes the
grants they approved and their tokens (`gnapGrant.userId` cascades; a database created by an earlier alpha keeps its old `SET NULL` constraint until you alter that foreign key); a `databaseHooks.user.delete.before` hook of the
plugin also revokes them on adapters that do not cascade (`revokeUserGrants` is exported). `gnapNonce` gets a row for each signed request that carries a
`nonce` (the `/hono` middleware always sends one, the Open Payments client only with its `retry` option); `betterAuthGnapStore` deletes the rows whose `expiresAt` has passed itself, at most once a minute per database. It needs `deleteMany` on the adapter for that (every Better Auth adapter has it; a `GnapDb` without it just skips the cleanup).
Endpoints live under the Better Auth base path (`/api/auth` by default) and delegate to
[`open-payments-ilp/gnap/server`](#open-payments-ilpgnapserver) with a Better Auth `GnapStore`:

| Endpoint                                                                   | Purpose                                                                               |
| -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `POST /gnap`                                                               | Grant request (HTTP-signed by the client)                                             |
| `POST` / `DELETE /gnap/continue/:id`                                       | Continue / cancel a grant                                                             |
| `POST` / `DELETE /gnap/token/:id`                                          | Rotate / revoke an access token                                                       |
| `GET /gnap/interact/:id/:nonce`, `…/finish`                                | Start interaction (redirects to `consentUrl`) / finish                                |
| `GET /gnap/interaction/:id/:nonce`, `POST …/accept`, `…/reject`            | Consent API for the signed-in resource owner (authoritative session, no cookie cache) |
| `GET /gnap/grant/:id/:nonce`, `POST …/accept`, `…/reject` (`x-idp-secret`) | Rafiki's identity provider API; only with `idpSecret` or `tenants`                    |
| `POST /gnap/introspect`                                                    | Token introspection for resource servers (opt-in)                                     |

The options of `gnap()` are those of `createGnapServer` without `baseUrl` and `store`: `tenants`, `interaction` (`consentUrl`,
`expiresInSeconds`, `authorize`), `idpSecret`, `introspection` (`authorize`), `policy` (`requiresInteraction`),
`waitSeconds`, `accessTokenExpiresInSeconds`, `resolveClientKeys`, `finishHashEncoding` (`"base64"` default, as Rafiki
sends it; `"base64url"` is the RFC 9635 encoding), `maxBodyBytes`, `fetch`, `clock`, `onError` (as for the core, it
sees the failures of the GNAP routes, not those of the consent endpoints) and `generateToken`, plus `rateLimit`
(`{ grantRequest?: { window, max }, continue?: { window, max } }`, `window` in seconds, or `false` for none). Grant requests
(20 a minute) and continue requests (30 a minute) by default are limited per client IP and per URL while Better Auth's
rate limiter is on (by default in production). Without a client IP Better Auth uses one shared bucket per path, so set
`advanced.ipAddress` (and `trustedProxies`) for a deployment behind a proxy: Better Auth keys the bucket by IP and path, so continue requests are
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

**Consent.** The consent endpoints (the `GET` that shows the grant as well as accept and reject) work for the signed-in user,
which proves nothing about who owns the wallet address
a grant names (sign-up is open in the example). They answer `403` until you set `interaction.authorize`: it receives the
`userId` and the grant's `details` and must answer `true` only if that user owns every wallet address the grant names,
in `details.access` and in `details.subject` (a grant may carry only a subject, with no access items). The consent page
has to reach these endpoints with the session cookie: serve it from the same site
as the auth server (a shared parent domain with cross-subdomain cookies), or set up Better Auth's `trustedOrigins`, CORS
and cookie attributes for the cross-site case.

Accept and reject also need the browser to be the one that opened `interact.redirect`: that visit sets the `gnap-binding-<interactId>`
cookie (HttpOnly, scoped to the plugin's endpoints, `/api/auth/gnap` by default), and a user who opens the consent URL in another browser gets
`403`. `/finish` needs the same cookie. With your own consent endpoint around `decideInteraction`, pass
`binding: bindingFromRequest(request, interactId)` from `open-payments-ilp/gnap/server`. The consent API answers with the `GNAP_ERROR_CODES`
(`unknown_interaction`, `invalid_interaction`, `user_denied`, `request_denied`), which the plugin also exposes as its `$ERROR_CODES`; `gnapSchema` is
the schema it registers.

### `open-payments-ilp/better-auth/client`

The client plugin for your consent page: `authClient.gnap.getInteraction(interactId, nonce)`,
`acceptInteraction(interactId, nonce)` and `rejectInteraction(interactId, nonce)` (both values are on the consent URL
your server sends the owner to). `getInteraction` resolves to `{ data: details }` (`grantId`, `client`, `access`, `subject?`, `state`, `finish`,
`expiresAt`). Accept and reject resolve to `{ data: { redirect } }`: navigate the browser to `redirect`,
the server's `/finish` step, which approves (or rejects) the grant and sends the browser back to the client. A refused call
(`403` when `interaction.authorize` does not allow the user) does not throw: it resolves to `{ data: null, error: { status, statusText, code?, message? } }`.

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

1. No session: a `GET` navigation (`Sec-Fetch-Mode: navigate`, or no `Sec-Fetch-Mode` and `Accept: text/html`; never a
   prefetch, `Sec-Purpose` or `Purpose: prefetch`) makes the middleware POST a signed grant
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
   first (`202` with `Retry-After` when the server offered no `interact.redirect`), `401` for a denial, the request goes through once approved.
2. The callback checks the state cookie, rejects a failed interaction (`result=…`, Rafiki's convention), verifies the
   `hash` of the finish redirect, waits out `continue.wait` (five seconds when absent), continues the grant (`POST`
   with the one-time `interact_ref`) and, while the server says pending, waits its `wait` and polls without
   `interact_ref` up to three times (then `504`), then stores the session. An RFC 9635 server reports a denial through the
   same finish redirect and answers the continue call with `user_denied` (or `request_denied`): `401`, like Rafiki's
   `result=grant_rejected`. A bearer token that comes with a key and an `access_token` array are refused. An access token already past its
   `expires_in` is accepted at the callback and rotated on the next request, or the session ends when it cannot be.
3. The session is an AES-256-GCM encrypted value (key derived from `secret` with HKDF; an HS256 JWT with `encryptCookies: false`) in an httpOnly, Secure, `SameSite=Lax` cookie: the access token, its `manage` and
   `continue` credentials, the granted `access` and its times (`expiresAt`, the next rotation, the end of the session). After the refresh interval (or when the token is about to expire) the
   access token is rotated through its management URI and the cookie re-issued; when the session lifetime is over it is
   revoked and a new grant is requested. A rotation that fails because the server is unavailable (`408`, `429`, `5xx`,
   network, timeout) or because a parallel request rotated first (`401`, `404`) keeps the cookie and serves that request
   without a session; only another refusal (`400`, `403`, …) drops the cookie and calls the refresh error hook.

**Open Payments / Rafiki.** The client is a wallet address; the grant endpoint is the `authServer` of that wallet
address document (pass a function to look it up). `privateKey` is the text of an unencrypted PKCS #8 PEM
(`openssl genpkey -algorithm ed25519`).

```ts
import { Hono } from "hono";
import { getGnapAuth, gnapAuthMiddleware, initGnapAuthMiddleware, revokeGnapSession } from "open-payments-ilp/hono";

const app = new Hono();

app.use(
  "*",
  initGnapAuthMiddleware({
    secret: "a-session-secret-of-at-least-32-characters",
    externalUrl: "https://app.example",
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
    externalUrl: "https://app.example",
    grantEndpoint: "https://as.example/gnap",
    access: [{ type: "outgoing-payment", actions: ["read"], identifier: "https://wallet.example/alice" }],
    keyId: "my-key-1",
    privateJwk,
  }),
);

app.use("*", gnapAuthMiddleware());
```

Everything but `access`, `fetch`, `clock`, `requestTimeoutMs` and `encryptCookies` (default `true`; changing it logs every
user out) can come from environment variables instead; a value in the config (`GnapAuthConfig`) wins over its variable,
except that the private key is resolved as a unit (passing `privateKey` or `privateJwk` ignores both `GNAP_PRIVATE_KEY`
and `GNAP_PRIVATE_JWK`, and `privateJwk` wins over `privateKey`): `GNAP_AUTH_SECRET` (`secret`; random, at least 32 characters: never this README's placeholders),
`GNAP_GRANT_ENDPOINT` (`grantEndpoint`), `GNAP_KEY_ID` (`keyId`), `GNAP_PRIVATE_KEY` (`privateKey`, PEM), `GNAP_PRIVATE_JWK` (`privateJwk`, JWK as JSON),
`GNAP_CLIENT` (`client`), `GNAP_REDIRECT_URI` (`redirectUri`, default `/callback`), `GNAP_COOKIE_NAME` (`cookieName`, `gnap-auth`; the login-state and
pending-login cookies add `-state` and `-pending`), `GNAP_COOKIE_PATH` (`cookiePath`, `/`),
`GNAP_COOKIE_DOMAIN` (`cookieDomain`), `GNAP_AUTH_REFRESH_INTERVAL` (`refreshInterval`, seconds, 900), `GNAP_AUTH_EXPIRES` (`expires`, seconds, 86400, at most
34 560 000) and `GNAP_AUTH_EXTERNAL_URL` (`externalUrl`, public origin of this app, may carry a path prefix; required on any host that is not
loopback, also with an absolute `redirectUri`, because the post-login URL is built from it). An empty or blank
`GNAP_AUTH_REFRESH_INTERVAL` or `GNAP_AUTH_EXPIRES` counts as unset. `access` and `grantEndpoint` may be
functions of the request context. `fetch`, `clock` and `requestTimeoutMs` (default 10 000 ms: it aborts every call to
the authorisation server and the read of its answer, which is capped at 64 KiB) are set in the config (tests, Workers).
`getGnapAuth(c)` resolves to the session, a `GnapAuth` (`accessToken`, `expiresAt?`, `access`, `manage?`, `continue?`, `rtkexp`, `ssnexp`), or `null`.

What you pass to `initGnapAuthMiddleware` is checked when it is called, not on the first request: a session secret of
fewer than 32 characters, a negative or non-numeric `refreshInterval`, an `expires` that is not positive or exceeds 34 560 000, a
`requestTimeoutMs` that is not a positive finite number, an `externalUrl` that is no URL, a `redirectUri` that is neither
path nor URL (or that is known to be neither HTTPS/`localhost` nor free of a fragment), a `grantEndpoint` or `client`
that is no http(s) URL (a non-loopback `grantEndpoint` must be `https:`), a `__Host-` `cookieName` with a `cookiePath` other than `/` or with a `cookieDomain`, a `privateKey` that does not look like an unencrypted PKCS #8 PEM and a `privateJwk` that is no Ed25519 key shape
(`kty` `OKP`, `crv` `Ed25519`, `x` and `d`) throw an `HTTPException` (`500`) at once (the message names the option, never the key); a key of the right shape that does not import fails with a `500` when the first grant is signed. Values that come from the environment
are checked by the same code on the first request they are seen in (`500`, same messages), as is a relative callback on a public request host without `externalUrl`. The private key is imported once and reused for every grant, rotation and revocation (an
environment key again only when its text changes).

The middleware serves the callback itself when mounted on the `redirectUri` path; behind a path-prefixing proxy mount
`app.get("/callback", processGnapCallback)` yourself. With `externalUrl` the state cookie
is scoped to the public callback path and the callback is matched on its path alone, so a proxy that strips a prefix
works. A failing callback throws an `HTTPException` (`400` for a missing, forged or expired state, a failed
interaction or a missing `interact_ref` or `hash`, `401` for a denied one or a wrong `hash`, `502` for a server that fails the
continue request (its own `401` and `504` pass through, and `504` is also the answer for a grant still pending after the polls), `502` / `503`
for one that fails or cannot be reached when a login starts; the message never repeats free text or URLs that the callback URL carried, only one of the fixed
`result` names `grant_rejected`, `request_denied` and `user_denied`); handle it with `app.onError`. Set a `gnapAuthRefreshErrorHook` with `c.set` to see why a rotation was refused (only a
definitive refusal, see 3 above; it receives a `GnapAuthError` with `status`, `code` and `remote`, whether its `message` quotes the server and so belongs in a log only, runs after the cookie was
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

- The session cookie is AES-256-GCM encrypted by default (key derived from `secret` with HKDF), so the browser stores the
  access, management and continue tokens but cannot read them. With `encryptCookies: false` it is only signed (an HS256
  JWT) and the browser's owner can read them (httpOnly only hides them from scripts). Use a long random `secret`, serve
  over HTTPS (cookies are `Secure`), and give the grant only the access the user's session needs. Protected state
  cookies stop a forged or replayed callback and bind it to the browser that started the grant (RFC 9635 §11.24); `SameSite=Lax` is needed
  for the cross-site redirect back.
- The `hash` is verified in constant time and accepts padded base64 (Rafiki) and unpadded base64url (RFC 9635).
  `hash_method` is not sent, so the default `sha-256` applies; Rafiki rejects nothing else.
- Waits are never cut short (RFC 9635 §3.1, §5): the continuation URI is not called before the `continue.wait` of the
  response that announced it is over (five seconds when the response has no `wait`), so a user who comes back early
  makes the callback sleep the remainder; a wait over 10 s fails the callback with `504` instead of being cut short.
  The `interact_ref` is one-time-use (§5.1): it is sent in the one first continue request, never again, and a
  `too_fast` answer is an error, not a retry.
- `https:` or `localhost` only for the URIs a browser follows (RFC 9635 §2.5.2.1, §4.1.1): the callback URI (also
  without fragment) and `interact.redirect`. A relative `redirectUri` is resolved against `externalUrl`, or against
  the request URL only when that host is loopback and no proxy header (`X-Forwarded-For`, `-Host`, `-Proto`, `Forwarded`) came with it. On any other host set `externalUrl`;
  the request host is neither registered as the finish origin nor used as the post-login URL, and `externalUrl` is needed
  even with an absolute `redirectUri`, because the post-login URL is built from it.
- The grant endpoint must be `https:` (`http:` only on loopback); the `continue` and `manage` URIs too, and all three are
  URLs without userinfo. Redirects are not followed, and an error answer never repeats the server's text or URLs. A
  `continue` or `manage` host other than the grant endpoint is the server's to name (RFC 9635), so serve that server
  over TLS (§11.1).
- The session is stateless: a copy of the signed cookie stays valid until the next rotation check, up to
  `refreshInterval` (900 s by default) after `revokeGnapSession`, so use a small `refreshInterval` for sensitive apps.
  Log out with a `POST` (`SameSite=Lax` sends the cookie on a cross-site `GET` navigation, so a `GET` logout can be
  triggered by any page). `revokeGnapSession` uses the session of the current request, so it can be mounted before or
  after the middleware; it throws when the server refuses the revocation, but the cookie is deleted either way.
- Cookie names may carry the `__Secure-` or `__Host-` prefix (`__Host-` needs path `/` and no domain, and then the login state cookie is scoped to `/` too); the middleware
  deletes a cookie with the attributes it set it with. The login state cookie that does not fit in 4096 bytes keeps the
  return URL without its query string.
- Concurrent requests with the same expired session merge into one rotation per process: a page load that still loses
  the race to another instance is redirected once to the same URL, an API call gets `401`.
- The whole session lives in one cookie: keep `access` small. A session over 4096 bytes fails with a `500` (browsers
  would drop the cookie silently). An interaction URL too long for the pending-login pointer (over 4096 bytes with the
  cookie name) is left out of it: a second tab then requests its own grant, as it would without the pointer.

Differences from `@hono/oidc-auth`: no discovery document (you name the grant endpoint and the access); the signing key
replaces the client secret; the session holds the GNAP access token and its `manage`/`continue` credentials instead of
ID token claims, so there is no claims hook; the cookie is `SameSite=Lax`; state is one sealed cookie (plus the pending-login pointer) instead of
`state`, `nonce`, `code_verifier` and `continue` cookies; refresh and logout call the token management API (`POST` / `DELETE`
the `manage` URI) and cancel the grant (`DELETE` the `continue` URI) instead of OAuth refresh and revocation endpoints.

## Compatibility

How each part behaves against the packages and servers it is compared with (`ilp-packet`, `ilp-protocol-ildcp`, `ilp-protocol-stream`, `@interledger/open-payments`, `@interledger/http-signature-utils`, Rafiki's auth server and webhooks), with every deliberate deviation and the reason, is in [docs/compatibility.md](https://github.com/dayjobdoor/open-payments-ilp/blob/main/docs/compatibility.md).

## Versioning

[Semantic versioning](https://semver.org/). While the major version is `0`, minor releases may contain breaking changes;
see [CHANGELOG.md](CHANGELOG.md).

## License

[Apache-2.0](LICENSE). Generated types derive from Interledger Foundation OpenAPI specifications; see [NOTICE](NOTICE).
