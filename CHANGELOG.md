# Changelog

This project follows [semantic versioning](https://semver.org/). While the major version is `0`, minor
releases may contain breaking changes.

## Unreleased

- `/plain/ilp`, `/plain/ildcp`, `/plain/http-signatures`, `/plain/open-payments`: Promise and exception entry points over the Effect modules, shaped after `ilp-packet`, `ilp-protocol-ildcp` and `@interledger/open-payments` (`await createAuthenticatedClient({ walletAddressUrl, keyId, privateKey })`, `privateKey` as CryptoKey, JWK or PEM). `effect` stays a required peer dependency.
- `/plain/stream`, `/plain/webhooks`, `/plain/gnap`, `/plain/gnap/server` (with `/plain/gnap/server/testing`) and `/plain/better-auth`: the same Promise and exception layer for STREAM, webhooks, GNAP and the Better Auth plugin. A Promise `GnapStore` and `async` hooks replace the Effect-returning ones.
- `/hono`: a relative redirect URI is resolved against `externalUrl`, or against the request only on loopback. A public request host is not the GNAP finish origin. Continuation and management URLs must be http(s) without userinfo. Grant requests do not follow redirects.
- `/open-payments`, `/ilp`: client fetches do not follow redirects.
- **Security, `/gnap/server`:** a decision whose write lost an optimistic-lock race is no longer applied to a request the client replaced meanwhile (`PATCH /continue/:id`): the approval of the first request could be carried over to the wider one. The retry now checks the interaction id and nonce.
- **Security, `/gnap/server`, `/better-auth`:** interaction binding. A store with the new `interactionBinding: true` capability (`GrantRecord.interactBinding`; `memoryGnapStore()` and `betterAuthGnapStore()` have it) binds an interaction to the first browser that opens `interact.redirect` through a random `gnap-binding-<id>` cookie. `/finish` and a consent with a `userId` (`decideInteraction({ binding })`, `bindingFromRequest`, the Better Auth consent endpoints) are refused to any other browser, so a browser that only knows the nonce can no longer collect `interact_ref`. Custom stores without the flag keep the old check. **Better Auth users run the migration** for the new nullable `gnapGrant.interactBinding` column.
- `/gnap/server`: concurrent `PATCH`es no longer overwrite each other's `access`; the server's own `500`s reach `onError`; a request body that cannot be read is `400` instead of a crash; a token of a revoked or rejected grant cannot be rotated; the IdP secret is compared by digest; replay nonces are kept per client; `{ walletAddress: "" }` is refused; the key-fetch guard also refuses `*.lan`, `*.corp`, `*.intranet`, `*.private`, `*.home.arpa` and `*.svc`; the start of a push client's interaction no longer redirects the browser to its push endpoint; the in-memory nonce map drops expired entries. `storeContract` also checks `interactBinding`, and the version and untouched fields of `updateGrant`.
- **Fix, `/better-auth`:** `betterAuthGnapStore` could not create a grant on PostgreSQL (a JSON array was written as a PostgreSQL array: `invalid input syntax for type json`). The JSON columns are now written as JSON text. `test/better-auth/postgres.test.ts` runs the store contract and a replayed nonce inside a transaction on a real PostgreSQL when `GNAP_TEST_POSTGRES_URL` is set (CI does).
- `/better-auth`: `rateLimit` option; the consent `GET` runs `interaction.authorize`; `user_denied` is `403`.
- `/hono`: `__Secure-` and `__Host-` cookie names work; an oversized login-state cookie keeps the return URL without its query; only `GET` navigations (`Sec-Fetch-Mode: navigate`, or no such header with `Accept: text/html`; never a prefetch) start a login; concurrent rotations merge; the grant endpoint and the `continue` and `manage` URIs must be `https:` (loopback excepted); a blank `GNAP_AUTH_REFRESH_INTERVAL` or `GNAP_AUTH_EXPIRES` counts as unset; the 502 no longer repeats the server's text.
- **Behaviour change, `/open-payments`:** a request URL must be `https:` (`http:` with `useHttp`) without credentials or fragment, else `invalid-request` before anything is sent; `urlPolicy` can narrow it. `token.rotate` and `grant.continue` are no longer retried by a client-wide `retryNonIdempotent`; a `Retry-After` longer than `maxDelayMs` ends the retries; `assetScale` and amounts are bounds-checked, a pending grant needs `interact.finish`, and a response that breaks a payment invariant is `validation`.
- `/stream`: `buildStreamPrepare` may leave out `sourceAddress` (the empty `ConnectionNewAddress` of `@interledger/pay`); `decryptStreamPacket(..., { expect: { sequence, ilpPacketType } })` refuses a reply that is not the request's (`unexpected-packet`); `finalDecline` fails with `invalid-option` when its data cannot fit; `createStreamReply` refuses an amount outside uint64; the `verifyStreamReceipt` secret lookup may be async; the connection key cache no longer evicts real entries for tokens still being checked.
- `/ilp`: `postPrepare` validates `timeoutMs` and `maxReplyBytes` (`invalid-option`) and leaves no timer behind; `OerReader` refuses negative and fractional lengths; a Reject `message` over 8191 bytes is refused on serialize; the UTF-8 decoders keep a leading BOM.
- `/webhooks`: `canonicalizeJson` follows `json-canonicalize` for `toJSON` members and `Date` (a crafted `metadata` could make Rafiki's signature fail verification), has no nesting limit, and an empty secret is `WebhookError` `missing`. `invalid-config` reason for unusable options.
- `/http-signatures`: `verifyRequest` caps the body it reads (`maxBodyBytes`, 64 KiB) and only reads it when a digest is covered; `VerifiedSignature.replayWindowSeconds`; `@target-uri` drops the fragment; the structured-field serializer rejects NaN and rounds half to even; private JWK import checks that `d` matches `x`, and small-order public keys are refused.
- `/plain/*`: `Result` no longer leaks from `/plain/http-signatures` and `/plain/open-payments`; `fetchIldcp` exists in `/ildcp` too and reports the connector's Reject; `importPrivateKey` refuses unusable keys; a resolver that throws anything but `HttpSignatureError` is a defect (500 with `onError` in the server); store adapters are internal and bind `this`.
- CI and `mise.toml` pin Node `24.22.0` and Bun `1.4.4`. `publish.yml` never maps a `latest.N` prerelease to `latest`.

## 0.1.0-alpha.2 (2026-10-16)

- `open-payments-ilp/ilp`: `postPrepare`, an ILP-over-HTTP (RFC 35) client with a reply cap, a timeout and `IlpHttpError`.

## 0.1.0-alpha.1 (2026-10-16)

First release published keylessly from GitHub Actions (npm trusted publishing, with provenance). No code changes since 0.1.0-alpha.0.

## 0.1.0-alpha.0 (2026-10-16)

Pre-release: install with `npm i open-payments-ilp@alpha` to get the newest alpha.

First release. Web Standards only. `effect` (`^4`) is a peer dependency; `better-auth` (`^1.6.19`) and `hono` (`^4.7.11`)
are optional peers of their subpaths. Anything that reads the time takes `clock?: () => Date`; every error `reason` is
kebab-case.

- `/ilp`: ILP Prepare, Fulfill and Reject codecs, OER primitives, ILP address validation, fulfillment and condition helpers. Byte-identical to `ilp-packet`, stricter on malformed input.
- `/ildcp`: IL-DCP request and response codecs, `serveIldcp`.
- `/stream`: STREAM packet and frame codecs, packet encryption, SPSP-style credentials, a receiver (`createStreamReply`), sender helpers (`planStreamChunks`, `buildStreamPrepare` with rate probes, `decryptStreamPacket`), RFC 39 receipts, `decodeStreamPaymentTag`.
- `/http-signatures`: RFC 9421 Ed25519 request signing and verification (`nonce`, `tag`, `Content-Digest` sha-256 / sha-512, a `clock` option), RFC 9530 digests, a strict RFC 8941 parser, PEM and JWK key import, `exportPublicJwk`. `HttpSignatureError` carries the underlying `cause` of a failed key lookup.
  - Signature parameters `nonce` and `tag` of the wrong type are rejected like a wrong-typed `created`; `SIGNATURE_REPLAY_WINDOW_SECONDS` (331 s, one second more than before) is exported.
- `/open-payments`: generated wire types, amount helpers, Effect-based authenticated and unauthenticated clients (`validateResponses`, `requestTimeoutMs`, `maxResponseBytes`, `clock`).
  - Opt-in `retry` (`RetryOptions`): exponential backoff with full or no jitter, `Retry-After` (seconds or HTTP-date) capped by `maxDelayMs`, retries of network errors, timeouts and 408/429/502/503/504 for `GET`/`HEAD`/`PUT`/`DELETE`; `POST`/`PATCH` only with `retryNonIdempotent` (client-wide or per request). Every attempt is signed again with a fresh `created` and `nonce`; `sleep` and `random` are injectable, and interruption cancels the wait and the in-flight request. `OpenPaymentsError.attempts` reports the attempts made. Off by default.
- `/gnap`: GNAP types as profiled by Open Payments, access-item matching and limit checks (including ISO 8601 repeating `limits.interval`), error bodies, token helpers, interaction finish hash.
- `/gnap/server`: framework-agnostic GNAP authorisation server, wire-compatible with Rafiki's auth server (grant, continue, token, interaction, identity provider and introspection routes), the `GnapStore` port with `memoryGnapStore()`, optional multi-tenancy, and the RFC 9635 / 9767 requirements Open Payments clients never notice. A signed-in user's consent decision is refused unless `interaction.authorize` allows it. `onError(cause)` observes every failure answered with a `500`; the server logs nothing itself. Key fetches and body reads stop when the request is interrupted.
  - Fail-closed hooks: `interaction.authorize` must answer `true` and `introspection.authorize` `true` or `{ tenantId: string }`, anything else is refused. The default client key fetch refuses wallet addresses with a query or fragment.
  - `PATCH /continue/:id` grant modification (RFC 9635 §5.3: replaces access, subject and interact and re-evaluates; new consent starts a new interaction, earlier tokens are never widened), `access_token` arrays (§2.1.2, §3.2.2: up to 10 labelled tokens, each with its own access) and `interact.finish.method: "push"` (§2.5.2.2: one SSRF-checked POST on approval, no redirects, 5 s timeout, failures go to `onError`). They need a store that sets the new optional `GnapStore.extendedRecords` flag (`memoryGnapStore()` does; `GrantRecord.finishMethod` / `tokenRequests`, `TokenRecord.access` / `label`); other stores answer them `501 invalid_request`. `introspectToken().grantAccess` is the token's own access. The `bearer` flag stays refused.
- `/gnap/server/testing`: `storeContract({ describe, it }, name, makeStore)`, the framework-neutral conformance kit for custom `GnapStore`s.
- `/webhooks`: Rafiki-compatible webhook signing and verification (a `clock` option), RFC 8785 canonicalisation, event types.
- `/better-auth`, `/better-auth/client`: a Better Auth plugin over `/gnap/server` (tables `gnapGrant`, `gnapAccessToken`, `gnapNonce`; session-based consent next to the `x-idp-secret` identity provider API; rate limits; `onError`) and the client plugin for the consent page.
  - The identity provider routes are also mounted with `tenants`.
  - Consent read and accept/reject use Better Auth's sensitive session. A cached session cannot decide a grant.
- `/hono`: GNAP client middleware modelled on `@hono/oidc-auth`, for Rafiki / Open Payments and generic RFC 9635 servers (`initGnapAuthMiddleware`, `gnapAuthMiddleware`, `processGnapCallback`, `getGnapAuth`, `revokeGnapSession`, `gnapAuthRefreshErrorHook`). The configuration is validated when the middleware is created, the signing key is imported once, and a second navigation made while a login is pending joins it instead of requesting another grant.
  - Session, state and pending cookies are AES-256-GCM encrypted (HKDF key from `secret`, versioned format); `encryptCookies: false` keeps signed JWTs. Unreadable cookies mean "no session", never an error.
  - Grants answered with `continue` but no `interact.finish` are polled by later navigations (RFC 9635 §5.2); `interact.expires_in` shortens the pending state (0 or less is `502`).
  - `revokeGnapSession` revokes the token, then cancels the grant, in that order. A swap of `keyId` and the signing key applies from the next request and keeps sessions; rebinding a token's key (§6.1.1) is not implemented.

Every deliberate deviation from Rafiki and from the RFCs is listed in the README's Compatibility section.
