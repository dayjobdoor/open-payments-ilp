# Changelog

This project follows [semantic versioning](https://semver.org/). While the major version is `0`, minor
releases may contain breaking changes.

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
