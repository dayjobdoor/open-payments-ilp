import * as Effect from "effect/Effect";
import { constantTimeEqual, hmacSha256, toHex, utf8Encode } from "../internal/bytes";
import { WebhookError } from "./errors";
import { canonicalizeJson, type JsonValue } from "./jcs";

/** Default signature version: Rafiki's `SIGNATURE_VERSION` default. Every version signs the same bytes; the version only labels the scheme. */
const DEFAULT_VERSION = 1;

/** Default replay window: a signature older than this is rejected. */
const DEFAULT_MAX_AGE_MS = 300_000;

/** Default tolerated clock skew for signatures timestamped in the future. */
const DEFAULT_FUTURE_SKEW_MS = 30_000;

/** How webhooks are signed and verified. */
export interface WebhookSignatureConfig {
  /** Shared HMAC secret. */
  readonly secret: string;
  /** Signature version `N` of `v<N>=…`; defaults to 1, Rafiki's own default (its `SIGNATURE_VERSION`). */
  readonly version?: number;
  /** Replay window in ms; defaults to 300000. */
  readonly maxAgeMs?: number;
  /** Tolerated future skew in ms; defaults to 30000. */
  readonly futureSkewMs?: number;
}

/** Time source for signing and for the replay window. Defaults to `new Date()`. */
export interface WebhookClock {
  readonly clock?: () => Date;
}

const digest = (body: JsonValue, secret: string, timestamp: number): Effect.Effect<string, WebhookError> =>
  Effect.flatMap(Effect.fromResult(canonicalizeJson(body)), (canonical) =>
    Effect.promise(async () => toHex(await hmacSha256(utf8Encode(secret), utf8Encode(`${timestamp}.${canonical}`)))),
  );

/**
 * Signs a webhook the way Rafiki does: HMAC-SHA256 (hex) over `<t>.<canonical JSON body>` with `t` in Unix
 * milliseconds, returned as the `Rafiki-Signature` header value `t=<ms>, v<N>=<hex>`.
 * Fails with `WebhookError` (`unsupported-value`) when the body cannot be canonicalised.
 *
 * The signing time is read from `config.clock` when the effect runs.
 * @see https://rafiki.dev/integration/webhooks/#signature-verification
 */
export function signWebhook(
  body: JsonValue,
  config: WebhookSignatureConfig & WebhookClock,
): Effect.Effect<string, WebhookError> {
  const version = config.version ?? DEFAULT_VERSION;

  return Effect.suspend(() => {
    const signedAt = (config.clock?.() ?? new Date()).getTime();

    return Effect.map(digest(body, config.secret, signedAt), (hex) => `t=${signedAt}, v${version}=${hex}`);
  });
}

const fail = (reason: WebhookError["reason"], message: string): Effect.Effect<never, WebhookError> =>
  Effect.fail(new WebhookError({ reason, message }));

const verify = (
  body: JsonValue,
  header: string | undefined,
  config: WebhookSignatureConfig & WebhookClock,
): Effect.Effect<void, WebhookError> => {
  if (!header || !config.secret) return fail("missing", "Signature header or secret is missing");
  const match = /^t=(\d+),\s*v(\d+)=([0-9a-f]{64})$/.exec(header.trim());

  if (!match) return fail("malformed", "Signature header is not `t=<ms>, v<N>=<hex>`");
  const timestamp = Number(match[1]);
  const version = Number(match[2]);

  if (!Number.isSafeInteger(timestamp)) return fail("malformed", "Signature timestamp is out of range");

  if (version !== (config.version ?? DEFAULT_VERSION))
    return fail("version-mismatch", `Unexpected signature version v${version}`);
  const now = (config.clock?.() ?? new Date()).getTime();

  if (timestamp < now - (config.maxAgeMs ?? DEFAULT_MAX_AGE_MS))
    return fail("expired", "Signature is older than the replay window");

  if (timestamp > now + (config.futureSkewMs ?? DEFAULT_FUTURE_SKEW_MS))
    return fail("future", "Signature is timestamped in the future");
  const provided = utf8Encode(match[3] ?? "");

  return Effect.flatMap(digest(body, config.secret, timestamp), (expected) =>
    constantTimeEqual(provided, utf8Encode(expected))
      ? Effect.void
      : fail("mismatch", "Signature does not match the body"),
  );
};

/**
 * Verifies a `Rafiki-Signature` header against the body: header form, version, replay window and digest
 * (compared in constant time). Succeeds with `void`; fails with `WebhookError` whose `reason` is `missing`
 * (no header or no secret), `malformed`, `version-mismatch`, `expired`, `future`, `mismatch`, or
 * `unsupported-value` (body not canonicalisable). The clock is read when the effect runs.
 *
 * @see https://rafiki.dev/integration/webhooks/#signature-verification
 */
export function verifyWebhookSignature(
  body: JsonValue,
  header: string | undefined,
  config: WebhookSignatureConfig & WebhookClock,
): Effect.Effect<void, WebhookError> {
  return Effect.suspend(() => verify(body, header, config));
}

/** `true` when the signature verifies; any failure reason collapses to `false`. */
export function isValidWebhookSignature(
  body: JsonValue,
  header: string | undefined,
  config: WebhookSignatureConfig & WebhookClock,
): Effect.Effect<boolean> {
  return Effect.match(verifyWebhookSignature(body, header, config), {
    onFailure: () => false,
    onSuccess: () => true,
  });
}
