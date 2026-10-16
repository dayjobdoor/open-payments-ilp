import type { YieldableError } from "effect/Cause";
import * as Data from "effect/Data";

/** Why a webhook could not be canonicalised, signed, or verified. */
export type WebhookErrorReason =
  /** The body contains a value JSON cannot represent (NaN, Infinity, bigint, function, symbol) or a cycle. */
  | "unsupported-value"
  /** The signature header or the signing secret is absent. */
  | "missing"
  /** The signature header does not have the `t=<ms>, v<N>=<hex>` form. */
  | "malformed"
  /** The header's signature version differs from the configured version. */
  | "version-mismatch"
  /** The timestamp is older than the replay window. */
  | "expired"
  /** The timestamp is further in the future than the allowed clock skew. */
  | "future"
  /** The digest does not match the body. */
  | "mismatch";

interface WebhookErrorFields {
  readonly reason: WebhookErrorReason;
  readonly message: string;
}

// Explicit annotation: `isolatedDeclarations` forbids a call expression in an `extends` clause.
const Base: new (fields: WebhookErrorFields) => YieldableError & {
  readonly _tag: "WebhookError";
} & Readonly<WebhookErrorFields> = Data.TaggedError("WebhookError")<WebhookErrorFields>;

/** Every failure of the webhooks toolkit, discriminated by `reason`. */
export class WebhookError extends Base {}
