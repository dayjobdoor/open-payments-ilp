import * as signature from "../webhooks/signature";
import * as jcs from "../webhooks/jcs";
import { sync, task, type Sync, type Task } from "../internal/plain";

/**
 * Promise and exception flavour of `open-payments-ilp/webhooks`: signing and verifying return a `Promise` that rejects
 * with `WebhookError`; `canonicalizeJson` returns the string or throws `WebhookError`. `isValidWebhookSignature`
 * resolves `false` for an invalid signature and never rejects.
 */

export { WebhookError, type WebhookErrorReason } from "../webhooks/errors";
export type {
  IncomingPaymentEvent,
  LiquidityEvent,
  OutgoingPaymentEvent,
  WalletAddressNotFoundEvent,
  WebhookEvent,
  WebhookEventType,
  WebMonetizationEvent,
} from "../webhooks/events";
export type { JsonValue } from "../webhooks/jcs";
export type { WebhookClock, WebhookSignatureConfig } from "../webhooks/signature";

/** RFC 8785 canonical JSON; throws `WebhookError` for a value JSON cannot represent. */
export const canonicalizeJson: Sync<typeof jcs.canonicalizeJson> = sync(jcs.canonicalizeJson);
/** Signs a webhook body (`Rafiki-Signature` header value); rejects with `WebhookError` (`unsupported-value`) for a body JSON cannot represent. */
export const signWebhook: Task<typeof signature.signWebhook> = task(signature.signWebhook);
/** Verifies a `Rafiki-Signature` header; resolves with nothing, or rejects with `WebhookError` (`missing`, `malformed`, `expired`, `mismatch`, ...). */
export const verifyWebhookSignature: Task<typeof signature.verifyWebhookSignature> = task(
  signature.verifyWebhookSignature,
);
/** Resolves `true` when the signature verifies and `false` for any failure; never rejects. */
export const isValidWebhookSignature: Task<typeof signature.isValidWebhookSignature> = task(
  signature.isValidWebhookSignature,
);
