/**
 * Rafiki-compatible webhook signatures (HMAC-SHA256 over `<t>.<canonical JSON>`), RFC 8785 JSON
 * canonicalisation, and the webhook event types generated from Rafiki's webhooks OpenAPI document.
 * Web Standards only.
 *
 * @see https://rafiki.dev/integration/webhooks/
 * @module
 */
export { WebhookError, type WebhookErrorReason } from "./errors";

export type {
  IncomingPaymentEvent,
  LiquidityEvent,
  OutgoingPaymentEvent,
  WalletAddressNotFoundEvent,
  WebhookEvent,
  WebhookEventType,
  WebMonetizationEvent,
} from "./events";

export { canonicalizeJson, type JsonValue } from "./jcs";

export {
  isValidWebhookSignature,
  signWebhook,
  verifyWebhookSignature,
  type WebhookClock,
  type WebhookSignatureConfig,
} from "./signature";
