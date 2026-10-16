import type { components } from "../open-payments/generated/webhooks";

/** `incoming_payment.*` event. */
export type IncomingPaymentEvent = components["schemas"]["incomingPaymentEvent"];

/** `outgoing_payment.*` event. */
export type OutgoingPaymentEvent = components["schemas"]["outgoingPaymentEvent"];

/** `wallet_address.not_found` event. */
export type WalletAddressNotFoundEvent = components["schemas"]["walletAddressNotFound"];

/** `wallet_address.web_monetization` event. */
export type WebMonetizationEvent = components["schemas"]["webMonetizationEvent"];

/** `asset.liquidity_low` / `peer.liquidity_low` event. */
export type LiquidityEvent = components["schemas"]["liquidityEvent"];

/** Any Rafiki webhook event: `{ id, type, data }`. */
export type WebhookEvent =
  | IncomingPaymentEvent
  | OutgoingPaymentEvent
  | WalletAddressNotFoundEvent
  | WebMonetizationEvent
  | LiquidityEvent;

/** Every webhook event `type`. */
export type WebhookEventType = WebhookEvent["type"];
