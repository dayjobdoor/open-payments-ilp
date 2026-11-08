import type * as Effect from "effect/Effect";
import * as amount from "../open-payments/amount";
import * as client from "../open-payments/client";
import { sync, task, type Promisified, type Sync } from "../internal/plain";
import type { RetryOptions as EffectRetryOptions } from "../open-payments/retry";
import { importPrivateKey, type PrivateKeyInput } from "./http-signatures";

/**
 * Promise flavour of `open-payments-ilp/open-payments`, shaped after `@interledger/open-payments`: the clients are
 * created with `await`, every route returns a `Promise`, and a failed request rejects with `OpenPaymentsError`.
 * Everything that is not a client (amount helpers, wire types, `OpenPaymentsError`) is the same as in the main entry.
 */

export {
  isAmountValue,
  isPositiveAmountValue,
  isSameAsset,
  normalizeAmount,
  UINT128_MAX,
  UINT64_MAX,
} from "../open-payments/amount";
export { OpenPaymentsError, type OpenPaymentsErrorReason } from "../open-payments/errors";
export {
  AccessAction,
  AccessType,
  isFinalizedGrantWithAccessToken,
  isFinalizedGrantWithSubject,
  isPendingGrant,
  type AccessIncomingActions,
  type AccessItem,
  type AccessOutgoing,
  type AccessOutgoingBase,
  type AccessOutgoingLimits,
  type AccessOutgoingWithDebitAmount,
  type AccessOutgoingWithReceiveAmount,
  type AccessQuoteActions,
  type AccessOutgoingActions,
  type AccessToken,
  type Amount,
  type BackwardPagination,
  type Client,
  type CreateIncomingPaymentArgs,
  type CreateOutgoingPaymentArgs,
  type CreateQuoteArgs,
  type DIDDocument,
  type ErrorResponse,
  type ForwardPagination,
  type Grant,
  type GrantContinuation,
  type GrantContinuationRequest,
  type GrantRequest,
  type GrantRequestAccessItem,
  type GrantWithAccessToken,
  type GrantWithSubject,
  type IlpPaymentMethod,
  type IncomingPayment,
  type IncomingPaymentPaginationResult,
  type IncomingPaymentWithPaymentMethods,
  type JWK,
  type JWKS,
  type NonInteractiveGrantRequest,
  type OutgoingPayment,
  type OutgoingPaymentGrantSpentAmounts,
  type OutgoingPaymentPaginationResult,
  type OutgoingPaymentWithSpentAmounts,
  type PaginationArgs,
  type PendingGrant,
  type PublicIncomingPayment,
  type Quote,
  type Subject,
  type WalletAddress,
} from "../open-payments/types";

export type {
  CollectionRequestArgs,
  GrantOrTokenRequestArgs,
  ResourceRequestArgs,
  UnauthenticatedResourceRequestArgs,
} from "../open-payments/client";
export type { PrivateKeyInput } from "./http-signatures";

/** Retry policy; `sleep` is a plain `(ms) => Promise<void>` here. */
export interface RetryOptions extends Omit<EffectRetryOptions, "sleep"> {
  readonly sleep?: (ms: number) => Promise<void>;
}

export interface ClientOptions extends Omit<client.ClientOptions, "retry"> {
  readonly retry?: RetryOptions;
}

export type WalletAddressRoutes = Promisified<client.WalletAddressRoutes>;
export type UnauthenticatedIncomingPaymentRoutes = Promisified<client.UnauthenticatedIncomingPaymentRoutes>;
export type IncomingPaymentRoutes = Promisified<client.IncomingPaymentRoutes>;
export type OutgoingPaymentRoutes = Promisified<client.OutgoingPaymentRoutes>;
export type QuoteRoutes = Promisified<client.QuoteRoutes>;
export type GrantRoutes = Promisified<client.GrantRoutes>;
export type TokenRoutes = Promisified<client.TokenRoutes>;

export interface UnauthenticatedClient {
  readonly walletAddress: WalletAddressRoutes;
  readonly incomingPayment: UnauthenticatedIncomingPaymentRoutes;
}

export interface AuthenticatedClient {
  readonly walletAddress: WalletAddressRoutes;
  readonly incomingPayment: IncomingPaymentRoutes;
  readonly outgoingPayment: OutgoingPaymentRoutes;
  readonly grant: GrantRoutes;
  readonly token: TokenRoutes;
  readonly quote: QuoteRoutes;
}

export interface AuthenticatedClientOptions extends Omit<client.AuthenticatedClientOptions, "privateKey" | "retry"> {
  readonly retry?: RetryOptions;
  /** Ed25519 private key: a `CryptoKey`, a private JWK, or a PKCS#8 PEM string. */
  readonly privateKey: PrivateKeyInput;
}

/** Parses a decimal amount string; throws `OpenPaymentsError` when it is not one or exceeds `max` (default `UINT64_MAX`). */
export const parseAmountValue: Sync<typeof amount.parseAmountValue> = sync(amount.parseAmountValue);
/** Compares two amounts (`-1`, `0`, `1`); throws `OpenPaymentsError` when they differ in asset or either value is invalid. */
export const compareAmounts: Sync<typeof amount.compareAmounts> = sync(amount.compareAmounts);
/** Adds two amounts of the same asset; throws `OpenPaymentsError` when assets differ or the sum exceeds `max`. */
export const addAmounts: Sync<typeof amount.addAmounts> = sync(amount.addAmounts);

/**
 * Turns every `Effect`-returning route of one group into a `Promise`-returning one.
 *
 * SAFETY: the route groups are plain objects whose members are all `Effect`-returning functions (or data), which is
 * what {@link Promisified} describes; `Object.fromEntries` cannot carry that mapping, so the casts state it.
 */
const promisifyRoutes = <T extends object>(routes: T): Promisified<T> =>
  Object.fromEntries(
    Object.entries(routes).map(([name, route]) => [
      name,
      // SAFETY: a function member of a route group returns an `Effect` (see above).
      typeof route === "function" ? task(route as (...args: never[]) => Effect.Effect<unknown, unknown>) : route,
    ]),
    // SAFETY: the mapping above is what `Promisified<T>` describes (see above).
  ) as Promisified<T>;

// Written out group by group: a route group added to the Effect client fails to compile here until it is mapped.
const promisifyUnauthenticated = (built: client.UnauthenticatedClient): UnauthenticatedClient => ({
  walletAddress: promisifyRoutes(built.walletAddress),
  incomingPayment: promisifyRoutes(built.incomingPayment),
});

const promisifyAuthenticated = (built: client.AuthenticatedClient): AuthenticatedClient => ({
  walletAddress: promisifyRoutes(built.walletAddress),
  incomingPayment: promisifyRoutes(built.incomingPayment),
  outgoingPayment: promisifyRoutes(built.outgoingPayment),
  grant: promisifyRoutes(built.grant),
  token: promisifyRoutes(built.token),
  quote: promisifyRoutes(built.quote),
});

/** Client for the public Open Payments endpoints (no signing). */
export const createUnauthenticatedClient = async (options: ClientOptions = {}): Promise<UnauthenticatedClient> =>
  promisifyUnauthenticated(client.createUnauthenticatedClient(options));

/** Client for every Open Payments API; requests that need authorisation are signed with `privateKey`. */
export const createAuthenticatedClient = async (options: AuthenticatedClientOptions): Promise<AuthenticatedClient> =>
  promisifyAuthenticated(
    client.createAuthenticatedClient({
      ...options,
      privateKey: await importPrivateKey(options.privateKey),
    }),
  );
