/**
 * Open Payments wire types, generated from the Open Payments OpenAPI documents.
 * Names and shapes mirror `@interledger/open-payments`' `types.d.ts` (mutual assignability is
 * asserted by test/open-payments/types-compat.test.ts).
 */
import type { components as ASComponents, operations as ASOperations } from "./generated/auth-server";
import type { components as RSComponents, operations as RSOperations } from "./generated/resource-server";
import type { components as WAComponents } from "./generated/wallet-address-server";

/** Wallet address document (`GET {walletAddress}`). */
export type WalletAddress = WAComponents["schemas"]["wallet-address"];

/** Ed25519 public JSON Web Key. */
export type JWK = WAComponents["schemas"]["json-web-key"];

/** JSON Web Key Set (`GET {walletAddress}/jwks.json`). */
export type JWKS = WAComponents["schemas"]["json-web-key-set"];

/** DID document (`GET {walletAddress}/did.json`). */
export type DIDDocument = WAComponents["schemas"]["did-document"];

/** Open Payments amount: `value` is a uint64 string in the smallest unit of the asset. */
export type Amount = RSComponents["schemas"]["amount"];

/** Incoming payment as returned to an authorised client. */
export type IncomingPayment = RSComponents["schemas"]["incoming-payment"];

/** Unauthenticated view of an incoming payment. */
export type PublicIncomingPayment = RSComponents["schemas"]["public-incoming-payment"];

/** ILP payment method of an incoming payment. */
export type IlpPaymentMethod = RSComponents["schemas"]["ilp-payment-method"];

/** Incoming payment including its payment methods (create/get responses). */
export type IncomingPaymentWithPaymentMethods = IncomingPayment & { methods: IlpPaymentMethod[] };

/** Body of `POST /incoming-payments`. */
export type CreateIncomingPaymentArgs =
  RSOperations["create-incoming-payment"]["requestBody"]["content"]["application/json"];

/** Outgoing payment. */
export type OutgoingPayment = RSComponents["schemas"]["outgoing-payment"];

/** Outgoing payment with the amounts spent against the grant. */
export type OutgoingPaymentWithSpentAmounts = RSComponents["schemas"]["outgoing-payment-with-spent-amounts"];

/** Response of `GET /outgoing-payment-grant`. */
export type OutgoingPaymentGrantSpentAmounts =
  RSOperations["get-outgoing-payment-grant"]["responses"]["200"]["content"]["application/json"];

/** Body of `POST /outgoing-payments`: a quote id, or an incoming payment plus debit amount. */
export type CreateOutgoingPaymentArgs =
  RSOperations["create-outgoing-payment"]["requestBody"]["content"]["application/json"];

type PaginationResult<T> = { pagination: RSComponents["schemas"]["page-info"]; result: T[] };

/** One page of incoming payments. */
export type IncomingPaymentPaginationResult = PaginationResult<IncomingPayment>;

/** One page of outgoing payments. */
export type OutgoingPaymentPaginationResult = PaginationResult<OutgoingPayment>;

type BasePaginationArgs = Pick<
  RSOperations["list-incoming-payments"]["parameters"]["query"],
  "first" | "last" | "cursor" | "wallet-address"
>;

/** Forward pagination (`first` / `cursor`). */
export type ForwardPagination = Omit<BasePaginationArgs, "last"> & { last?: never };

/** Backward pagination (`last` / `cursor`). */
export type BackwardPagination = Omit<BasePaginationArgs, "first"> & { first?: never };

/** Pagination arguments of the list operations. */
export type PaginationArgs = ForwardPagination | BackwardPagination;

/** Quote. */
export type Quote = RSComponents["schemas"]["quote"];

type QuoteArgsBase = {
  walletAddress: RSOperations["create-quote"]["requestBody"]["content"]["application/json"]["walletAddress"];
  receiver: RSOperations["create-quote"]["requestBody"]["content"]["application/json"]["receiver"];
  method: RSComponents["schemas"]["payment-method"];
};

type QuoteArgsWithDebitAmount = QuoteArgsBase & {
  debitAmount?: RSComponents["schemas"]["quote"]["debitAmount"];
  receiveAmount?: never;
};

type QuoteArgsWithReceiveAmount = QuoteArgsBase & {
  debitAmount?: never;
  receiveAmount?: RSComponents["schemas"]["quote"]["receiveAmount"];
};

/** Body of `POST /quotes`: either a debit amount or a receive amount. */
export type CreateQuoteArgs = QuoteArgsWithDebitAmount | QuoteArgsWithReceiveAmount;

/** Error body of the resource server: `{ error: { code, description, details? } }`. */
export type ErrorResponse = RSComponents["schemas"]["error-response"];

/** GNAP subject request/response. */
export type Subject = ASComponents["schemas"]["subject"];

/** GNAP `client` field: wallet address string, `{ walletAddress }`, or `{ jwk }`. */
export type Client = string | { walletAddress: string; jwk?: never } | { jwk: JWK; walletAddress?: never };

type GrantRequestBody = ASOperations["post-request"]["requestBody"]["content"]["application/json"];

/** Grant request that only asks for an access token. */
export type NonInteractiveGrantRequest = {
  access_token: GrantRequestBody["access_token"];
  client: Client;
};

type BaseGrantRequest = { client: Client; interact?: GrantRequestBody["interact"] };

type GrantRequestWithAccessToken = BaseGrantRequest & {
  access_token: { access: GrantRequestAccessItem[] };
  subject?: Subject;
};

type GrantRequestWithSubject = BaseGrantRequest & {
  access_token?: { access: GrantRequestAccessItem[] };
  subject: Subject;
};

/** Grant request: needs `access_token`, `subject`, or both. */
export type GrantRequest = GrantRequestWithAccessToken | GrantRequestWithSubject;

/** Finalised grant. */
export type Grant = {
  access_token?: ASComponents["schemas"]["access_token"];
  continue: ASComponents["schemas"]["continue"];
  subject?: Subject;
};

/** Finalised grant carrying an access token. */
export type GrantWithAccessToken = Grant & { access_token: NonNullable<Grant["access_token"]> };

/** Finalised grant carrying a subject. */
export type GrantWithSubject = Grant & { subject: NonNullable<Grant["subject"]> };

/** Continuation-only grant response (interaction still pending or approved without result). */
export type GrantContinuation = { continue: ASComponents["schemas"]["continue"] };

/** Body of `POST /continue/{id}`. */
export type GrantContinuationRequest =
  | Required<NonNullable<ASOperations["post-continue"]["requestBody"]>["content"]["application/json"]>
  | undefined;

/** Grant awaiting user interaction. */
export type PendingGrant = {
  interact: ASComponents["schemas"]["interact-response"];
  continue: ASComponents["schemas"]["continue"];
};

/** Response of token rotation. */
export type AccessToken = { access_token: ASComponents["schemas"]["access_token"] };

/** Actions of an incoming-payment access item. */
export type AccessIncomingActions = ASComponents["schemas"]["access-incoming"]["actions"];

/** Actions of an outgoing-payment access item. */
export type AccessOutgoingActions = ASComponents["schemas"]["access-outgoing"]["actions"];

/** Actions of a quote access item. */
export type AccessQuoteActions = ASComponents["schemas"]["access-quote"]["actions"];

/** One entry of a grant's `access` array. */
export type AccessItem = ASComponents["schemas"]["access-item"];

/** Access item `type`. */
export type AccessType =
  | ASComponents["schemas"]["access-incoming"]["type"]
  | ASComponents["schemas"]["access-outgoing"]["type"]
  | ASComponents["schemas"]["access-quote"]["type"];

/** Access item action. */
export type AccessAction = (AccessIncomingActions | AccessOutgoingActions | AccessQuoteActions)[number];

type Without<T, U> = { [P in Exclude<keyof T, keyof U>]?: never };

type XOR<T, U> = T | U extends object ? (Without<T, U> & U) | (Without<U, T> & T) : T | U;

type XOR3<T, U, V> = XOR<T, XOR<U, V>>;

/** Limits shared by every outgoing-payment access item. */
export type AccessOutgoingBase = {
  receiver?: ASComponents["schemas"]["receiver"];
  interval?: ASComponents["schemas"]["interval"];
};

/** Outgoing limits with a debit amount. */
export type AccessOutgoingWithDebitAmount = AccessOutgoingBase & {
  debitAmount: ASComponents["schemas"]["amount"];
};

/** Outgoing limits with a receive amount. */
export type AccessOutgoingWithReceiveAmount = AccessOutgoingBase & {
  receiveAmount: ASComponents["schemas"]["amount"];
};

/** Outgoing limits: at most one of `debitAmount` / `receiveAmount`. */
export type AccessOutgoingLimits = XOR3<
  AccessOutgoingBase,
  AccessOutgoingWithDebitAmount,
  AccessOutgoingWithReceiveAmount
>;

/** Outgoing-payment access item with XOR'd limits. */
export type AccessOutgoing = {
  type: "outgoing-payment";
  actions: ("create" | "read" | "read-all" | "list" | "list-all")[];
  identifier: string;
  limits?: AccessOutgoingLimits;
};

/** Access item accepted in a grant request. */
export type GrantRequestAccessItem =
  | ASComponents["schemas"]["access-incoming"]
  | AccessOutgoing
  | ASComponents["schemas"]["access-quote"];

interface AccessTypeValues {
  readonly IncomingPayment: "incoming-payment";
  readonly OutgoingPayment: "outgoing-payment";
  readonly Quote: "quote";
}

/** Named access `type` values. */
export const AccessType: AccessTypeValues = {
  IncomingPayment: "incoming-payment",
  OutgoingPayment: "outgoing-payment",
  Quote: "quote",
};

interface AccessActionValues {
  readonly Create: "create";
  readonly Read: "read";
  readonly ReadAll: "read-all";
  readonly Complete: "complete";
  readonly List: "list";
  readonly ListAll: "list-all";
}

/** Named access action values. */
export const AccessAction: AccessActionValues = {
  Create: "create",
  Read: "read",
  ReadAll: "read-all",
  Complete: "complete",
  List: "list",
  ListAll: "list-all",
};

/** True when the grant response requires user interaction. */
export function isPendingGrant(grant: PendingGrant | Grant): grant is PendingGrant {
  return "interact" in grant;
}

/** True when the response is a finalised grant with an access token. */
export function isFinalizedGrantWithAccessToken(grant: GrantContinuation | Grant): grant is GrantWithAccessToken {
  return "access_token" in grant && grant.access_token !== undefined;
}

/** True when the response is a finalised grant with a subject. */
export function isFinalizedGrantWithSubject(grant: GrantContinuation | Grant): grant is GrantWithSubject {
  return "subject" in grant && grant.subject !== undefined;
}
