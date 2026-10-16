/**
 * GNAP (RFC 9635) as profiled by Open Payments: wire types, access-item matching and limit checks, error
 * bodies, token helpers, and the interaction finish `hash`. Web Standards only.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9635
 * @see https://openpayments.dev/apis/auth-server/
 * @module
 */
export {
  compareRequestAndGrantAccessItems,
  currentAccessIntervalStart,
  parseAccessIntervalMs,
  validateOutgoingPaymentAmounts,
  validateOutgoingPaymentReceiver,
  type AccessLimits,
  type AccessMatchItem,
} from "./access";

export { getGrantClientIdentity, parseClientField, toTokenInfoClient, type ParsedClientField } from "./client-field";

export { GnapClientFieldError, type GnapClientFieldErrorReason } from "./errors";

export { gnapErrorBody, type GnapErrorCode, type GnapErrorResponse } from "./error-response";

export {
  buildFinishUrl,
  buildRejectedFinishUrl,
  computeInteractionHash,
  verifyInteractionHash,
  type InteractionHashInput,
  type InteractionHashMethod,
} from "./interaction";

export { extractGnapToken, formatGnapAuthorization, hashToken } from "./token";

export type {
  AuthServerError,
  GrantAccessToken,
  GrantContinue,
  InteractRequest,
  InteractResponse,
  TokenInfo,
  TokenInfoClient,
  TokenIntrospectionRequest,
  TokenIntrospectionResponse,
} from "./types";

export type {
  AccessItem,
  AccessToken,
  Client,
  Grant,
  GrantContinuation,
  GrantContinuationRequest,
  GrantRequest,
  GrantRequestAccessItem,
  GrantWithAccessToken,
  GrantWithSubject,
  PendingGrant,
  Subject,
} from "../open-payments/types";

export {
  AccessAction,
  AccessType,
  isFinalizedGrantWithAccessToken,
  isFinalizedGrantWithSubject,
  isPendingGrant,
} from "../open-payments/types";
