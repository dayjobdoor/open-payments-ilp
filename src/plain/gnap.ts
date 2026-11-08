import * as clientField from "../gnap/client-field";
import * as interaction from "../gnap/interaction";
import * as token from "../gnap/token";
import { sync, task, type Sync, type Task } from "../internal/plain";

/**
 * Promise and exception flavour of `open-payments-ilp/gnap`: the digest helpers return a `Promise`; the client-field
 * parsers return the value or throw `GnapClientFieldError`. Everything else is the same as in the main entry.
 */

export {
  compareRequestAndGrantAccessItems,
  currentAccessIntervalStart,
  parseAccessIntervalMs,
  validateOutgoingPaymentAmounts,
  validateOutgoingPaymentReceiver,
  type AccessLimits,
  type AccessMatchItem,
} from "../gnap/access";
export { toTokenInfoClient, type ParsedClientField } from "../gnap/client-field";
export { GnapClientFieldError, type GnapClientFieldErrorReason } from "../gnap/errors";
export { gnapErrorBody, type GnapErrorCode, type GnapErrorResponse } from "../gnap/error-response";
export {
  buildFinishUrl,
  buildRejectedFinishUrl,
  type InteractionHashInput,
  type InteractionHashMethod,
} from "../gnap/interaction";
export { extractGnapToken, formatGnapAuthorization } from "../gnap/token";
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
} from "../gnap/types";
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

/** Parses a grant request's `client` field; throws `GnapClientFieldError` when it is not a wallet address or a key reference. */
export const parseClientField: Sync<typeof clientField.parseClientField> = sync(clientField.parseClientField);
/** The client identity of a grant request; throws `GnapClientFieldError` when its `client` field is invalid. */
export const getGrantClientIdentity: Sync<typeof clientField.getGrantClientIdentity> = sync(
  clientField.getGrantClientIdentity,
);
export const computeInteractionHash: Task<typeof interaction.computeInteractionHash> = task(
  interaction.computeInteractionHash,
);
export const verifyInteractionHash: Task<typeof interaction.verifyInteractionHash> = task(
  interaction.verifyInteractionHash,
);
export const hashToken: Task<typeof token.hashToken> = task(token.hashToken);
