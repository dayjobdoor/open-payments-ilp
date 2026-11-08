import {
  conditionFromFulfillment as conditionFromFulfillmentEffect,
  fulfillmentMatchesCondition as fulfillmentMatchesConditionEffect,
} from "../ilp/fulfillment";
import { postPrepare as postPrepareEffect } from "../ilp/http";
import * as packets from "../ilp/packets";
import { sync, task, type Sync, type Task } from "../internal/plain";

/**
 * Promise and exception flavour of `open-payments-ilp/ilp`, shaped after `ilp-packet`: codecs return the value
 * and throw `IlpCodecError`; I/O returns a `Promise` that rejects with `IlpHttpError`. Amounts stay `bigint`, bytes
 * stay `Uint8Array` and expiries stay `Date`.
 */

export { isValidIlpAddress } from "../ilp/address";
export { IlpErrorCode, IlpPacketType, type IlpErrorCodeValue } from "../ilp/codes";
export { IlpCodecError, type IlpCodecErrorReason } from "../ilp/errors";
export {
  DEFAULT_ILP_HTTP_MAX_REPLY_BYTES,
  DEFAULT_ILP_HTTP_TIMEOUT_MS,
  IlpHttpError,
  type IlpHttpErrorReason,
  type PostPrepareOptions,
} from "../ilp/http";
export {
  isFulfill,
  isReject,
  MAX_ILP_DATA_LENGTH,
  type IlpFulfill,
  type IlpPacket,
  type IlpPrepare,
  type IlpReject,
  type IlpReply,
} from "../ilp/packets";

/** Serializes a Prepare to bytes; throws `IlpCodecError` for an invalid field (address, expiry, data length). */
export const serializePrepare: Sync<typeof packets.serializePrepare> = sync(packets.serializePrepare);
/** Parses a Prepare; throws `IlpCodecError` when the bytes are not a valid Prepare packet. */
export const deserializePrepare: Sync<typeof packets.deserializePrepare> = sync(packets.deserializePrepare);
/** Serializes a Fulfill to bytes; throws `IlpCodecError` for a fulfillment that is not 32 bytes or oversized data. */
export const serializeFulfill: Sync<typeof packets.serializeFulfill> = sync(packets.serializeFulfill);
/** Parses a Fulfill; throws `IlpCodecError` when the bytes are not a valid Fulfill packet. */
export const deserializeFulfill: Sync<typeof packets.deserializeFulfill> = sync(packets.deserializeFulfill);
/** Serializes a Reject to bytes; throws `IlpCodecError` for an invalid code, address or oversized field. */
export const serializeReject: Sync<typeof packets.serializeReject> = sync(packets.serializeReject);
/** Parses a Reject; throws `IlpCodecError` when the bytes are not a valid Reject packet. */
export const deserializeReject: Sync<typeof packets.deserializeReject> = sync(packets.deserializeReject);
/** Serializes a Fulfill or a Reject; throws `IlpCodecError` as {@link serializeFulfill} / {@link serializeReject}. */
export const serializeReply: Sync<typeof packets.serializeReply> = sync(packets.serializeReply);
/** Parses a Fulfill or a Reject; throws `IlpCodecError` for any other packet or invalid bytes. */
export const deserializeReply: Sync<typeof packets.deserializeReply> = sync(packets.deserializeReply);
/** Parses any ILP packet, tagged with its type; throws `IlpCodecError` for invalid bytes. */
export const deserializePacket: Sync<typeof packets.deserializePacket> = sync(packets.deserializePacket);

/** `ilp-packet` spellings of the codecs above. */
export const serializeIlpPrepare: typeof serializePrepare = serializePrepare;
export const deserializeIlpPrepare: typeof deserializePrepare = deserializePrepare;
export const serializeIlpFulfill: typeof serializeFulfill = serializeFulfill;
export const deserializeIlpFulfill: typeof deserializeFulfill = deserializeFulfill;
export const serializeIlpReject: typeof serializeReject = serializeReject;
export const deserializeIlpReject: typeof deserializeReject = deserializeReject;
export const serializeIlpReply: typeof serializeReply = serializeReply;
export const deserializeIlpReply: typeof deserializeReply = deserializeReply;
export const deserializeIlpPacket: typeof deserializePacket = deserializePacket;

/** SHA-256 of a 32-byte fulfillment. Rejects with `IlpCodecError` when it is not 32 bytes. */
export const conditionFromFulfillment: Task<typeof conditionFromFulfillmentEffect> =
  task(conditionFromFulfillmentEffect);
/** Constant-time check that `fulfillment` hashes to `executionCondition`. */
export const fulfillmentMatchesCondition: Task<typeof fulfillmentMatchesConditionEffect> = task(
  fulfillmentMatchesConditionEffect,
);

/** POSTs a serialized Prepare over ILP-over-HTTP and resolves with the serialized reply. */
export const postPrepare: Task<typeof postPrepareEffect> = task(postPrepareEffect);
