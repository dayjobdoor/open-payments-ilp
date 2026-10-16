/**
 * STREAM (RFC 29): packet and frame codecs, AES-256-GCM packet encryption with HMAC-derived keys,
 * fulfillment/condition generation, SPSP-style credentials, a receiver that answers incoming Prepares,
 * receipts (RFC 39), and the sender pieces (chunk planning, Prepare construction including unfulfillable rate
 * probes, reply decryption). Interoperates byte-for-byte with `ilp-protocol-stream` and
 * `@interledger/stream-receiver`. Web Standards only (WebCrypto); imported keys and per-connection derivations
 * are cached in small bounded maps, so repeat packets under one secret cost a fraction of the first.
 *
 * @see https://interledger.org/developers/rfcs/stream-protocol/
 * @module
 */
export {
  generateStreamCredentials,
  type StreamCredentialOptions,
  type StreamCredentials,
  type StreamServerConfig,
} from "./credentials";

export {
  decryptStreamData,
  deriveStreamKeys,
  encryptStreamData,
  generateStreamCondition,
  generateStreamFulfillment,
  STREAM_ENCRYPTION_OVERHEAD,
  type StreamKeys,
} from "./crypto";

export { StreamError, type StreamErrorReason } from "./errors";

export {
  decodeStreamFrame,
  encodeStreamFrame,
  StreamErrorCode,
  StreamFrameType,
  type ConnectionAssetDetailsFrame,
  type ConnectionCloseFrame,
  type ConnectionDataBlockedFrame,
  type ConnectionMaxDataFrame,
  type ConnectionMaxStreamIdFrame,
  type ConnectionNewAddressFrame,
  type ConnectionStreamIdBlockedFrame,
  type StreamCloseFrame,
  type StreamDataBlockedFrame,
  type StreamDataFrame,
  type StreamFrame,
  type StreamMaxDataFrame,
  type StreamMaxMoneyFrame,
  type StreamMoneyBlockedFrame,
  type StreamMoneyFrame,
  type StreamReceiptFrame,
} from "./frames";

export { decodeStreamPacket, decryptStreamPacket, encodeStreamPacket, type StreamPacket } from "./packet";

export { decodeStreamReceipt, verifyStreamReceipt, type StreamReceipt } from "./receipt";

export {
  createStreamReply,
  decodeStreamPaymentTag,
  type StreamFinalReply,
  type StreamPendingReply,
  type StreamReply,
} from "./receiver";

export { buildStreamPrepare, planStreamChunks, type BuildStreamPrepareOptions, type StreamChunk } from "./sender";
