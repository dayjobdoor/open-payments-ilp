import * as credentials from "../stream/credentials";
import * as crypto from "../stream/crypto";
import * as frames from "../stream/frames";
import * as packet from "../stream/packet";
import * as receipt from "../stream/receipt";
import * as receiver from "../stream/receiver";
import * as sender from "../stream/sender";
import { sync, task, type Promisified, type Sync, type Task } from "../internal/plain";

/**
 * Promise and exception flavour of `open-payments-ilp/stream`: codecs return the value and throw `IlpCodecError`;
 * crypto and receiver functions return a `Promise` that rejects with `StreamError` (or `IlpCodecError` for malformed
 * packets).
 */

export { type StreamCredentialOptions, type StreamCredentials, type StreamServerConfig } from "../stream/credentials";
export { STREAM_ENCRYPTION_OVERHEAD, type StreamKeys } from "../stream/crypto";
export { StreamError, type StreamErrorReason } from "../stream/errors";
export {
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
} from "../stream/frames";
export { type DecryptStreamPacketOptions, type ExpectedStreamPacket, type StreamPacket } from "../stream/packet";
export { type StreamReceipt } from "../stream/receipt";
export { planStreamChunks, type BuildStreamPrepareOptions, type StreamChunk } from "../stream/sender";

export const generateStreamCredentials: Task<typeof credentials.generateStreamCredentials> = task(
  credentials.generateStreamCredentials,
);
export const deriveStreamKeys: Task<typeof crypto.deriveStreamKeys> = task(crypto.deriveStreamKeys);
export const encryptStreamData: Task<typeof crypto.encryptStreamData> = task(crypto.encryptStreamData);
export const decryptStreamData: Task<typeof crypto.decryptStreamData> = task(crypto.decryptStreamData);
export const generateStreamFulfillment: Task<typeof crypto.generateStreamFulfillment> = task(
  crypto.generateStreamFulfillment,
);
export const generateStreamCondition: Task<typeof crypto.generateStreamCondition> = task(
  crypto.generateStreamCondition,
);
export const decryptStreamPacket: Task<typeof packet.decryptStreamPacket> = task(packet.decryptStreamPacket);
export const verifyStreamReceipt: Task<typeof receipt.verifyStreamReceipt> = task(receipt.verifyStreamReceipt);
export const decodeStreamPaymentTag: Task<typeof receiver.decodeStreamPaymentTag> = task(
  receiver.decodeStreamPaymentTag,
);
export const buildStreamPrepare: Task<typeof sender.buildStreamPrepare> = task(sender.buildStreamPrepare);

/** Encodes one STREAM frame; throws `IlpCodecError` for a value that does not fit its field. */
export const encodeStreamFrame: Sync<typeof frames.encodeStreamFrame> = sync(frames.encodeStreamFrame);
/** Decodes one STREAM frame; throws `IlpCodecError` for truncated or invalid bytes. */
export const decodeStreamFrame: Sync<typeof frames.decodeStreamFrame> = sync(frames.decodeStreamFrame);
/** Encodes a STREAM packet (clear text, before encryption); throws `IlpCodecError` for an unencodable frame or amount. */
export const encodeStreamPacket: Sync<typeof packet.encodeStreamPacket> = sync(packet.encodeStreamPacket);
/** Decodes a clear-text STREAM packet; throws `IlpCodecError` for truncated or invalid bytes. */
export const decodeStreamPacket: Sync<typeof packet.decodeStreamPacket> = sync(packet.decodeStreamPacket);
/** Decodes a STREAM receipt; throws `IlpCodecError` when it is not a valid receipt. */
export const decodeStreamReceipt: Sync<typeof receipt.decodeStreamReceipt> = sync(receipt.decodeStreamReceipt);

type DecisionMethods = "accept" | "temporaryDecline" | "finalDecline";

/** A prepare that reached a known connection: `accept` or decline it, each returning a `Promise`. */
export type StreamPendingReply = Omit<receiver.StreamPendingReply, DecisionMethods> &
  Promisified<Pick<receiver.StreamPendingReply, DecisionMethods>>;

export type StreamFinalReply = receiver.StreamFinalReply;

export type StreamReply = StreamFinalReply | StreamPendingReply;

/** Answers a Prepare addressed to this server: either a final reply, or a pending one awaiting the application's decision. */
export const createStreamReply = async (
  config: Parameters<typeof receiver.createStreamReply>[0],
  prepare: Parameters<typeof receiver.createStreamReply>[1],
): Promise<StreamReply> => {
  const reply = await task(receiver.createStreamReply)(config, prepare);

  if (reply.type === "final") return reply;
  const { accept, temporaryDecline, finalDecline, ...data } = reply;

  return {
    ...data,
    accept: task(accept),
    temporaryDecline: task(temporaryDecline),
    finalDecline: task(finalDecline),
  };
};
