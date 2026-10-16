import * as Effect from "effect/Effect";
import * as Result from "effect/Result";
import { IlpErrorCode, IlpPacketType } from "../ilp/codes";
import type { IlpFulfill, IlpPrepare, IlpReject, IlpReply } from "../ilp/packets";
import { constantTimeEqual, sha256, toHex, utf8Encode } from "../internal/bytes";
import { checkServerConfig, openConnection, secretKeys, type SecretKeys, type StreamServerConfig } from "./credentials";
import { decrypt, encrypt, STREAM_ENCRYPTION_OVERHEAD } from "./crypto";
import { StreamError } from "./errors";
import { StreamErrorCode, type StreamDataFrame, type StreamFrame } from "./frames";
import { hmac } from "./key-cache";
import { decodeStreamPacket, encodeStreamPacket, type StreamPacket } from "./packet";
import { createStreamReceipt } from "./receipt";

const MAX_UINT64 = (1n << 64n) - 1n;

/** A Prepare that authenticated as a STREAM packet for a known connection and awaits the application's decision. */
export interface StreamPendingReply {
  readonly type: "pending";
  /** Hex SHA-256 of the destination address: a stable id for the connection. */
  readonly connectionId: string;
  /** The payment tag bound into the credentials, if any. */
  readonly paymentTag: string | undefined;
  /** `StreamData` frames the sender attached, if any. */
  readonly dataFrames: ReadonlyArray<StreamDataFrame>;
  /**
   * Fulfills the Prepare. With `totalReceived` and credentials that carry a receipt setup, the reply includes a
   * `StreamReceipt` frame for stream 1.
   */
  readonly accept: (options?: { readonly totalReceived?: bigint }) => Effect.Effect<IlpFulfill, StreamError>;
  /** Rejects with `T00` (temporary): the sender may retry. */
  readonly temporaryDecline: () => Effect.Effect<IlpReject>;
  /** Rejects with `F99` and a `ConnectionClose` frame (plus a `StreamData` frame when `applicationData` is non-empty). */
  readonly finalDecline: (applicationData?: Uint8Array | string) => Effect.Effect<IlpReject>;
}

/** A reply decided without the application (reject, or a zero-amount Fulfill). */
export interface StreamFinalReply {
  readonly type: "final";
  readonly reply: IlpReply;
}

/** Outcome of {@link createStreamReply}. */
export type StreamReply = StreamFinalReply | StreamPendingReply;

interface ReplyState {
  readonly serverAddress: string;
  readonly encryptionKey: Uint8Array | undefined;
  readonly sequence: bigint;
  readonly receivedAmount: bigint;
  readonly frames: ReadonlyArray<StreamFrame>;
}

/**
 * Answers an incoming ILP Prepare addressed to a STREAM connection, with the same decisions and the same reply
 * encodings as `@interledger/stream-receiver`'s `StreamServer.createReply`:
 *
 * - destination outside `serverAddress.<token>` → Reject `F02`
 * - token that does not authenticate, or STREAM data that does not decrypt/parse → Reject `F06`
 * - STREAM packet that is not a Prepare → Reject `F00` (empty data)
 * - `ConnectionClose` frame → Reject `F99` with a `ConnectionClose` frame
 * - execution condition ≠ `SHA-256(HMAC(fulfillmentKey, data))` → Reject `F05`
 * - amount 0 → Fulfill
 * - amount below the packet's minimum destination amount → Reject `F04`
 * - otherwise a {@link StreamPendingReply} for the application to accept or decline
 *
 * Replies carry an encrypted STREAM packet so the sender sees the received amount. A `ConnectionAssetDetails`
 * frame is added when the sender announced a new address and the credentials carry asset details.
 *
 * The caller must still enforce its own rules (expiry, replay protection, caps) before calling `accept`.
 * Fails with `StreamError` only when `config` is invalid.
 */
export function createStreamReply(
  config: StreamServerConfig,
  prepare: IlpPrepare,
): Effect.Effect<StreamReply, StreamError> {
  const invalid = checkServerConfig(config);

  if (invalid) return Effect.fail(invalid);

  return Effect.promise(async () => replyTo(await secretKeys(config.serverSecret), config.serverAddress, prepare));
}

/**
 * The payment tag bound into the credentials that `destination` carries, like `@interledger/stream-receiver`'s
 * `decodePaymentTag`: `undefined` when the destination is outside `serverAddress`, its token does not authenticate,
 * or the credentials carry no tag. Use it to route a Prepare (e.g. to an incoming payment) before answering it with
 * {@link createStreamReply}.
 * Fails with `StreamError` only when `config` is invalid.
 */
export function decodeStreamPaymentTag(
  config: StreamServerConfig,
  destination: string,
): Effect.Effect<string | undefined, StreamError> {
  const invalid = checkServerConfig(config);

  if (invalid) return Effect.fail(invalid);
  const segment = localSegment(config.serverAddress, destination);

  if (segment === undefined) return Effect.succeed(undefined);

  return Effect.promise(async () => {
    const connection = await openConnection(await secretKeys(config.serverSecret), segment);

    return connection?.details.paymentTag;
  });
}

async function replyTo(keys: SecretKeys, serverAddress: string, prepare: IlpPrepare): Promise<StreamReply> {
  let state: ReplyState = {
    serverAddress,
    encryptionKey: undefined,
    sequence: 0n,
    receivedAmount: 0n,
    frames: [],
  };

  const final = async (code: string): Promise<StreamReply> => ({ type: "final", reply: await rejectWith(state, code) });
  const segment = localSegment(serverAddress, prepare.destination);

  if (segment === undefined) return final(IlpErrorCode.F02_UNREACHABLE);
  const connection = await openConnection(keys, segment);

  if (!connection) return final(IlpErrorCode.F06_UNEXPECTED_PAYMENT);
  const { details, keys: connectionKeys } = connection;
  const { encryptionKey, fulfillmentKey } = connectionKeys;
  // Independent of the packet's contents, so it runs alongside the decryption.
  const connectionId = sha256(utf8Encode(prepare.destination)).then(toHex);
  const request = await decryptPacket(encryptionKey, prepare.data);

  if (!request) return final(IlpErrorCode.F06_UNEXPECTED_PAYMENT);

  if (request.ilpPacketType !== IlpPacketType.Prepare) return final(IlpErrorCode.F00_BAD_REQUEST);
  state = { ...state, encryptionKey, sequence: request.sequence, receivedAmount: prepare.amount };

  if (request.frames.some((frame) => frame.type === "ConnectionClose")) {
    state = { ...state, frames: [{ type: "ConnectionClose", errorCode: StreamErrorCode.NoError, errorMessage: "" }] };

    return final(IlpErrorCode.F99_APPLICATION_ERROR);
  }

  if (details.asset && request.frames.some((frame) => frame.type === "ConnectionNewAddress")) {
    state = {
      ...state,
      frames: [
        { type: "ConnectionAssetDetails", sourceAssetCode: details.asset.code, sourceAssetScale: details.asset.scale },
      ],
    };
  }

  const fulfillment = await hmac(fulfillmentKey, prepare.data);

  if (!constantTimeEqual(await sha256(fulfillment), prepare.executionCondition)) {
    return final(IlpErrorCode.F05_WRONG_CONDITION);
  }

  if (prepare.amount === 0n) return { type: "final", reply: await fulfillWith(state, fulfillment) };

  if (prepare.amount < request.prepareAmount) return final(IlpErrorCode.F04_INSUFFICIENT_DESTINATION_AMOUNT);

  return {
    type: "pending",
    connectionId: await connectionId,
    paymentTag: details.paymentTag,
    dataFrames: request.frames.filter((frame) => frame.type === "StreamData"),
    accept: (options) => {
      const totalReceived = options?.totalReceived;

      if (!details.receipt || totalReceived === undefined) return Effect.promise(() => fulfillWith(state, fulfillment));

      if (totalReceived < 0n || totalReceived > MAX_UINT64) {
        return Effect.fail(new StreamError({ reason: "invalid-option", message: "totalReceived is not a uint64" }));
      }

      const receiptSetup = details.receipt;

      return Effect.promise(async () => {
        const receipt = await createStreamReceipt(receiptSetup, totalReceived);

        return fulfillWith(
          { ...state, frames: [...state.frames, { type: "StreamReceipt", streamId: 1n, receipt }] },
          fulfillment,
        );
      });
    },
    temporaryDecline: () => Effect.promise(() => rejectWith(state, IlpErrorCode.T00_INTERNAL_ERROR)),
    finalDecline: (applicationData) => {
      const frames: StreamFrame[] = [
        ...state.frames,
        { type: "ConnectionClose", errorCode: StreamErrorCode.NoError, errorMessage: "" },
      ];

      const data =
        applicationData instanceof Uint8Array ? applicationData : applicationData && utf8Encode(applicationData);

      if (data && data.length > 0) frames.push({ type: "StreamData", streamId: 1n, offset: 0n, data });

      return Effect.promise(() => rejectWith({ ...state, frames }, IlpErrorCode.F99_APPLICATION_ERROR));
    },
  };
}

/** The STREAM packet inside `data`, or `undefined` when it does not decrypt or parse. */
async function decryptPacket(encryptionKey: Uint8Array, data: Uint8Array): Promise<StreamPacket | undefined> {
  if (data.length < STREAM_ENCRYPTION_OVERHEAD) return undefined;

  try {
    const decoded = decodeStreamPacket(await decrypt(encryptionKey, data));

    return Result.isSuccess(decoded) ? decoded.success : undefined;
  } catch {
    return undefined;
  }
}

/** `destination` minus `serverAddress.`, up to the next `.`; undefined when it is not under the server address. */
function localSegment(serverAddress: string, destination: string): string | undefined {
  if (!destination.startsWith(`${serverAddress}.`)) return undefined;
  const start = serverAddress.length + 1;
  const end = destination.indexOf(".", start);
  const segment = destination.slice(start, end === -1 ? undefined : end);

  return segment === "" ? undefined : segment;
}

/** The encrypted STREAM reply packet carried in a Fulfill/Reject, or empty when no key is established yet. */
async function replyData(state: ReplyState, ilpPacketType: number): Promise<Uint8Array<ArrayBuffer>> {
  if (!state.encryptionKey) return new Uint8Array(0);

  return encrypt(
    state.encryptionKey,
    Result.getOrThrow(
      encodeStreamPacket({
        sequence: state.sequence,
        ilpPacketType,
        prepareAmount: state.receivedAmount,
        frames: state.frames,
      }),
    ),
  );
}

async function fulfillWith(state: ReplyState, fulfillment: Uint8Array): Promise<IlpFulfill> {
  return { fulfillment, data: await replyData(state, IlpPacketType.Fulfill) };
}

async function rejectWith(state: ReplyState, code: string): Promise<IlpReject> {
  return { code, message: "", triggeredBy: state.serverAddress, data: await replyData(state, IlpPacketType.Reject) };
}
