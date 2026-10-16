import type { Result } from "effect/Result";
import { isValidIlpAddress } from "../ilp/address";
import { codecFail, type IlpCodecError } from "../ilp/errors";
import { asciiBytes, OerReader, OerWriter, readOer, writeOer } from "../ilp/oer";
import { utf8Encode } from "../internal/bytes";

const lenientUtf8 = new TextDecoder();

/** STREAM frame type bytes (RFC 29 §6). */
export const StreamFrameType = {
  ConnectionClose: 1,
  ConnectionNewAddress: 2,
  ConnectionMaxData: 3,
  ConnectionDataBlocked: 4,
  ConnectionMaxStreamId: 5,
  ConnectionStreamIdBlocked: 6,
  ConnectionAssetDetails: 7,
  StreamClose: 16,
  StreamMoney: 17,
  StreamMaxMoney: 18,
  StreamMoneyBlocked: 19,
  StreamData: 20,
  StreamMaxData: 21,
  StreamDataBlocked: 22,
  StreamReceipt: 23,
} as const;

/** STREAM error codes carried by `ConnectionClose` / `StreamClose` (RFC 29 §7). */
export const StreamErrorCode = {
  NoError: 1,
  InternalError: 2,
  EndpointBusy: 3,
  FlowControlError: 4,
  StreamIdError: 5,
  StreamStateError: 6,
  FrameFormatError: 7,
  ProtocolViolation: 8,
  ApplicationError: 9,
} as const;

/** The sender is closing the connection. */
export interface ConnectionCloseFrame {
  readonly type: "ConnectionClose";
  readonly errorCode: number;
  readonly errorMessage: string;
}

/** The sender announces the ILP address it can be reached on. */
export interface ConnectionNewAddressFrame {
  readonly type: "ConnectionNewAddress";
  readonly sourceAccount: string;
}

/** The receiver's asset, sent in reply to a `ConnectionNewAddress`. */
export interface ConnectionAssetDetailsFrame {
  readonly type: "ConnectionAssetDetails";
  readonly sourceAssetCode: string;
  readonly sourceAssetScale: number;
}

/** Connection-level data flow-control limit. */
export interface ConnectionMaxDataFrame {
  readonly type: "ConnectionMaxData";
  readonly maxOffset: bigint;
}

/** The sender is blocked by the connection data limit. */
export interface ConnectionDataBlockedFrame {
  readonly type: "ConnectionDataBlocked";
  readonly maxOffset: bigint;
}

/** Highest stream id the sender will accept. */
export interface ConnectionMaxStreamIdFrame {
  readonly type: "ConnectionMaxStreamId";
  readonly maxStreamId: bigint;
}

/** The sender is blocked by the stream id limit. */
export interface ConnectionStreamIdBlockedFrame {
  readonly type: "ConnectionStreamIdBlocked";
  readonly maxStreamId: bigint;
}

/** A stream is closing. */
export interface StreamCloseFrame {
  readonly type: "StreamClose";
  readonly streamId: bigint;
  readonly errorCode: number;
  readonly errorMessage: string;
}

/** Money for a stream; `shares` weights the Prepare amount between streams. */
export interface StreamMoneyFrame {
  readonly type: "StreamMoney";
  readonly streamId: bigint;
  readonly shares: bigint;
}

/** Stream money limit. A value wider than uint64 on the wire decodes as 2^64-1. */
export interface StreamMaxMoneyFrame {
  readonly type: "StreamMaxMoney";
  readonly streamId: bigint;
  readonly receiveMax: bigint;
  readonly totalReceived: bigint;
}

/** The sender is blocked by the stream money limit. A wire value wider than uint64 decodes as 2^64-1. */
export interface StreamMoneyBlockedFrame {
  readonly type: "StreamMoneyBlocked";
  readonly streamId: bigint;
  readonly sendMax: bigint;
  readonly totalSent: bigint;
}

/** Application data for a stream at byte `offset`. */
export interface StreamDataFrame {
  readonly type: "StreamData";
  readonly streamId: bigint;
  readonly offset: bigint;
  readonly data: Uint8Array;
}

/** Stream data flow-control limit. */
export interface StreamMaxDataFrame {
  readonly type: "StreamMaxData";
  readonly streamId: bigint;
  readonly maxOffset: bigint;
}

/** The sender is blocked by the stream data limit. */
export interface StreamDataBlockedFrame {
  readonly type: "StreamDataBlocked";
  readonly streamId: bigint;
  readonly maxOffset: bigint;
}

/** A 58-byte STREAM receipt (RFC 39) for a stream. */
export interface StreamReceiptFrame {
  readonly type: "StreamReceipt";
  readonly streamId: bigint;
  readonly receipt: Uint8Array;
}

/** Every STREAM frame this library can encode and decode. Frames of unknown type are skipped on decode. */
export type StreamFrame =
  | ConnectionCloseFrame
  | ConnectionNewAddressFrame
  | ConnectionAssetDetailsFrame
  | ConnectionMaxDataFrame
  | ConnectionDataBlockedFrame
  | ConnectionMaxStreamIdFrame
  | ConnectionStreamIdBlockedFrame
  | StreamCloseFrame
  | StreamMoneyFrame
  | StreamMaxMoneyFrame
  | StreamMoneyBlockedFrame
  | StreamDataFrame
  | StreamMaxDataFrame
  | StreamDataBlockedFrame
  | StreamReceiptFrame;

/** @internal Writes one frame: type byte then its contents as a VarOctetString. */
export function writeFrame(out: OerWriter, frame: StreamFrame): void {
  out.writeUInt8(StreamFrameType[frame.type]);
  out.writeNested((body) => writeFrameContents(body, frame));
}

/**
 * @internal Reads one frame. Returns `undefined` for an unknown frame type (its contents are skipped,
 * as RFC 29 requires); a known type with malformed contents throws.
 */
export function readFrame(reader: OerReader): StreamFrame | undefined {
  const type = reader.readUInt8();
  const contents = reader.readNested();

  switch (type) {
    case StreamFrameType.ConnectionClose:
      return {
        type: "ConnectionClose",
        errorCode: contents.readUInt8(),
        errorMessage: lenientUtf8.decode(contents.readVarOctetString()),
      };

    case StreamFrameType.ConnectionNewAddress:
      return {
        type: "ConnectionNewAddress",
        sourceAccount: lenientUtf8.decode(contents.readVarOctetString()),
      };

    case StreamFrameType.ConnectionAssetDetails:
      return {
        type: "ConnectionAssetDetails",
        sourceAssetCode: lenientUtf8.decode(contents.readVarOctetString()),
        sourceAssetScale: contents.readUInt8(),
      };

    case StreamFrameType.ConnectionMaxData:
      return { type: "ConnectionMaxData", maxOffset: contents.readVarUInt() };

    case StreamFrameType.ConnectionDataBlocked:
      return { type: "ConnectionDataBlocked", maxOffset: contents.readVarUInt() };

    case StreamFrameType.ConnectionMaxStreamId:
      return { type: "ConnectionMaxStreamId", maxStreamId: contents.readVarUInt() };

    case StreamFrameType.ConnectionStreamIdBlocked:
      return { type: "ConnectionStreamIdBlocked", maxStreamId: contents.readVarUInt() };

    case StreamFrameType.StreamClose:
      return {
        type: "StreamClose",
        streamId: contents.readVarUInt(),
        errorCode: contents.readUInt8(),
        errorMessage: lenientUtf8.decode(contents.readVarOctetString()),
      };

    case StreamFrameType.StreamMoney:
      return { type: "StreamMoney", streamId: contents.readVarUInt(), shares: contents.readVarUInt() };

    case StreamFrameType.StreamMaxMoney:
      return {
        type: "StreamMaxMoney",
        streamId: contents.readVarUInt(),
        receiveMax: contents.readVarUIntSaturating(),
        totalReceived: contents.readVarUInt(),
      };

    case StreamFrameType.StreamMoneyBlocked:
      return {
        type: "StreamMoneyBlocked",
        streamId: contents.readVarUInt(),
        sendMax: contents.readVarUIntSaturating(),
        totalSent: contents.readVarUInt(),
      };

    case StreamFrameType.StreamData:
      return {
        type: "StreamData",
        streamId: contents.readVarUInt(),
        offset: contents.readVarUInt(),
        data: contents.readVarOctetString(),
      };

    case StreamFrameType.StreamMaxData:
      return { type: "StreamMaxData", streamId: contents.readVarUInt(), maxOffset: contents.readVarUInt() };

    case StreamFrameType.StreamDataBlocked:
      return { type: "StreamDataBlocked", streamId: contents.readVarUInt(), maxOffset: contents.readVarUInt() };

    case StreamFrameType.StreamReceipt:
      return { type: "StreamReceipt", streamId: contents.readVarUInt(), receipt: contents.readVarOctetString() };

    default:
      return undefined;
  }
}

function writeFrameContents(body: OerWriter, frame: StreamFrame): void {
  switch (frame.type) {
    case "ConnectionClose":
      body.writeUInt8(frame.errorCode);
      body.writeVarOctetString(utf8Encode(frame.errorMessage));

      return;

    case "ConnectionNewAddress":
      if (!isValidIlpAddress(frame.sourceAccount)) {
        codecFail("invalid-address", "sourceAccount is not a valid ILP address");
      }

      body.writeVarOctetString(asciiBytes(frame.sourceAccount, "sourceAccount"));

      return;

    case "ConnectionAssetDetails":
      body.writeVarOctetString(utf8Encode(frame.sourceAssetCode));
      body.writeUInt8(frame.sourceAssetScale);

      return;

    case "ConnectionMaxData":
    case "ConnectionDataBlocked":
      body.writeVarUInt(frame.maxOffset);

      return;

    case "ConnectionMaxStreamId":
    case "ConnectionStreamIdBlocked":
      body.writeVarUInt(frame.maxStreamId);

      return;

    case "StreamClose":
      body.writeVarUInt(frame.streamId);
      body.writeUInt8(frame.errorCode);
      body.writeVarOctetString(utf8Encode(frame.errorMessage));

      return;

    case "StreamMoney":
      body.writeVarUInt(frame.streamId);
      body.writeVarUInt(frame.shares);

      return;

    case "StreamMaxMoney":
      body.writeVarUInt(frame.streamId);
      body.writeVarUInt(frame.receiveMax);
      body.writeVarUInt(frame.totalReceived);

      return;

    case "StreamMoneyBlocked":
      body.writeVarUInt(frame.streamId);
      body.writeVarUInt(frame.sendMax);
      body.writeVarUInt(frame.totalSent);

      return;

    case "StreamData":
      body.writeVarUInt(frame.streamId);
      body.writeVarUInt(frame.offset);
      body.writeVarOctetString(frame.data);

      return;

    case "StreamMaxData":
    case "StreamDataBlocked":
      body.writeVarUInt(frame.streamId);
      body.writeVarUInt(frame.maxOffset);

      return;

    case "StreamReceipt":
      body.writeVarUInt(frame.streamId);
      body.writeVarOctetString(frame.receipt);

      return;
  }
}

/** Serializes one frame (type byte + length-prefixed contents). Fails with `IlpCodecError` on unencodable fields. */
export function encodeStreamFrame(frame: StreamFrame): Result<Uint8Array<ArrayBuffer>, IlpCodecError> {
  return writeOer((out) => writeFrame(out, frame));
}

/**
 * Parses one frame from the start of `bytes`. An unknown frame type yields `undefined`;
 * malformed contents of a known type fail with `IlpCodecError`.
 */
export function decodeStreamFrame(bytes: Uint8Array): Result<StreamFrame | undefined, IlpCodecError> {
  return readOer(bytes, readFrame);
}
