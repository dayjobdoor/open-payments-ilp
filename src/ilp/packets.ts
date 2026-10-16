import * as Result from "effect/Result";
import { isValidIlpAddress } from "./address";
import { IlpPacketType } from "./codes";
import { codecFail, type IlpCodecError } from "./errors";
import { asciiBytes, asciiString, type OerReader, readOer, writeOer } from "./oer";
import { utf8Encode } from "../internal/bytes";

/** Maximum `data` length of any ILP packet (RFC 27). */
export const MAX_ILP_DATA_LENGTH = 32767;

/** ILP Prepare: a conditional transfer request. */
export interface IlpPrepare {
  /** Amount in the receiving account's units (uint64). */
  readonly amount: bigint;
  /** Absolute expiry, millisecond precision, UTC. */
  readonly expiresAt: Date;
  /** 32-byte SHA-256 hash of the fulfillment. */
  readonly executionCondition: Uint8Array;
  /** Destination ILP address. */
  readonly destination: string;
  /** Opaque end-to-end payload (≤ 32767 bytes). */
  readonly data: Uint8Array;
}

/** ILP Fulfill: the preimage proving the Prepare was paid. */
export interface IlpFulfill {
  /** 32-byte preimage of the Prepare's `executionCondition`. */
  readonly fulfillment: Uint8Array;
  readonly data: Uint8Array;
}

/** ILP Reject: the Prepare was not paid. */
export interface IlpReject {
  /** Three-character error code, e.g. `F02` (see `IlpErrorCode`). */
  readonly code: string;
  /** Address of the node that rejected, or `""` when unknown. */
  readonly triggeredBy: string;
  /** Human-readable diagnostic (UTF-8). */
  readonly message: string;
  readonly data: Uint8Array;
}

/** Either reply to a Prepare. */
export type IlpReply = IlpFulfill | IlpReject;

/** A decoded ILP packet tagged with its wire type byte. */
export type IlpPacket =
  | { readonly type: typeof IlpPacketType.Prepare; readonly data: IlpPrepare }
  | { readonly type: typeof IlpPacketType.Fulfill; readonly data: IlpFulfill }
  | { readonly type: typeof IlpPacketType.Reject; readonly data: IlpReject };

const CONDITION_LENGTH = 32;

const lenientUtf8 = new TextDecoder();

/** Type guard: `reply` is a Fulfill. */
export function isFulfill(reply: IlpReply): reply is IlpFulfill {
  return "fulfillment" in reply;
}

/** Type guard: `reply` is a Reject. */
export function isReject(reply: IlpReply): reply is IlpReject {
  return "code" in reply;
}

/**
 * Serializes a Prepare to its OER wire form (RFC 27).
 * Fails with `IlpCodecError` when `amount` is outside uint64, the condition is not 32 bytes,
 * `destination` is not a valid ILP address, `expiresAt` is not a representable date, or `data` exceeds 32767 bytes.
 */
export function serializePrepare(prepare: IlpPrepare): Result.Result<Uint8Array<ArrayBuffer>, IlpCodecError> {
  return writeOer((out) => {
    if (prepare.executionCondition.length !== CONDITION_LENGTH) {
      codecFail("invalid-field", "executionCondition must be 32 bytes");
    }

    if (!isValidIlpAddress(prepare.destination)) codecFail("invalid-address", "destination is not a valid ILP address");
    checkData(prepare.data);
    out.writeUInt8(IlpPacketType.Prepare);
    out.writeNested((body) => {
      body.writeUInt64(prepare.amount);
      body.writeTimestamp(prepare.expiresAt);
      body.writeOctets(prepare.executionCondition);
      body.writeVarOctetString(asciiBytes(prepare.destination, "destination"));
      body.writeVarOctetString(prepare.data);
    });
  });
}

/**
 * Parses a Prepare. Fails with `IlpCodecError` on truncation, a wrong type byte, a non-canonical length,
 * an invalid destination address or timestamp, or `data` over 32767 bytes.
 * Bytes after the envelope are ignored, as in ilp-packet.
 */
export function deserializePrepare(bytes: Uint8Array): Result.Result<IlpPrepare, IlpCodecError> {
  return readOer(bytes, readPrepare);
}

/** Serializes a Fulfill. Fails with `IlpCodecError` unless the fulfillment is 32 bytes and `data` ≤ 32767 bytes. */
export function serializeFulfill(fulfill: IlpFulfill): Result.Result<Uint8Array<ArrayBuffer>, IlpCodecError> {
  return writeOer((out) => {
    if (fulfill.fulfillment.length !== CONDITION_LENGTH) codecFail("invalid-field", "fulfillment must be 32 bytes");
    checkData(fulfill.data);
    out.writeUInt8(IlpPacketType.Fulfill);
    out.writeNested((body) => {
      body.writeOctets(fulfill.fulfillment);
      body.writeVarOctetString(fulfill.data);
    });
  });
}

/** Parses a Fulfill. Fails with `IlpCodecError` on truncation, a wrong type byte or oversize `data`. */
export function deserializeFulfill(bytes: Uint8Array): Result.Result<IlpFulfill, IlpCodecError> {
  return readOer(bytes, readFulfill);
}

/**
 * Serializes a Reject. Fails with `IlpCodecError` unless `code` is three printable ASCII characters,
 * `triggeredBy` is `""` or a valid ILP address, and `data` ≤ 32767 bytes.
 */
export function serializeReject(reject: IlpReject): Result.Result<Uint8Array<ArrayBuffer>, IlpCodecError> {
  return writeOer((out) => {
    const code = asciiBytes(reject.code, "code");

    if (!isErrorCode(code)) codecFail("invalid-field", "code must be three printable ASCII characters");

    if (reject.triggeredBy !== "" && !isValidIlpAddress(reject.triggeredBy)) {
      codecFail("invalid-address", "triggeredBy is not a valid ILP address");
    }

    checkData(reject.data);
    out.writeUInt8(IlpPacketType.Reject);
    out.writeNested((body) => {
      body.writeOctets(code);
      body.writeVarOctetString(asciiBytes(reject.triggeredBy, "triggeredBy"));
      body.writeVarOctetString(utf8Encode(reject.message));
      body.writeVarOctetString(reject.data);
    });
  });
}

/**
 * Parses a Reject. The message is decoded leniently (invalid UTF-8 becomes U+FFFD) because it is diagnostic only.
 * Fails with `IlpCodecError` on truncation, a wrong type byte, a malformed code or `triggeredBy`, or oversize `data`.
 */
export function deserializeReject(bytes: Uint8Array): Result.Result<IlpReject, IlpCodecError> {
  return readOer(bytes, readReject);
}

/** Serializes whichever reply `reply` is. */
export function serializeReply(reply: IlpReply): Result.Result<Uint8Array<ArrayBuffer>, IlpCodecError> {
  return isFulfill(reply) ? serializeFulfill(reply) : serializeReject(reply);
}

/** Parses a Fulfill or Reject by its type byte. Any other type byte fails with reason `invalid-type`. */
export function deserializeReply(bytes: Uint8Array): Result.Result<IlpReply, IlpCodecError> {
  return readOer(bytes, (reader) => {
    const type = peekType(bytes);

    if (type === IlpPacketType.Fulfill) return readFulfill(reader);

    if (type === IlpPacketType.Reject) return readReject(reader);

    return codecFail("invalid-type", `expected a Fulfill or Reject, got packet type ${type}`);
  });
}

/** Parses any ILP packet by its type byte. An unknown type byte fails with reason `invalid-type`. */
export function deserializePacket(bytes: Uint8Array): Result.Result<IlpPacket, IlpCodecError> {
  return readOer(bytes, (reader): IlpPacket => {
    const type = peekType(bytes);

    if (type === IlpPacketType.Prepare) return { type, data: readPrepare(reader) };

    if (type === IlpPacketType.Fulfill) return { type, data: readFulfill(reader) };

    if (type === IlpPacketType.Reject) return { type, data: readReject(reader) };

    return codecFail("invalid-type", `unknown ILP packet type ${type}`);
  });
}

function peekType(bytes: Uint8Array): number {
  const type = bytes[0];

  if (type === undefined) return codecFail("truncated", "empty packet");

  return type;
}

function checkData(data: Uint8Array): void {
  if (data.length > MAX_ILP_DATA_LENGTH) {
    codecFail("out-of-range", `data of ${data.length} bytes exceeds ${MAX_ILP_DATA_LENGTH}`);
  }
}

function isErrorCode(code: Uint8Array): boolean {
  return code.length === 3 && code.every((byte) => byte >= 0x21 && byte <= 0x7e);
}

function readEnvelope(reader: OerReader, expected: number): OerReader {
  const type = reader.readUInt8();

  if (type !== expected) codecFail("invalid-type", `expected packet type ${expected}, got ${type}`);

  return reader.readNested();
}

function readData(body: OerReader): Uint8Array {
  const data = body.readVarOctetString();
  checkData(data);

  return data;
}

function readPrepare(reader: OerReader): IlpPrepare {
  const body = readEnvelope(reader, IlpPacketType.Prepare);
  const amount = body.readUInt64();
  const expiresAt = body.readTimestamp();
  const executionCondition = body.readOctets(CONDITION_LENGTH);
  const destination = asciiString(body.readVarOctetString(), "destination");

  if (!isValidIlpAddress(destination)) codecFail("invalid-address", "destination is not a valid ILP address");

  return { amount, expiresAt, executionCondition, destination, data: readData(body) };
}

function readFulfill(reader: OerReader): IlpFulfill {
  const body = readEnvelope(reader, IlpPacketType.Fulfill);
  const fulfillment = body.readOctets(CONDITION_LENGTH);

  return { fulfillment, data: readData(body) };
}

function readReject(reader: OerReader): IlpReject {
  const body = readEnvelope(reader, IlpPacketType.Reject);
  const codeBytes = body.readOctets(3);

  if (!isErrorCode(codeBytes)) codecFail("invalid-field", "code must be three printable ASCII characters");
  const triggeredBy = asciiString(body.readVarOctetString(), "triggeredBy");

  if (triggeredBy !== "" && !isValidIlpAddress(triggeredBy)) {
    codecFail("invalid-address", "triggeredBy is not a valid ILP address");
  }

  const message = lenientUtf8.decode(body.readVarOctetString());

  return { code: asciiString(codeBytes, "code"), triggeredBy, message, data: readData(body) };
}
