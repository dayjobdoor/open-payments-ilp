import * as Effect from "effect/Effect";
import * as Result from "effect/Result";
import { codecFail, type IlpCodecError } from "../ilp/errors";
import { readOer, writeOer } from "../ilp/oer";
import { decrypt, keysForSecret, STREAM_ENCRYPTION_OVERHEAD } from "./crypto";
import { StreamError } from "./errors";
import { readFrame, writeFrame, type StreamFrame } from "./frames";

/** The only STREAM protocol version. */
const STREAM_VERSION = 1;

/** A decoded (plaintext) STREAM packet. */
export interface StreamPacket {
  /** Packet sequence number (uint64). */
  readonly sequence: bigint;
  /** The ILP packet type this STREAM packet travels in: 12 Prepare, 13 Fulfill, 14 Reject. */
  readonly ilpPacketType: number;
  /** In a Prepare: the minimum destination amount. In a reply: the amount the receiver got. */
  readonly prepareAmount: bigint;
  readonly frames: ReadonlyArray<StreamFrame>;
}

/**
 * Serializes a STREAM packet (unencrypted): `UInt8 version=1 | UInt8 ilpPacketType | VarUInt sequence |
 * VarUInt prepareAmount | VarUInt frameCount | frames`.
 * Fails with `IlpCodecError` when a number is out of range or a frame is unencodable.
 */
export function encodeStreamPacket(packet: StreamPacket): Result.Result<Uint8Array<ArrayBuffer>, IlpCodecError> {
  return writeOer((out) => {
    out.writeUInt8(STREAM_VERSION);
    out.writeUInt8(packet.ilpPacketType);
    out.writeVarUInt(packet.sequence);
    out.writeVarUInt(packet.prepareAmount);
    out.writeVarUInt(BigInt(packet.frames.length));

    for (const frame of packet.frames) writeFrame(out, frame);
  });
}

/**
 * Parses a plaintext STREAM packet. Frames of unknown type are skipped, as RFC 29 requires.
 * Fails with `IlpCodecError` for an unsupported version, truncation, or malformed contents of a known frame.
 * Bytes after the last frame are ignored.
 */
export function decodeStreamPacket(bytes: Uint8Array): Result.Result<StreamPacket, IlpCodecError> {
  return readOer(bytes, (reader) => {
    const version = reader.readUInt8();

    if (version !== STREAM_VERSION) codecFail("invalid-field", `unsupported STREAM version ${version}`);
    const ilpPacketType = reader.readUInt8();
    const sequence = reader.readVarUInt();
    const prepareAmount = reader.readVarUInt();
    const frameCount = reader.readVarUInt();
    const frames: StreamFrame[] = [];

    // Every frame takes at least its type byte and a length byte, so a larger count can only be truncated.
    if (frameCount * 2n > BigInt(reader.remaining)) codecFail("truncated", `${frameCount} frames declared`);
    const count = Number(frameCount);

    for (let i = 0; i < count; i++) {
      const frame = readFrame(reader);

      if (frame) frames.push(frame);
    }

    return { sequence, ilpPacketType, prepareAmount, frames };
  });
}

/** What {@link decryptStreamPacket} checks the decrypted packet against. */
export interface ExpectedStreamPacket {
  /** The sequence number of the request this reply answers. */
  readonly sequence?: bigint;
  /**
   * The ILP packet type the reply travels in: `IlpPacketType.Fulfill` for a Fulfill's data, `IlpPacketType.Reject`
   * for a Reject's, `IlpPacketType.Prepare` for a Prepare's.
   */
  readonly ilpPacketType?: number;
}

/** Options of {@link decryptStreamPacket}. */
export interface DecryptStreamPacketOptions {
  /**
   * Bind the packet to its request. A connection's replies are all encrypted under the same key, so without this a
   * connector can replay an older reply (with another `prepareAmount`) into a later exchange, or hand a Reject's data
   * over as a Fulfill's. A mismatch fails with `StreamError` (`unexpected-packet`).
   */
  readonly expect?: ExpectedStreamPacket;
}

/**
 * Decrypts and parses the STREAM packet in an ILP packet's `data` under `sharedSecret`: the sender's view of a
 * Fulfill or Reject (how much arrived, receipts, `ConnectionClose`, asset details) and the receiver's of a Prepare.
 *
 * A reply is only authentic for the exchange that produced it when its `sequence` and `ilpPacketType` match the
 * request and the ILP reply type. Pass them as `options.expect`, as `@interledger/pay` checks them; the decrypted
 * packet is returned unchecked otherwise.
 *
 * Fails with `StreamError` (`invalid-key` for an empty secret, `decryption-failed` for data that is too short or
 * does not authenticate, e.g. a reply from a connector rather than the receiver, `unexpected-packet` when
 * `options.expect` does not match) or `IlpCodecError` when the decrypted packet is malformed.
 */
export function decryptStreamPacket(
  sharedSecret: Uint8Array,
  data: Uint8Array,
  options: DecryptStreamPacketOptions = {},
): Effect.Effect<StreamPacket, StreamError | IlpCodecError> {
  if (sharedSecret.length === 0) {
    return Effect.fail(new StreamError({ reason: "invalid-key", message: "shared secret must not be empty" }));
  }

  if (data.length < STREAM_ENCRYPTION_OVERHEAD) {
    return Effect.fail(new StreamError({ reason: "decryption-failed", message: "ciphertext is too short" }));
  }

  return Effect.gen(function* () {
    const plaintext = yield* Effect.promise(async () => {
      const { encryptionKey } = await keysForSecret(sharedSecret);

      return decrypt(encryptionKey, data).catch(() => undefined);
    });

    if (plaintext === undefined) {
      return yield* Effect.fail(new StreamError({ reason: "decryption-failed", message: "authentication failed" }));
    }

    const packet = yield* Effect.fromResult(decodeStreamPacket(plaintext));
    const expected = options.expect;

    if (expected?.sequence !== undefined && packet.sequence !== expected.sequence) {
      return yield* Effect.fail(
        new StreamError({
          reason: "unexpected-packet",
          message: `expected sequence ${expected.sequence}, got ${packet.sequence}`,
        }),
      );
    }

    if (expected?.ilpPacketType !== undefined && packet.ilpPacketType !== expected.ilpPacketType) {
      return yield* Effect.fail(
        new StreamError({
          reason: "unexpected-packet",
          message: `expected ILP packet type ${expected.ilpPacketType}, got ${packet.ilpPacketType}`,
        }),
      );
    }

    return packet;
  });
}
