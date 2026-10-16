import * as Effect from "effect/Effect";
import * as Result from "effect/Result";
import { IlpPacketType } from "../ilp/codes";
import type { IlpCodecError } from "../ilp/errors";
import type { IlpPrepare } from "../ilp/packets";
import { sha256 } from "../internal/bytes";
import { encrypt, keysForSecret } from "./crypto";
import { StreamError } from "./errors";
import { hmac } from "./key-cache";
import type { StreamFrame } from "./frames";
import { encodeStreamPacket } from "./packet";

/** One Prepare's worth of a payment. */
export interface StreamChunk {
  /** Amount of this packet. */
  readonly chunkAmount: bigint;
  /** What is still unsent after this packet. */
  readonly remainingAfter: bigint;
}

/** Inputs of {@link buildStreamPrepare}. */
export interface BuildStreamPrepareOptions {
  /** Destination ILP address from the receiver's SPSP/Open Payments credentials. */
  readonly destination: string;
  /** The shared secret (32 bytes by convention) from the receiver's credentials. */
  readonly sharedSecret: Uint8Array;
  /** Amount of this packet, in the sender's units; the Prepare's `amount` and the `StreamMoney` shares. */
  readonly amount: bigint;
  /**
   * Minimum amount the receiver must credit, in the receiver's units (it rejects with `F04` below it).
   * Defaults to `amount`, which suits a same-asset path; across an exchange, pass `amount` times the lowest
   * acceptable exchange rate. `0n` accepts any delivery.
   */
  readonly minDestinationAmount?: bigint;
  /** Packet sequence number, starting at 1 for a connection. */
  readonly sequence: bigint;
  /** The sender's own ILP address, announced in a `ConnectionNewAddress` frame on sequence 1. */
  readonly sourceAddress: string;
  /** Prepare expiry. */
  readonly expiresAt: Date;
  /** Optional application payload, sent as a `StreamData` frame on stream 1 at offset 0. */
  readonly additionalData?: Uint8Array;
  /**
   * Use a random execution condition that nobody can fulfill, so no money moves. A receiver answers with `F05` and a
   * STREAM reply (read it with `decryptStreamPacket`) whose `prepareAmount` is the amount that arrived. That is the
   * exchange-rate probe `@interledger/pay` runs before a payment. Defaults to `false`.
   */
  readonly unfulfillable?: boolean;
}

/**
 * Splits `remaining` into packets of at most `maxPacketAmount`, stopping after `maxChunks` (the rest is left for the
 * next run). A `maxPacketAmount` ≤ 0 means "no limit": one packet with everything. Returns `[]` when there is
 * nothing to send.
 */
export function planStreamChunks(
  remaining: bigint,
  maxPacketAmount: bigint,
  maxChunks: number,
): ReadonlyArray<StreamChunk> {
  if (remaining <= 0n || maxChunks <= 0) return [];

  if (maxPacketAmount <= 0n) return [{ chunkAmount: remaining, remainingAfter: 0n }];
  const chunks: StreamChunk[] = [];
  let left = remaining;

  while (left > 0n && chunks.length < maxChunks) {
    const chunkAmount = left > maxPacketAmount ? maxPacketAmount : left;
    left -= chunkAmount;
    chunks.push({ chunkAmount, remainingAfter: left });
  }

  return chunks;
}

/**
 * Builds the ILP Prepare for one STREAM packet carrying `amount` on stream 1.
 *
 * The STREAM packet holds `ConnectionNewAddress` (sequence 1 only), `StreamMoney(1, amount)` and optionally
 * `StreamData(1, 0, additionalData)`; it is encrypted with a fresh IV, so rebuilding the same chunk yields a
 * different, equally valid Prepare. The execution condition is `SHA-256(HMAC(fulfillmentKey, encryptedData))`,
 * which only the holder of the shared secret can fulfill (or random when `unfulfillable`).
 *
 * Fails with `StreamError` (`invalid-key`) for an empty shared secret, or `IlpCodecError` when `amount`,
 * `sequence` or `sourceAddress` cannot be encoded into the STREAM packet. `destination`, `expiresAt` and the size of
 * the packet are checked by `encodePrepare` when the returned Prepare is encoded.
 */
export function buildStreamPrepare(
  options: BuildStreamPrepareOptions,
): Effect.Effect<IlpPrepare, StreamError | IlpCodecError> {
  if (options.sharedSecret.length === 0) {
    return Effect.fail(new StreamError({ reason: "invalid-key", message: "shared secret must not be empty" }));
  }

  const frames: StreamFrame[] = [];

  if (options.sequence === 1n) frames.push({ type: "ConnectionNewAddress", sourceAccount: options.sourceAddress });
  frames.push({ type: "StreamMoney", streamId: 1n, shares: options.amount });

  if (options.additionalData && options.additionalData.length > 0) {
    frames.push({ type: "StreamData", streamId: 1n, offset: 0n, data: options.additionalData });
  }

  const plaintext = encodeStreamPacket({
    sequence: options.sequence,
    ilpPacketType: IlpPacketType.Prepare,
    prepareAmount: options.minDestinationAmount ?? options.amount,
    frames,
  });

  if (Result.isFailure(plaintext)) return Effect.fail(plaintext.failure);

  return Effect.promise(async () => {
    const { encryptionKey, fulfillmentKey } = await keysForSecret(options.sharedSecret);
    const data = await encrypt(encryptionKey, plaintext.success);

    return {
      amount: options.amount,
      expiresAt: options.expiresAt,
      executionCondition: options.unfulfillable
        ? crypto.getRandomValues(new Uint8Array(32))
        : await sha256(await hmac(fulfillmentKey, data)),
      destination: options.destination,
      data,
    };
  });
}
