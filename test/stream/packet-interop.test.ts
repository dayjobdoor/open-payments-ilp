import * as Result from "effect/Result";
import { describe, expect, it } from "vite-plus/test";
import { IlpPacketType } from "../../src/ilp";
import {
  decodeStreamFrame,
  decodeStreamPacket,
  encodeStreamFrame,
  encodeStreamPacket,
  StreamErrorCode,
  StreamFrameType,
  type StreamFrame,
  type StreamPacket,
} from "../../src/stream";
import { mutations } from "../support/prng";
import { MAX_UINT64, normalizeReference, Reference, referencePacket } from "../support/stream-oracle";

const bytes = (...values: number[]): Uint8Array => Uint8Array.from(values);

const allFrames: StreamFrame[] = [
  { type: "ConnectionClose", errorCode: StreamErrorCode.ApplicationError, errorMessage: "bye ✓" },
  { type: "ConnectionNewAddress", sourceAccount: "test.sender.abc" },
  { type: "ConnectionAssetDetails", sourceAssetCode: "USD", sourceAssetScale: 9 },
  { type: "ConnectionMaxData", maxOffset: 0n },
  { type: "ConnectionDataBlocked", maxOffset: MAX_UINT64 },
  { type: "ConnectionMaxStreamId", maxStreamId: 65535n },
  { type: "ConnectionStreamIdBlocked", maxStreamId: 256n },
  { type: "StreamClose", streamId: 1n, errorCode: StreamErrorCode.NoError, errorMessage: "" },
  { type: "StreamMoney", streamId: 1n, shares: 0n },
  { type: "StreamMoney", streamId: MAX_UINT64, shares: MAX_UINT64 },
  { type: "StreamMaxMoney", streamId: 3n, receiveMax: MAX_UINT64, totalReceived: 12345678901234n },
  { type: "StreamMoneyBlocked", streamId: 3n, sendMax: 255n, totalSent: 0n },
  { type: "StreamData", streamId: 1n, offset: 0n, data: new Uint8Array(0) },
  { type: "StreamData", streamId: 2n, offset: 1n << 40n, data: Uint8Array.from({ length: 400 }, (_, i) => i & 0xff) },
  { type: "StreamMaxData", streamId: 1n, maxOffset: 1n << 32n },
  { type: "StreamDataBlocked", streamId: 1n, maxOffset: 127n },
  { type: "StreamReceipt", streamId: 1n, receipt: Uint8Array.from({ length: 58 }, (_, i) => i) },
];

const packets: StreamPacket[] = [
  { sequence: 0n, ilpPacketType: IlpPacketType.Prepare, prepareAmount: 0n, frames: [] },
  { sequence: MAX_UINT64, ilpPacketType: IlpPacketType.Fulfill, prepareAmount: MAX_UINT64, frames: [allFrames[8]!] },
  { sequence: 1n, ilpPacketType: IlpPacketType.Prepare, prepareAmount: 1_000_000n, frames: allFrames },
  { sequence: 255n, ilpPacketType: IlpPacketType.Reject, prepareAmount: 256n, frames: allFrames.slice(0, 7) },
];

const ours = <A, E>(result: Result.Result<A, E>): A => Result.getOrThrow(result);

const referenceDecodes = (wire: Uint8Array): Reference.Packet | undefined => {
  try {
    return Reference.Packet._deserializeUnencrypted(Buffer.from(wire));
  } catch {
    return undefined;
  }
};

describe("STREAM packet codec matches ilp-protocol-stream", () => {
  it("exposes the frame type bytes of RFC 29", () => {
    const referenceFrameTypes: Record<string, string | number> = Reference.FrameType;
    const referenceErrorCodes: Record<string, string | number> = Reference.ErrorCode;

    for (const [name, value] of Object.entries(StreamFrameType)) expect(referenceFrameTypes[name]).toBe(value);

    for (const [name, value] of Object.entries(StreamErrorCode)) expect(referenceErrorCodes[name]).toBe(value);
  });

  it.each(allFrames.map((frame, i) => [i, frame] as const))("encodes frame #%i byte for byte", (_i, frame) => {
    const mine = ours(encodeStreamFrame(frame));

    const reference = new Reference.Packet(1, Reference.IlpPacketType.Prepare, 0, [
      referencePacket({ sequence: 1n, ilpPacketType: 12, prepareAmount: 0n, frames: [frame] }).frames[0]!,
    ]);

    // Skip the 4-byte packet header (version, type, 1-byte-VarUInt sequence, 1-byte-VarUInt amount) and count byte.
    expect(
      Buffer.from(reference._serialize())
        .subarray(2 + 2 + 2 + 2)
        .equals(Buffer.from(mine)),
    ).toBe(true);
  });

  it.each(packets.map((packet, i) => [i, packet] as const))(
    "encodes packet #%i byte for byte and decodes it back",
    (_i, packet) => {
      const mine = ours(encodeStreamPacket(packet));

      expect(Buffer.from(mine).equals(referencePacket(packet)._serialize())).toBe(true);
      expect(ours(decodeStreamPacket(mine))).toEqual(packet);
    },
  );

  it.each(packets.map((packet, i) => [i, packet] as const))(
    "decodes the reference's packet #%i to equal values",
    (_i, packet) => {
      const wire = referencePacket(packet)._serialize();

      expect(ours(decodeStreamPacket(wire))).toEqual(packet);
      expect(normalizeReference(Reference.Packet._deserializeUnencrypted(wire))).toEqual(packet);
    },
  );

  it("decodes a single frame and reports unknown frame types as undefined", () => {
    expect(ours(decodeStreamFrame(ours(encodeStreamFrame(allFrames[1]!))))).toEqual(allFrames[1]);
    expect(ours(decodeStreamFrame(bytes(99, 2, 1, 2)))).toBeUndefined();
  });

  it("skips unknown frame types and keeps the known ones, as the reference does", () => {
    const known = ours(encodeStreamFrame({ type: "StreamMoney", streamId: 1n, shares: 5n }));
    const unknown = bytes(0x7f, 3, 9, 9, 9);
    const wire = Uint8Array.of(1, 12, 1, 1, 1, 0, 1, 2, ...unknown, ...known);
    const mine = ours(decodeStreamPacket(wire));

    expect(mine.frames).toEqual([{ type: "StreamMoney", streamId: 1n, shares: 5n }]);
    expect(normalizeReference(Reference.Packet._deserializeUnencrypted(Buffer.from(wire)))).toEqual(mine);
  });

  it("saturates over-wide receiveMax / sendMax to 2^64-1 like the reference", () => {
    const wide = bytes(9, 1, 0, 0, 0, 0, 0, 0, 0, 0);
    const contents = Uint8Array.of(1, 1, ...wide, 1, 4);
    const frame = Uint8Array.of(StreamFrameType.StreamMaxMoney, contents.length, ...contents);
    const wire = Uint8Array.of(1, 12, 1, 1, 1, 0, 1, 1, ...frame);
    const mine = ours(decodeStreamPacket(wire));

    expect(mine.frames[0]).toEqual({ type: "StreamMaxMoney", streamId: 1n, receiveMax: MAX_UINT64, totalReceived: 4n });
    expect(normalizeReference(Reference.Packet._deserializeUnencrypted(Buffer.from(wire)))).toEqual(mine);
  });

  it("rejects values above uint64 when encoding", () => {
    const tooBig = { sequence: 1n << 64n, ilpPacketType: 12, prepareAmount: 0n, frames: [] };
    const tooBigMoney: StreamFrame = { type: "StreamMoney", streamId: 1n, shares: 1n << 64n };

    expect(Result.isFailure(encodeStreamPacket(tooBig))).toBe(true);
    expect(Result.isFailure(encodeStreamFrame(tooBigMoney))).toBe(true);
    expect(Result.isFailure(encodeStreamFrame({ type: "ConnectionNewAddress", sourceAccount: "not an address" }))).toBe(
      true,
    );
  });

  it("rejects an unsupported version and every strict prefix of a valid packet", () => {
    const wire = ours(encodeStreamPacket(packets[2]!));
    const wrongVersion = wire.slice();
    wrongVersion[0] = 2;

    expect(Result.isFailure(decodeStreamPacket(wrongVersion))).toBe(true);
    expect(referenceDecodes(wrongVersion)).toBeUndefined();

    for (let length = 0; length < wire.length; length++) {
      const prefix = wire.slice(0, length);
      const mine = decodeStreamPacket(prefix);

      // A prefix that ends exactly on a frame boundary still declares more frames than it has: truncated.
      expect(Result.isFailure(mine)).toBe(true);
      expect(referenceDecodes(prefix)).toBeUndefined();
    }
  });

  it("fails fast as truncated when the declared frame count cannot fit in the input", () => {
    // version 1, Prepare, sequence 1, amount 0, then a count of 2^64-1 (8 bytes) followed by a single frame.
    const huge = Uint8Array.from([1, 12, 1, 1, 1, 0, 8, ...Array.from({ length: 8 }, () => 0xff), 17, 2, 1, 1]);
    const result = decodeStreamPacket(huge);

    expect(Result.isFailure(result) && result.failure.reason).toBe("truncated");
    expect(referenceDecodes(huge)).toBeUndefined();

    // A count of 1000 with a few bytes of frames left.
    const many = Uint8Array.from([1, 12, 1, 1, 1, 0, 2, 0x03, 0xe8, 17, 2, 1, 1]);
    const tooMany = decodeStreamPacket(many);

    expect(Result.isFailure(tooMany) && tooMany.failure.reason).toBe("truncated");
    expect(referenceDecodes(many)).toBeUndefined();
  });

  it("agrees with the reference on seeded random mutations", () => {
    let both = 0;
    let neither = 0;
    const disagreements: string[] = [];

    for (const [index, packet] of packets.entries()) {
      const wire = ours(encodeStreamPacket(packet));

      for (const mutated of mutations(wire, 600, 0xfeed + index)) {
        const mine = decodeStreamPacket(mutated);
        const theirs = referenceDecodes(mutated);

        if (Result.isSuccess(mine) && theirs) {
          both++;
          expect(mine.success).toEqual(normalizeReference(theirs));
        } else if (Result.isFailure(mine) && !theirs) {
          neither++;
        } else {
          disagreements.push(
            `${Buffer.from(mutated).toString("hex")} mine=${Result.isSuccess(mine)} theirs=${theirs !== undefined}`,
          );
        }
      }
    }

    expect(disagreements).toEqual([]);
    expect(both).toBeGreaterThan(200);
    expect(neither).toBeGreaterThan(200);
  }, 30_000);
});
