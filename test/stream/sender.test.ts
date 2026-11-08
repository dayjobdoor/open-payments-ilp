import * as Effect from "effect/Effect";
import { describe, expect, it } from "vite-plus/test";
import * as Result from "effect/Result";
import { IlpPacketType } from "../../src/ilp";
import {
  buildStreamPrepare,
  decryptStreamData,
  decryptStreamPacket,
  deriveStreamKeys,
  generateStreamCredentials,
  planStreamChunks,
} from "../../src/stream";
import { byteSource } from "../support/prng";
import { Reference, referencePacket } from "../support/stream-oracle";

const bytes = byteSource(0x5e4d);

describe("planStreamChunks", () => {
  it("splits 250 with a 100 cap into 100, 100, 50 and tracks what remains", () => {
    expect(planStreamChunks(250n, 100n, 100)).toEqual([
      { chunkAmount: 100n, remainingAfter: 150n },
      { chunkAmount: 100n, remainingAfter: 50n },
      { chunkAmount: 50n, remainingAfter: 0n },
    ]);
  });

  it("stops at the chunk cap instead of planning the whole remainder", () => {
    expect(planStreamChunks(10_000_000n, 1n, 3)).toEqual([
      { chunkAmount: 1n, remainingAfter: 9_999_999n },
      { chunkAmount: 1n, remainingAfter: 9_999_998n },
      { chunkAmount: 1n, remainingAfter: 9_999_997n },
    ]);
  });

  it("sends everything in one packet when there is no packet limit", () => {
    expect(planStreamChunks(500n, 0n, 10)).toEqual([{ chunkAmount: 500n, remainingAfter: 0n }]);
    expect(planStreamChunks(500n, -1n, 10)).toEqual([{ chunkAmount: 500n, remainingAfter: 0n }]);
  });

  it("plans nothing when there is nothing to send or no budget", () => {
    expect(planStreamChunks(0n, 100n, 10)).toEqual([]);
    expect(planStreamChunks(-5n, 100n, 10)).toEqual([]);
    expect(planStreamChunks(100n, 100n, 0)).toEqual([]);
  });

  it("never exceeds the packet limit and conserves the amount, including beyond 2^53", () => {
    const remaining = (1n << 64n) - 1n;
    const max = 1n << 60n;
    const chunks = planStreamChunks(remaining, max, 100);

    expect(chunks.every((chunk) => chunk.chunkAmount > 0n && chunk.chunkAmount <= max)).toBe(true);
    expect(chunks.reduce((sum, chunk) => sum + chunk.chunkAmount, 0n)).toBe(remaining);
    expect(chunks.at(-1)?.remainingAfter).toBe(0n);
  });

  it("emits a single exact chunk when the amount equals the limit", () => {
    expect(planStreamChunks(100n, 100n, 5)).toEqual([{ chunkAmount: 100n, remainingAfter: 0n }]);
  });
});

describe("buildStreamPrepare", () => {
  const serverAddress = "test.stream.sender.example";

  it("uses a fresh IV per build, so rebuilding a chunk changes data and condition", async () => {
    const credentials = await Effect.runPromise(generateStreamCredentials({ serverSecret: bytes(32), serverAddress }));

    const options = {
      destination: credentials.ilpAddress,
      sharedSecret: credentials.sharedSecret,
      amount: 50n,
      sequence: 2n,
      sourceAddress: serverAddress,
      expiresAt: new Date("2030-01-01T00:00:00.000Z"),
    };

    const first = await Effect.runPromise(buildStreamPrepare(options));
    const second = await Effect.runPromise(buildStreamPrepare(options));

    expect(Buffer.from(first.data).equals(Buffer.from(second.data))).toBe(false);
    expect(Buffer.from(first.executionCondition).equals(Buffer.from(second.executionCondition))).toBe(false);
    expect(first.amount).toBe(50n);
    expect(first.destination).toBe(credentials.ilpAddress);
    expect(first.expiresAt).toEqual(options.expiresAt);
    expect(first.executionCondition).toHaveLength(32);
  });
});

describe("buildStreamPrepare and the ConnectionNewAddress frame", () => {
  const serverAddress = "test.stream.sender.example";
  const expiresAt = new Date("2030-01-01T00:00:00.000Z");

  const credentials = () => Effect.runPromise(generateStreamCredentials({ serverSecret: bytes(32), serverAddress }));

  // `@interledger/pay` asks for the receiver's asset details with `new ConnectionNewAddressFrame("")`.
  it.each([
    ["omitted", {}],
    ["empty", { sourceAddress: "" }],
  ])(
    "sends an empty address on sequence 1 when sourceAddress is %s, byte for byte like the reference",
    async (_name, extra) => {
      const { ilpAddress, sharedSecret } = await credentials();

      const prepare = await Effect.runPromise(
        buildStreamPrepare({ destination: ilpAddress, sharedSecret, amount: 10n, sequence: 1n, expiresAt, ...extra }),
      );

      const { encryptionKey } = await Effect.runPromise(deriveStreamKeys(sharedSecret));
      const plaintext = await Effect.runPromise(decryptStreamData(encryptionKey, prepare.data));

      const expected = referencePacket({
        sequence: 1n,
        ilpPacketType: IlpPacketType.Prepare,
        prepareAmount: 10n,
        frames: [
          { type: "ConnectionNewAddress", sourceAccount: "" },
          { type: "StreamMoney", streamId: 1n, shares: 10n },
        ],
      })._serialize();

      expect(Buffer.from(plaintext).equals(expected)).toBe(true);

      // And the reference's own decoder reads it back as an empty address.
      const theirs = Reference.Packet._deserializeUnencrypted(Buffer.from(plaintext));
      const frame = theirs.frames[0];

      expect(frame).toBeInstanceOf(Reference.ConnectionNewAddressFrame);
      expect(frame instanceof Reference.ConnectionNewAddressFrame && frame.sourceAccount).toBe("");

      const mine = await Effect.runPromise(decryptStreamPacket(sharedSecret, prepare.data));

      expect(mine.frames[0]).toEqual({ type: "ConnectionNewAddress", sourceAccount: "" });
    },
  );

  it("announces a real source address unchanged, and only on sequence 1", async () => {
    const { ilpAddress, sharedSecret } = await credentials();

    const build = (sequence: bigint) =>
      Effect.runPromise(
        buildStreamPrepare({
          destination: ilpAddress,
          sharedSecret,
          amount: 10n,
          sequence,
          sourceAddress: "test.sender.abc",
          expiresAt,
        }),
      );

    const first = await Effect.runPromise(decryptStreamPacket(sharedSecret, (await build(1n)).data));
    const second = await Effect.runPromise(decryptStreamPacket(sharedSecret, (await build(2n)).data));

    expect(first.frames[0]).toEqual({ type: "ConnectionNewAddress", sourceAccount: "test.sender.abc" });
    expect(second.frames.map((frame) => frame.type)).toEqual(["StreamMoney"]);
  });

  it.each(["not an address", "test", "test.", "test.a b", " "])(
    "still refuses the non-empty invalid address %j as invalid-address",
    async (sourceAddress) => {
      const { ilpAddress, sharedSecret } = await credentials();

      const result = await Effect.runPromise(
        Effect.result(
          buildStreamPrepare({
            destination: ilpAddress,
            sharedSecret,
            amount: 1n,
            sequence: 1n,
            sourceAddress,
            expiresAt,
          }),
        ),
      );

      expect(Result.isFailure(result) && result.failure).toMatchObject({
        _tag: "IlpCodecError",
        reason: "invalid-address",
      });
    },
  );

  it("does not check the source address on later sequences, where it is not sent", async () => {
    const { ilpAddress, sharedSecret } = await credentials();

    const prepare = await Effect.runPromise(
      buildStreamPrepare({
        destination: ilpAddress,
        sharedSecret,
        amount: 1n,
        sequence: 2n,
        sourceAddress: "not an address",
        expiresAt,
      }),
    );

    expect(prepare.amount).toBe(1n);
  });
});
