import { randomBytes } from "node:crypto";
import * as Effect from "effect/Effect";
import { describe, expect, it } from "vite-plus/test";
import { buildStreamPrepare, generateStreamCredentials, planStreamChunks } from "../../src/stream";

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
    const credentials = await Effect.runPromise(
      generateStreamCredentials({ serverSecret: new Uint8Array(randomBytes(32)), serverAddress }),
    );

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
