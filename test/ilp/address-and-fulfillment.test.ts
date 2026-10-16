import { createHash } from "node:crypto";
import * as Effect from "effect/Effect";
import * as Result from "effect/Result";
import { isValidIlpAddress as theirsIsValid } from "ilp-packet";
import { describe, expect, it } from "vite-plus/test";
import { conditionFromFulfillment, fulfillmentMatchesCondition, isValidIlpAddress } from "../../src/ilp";

const valid = [
  "g.a",
  "g.us.bank.alice",
  "private.x",
  "example.a.b",
  "peer.config",
  "self.x",
  "test.a",
  "test1.a",
  "test2.a",
  "test3.a",
  "local.host",
  "g.A-Z_a~z.0-9",
  `g.${"a".repeat(1021)}`,
];

const invalid = [
  "",
  "g",
  "g.",
  "g..a",
  "g.a.",
  ".g.a",
  "G.a",
  "test4.a",
  "test0.a",
  "unknown.a",
  "g.a b",
  "g.a/b",
  "g.é",
  "g.a\n",
  "g.a:b",
  `g.${"a".repeat(1022)}`,
];

describe("ILP address validation (RFC 15)", () => {
  it.each(valid)("accepts %s", (address) => {
    expect(isValidIlpAddress(address)).toBe(true);
  });

  it.each(invalid)("rejects %j", (address) => {
    expect(isValidIlpAddress(address)).toBe(false);
  });

  it("agrees with ilp-packet on the whole corpus", () => {
    for (const address of [...valid, ...invalid]) expect(isValidIlpAddress(address)).toBe(theirsIsValid(address));
  });
});

describe("fulfillment / condition", () => {
  const fulfillment = Uint8Array.from({ length: 32 }, (_, i) => i * 3);
  const condition = new Uint8Array(createHash("sha256").update(fulfillment).digest());

  it("derives the condition as SHA-256 of the fulfillment", async () => {
    expect(await Effect.runPromise(conditionFromFulfillment(fulfillment))).toEqual(condition);
  });

  it("accepts only the matching preimage", async () => {
    expect(await Effect.runPromise(fulfillmentMatchesCondition(fulfillment, condition))).toBe(true);

    const other = fulfillment.slice();
    other.fill(0xff, 31);

    expect(await Effect.runPromise(fulfillmentMatchesCondition(other, condition))).toBe(false);
    expect(await Effect.runPromise(fulfillmentMatchesCondition(fulfillment, new Uint8Array(32)))).toBe(false);
  });

  it("treats inputs that are not 32 bytes as non-matching", async () => {
    expect(await Effect.runPromise(fulfillmentMatchesCondition(fulfillment.slice(1), condition))).toBe(false);
    expect(await Effect.runPromise(fulfillmentMatchesCondition(fulfillment, condition.slice(1)))).toBe(false);
  });

  it("refuses to derive a condition from a fulfillment that is not 32 bytes", async () => {
    const result = await Effect.runPromise(Effect.result(conditionFromFulfillment(new Uint8Array(31))));

    expect(Result.isFailure(result) && result.failure.reason).toBe("invalid-field");
  });

  it("accepts a Node Buffer and a SharedArrayBuffer-backed view", async () => {
    const shared = new Uint8Array(new SharedArrayBuffer(32));
    shared.set(fulfillment);

    expect(await Effect.runPromise(fulfillmentMatchesCondition(Buffer.from(fulfillment), condition))).toBe(true);
    expect(await Effect.runPromise(fulfillmentMatchesCondition(shared, condition))).toBe(true);
  });
});
