import * as IlpPacket from "ilp-packet";
import * as Result from "effect/Result";
import { describe, expect, it } from "vite-plus/test";
import {
  deserializeFulfill,
  deserializePacket,
  deserializePrepare,
  deserializeReject,
  deserializeReply,
  IlpErrorCode,
  IlpPacketType,
  isFulfill,
  isReject,
  serializeFulfill,
  serializePrepare,
  serializeReject,
  serializeReply,
  type IlpFulfill,
  type IlpPrepare,
  type IlpReject,
} from "../../src/ilp";
import { mutations } from "../support/prng";

const MAX_UINT64 = (1n << 64n) - 1n;

const condition = (fill: number): Uint8Array => new Uint8Array(32).fill(fill);

const prepares: IlpPrepare[] = [
  {
    amount: 0n,
    expiresAt: new Date(Date.UTC(2026, 0, 2, 3, 4, 5, 6)),
    executionCondition: condition(1),
    destination: "g.us.bank.alice",
    data: new Uint8Array(0),
  },
  {
    amount: MAX_UINT64,
    expiresAt: new Date(Date.UTC(2099, 11, 31, 23, 59, 59, 999)),
    executionCondition: condition(0xff),
    destination: "test3.a_b-c~d.e",
    data: Uint8Array.from({ length: 300 }, (_, i) => i & 0xff),
  },
  {
    amount: 1n,
    expiresAt: new Date(Date.UTC(2026, 5, 15, 0, 0, 0, 0)),
    executionCondition: condition(7),
    destination: `g.${"a".repeat(1021)}`,
    data: Uint8Array.from({ length: 32767 }, (_, i) => (i * 7) & 0xff),
  },
  {
    amount: 1_000_000_007n,
    expiresAt: new Date(Date.UTC(2026, 5, 15, 12, 30, 15, 500)),
    executionCondition: condition(0),
    destination: "private.x",
    data: Uint8Array.of(0),
  },
];

const fulfills: IlpFulfill[] = [
  { fulfillment: condition(0), data: new Uint8Array(0) },
  { fulfillment: condition(0xab), data: Uint8Array.from({ length: 200 }, (_, i) => i) },
];

const rejects: IlpReject[] = [
  { code: "F00", triggeredBy: "", message: "", data: new Uint8Array(0) },
  { code: "T04", triggeredBy: "g.us.connector", message: "Insufficient liquidity", data: Uint8Array.of(1, 2, 3) },
  { code: "R99", triggeredBy: "peer.config", message: "ünïcödé ✓ message", data: new Uint8Array(0) },
  { code: "F99", triggeredBy: "g.a", message: "x".repeat(300), data: new Uint8Array(1000) },
];

function theirsPrepare(prepare: IlpPrepare): IlpPacket.IlpPrepare {
  return {
    amount: prepare.amount.toString(),
    executionCondition: Buffer.from(prepare.executionCondition),
    expiresAt: prepare.expiresAt,
    destination: prepare.destination,
    data: Buffer.from(prepare.data),
  };
}

function ours<A, E>(result: Result.Result<A, E>): A {
  return Result.getOrThrow(result);
}

describe("ILP packet codec matches ilp-packet byte for byte", () => {
  it.each(prepares.map((p, i) => [i, p] as const))("serializes Prepare #%i identically", (_i, prepare) => {
    const bytes = ours(serializePrepare(prepare));

    expect(Buffer.from(bytes).equals(IlpPacket.serializeIlpPrepare(theirsPrepare(prepare)))).toBe(true);
  });

  it.each(fulfills.map((p, i) => [i, p] as const))("serializes Fulfill #%i identically", (_i, fulfill) => {
    const bytes = ours(serializeFulfill(fulfill));

    expect(
      Buffer.from(bytes).equals(
        IlpPacket.serializeIlpFulfill({
          fulfillment: Buffer.from(fulfill.fulfillment),
          data: Buffer.from(fulfill.data),
        }),
      ),
    ).toBe(true);
  });

  it.each(rejects.map((p, i) => [i, p] as const))("serializes Reject #%i identically", (_i, reject) => {
    const bytes = ours(serializeReject(reject));

    expect(Buffer.from(bytes).equals(IlpPacket.serializeIlpReject({ ...reject, data: Buffer.from(reject.data) }))).toBe(
      true,
    );
  });

  it.each(prepares.map((p, i) => [i, p] as const))("parses ilp-packet's Prepare #%i", (_i, prepare) => {
    const parsed = ours(deserializePrepare(IlpPacket.serializeIlpPrepare(theirsPrepare(prepare))));

    expect(parsed).toEqual(prepare);
  });

  it.each(fulfills.map((p, i) => [i, p] as const))("parses ilp-packet's Fulfill #%i", (_i, fulfill) => {
    const wire = IlpPacket.serializeIlpFulfill({
      fulfillment: Buffer.from(fulfill.fulfillment),
      data: Buffer.from(fulfill.data),
    });

    expect(ours(deserializeFulfill(wire))).toEqual(fulfill);
  });

  it.each(rejects.map((p, i) => [i, p] as const))("parses ilp-packet's Reject #%i", (_i, reject) => {
    const wire = IlpPacket.serializeIlpReject({ ...reject, data: Buffer.from(reject.data) });

    expect(ours(deserializeReject(wire))).toEqual(reject);
  });

  it("is parsed back by ilp-packet to the same values (amount 0 and 2^64-1 included)", () => {
    for (const prepare of prepares) {
      const parsed = IlpPacket.deserializeIlpPrepare(Buffer.from(ours(serializePrepare(prepare))));

      expect(parsed.amount).toBe(prepare.amount.toString());
      expect(parsed.expiresAt.getTime()).toBe(prepare.expiresAt.getTime());
      expect(parsed.destination).toBe(prepare.destination);
      expect(Buffer.from(prepare.data).equals(parsed.data)).toBe(true);
    }
  });
});

describe("ILP packet dispatch", () => {
  it("deserializePacket tags each packet with its type byte", () => {
    const prepare = prepares[0]!;
    const fulfill = fulfills[0]!;
    const reject = rejects[1]!;

    expect(ours(deserializePacket(ours(serializePrepare(prepare))))).toEqual({
      type: IlpPacketType.Prepare,
      data: prepare,
    });
    expect(ours(deserializePacket(ours(serializeFulfill(fulfill))))).toEqual({
      type: IlpPacketType.Fulfill,
      data: fulfill,
    });
    expect(ours(deserializePacket(ours(serializeReject(reject))))).toEqual({
      type: IlpPacketType.Reject,
      data: reject,
    });
  });

  it("deserializeReply accepts Fulfill and Reject only", () => {
    expect(isFulfill(ours(deserializeReply(ours(serializeFulfill(fulfills[0]!)))))).toBe(true);
    expect(isReject(ours(deserializeReply(ours(serializeReject(rejects[0]!)))))).toBe(true);

    const result = deserializeReply(ours(serializePrepare(prepares[0]!)));

    expect(Result.isFailure(result) && result.failure.reason).toBe("invalid-type");
  });

  it("serializeReply picks the codec by reply shape", () => {
    expect(ours(serializeReply(fulfills[1]!))).toEqual(ours(serializeFulfill(fulfills[1]!)));
    expect(ours(serializeReply(rejects[1]!))).toEqual(ours(serializeReject(rejects[1]!)));
  });

  it("rejects empty input and unknown type bytes", () => {
    const empty = deserializePacket(new Uint8Array(0));
    const unknown = deserializePacket(Uint8Array.of(99, 0));

    expect(Result.isFailure(empty) && empty.failure.reason).toBe("truncated");
    expect(Result.isFailure(unknown) && unknown.failure.reason).toBe("invalid-type");
  });

  it("exposes the RFC 27 error codes", () => {
    expect(IlpErrorCode.F02_UNREACHABLE).toBe("F02");
    expect(IlpErrorCode.R99_APPLICATION_ERROR).toBe("R99");
    expect(Object.values(IlpErrorCode)).toHaveLength(21);
    expect(Object.values(IlpErrorCode).every((code) => /^[FTR][0-9]{2}$/.test(code))).toBe(true);
  });
});

describe("ILP serializers refuse invalid input", () => {
  const base = prepares[0]!;

  it.each([
    ["amount above uint64", { ...base, amount: MAX_UINT64 + 1n }],
    ["negative amount", { ...base, amount: -1n }],
    ["short condition", { ...base, executionCondition: new Uint8Array(31) }],
    ["invalid destination", { ...base, destination: "not an address" }],
    ["destination without a segment", { ...base, destination: "g" }],
    ["oversize data", { ...base, data: new Uint8Array(32768) }],
    ["invalid date", { ...base, expiresAt: new Date(Number.NaN) }],
  ])("Prepare with %s", (_name, prepare) => {
    expect(Result.isFailure(serializePrepare(prepare))).toBe(true);
  });

  it("Fulfill with a short fulfillment", () => {
    expect(Result.isFailure(serializeFulfill({ fulfillment: new Uint8Array(31), data: new Uint8Array(0) }))).toBe(true);
  });

  it.each([
    ["two-character code", { ...rejects[0]!, code: "F0" }],
    ["lowercase-free code with space", { ...rejects[0]!, code: "F 0" }],
    ["invalid triggeredBy", { ...rejects[0]!, triggeredBy: "nope" }],
    ["non-ASCII code", { ...rejects[0]!, code: "F0é" }],
  ])("Reject with %s", (_name, reject) => {
    expect(Result.isFailure(serializeReject(reject))).toBe(true);
  });
});

describe("ILP deserializers on malformed input", () => {
  const samples = [
    ...prepares.slice(0, 2).map((p) => ours(serializePrepare(p))),
    ...fulfills.map((p) => ours(serializeFulfill(p))),
    ...rejects.slice(0, 3).map((p) => ours(serializeReject(p))),
  ];

  const theirsParses = (bytes: Uint8Array): boolean => {
    try {
      IlpPacket.deserializeIlpPacket(Buffer.from(bytes));

      return true;
    } catch {
      return false;
    }
  };

  it("rejects every strict prefix of a valid packet, as ilp-packet does", () => {
    for (const sample of samples) {
      for (let length = 0; length < sample.length; length++) {
        const prefix = sample.slice(0, length);

        expect(Result.isFailure(deserializePacket(prefix))).toBe(true);
        expect(theirsParses(prefix)).toBe(false);
      }
    }
  });

  it("agrees with ilp-packet on seeded random mutations: accepts only what it accepts, rejects at least what it rejects", () => {
    // Where we are stricter than ilp-packet the reason must be one of these deliberate tightenings:
    // calendar-invalid timestamps, non-ASCII bytes that ilp-packet masks, malformed reject codes, oversize data.
    const stricter = new Set(["invalid-timestamp", "invalid-field", "out-of-range"]);
    let compared = 0;
    let rejectedByBoth = 0;

    for (const [index, sample] of samples.entries()) {
      for (const mutated of mutations(sample, 600, 0x5eed + index)) {
        const mine = deserializePacket(mutated);
        const theirsOk = theirsParses(mutated);
        compared++;

        if (Result.isSuccess(mine)) {
          expect(theirsOk).toBe(true);
          const theirs = IlpPacket.deserializeIlpPacket(Buffer.from(mutated));

          if (mine.success.type === IlpPacketType.Prepare && theirs.type === IlpPacket.Type.TYPE_ILP_PREPARE) {
            expect(mine.success.data.amount.toString()).toBe(theirs.data.amount);

            // ilp-packet maps years 0000–0099 to 1900–1999 (Date.UTC); we keep them literal.
            if (mine.success.data.expiresAt.getUTCFullYear() >= 100) {
              expect(mine.success.data.expiresAt.getTime()).toBe(theirs.data.expiresAt.getTime());
            }

            expect(mine.success.data.destination).toBe(theirs.data.destination);
            expect(Buffer.from(mine.success.data.data).equals(theirs.data.data)).toBe(true);
          }
        } else if (theirsOk) {
          expect(stricter.has(mine.failure.reason)).toBe(true);
        } else {
          rejectedByBoth++;
        }
      }
    }

    expect(compared).toBeGreaterThan(3000);
    expect(rejectedByBoth).toBeGreaterThan(300);
  }, 30_000);

  it("rejects the wrong packet type for each typed parser", () => {
    expect(Result.isFailure(deserializePrepare(ours(serializeFulfill(fulfills[0]!))))).toBe(true);
    expect(Result.isFailure(deserializeFulfill(ours(serializeReject(rejects[0]!))))).toBe(true);
    expect(Result.isFailure(deserializeReject(ours(serializePrepare(prepares[0]!))))).toBe(true);
  });

  it("rejects a Prepare whose destination is not a valid ILP address", () => {
    const wire = Buffer.from(ours(serializePrepare(prepares[0]!)));
    const at = wire.indexOf(Buffer.from("g.us"));
    wire[at] = 0x21;

    expect(Result.isFailure(deserializePrepare(wire))).toBe(true);
    expect(() => IlpPacket.deserializeIlpPrepare(wire)).toThrow();
  });

  it("ignores bytes after the envelope, as ilp-packet does", () => {
    const wire = Uint8Array.of(...ours(serializeFulfill(fulfills[0]!)), 0xde, 0xad);

    expect(Result.isSuccess(deserializeFulfill(wire))).toBe(true);
    expect(() => IlpPacket.deserializeIlpFulfill(Buffer.from(wire))).not.toThrow();
  });

  it("rejects Prepare data above 32767 bytes even when well framed", () => {
    // Hand-framed because the serializer refuses to produce it.
    const body = Buffer.concat([
      Buffer.alloc(8),
      Buffer.from("20260101000000000"),
      Buffer.alloc(32),
      Buffer.from([3]),
      Buffer.from("g.a"),
      Buffer.from([0x82, 0x80, 0x00]),
      Buffer.alloc(32768),
    ]);

    const wire = Buffer.concat([
      Buffer.from([12, 0x83]),
      Buffer.from([0, (body.length >> 8) & 0xff, body.length & 0xff]),
      body,
    ]);

    const result = deserializePrepare(
      Buffer.concat([Buffer.from([12, 0x82, (body.length >> 8) & 0xff, body.length & 0xff]), body]),
    );

    expect(wire.length).toBeGreaterThan(0);
    expect(Result.isFailure(result) && result.failure.reason).toBe("out-of-range");
  });
});
