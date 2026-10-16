import { describe, expect, it } from "vite-plus/test";
import * as Result from "effect/Result";
import { OerReader, OerWriter, readOer, writeOer } from "../../src/ilp";

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function written(write: (writer: OerWriter) => void): string {
  return hex(Result.getOrThrow(writeOer(write)));
}

describe("OER length determinants", () => {
  it.each([
    [0, "00"],
    [127, "7f"],
    [128, "8180"],
    [255, "81ff"],
    [256, "820100"],
    [65535, "82ffff"],
    [65536, "83010000"],
  ])("writes length %i as %s and reads it back", (length, encoded) => {
    expect(written((w) => w.writeLengthPrefix(length))).toBe(encoded);
    expect(Result.getOrThrow(readOer(Buffer.from(encoded, "hex"), (r) => r.readLengthPrefix()))).toBe(length);
  });

  it.each([
    ["a zero-byte prefix", "80"],
    ["a long form for a short length", "817f"],
    ["a leading zero byte", "820080"],
    ["a prefix wider than 4 bytes", "850000000000"],
  ])("rejects %s", (_name, encoded) => {
    const result = readOer(Buffer.from(encoded, "hex"), (r) => r.readLengthPrefix());

    expect(Result.isFailure(result)).toBe(true);
  });
});

describe("VarUInt", () => {
  it.each([
    [0n, "0100"],
    [255n, "01ff"],
    [256n, "020100"],
    [(1n << 32n) - 1n, "04ffffffff"],
    [1n << 32n, "050100000000"],
    [(1n << 64n) - 1n, "08ffffffffffffffff"],
  ])("encodes %s minimally as %s", (value, encoded) => {
    expect(written((w) => w.writeVarUInt(value))).toBe(encoded);
    expect(Result.getOrThrow(readOer(Buffer.from(encoded, "hex"), (r) => r.readVarUInt()))).toBe(value);
  });

  it("rejects values outside uint64 on write", () => {
    expect(Result.isFailure(writeOer((w) => w.writeVarUInt(1n << 64n)))).toBe(true);
    expect(Result.isFailure(writeOer((w) => w.writeVarUInt(-1n)))).toBe(true);
  });

  it("rejects a zero-length and a nine-byte VarUInt on read, but saturates when asked", () => {
    const nine = Buffer.from("09010000000000000000", "hex");

    expect(Result.isFailure(readOer(Buffer.from("00", "hex"), (r) => r.readVarUInt()))).toBe(true);
    expect(Result.isFailure(readOer(nine, (r) => r.readVarUInt()))).toBe(true);
    expect(Result.getOrThrow(readOer(nine, (r) => r.readVarUIntSaturating()))).toBe((1n << 64n) - 1n);
  });

  it("tolerates leading zero bytes like ilp-packet does", () => {
    expect(Result.getOrThrow(readOer(Buffer.from("020001", "hex"), (r) => r.readVarUInt()))).toBe(1n);
  });
});

describe("fixed integers", () => {
  it("round-trips uint8, uint32 and uint64 big-endian", () => {
    expect(
      written((w) => {
        w.writeUInt8(0xab);
        w.writeUInt32(0x01020304);
        w.writeUInt64(0x0102030405060708n);
      }),
    ).toBe("ab010203040102030405060708");

    const read = readOer(Buffer.from("ab010203040102030405060708", "hex"), (r) => [
      r.readUInt8(),
      r.readUInt32(),
      r.readUInt64(),
    ]);

    expect(Result.getOrThrow(read)).toEqual([0xab, 0x01020304, 0x0102030405060708n]);
  });

  it.each([
    ["uint8", (w: OerWriter) => w.writeUInt8(256)],
    ["uint8", (w: OerWriter) => w.writeUInt8(-1)],
    ["uint32", (w: OerWriter) => w.writeUInt32(2 ** 32)],
    ["uint64", (w: OerWriter) => w.writeUInt64(1n << 64n)],
    ["uint64", (w: OerWriter) => w.writeUInt64(-1n)],
  ])("rejects an out-of-range %s", (_type, write) => {
    const result = writeOer(write);

    expect(Result.isFailure(result) && result.failure.reason).toBe("out-of-range");
  });

  it("reports truncation with the truncated reason", () => {
    const result = readOer(Buffer.from("0102", "hex"), (r) => r.readUInt64());

    expect(Result.isFailure(result) && result.failure.reason).toBe("truncated");
  });
});

describe("VarOctetString", () => {
  it.each([0, 1, 127, 128, 255, 256, 70_000])("round-trips %i bytes", (length) => {
    const payload = Uint8Array.from({ length }, (_, i) => i & 0xff);
    const encoded = Result.getOrThrow(writeOer((w) => w.writeVarOctetString(payload)));

    expect(Result.getOrThrow(readOer(encoded, (r) => r.readVarOctetString()))).toEqual(payload);
  });

  it("returns plain copies, not views of the input (even for a Node Buffer)", () => {
    const input = Buffer.from([1, 5]);
    const out = Result.getOrThrow(readOer(input, (r) => r.readVarOctetString()));
    input[1] = 9;

    expect(out).toEqual(Uint8Array.of(5));
    expect(Buffer.isBuffer(out)).toBe(false);
  });

  it("rejects a length that exceeds the remaining input", () => {
    const result = readOer(Buffer.from("05aabb", "hex"), (r) => r.readVarOctetString());

    expect(Result.isFailure(result) && result.failure.reason).toBe("truncated");
  });
});

describe("ILP timestamp (YYYYMMDDhhmmssfff)", () => {
  const read = (text: string) => readOer(Buffer.from(text, "ascii"), (r) => r.readTimestamp());

  it("round-trips millisecond-precision UTC dates", () => {
    const date = new Date(Date.UTC(2026, 9, 11, 13, 5, 9, 7));
    const encoded = Result.getOrThrow(writeOer((w) => w.writeTimestamp(date)));

    expect(Buffer.from(encoded).toString("ascii")).toBe("20261011130509007");
    expect(Result.getOrThrow(read("20261011130509007")).getTime()).toBe(date.getTime());
  });

  it("keeps years 0000–0099 literal and accepts the epoch", () => {
    expect(Result.getOrThrow(read("00990101000000000")).getUTCFullYear()).toBe(99);
    expect(Result.getOrThrow(read("19700101000000000")).getTime()).toBe(0);
  });

  it.each([
    "2026101113050900",
    "2026-10-11T13:05:09",
    "20261301000000000",
    "20260230000000000",
    "20261011240000000",
    "20261011126000000",
    "20261011120060000",
    "abcdefghijklmnopq",
  ])("rejects %s", (text) => {
    expect(Result.isFailure(read(text))).toBe(true);
  });

  it("refuses to write an invalid date or a year beyond four digits", () => {
    expect(Result.isFailure(writeOer((w) => w.writeTimestamp(new Date(Number.NaN))))).toBe(true);
    expect(Result.isFailure(writeOer((w) => w.writeTimestamp(new Date(Date.UTC(10_000, 0, 1)))))).toBe(true);
  });
});

describe("nested VarOctetStrings", () => {
  const payload = (length: number): Uint8Array => Uint8Array.from({ length }, (_, i) => (i * 7) & 0xff);

  // Lengths either side of every length-determinant width change, plus a body larger than the writer's first buffer.
  it.each([0, 1, 127, 128, 255, 256, 65_535, 65_536, 70_000])(
    "writeNested is byte-identical to writeVarOctetString for %i bytes",
    (length) => {
      const body = payload(length);

      const nested = written((w) => {
        w.writeUInt8(0xaa);
        w.writeNested((inner) => inner.writeOctets(body));
        w.writeUInt8(0xbb);
      });

      const flat = written((w) => {
        w.writeUInt8(0xaa);
        w.writeVarOctetString(body);
        w.writeUInt8(0xbb);
      });

      expect(nested).toBe(flat);
    },
  );

  it("nests inside nested content, each level sized by what it holds", () => {
    const inner = payload(200);

    const nested = written((w) =>
      w.writeNested((outer) => {
        outer.writeUInt8(1);
        outer.writeNested((deep) => deep.writeOctets(inner));
        outer.writeUInt8(2);
      }),
    );

    const manual = written((w) => {
      const middle = Result.getOrThrow(
        writeOer((m) => {
          m.writeUInt8(1);
          m.writeVarOctetString(inner);
          m.writeUInt8(2);
        }),
      );

      w.writeVarOctetString(middle);
    });

    expect(nested).toBe(manual);
  });

  it("readNested reads the contents without disturbing the outer cursor", () => {
    const encoded = Result.getOrThrow(
      writeOer((w) => {
        w.writeNested((inner) => {
          inner.writeUInt8(7);
          inner.writeVarOctetString(payload(300));
        });

        w.writeUInt8(9);
      }),
    );

    const read = readOer(Buffer.from(encoded), (r) => {
      const nested: OerReader = r.readNested();
      const first = nested.readUInt8();
      const body = nested.readVarOctetString();

      return { first, body, innerLeft: nested.remaining, after: r.readUInt8(), outerLeft: r.remaining };
    });

    expect(Result.getOrThrow(read)).toEqual({ first: 7, body: payload(300), innerLeft: 0, after: 9, outerLeft: 0 });
  });

  it("readNested fails on truncation and the nested reader cannot read past its contents", () => {
    expect(Result.isFailure(readOer(Buffer.from("05aabb", "hex"), (r) => r.readNested()))).toBe(true);

    // The outer input still has bb cc left, but the nested contents are only aa.
    const overrun = readOer(Buffer.from("01aabbcc", "hex"), (r) => {
      const nested = r.readNested();
      nested.readUInt8();

      return nested.readUInt8();
    });

    expect(Result.isFailure(overrun) && overrun.failure.reason).toBe("truncated");
  });

  it("surfaces an error thrown while writing nested content as a codec failure", () => {
    const result = writeOer((w) => w.writeNested((inner) => inner.writeUInt8(256)));

    expect(Result.isFailure(result) && result.failure.reason).toBe("out-of-range");
  });
});

describe("OER numbers across their width boundaries", () => {
  it.each([
    0n,
    0xffn,
    0x100n,
    0xffffn,
    0x1_0000n,
    0xff_ffffn,
    0x100_0000n,
    0xffff_ffffn,
    0x1_0000_0000n,
    0xff_ffff_ffffn,
    0xffff_ffff_ffffn,
    0x1_0000_0000_0000n,
    2n ** 53n - 1n,
    2n ** 53n,
    2n ** 53n + 1n,
    0xff_ffff_ffff_ffffn,
    0x100_0000_0000_0000n,
    (1n << 64n) - 1n,
  ])("VarUInt and UInt64 round-trip %s with the minimal VarUInt width", (value) => {
    const varUInt = Result.getOrThrow(writeOer((w) => w.writeVarUInt(value)));
    const width = Math.max(1, Math.ceil(value.toString(2).length / 8));

    expect(varUInt).toHaveLength(1 + width);
    expect(varUInt[0]).toBe(width);
    expect(Result.getOrThrow(readOer(varUInt, (r) => r.readVarUInt()))).toBe(value);

    const fixed = Result.getOrThrow(writeOer((w) => w.writeUInt64(value)));

    expect(Buffer.from(fixed).readBigUInt64BE()).toBe(value);
    expect(Result.getOrThrow(readOer(fixed, (r) => r.readUInt64()))).toBe(value);
  });

  it.each([0, 1, 255, 256, 65_535, 65_536, 0xff_ffff, 0x100_0000, 0xffff_ffff])("UInt32 round-trips %i", (value) => {
    const encoded = Result.getOrThrow(writeOer((w) => w.writeUInt32(value)));

    expect(Buffer.from(encoded).readUInt32BE()).toBe(value);
    expect(Result.getOrThrow(readOer(encoded, (r) => r.readUInt32()))).toBe(value);
  });
});

describe("ILP timestamp calendar rules", () => {
  const read = (text: string) => readOer(Buffer.from(text, "ascii"), (r) => r.readTimestamp());

  it.each([
    ["a leap day in a year divisible by 4", "20240229235959999"],
    ["a leap day in a year divisible by 400", "20000229000000000"],
    ["the last day of every 31-day month", "20260131000000000"],
    ["a leap day in year 0000, which is divisible by 400", "00000229000000000"],
    ["the largest year", "99991231235959999"],
  ])("accepts %s", (_name, text) => {
    expect(Result.isSuccess(read(text))).toBe(true);
    expect(
      Buffer.from(Result.getOrThrow(writeOer((w) => w.writeTimestamp(Result.getOrThrow(read(text)))))).toString(),
    ).toBe(text);
  });

  it.each([
    ["Feb 29 in a common year", "20230229000000000"],
    ["Feb 29 in a year divisible by 100 but not 400", "19000229000000000"],
    ["April 31", "20260431000000000"],
    ["day 00", "20260100000000000"],
    ["month 00", "20260001000000000"],
    ["a non-digit in the milliseconds", "2026101113050900a"],
    ["a byte just below the digits", "2026101113050900/"],
    ["a byte just above the digits", "2026101113050900:"],
    ["a non-ASCII byte", "2026101113050900\u00e9"],
  ])("rejects %s", (_name, text) => {
    expect(Result.isFailure(read(text))).toBe(true);
  });

  it("is exact over every day of a leap year and its neighbours", () => {
    for (const year of [1999, 2000, 2023, 2024, 2100]) {
      for (let month = 1; month <= 12; month++) {
        const days = new Date(Date.UTC(year, month, 0)).getUTCDate();

        const at = (day: number) =>
          `${String(year).padStart(4, "0")}${String(month).padStart(2, "0")}${String(day).padStart(2, "0")}000000000`;

        expect(Result.isSuccess(read(at(days)))).toBe(true);
        expect(Result.isFailure(read(at(days + 1)))).toBe(true);
      }
    }
  });
});
