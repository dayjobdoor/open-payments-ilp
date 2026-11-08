import { describe, expect, it } from "vite-plus/test";
import * as Result from "effect/Result";
import { IlpCodecError, OerReader, OerWriter, readOer, writeOer } from "../../src/ilp";
import { utf8String } from "../../src/ilp/oer";
import { reasonOf } from "../support/result";

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
    [0xff_ffff, "83ffffff"],
    [0x100_0000, "8401000000"],
    [0xffff_ffff, "84ffffffff"],
  ])("writes length %i as %s and reads it back", (length, encoded) => {
    expect(written((w) => w.writeLengthPrefix(length))).toBe(encoded);
    expect(Result.getOrThrow(readOer(Buffer.from(encoded, "hex"), (r) => r.readLengthPrefix()))).toBe(length);
  });

  it.each([
    ["a zero-byte prefix", "80", "non-canonical"],
    ["a long form for a short length", "817f", "non-canonical"],
    ["a leading zero byte", "820080", "non-canonical"],
    ["a 3-byte form for a 2-byte length", "8300ffff", "non-canonical"],
    ["a 3-byte form for a 1-byte length", "83000001", "non-canonical"],
    ["a 4-byte form for a 3-byte length", "8400ffffff", "non-canonical"],
    ["a 4-byte form for a 2-byte length", "840000ffff", "non-canonical"],
    ["a prefix wider than 4 bytes", "850000000000", "out-of-range"],
    ["a prefix of 127 bytes", "ff", "out-of-range"],
    ["no input at all", "", "truncated"],
    ["a prefix cut short", "82ff", "truncated"],
  ])("rejects %s", (_name, encoded, reason) => {
    const result = readOer(Buffer.from(encoded, "hex"), (r) => r.readLengthPrefix());

    expect(reasonOf(result)).toBe(reason);
  });

  it("reads a 4-byte length without allocating it: a huge announced length is just truncated", () => {
    const result = readOer(Buffer.from("84ffffffff01", "hex"), (r) => r.readVarOctetString());

    expect(reasonOf(result)).toBe("truncated");
  });

  it.each([-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 32])("refuses to write the length %s", (length) => {
    expect(reasonOf(writeOer((w) => w.writeLengthPrefix(length)))).toBe("out-of-range");
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
    expect(reasonOf(writeOer((w) => w.writeVarUInt(1n << 64n)))).toBe("out-of-range");
    expect(reasonOf(writeOer((w) => w.writeVarUInt(-1n)))).toBe("out-of-range");
  });

  it("rejects a zero-length and a nine-byte VarUInt on read, but saturates when asked", () => {
    const nine = Buffer.from("09010000000000000000", "hex");

    expect(reasonOf(readOer(Buffer.from("00", "hex"), (r) => r.readVarUInt()))).toBe("invalid-field");
    expect(reasonOf(readOer(Buffer.from("00", "hex"), (r) => r.readVarUIntSaturating()))).toBe("invalid-field");
    expect(reasonOf(readOer(nine, (r) => r.readVarUInt()))).toBe("out-of-range");
    expect(Result.getOrThrow(readOer(nine, (r) => r.readVarUIntSaturating()))).toBe((1n << 64n) - 1n);
  });

  it("saturates on the encoded width, not the value: nine zero bytes are 2^64-1 too", () => {
    const zeros = Buffer.from("0900000000000000000000", "hex");

    expect(Result.getOrThrow(readOer(zeros, (r) => r.readVarUIntSaturating()))).toBe((1n << 64n) - 1n);
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

describe("OerReader.readOctets", () => {
  it("reads exactly the requested number of octets and advances", () => {
    const result = readOer(Uint8Array.of(1, 2, 3, 4), (r) => ({
      none: r.readOctets(0),
      two: r.readOctets(2),
      offset: r.offset,
      remaining: r.remaining,
    }));

    expect(Result.getOrThrow(result)).toEqual({
      none: new Uint8Array(),
      two: Uint8Array.of(1, 2),
      offset: 2,
      remaining: 2,
    });
  });

  it.each([-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])(
    "refuses the length %s as out-of-range and leaves the cursor where it was",
    (length) => {
      const reader = new OerReader(Uint8Array.of(1, 2, 3));
      reader.readUInt8();
      let thrown: unknown;

      try {
        reader.readOctets(length);
      } catch (error) {
        thrown = error;
      }

      expect(thrown).toBeInstanceOf(IlpCodecError);
      expect(thrown).toMatchObject({ reason: "out-of-range" });
      expect(reader.offset).toBe(1);
      expect(reader.remaining).toBe(2);
      expect(reader.readUInt8()).toBe(2);
    },
  );

  it("reports a length beyond the input as truncated", () => {
    expect(reasonOf(readOer(Uint8Array.of(1, 2, 3), (r) => r.readOctets(4)))).toBe("truncated");
  });
});

describe("readOer and writeOer", () => {
  it("rethrow anything that is not an IlpCodecError instead of hiding a defect", () => {
    const boom = new RangeError("boom");

    expect(() =>
      readOer(Uint8Array.of(1), () => {
        throw boom;
      }),
    ).toThrow(boom);

    expect(() =>
      writeOer(() => {
        throw boom;
      }),
    ).toThrow(boom);
  });

  it("turn a thrown IlpCodecError into a failure carrying the same error", () => {
    const error = new IlpCodecError({ reason: "invalid-field", message: "nope" });

    const read = readOer(Uint8Array.of(1), () => {
      throw error;
    });

    expect(Result.isFailure(read) && read.failure).toBe(error);
  });
});

describe("UTF-8 strings", () => {
  const encoder = new TextEncoder();

  it("keeps a leading byte-order mark, so decoding then encoding is the identity", () => {
    const bytes = Uint8Array.of(0xef, 0xbb, 0xbf, 0x41);

    expect(utf8String(bytes, "text")).toBe("\ufeffA");
    expect(encoder.encode(utf8String(bytes, "text"))).toEqual(bytes);
  });

  it("reports malformed UTF-8 as an invalid-field codec error, not a TypeError", () => {
    expect(() => utf8String(Uint8Array.of(0xc3, 0x28), "text")).toThrow(
      expect.objectContaining({ _tag: "IlpCodecError", reason: "invalid-field", message: "text is not valid UTF-8" }),
    );
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
    ["2026101113050900", "truncated"],
    ["2026-10-11T13:05:09", "invalid-timestamp"],
    ["20261301000000000", "invalid-timestamp"],
    ["20260230000000000", "invalid-timestamp"],
    ["20261011240000000", "invalid-timestamp"],
    ["20261011126000000", "invalid-timestamp"],
    ["20261011120060000", "invalid-timestamp"],
    ["abcdefghijklmnopq", "invalid-timestamp"],
  ])("rejects %s as %s", (text, reason) => {
    expect(reasonOf(read(text))).toBe(reason);
  });

  it("refuses to write an invalid date or a year outside 0000–9999, all as invalid-timestamp", () => {
    const years = [
      new Date(Number.NaN),
      new Date(Date.UTC(10_000, 0, 1)),
      new Date(Date.UTC(9999, 11, 31, 23, 59, 59, 999) + 1),
      new Date(-62_167_219_200_001),
    ];

    for (const date of years) expect(reasonOf(writeOer((w) => w.writeTimestamp(date)))).toBe("invalid-timestamp");
  });

  it("writes the first and last representable instants", () => {
    const first = Result.getOrThrow(writeOer((w) => w.writeTimestamp(new Date(-62_167_219_200_000))));
    const last = Result.getOrThrow(writeOer((w) => w.writeTimestamp(new Date(253_402_300_799_999))));

    expect(Buffer.from(first).toString("ascii")).toBe("00000101000000000");
    expect(Buffer.from(last).toString("ascii")).toBe("99991231235959999");
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
    expect(reasonOf(readOer(Buffer.from("05aabb", "hex"), (r) => r.readNested()))).toBe("truncated");

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
    expect(reasonOf(read(text))).toBe("invalid-timestamp");
  });

  it("is exact over every day of a leap year and its neighbours", () => {
    for (const year of [1999, 2000, 2023, 2024, 2100]) {
      for (let month = 1; month <= 12; month++) {
        const days = new Date(Date.UTC(year, month, 0)).getUTCDate();

        const at = (day: number) =>
          `${String(year).padStart(4, "0")}${String(month).padStart(2, "0")}${String(day).padStart(2, "0")}000000000`;

        expect(reasonOf(read(at(days)))).toBe("success");
        expect(reasonOf(read(at(days + 1)))).toBe("invalid-timestamp");
      }
    }
  });
});
