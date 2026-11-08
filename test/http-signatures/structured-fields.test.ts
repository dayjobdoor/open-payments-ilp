import { Result } from "effect";
import { describe, expect, it } from "vite-plus/test";
import {
  parseDictionary,
  serializeInnerList,
  serializeItem,
  type SfBareItem,
  type SfParams,
} from "../../src/http-signatures";
import type { SfInnerList } from "../../src/http-signatures";

describe("parseDictionary", () => {
  it("parses a signature input with inner list and typed parameters", () => {
    const result = parseDictionary('sig1=("@method" "content-digest");created=1618884473;keyid="k";alg="ed25519"');
    const [entry] = Result.getOrThrow(result);
    // SAFETY: the input above is an inner list.
    const member = entry?.[1] as SfInnerList;

    expect(entry?.[0]).toBe("sig1");
    expect(member.items.map((item) => item.value)).toEqual([
      { type: "string", value: "@method" },
      { type: "string", value: "content-digest" },
    ]);
    expect(member.params.map(([key]) => key)).toEqual(["created", "keyid", "alg"]);
  });

  it("parses byte sequences, booleans, tokens, decimals and escaped strings", () => {
    const result = parseDictionary('a=:AQID:, b=?0, c, d=tok/en:1, e=-1.50, f="q\\"\\\\"');
    // SAFETY: every member above is a plain item.
    const values = Result.getOrThrow(result).map(([, member]) => (member as { value: unknown }).value);

    expect(values).toEqual([
      { type: "binary", value: new Uint8Array([1, 2, 3]) },
      { type: "boolean", value: false },
      { type: "boolean", value: true },
      { type: "token", value: "tok/en:1" },
      { type: "decimal", value: -1.5 },
      { type: "string", value: 'q"\\' },
    ]);
  });

  it.each([
    ["duplicate key", "a=1, a=2"],
    ["duplicate parameter", "a=1;p=1;p=2"],
    ["trailing comma", "a=1,"],
    ["missing comma", "a=1 b=2"],
    ["uppercase key", "A=1"],
    ["trailing garbage", 'a=1 "x"'],
    ["unterminated string", 'a="x'],
    ["control character in string", 'a="x\u0001"'],
    ["bad escape", 'a="\\n"'],
    ["unterminated inner list", 'a=("x"'],
    ["inner list without separator", 'a=("x""y")'],
    ["unpadded base64", "a=:AQI:"],
    ["non-canonical base64", "a=:AB==:"],
    ["16-digit integer", "a=1234567890123456"],
    ["four fractional digits", "a=1.2345"],
    ["bad boolean", "a=?2"],
    ["date items", "a=@123"],
  ])("rejects %s", (_name, input) => {
    const result = parseDictionary(input);

    expect(Result.isFailure(result) && result.failure.reason).toBe("malformed");
  });
});

describe("serializeInnerList", () => {
  it("round-trips a parsed signature input", () => {
    const input = '("@method" "@target-uri");created=1;keyid="a\\"b"';
    const [entry] = Result.getOrThrow(parseDictionary(`sig1=${input}`));

    // SAFETY: the input above is an inner list.
    expect(Result.getOrThrow(serializeInnerList(entry?.[1] as SfInnerList))).toBe(input);
  });

  it("refuses strings that are not printable ASCII", () => {
    const list: SfInnerList = { items: [{ value: { type: "string", value: "é" }, params: [] }], params: [] };

    expect(Result.isFailure(serializeInnerList(list))).toBe(true);
  });
});

const item = (value: SfBareItem, params: SfParams = []) => serializeItem({ value, params });

const decimal = (value: number) => item({ type: "decimal", value });

const serialized = (result: ReturnType<typeof item>): string => Result.getOrThrow(result);

const failureReason = (result: ReturnType<typeof item>): string | undefined =>
  Result.isFailure(result) ? result.failure.reason : undefined;

describe("serializeItem", () => {
  it.each([
    [0, "0.0"],
    [1, "1.0"],
    [-1, "-1.0"],
    [1.5, "1.5"],
    [-1.5, "-1.5"],
    [0.123, "0.123"],
    [100.1, "100.1"],
    [999_999_999_999.999, "999999999999.999"],
    [-999_999_999_999.999, "-999999999999.999"],
    [-0.0004, "-0.0"],
  ])("serialises the decimal %s as %s", (value, text) => {
    expect(serialized(decimal(value))).toBe(text);
  });

  it.each([
    // Exact ties (multiples of 1/16): RFC 8941 §4.1.5 rounds half to even, `toFixed` would round up.
    [0.0625, "0.062"],
    [0.1875, "0.188"],
    [0.3125, "0.312"],
    [0.4375, "0.438"],
    [2.5625, "2.562"],
    [-0.0625, "-0.062"],
    [-0.1875, "-0.188"],
    // Not ties: ordinary rounding of the exact binary value.
    [0.0626, "0.063"],
    [0.0624, "0.062"],
    [1.0005, "1.0"],
  ])("rounds the decimal %s half to even, to %s", (value, text) => {
    expect(serialized(decimal(value))).toBe(text);
  });

  it.each([
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["-Infinity", Number.NEGATIVE_INFINITY],
    ["1e12 (13 integer digits)", 1e12],
    ["-1e12", -1e12],
    ["a value that rounds up into 13 integer digits", 999_999_999_999.9996],
    ["1e21", 1e21],
  ])("refuses the decimal %s", (_name, value) => {
    expect(failureReason(decimal(value))).toBe("malformed");
  });

  it("serialises integers up to 15 digits and refuses the rest", () => {
    expect(serialized(item({ type: "integer", value: 999_999_999_999_999 }))).toBe("999999999999999");
    expect(serialized(item({ type: "integer", value: -999_999_999_999_999 }))).toBe("-999999999999999");
    expect(serialized(item({ type: "integer", value: -0 }))).toBe("0");

    for (const value of [1e15, Number.NaN, Number.POSITIVE_INFINITY, 1.5, 2 ** 53]) {
      expect(failureReason(item({ type: "integer", value }))).toBe("malformed");
    }
  });

  it("serialises booleans, binary values, tokens and strings", () => {
    expect(serialized(item({ type: "boolean", value: true }))).toBe("?1");
    expect(serialized(item({ type: "boolean", value: false }))).toBe("?0");
    expect(serialized(item({ type: "binary", value: new Uint8Array([1, 2, 3]) }))).toBe(":AQID:");
    expect(serialized(item({ type: "binary", value: new Uint8Array() }))).toBe("::");
    expect(serialized(item({ type: "token", value: "tok/en:1" }))).toBe("tok/en:1");
    expect(serialized(item({ type: "token", value: "*foo" }))).toBe("*foo");
    expect(serialized(item({ type: "string", value: 'q"\\' }))).toBe('"q\\"\\\\"');
  });

  it.each(["", "1abc", "has space", '"quoted"', "é", ":x"])("refuses the token %j", (value) => {
    expect(failureReason(item({ type: "token", value }))).toBe("malformed");
  });

  it("serialises parameters in order, leaving out the value of a true boolean", () => {
    const params: SfParams = [
      ["a", { type: "boolean", value: true }],
      ["b", { type: "boolean", value: false }],
      ["c", { type: "integer", value: 2 }],
      ["d", { type: "decimal", value: 0.5 }],
      ["e", { type: "token", value: "t" }],
      ["f", { type: "binary", value: new Uint8Array([255]) }],
    ];

    expect(serialized(item({ type: "string", value: "x" }, params))).toBe('"x";a;b=?0;c=2;d=0.5;e=t;f=:/w==:');
  });

  it("refuses a parameter given twice, which the parser refuses as well", () => {
    const twice: SfParams = [
      ["created", { type: "integer", value: 1 }],
      ["created", { type: "integer", value: 2 }],
    ];

    expect(failureReason(item({ type: "integer", value: 1 }, twice))).toBe("malformed");
    expect(Result.isFailure(serializeInnerList({ items: [], params: twice }))).toBe(true);
    expect(Result.isFailure(parseDictionary("a=1;created=1;created=2"))).toBe(true);
  });

  it("refuses an invalid parameter key", () => {
    for (const key of ["", "Upper", "1a", "a b"]) {
      expect(failureReason(item({ type: "integer", value: 1 }, [[key, { type: "boolean", value: true }]]))).toBe(
        "malformed",
      );
    }
  });
});
