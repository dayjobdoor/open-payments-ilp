import { Result } from "effect";
import { describe, expect, it } from "vite-plus/test";
import { parseDictionary, serializeInnerList, type SfInnerList } from "../../src/http-signatures";

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
