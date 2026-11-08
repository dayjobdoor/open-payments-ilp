import { describe, expect, it } from "vite-plus/test";
import {
  concatBytes,
  constantTimeEqual,
  constantTimeEqualText,
  decodeBase64,
  decodeBase64Url,
  encodeBase64,
  encodeBase64Url,
  hmacSha256,
  sha256,
  toHex,
  utf8Decode,
  utf8Encode,
} from "../../src/internal/bytes";

describe("base64url", () => {
  it("round-trips every byte value without padding", () => {
    const bytes = Uint8Array.from({ length: 256 }, (_, i) => i);
    const text = encodeBase64Url(bytes);

    expect(text).not.toMatch(/[+/=]/);
    expect(decodeBase64Url(text)).toEqual(bytes);
  });

  it("matches the Node base64url encoding", () => {
    const bytes = utf8Encode("\u00ff\u00fe? interledger >>>");

    expect(encodeBase64Url(bytes)).toBe(Buffer.from(bytes).toString("base64url"));
  });

  it("rejects characters outside the base64url alphabet", () => {
    expect(() => decodeBase64Url("ab+c")).toThrow(TypeError);
    expect(() => decodeBase64Url("ab/c")).toThrow(TypeError);
    expect(() => decodeBase64Url("ab c")).toThrow(TypeError);
    expect(() => decodeBase64Url("ab\nc")).toThrow(TypeError);
  });

  it.each(["A", "AAAAA", "QUJDR"])(
    "rejects the impossible length of %j with a TypeError, not a DOMException",
    (text) => {
      expect(() => decodeBase64Url(text)).toThrow(TypeError);
    },
  );

  it("accepts padded and unpadded input alike", () => {
    expect(decodeBase64Url("QUI=")).toEqual(Uint8Array.of(65, 66));
    expect(decodeBase64Url("QUI")).toEqual(Uint8Array.of(65, 66));
    expect(decodeBase64Url("QQ==")).toEqual(Uint8Array.of(65));
    expect(decodeBase64Url("")).toEqual(new Uint8Array());
  });

  it("lenient decoding gives one byte string several spellings: QQ, QR and QW all decode to [65]", () => {
    for (const text of ["QQ", "QR", "QW", "QX"]) expect(decodeBase64Url(text)).toEqual(Uint8Array.of(65));
  });
});

describe("base64", () => {
  it("round-trips and matches the Node encoding, padding included", () => {
    for (const length of [0, 1, 2, 3, 4, 255]) {
      const bytes = Uint8Array.from({ length }, (_, i) => (i * 7) & 0xff);

      expect(encodeBase64(bytes)).toBe(Buffer.from(bytes).toString("base64"));
      expect(decodeBase64(encodeBase64(bytes))).toEqual(bytes);
    }
  });

  it("throws a DOMException on malformed input", () => {
    expect(() => decodeBase64("A")).toThrow(DOMException);
    expect(() => decodeBase64("***")).toThrow(DOMException);
  });
});

describe("concatBytes", () => {
  it("joins the parts in order into a fresh array", () => {
    const a = Uint8Array.of(1, 2);
    const b = new Uint8Array();
    const c = Uint8Array.of(3);
    const joined = concatBytes(a, b, c);

    expect(joined).toEqual(Uint8Array.of(1, 2, 3));

    joined[0] = 9;

    expect(a[0]).toBe(1);
  });

  it("returns an empty array for no parts or only empty parts", () => {
    expect(concatBytes()).toEqual(new Uint8Array());
    expect(concatBytes(new Uint8Array(), new Uint8Array())).toEqual(new Uint8Array());
  });

  it("copies views at their own offset and length, not the whole backing buffer", () => {
    const backing = Uint8Array.of(0, 1, 2, 3, 4, 5);

    expect(concatBytes(backing.subarray(1, 3), backing.subarray(4))).toEqual(Uint8Array.of(1, 2, 4, 5));
  });

  it("joins large parts", () => {
    const big = new Uint8Array(100_000).fill(7);
    const joined = concatBytes(big, Uint8Array.of(1), big);

    expect(joined).toHaveLength(200_001);
    expect(joined[100_000]).toBe(1);
    expect(joined[200_000]).toBe(7);
  });
});

describe("UTF-8", () => {
  it("round-trips text, including characters outside the BMP", () => {
    const text = "héllo ✓ 𝄞";

    expect(utf8Decode(utf8Encode(text))).toBe(text);
  });

  it.each([
    ["a lone continuation byte", Uint8Array.of(0x80)],
    ["an overlong encoding", Uint8Array.of(0xc0, 0xaf)],
    ["a truncated sequence", Uint8Array.of(0xe2, 0x82)],
    ["an encoded surrogate", Uint8Array.of(0xed, 0xa0, 0x80)],
    ["a byte that never occurs", Uint8Array.of(0xff)],
  ])("throws a TypeError for %s", (_name, bytes) => {
    expect(() => utf8Decode(bytes)).toThrow(TypeError);
  });

  it("keeps a leading byte-order mark, so decoding then re-encoding is the identity", () => {
    const bytes = Uint8Array.of(0xef, 0xbb, 0xbf, 0x68, 0x69);

    expect(utf8Decode(bytes)).toBe("\ufeffhi");
    expect(utf8Encode(utf8Decode(bytes))).toEqual(bytes);
  });

  it("decodes the empty input to the empty string", () => {
    expect(utf8Decode(new Uint8Array())).toBe("");
  });
});

describe("constantTimeEqual", () => {
  it("is true only for identical bytes", () => {
    expect(constantTimeEqual(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 3))).toBe(true);
    expect(constantTimeEqual(new Uint8Array(), new Uint8Array())).toBe(true);
    expect(constantTimeEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 2, 3))).toBe(false);
  });

  it.each([
    ["first", Uint8Array.of(9, 2, 3, 4, 5), Uint8Array.of(1, 2, 3, 4, 5)],
    ["middle", Uint8Array.of(1, 2, 9, 4, 5), Uint8Array.of(1, 2, 3, 4, 5)],
    ["last", Uint8Array.of(1, 2, 3, 4, 9), Uint8Array.of(1, 2, 3, 4, 5)],
    ["high bit", Uint8Array.of(0x00), Uint8Array.of(0x80)],
  ])("rejects equal-length input differing only in the %s byte", (_, a, b) => {
    expect(constantTimeEqual(a, b)).toBe(false);
    expect(constantTimeEqual(b, a)).toBe(false);
  });
});

describe("constantTimeEqualText", () => {
  it("compares strings by their UTF-8 bytes", () => {
    expect(constantTimeEqualText("secret", "secret")).toBe(true);
    expect(constantTimeEqualText("", "")).toBe(true);
    expect(constantTimeEqualText("héllo ✓", "héllo ✓")).toBe(true);
  });

  it.each([
    ["differing in one character", "secret", "secreu"],
    ["of different lengths", "secret", "secrets"],
    ["a prefix of the other", "secret", "sec"],
    ["differing only in the last character", "abcdef", "abcdeg"],
    ["differing in a non-ASCII character", "héllo", "hello"],
    ["with the same character count but different byte lengths", "é", "ee"],
  ])("is false for strings %s", (_name, a, b) => {
    expect(constantTimeEqualText(a, b)).toBe(false);
    expect(constantTimeEqualText(b, a)).toBe(false);
  });
});

describe("digests", () => {
  it("sha256 matches the FIPS 180-2 'abc' vector", async () => {
    expect(toHex(await sha256(utf8Encode("abc")))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("hmacSha256 matches RFC 4231 test case 2", async () => {
    expect(toHex(await hmacSha256(utf8Encode("Jefe"), utf8Encode("what do ya want for nothing?")))).toBe(
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    );
  });
});
