import { describe, expect, it } from "vite-plus/test";
import {
  constantTimeEqual,
  decodeBase64Url,
  encodeBase64Url,
  hmacSha256,
  sha256,
  toHex,
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
