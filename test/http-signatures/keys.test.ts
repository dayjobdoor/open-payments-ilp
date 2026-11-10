import { generateKeyPairSync } from "node:crypto";
import { Effect } from "effect";
import { describe, expect, it } from "vite-plus/test";
import {
  exportPublicJwk,
  generateEd25519KeyPair,
  importEd25519PrivateJwk,
  importEd25519PrivateKeyPem,
  importEd25519PublicJwk,
  signRequest,
  verifyRequest,
} from "../../src/http-signatures";
import { encodeBase64, encodeBase64Url } from "../../src/internal/bytes";

const run = <A, E>(effect: Effect.Effect<A, E>): Promise<A> => Effect.runPromise(effect);

describe("importEd25519PrivateKeyPem", () => {
  const pair = generateKeyPairSync("ed25519");
  const pem = pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString();

  it("imports the PEM a PKCS #8 Ed25519 key is stored in, and signs requests that verify against its public key", async () => {
    const privateKey = await run(importEd25519PrivateKeyPem(pem));
    const url = "https://rs.example.com/quotes";

    const request = await run(signRequest(new Request(url), { keyId: "pem-key", privateKey }));

    const verified = await run(
      verifyRequest(request, { resolveKey: () => Effect.succeed(pair.publicKey.export({ format: "jwk" })) }),
    );

    expect(verified.keyId).toBe("pem-key");
  });

  it.each([
    ["text that is not a PEM", "hello"],
    ["a PEM of another kind", pem.replace(/PRIVATE KEY/g, "RSA PRIVATE KEY")],
    [
      "an RSA key",
      generateKeyPairSync("rsa", { modulusLength: 2048 })
        .privateKey.export({ format: "pem", type: "pkcs8" })
        .toString(),
    ],
    ["a corrupted body", pem.replace(/[A-Z]/, "!")],
  ])("rejects %s as malformed", async (_name, text) => {
    expect((await run(Effect.flip(importEd25519PrivateKeyPem(text)))).reason).toBe("malformed");
  });
});

describe("exportPublicJwk", () => {
  it("names the key for publication when given a keyId, like the reference generateJwk", async () => {
    const { privateKey } = await run(generateEd25519KeyPair());

    expect(await run(exportPublicJwk(privateKey, { keyId: "my-key" }))).toMatchObject({
      kid: "my-key",
      alg: "EdDSA",
      kty: "OKP",
      crv: "Ed25519",
    });
    expect(Object.keys(await run(exportPublicJwk(privateKey))).sort()).toEqual(["crv", "kty", "x"]);
  });
});

const hex = (text: string): Uint8Array => Uint8Array.from(text.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));

/** The encodings of the eight points of small order on Ed25519, plus their sign-bit and non-canonical variants. */
const SMALL_ORDER_POINTS: ReadonlyArray<readonly [string, string]> = [
  ["the identity (y = 1)", `01${"00".repeat(31)}`],
  ["the identity with the sign bit set", `01${"00".repeat(30)}80`],
  ["the point of order 2 (y = -1)", `ec${"ff".repeat(30)}7f`],
  ["y = -1 with the sign bit set", `ec${"ff".repeat(31)}`],
  ["a point of order 4 (y = 0)", "00".repeat(32)],
  ["the other point of order 4 (y = 0, sign bit set)", `${"00".repeat(31)}80`],
  ["the non-canonical y = p (0)", `ed${"ff".repeat(30)}7f`],
  ["the non-canonical y = p + 1 (1)", `ee${"ff".repeat(30)}7f`],
  ["a point of order 8", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"],
  ["a point of order 8, sign bit set", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"],
  ["another point of order 8", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"],
  ["another point of order 8, sign bit set", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"],
];

const reasonOf = async (effect: Effect.Effect<unknown, { readonly reason: string }>): Promise<string> =>
  (await run(Effect.flip(effect))).reason;

describe("importEd25519PrivateJwk", () => {
  async function privateJwk(): Promise<JsonWebKey> {
    const { privateKey } = await run(generateEd25519KeyPair());

    return crypto.subtle.exportKey("jwk", privateKey);
  }

  it("imports a private JWK into a key that signs requests which verify against the public half", async () => {
    const jwk = await privateJwk();
    const privateKey = await run(importEd25519PrivateJwk(jwk));
    const request = await run(signRequest(new Request("https://rs.example.com/q"), { keyId: "k", privateKey }));

    const verified = await run(
      verifyRequest(request, { resolveKey: () => Effect.succeed({ kty: "OKP", crv: "Ed25519", x: jwk.x ?? "" }) }),
    );

    expect(verified.keyId).toBe("k");
    expect(privateKey.extractable).toBe(false);
  });

  it("rejects a d that does not belong to x, on every runtime", async () => {
    const jwk = await privateJwk();
    const other = await privateJwk();

    expect(await reasonOf(importEd25519PrivateJwk({ ...jwk, x: other.x ?? "" }))).toBe("malformed");
    expect(await reasonOf(importEd25519PrivateJwk({ ...jwk, d: other.d ?? "" }))).toBe("malformed");
  });

  it.each(SMALL_ORDER_POINTS)("rejects %s as x", async (_name, point) => {
    expect(await reasonOf(importEd25519PrivateJwk({ ...(await privateJwk()), x: encodeBase64Url(hex(point)) }))).toBe(
      "malformed",
    );
  });

  it.each([
    ["no d", ({ d: _d, ...rest }: JsonWebKey): JsonWebKey => rest],
    ["no x", ({ x: _x, ...rest }: JsonWebKey): JsonWebKey => rest],
    ["another kty", (jwk: JsonWebKey) => ({ ...jwk, kty: "EC" })],
    ["another crv", (jwk: JsonWebKey) => ({ ...jwk, crv: "X25519" })],
    ["a d of the wrong length", (jwk: JsonWebKey) => ({ ...jwk, d: "AAAA" })],
    ["an x of the wrong length", (jwk: JsonWebKey) => ({ ...jwk, x: "AAAA" })],
    ["an x that is not base64url", (jwk: JsonWebKey) => ({ ...jwk, x: "@@@@" })],
    ["an empty x", (jwk: JsonWebKey) => ({ ...jwk, x: "" })],
  ])("rejects a JWK with %s as malformed", async (_name, change) => {
    expect(await reasonOf(importEd25519PrivateJwk(change(await privateJwk())))).toBe("malformed");
  });
});

describe("importEd25519PublicJwk", () => {
  it("imports kty, crv and x, ignoring a private d", async () => {
    const { privateKey } = await run(generateEd25519KeyPair());
    const jwk = await crypto.subtle.exportKey("jwk", privateKey);
    const key = await run(importEd25519PublicJwk(jwk));

    expect(key.type).toBe("public");
    expect(key.usages).toEqual(["verify"]);
  });

  it.each(SMALL_ORDER_POINTS)("rejects %s", async (_name, point) => {
    expect(await reasonOf(importEd25519PublicJwk({ kty: "OKP", crv: "Ed25519", x: encodeBase64Url(hex(point)) }))).toBe(
      "malformed",
    );
  });

  it.each([
    ["no x", { kty: "OKP", crv: "Ed25519" }],
    ["another kty", { kty: "EC", crv: "Ed25519", x: "AAAA" }],
    ["another crv", { kty: "OKP", crv: "Ed448", x: "AAAA" }],
    ["an x of the wrong length", { kty: "OKP", crv: "Ed25519", x: "AAAA" }],
    ["an x that is not base64url", { kty: "OKP", crv: "Ed25519", x: "!!!!" }],
    ["an empty x", { kty: "OKP", crv: "Ed25519", x: "" }],
  ])("rejects a JWK with %s as malformed", async (_name, jwk) => {
    expect(await reasonOf(importEd25519PublicJwk(jwk))).toBe("malformed");
  });

  it("refuses the all-zero 'universal' signature that an identity public key would accept on Bun", async () => {
    const identity: JsonWebKey = { kty: "OKP", crv: "Ed25519", x: encodeBase64Url(hex(`01${"00".repeat(31)}`)) };
    const now = new Date("2030-01-01T00:00:00Z");
    const created = Math.floor(now.getTime() / 1000);
    const zeroSignature = encodeBase64(hex(`01${"00".repeat(63)}`));

    const request = new Request("https://rs.example.com/quotes", {
      headers: {
        "Signature-Input": `sig1=("@method" "@target-uri");created=${created};keyid="evil"`,
        Signature: `sig1=:${zeroSignature}:`,
      },
    });

    const error = await run(
      Effect.flip(verifyRequest(request, { resolveKey: () => Effect.succeed(identity), clock: () => now })),
    );

    expect(error.reason).toBe("malformed");
  });
});
