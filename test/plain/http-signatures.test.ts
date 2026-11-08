import { describe, expect, it } from "vite-plus/test";
import { KeyObject as NodeKeyObject } from "node:crypto";
import {
  createContentDigest,
  createSignatureBase,
  generateEd25519KeyPair,
  HttpSignatureError,
  exportPublicJwk,
  importEd25519PrivateJwk,
  importEd25519PrivateKeyPem,
  importEd25519PublicJwk,
  importPrivateKey,
  parseDictionary,
  serializeInnerList,
  serializeItem,
  serializeSignatureParams,
  signRequest,
  verifyContentDigest,
  verifyRequest,
} from "../../src/plain/http-signatures";

const request = () =>
  new Request("https://rs.test/incoming-payments", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "GNAP token" },
    body: JSON.stringify({ a: 1 }),
  });

const verifyOptions = { requiredComponents: ["@method", "@target-uri", "authorization"] };

describe("plain http-signatures", () => {
  it("signs and verifies with an async key resolver", async () => {
    const { privateKey, publicJwk } = await generateEd25519KeyPair();
    const signed = await signRequest(request(), { keyId: "k1", privateKey });

    const verified = await verifyRequest(signed, {
      ...verifyOptions,
      resolveKey: async (keyId) => (keyId === "k1" ? publicJwk : undefined),
    });

    expect(verified.keyId).toBe("k1");
  });

  it("rejects with HttpSignatureError unknown-key when the resolver finds nothing", async () => {
    const { privateKey } = await generateEd25519KeyPair();
    const signed = await signRequest(request(), { keyId: "k1", privateKey });

    for (const resolveKey of [() => null, () => undefined, async () => null]) {
      await expect(verifyRequest(signed, { ...verifyOptions, resolveKey })).rejects.toMatchObject({
        _tag: "HttpSignatureError",
        reason: "unknown-key",
      });
    }
  });

  it("never copies the keyid into the unknown-key message", async () => {
    const { privateKey } = await generateEd25519KeyPair();
    const signed = await signRequest(request(), { keyId: "attacker-chosen-keyid", privateKey });
    const error = await verifyRequest(signed, { ...verifyOptions, resolveKey: () => null }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(HttpSignatureError);
    expect((error as HttpSignatureError).message).not.toContain("attacker-chosen-keyid");
  });

  it("passes a thrown HttpSignatureError through with its own reason", async () => {
    const { privateKey } = await generateEd25519KeyPair();
    const signed = await signRequest(request(), { keyId: "k1", privateKey });

    await expect(
      verifyRequest(signed, {
        ...verifyOptions,
        resolveKey: async () => {
          throw new HttpSignatureError({ reason: "expired", message: "key retired" });
        },
      }),
    ).rejects.toMatchObject({ reason: "expired", message: "key retired" });
  });

  it("rejects with the resolver's own error when it throws anything else (a bug, not an unknown key)", async () => {
    const { privateKey } = await generateEd25519KeyPair();
    const signed = await signRequest(request(), { keyId: "k1", privateKey });
    const boom = new Error("db down");

    await expect(
      verifyRequest(signed, {
        ...verifyOptions,
        resolveKey: () => {
          throw boom;
        },
      }),
    ).rejects.toBe(boom);
    await expect(
      verifyRequest(signed, { ...verifyOptions, resolveKey: async () => Promise.reject(boom) }),
    ).rejects.toBe(boom);
  });

  it("rejects a tampered body", async () => {
    const { privateKey, publicJwk } = await generateEd25519KeyPair();
    const signed = await signRequest(request(), { keyId: "k1", privateKey });
    const tampered = new Request(signed, { method: "POST", body: JSON.stringify({ a: 2 }) });

    await expect(verifyRequest(tampered, { ...verifyOptions, resolveKey: () => publicJwk })).rejects.toBeInstanceOf(
      HttpSignatureError,
    );
  });

  it("checks content digests", async () => {
    const body = new TextEncoder().encode("hello");
    const header = await createContentDigest(body);

    await expect(verifyContentDigest(header, body)).resolves.toBeUndefined();
    await expect(verifyContentDigest(header, new TextEncoder().encode("world"))).rejects.toBeInstanceOf(
      HttpSignatureError,
    );
  });

  it("imports a private key given as CryptoKey, JWK or PEM", async () => {
    const { privateKey, publicJwk } = await generateEd25519KeyPair();
    const jwk = await crypto.subtle.exportKey("jwk", privateKey);
    const pem = `-----BEGIN PRIVATE KEY-----\n${btoa(
      String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey("pkcs8", privateKey))),
    )}\n-----END PRIVATE KEY-----`;

    expect(await importPrivateKey(privateKey)).toBe(privateKey);

    for (const input of [jwk, pem]) {
      const imported = await importPrivateKey(input);
      const signed = await signRequest(request(), { keyId: "k1", privateKey: imported });

      await expect(verifyRequest(signed, { ...verifyOptions, resolveKey: () => publicJwk })).resolves.toMatchObject({
        keyId: "k1",
      });
    }
  });

  it("rejects anything that is not an Ed25519 private CryptoKey, a JWK with a kty, or a PEM string as malformed", async () => {
    const { privateKey, publicJwk } = await generateEd25519KeyPair();
    const publicKey = await importEd25519PublicJwk(publicJwk);
    const jwk = await crypto.subtle.exportKey("jwk", privateKey);
    const { kty: _kty, ...jwkWithoutKty } = jwk;
    const keyObject = NodeKeyObject.from(privateKey);

    for (const input of [keyObject, jwkWithoutKty, publicKey, null, 42, {}]) {
      await expect(importPrivateKey(input as never)).rejects.toMatchObject({
        _tag: "HttpSignatureError",
        reason: "malformed",
      });
    }
  });

  it("wraps the structured-field and signature-base codecs to return values and throw HttpSignatureError", () => {
    expect(parseDictionary("a=1, b=?0")).toHaveLength(2);
    expect(serializeItem({ value: { type: "string", value: "x" }, params: [] })).toBe('"x"');
    expect(
      serializeInnerList({
        items: [{ value: { type: "string", value: "a" }, params: [] }],
        params: [],
      }),
    ).toBe('("a")');
    expect(serializeSignatureParams(["@method"], [["created", 1]])).toBe('("@method");created=1');
    expect(
      createSignatureBase(new Request("https://rs.test/x", { method: "POST" }), ["@method"], [["created", 1]]),
    ).toBe('"@method": POST\n"@signature-params": ("@method");created=1');
    expect(() => parseDictionary("a=")).toThrow(
      expect.objectContaining({ _tag: "HttpSignatureError", reason: "malformed" }),
    );
    expect(() => createSignatureBase(new Request("https://rs.test/x"), ["x-missing"], [])).toThrow(
      expect.objectContaining({ _tag: "HttpSignatureError" }),
    );
  });

  it("imports and exports Ed25519 keys through the Promise wrappers", async () => {
    const { privateKey, publicJwk } = await generateEd25519KeyPair();
    const pem = `-----BEGIN PRIVATE KEY-----\n${btoa(
      String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey("pkcs8", privateKey))),
    )}\n-----END PRIVATE KEY-----`;
    const publicKey = await importEd25519PublicJwk(publicJwk);

    expect(publicKey.type).toBe("public");
    expect((await exportPublicJwk(publicKey)).x).toBe(publicJwk.x);
    expect((await importEd25519PrivateKeyPem(pem)).type).toBe("private");
    await expect(importEd25519PublicJwk({ kty: "RSA" })).rejects.toMatchObject({
      reason: "malformed",
    });
    await expect(importEd25519PrivateJwk(publicJwk)).rejects.toMatchObject({ reason: "malformed" });
    await expect(importEd25519PrivateKeyPem("not pem")).rejects.toMatchObject({
      reason: "malformed",
    });
  });
});
