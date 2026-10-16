import { Effect } from "effect";
import { describe, expect, it } from "vite-plus/test";
import { decodeBase64 } from "../../src/internal/bytes";
import {
  createContentDigest,
  createSignatureBase,
  importEd25519PublicJwk,
  verifyContentDigest,
  verifyRequest,
} from "../../src/http-signatures";

// RFC 9421 Appendix B.1.4 test-key-ed25519 (public key as JWK; x is the raw key from the SPKI PEM).
const publicJwk: JsonWebKey = {
  kty: "OKP",
  crv: "Ed25519",
  x: "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
};

// RFC 9421 B.2 message and B.2.6 signature.
const body = '{"hello": "world"}';

const headers = {
  Host: "example.com",
  Date: "Tue, 20 Apr 2021 02:07:55 GMT",
  "Content-Type": "application/json",
  "Content-Digest":
    "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
  "Content-Length": "18",
  "Signature-Input":
    'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
  Signature: "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:",
};

const components = ["date", "@method", "@path", "@authority", "content-type", "content-length"];

function b26Request(): Request {
  return new Request("https://example.com/foo?param=Value&Pet=dog", { method: "POST", headers, body });
}

describe("RFC 9421 B.2.6 (ed25519)", () => {
  it("verifies the published signature", async () => {
    const verified = await Effect.runPromise(
      verifyRequest(b26Request(), {
        label: "sig-b26",
        requireBodyDigest: false,
        requiredComponents: ["@method"],
        clock: () => new Date(1618884473_000 + 60_000),
        resolveKey: (keyId) =>
          keyId === "test-key-ed25519" ? Effect.succeed(publicJwk) : Effect.die(new Error(`unexpected ${keyId}`)),
      }),
    );

    expect(verified).toEqual({
      keyId: "test-key-ed25519",
      label: "sig-b26",
      created: new Date(1618884473_000),
      components,
    });
  });

  it("rebuilds the published signature base", () => {
    const base = createSignatureBase(b26Request(), components, [
      ["created", 1618884473],
      ["keyid", "test-key-ed25519"],
    ]);

    expect(base).toMatchObject({
      success: [
        '"date": Tue, 20 Apr 2021 02:07:55 GMT',
        '"@method": POST',
        '"@path": /foo',
        '"@authority": example.com',
        '"content-type": application/json',
        '"content-length": 18',
        '"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
      ].join("\n"),
    });
  });

  it("rejects the signature once a covered header changes", async () => {
    const tampered = new Request("https://example.com/foo?param=Value&Pet=dog", {
      method: "POST",
      headers: { ...headers, Date: "Tue, 20 Apr 2021 02:07:56 GMT" },
      body,
    });

    const error = await Effect.runPromise(
      Effect.flip(
        verifyRequest(tampered, {
          label: "sig-b26",
          requireBodyDigest: false,
          requiredComponents: ["@method"],
          clock: () => new Date(1618884473_000),
          resolveKey: () => Effect.succeed(publicJwk),
        }),
      ),
    );

    expect(error).toMatchObject({ reason: "invalid" });
  });

  it("imports the RFC public key", async () => {
    const key = await Effect.runPromise(importEd25519PublicJwk(publicJwk));

    expect(key.algorithm.name).toBe("Ed25519");
    expect(decodeBase64("JrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=")).toHaveLength(32);
  });
});

describe("createSignatureBase components (RFC 9421 section 2.2)", () => {
  const message = {
    method: "POST",
    url: "https://www.example.com:8443/path?param=value",
    headers: new Headers({ "X-A": "a" }),
  };

  const lineFor = (name: string, target = message) => {
    const result = createSignatureBase(target, [name], []);

    return result._tag === "Success" ? result.success.split("\n")[0] : result.failure.reason;
  };

  it.each([
    ["@authority", '"@authority": www.example.com:8443'],
    ["@scheme", '"@scheme": https'],
    ["@request-target", '"@request-target": /path?param=value'],
    ["@path", '"@path": /path'],
    ["@query", '"@query": ?param=value'],
    ["@target-uri", '"@target-uri": https://www.example.com:8443/path?param=value'],
    ["x-a", '"x-a": a'],
  ])("derives %s", (name, line) => {
    expect(lineFor(name)).toBe(line);
  });

  it("renders an empty query as a lone question mark and omits it from the request target", () => {
    const bare = { ...message, url: "https://www.example.com/path" };

    expect(lineFor("@query", bare)).toBe('"@query": ?');
    expect(lineFor("@request-target", bare)).toBe('"@request-target": /path');
    expect(lineFor("@authority", bare)).toBe('"@authority": www.example.com');
  });

  it("fails with the documented reason for unusable components", () => {
    const lineBreak = { ...message, headers: Object.assign(new Headers(), { get: () => "a\r\nb" }) };

    expect(lineFor("x-absent")).toBe("missing");
    expect(lineFor("x-a", lineBreak)).toBe("malformed");
    expect(lineFor("X-A")).toBe("malformed");
    expect(lineFor("@Method")).toBe("malformed");
    expect(lineFor("@status")).toBe("unsupported");

    const duplicated = createSignatureBase(message, ["x-a", "x-a"], []);

    expect(duplicated).toMatchObject({ _tag: "Failure", failure: { reason: "malformed" } });
  });
});

describe("RFC 9530 Content-Digest vectors", () => {
  const bytes = new TextEncoder().encode(body);
  const sha256 = "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:";
  const sha512 = headers["Content-Digest"];

  it("creates both published digests", async () => {
    expect(await Effect.runPromise(createContentDigest(bytes))).toBe(sha256);
    expect(await Effect.runPromise(createContentDigest(bytes, "sha-512"))).toBe(sha512);
  });

  it("verifies each digest alone and together", async () => {
    for (const header of [sha256, sha512, `${sha256}, ${sha512}`]) {
      await Effect.runPromise(verifyContentDigest(header, bytes));
    }
  });

  it("fails when any supported digest in the header mismatches", async () => {
    const error = await Effect.runPromise(Effect.flip(verifyContentDigest(`${sha256}, sha-512=:AAAA:`, bytes)));

    expect(error.reason).toBe("digest-mismatch");
  });

  it("ignores unknown algorithms but needs one known", async () => {
    await Effect.runPromise(verifyContentDigest(`md5=:AAAA:, ${sha256}`, bytes));
    const error = await Effect.runPromise(Effect.flip(verifyContentDigest("md5=:AAAA:", bytes)));

    expect(error.reason).toBe("unsupported");
  });
});
