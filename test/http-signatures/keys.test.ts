import { generateKeyPairSync } from "node:crypto";
import { Effect } from "effect";
import { describe, expect, it } from "vite-plus/test";
import {
  exportPublicJwk,
  generateEd25519KeyPair,
  importEd25519PrivateKeyPem,
  signRequest,
  verifyRequest,
} from "../../src/http-signatures";

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
