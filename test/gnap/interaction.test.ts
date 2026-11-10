import { createHash } from "node:crypto";
import * as Effect from "effect/Effect";
import { describe, expect, it } from "vite-plus/test";
import {
  buildFinishUrl,
  buildRejectedFinishUrl,
  computeInteractionHash,
  verifyInteractionHash,
} from "../../src/gnap/index";

// Fixed inputs; the expected digests come from node:crypto.
const input = {
  clientNonce: "VJLO6A4CATPIQDZIKH2",
  serverNonce: "MBDOFXG4Y5CVJCX821LH",
  interactRef: "4IFWWIKYBC2PQ6U56NL1",
  grantEndpoint: "https://server.example.com/tx",
};

const base = "VJLO6A4CATPIQDZIKH2\nMBDOFXG4Y5CVJCX821LH\n4IFWWIKYBC2PQ6U56NL1\nhttps://server.example.com/tx";

describe("computeInteractionHash", () => {
  it("is the unpadded base64url SHA-256 of the newline-joined inputs", async () => {
    const expected = createHash("sha256").update(base).digest("base64url");

    expect(await Effect.runPromise(computeInteractionHash(input))).toBe(expected);
    expect(expected).not.toContain("=");
  });

  it("supports Rafiki's padded base64 and the other SHA-2 methods", async () => {
    expect(await Effect.runPromise(computeInteractionHash({ ...input, encoding: "base64" }))).toBe(
      createHash("sha256").update(base).digest("base64"),
    );
    expect(await Effect.runPromise(computeInteractionHash({ ...input, method: "sha-512" }))).toBe(
      createHash("sha512").update(base).digest("base64url"),
    );
    expect(await Effect.runPromise(computeInteractionHash({ ...input, method: "sha-384" }))).toBe(
      createHash("sha384").update(base).digest("base64url"),
    );
  });

  it.each(["clientNonce", "serverNonce", "interactRef", "grantEndpoint"] as const)(
    "changes when %s changes",
    async (field) => {
      const original = await Effect.runPromise(computeInteractionHash(input));
      const changed = await Effect.runPromise(computeInteractionHash({ ...input, [field]: `${input[field]}x` }));

      expect(changed).not.toBe(original);
    },
  );
});

describe("verifyInteractionHash", () => {
  it("accepts the right hash and rejects a wrong or truncated one", async () => {
    const hash = await Effect.runPromise(computeInteractionHash(input));

    expect(await Effect.runPromise(verifyInteractionHash({ ...input, hash }))).toBe(true);
    expect(await Effect.runPromise(verifyInteractionHash({ ...input, hash: `${hash.slice(0, -1)}A` }))).toBe(false);
    expect(await Effect.runPromise(verifyInteractionHash({ ...input, hash: hash.slice(0, -1) }))).toBe(false);
    expect(await Effect.runPromise(verifyInteractionHash({ ...input, hash: "" }))).toBe(false);
  });
});

describe("finish URLs", () => {
  it("appends interact_ref and hash and keeps existing query parameters", () => {
    const url = new URL(buildFinishUrl("https://client.example/cb?state=1", { interactRef: "r e/f", hash: "h-_" }));

    expect(Object.fromEntries(url.searchParams)).toEqual({ state: "1", interact_ref: "r e/f", hash: "h-_" });
  });

  it("marks a rejected grant", () => {
    expect(buildRejectedFinishUrl("https://client.example/cb")).toBe("https://client.example/cb?result=grant_rejected");
  });

  it("rejects a relative finish URI", () => {
    expect(() => buildFinishUrl("/cb", { interactRef: "r", hash: "h" })).toThrow(TypeError);
  });
});

describe("RFC 9635 §4.2.3 example", () => {
  // The nonces, the interact_ref and the grant endpoint of the example, and its sha-256 value (an anchor that does not
  // come from the same crypto API as the implementation).
  const rfc = {
    clientNonce: "VJLO6A4CATR0KRO",
    serverNonce: "MBDOFXG4Y5CVJCX821LH",
    interactRef: "4IFWWIKYB2PQ6U56NL1",
    grantEndpoint: "https://server.example.com/tx",
  };

  const expected = "x-gguKWTj8rQf7d7i3w3UhzvuJ5bpOlKyAlVpLxBffY";

  it("computes the hash the RFC prints", async () => {
    expect(await Effect.runPromise(computeInteractionHash(rfc))).toBe(expected);
  });

  it("verifies it", async () => {
    expect(await Effect.runPromise(verifyInteractionHash({ ...rfc, hash: expected }))).toBe(true);
  });
});

describe("verifyInteractionHash across encodings and methods", () => {
  it("accepts Rafiki's padded base64 as well as the unpadded base64url form", async () => {
    // This digest has `+` and `/` in its base64 form, so the two encodings differ in more than the padding.
    const hash = await Effect.runPromise(computeInteractionHash({ ...input, encoding: "base64" }));
    const unpadded = await Effect.runPromise(computeInteractionHash(input));

    expect(hash).not.toBe(unpadded);
    expect(hash.endsWith("=")).toBe(true);
    expect(await Effect.runPromise(verifyInteractionHash({ ...input, hash }))).toBe(true);
    expect(await Effect.runPromise(verifyInteractionHash({ ...input, hash: unpadded }))).toBe(true);
  });

  it("checks the hash of the requested method only", async () => {
    const sha512 = await Effect.runPromise(computeInteractionHash({ ...input, method: "sha-512" }));

    expect(await Effect.runPromise(verifyInteractionHash({ ...input, method: "sha-512", hash: sha512 }))).toBe(true);
    expect(await Effect.runPromise(verifyInteractionHash({ ...input, hash: sha512 }))).toBe(false);
    expect(
      await Effect.runPromise(
        verifyInteractionHash({
          ...input,
          method: "sha-512",
          hash: await Effect.runPromise(computeInteractionHash(input)),
        }),
      ),
    ).toBe(false);
  });

  it.each(["clientNonce", "serverNonce", "interactRef", "grantEndpoint"] as const)(
    "rejects the hash of another %s",
    async (field) => {
      const hash = await Effect.runPromise(computeInteractionHash({ ...input, [field]: `${input[field]}x` }));

      expect(await Effect.runPromise(verifyInteractionHash({ ...input, hash }))).toBe(false);
    },
  );

  it("depends on the order of the fields, so a swapped client and server nonce does not verify", async () => {
    const swapped = await Effect.runPromise(
      computeInteractionHash({ ...input, clientNonce: input.serverNonce, serverNonce: input.clientNonce }),
    );

    expect(await Effect.runPromise(verifyInteractionHash({ ...input, hash: swapped }))).toBe(false);
  });
});

describe("finish URL edge cases", () => {
  it("replaces an interact_ref or hash already on the client's finish URI instead of adding a second one", () => {
    const url = new URL(
      buildFinishUrl("https://client.example/cb?interact_ref=old&hash=old#done", { interactRef: "new", hash: "h" }),
    );

    expect(url.searchParams.getAll("interact_ref")).toEqual(["new"]);
    expect(url.searchParams.getAll("hash")).toEqual(["h"]);
    expect(url.hash).toBe("#done");
  });

  it("replaces a result already on the finish URI of a rejected grant", () => {
    const url = new URL(buildRejectedFinishUrl("https://client.example/cb?result=ok&state=1"));

    expect(url.searchParams.getAll("result")).toEqual(["grant_rejected"]);
    expect(url.searchParams.get("state")).toBe("1");
    expect(url.searchParams.has("hash")).toBe(false);
  });
});
