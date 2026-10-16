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
