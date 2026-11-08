import { describe, expect, it } from "vite-plus/test";
import {
  computeInteractionHash,
  extractGnapToken,
  getGrantClientIdentity,
  GnapClientFieldError,
  hashToken,
  parseClientField,
  verifyInteractionHash,
} from "../../src/plain/gnap";

const input = {
  clientNonce: "client-nonce",
  serverNonce: "server-nonce",
  interactRef: "ref-1",
  grantEndpoint: "https://auth.example/",
};

describe("plain gnap", () => {
  it("computes and verifies the interaction hash with Promises", async () => {
    const hash = await computeInteractionHash(input);

    expect(await verifyInteractionHash({ ...input, hash })).toBe(true);
    expect(await verifyInteractionHash({ ...input, hash: "nope" })).toBe(false);
  });

  it("hashes a token and extracts one from an Authorization header", async () => {
    expect(await hashToken("secret")).toMatch(/^[\w-]+$/);
    expect(extractGnapToken("GNAP abc")).toBe("abc");
  });

  it("parses the client field and throws GnapClientFieldError on an unusable one", () => {
    expect(parseClientField("https://wallet.example/alice")).toMatchObject({
      client: "https://wallet.example/alice",
    });
    expect(() => parseClientField(undefined)).toThrow(GnapClientFieldError);
    expect(() => getGrantClientIdentity({})).toThrow(GnapClientFieldError);
  });
});
