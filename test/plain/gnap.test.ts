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
    expect(await hashToken("secret")).toBe("2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b");
    expect(extractGnapToken("GNAP abc")).toBe("abc");
  });

  it("computes the hash the RFC 9635 §4.2.3 example prints", async () => {
    expect(
      await computeInteractionHash({
        clientNonce: "VJLO6A4CATR0KRO",
        serverNonce: "MBDOFXG4Y5CVJCX821LH",
        interactRef: "4IFWWIKYB2PQ6U56NL1",
        grantEndpoint: "https://server.example.com/tx",
      }),
    ).toBe("x-gguKWTj8rQf7d7i3w3UhzvuJ5bpOlKyAlVpLxBffY");
  });

  it("parses the client field and throws GnapClientFieldError on an unusable one", () => {
    expect(parseClientField("https://wallet.example/alice")).toMatchObject({
      client: "https://wallet.example/alice",
    });
    expect(() => parseClientField(undefined)).toThrow(GnapClientFieldError);
    expect(() => getGrantClientIdentity({})).toThrow(GnapClientFieldError);
  });

  it("throws the tagged error itself, with its reason", () => {
    expect(() => parseClientField({ walletAddress: "https://w.example", jwk: {} })).toThrow(
      expect.objectContaining({ _tag: "GnapClientFieldError", reason: "client-invalid-shape" }),
    );
    expect(() => getGrantClientIdentity({ client: null })).toThrow(
      expect.objectContaining({ _tag: "GnapClientFieldError", reason: "client-missing-identity" }),
    );
  });
});
