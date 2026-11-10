import { createHash } from "node:crypto";
import * as Effect from "effect/Effect";
import { describe, expect, it } from "vite-plus/test";
import { extractGnapToken, formatGnapAuthorization, hashToken } from "../../src/gnap/index";

describe("extractGnapToken", () => {
  it("reads the token of a GNAP Authorization header", () => {
    expect(extractGnapToken("GNAP abc123")).toBe("abc123");
    expect(extractGnapToken("GNAP   abc123  ")).toBe("abc123");
    expect(extractGnapToken("gnap abc123")).toBe("abc123");
  });

  it.each([undefined, "", "Bearer abc", "GNAP", "GNAP    "])("returns null for %j", (header) => {
    expect(extractGnapToken(header)).toBeNull();
  });

  it("round-trips with formatGnapAuthorization", () => {
    expect(extractGnapToken(formatGnapAuthorization("tok"))).toBe("tok");
  });
});

describe("hashToken", () => {
  it("is the lower-case hex SHA-256 of the token's UTF-8 bytes", async () => {
    for (const token of ["a", "continue-token", "日本語"]) {
      expect(await Effect.runPromise(hashToken(token))).toBe(createHash("sha256").update(token, "utf8").digest("hex"));
    }
  });
});

describe("extractGnapToken on malformed headers", () => {
  // RFC 9110 §11.4: `auth-scheme 1*SP token68`: one credential, separated by spaces only.
  it.each([
    ["a second token", "GNAP abc def"],
    ["a list of credentials", "GNAP abc, GNAP def"],
    ["another scheme first", "Bearer abc GNAP def"],
    ["a tab as separator", "GNAP\tabc"],
    ["no separator", "GNAPabc"],
    ["a scheme that only starts with GNAP", "GNAPX abc"],
    ["leading whitespace", " GNAP abc"],
  ])("returns null for %s", (_name, header) => {
    expect(extractGnapToken(header)).toBeNull();
  });

  it("keeps the punctuation of the token as it is", () => {
    expect(extractGnapToken("GNAP a-b_c.d~e+f/g=")).toBe("a-b_c.d~e+f/g=");
  });
});

describe("formatGnapAuthorization", () => {
  it("is the GNAP scheme, one space, the token", () => {
    expect(formatGnapAuthorization("8N6BW7OZB8CDFONP219RP1LT0OS9M2PU")).toBe("GNAP 8N6BW7OZB8CDFONP219RP1LT0OS9M2PU");
  });
});
