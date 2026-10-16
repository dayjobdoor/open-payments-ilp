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
