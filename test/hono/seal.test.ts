import * as Schema from "effect/Schema";
import { describe, expect, it } from "vite-plus/test";
import { decodeBase64Url, utf8Decode } from "../../src/internal/bytes";
import { openCookie, sealCookie } from "../../src/hono/seal";

const SECRET = "a-session-secret-of-at-least-32-characters";

const OTHER_SECRET = "another-session-secret-of-at-least-32-chars";

const encrypted = { secret: SECRET, encryptCookies: true };

const signed = { secret: SECRET, encryptCookies: false };

const thing = Schema.Struct({ token: Schema.String, n: Schema.Number });

const value = { token: "tok-4711", n: 7 };

/** The cookie with one character in its middle replaced by another valid one. */
const tamper = (cookie: string): string => {
  const at = Math.floor(cookie.length / 2);

  return `${cookie.slice(0, at)}${cookie[at] === "A" ? "B" : "A"}${cookie.slice(at + 1)}`;
};

describe.each([
  ["encrypted", encrypted],
  ["signed", signed],
] as const)("a %s cookie", (_format, config) => {
  it.each(["session", "state", "pending"] as const)("opens what was sealed for %s", async (kind) => {
    expect(await openCookie(config, kind, await sealCookie(config, kind, value), thing)).toEqual(value);
  });

  it("is no value for another secret, and never an error", async () => {
    const cookie = await sealCookie(config, "session", value);

    expect(await openCookie({ ...config, secret: OTHER_SECRET }, "session", cookie, thing)).toBeUndefined();
  });

  it("is no value when it was changed", async () => {
    expect(
      await openCookie(config, "session", tamper(await sealCookie(config, "session", value)), thing),
    ).toBeUndefined();
  });

  it("is no value when the schema refuses what it holds", async () => {
    const cookie = await sealCookie(config, "session", { token: 1 });

    expect(await openCookie(config, "session", cookie, thing)).toBeUndefined();
  });

  it.each(["", ".", "1.", "1.!!!", "1.AAAA", "2.AAAA", "a.b.c", "x".repeat(10_000)])(
    "is no value for the garbage %#, and never an error",
    async (garbage) => {
      expect(await openCookie(config, "session", garbage, thing)).toBeUndefined();
    },
  );

  it("is no value for a cookie of the other format", async () => {
    const other = { ...config, encryptCookies: !config.encryptCookies };

    expect(await openCookie(other, "session", await sealCookie(config, "session", value), thing)).toBeUndefined();
  });
});

describe("an encrypted cookie", () => {
  it("has the format of version 1: `1.` and base64url", async () => {
    expect(await sealCookie(encrypted, "session", value)).toMatch(/^1\.[\w-]+$/);
  });

  it("does not show what it holds, and differs on every sealing of the same value", async () => {
    const first = await sealCookie(encrypted, "session", value);
    const second = await sealCookie(encrypted, "session", value);

    expect(first).not.toBe(second);

    for (const cookie of [first, second]) {
      // Ciphertext is not UTF-8: read the bytes one to one as characters.
      expect(String.fromCharCode(...decodeBase64Url(cookie.slice(2)))).not.toContain("tok-4711");
    }
  });

  it("is refused in the cookie of another kind", async () => {
    const cookie = await sealCookie(encrypted, "state", value);

    expect(await openCookie(encrypted, "state", cookie, thing)).toEqual(value);
    expect(await openCookie(encrypted, "session", cookie, thing)).toBeUndefined();
    expect(await openCookie(encrypted, "pending", cookie, thing)).toBeUndefined();
  });
});

describe("a signed cookie", () => {
  it("is a JWT, readable by whoever holds it", async () => {
    const cookie = await sealCookie(signed, "session", value);

    expect(cookie).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);
    expect(JSON.parse(utf8Decode(decodeBase64Url(cookie.split(".")[1] ?? "")))).toEqual(value);
  });

  it("does not bind the kind: only the schema tells the cookies apart", async () => {
    const cookie = await sealCookie(signed, "state", value);

    expect(await openCookie(signed, "session", cookie, thing)).toEqual(value);
    expect(await openCookie(signed, "session", cookie, Schema.Struct({ other: Schema.String }))).toBeUndefined();
  });
});
