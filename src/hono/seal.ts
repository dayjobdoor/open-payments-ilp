/**
 * Protects the values of the cookies: sealed with AES-256-GCM by default, or only signed as an HS256 JWT with
 * `encryptCookies: false`. Both use `secret`. Opening a value never throws: one that is tampered with, written with
 * another secret, another format or another version is simply not there.
 * @internal Not exported from the public entry point.
 */
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import { sign, verify } from "hono/jwt";
import { concatBytes, decodeBase64Url, encodeBase64Url, utf8Decode, utf8Encode } from "../internal/bytes";
import type { Resolved } from "./config";

/** Which cookie a value is for. It is authenticated with the value, so a value is refused in the cookie of another kind. */
type CookieKind = "session" | "state" | "pending";

/** What is stored in a cookie: a JSON object. */
type Payload = Parameters<typeof sign>[0];

/** The format of an encrypted value: `{VERSION}.{base64url(iv ‖ ciphertext ‖ tag)}`. A new format gets a new number. */
const VERSION = "1";

/** The recommended AES-GCM nonce size. Random per value: with one key, 2³² values keep a collision below 2⁻³². */
const IV_BYTES = 12;

const JWT_ALG = "HS256";

/** What the keys are derived from: the key of one format and version is no key of another. */
const KEY_LABEL = `open-payments-ilp/hono cookie v${VERSION}`;

type Protection = Pick<Resolved, "secret" | "encryptCookies">;

/** HKDF-SHA-256 of the secret: the AES key is not the secret, and no other use of the secret yields it. */
const deriveKey = async (secret: string): Promise<CryptoKey> => {
  const material = await crypto.subtle.importKey("raw", utf8Encode(secret), "HKDF", false, ["deriveKey"]);

  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: utf8Encode(KEY_LABEL), info: utf8Encode("aes-256-gcm") },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
};

const aad = (kind: CookieKind): Uint8Array<ArrayBuffer> => utf8Encode(`${VERSION}:${kind}`);

/** The cookie value for `value`. */
export const sealCookie = async (config: Protection, kind: CookieKind, value: Payload): Promise<string> => {
  if (!config.encryptCookies) return sign(value, config.secret, JWT_ALG);

  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));

  const sealed = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad(kind) },
    await deriveKey(config.secret),
    utf8Encode(JSON.stringify(value)),
  );

  return `${VERSION}.${encodeBase64Url(concatBytes(iv, new Uint8Array(sealed)))}`;
};

/**
 * The value in `cookie` as `schema` reads it, or `undefined` when it is not one this configuration wrote or `schema`
 * refuses it (nothing to trust, not an error).
 */
export const openCookie = async <T>(
  config: Protection,
  kind: CookieKind,
  cookie: string,
  schema: Schema.Codec<T>,
): Promise<T | undefined> => {
  let value: unknown;

  try {
    if (config.encryptCookies) {
      if (!cookie.startsWith(`${VERSION}.`)) return undefined;
      const bytes = decodeBase64Url(cookie.slice(VERSION.length + 1));

      const opened = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: bytes.subarray(0, IV_BYTES), additionalData: aad(kind) },
        await deriveKey(config.secret),
        bytes.subarray(IV_BYTES),
      );

      value = JSON.parse(utf8Decode(new Uint8Array(opened)));
    } else {
      value = await verify(cookie, config.secret, JWT_ALG);
    }
  } catch {
    return undefined;
  }

  const decoded = Schema.decodeUnknownResult(schema)(value);

  return Result.isSuccess(decoded) ? decoded.success : undefined;
};
