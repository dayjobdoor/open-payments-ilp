/**
 * Byte helpers shared by every subpath. Web Standards only (no Buffer).
 * @internal Not exported from any public entry point.
 */

const encoder = new TextEncoder();

const decoder = new TextDecoder("utf-8", { fatal: true });

export function utf8Encode(text: string): Uint8Array<ArrayBuffer> {
  return encoder.encode(text);
}

/** Throws a `TypeError` on invalid UTF-8. */
export function utf8Decode(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

export function concatBytes(...parts: ReadonlyArray<Uint8Array>): Uint8Array<ArrayBuffer> {
  let length = 0;

  for (const part of parts) length += part.length;
  const out = new Uint8Array(length);
  let offset = 0;

  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }

  return out;
}

/** Length-independent comparison time for equal-length inputs; different lengths return false immediately. */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;

  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);

  return diff === 0;
}

/** {@link constantTimeEqual} of the UTF-8 bytes of two strings. */
export function constantTimeEqualText(a: string, b: string): boolean {
  return constantTimeEqual(utf8Encode(a), utf8Encode(b));
}

export function toHex(bytes: Uint8Array): string {
  let out = "";

  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");

  return out;
}

export function encodeBase64(bytes: Uint8Array): string {
  let binary = "";

  for (const byte of bytes) binary += String.fromCharCode(byte);

  return btoa(binary);
}

/** Throws a `DOMException` (`InvalidCharacterError`) on malformed input. */
export function decodeBase64(text: string): Uint8Array<ArrayBuffer> {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);

  return out;
}

export function encodeBase64Url(bytes: Uint8Array): string {
  return encodeBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Accepts padded or unpadded input. Throws on characters outside the base64url alphabet. */
export function decodeBase64Url(text: string): Uint8Array<ArrayBuffer> {
  if (/[^A-Za-z0-9\-_=]/.test(text)) throw new TypeError("Invalid base64url");
  const base64 = text.replace(/-/g, "+").replace(/_/g, "/");

  return decodeBase64(base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "="));
}

export async function sha256(data: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

export async function hmacSha256(
  key: Uint8Array<ArrayBuffer>,
  data: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);

  return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, data));
}
