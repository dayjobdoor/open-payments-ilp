import * as Effect from "effect/Effect";
import { sha256, utf8Encode } from "../internal/bytes";
import { owned } from "../internal/web-bytes";
import { StreamError } from "./errors";
import { aesKey, hmac, latin1, memo } from "./key-cache";

const IV_LENGTH = 12;

const TAG_LENGTH = 16;

const KEY_LENGTH = 32;

const ENCRYPTION_KEY_LABEL = utf8Encode("ilp_stream_encryption");

const FULFILLMENT_KEY_LABEL = utf8Encode("ilp_stream_fulfillment");

/** Per-packet overhead of {@link encryptStreamData}: 12-byte IV + 16-byte GCM tag. */
export const STREAM_ENCRYPTION_OVERHEAD: number = IV_LENGTH + TAG_LENGTH;

/** The two keys derived from a STREAM shared secret. */
export interface StreamKeys {
  /** AES-256-GCM key protecting STREAM packet data: `HMAC-SHA256(secret, "ilp_stream_encryption")`. */
  readonly encryptionKey: Uint8Array;
  /** HMAC key deriving per-packet fulfillments: `HMAC-SHA256(secret, "ilp_stream_fulfillment")`. */
  readonly fulfillmentKey: Uint8Array;
}

/**
 * Derives the encryption and fulfillment keys from a STREAM shared secret (RFC 29 §3).
 * Secrets are 32 bytes by convention; like ilp-protocol-stream, any non-empty length is accepted so that
 * receivers with other secret sizes still interoperate.
 * Fails with `StreamError` (`invalid-key`) when the secret is empty.
 */
export function deriveStreamKeys(sharedSecret: Uint8Array): Effect.Effect<StreamKeys, StreamError> {
  if (sharedSecret.length === 0) {
    return Effect.fail(new StreamError({ reason: "invalid-key", message: "shared secret must not be empty" }));
  }

  return Effect.promise(() => deriveKeys(sharedSecret));
}

/** @internal {@link deriveStreamKeys} without the Effect wrapper, for callers already inside an async function. */
export async function deriveKeys(sharedSecret: Uint8Array): Promise<StreamKeys> {
  const [encryptionKey, fulfillmentKey] = await Promise.all([
    hmac(sharedSecret, ENCRYPTION_KEY_LABEL),
    hmac(sharedSecret, FULFILLMENT_KEY_LABEL),
  ]);

  return { encryptionKey, fulfillmentKey };
}

const keyCache = new Map<string, Promise<StreamKeys>>();

/** @internal {@link deriveKeys} memoized per shared secret; the returned keys must not be mutated or handed out. */
export function keysForSecret(sharedSecret: Uint8Array): Promise<StreamKeys> {
  return memo(keyCache, latin1(sharedSecret), () => deriveKeys(sharedSecret), 256);
}

/**
 * Encrypts `plaintext` with AES-256-GCM under a fresh random 12-byte IV.
 * Output layout (RFC 29 §3.1): `IV (12) | auth tag (16) | ciphertext`.
 * Fails with `StreamError` (`invalid-key`) when `key` is not 32 bytes.
 */
export function encryptStreamData(
  key: Uint8Array,
  plaintext: Uint8Array,
): Effect.Effect<Uint8Array<ArrayBuffer>, StreamError> {
  if (key.length !== KEY_LENGTH) {
    return Effect.fail(new StreamError({ reason: "invalid-key", message: "encryption key must be 32 bytes" }));
  }

  return Effect.promise(() => encrypt(key, plaintext));
}

/** @internal {@link encryptStreamData} for a key already checked to be 32 bytes. */
export async function encrypt(key: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

  // WebCrypto returns ciphertext | tag; the wire format puts the tag first.
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, tagLength: TAG_LENGTH * 8 },
      await aesKey(key),
      owned(plaintext),
    ),
  );

  const split = sealed.length - TAG_LENGTH;
  const out = new Uint8Array(IV_LENGTH + sealed.length);
  out.set(iv);
  out.set(sealed.subarray(split), IV_LENGTH);
  out.set(sealed.subarray(0, split), STREAM_ENCRYPTION_OVERHEAD);

  return out;
}

/**
 * Decrypts `IV | tag | ciphertext` produced by {@link encryptStreamData}.
 * Fails with `StreamError`: `invalid-key` for a key that is not 32 bytes, `decryption-failed` for input shorter
 * than IV + tag or when authentication fails (wrong key or tampered data).
 */
export function decryptStreamData(
  key: Uint8Array,
  data: Uint8Array,
): Effect.Effect<Uint8Array<ArrayBuffer>, StreamError> {
  if (key.length !== KEY_LENGTH) {
    return Effect.fail(new StreamError({ reason: "invalid-key", message: "encryption key must be 32 bytes" }));
  }

  if (data.length < STREAM_ENCRYPTION_OVERHEAD) {
    return Effect.fail(new StreamError({ reason: "decryption-failed", message: "ciphertext is too short" }));
  }

  return Effect.tryPromise({
    try: () => decrypt(key, data),
    catch: () => new StreamError({ reason: "decryption-failed", message: "authentication failed" }),
  });
}

/** @internal {@link decryptStreamData} for a 32-byte key and input of at least IV + tag; rejects when authentication fails. */
export async function decrypt(key: Uint8Array, data: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const input = owned(data);
  const sealed = new Uint8Array(input.length - IV_LENGTH);
  // WebCrypto expects ciphertext | tag; the wire format puts the tag first.
  sealed.set(input.subarray(STREAM_ENCRYPTION_OVERHEAD));
  sealed.set(input.subarray(IV_LENGTH, STREAM_ENCRYPTION_OVERHEAD), input.length - STREAM_ENCRYPTION_OVERHEAD);

  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: input.subarray(0, IV_LENGTH), tagLength: TAG_LENGTH * 8 },
      await aesKey(key),
      sealed,
    ),
  );
}

/**
 * The fulfillment for an encrypted STREAM packet: `HMAC-SHA256(fulfillmentKey, data)` (RFC 29 §3.3).
 * `data` is the full encrypted payload of the Prepare. Fails with `StreamError` (`invalid-key`) for an empty key.
 */
export function generateStreamFulfillment(
  fulfillmentKey: Uint8Array,
  data: Uint8Array,
): Effect.Effect<Uint8Array<ArrayBuffer>, StreamError> {
  if (fulfillmentKey.length === 0) {
    return Effect.fail(new StreamError({ reason: "invalid-key", message: "fulfillment key must not be empty" }));
  }

  return Effect.promise(() => hmac(fulfillmentKey, data));
}

/**
 * The execution condition matching {@link generateStreamFulfillment}: `SHA-256(HMAC-SHA256(fulfillmentKey, data))`.
 * Fails with `StreamError` (`invalid-key`) for an empty key.
 */
export function generateStreamCondition(
  fulfillmentKey: Uint8Array,
  data: Uint8Array,
): Effect.Effect<Uint8Array<ArrayBuffer>, StreamError> {
  return Effect.flatMap(generateStreamFulfillment(fulfillmentKey, data), (fulfillment) =>
    Effect.promise(() => sha256(owned(fulfillment))),
  );
}
