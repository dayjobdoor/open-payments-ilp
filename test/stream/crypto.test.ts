import { createDecipheriv, createHash, createHmac, randomBytes } from "node:crypto";
import * as Effect from "effect/Effect";
import * as Result from "effect/Result";
import { describe, expect, it } from "vite-plus/test";
import {
  decryptStreamData,
  deriveStreamKeys,
  encryptStreamData,
  generateStreamCondition,
  generateStreamFulfillment,
  STREAM_ENCRYPTION_OVERHEAD,
  StreamError,
} from "../../src/stream";
import {
  generateFulfillment,
  generateFulfillmentKey,
  generatePskEncryptionKey,
  decrypt,
  encrypt,
} from "ilp-protocol-stream/dist/src/crypto";

const run = <A>(effect: Effect.Effect<A, StreamError>): Promise<A> => Effect.runPromise(effect);

const failure = async <A>(effect: Effect.Effect<A, StreamError>): Promise<StreamError["reason"] | undefined> => {
  const result = await Effect.runPromise(Effect.result(effect));

  return Result.isFailure(result) ? result.failure.reason : undefined;
};

const sharedSecret = new Uint8Array(randomBytes(32));

describe("STREAM key derivation and fulfillment", () => {
  it("derives the same keys as ilp-protocol-stream", async () => {
    const { encryptionKey, fulfillmentKey } = await run(deriveStreamKeys(sharedSecret));

    expect(Buffer.from(encryptionKey).equals(await generatePskEncryptionKey(Buffer.from(sharedSecret)))).toBe(true);
    expect(Buffer.from(fulfillmentKey).equals(await generateFulfillmentKey(Buffer.from(sharedSecret)))).toBe(true);
  });

  it("generates the same fulfillment and condition as the reference", async () => {
    const { fulfillmentKey } = await run(deriveStreamKeys(sharedSecret));
    const data = new Uint8Array(randomBytes(100));
    const reference = await generateFulfillment(Buffer.from(fulfillmentKey), Buffer.from(data));

    expect(Buffer.from(await run(generateStreamFulfillment(fulfillmentKey, data))).equals(reference)).toBe(true);
    expect(
      Buffer.from(await run(generateStreamCondition(fulfillmentKey, data))).equals(
        createHash("sha256").update(reference).digest(),
      ),
    ).toBe(true);
  });

  it("rejects an empty shared secret but, like ilp-protocol-stream, accepts any other length", async () => {
    expect(await failure(deriveStreamKeys(new Uint8Array(0)))).toBe("invalid-key");

    for (const length of [1, 12, 31, 33, 64]) {
      const secret = new Uint8Array(randomBytes(length));
      const { encryptionKey } = await run(deriveStreamKeys(secret));

      expect(Buffer.from(encryptionKey).equals(await generatePskEncryptionKey(Buffer.from(secret)))).toBe(true);
    }

    expect(await failure(generateStreamFulfillment(new Uint8Array(0), new Uint8Array(1)))).toBe("invalid-key");
  });

  it("matches an independent HMAC computation", async () => {
    const { encryptionKey } = await run(deriveStreamKeys(sharedSecret));

    expect(
      Buffer.from(encryptionKey).equals(createHmac("sha256", sharedSecret).update("ilp_stream_encryption").digest()),
    ).toBe(true);
  });
});

describe("STREAM packet encryption (AES-256-GCM, IV | tag | ciphertext)", () => {
  const key = new Uint8Array(randomBytes(32));

  it.each([0, 1, 15, 16, 17, 1000, 32000])("round-trips %i bytes with a 28-byte overhead", async (length) => {
    const plaintext = new Uint8Array(randomBytes(length));
    const sealed = await run(encryptStreamData(key, plaintext));

    expect(sealed.length).toBe(length + STREAM_ENCRYPTION_OVERHEAD);
    expect(await run(decryptStreamData(key, sealed))).toEqual(plaintext);
  });

  it("uses a fresh IV for every call", async () => {
    const plaintext = new Uint8Array(8);
    const [a, b] = [await run(encryptStreamData(key, plaintext)), await run(encryptStreamData(key, plaintext))];

    expect(Buffer.from(a.subarray(0, 12)).equals(Buffer.from(b.subarray(0, 12)))).toBe(false);
  });

  it("is decrypted by ilp-protocol-stream, and decrypts its output", async () => {
    const plaintext = new Uint8Array(randomBytes(77));

    expect(
      Buffer.from(await decrypt(Buffer.from(key), Buffer.from(await run(encryptStreamData(key, plaintext))))),
    ).toEqual(Buffer.from(plaintext));
    expect(await run(decryptStreamData(key, await encrypt(Buffer.from(key), Buffer.from(plaintext))))).toEqual(
      plaintext,
    );
  });

  it("is decrypted by node's AES-256-GCM given the documented layout", async () => {
    const plaintext = new Uint8Array(randomBytes(33));
    const sealed = await run(encryptStreamData(key, plaintext));
    const decipher = createDecipheriv("aes-256-gcm", key, sealed.subarray(0, 12));
    decipher.setAuthTag(Buffer.from(sealed.subarray(12, 28)));

    expect(Buffer.concat([decipher.update(sealed.subarray(28)), decipher.final()])).toEqual(Buffer.from(plaintext));
  });

  it("fails authentication for tampering, truncation, a wrong key and short input", async () => {
    const sealed = await run(encryptStreamData(key, Uint8Array.of(1, 2, 3, 4)));

    for (const index of [0, 12, 28, sealed.length - 1]) {
      const tampered = sealed.slice();
      tampered.fill(~(tampered[index] ?? 0) & 0xff, index, index + 1);

      expect(await failure(decryptStreamData(key, tampered))).toBe("decryption-failed");
    }

    expect(await failure(decryptStreamData(key, sealed.slice(0, sealed.length - 1)))).toBe("decryption-failed");
    expect(await failure(decryptStreamData(new Uint8Array(randomBytes(32)), sealed))).toBe("decryption-failed");
    expect(await failure(decryptStreamData(key, new Uint8Array(27)))).toBe("decryption-failed");
    expect(await failure(decryptStreamData(key, new Uint8Array(0)))).toBe("decryption-failed");
  });

  it("requires a 32-byte key", async () => {
    expect(await failure(encryptStreamData(new Uint8Array(16), new Uint8Array(1)))).toBe("invalid-key");
    expect(await failure(decryptStreamData(new Uint8Array(16), new Uint8Array(40)))).toBe("invalid-key");
  });
});
