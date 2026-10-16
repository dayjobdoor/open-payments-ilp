/**
 * Bounded caches for per-secret work, shared by the sender and the receiver.
 *
 * `SubtleCrypto.importKey` costs an async round trip as expensive as the HMAC or AES operation it enables,
 * and STREAM sends many packets under the same few secrets. Entries are keyed by the secret's bytes (never by array
 * identity, so a caller mutating its array cannot poison a cache) in small least-recently-used maps, so memory is
 * bounded no matter how many distinct secrets pass through. Failed computations are not cached.
 * @internal Not exported from any public entry point.
 */
import { owned } from "../internal/web-bytes";

const KEY_CAPACITY = 256;

const hmacKeys = new Map<string, Promise<CryptoKey>>();

const aesKeys = new Map<string, Promise<CryptoKey>>();

/** A `CryptoKey` for `HMAC-SHA256` signing with the raw key `raw` (non-empty). */
export function hmacKey(raw: Uint8Array): Promise<CryptoKey> {
  return cached(hmacKeys, raw, () =>
    crypto.subtle.importKey("raw", owned(raw), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]),
  );
}

/** A `CryptoKey` for `AES-GCM` encryption and decryption with the raw 32-byte key `raw`. */
export function aesKey(raw: Uint8Array): Promise<CryptoKey> {
  return cached(aesKeys, raw, () =>
    crypto.subtle.importKey("raw", owned(raw), "AES-GCM", false, ["encrypt", "decrypt"]),
  );
}

/** `HMAC-SHA256(raw, data)`. */
export async function hmac(raw: Uint8Array, data: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.sign("HMAC", await hmacKey(raw), owned(data)));
}

function cached(
  cache: Map<string, Promise<CryptoKey>>,
  raw: Uint8Array,
  importKey: () => Promise<CryptoKey>,
): Promise<CryptoKey> {
  return memo(cache, latin1(raw), importKey, KEY_CAPACITY);
}

/**
 * The value cached under `id`, computed by `create` on a miss. Concurrent misses share one computation.
 * A computation that rejects or yields `undefined` is not kept. Once a computation succeeds, the least recently
 * used entries beyond `capacity` are evicted, so failing lookups never push out good entries.
 */
export function memo<V>(
  cache: Map<string, Promise<V>>,
  id: string,
  create: () => Promise<V>,
  capacity: number,
): Promise<V> {
  const hit = cache.get(id);

  if (hit) {
    // Re-insert to mark as most recently used.
    cache.delete(id);
    cache.set(id, hit);

    return hit;
  }

  const created = create();
  cache.set(id, created);

  created.then(
    (value) => {
      if (value === undefined) cache.delete(id);
      else if (cache.size > capacity) {
        for (const oldest of cache.keys()) {
          cache.delete(oldest);
          break;
        }
      }
    },
    () => cache.delete(id),
  );

  return created;
}

/** One character per byte: a cheap, collision-free map key for secrets. */
export function latin1(bytes: Uint8Array): string {
  let out = "";

  for (const byte of bytes) out += String.fromCharCode(byte);

  return out;
}
