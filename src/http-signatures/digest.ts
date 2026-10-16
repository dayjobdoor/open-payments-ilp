import * as Effect from "effect/Effect";
import { constantTimeEqual, encodeBase64 } from "../internal/bytes";
import { HttpSignatureError } from "./errors";
import { parseDictionary } from "./structured-fields";

type DigestAlgorithm = "sha-256" | "sha-512";

const WEBCRYPTO_NAME = { "sha-256": "SHA-256", "sha-512": "SHA-512" } as const satisfies Record<
  DigestAlgorithm,
  string
>;

async function digest(algorithm: DigestAlgorithm, body: Uint8Array): Promise<Uint8Array> {
  // Copy: WebCrypto rejects views over shared or oversized buffers on some runtimes.
  return new Uint8Array(await crypto.subtle.digest(WEBCRYPTO_NAME[algorithm], new Uint8Array(body)));
}

/**
 * Builds an RFC 9530 `Content-Digest` header value over the exact representation bytes, e.g.
 * `sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:`.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9530#section-2
 */
export const createContentDigest: (body: Uint8Array, algorithm?: DigestAlgorithm) => Effect.Effect<string, never> = (
  body,
  algorithm = "sha-256",
) => Effect.promise(async () => `${algorithm}=:${encodeBase64(await digest(algorithm, body))}:`);

/**
 * Verifies a `Content-Digest` header against body bytes. Every supported algorithm (sha-256, sha-512) present in
 * the header must match; unknown algorithms are ignored but at least one supported one is required.
 *
 * Fails with `HttpSignatureError`: `malformed` (unparsable header), `unsupported` (no supported algorithm),
 * `digest-mismatch`.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9530#section-2
 */
export const verifyContentDigest: (header: string, body: Uint8Array) => Effect.Effect<void, HttpSignatureError> = (
  header,
  body,
) =>
  Effect.gen(function* () {
    const dictionary = yield* Effect.fromResult(parseDictionary(header));
    let checked = 0;

    for (const [name, member] of dictionary) {
      if (name !== "sha-256" && name !== "sha-512") continue;

      if ("items" in member || member.value.type !== "binary") {
        return yield* new HttpSignatureError({
          reason: "malformed",
          message: `Content-Digest ${name} must be a byte sequence`,
        });
      }

      const actual = yield* Effect.promise(() => digest(name, body));
      checked++;

      if (!constantTimeEqual(actual, member.value.value)) {
        return yield* new HttpSignatureError({
          reason: "digest-mismatch",
          message: `Content-Digest ${name} does not match the body`,
        });
      }
    }

    if (checked === 0) {
      return yield* new HttpSignatureError({
        reason: "unsupported",
        message: "Content-Digest has no supported algorithm",
      });
    }
  });
