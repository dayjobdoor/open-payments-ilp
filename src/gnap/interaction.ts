import * as Effect from "effect/Effect";
import { constantTimeEqual, encodeBase64, encodeBase64Url, utf8Encode } from "../internal/bytes";

/** Hash methods of RFC 9635 §4.2.3 that WebCrypto can compute. */
export type InteractionHashMethod = "sha-256" | "sha-384" | "sha-512";

/** Inputs of the interaction hash. */
export interface InteractionHashInput {
  /** `interact.finish.nonce` the client sent in its grant request. */
  readonly clientNonce: string;
  /** The nonce the authorisation server returned as `interact.finish`. */
  readonly serverNonce: string;
  /** The `interact_ref` delivered through the finish redirect. */
  readonly interactRef: string;
  /** The grant endpoint URI the client sent its grant request to. */
  readonly grantEndpoint: string;
  /** Hash method; defaults to `sha-256`. */
  readonly method?: InteractionHashMethod;
  /**
   * Text encoding of the digest. `base64url` (unpadded, the default) is what RFC 9635 §4.2.3 specifies;
   * Rafiki's authorisation server emits padded standard `base64`.
   */
  readonly encoding?: "base64url" | "base64";
}

const ALGORITHMS = { "sha-256": "SHA-256", "sha-384": "SHA-384", "sha-512": "SHA-512" } as const;

/**
 * Computes the `hash` the authorisation server sends with the finish redirect: the encoded (default base64url,
 * unpadded) digest of `clientNonce \n serverNonce \n interactRef \n grantEndpoint`.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9635#section-4.2.3
 */
export function computeInteractionHash(input: InteractionHashInput): Effect.Effect<string> {
  const base = [input.clientNonce, input.serverNonce, input.interactRef, input.grantEndpoint].join("\n");

  const encode = input.encoding === "base64" ? encodeBase64 : encodeBase64Url;

  return Effect.promise(async () =>
    encode(new Uint8Array(await crypto.subtle.digest(ALGORITHMS[input.method ?? "sha-256"], utf8Encode(base)))),
  );
}

/**
 * Client side of the finish redirect: recomputes the hash and compares it to the `hash` query parameter in
 * constant time. Accepts the unpadded base64url form of RFC 9635 §4.2.3 and the padded base64 form Rafiki sends,
 * so the caller need not know which authorisation server it talks to. A client MUST NOT continue the grant when
 * this is `false`.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9635#section-4.2.3
 */
export function verifyInteractionHash(
  input: Omit<InteractionHashInput, "encoding"> & { readonly hash: string },
): Effect.Effect<boolean> {
  return Effect.gen(function* () {
    const url = yield* computeInteractionHash({ ...input, encoding: "base64url" });
    const padded = yield* computeInteractionHash({ ...input, encoding: "base64" });
    const presented = utf8Encode(input.hash);
    // Both comparisons always run: no early exit on the first match.
    const matches = [constantTimeEqual(utf8Encode(url), presented), constantTimeEqual(utf8Encode(padded), presented)];

    return matches.includes(true);
  });
}

/**
 * The client's finish URI with `interact_ref` and `hash` query parameters appended.
 * Throws a `TypeError` when `finishUri` is not an absolute URL.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9635#section-4.2.3
 */
export function buildFinishUrl(
  finishUri: string,
  params: { readonly interactRef: string; readonly hash: string },
): string {
  const url = new URL(finishUri);

  url.searchParams.set("interact_ref", params.interactRef);
  url.searchParams.set("hash", params.hash);

  return url.toString();
}

/**
 * The client's finish URI marked `result=grant_rejected`, used when the resource owner denied the grant
 * (Open Payments / Rafiki convention; no hash is sent).
 * Throws a `TypeError` when `finishUri` is not an absolute URL.
 */
export function buildRejectedFinishUrl(finishUri: string): string {
  const url = new URL(finishUri);

  url.searchParams.set("result", "grant_rejected");

  return url.toString();
}
