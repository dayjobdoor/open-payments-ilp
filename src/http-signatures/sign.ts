import * as Effect from "effect/Effect";
import { encodeBase64, utf8Encode } from "../internal/bytes";
import { createContentDigest } from "./digest";
import { HttpSignatureError } from "./errors";
import { createSignatureBase, serializeSignatureParams, type SignedMessage } from "./signature-base";

/** An Ed25519 signing key identified by the `keyid` that verifiers resolve to the public JWK. */
export interface SigningKey {
  readonly keyId: string;
  readonly privateKey: CryptoKey;
}

const LABEL = "sig1";

/** Optional signing parameters: `created`, `tag`, a `nonce` parameter, and the `Content-Digest` algorithm (default `sha-512`, as the Open Payments reference client). */
export interface SignOptions {
  readonly created?: Date;
  readonly tag?: string;
  readonly nonce?: string;
  readonly digest?: "sha-256" | "sha-512";
}

/**
 * Signs `message` in place: sets `Content-Digest` (sha-512) and `Content-Length` when `body` is given, then
 * `Signature-Input` and `Signature` on `message.headers`. `body` must be the exact bytes that will be sent.
 * Shared by {@link signRequest} and the Open Payments client, which already holds the encoded body.
 * @internal Not exported from the public entry point.
 */
export const signHeaders: (
  message: SignedMessage,
  body: Uint8Array | undefined,
  key: SigningKey,
  options?: SignOptions,
) => Effect.Effect<void, HttpSignatureError> = (message, body, key, options) =>
  Effect.gen(function* () {
    const { headers } = message;
    const components = ["@method", "@target-uri"];

    if (body !== undefined) {
      headers.set("Content-Digest", yield* createContentDigest(body, options?.digest ?? "sha-512"));
      headers.set("Content-Length", String(body.byteLength));
    }

    if (headers.has("authorization")) components.push("authorization");

    if (body !== undefined) {
      components.push("content-digest", "content-length");

      if (headers.has("content-type")) components.push("content-type");
    }

    const created = Math.floor((options?.created ?? new Date()).getTime() / 1000);

    const params: Array<readonly [string, string | number]> = [
      ["created", created],
      ["keyid", key.keyId],
    ];

    if (options?.nonce !== undefined) params.push(["nonce", options.nonce]);

    if (options?.tag !== undefined) params.push(["tag", options.tag]);

    const base = yield* Effect.fromResult(createSignatureBase(message, components, params));
    const paramsValue = yield* Effect.fromResult(serializeSignatureParams(components, params));

    const signature = yield* Effect.tryPromise({
      try: () => crypto.subtle.sign("Ed25519", key.privateKey, utf8Encode(base)),
      catch: () =>
        new HttpSignatureError({ reason: "malformed", message: "Signing key is not a usable Ed25519 private key" }),
    });

    headers.set("Signature-Input", `${LABEL}=${paramsValue}`);
    headers.set("Signature", `${LABEL}=:${encodeBase64(new Uint8Array(signature))}:`);
  });

/**
 * Signs a request per Open Payments (RFC 9421, Ed25519, label `sig1`) and returns a new `Request` with
 * `Signature` and `Signature-Input` headers. When a body is present it also sets `Content-Digest` (`options.digest`,
 * default sha-512 as the reference client does) and `Content-Length`.
 *
 * Covered components: `@method`, `@target-uri`, `authorization` (if present) and, with a body,
 * `content-digest`, `content-length` and `content-type` (if present). Parameters: `created`, `keyid`, plus
 * `nonce` and `tag` when given.
 *
 * The input request's body is handed over to the returned request; use the returned request. Fails with `HttpSignatureError`
 * (`malformed`) when the body cannot be read, the keyid is not printable ASCII, or signing fails.
 *
 * @see https://openpayments.dev/identity/http-signatures
 * @see https://www.rfc-editor.org/rfc/rfc9421
 */
export const signRequest: (
  request: Request,
  key: SigningKey,
  options?: SignOptions,
) => Effect.Effect<Request, HttpSignatureError> = (request, key, options) =>
  Effect.gen(function* () {
    const headers = new Headers(request.headers);

    const body =
      request.body === null
        ? undefined
        : yield* Effect.tryPromise({
            try: async () => new Uint8Array(await request.clone().arrayBuffer()),
            catch: () => new HttpSignatureError({ reason: "malformed", message: "Request body cannot be read" }),
          });

    yield* signHeaders({ method: request.method, url: request.url, headers }, body, key, options);

    return new Request(request, { headers });
  });
