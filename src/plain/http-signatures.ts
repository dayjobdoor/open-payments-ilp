import * as Effect from "effect/Effect";
import { HttpSignatureError } from "../http-signatures/errors";
import * as digest from "../http-signatures/digest";
import * as keys from "../http-signatures/keys";
import * as signatureBase from "../http-signatures/signature-base";
import * as signing from "../http-signatures/sign";
import * as structuredFields from "../http-signatures/structured-fields";
import * as verification from "../http-signatures/verify";
import { attemptResolver, sync, task, type Sync, type Task } from "../internal/plain";

/**
 * Promise flavour of `open-payments-ilp/http-signatures` (RFC 9421, Ed25519): async functions return a `Promise` that
 * rejects with `HttpSignatureError`, and the codecs return the value and throw it. Keys are WebCrypto keys or JWKs;
 * nothing reads the file system.
 */

export { HttpSignatureError, type HttpSignatureErrorReason } from "../http-signatures/errors";
export { type SignatureParams, type SignatureParamValue, type SignedMessage } from "../http-signatures/signature-base";
export {
  type SfBareItem,
  type SfDictionary,
  type SfInnerList,
  type SfItem,
  type SfParams,
} from "../http-signatures/structured-fields";
export { SIGNATURE_REPLAY_WINDOW_SECONDS, type VerifiedSignature } from "../http-signatures/verify";
export { type SignOptions, type SigningKey } from "../http-signatures/sign";

/** Builds the RFC 9421 signature base; throws `HttpSignatureError` for a missing header or an invalid component. */
export const createSignatureBase: Sync<typeof signatureBase.createSignatureBase> = sync(
  signatureBase.createSignatureBase,
);
/** Serializes the `@signature-params` value; throws `HttpSignatureError` for an invalid component or parameter. */
export const serializeSignatureParams: Sync<typeof signatureBase.serializeSignatureParams> = sync(
  signatureBase.serializeSignatureParams,
);
/** Parses an RFC 8941 Dictionary Structured Field; throws `HttpSignatureError` (`malformed`) on invalid input. */
export const parseDictionary: Sync<typeof structuredFields.parseDictionary> = sync(structuredFields.parseDictionary);
/** Serializes an RFC 8941 Item; throws `HttpSignatureError` (`malformed`) for an invalid value or parameter. */
export const serializeItem: Sync<typeof structuredFields.serializeItem> = sync(structuredFields.serializeItem);
/** Serializes an RFC 8941 Inner List; throws `HttpSignatureError` (`malformed`) for an invalid item or parameter. */
export const serializeInnerList: Sync<typeof structuredFields.serializeInnerList> = sync(
  structuredFields.serializeInnerList,
);

export const generateEd25519KeyPair: Task<typeof keys.generateEd25519KeyPair> = task(keys.generateEd25519KeyPair);
export const importEd25519PublicJwk: Task<typeof keys.importEd25519PublicJwk> = task(keys.importEd25519PublicJwk);
export const importEd25519PrivateJwk: Task<typeof keys.importEd25519PrivateJwk> = task(keys.importEd25519PrivateJwk);
export const importEd25519PrivateKeyPem: Task<typeof keys.importEd25519PrivateKeyPem> = task(
  keys.importEd25519PrivateKeyPem,
);
export const exportPublicJwk: Task<typeof keys.exportPublicJwk> = task(keys.exportPublicJwk);
export const createContentDigest: Task<typeof digest.createContentDigest> = task(digest.createContentDigest);
export const verifyContentDigest: Task<typeof digest.verifyContentDigest> = task(digest.verifyContentDigest);
export const signRequest: Task<typeof signing.signRequest> = task(signing.signRequest);

/** An Ed25519 private key as a WebCrypto key, a private JWK, or a PKCS#8 PEM string. */
export type PrivateKeyInput = CryptoKey | JsonWebKey | string;

const isEd25519PrivateCryptoKey = (key: unknown): key is CryptoKey => {
  if (typeof key !== "object" || key === null) return false;
  // Where the runtime has `CryptoKey`, only its instances count; without that global the shape decides.
  if (typeof CryptoKey === "function" && !(key instanceof CryptoKey)) return false;
  // SAFETY: `key` is a non-null object; its two members are read as `unknown` and checked below.
  const { type, algorithm } = key as { type?: unknown; algorithm?: { name?: unknown } };

  return type === "private" && algorithm?.name === "Ed25519";
};

const isJwk = (key: unknown): key is JsonWebKey =>
  typeof key === "object" && key !== null && "kty" in key && typeof key.kty === "string";

/**
 * Resolves a {@link PrivateKeyInput} to a signing `CryptoKey`. Only an Ed25519 private `CryptoKey`, a JWK (it has a
 * string `kty`) or a PEM string is accepted; anything else (a Node `KeyObject`, a public key) rejects with
 * `HttpSignatureError` reason `malformed`.
 */
export const importPrivateKey = async (key: PrivateKeyInput): Promise<CryptoKey> => {
  if (typeof key === "string") return importEd25519PrivateKeyPem(key);
  if (isEd25519PrivateCryptoKey(key)) return key;
  if (isJwk(key)) return importEd25519PrivateJwk(key);

  throw new HttpSignatureError({
    reason: "malformed",
    message: "Private key must be an Ed25519 private CryptoKey, a private JWK or a PKCS#8 PEM string",
  });
};

type VerifyOptions = Parameters<typeof verification.verifyRequest>[1];

/**
 * Verifies the RFC 9421 signature on `request`. `resolveKey` maps a `keyid` to the signer's public JWK and may be
 * async. Returning `null`/`undefined` fails with `HttpSignatureError` reason `unknown-key`, and so does throwing an
 * `HttpSignatureError` (which keeps its own reason). Any other throw is a bug in the resolver: the returned promise
 * rejects with that error itself.
 */
export const verifyRequest = (
  request: Request,
  options: Omit<VerifyOptions, "resolveKey"> & {
    readonly resolveKey: (keyId: string) => JsonWebKey | null | undefined | Promise<JsonWebKey | null | undefined>;
  },
): Promise<verification.VerifiedSignature> =>
  Effect.runPromise(
    verification.verifyRequest(request, {
      ...options,
      resolveKey: (keyId) =>
        attemptResolver(() => options.resolveKey(keyId)).pipe(
          Effect.flatMap((jwk) =>
            jwk == null
              ? Effect.fail(new HttpSignatureError({ reason: "unknown-key", message: "Unknown keyid" }))
              : Effect.succeed(jwk),
          ),
        ),
    }),
  );
