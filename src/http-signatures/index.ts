/**
 * HTTP message signatures (RFC 9421, Ed25519) as profiled by Open Payments and GNAP, plus RFC 9530
 * `Content-Digest` and the strict RFC 8941 structured-field parsing they need. Web Standards only.
 *
 * @see https://openpayments.dev/identity/http-signatures
 * @module
 */
export { createContentDigest, verifyContentDigest } from "./digest";

export { HttpSignatureError, type HttpSignatureErrorReason } from "./errors";

export {
  exportPublicJwk,
  generateEd25519KeyPair,
  importEd25519PrivateJwk,
  importEd25519PrivateKeyPem,
  importEd25519PublicJwk,
} from "./keys";

export { signRequest, type SignOptions, type SigningKey } from "./sign";

export {
  createSignatureBase,
  serializeSignatureParams,
  type SignatureParams,
  type SignatureParamValue,
  type SignedMessage,
} from "./signature-base";

export {
  parseDictionary,
  serializeInnerList,
  serializeItem,
  type SfBareItem,
  type SfDictionary,
  type SfInnerList,
  type SfItem,
  type SfParams,
} from "./structured-fields";

export { SIGNATURE_REPLAY_WINDOW_SECONDS, verifyRequest, type VerifiedSignature } from "./verify";
