import * as Effect from "effect/Effect";
import { decodeBase64, decodeBase64Url, toHex, utf8Encode } from "../internal/bytes";
import { HttpSignatureError } from "./errors";

const ED25519 = { name: "Ed25519" } as const;

function publicParts(jwk: JsonWebKey): JsonWebKey {
  return {
    ...(jwk.kty !== undefined && { kty: jwk.kty }),
    ...(jwk.crv !== undefined && { crv: jwk.crv }),
    ...(jwk.x !== undefined && { x: jwk.x }),
  };
}

/**
 * Generates an extractable Ed25519 key pair via WebCrypto. `publicJwk` contains only `kty`, `crv`, `x`.
 *
 * @see https://www.rfc-editor.org/rfc/rfc8037
 */
export const generateEd25519KeyPair: () => Effect.Effect<
  { readonly privateKey: CryptoKey; readonly publicJwk: JsonWebKey },
  never
> = () =>
  Effect.promise(async () => {
    const pair = await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"]);
    const publicJwk = publicParts(await crypto.subtle.exportKey("jwk", pair.publicKey));

    return { privateKey: pair.privateKey, publicJwk };
  });

/**
 * The `y` coordinates (little-endian, sign bit cleared) of the eight points of small order on Ed25519, which libsodium
 * also refuses: 0, 1, p-1 and the non-canonical p and p+1 (the same points), and the two of order 8. As a public
 * key such a point makes `R = identity, S = 0` verify for every message on runtimes that do not check (Bun).
 */
const SMALL_ORDER_Y: ReadonlySet<string> = new Set([
  "00".repeat(32),
  `01${"00".repeat(31)}`,
  `ec${"ff".repeat(30)}7f`,
  `ed${"ff".repeat(30)}7f`,
  `ee${"ff".repeat(30)}7f`,
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
]);

/** `true` when `x` is not 32 bytes of base64url, or encodes a point of small order. */
function isUnusablePublicPoint(x: string): boolean {
  try {
    const point = decodeBase64Url(x);

    if (point.length !== 32) return true;
    const masked = point.slice();

    masked[31] = (masked[31] ?? 0) & 0x7f;

    return SMALL_ORDER_Y.has(toHex(masked));
  } catch {
    return true;
  }
}

function checkOkp(jwk: JsonWebKey, needsPrivate: boolean): HttpSignatureError | undefined {
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || jwk.x === undefined) {
    return new HttpSignatureError({ reason: "malformed", message: "JWK is not an Ed25519 OKP key" });
  }

  if (isUnusablePublicPoint(jwk.x)) {
    return new HttpSignatureError({ reason: "malformed", message: "JWK x is not a usable Ed25519 public key" });
  }

  if (needsPrivate && jwk.d === undefined) {
    return new HttpSignatureError({ reason: "malformed", message: "JWK has no private component (d)" });
  }
}

/**
 * Imports an Ed25519 public JWK (`kty: OKP`, `crv: Ed25519`) for verification. Only `kty`, `crv` and `x` are
 * used; a private `d` or other members are ignored. A public key of small order (the identity among them) is refused
 * on every runtime: it would let an all-zero signature verify.
 *
 * Fails with `HttpSignatureError` (`malformed`).
 */
export const importEd25519PublicJwk: (jwk: JsonWebKey) => Effect.Effect<CryptoKey, HttpSignatureError> = (jwk) => {
  const problem = checkOkp(jwk, false);

  if (problem) return Effect.fail(problem);

  return Effect.tryPromise({
    try: () => crypto.subtle.importKey("jwk", publicParts(jwk), ED25519, true, ["verify"]),
    catch: () => new HttpSignatureError({ reason: "malformed", message: "Invalid Ed25519 public key" }),
  });
};

/**
 * Imports an Ed25519 private JWK (with `d`) as a non-extractable signing key. Whether `x` belongs to `d` is checked by
 * signing and verifying a probe message, because Bun imports a mismatched pair that Node rejects, and its signatures
 * would then never verify. A small-order `x` is refused as in {@link importEd25519PublicJwk}.
 *
 * Fails with `HttpSignatureError` (`malformed`).
 */
export const importEd25519PrivateJwk: (jwk: JsonWebKey) => Effect.Effect<CryptoKey, HttpSignatureError> = (jwk) => {
  const problem = checkOkp(jwk, true);

  if (problem) return Effect.fail(problem);

  return Effect.tryPromise({
    try: async () => {
      const privateKey = await crypto.subtle.importKey(
        "jwk",
        { ...publicParts(jwk), ...(jwk.d !== undefined && { d: jwk.d }) },
        ED25519,
        false,
        ["sign"],
      );

      const publicKey = await crypto.subtle.importKey("jwk", publicParts(jwk), ED25519, false, ["verify"]);
      const probe = utf8Encode("open-payments-ilp: private key check");
      const signature = await crypto.subtle.sign(ED25519, privateKey, probe);

      if (!(await crypto.subtle.verify(ED25519, publicKey, signature, probe))) throw new Error("d does not match x");

      return privateKey;
    },
    catch: () => new HttpSignatureError({ reason: "malformed", message: "Invalid Ed25519 private key" }),
  });
};

const PEM_PKCS8 = /^-----BEGIN PRIVATE KEY-----([A-Za-z0-9+/=\s]+)-----END PRIVATE KEY-----$/;

/**
 * Imports an Ed25519 private key from an unencrypted PKCS #8 PEM (`-----BEGIN PRIVATE KEY-----`), the format
 * `openssl genpkey -algorithm ed25519` writes and the one `@interledger/http-signature-utils`' `loadKey` and
 * Rafiki's `PRIVATE_KEY` deployments use. The key is non-extractable. To publish the matching JWK, generate it
 * with {@link generateEd25519KeyPair} or derive it from the PEM outside this library.
 *
 * Fails with `HttpSignatureError` (`malformed`) when the text is not a PKCS #8 PEM or not an Ed25519 key.
 *
 * @see https://www.rfc-editor.org/rfc/rfc8410#section-7
 */
export const importEd25519PrivateKeyPem: (pem: string) => Effect.Effect<CryptoKey, HttpSignatureError> = (pem) => {
  const base64 = PEM_PKCS8.exec(pem.trim())?.[1];

  const malformed = (): HttpSignatureError =>
    new HttpSignatureError({ reason: "malformed", message: "Not an Ed25519 PKCS #8 PEM private key" });

  if (base64 === undefined) return Effect.fail(malformed());

  return Effect.tryPromise({
    try: () => crypto.subtle.importKey("pkcs8", decodeBase64(base64.replace(/\s/g, "")), ED25519, false, ["sign"]),
    catch: malformed,
  });
};

/**
 * Exports the public half of an Ed25519 key as a minimal JWK (`kty`, `crv`, `x`). Works for public keys and for
 * extractable private keys (e.g. from `generateEd25519KeyPair`). With `keyId`, returns the JWK Open Payments
 * publishes in `{walletAddress}/jwks.json`, as the reference `generateJwk` does: `{ kid, alg: "EdDSA", kty, crv, x }`.
 *
 * Fails with `HttpSignatureError` (`malformed`) when the key is not extractable.
 *
 * @see https://openpayments.dev/identity/client-keys
 */
export const exportPublicJwk: (
  key: CryptoKey,
  options?: { readonly keyId?: string },
) => Effect.Effect<JsonWebKey, HttpSignatureError> = (key, options) =>
  Effect.tryPromise({
    try: async () => {
      const jwk = publicParts(await crypto.subtle.exportKey("jwk", key));

      return options?.keyId === undefined ? jwk : { kid: options.keyId, alg: "EdDSA", ...jwk };
    },
    catch: () => new HttpSignatureError({ reason: "malformed", message: "Key is not extractable" }),
  });
