import type { YieldableError } from "effect/Cause";
import * as Data from "effect/Data";

export type HttpSignatureErrorReason =
  | "missing"
  | "malformed"
  | "unknown-key"
  | "invalid"
  | "digest-mismatch"
  | "expired"
  | "unsupported"
  | "invalid-config";

interface HttpSignatureErrorFields {
  readonly reason: HttpSignatureErrorReason;
  readonly message: string;
  readonly cause?: unknown;
}

// Explicit annotation: `isolatedDeclarations` forbids a call expression in an `extends` clause.
const Base: new (fields: HttpSignatureErrorFields) => YieldableError & {
  readonly _tag: "HttpSignatureError";
} & Readonly<HttpSignatureErrorFields> = Data.TaggedError("HttpSignatureError")<HttpSignatureErrorFields>;

/**
 * Every failure of the HTTP message signature toolkit.
 *
 * `reason` discriminates the failure:
 * - `missing`: a required header, signature member or covered header field is absent
 * - `malformed`: unparsable structured field, invalid component or parameter, unusable JWK (not Ed25519, `d` not
 *   matching `x`, or `x` a point of small order), a body that cannot be read or is longer than `maxBodyBytes`
 * - `unknown-key`: the `keyid` could not be resolved to a key
 * - `invalid`: signature does not verify, required component not covered, an `alg` parameter refused under
 *   `forbidAlg`, or created time is in the future
 * - `digest-mismatch`: the `Content-Digest` does not match the body, or a non-empty body is not covered by
 *   `content-digest` (an absent header is `missing`)
 * - `expired`: `created` is older than the allowed age, or `expires` has passed
 * - `unsupported`: valid syntax that this implementation does not handle (algorithm, component parameters)
 * - `invalid-config`: the verifier's own options are unusable (`maxAgeSeconds` or `maxBodyBytes` not a finite number
 *   of at least 0) or its clock returned an Invalid Date; not the request's fault
 *
 * `cause`, when set, is what actually went wrong underneath (for `unknown-key` from the default key fetch: the
 * timeout, status, size or JWKS error). It never reaches a client; log it from a `resolveClientKeys` wrapper.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9421
 */
export class HttpSignatureError extends Base {}
