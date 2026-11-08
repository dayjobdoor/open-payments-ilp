import * as Effect from "effect/Effect";
import { utf8Encode } from "../internal/bytes";
import { announcesMoreThan, readCapped } from "../internal/http";
import { verifyContentDigest } from "./digest";
import { HttpSignatureError } from "./errors";
import { importEd25519PublicJwk } from "./keys";
import { createSignatureBase, type SignatureParams } from "./signature-base";
import { parseDictionary, type SfDictionary } from "./structured-fields";

/** The outcome of a successful verification. `components` are the covered component names in signed order. */
export interface VerifiedSignature {
  readonly keyId: string;
  readonly label: string;
  readonly created: Date;
  readonly components: ReadonlyArray<string>;
  /** The `nonce` signature parameter, when the signer included one. */
  readonly nonce?: string;
  /**
   * How long, in seconds from now, this signature could still have been accepted at most: remember its nonce (or the
   * signature) this long to stop replays. It follows the `maxAgeSeconds` the verification used, which
   * {@link SIGNATURE_REPLAY_WINDOW_SECONDS} does not.
   */
  readonly replayWindowSeconds: number;
}

const DEFAULT_MAX_AGE_SECONDS = 300;

/** Largest body `verifyRequest` reads when `maxBodyBytes` is not given. */
const DEFAULT_MAX_BODY_BYTES = 64 * 1024;

/** Tolerated clock skew for a `created` time ahead of the verifier's clock. */
const FUTURE_SKEW_SECONDS = 30;

/**
 * How long a signature verified with the default `maxAgeSeconds` (300) stays acceptable at most: 300 s of age, 30 s
 * of future skew and 1 s for the whole-second rounding of `created` (a signature stamped 30 s ahead of the verifier's
 * clock stays acceptable until the verifier's whole second `created + 300` is over, up to one second after 330 s).
 * Remember a nonce (or the signature) this long to stop replays. A verifier passing a larger `maxAgeSeconds` must
 * remember it longer: use `VerifiedSignature.replayWindowSeconds`, which is `maxAgeSeconds + 31`.
 */
export const SIGNATURE_REPLAY_WINDOW_SECONDS: number = DEFAULT_MAX_AGE_SECONDS + FUTURE_SKEW_SECONDS + 1;

const ED25519_SIGNATURE_BYTES = 64;

function fail(reason: HttpSignatureError["reason"], message: string): Effect.Effect<never, HttpSignatureError> {
  return Effect.fail(new HttpSignatureError({ reason, message }));
}

const isLimit = (value: number | undefined): boolean => value === undefined || (Number.isFinite(value) && value >= 0);

function header(request: Request, name: string): Effect.Effect<string, HttpSignatureError> {
  const value = request.headers.get(name);

  return value === null ? fail("missing", `Missing ${name} header`) : Effect.succeed(value);
}

/** The body of a clone of `request`, or `null` when it is longer than `maxBytes` (read no further than that). */
function readBody(request: Request, maxBytes: number): Effect.Effect<Uint8Array | null, HttpSignatureError> {
  return Effect.tryPromise({
    try: async () => (announcesMoreThan(request.headers, maxBytes) ? null : readCapped(request.clone().body, maxBytes)),
    catch: () => new HttpSignatureError({ reason: "malformed", message: "Request body cannot be read" }),
  });
}

function member(dictionary: SfDictionary, label: string): SfDictionary[number][1] | undefined {
  return dictionary.find(([name]) => name === label)?.[1];
}

/**
 * Verifies the `sig1` HTTP message signature of a request (RFC 9421, Ed25519) the way Open Payments servers do.
 *
 * Checks, in order: the options and clock (finite numbers, a valid date), header syntax (strict RFC 8941),
 * supported `alg` (ed25519 or absent, and absent under `forbidAlg`), a `created` and a `keyid` parameter, `created`
 * within `maxAgeSeconds` (default 300; `expires`, if present, must not have passed), required components covered
 * (`@method` and `@target-uri` unless `requiredComponents` says otherwise; `authorization` must be covered
 * whenever the request carries it), body integrity (a non-empty body must be covered by a matching `Content-Digest`),
 * every covered header present, then `resolveKey(keyid)` and the Ed25519 signature. `resolveKey` is only called
 * once every structural check has passed, so it can safely perform expensive or remote lookups.
 *
 * The body is read, from a clone (the request stays usable), only when a digest has to be checked: when
 * `content-digest` is covered, at most `maxBodyBytes` of it (default 65536; a longer body fails as `malformed`
 * without being drained, so cap the size before calling as well when the server buffers requests itself). Otherwise
 * nothing is read beyond finding out whether the body is empty. Fails with `HttpSignatureError`
 * (`missing`, `malformed`, `invalid`, `digest-mismatch`, `expired`, `unsupported`, `invalid-config`, or whatever
 * `resolveKey` fails with).
 *
 * @see https://openpayments.dev/identity/http-signatures
 * @see https://www.rfc-editor.org/rfc/rfc9421#section-3.2
 */
export const verifyRequest: (
  request: Request,
  options: {
    readonly resolveKey: (keyId: string) => Effect.Effect<JsonWebKey, HttpSignatureError>;
    readonly requiredComponents?: ReadonlyArray<string>;
    /** Oldest acceptable `created`, in seconds; a finite number of at least 0, default 300. Anything else fails with `invalid-config`. */
    readonly maxAgeSeconds?: number;
    /** Largest body read to check `Content-Digest`, in bytes; a finite number of at least 0, default 65536. */
    readonly maxBodyBytes?: number;
    /** Time source; an Invalid Date fails with `invalid-config`. Defaults to `new Date()`. */
    readonly clock?: () => Date;
    /** Signature label to verify. Defaults to `sig1`, the label Open Payments uses. */
    readonly label?: string;
    /**
     * Require a non-empty body to be covered by a matching `Content-Digest` (default `true`). Disable only for
     * generic RFC 9421 signatures that do not protect the body, e.g. published test vectors.
     */
    readonly requireBodyDigest?: boolean;
    /** Reject an explicit `alg` parameter (RFC 9635 §7.3.1: GNAP derives the algorithm from the key). Default `false`. */
    readonly forbidAlg?: boolean;
  },
) => Effect.Effect<VerifiedSignature, HttpSignatureError> = (request, options) =>
  Effect.gen(function* () {
    const label = options.label ?? "sig1";
    const maxAgeSeconds = options.maxAgeSeconds ?? DEFAULT_MAX_AGE_SECONDS;
    const maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;

    // NaN compares false with everything: unchecked, it would switch the freshness checks and the size cap off.
    if (!isLimit(options.maxAgeSeconds) || !isLimit(options.maxBodyBytes)) {
      return yield* fail("invalid-config", "maxAgeSeconds and maxBodyBytes must be finite numbers of at least 0");
    }

    const nowSeconds = Math.floor((options.clock?.() ?? new Date()).getTime() / 1000);

    if (Number.isNaN(nowSeconds)) return yield* fail("invalid-config", "The clock returned an Invalid Date");
    const signatureHeader = yield* header(request, "Signature");
    const inputHeader = yield* header(request, "Signature-Input");
    const signatures = yield* Effect.fromResult(parseDictionary(signatureHeader));
    const inputs = yield* Effect.fromResult(parseDictionary(inputHeader));
    const signature = member(signatures, label);
    const input = member(inputs, label);

    if (!input || !signature) return yield* fail("missing", `No "${label}" signature`);

    if (!("items" in input)) return yield* fail("malformed", "Signature-Input member must be an inner list");

    if ("items" in signature || signature.value.type !== "binary") {
      return yield* fail("malformed", "Signature member must be a byte sequence");
    }

    const components: string[] = [];

    for (const item of input.items) {
      if (item.value.type !== "string") return yield* fail("malformed", "Covered component must be a string");

      if (item.params.length > 0) return yield* fail("unsupported", "Component parameters are not supported");
      components.push(item.value.value);
    }

    const params: Array<readonly [string, string | number | boolean]> = [];
    let created: number | undefined;
    let expires: number | undefined;
    let keyId: string | undefined;
    let nonce: string | undefined;

    for (const [name, param] of input.params) {
      if (param.type !== "string" && param.type !== "integer" && param.type !== "boolean") {
        return yield* fail("unsupported", `Unsupported type for signature parameter "${name}"`);
      }

      params.push([name, param.value]);

      if (name === "created" && param.type === "integer") created = param.value;
      else if (name === "expires" && param.type === "integer") expires = param.value;
      else if (name === "keyid" && param.type === "string") keyId = param.value;
      else if (name === "nonce" && param.type === "string") nonce = param.value;
      else if (name === "tag" && param.type === "string") continue;
      else if (name === "alg" && options.forbidAlg === true) {
        return yield* fail("invalid", "The alg parameter must not be included");
      } else if (name === "alg" && !(param.type === "string" && param.value === "ed25519")) {
        return yield* fail("unsupported", "Only the ed25519 algorithm is supported");
      } else if (["created", "expires", "keyid", "nonce", "tag"].includes(name)) {
        return yield* fail("malformed", `Signature parameter "${name}" has the wrong type`);
      }
    }

    if (created === undefined) return yield* fail("malformed", "Signature has no created parameter");

    if (keyId === undefined || keyId === "") return yield* fail("malformed", "Signature has no keyid parameter");

    if (created > nowSeconds + FUTURE_SKEW_SECONDS) return yield* fail("invalid", "Signature created in the future");

    if (created < nowSeconds - maxAgeSeconds) {
      return yield* fail("expired", "Signature is too old");
    }

    if (expires !== undefined && expires < nowSeconds) return yield* fail("expired", "Signature has expired");

    for (const required of options.requiredComponents ?? ["@method", "@target-uri"]) {
      if (!components.includes(required)) return yield* fail("invalid", `Signature does not cover "${required}"`);
    }

    if (request.headers.has("authorization") && !components.includes("authorization")) {
      return yield* fail("invalid", "Signature does not cover the Authorization header");
    }

    if (components.includes("content-digest")) {
      const body = yield* readBody(request, maxBodyBytes);

      if (body === null) return yield* fail("malformed", `Request body is longer than ${maxBodyBytes} bytes`);

      yield* verifyContentDigest(yield* header(request, "Content-Digest"), body);
    } else if (options.requireBodyDigest !== false) {
      // Only whether there is a body matters, not its bytes: a limit of 0 stops at the first byte.
      const body = yield* readBody(request, 0);

      if (body === null || body.byteLength > 0) {
        return yield* fail("digest-mismatch", "Request body is not covered by content-digest");
      }
    }

    const signatureParams: SignatureParams = params;
    const base = yield* Effect.fromResult(createSignatureBase(request, components, signatureParams));
    const signatureBytes = signature.value.value;

    if (signatureBytes.length !== ED25519_SIGNATURE_BYTES) return yield* fail("invalid", "Signature does not verify");
    const jwk = yield* options.resolveKey(keyId);
    const publicKey = yield* importEd25519PublicJwk(jwk);

    const valid = yield* Effect.promise(() =>
      crypto.subtle.verify("Ed25519", publicKey, new Uint8Array(signatureBytes), utf8Encode(base)),
    );

    if (!valid) return yield* fail("invalid", "Signature does not verify");

    return {
      keyId,
      label,
      created: new Date(created * 1000),
      components,
      replayWindowSeconds: maxAgeSeconds + FUTURE_SKEW_SECONDS + 1,
      ...(nonce !== undefined && { nonce }),
    };
  });
