import * as Effect from "effect/Effect";
import { utf8Encode } from "../internal/bytes";
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
}

const DEFAULT_MAX_AGE_SECONDS = 300;

/** Tolerated clock skew for a `created` time ahead of the verifier's clock. */
const FUTURE_SKEW_SECONDS = 30;

/**
 * How long a verified signature stays acceptable at most: a nonce (or the signature itself) must be remembered this
 * long to stop replays. The extra second is the rounding of `created`, which is whole seconds: a signature stamped 30 s
 * ahead of the verifier's clock stays acceptable until the verifier's whole second `created + 300` is over, which is
 * up to one second after 330 s.
 */
export const SIGNATURE_REPLAY_WINDOW_SECONDS: number = DEFAULT_MAX_AGE_SECONDS + FUTURE_SKEW_SECONDS + 1;

const ED25519_SIGNATURE_BYTES = 64;

function fail(reason: HttpSignatureError["reason"], message: string): Effect.Effect<never, HttpSignatureError> {
  return Effect.fail(new HttpSignatureError({ reason, message }));
}

function header(request: Request, name: string): Effect.Effect<string, HttpSignatureError> {
  const value = request.headers.get(name);

  return value === null ? fail("missing", `Missing ${name} header`) : Effect.succeed(value);
}

function member(dictionary: SfDictionary, label: string): SfDictionary[number][1] | undefined {
  return dictionary.find(([name]) => name === label)?.[1];
}

/**
 * Verifies the `sig1` HTTP message signature of a request (RFC 9421, Ed25519) the way Open Payments servers do.
 *
 * Checks, in order: header syntax (strict RFC 8941), supported `alg` (ed25519 or absent), `created` present and
 * within `maxAgeSeconds` (default 300; `expires`, if present, must not have passed), required components covered
 * (`@method` and `@target-uri` unless `requiredComponents` says otherwise; `authorization` must be covered
 * whenever the request carries it), every covered header present, body integrity (a non-empty body must be covered
 * by a matching `Content-Digest`), then `resolveKey(keyid)` and the Ed25519 signature. `resolveKey` is only called
 * once every structural check has passed, so it can safely perform expensive or remote lookups.
 *
 * The request body is read from a clone; the request stays usable. Fails with `HttpSignatureError`
 * (`missing`, `malformed`, `invalid`, `digest-mismatch`, `expired`, `unsupported`, or whatever `resolveKey` fails with).
 *
 * @see https://openpayments.dev/identity/http-signatures
 * @see https://www.rfc-editor.org/rfc/rfc9421#section-3.2
 */
export const verifyRequest: (
  request: Request,
  options: {
    readonly resolveKey: (keyId: string) => Effect.Effect<JsonWebKey, HttpSignatureError>;
    readonly requiredComponents?: ReadonlyArray<string>;
    readonly maxAgeSeconds?: number;
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
    const nowSeconds = Math.floor((options.clock?.() ?? new Date()).getTime() / 1000);

    if (created > nowSeconds + FUTURE_SKEW_SECONDS) return yield* fail("invalid", "Signature created in the future");

    if (created < nowSeconds - (options.maxAgeSeconds ?? DEFAULT_MAX_AGE_SECONDS)) {
      return yield* fail("expired", "Signature is too old");
    }

    if (expires !== undefined && expires < nowSeconds) return yield* fail("expired", "Signature has expired");

    for (const required of options.requiredComponents ?? ["@method", "@target-uri"]) {
      if (!components.includes(required)) return yield* fail("invalid", `Signature does not cover "${required}"`);
    }

    if (request.headers.has("authorization") && !components.includes("authorization")) {
      return yield* fail("invalid", "Signature does not cover the Authorization header");
    }

    const body = yield* Effect.tryPromise({
      try: async () => (request.body === null ? new Uint8Array() : new Uint8Array(await request.clone().arrayBuffer())),
      catch: () => new HttpSignatureError({ reason: "malformed", message: "Request body cannot be read" }),
    });

    if ((body.byteLength > 0 && options.requireBodyDigest !== false) || components.includes("content-digest")) {
      if (!components.includes("content-digest")) {
        return yield* fail("digest-mismatch", "Request body is not covered by content-digest");
      }

      yield* verifyContentDigest(yield* header(request, "Content-Digest"), body);
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

    return { keyId, label, created: new Date(created * 1000), components, ...(nonce !== undefined && { nonce }) };
  });
