import * as Predicate from "effect/Predicate";
import * as Result from "effect/Result";
import { HttpSignatureError } from "./errors";
import { serializeInnerList, type SfBareItem } from "./structured-fields";

/** The parts of a request that signature bases are built from. A `Request` satisfies this. */
export interface SignedMessage {
  readonly method: string;
  readonly url: string;
  readonly headers: Headers;
}

/** An RFC 9421 signature parameter value. Numbers must be integers (e.g. `created`). */
export type SignatureParamValue = string | number | boolean;

/** Ordered signature parameters, e.g. `[["created", 1618884473], ["keyid", "test-key"]]`. */
export type SignatureParams = ReadonlyArray<readonly [string, SignatureParamValue]>;

const FIELD_NAME = /^[a-z0-9!#$%&'*+.^_`|~-]+$/;

function bareParam(value: SignatureParamValue): SfBareItem {
  if (Predicate.isString(value)) return { type: "string", value };

  if (Predicate.isBoolean(value)) return { type: "boolean", value };

  return { type: "integer", value };
}

function invalid(reason: HttpSignatureError["reason"], message: string): Result.Result<never, HttpSignatureError> {
  return Result.fail(new HttpSignatureError({ reason, message }));
}

function derived(message: SignedMessage, name: string): Result.Result<string, HttpSignatureError> {
  if (name === "@method") return Result.succeed(message.method);

  if (name === "@target-uri") return Result.succeed(message.url);
  let url: URL;

  try {
    url = new URL(message.url);
  } catch {
    return invalid("malformed", "Request URL is not absolute");
  }

  switch (name) {
    case "@authority":
      return Result.succeed(url.host);
    case "@scheme":
      return Result.succeed(url.protocol.slice(0, -1));
    case "@path":
      return Result.succeed(url.pathname);
    case "@query":
      return Result.succeed(`?${url.search.slice(1)}`);
    case "@request-target":
      return Result.succeed(`${url.pathname}${url.search}`);
    default:
      return invalid("unsupported", `Unsupported derived component "${name}"`);
  }
}

function componentValue(message: SignedMessage, name: string): Result.Result<string, HttpSignatureError> {
  if (name.startsWith("@")) return derived(message, name);

  if (!FIELD_NAME.test(name)) return invalid("malformed", `Invalid component name "${name}"`);
  const value = message.headers.get(name);

  if (value === null) return invalid("missing", `Covered header "${name}" is absent`);

  if (/[\r\n]/.test(value)) return invalid("malformed", `Header "${name}" contains a line break`);

  return Result.succeed(value);
}

/**
 * Serializes the `@signature-params` value, e.g. `("@method" "@target-uri");created=1;keyid="k"`. This is the
 * Signature-Input member value (after `label=`) and the last line of the signature base.
 *
 * Fails with `HttpSignatureError` (`malformed`) on unrepresentable names/values.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9421#section-2.3
 */
export const serializeSignatureParams: (
  components: ReadonlyArray<string>,
  params: SignatureParams,
) => Result.Result<string, HttpSignatureError> = (components, params) =>
  serializeInnerList({
    items: components.map((name) => ({ value: { type: "string", value: name }, params: [] })),
    params: params.map(([key, value]) => [key, bareParam(value)] as const),
  });

/**
 * Builds the RFC 9421 signature base for `components` (lowercase names: `@method`, `@target-uri`, `@authority`,
 * `@scheme`, `@path`, `@query`, `@request-target`, or header field names) and `params`.
 *
 * Fails with `HttpSignatureError`: `missing` (covered header absent), `malformed` (bad name/value, duplicate or
 * uppercase component), `unsupported` (other derived components).
 *
 * @see https://www.rfc-editor.org/rfc/rfc9421#section-2.5
 */
export const createSignatureBase: (
  message: SignedMessage,
  components: ReadonlyArray<string>,
  params: SignatureParams,
) => Result.Result<string, HttpSignatureError> = (message, components, params) =>
  Result.gen(function* () {
    const seen = new Set<string>();
    let base = "";

    for (const name of components) {
      if (name !== name.toLowerCase() || seen.has(name)) {
        return yield* invalid("malformed", `Component "${name}" is duplicated or not lowercase`);
      }

      seen.add(name);
      base += `"${name}": ${yield* componentValue(message, name)}\n`;
    }

    return `${base}"@signature-params": ${yield* serializeSignatureParams(components, params)}`;
  });
