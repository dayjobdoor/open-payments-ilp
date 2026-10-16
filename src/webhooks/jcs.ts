// oxlint-disable anti-slop/no-runtime-typeof -- RFC 8785 serialisation dispatches on the JSON value kind by definition.
import * as Result from "effect/Result";
import { WebhookError } from "./errors";

/** A JSON value. */
export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

const unsupported = (message: string): Result.Result<never, WebhookError> =>
  Result.fail(new WebhookError({ reason: "unsupported-value", message }));

/** Deepest nesting serialised: deeper hostile input would overflow the stack. */
const MAX_DEPTH = 256;

function serialize(value: JsonValue | undefined, ancestors: Set<object>): Result.Result<string, WebhookError> {
  if (value === null || typeof value === "string" || typeof value === "boolean")
    return Result.succeed(JSON.stringify(value));

  if (typeof value === "number") {
    return Number.isFinite(value) ? Result.succeed(JSON.stringify(value)) : unsupported(`Non-finite number (${value})`);
  }

  // `undefined` can only appear in untyped input: arrays carry null in its place and objects omit the member.
  if (typeof value !== "object") return unsupported(`Cannot serialise a value of type ${typeof value}`);

  if (ancestors.has(value)) return unsupported("Circular reference");

  // `ancestors` holds the chain of enclosing containers, so its size is the current depth.
  if (ancestors.size >= MAX_DEPTH) return unsupported(`Nesting is deeper than ${MAX_DEPTH} levels`);

  ancestors.add(value);
  const parts: string[] = [];

  if (Array.isArray(value)) {
    for (const element of value) {
      const part = serialize(element ?? null, ancestors);

      if (Result.isFailure(part)) return part;
      parts.push(part.success);
    }

    ancestors.delete(value);

    return Result.succeed(`[${parts.join(",")}]`);
  }

  // Keys sort by UTF-16 code units, which is `Array.prototype.sort`'s default order for strings.
  for (const key of Object.keys(value).sort()) {
    const member = value[key];

    if (member === undefined) continue;
    const part = serialize(member, ancestors);

    if (Result.isFailure(part)) return part;
    parts.push(`${JSON.stringify(key)}:${part.success}`);
  }

  ancestors.delete(value);

  return Result.succeed(`{${parts.join(",")}}`);
}

/**
 * Canonical JSON per RFC 8785 (JCS): no insignificant whitespace, object members sorted by UTF-16 code units,
 * numbers and strings serialised as ECMAScript `JSON.stringify` does. Matches `json-canonicalize`'s
 * `canonicalize`, which Rafiki signs with: `undefined` members are omitted and `undefined` array elements become `null`.
 * Fails with `WebhookError` (`unsupported-value`) for NaN, ±Infinity, bigint, functions, symbols and cycles.
 *
 * @see https://www.rfc-editor.org/rfc/rfc8785
 */
export function canonicalizeJson(value: JsonValue): Result.Result<string, WebhookError> {
  return serialize(value, new Set());
}
