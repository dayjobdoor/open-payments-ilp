// oxlint-disable anti-slop/no-runtime-typeof -- RFC 8785 serialisation dispatches on the JSON value kind by definition.
import * as Result from "effect/Result";
import { WebhookError } from "./errors";

/** A JSON value. */
export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

const unsupported = (message: string): WebhookError => new WebhookError({ reason: "unsupported-value", message });

/** An enclosing array or object whose members are still being written. */
type Frame =
  | {
      readonly kind: "array";
      readonly container: JsonValue[];
      /** Index of the next element. */
      next: number;
    }
  | {
      readonly kind: "object";
      readonly container: { [key: string]: JsonValue };
      /** The sorted keys. */
      readonly keys: string[];
      /** Index of the next key. */
      next: number;
      /** Whether a member was already written, so the next one needs a comma. */
      wrote: boolean;
    };

/**
 * Writes a scalar to `out`, or the opening bracket of a container (which becomes the innermost frame). Returns the
 * failure, if any.
 */
function open(
  value: JsonValue | undefined,
  out: string[],
  stack: Frame[],
  ancestors: Set<object>,
): WebhookError | undefined {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    out.push(JSON.stringify(value));

    return undefined;
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) return unsupported(`Non-finite number (${value})`);
    out.push(JSON.stringify(value));

    return undefined;
  }

  // `undefined` can only appear in untyped input: arrays carry null in its place and objects omit the member.
  if (typeof value !== "object") return unsupported(`Cannot serialise a value of type ${typeof value}`);

  // json-canonicalize hands every object with a non-null `toJSON` member (a `Date`, or a plain `{ toJSON: 1 }` that
  // JSON.stringify ignores as a method) to JSON.stringify, which neither sorts keys nor follows the JCS rules.
  // Rafiki signs that output, so verification must produce the same bytes.
  if (Reflect.get(value, "toJSON") != null) {
    let text: string | undefined;

    try {
      text = JSON.stringify(value);
    } catch (cause) {
      return unsupported(`JSON.stringify failed on a value with a toJSON member: ${String(cause)}`);
    }

    if (text === undefined) return unsupported("A toJSON member produced no JSON value");
    out.push(text);

    return undefined;
  }

  if (ancestors.has(value)) return unsupported("Circular reference");

  ancestors.add(value);

  if (Array.isArray(value)) {
    stack.push({ kind: "array", container: value, next: 0 });
    out.push("[");
  } else {
    // Keys sort by UTF-16 code units, which is `Array.prototype.sort`'s default order for strings.
    stack.push({ kind: "object", container: value, keys: Object.keys(value).sort(), next: 0, wrote: false });
    out.push("{");
  }

  return undefined;
}

/**
 * Serialises without recursion: nesting depth is bounded by memory, not by the call stack, so hostile input
 * (`JSON.parse` accepts arbitrarily deep documents) cannot overflow it.
 */
function serialize(root: JsonValue): Result.Result<string, WebhookError> {
  const out: string[] = [];
  const stack: Frame[] = [];
  const ancestors = new Set<object>();
  let failure = open(root, out, stack, ancestors);

  while (failure === undefined && stack.length > 0) {
    // SAFETY: the loop condition guarantees a frame.
    const frame = stack[stack.length - 1]!;

    if (frame.kind === "array") {
      const elements = frame.container;

      if (frame.next >= elements.length) {
        out.push("]");
        ancestors.delete(elements);
        stack.pop();
        continue;
      }

      if (frame.next > 0) out.push(",");
      failure = open(elements[frame.next++] ?? null, out, stack, ancestors);
      continue;
    }

    const { container: members, keys } = frame;
    let key = keys[frame.next];

    // Members whose value is `undefined` are omitted.
    while (key !== undefined && members[key] === undefined) key = keys[++frame.next];

    if (key === undefined) {
      out.push("}");
      ancestors.delete(members);
      stack.pop();
      continue;
    }

    frame.next++;

    if (frame.wrote) out.push(",");
    frame.wrote = true;
    out.push(JSON.stringify(key), ":");
    failure = open(members[key], out, stack, ancestors);
  }

  return failure === undefined ? Result.succeed(out.join("")) : Result.fail(failure);
}

/**
 * Canonical JSON per RFC 8785 (JCS): no insignificant whitespace, object members sorted by UTF-16 code units,
 * numbers and strings serialised as ECMAScript `JSON.stringify` does. Produces the bytes of `json-canonicalize`'s
 * `canonicalize`, which Rafiki signs with, for every JSON value and for `undefined` (an `undefined` member is
 * omitted, an `undefined` array element becomes `null`), including its quirk that an object with a non-null `toJSON`
 * member (a `Date`, say) is serialised by `JSON.stringify` alone, with members in insertion order.
 *
 * Where `canonicalize` would emit something other than a JSON document (or, depending on its version, throws or emits
 * `null`), this fails with `WebhookError` (`unsupported-value`): NaN and ±Infinity, bigint, functions, symbols,
 * cycles, and a `toJSON` member whose `JSON.stringify` throws or yields nothing. Sparse arrays are read as `undefined`
 * elements (`null`); `canonicalize` skips the holes. There is no nesting limit.
 *
 * @see https://www.rfc-editor.org/rfc/rfc8785
 */
export function canonicalizeJson(value: JsonValue): Result.Result<string, WebhookError> {
  return serialize(value);
}
