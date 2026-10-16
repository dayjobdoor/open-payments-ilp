import * as Effect from "effect/Effect";
import { IlpCodecError } from "./errors";
import { constantTimeEqual, sha256 } from "../internal/bytes";
import { owned } from "../internal/web-bytes";

const FULFILLMENT_LENGTH = 32;

/**
 * The execution condition of `fulfillment`: its SHA-256 digest (RFC 27).
 * Fails with `IlpCodecError` (`invalid-field`) when `fulfillment` is not exactly 32 bytes.
 */
export function conditionFromFulfillment(
  fulfillment: Uint8Array,
): Effect.Effect<Uint8Array<ArrayBuffer>, IlpCodecError> {
  if (fulfillment.length !== FULFILLMENT_LENGTH) {
    return Effect.fail(new IlpCodecError({ reason: "invalid-field", message: "fulfillment must be 32 bytes" }));
  }

  return Effect.promise(() => sha256(owned(fulfillment)));
}

/**
 * Whether `SHA-256(fulfillment) === executionCondition`, compared in constant time.
 * A Fulfill only proves payment when this holds; without it a peer could answer any Prepare with an arbitrary Fulfill.
 * Inputs that are not both 32 bytes yield `false`.
 */
export function fulfillmentMatchesCondition(
  fulfillment: Uint8Array,
  executionCondition: Uint8Array,
): Effect.Effect<boolean> {
  if (fulfillment.length !== FULFILLMENT_LENGTH || executionCondition.length !== FULFILLMENT_LENGTH) {
    return Effect.succeed(false);
  }

  return Effect.promise(async () => constantTimeEqual(await sha256(owned(fulfillment)), executionCondition));
}
