import type { YieldableError } from "effect/Cause";
import * as Data from "effect/Data";
import type { JsonObject } from "effect/Schema";

/** Why an Open Payments operation failed. */
export type OpenPaymentsErrorReason =
  /** The server answered with a non-2xx status. `status` and the `{ error: { code, description } }` body fields are set when present. */
  | "http"
  /** The response did not match the Open Payments schema, or violated a payment invariant. */
  | "validation"
  /** `fetch` rejected (network failure, abort, bad URL). */
  | "transport"
  /** The request was invalid before being sent (e.g. a grant request without `access_token` or `subject`). */
  | "invalid-request"
  /** Amount value out of range, malformed, or assets differ. */
  | "invalid-amount"
  /** HTTP message signing of the request failed. */
  | "signing";

interface OpenPaymentsErrorFields {
  readonly reason: OpenPaymentsErrorReason;
  readonly message: string;
  readonly status?: number;
  readonly code?: string;
  readonly description?: string;
  readonly details?: JsonObject;
  readonly validationErrors?: readonly string[];
  readonly cause?: unknown;
  readonly attempts?: number;
}

// Explicit annotation: `isolatedDeclarations` forbids a call expression in an `extends` clause.
const Base: new (fields: OpenPaymentsErrorFields) => YieldableError & {
  readonly _tag: "OpenPaymentsError";
} & Readonly<OpenPaymentsErrorFields> = Data.TaggedError("OpenPaymentsError")<OpenPaymentsErrorFields>;

/**
 * Single error type of the `open-payments` subpath, discriminated by `reason`.
 * For `reason: "http"`, `status`, `code`, `description` and `details` mirror the Open Payments
 * `{ error: { code, description, details? } }` response body. With `ClientOptions.retry`, `attempts` is the number of
 * attempts made when the request failed (the last attempt's error is the one reported); without it `attempts` is unset.
 */
export class OpenPaymentsError extends Base {}
