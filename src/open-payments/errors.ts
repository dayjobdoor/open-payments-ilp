import type { YieldableError } from "effect/Cause";
import * as Data from "effect/Data";
import type { JsonObject } from "effect/Schema";

/** Why an Open Payments operation failed. */
export type OpenPaymentsErrorReason =
  /**
   * The server answered with a 4xx or 5xx status (a 3xx is not followed and fails as `transport`). `status` and
   * `description` are always set; `code` and `details` when the `{ error: { code, description, details } }` body carries them.
   */
  | "http"
  /**
   * The response did not match the Open Payments schema (amounts are checked as `uint64`, `assetScale` as 0-255), or
   * violated a payment invariant (assets differ, sent more than debited, …), including an amount value the
   * invariants cannot read when `validateResponses` is off.
   */
  | "validation"
  /**
   * No usable response: `fetch` rejected (network failure, abort, timeout), the URL does not parse, the server
   * redirected (redirects are not followed), the body exceeded `maxResponseBytes`, or reading it failed or stalled
   * past `requestTimeoutMs`. `status` is not set.
   */
  | "transport"
  /**
   * The request was refused before being sent: a grant request without `access_token` or `subject`, a request URL
   * that is not `https:` (`http:` with `useHttp`) or has credentials or a fragment or is refused by `urlPolicy`, or a
   * `requestTimeoutMs` / `maxResponseBytes` that is not a finite number of at least 0.
   */
  | "invalid-request"
  /** Returned by the amount helpers (`parseAmountValue`, `compareAmounts`, `addAmounts`, …): a value out of range or malformed, or assets differ. */
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
