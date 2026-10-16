import type * as Effect from "effect/Effect";
import type { OpenPaymentsError } from "./errors";

/**
 * Opt-in retries of the Open Payments clients (`ClientOptions.retry`). Without it nothing is retried.
 *
 * **What is retried.** A request is repeated only when the failure is transient *and* repeating it is safe:
 *
 * | Failure                                                                   | `GET` `HEAD` `PUT` `DELETE` | `POST` `PATCH`                                  |
 * | ------------------------------------------------------------------------- | --------------------------- | ----------------------------------------------- |
 * | `transport`: `fetch` rejected or timed out, or the body could not be read | retried                     | only with `retryNonIdempotent`                  |
 * | `http` `408` `429` `502` `503` `504`                                      | retried                     | only with `retryNonIdempotent`                  |
 * | any other `http` status, `validation`, `signing`, `invalid-*`             | never                       | never                                           |
 * | `transport`: bad URL, response longer than `maxResponseBytes`             | never                       | never                                           |
 *
 * `retryOn` replaces the "transient" column (which errors are worth another attempt); the method rule and
 * `maxAttempts` still apply. A `POST` is not safe to repeat by default because the first attempt may have been
 * processed (a lost response creates the payment twice): Open Payments has no idempotency key, so repeating
 * a `POST` is an explicit decision, per client (`retryNonIdempotent`) or per request (`retryNonIdempotent` in the
 * request arguments, which wins over the client's).
 *
 * **Waiting.** After failed attempt `n` (1-based) the wait is `min(maxDelayMs, baseDelayMs * 2^(n-1))`, then
 * multiplied by `random()` for `jitter: "full"` (the default). A `Retry-After` header (seconds or HTTP-date) of a `429`
 * or `503` replaces that wait: it is honoured as sent, but at most `maxDelayMs`, without jitter.
 *
 * **Every attempt is a new request.** It is signed again with a fresh `created` (from `clock`) and a fresh `nonce`
 * (only when retries are on), and gets its own `requestTimeoutMs`. Nothing signed is ever replayed.
 *
 * **Interruption.** Interrupting the effect cancels the wait and the in-flight `fetch`; no further attempt starts.
 *
 * **Exhaustion.** The last error is returned as it is, with `attempts` set to the number of attempts made.
 */
export interface RetryOptions {
  /** Total number of attempts including the first, a finite integer; below 1 counts as 1 (no retry). */
  readonly maxAttempts: number;
  /** Wait before the second attempt, doubled for every further one. Defaults to 200. */
  readonly baseDelayMs?: number;
  /** Upper bound of every wait, `Retry-After` included. Defaults to 5000. */
  readonly maxDelayMs?: number;
  /** `"full"` (default) waits a random share of the backoff, `"none"` the whole backoff. */
  readonly jitter?: "full" | "none";
  /** Which errors are worth another attempt, instead of the default transient set (see above). */
  readonly retryOn?: (error: OpenPaymentsError) => boolean;
  /** Also repeat `POST` (and `PATCH`) requests. A request's own `retryNonIdempotent` overrides this. Defaults to `false`. */
  readonly retryNonIdempotent?: boolean;
  /** Waits `ms` milliseconds. Defaults to `Effect.sleep`. Effects are interrupted with the request; a promise is abandoned. */
  readonly sleep?: (ms: number) => Effect.Effect<void> | Promise<void>;
  /** Source of the jitter, in `[0, 1)`. Defaults to `Math.random`. */
  readonly random?: () => number;
}

export const DEFAULT_BASE_DELAY_MS = 200;

export const DEFAULT_MAX_DELAY_MS = 5000;

const TRANSIENT_STATUSES: ReadonlySet<number> = new Set([408, 429, 502, 503, 504]);

const IDEMPOTENT_METHODS: ReadonlySet<string> = new Set(["GET", "HEAD", "PUT", "DELETE"]);

/** Whether an `http` response status is worth another attempt. */
export const isTransientStatus = (status: number): boolean => TRANSIENT_STATUSES.has(status);

/** Whether `method` may be repeated: idempotent methods always, the others only when the caller opted in. */
export const mayRepeat = (method: string, optedIn: boolean): boolean => optedIn || IDEMPOTENT_METHODS.has(method);

/** The attempt limit of `options`: at least 1. */
export const attemptLimit = ({ maxAttempts }: RetryOptions): number =>
  Number.isFinite(maxAttempts) ? Math.max(1, Math.floor(maxAttempts)) : 1;

/** Milliseconds from `now` until a `Retry-After` value (delta-seconds or HTTP-date), or `undefined` when it is neither. */
const retryAfterMs = (value: string, now: number): number | undefined => {
  const text = value.trim();

  if (/^\d+$/.test(text)) return Number(text) * 1000;
  // `Date.parse` alone is too lenient ("5" is a date); an HTTP-date always names its day and month.
  const date = /[A-Za-z]{3}/.test(text) ? Date.parse(text) : Number.NaN;

  return Number.isNaN(date) ? undefined : Math.max(0, date - now);
};

/**
 * The wait before the attempt after failed attempt number `failed` (1-based). `retryAfter` is the response's
 * `Retry-After` header and counts for `429` and `503` only.
 */
export const retryDelayMs = (
  options: RetryOptions,
  failed: number,
  status: number | undefined,
  retryAfter: string | null,
  now: number,
): number => {
  const maxDelayMs = options.maxDelayMs ?? DEFAULT_MAX_DELAY_MS;

  if (retryAfter !== null && (status === 429 || status === 503)) {
    const asked = retryAfterMs(retryAfter, now);

    if (asked !== undefined) return Math.min(asked, maxDelayMs);
  }

  const backoff = Math.min(maxDelayMs, (options.baseDelayMs ?? DEFAULT_BASE_DELAY_MS) * 2 ** (failed - 1));

  return options.jitter === "none" ? backoff : (options.random ?? Math.random)() * backoff;
};
