/**
 * ILP-over-HTTP client, synchronous profile: POST one ILP Prepare to a peer and read the Fulfill or Reject from the
 * HTTP response body. Not the asynchronous mode of RFC 35 draft 3 (`Request-Id`/`Callback-Url`, `202`); no `Accept`
 * header is sent. Web Standards only. Parse the reply with `deserializeReply`.
 *
 * @see https://interledger.org/developers/rfcs/ilp-over-http/
 * @module
 */
import type { YieldableError } from "effect/Cause";
import * as Data from "effect/Data";
import * as Effect from "effect/Effect";
import { announcesMoreThan, readCapped } from "../internal/http";

/** Why a Prepare could not be exchanged with the peer. */
export type IlpHttpErrorReason =
  /** The peer answered with a 4xx or 5xx status; `status` is set (a 3xx fails as `network`). */
  | "status"
  /** The reply is longer than `maxReplyBytes`. */
  | "too-large"
  /** `timeoutMs` elapsed. */
  | "timeout"
  /**
   * No usable reply: the request failed before a reply arrived (DNS, TLS, reset, aborted), or the peer redirected
   * (redirects are not followed; no `status`).
   */
  | "network"
  /** `timeoutMs` or `maxReplyBytes` is not usable (NaN, infinite, out of range); nothing was sent. */
  | "invalid-option";

interface IlpHttpErrorFields {
  readonly reason: IlpHttpErrorReason;
  readonly message: string;
  readonly status?: number | undefined;
  readonly cause?: unknown;
}

// Explicit annotation: `isolatedDeclarations` forbids a call expression in an `extends` clause.
const Base: new (fields: IlpHttpErrorFields) => YieldableError & {
  readonly _tag: "IlpHttpError";
} & Readonly<IlpHttpErrorFields> = Data.TaggedError("IlpHttpError")<IlpHttpErrorFields>;

/** Failure of {@link postPrepare}. A Reject from the peer is not a failure: it is a valid reply. */
export class IlpHttpError extends Base {}

/** Request timeout when `timeoutMs` is not given. */
export const DEFAULT_ILP_HTTP_TIMEOUT_MS: number = 30_000;

/** Reply cap when `maxReplyBytes` is not given; an ILP packet is at most 32 KiB of data plus its envelope. */
export const DEFAULT_ILP_HTTP_MAX_REPLY_BYTES: number = 64 * 1024;

/** Longest delay a timer can hold; `setTimeout` fires after about 1 ms above it. */
const MAX_TIMEOUT_MS = 2 ** 31 - 1;

/** Options of {@link postPrepare}. */
export interface PostPrepareOptions {
  /** The peer's ILP-over-HTTP endpoint. */
  readonly url: string;
  /** Sent as `Authorization: Bearer <token>`; omitted when not given. */
  readonly token?: string;
  /** Defaults to the global `fetch`. */
  readonly fetch?: typeof fetch;
  /**
   * Milliseconds until the exchange fails with reason `timeout`; `0` disables it. Default 30 000.
   * Must be finite and between 0 and 2^31-1 (about 24.8 days), else the call fails with `invalid-option`.
   */
  readonly timeoutMs?: number;
  /** Longest reply accepted, announced or streamed. Finite and positive, else `invalid-option`. Default 64 KiB. */
  readonly maxReplyBytes?: number;
}

const isTimeout = (cause: unknown): boolean => cause instanceof DOMException && cause.name === "TimeoutError";

const invalidOption = (message: string): Effect.Effect<never, IlpHttpError> =>
  Effect.fail(new IlpHttpError({ reason: "invalid-option", message }));

/**
 * Sends the serialized `prepare` to `options.url` and resolves with the reply bytes (a Fulfill or a Reject).
 * Fails with {@link IlpHttpError} on a 4xx/5xx status, a redirect, an oversized reply, a timeout, a network error
 * or an unusable `timeoutMs`/`maxReplyBytes`. The timeout timer is cleared when the exchange ends, and interrupting
 * the effect aborts the request.
 */
export function postPrepare(
  prepare: Uint8Array<ArrayBuffer> | ArrayBuffer,
  options: PostPrepareOptions,
): Effect.Effect<Uint8Array<ArrayBuffer>, IlpHttpError> {
  const {
    url,
    token,
    timeoutMs = DEFAULT_ILP_HTTP_TIMEOUT_MS,
    maxReplyBytes = DEFAULT_ILP_HTTP_MAX_REPLY_BYTES,
  } = options;

  if (!Number.isFinite(timeoutMs) || timeoutMs < 0 || timeoutMs > MAX_TIMEOUT_MS) {
    return invalidOption(`timeoutMs must be between 0 and ${MAX_TIMEOUT_MS}, got ${timeoutMs}`);
  }

  if (!Number.isFinite(maxReplyBytes) || maxReplyBytes <= 0) {
    return invalidOption(`maxReplyBytes must be finite and positive, got ${maxReplyBytes}`);
  }

  const send = options.fetch ?? fetch;

  return Effect.tryPromise({
    try: async (interrupt) => {
      // Our own timer rather than `AbortSignal.timeout`, which cannot be cleared and keeps running after the reply.
      const deadline = new AbortController();

      const timer =
        timeoutMs > 0
          ? setTimeout(() => deadline.abort(new DOMException("The operation timed out.", "TimeoutError")), timeoutMs)
          : undefined;

      const signal = timer === undefined ? interrupt : AbortSignal.any([interrupt, deadline.signal]);

      try {
        const response = await send(url, {
          method: "POST",
          headers: {
            "Content-Type": "application/octet-stream",
            ...(token !== undefined && { Authorization: `Bearer ${token}` }),
          },
          body: prepare,
          redirect: "manual",
          signal,
        });

        if (response.type === "opaqueredirect" || (response.status >= 300 && response.status < 400)) {
          await response.body?.cancel().catch(() => undefined);
          throw new IlpHttpError({ reason: "network", message: "Redirects are not followed" });
        }

        if (!response.ok) {
          await response.body?.cancel().catch(() => undefined);
          throw new IlpHttpError({
            reason: "status",
            status: response.status,
            message: `ILP over HTTP failed: ${response.status}`,
          });
        }

        const reply = announcesMoreThan(response.headers, maxReplyBytes)
          ? null
          : await readCapped(response.body, maxReplyBytes, signal);

        if (reply === null) {
          await response.body?.cancel().catch(() => undefined);
          throw new IlpHttpError({ reason: "too-large", message: "ILP reply too large" });
        }

        return reply;
      } finally {
        clearTimeout(timer);
      }
    },
    catch: (cause) =>
      cause instanceof IlpHttpError
        ? cause
        : new IlpHttpError({
            reason: isTimeout(cause) ? "timeout" : "network",
            message: cause instanceof Error ? cause.message : String(cause),
            cause,
          }),
  });
}
