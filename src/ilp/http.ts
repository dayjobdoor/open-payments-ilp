/**
 * ILP over HTTP (RFC 35) client: POST one ILP Prepare to a peer and read the Fulfill or Reject it answers with.
 * Web Standards only. Parse the reply with `deserializeReply`.
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
  /** The peer answered with a non-2xx status; `status` is set. */
  | "status"
  /** The reply is longer than `maxReplyBytes`. */
  | "too-large"
  /** `timeoutMs` elapsed. */
  | "timeout"
  /** The request failed before a reply arrived (DNS, TLS, reset, aborted). */
  | "network";

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

/** Options of {@link postPrepare}. */
export interface PostPrepareOptions {
  /** The peer's ILP-over-HTTP endpoint. */
  readonly url: string;
  /** Sent as `Authorization: Bearer <token>`; omitted when not given. */
  readonly token?: string;
  /** Defaults to the global `fetch`. */
  readonly fetch?: typeof fetch;
  /** Milliseconds until the exchange fails with reason `timeout`; `0` disables it. Default 30 000. */
  readonly timeoutMs?: number;
  /** Longest reply accepted, announced or streamed. Default 64 KiB. */
  readonly maxReplyBytes?: number;
}

const isTimeout = (cause: unknown): boolean => cause instanceof DOMException && cause.name === "TimeoutError";

/**
 * Sends the serialized `prepare` to `options.url` and resolves with the reply bytes (a Fulfill or a Reject).
 * Fails with {@link IlpHttpError} on a non-2xx status, an oversized reply, a timeout or a network error.
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

  const send = options.fetch ?? fetch;

  return Effect.tryPromise({
    try: async (interrupt) => {
      const signal = timeoutMs > 0 ? AbortSignal.any([interrupt, AbortSignal.timeout(timeoutMs)]) : interrupt;

      const response = await send(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/octet-stream",
          ...(token !== undefined && { Authorization: `Bearer ${token}` }),
        },
        body: prepare,
        signal,
      });

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
