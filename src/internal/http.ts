/**
 * Bounded body reads for subpaths that talk to an untrusted peer. Web Standards only.
 * @internal Not exported from any public entry point.
 */
import { concatBytes } from "./bytes";

/** Whether `headers` announce a body longer than `maxBytes`. */
export const announcesMoreThan = (headers: Headers, maxBytes: number): boolean =>
  Number(headers.get("content-length")) > maxBytes;

/**
 * Reads `body`; `null` as soon as it is longer than `maxBytes` (the stream is cancelled, not drained). Aborting
 * `signal` cancels the stream and rejects with the signal's reason.
 */
export const readCapped = async (
  body: ReadableStream<Uint8Array> | null,
  maxBytes: number,
  signal?: AbortSignal,
): Promise<Uint8Array<ArrayBuffer> | null> => {
  if (body === null) return new Uint8Array(0);
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  const cancel = (): void => void reader.cancel(signal?.reason).catch(() => undefined);

  signal?.addEventListener("abort", cancel, { once: true });

  if (signal?.aborted) cancel();

  try {
    for (;;) {
      const { done, value } = await reader.read();

      // A cancelled stream reports `done`: the abort, not the truncated bytes, is the result.
      signal?.throwIfAborted();

      if (done) return concatBytes(...chunks);
      total += value.byteLength;

      if (total > maxBytes) {
        // Not awaited: on a `clone()`d request the promise only settles once the other branch is cancelled too.
        reader.cancel().catch(() => undefined);

        return null;
      }

      chunks.push(value);
    }
  } finally {
    signal?.removeEventListener("abort", cancel);
  }
};

/**
 * `response` with its body already read, or `null` when the body is longer than `maxBytes` (announced or streamed;
 * the stream is cancelled). The result is a plain `Response`: callers read it with `json()` / `text()` as usual.
 */
export const bufferResponse = async (
  response: Response,
  maxBytes: number,
  signal?: AbortSignal,
): Promise<Response | null> => {
  const bytes = announcesMoreThan(response.headers, maxBytes)
    ? null
    : await readCapped(response.body, maxBytes, signal);

  if (bytes === null) {
    // A streamed overflow was already cancelled by `readCapped` (the stream stays locked, so this rejects); an
    // announced one is cancelled here.
    await response.body?.cancel().catch(() => undefined);

    return null;
  }

  const bodyless = response.status === 204 || response.status === 205 || response.status === 304;

  return new Response(bodyless ? null : bytes, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
};
