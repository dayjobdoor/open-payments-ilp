import * as Effect from "effect/Effect";
import { isPublicHttpsUrl } from "./client-keys";

const PUSH_TIMEOUT_MS = 5_000;

/**
 * `POST`s `payload` as JSON to a client's `interact.finish.uri` (RFC 9635 §4.2.2). The URL must pass
 * {@link isPublicHttpsUrl} (the rule of the key fetch against SSRF), redirects are never followed and the response
 * body is never read. Resolves to why the delivery failed, or `null` when the client answered `2xx`. Never fails and
 * never reveals the URL: a timeout, a refused URL, a redirect, a status and a transport error are the only reasons.
 */
export const postFinish = (
  fetchImpl: typeof globalThis.fetch | undefined,
  uri: string,
  payload: { readonly hash: string; readonly interact_ref: string },
): Effect.Effect<string | null> =>
  Effect.promise(async (signal): Promise<string | null> => {
    if (!isPublicHttpsUrl(uri)) return "finish uri cannot be contacted";

    try {
      const response = await (fetchImpl ?? globalThis.fetch)(uri, {
        method: "POST",
        redirect: "manual",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
        signal: AbortSignal.any([signal, AbortSignal.timeout(PUSH_TIMEOUT_MS)]),
      });

      await response.body?.cancel();

      if (response.type === "opaqueredirect" || (response.status >= 300 && response.status < 400)) {
        return "redirects are not followed";
      }

      return response.ok ? null : `unexpected status ${response.status}`;
    } catch (cause) {
      return cause instanceof Error && cause.name === "TimeoutError" ? "timed out" : "request failed";
    }
  });
