import * as Effect from "effect/Effect";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import { HttpSignatureError } from "../../http-signatures/errors";
import * as schemas from "../../open-payments/schemas";
import type { JWK } from "../../open-payments/types";
import { bufferResponse } from "../../internal/http";

const decodeJwks = Schema.decodeUnknownResult(schemas.jwks);

const unknownKey = (message: string, cause?: unknown): HttpSignatureError =>
  new HttpSignatureError({ reason: "unknown-key", message, ...(cause !== undefined && { cause }) });

const WALLET_KEYS_TIMEOUT_MS = 10_000;

const MAX_KEYS_RESPONSE_BYTES = 64 * 1024;

const IPV4_HOST = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * A URL the server may contact on a client's behalf: `https`, no credentials, no fragment, and a public-looking host
 * name. WHATWG parsing has already normalised numeric hosts (`2130706433`, `0x7f.1`) to dotted IPv4, and IPv6
 * literals keep their brackets, so those are caught by the host checks below. Shared by the key fetch and the
 * finish push, the two outbound requests of the server.
 */
export const isPublicHttpsUrl = (candidate: string): boolean => {
  if (!URL.canParse(candidate)) return false;
  const { protocol, username, password, hostname, hash } = new URL(candidate);

  return (
    protocol === "https:" &&
    username === "" &&
    password === "" &&
    hash === "" &&
    hostname.includes(".") &&
    !hostname.endsWith(".") &&
    !hostname.startsWith("[") &&
    !IPV4_HOST.test(hostname) &&
    !hostname.endsWith(".localhost") &&
    !hostname.endsWith(".local") &&
    !hostname.endsWith(".internal")
  );
};

/** A wallet address the default key fetch may contact: {@link isPublicHttpsUrl} without a query. */
const isFetchableWalletAddress = (walletAddress: string): boolean =>
  isPublicHttpsUrl(walletAddress) && new URL(walletAddress).search === "";

/** `fetch` that refuses redirects and responses over 64 KiB (announced or streamed). */
const guardedFetch =
  (fetchImpl: typeof globalThis.fetch): typeof globalThis.fetch =>
  async (input, init) => {
    const response = await fetchImpl(input, { ...init, redirect: "manual" });

    if (response.type === "opaqueredirect" || (response.status >= 300 && response.status < 400)) {
      await response.body?.cancel();

      throw new Error("Redirects are not followed");
    }

    const buffered = await bufferResponse(response, MAX_KEYS_RESPONSE_BYTES, init?.signal ?? undefined);

    if (buffered === null) throw new Error("Response is too large");

    return buffered;
  };

/**
 * Fetches `{walletAddress}/jwks.json` from addresses {@link isFetchableWalletAddress} accepts: `https`, a dotted
 * public-looking host name, any port. Host names are not resolved, so a name that points at a private address is not
 * caught. There is no key cache (`verifyClient` asks once per request); pass `resolveClientKeys` to cache or filter.
 * A failed fetch is `unknown-key` with the underlying error as `cause`; interrupting the fiber aborts the request.
 */
export const fetchClientKeys =
  (fetchImpl: typeof globalThis.fetch | undefined) =>
  (walletAddress: string): Effect.Effect<ReadonlyArray<JWK>, HttpSignatureError> => {
    if (!isFetchableWalletAddress(walletAddress)) {
      return Effect.fail(unknownKey("Client wallet address cannot be fetched"));
    }

    const fetchJwks = guardedFetch(fetchImpl ?? globalThis.fetch);

    return Effect.tryPromise({
      try: async (signal): Promise<ReadonlyArray<JWK>> => {
        const target = new URL(walletAddress);

        target.pathname = `${target.pathname.replace(/\/$/, "")}/jwks.json`;

        const response = await fetchJwks(target.href, {
          headers: { accept: "application/json" },
          signal: AbortSignal.any([signal, AbortSignal.timeout(WALLET_KEYS_TIMEOUT_MS)]),
        });

        if (!response.ok) throw new Error(`Unexpected status ${response.status}`);
        const jwks = decodeJwks(await response.json());

        if (Result.isFailure(jwks)) throw new Error("Not a JWK set");

        return jwks.success.keys;
      },
      catch: (cause) => unknownKey("Could not fetch the client's keys", cause),
    });
  };

/** The key of `candidates` whose `kid` is the signature's `keyid`. */
export const selectKey = (
  candidates: ReadonlyArray<JWK>,
  keyId: string,
): Effect.Effect<JsonWebKey, HttpSignatureError> => {
  const key = candidates.find((candidate) => candidate.kid === keyId);

  return key === undefined ? Effect.fail(unknownKey("No client key matches the signature keyid")) : Effect.succeed(key);
};
