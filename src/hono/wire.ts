/**
 * The client side of GNAP on the wire (RFC 9635 as profiled by Open Payments / Rafiki): signed grant, continue,
 * token rotation and revocation requests, and tolerant parsing of both servers' responses. No Hono here.
 * @internal Not exported from the public entry point.
 */
import * as Effect from "effect/Effect";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import type { AccessItem, GrantRequestAccessItem } from "../gnap/index";
import { accessItem } from "../open-payments/schemas";
import type { JWK } from "../open-payments/types";
import { signRequest, type SigningKey } from "../http-signatures/index";
import { encodeBase64Url } from "../internal/bytes";
import { bufferResponse } from "../internal/http";

/** An authorisation server's answers are small JSON documents; anything longer is not one. */
const MAX_RESPONSE_BYTES = 64 * 1024;

/** A failed exchange with the authorisation server (or a response that is not GNAP). */
export class GnapAuthError extends Error {
  /** HTTP status of the authorisation server's answer; `502` when it was not understood, `503` when it could not be reached, `504` when it timed out. */
  readonly status: number;
  /** GNAP error code (`invalid_request`, `too_fast`, …) when the answer carried one. */
  readonly code: string | undefined;

  constructor(status: number, message: string, code?: string) {
    super(message);
    this.name = "GnapAuthError";
    this.status = status;
    this.code = code;
  }
}

/** Where to go next with a grant, or how to manage a token. */
export interface Credential {
  readonly uri: string;
  readonly token: string;
}

/** An access token, with its management credential normalised across Rafiki and RFC 9635. */
export interface IssuedToken {
  accessToken: string;
  /** Epoch seconds. */
  expiresAt?: number;
  access?: ReadonlyArray<AccessItem>;
  manage?: Credential;
}

/** The parsed grant (or continue) response. `continue.wait` is in seconds, with RFC 9635 §3.1's default of 5 applied. */
export interface GrantResponse {
  readonly token?: IssuedToken;
  readonly continue?: Credential & { readonly wait: number };
  /** `expires_in`: seconds after which the interaction (RFC 9635 §3.3) can no longer be started; absent: it does not expire. */
  readonly interact?: { readonly redirect?: string; readonly finish?: string; readonly expires_in?: number };
}

/** What every request needs. */
export interface Wire {
  readonly fetch: typeof globalThis.fetch;
  readonly clock: () => Date;
  readonly key: SigningKey;
  /**
   * `Content-Digest` algorithm: RFC 9635 §7.3.1 fixes sha-256 for the `proof: "httpsig"` string form (the inline key
   * of an RFC server); a wallet-address client (Open Payments) signs sha-512, like the official client.
   */
  readonly digest: "sha-256" | "sha-512";
  /** Every request to the authorisation server (answer body included) is aborted after this many milliseconds. */
  readonly timeoutMs: number;
}

const tokenCredential = Schema.Struct({ value: Schema.String });

const grantResponse = Schema.Struct({
  access_token: Schema.optionalKey(
    Schema.Struct({
      value: Schema.String,
      expires_in: Schema.optionalKey(Schema.Number),
      // RFC 9635 §3.2.1 `manage` is an object; Rafiki's is a URL string.
      manage: Schema.optionalKey(
        Schema.Union([Schema.String, Schema.Struct({ uri: Schema.String, access_token: tokenCredential })]),
      ),
      access: Schema.optionalKey(Schema.Unknown),
      flags: Schema.optionalKey(Schema.Array(Schema.String)),
      key: Schema.optionalKey(Schema.Unknown),
    }),
  ),
  continue: Schema.optionalKey(
    Schema.Struct({ uri: Schema.String, access_token: tokenCredential, wait: Schema.optionalKey(Schema.Number) }),
  ),
  interact: Schema.optionalKey(
    Schema.Struct({
      redirect: Schema.optionalKey(Schema.String),
      finish: Schema.optionalKey(Schema.String),
      expires_in: Schema.optionalKey(Schema.Number),
    }),
  ),
});

const errorResponse = Schema.Struct({
  error: Schema.optionalKey(
    Schema.Union([
      Schema.String,
      Schema.Struct({ code: Schema.optionalKey(Schema.String), description: Schema.optionalKey(Schema.String) }),
    ]),
  ),
  error_description: Schema.optionalKey(Schema.String),
});

const isString = Schema.is(Schema.String);

const decodeGrant = Schema.decodeUnknownResult(grantResponse);

const decodeError = Schema.decodeUnknownResult(errorResponse);

const DEFAULT_WAIT_SECONDS = 5;

const decodeAccess = Schema.decodeUnknownResult(Schema.Array(accessItem));

/**
 * Runs a signing effect. Its failures (an unusable key) are configuration errors, so they throw. RFC 9635 §7.3.1:
 * `tag="gnap"`, `created`, a fresh `nonce` per request, and the digest algorithm of {@link Wire.digest}.
 */
const sign = async (request: Request, wire: Wire): Promise<Request> => {
  const nonce = encodeBase64Url(crypto.getRandomValues(new Uint8Array(16)));

  const signed = await Effect.runPromise(
    Effect.result(signRequest(request, wire.key, { created: wire.clock(), tag: "gnap", nonce, digest: wire.digest })),
  );

  if (Result.isFailure(signed)) throw new GnapAuthError(500, signed.failure.message);

  return signed.success;
};

/**
 * Sends one signed request; any non-2xx answer, an unreachable or too slow server, and an answer longer than
 * {@link MAX_RESPONSE_BYTES} become a {@link GnapAuthError}. The returned response has its body already read.
 */
const send = async (
  wire: Wire,
  method: "POST" | "DELETE",
  url: string,
  options: { readonly body?: object; readonly token?: string } = {},
): Promise<Response> => {
  const headers = new Headers({ accept: "application/json" });

  if (options.token !== undefined) headers.set("authorization", `GNAP ${options.token}`);

  if (options.body !== undefined) headers.set("content-type", "application/json");
  const body = options.body === undefined ? null : JSON.stringify(options.body);
  const signed = await sign(new Request(url, { method, headers, body, redirect: "manual" }), wire);
  let response: Response | null;

  try {
    response = await bufferResponse(
      await wire.fetch(signed, { redirect: "manual", signal: AbortSignal.timeout(wire.timeoutMs) }),
      MAX_RESPONSE_BYTES,
    );
  } catch (error) {
    throw error instanceof Error && error.name === "TimeoutError"
      ? new GnapAuthError(504, `${method} ${url} timed out after ${wire.timeoutMs} ms`)
      : new GnapAuthError(503, `${method} ${url} could not reach the authorisation server`);
  }

  if (response === null)
    throw new GnapAuthError(502, `${method} ${url} answered with more than ${MAX_RESPONSE_BYTES} bytes`);

  if (response.type === "opaqueredirect" || (response.status >= 300 && response.status < 400)) {
    throw new GnapAuthError(502, `${method} ${url} redirected`);
  }

  if (response.ok) return response;
  const decoded = decodeError(await response.json().catch(() => undefined));
  const parsed = Result.isSuccess(decoded) ? decoded.success : {};
  const error = parsed.error;
  const code = error === undefined || isString(error) ? error : error.code;
  const description = error === undefined || isString(error) ? parsed.error_description : error.description;

  throw new GnapAuthError(response.status, description ?? code ?? `${method} ${url} answered ${response.status}`, code);
};

/** An http(s) URL with no userinfo. Cross-origin is the authorisation server's to name (RFC 9635). */
const credentialUrl = (uri: string, label: string): string => {
  if (!URL.canParse(uri)) throw new GnapAuthError(502, `${label} is not a URL`);
  const url = new URL(uri);

  if ((url.protocol !== "https:" && url.protocol !== "http:") || url.username !== "" || url.password !== "") {
    throw new GnapAuthError(502, `${label} must be an http(s) URL without credentials`);
  }

  return url.toString();
};

const parseGrant = async (response: Response, wire: Wire): Promise<GrantResponse> => {
  const decoded = decodeGrant(await response.json().catch(() => undefined));

  if (Result.isFailure(decoded)) throw new GnapAuthError(502, "Authorisation server answer is not a GNAP response");
  const { access_token: issued, continue: next, interact } = decoded.success;
  const result: { -readonly [K in keyof GrantResponse]: GrantResponse[K] } = {};

  if (issued !== undefined) {
    // RFC 9635 §3.2.1: the client MUST reject a bearer token that comes with a key.
    if (issued.flags?.includes("bearer") === true && issued.key !== undefined) {
      throw new GnapAuthError(502, "Access token is a bearer token but carries a key");
    }

    const { manage } = issued;
    const access = decodeAccess(issued.access);
    const token: IssuedToken = { accessToken: issued.value };

    if (issued.expires_in !== undefined)
      token.expiresAt = Math.floor(wire.clock().getTime() / 1000) + issued.expires_in;

    // Rafiki: the access token itself is the management credential. RFC 9635: a separate management token.
    if (manage !== undefined) {
      token.manage = isString(manage)
        ? { uri: credentialUrl(manage, "Token management URL"), token: issued.value }
        : { uri: credentialUrl(manage.uri, "Token management URL"), token: manage.access_token.value };
    }

    // Only Open Payments access items are understood; another server's `access` is not re-exposed.
    if (Result.isSuccess(access)) token.access = access.success;
    result.token = token;
  }

  if (next !== undefined) {
    // RFC 9635 §3.1: omission of `wait` MUST be interpreted as five seconds.
    result.continue = {
      uri: credentialUrl(next.uri, "Continuation URL"),
      token: next.access_token.value,
      wait: next.wait ?? DEFAULT_WAIT_SECONDS,
    };
  }

  if (interact !== undefined) result.interact = interact;

  return result;
};

/** `POST {endpoint}`: asks for `access`, to be confirmed through a redirect that comes back to `redirectUri`. */
export const requestGrant = async (
  wire: Wire,
  args: {
    readonly endpoint: string;
    readonly access: ReadonlyArray<GrantRequestAccessItem>;
    readonly client: string | { readonly key: { readonly proof: "httpsig"; readonly jwk: JWK } };
    readonly redirectUri: string;
    readonly nonce: string;
  },
): Promise<GrantResponse> =>
  parseGrant(
    await send(wire, "POST", args.endpoint, {
      body: {
        access_token: { access: args.access },
        client: args.client,
        interact: {
          start: ["redirect"],
          finish: { method: "redirect", uri: args.redirectUri, nonce: args.nonce },
        },
      },
    }),
    wire,
  );

/**
 * `POST {continue.uri}` without a body (RFC 9635 §5.2): one poll of a grant that has no `interact.finish`. The caller
 * waits out the server's `wait` first; the answer is the grant (a token once approved) or, while it is pending, only a
 * new `continue`.
 */
export const pollGrant = async (wire: Wire, current: Credential): Promise<GrantResponse> =>
  parseGrant(await send(wire, "POST", current.uri, { token: current.token }), wire);

const MAX_POLLS = 3;

const MAX_WAIT_SECONDS = 10;

/**
 * Sleeps `seconds`. A longer wait fails (`504`) instead of being cut short: calling the continuation URI before the
 * announced `wait` is over is forbidden (RFC 9635 §3.1, §5).
 */
const waitFor = async (seconds: number): Promise<void> => {
  if (seconds > MAX_WAIT_SECONDS) {
    throw new GnapAuthError(
      504,
      `Authorisation server asks to wait ${Math.ceil(seconds)} s before continuing; at most ${MAX_WAIT_SECONDS} s are waited`,
    );
  }

  await new Promise((resolve) => setTimeout(resolve, Math.max(seconds, 0) * 1000));
};

/**
 * `POST {continue.uri}` with the `interact_ref`, once `notBefore` (epoch seconds: the end of the `wait` period of the
 * response that announced the continuation) has passed, so the server never sees an early call (RFC 9635 §3.1,
 * §5). The `interact_ref` is one-time-use (§5.1): it is sent in that one request only, and a `too_fast` answer
 * is therefore an error, not a reason to send it again. While the server then answers with only a `continue` (a
 * pending grant), waits its `wait` (at most {@link MAX_WAIT_SECONDS}) and polls again without body, at most
 * {@link MAX_POLLS} times. RFC 9635 servers rotate the continue token, so the newest one is always used. The
 * result carries the continue credential of the final response; without one the grant cannot be continued (§5).
 */
export const continueGrant = async (
  wire: Wire,
  start: Credential,
  interactRef: string,
  notBefore: number,
): Promise<{ readonly token: IssuedToken; readonly continue?: Credential }> => {
  let current: Credential = start;

  await waitFor(notBefore - wire.clock().getTime() / 1000);

  for (let attempt = 0; attempt <= MAX_POLLS; attempt += 1) {
    const response = await parseGrant(
      await send(wire, "POST", current.uri, {
        token: current.token,
        ...(attempt === 0 && { body: { interact_ref: interactRef } }),
      }),
      wire,
    );

    const next = response.continue;

    if (response.token !== undefined) {
      return { token: response.token, ...(next !== undefined && { continue: { uri: next.uri, token: next.token } }) };
    }

    if (next === undefined) throw new GnapAuthError(502, "Continue response has neither token nor continue");
    current = { uri: next.uri, token: next.token };

    if (attempt < MAX_POLLS) await waitFor(next.wait);
  }

  throw new GnapAuthError(504, "Grant is still pending");
};

/** `POST {manage.uri}` with the management token: the rotated access token. */
export const rotateToken = async (wire: Wire, manage: Credential): Promise<IssuedToken> => {
  const { token } = await parseGrant(await send(wire, "POST", manage.uri, { token: manage.token }), wire);

  if (token === undefined) throw new GnapAuthError(502, "Rotation response has no access_token");

  return token;
};

/** Error codes of a 401 that say the credential is already gone (a cancelled grant), not that the request was refused. */
const GONE_CODES: ReadonlySet<string> = new Set(["invalid_continuation"]);

/**
 * `DELETE {credential.uri}` (token revocation or grant cancellation). An already gone token or grant is fine: `404`,
 * or a `401` whose GNAP error code says the credential is gone. Any other answer (a refused signature, `5xx`) is
 * an error.
 */
export const revokeCredential = async (wire: Wire, credential: Credential): Promise<void> => {
  try {
    await send(wire, "DELETE", credential.uri, { token: credential.token });
  } catch (error) {
    const gone =
      error instanceof GnapAuthError &&
      (error.status === 404 || (error.status === 401 && error.code !== undefined && GONE_CODES.has(error.code)));

    if (!gone) throw error;
  }
};
