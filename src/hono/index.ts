/**
 * GNAP client middleware for [Hono](https://hono.dev), modelled on `@hono/oidc-auth`: storage-less login sessions
 * (an AES-GCM encrypted httpOnly cookie), against a Rafiki / Open Payments authorisation server and a generic
 * RFC 9635 one. Requires the optional peer `hono`.
 *
 * This subpath is the documented exception to the package's Effect-only rule: it speaks Promises because Hono's
 * middleware boundary does.
 *
 * ```ts
 * app.use("*", initGnapAuthMiddleware({ secret, grantEndpoint, access, client, keyId, privateKey }));
 * app.use("*", gnapAuthMiddleware());
 * app.get("/", async (c) => c.text((await getGnapAuth(c))?.accessToken ?? ""));
 * ```
 *
 * @see https://www.rfc-editor.org/rfc/rfc9635
 * @see https://github.com/honojs/middleware/tree/main/packages/oidc-auth
 * @module
 */
import * as Effect from "effect/Effect";
import type { Context, MiddlewareHandler } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { createMiddleware } from "hono/factory";
import { HTTPException } from "hono/http-exception";
import { verifyInteractionHash } from "../gnap/index";
import { encodeBase64Url } from "../internal/bytes";
import {
  createKeyImporter,
  getConfig,
  httpError,
  isCallbackUri,
  isSecureUri,
  nowSeconds,
  resolveWire,
  setConfig,
  validateConfig,
  type GnapAuthConfig,
  type Resolved,
} from "./config";
import {
  cookieOptions,
  dropSessionCookie,
  getGnapAuth,
  grantFingerprint,
  pendingCookieName,
  readPending,
  readPendingPointer,
  saveSession,
  savePending,
  savePolling,
  STATE_SECONDS,
  stateCookieName,
  type GnapAuth,
  type GnapAuthRefreshErrorHook,
  type PendingPointer,
  type PendingPoll,
  type PendingState,
} from "./session";
import { isCallbackRequest, publicRedirectUri, publicRequestUrl, statePath } from "./urls";
import { continueGrant, GnapAuthError, pollGrant, requestGrant, type GrantResponse, type Wire } from "./wire";

export { GnapAuthError } from "./wire";

export type { GnapAuthConfig } from "./config";

export { getGnapAuth, revokeGnapSession } from "./session";

export type { GnapAuth, GnapAuthRefreshErrorHook } from "./session";

declare module "hono" {
  interface ContextVariableMap {
    gnapAuthConfig: GnapAuthConfig;
    gnapAuth: GnapAuth | null;
    gnapAuthCookie: string;
    gnapAuthRefreshErrorHook?: GnapAuthRefreshErrorHook;
  }
}

/**
 * Configures GNAP auth for the requests it is mounted on, instead of (or on top of) environment variables.
 * Mount it before every other function of this module.
 *
 * Throws an `Error` at once when a value passed in `config` is invalid (secret length, numbers, URIs and their schemes,
 * key material). Values from the environment are checked the same way on the request that first sees them (`500`).
 * The private key is imported once and reused.
 */
export const initGnapAuthMiddleware = (config: GnapAuthConfig): MiddlewareHandler => {
  // What is passed in is checked now, not on the first request; what the environment provides, on each request.
  validateConfig(config);
  const importKey = createKeyImporter();

  return createMiddleware(async (c, next) => {
    setConfig(c, config, importKey);
    await next();
  });
};

/** What the user sees while a grant waits for approval: the interaction again, or `202` when the server offered none. */
const stillPending = (c: Context, redirect: string | undefined, seconds: number): Response => {
  if (redirect !== undefined) return c.redirect(redirect);
  c.header("Retry-After", String(Math.max(Math.ceil(seconds), 1)));
  c.header("Cache-Control", "no-store");

  return c.text("Authorisation is pending: the access has not been approved yet", 202);
};

/** What a poll came to: the session exists now, the grant is over at the server, or the response to send. */
type Polled = Response | "approved" | "gone";

/**
 * A navigation of a browser whose grant has no `interact.finish` (RFC 9635 §5.2): no callback will come, so this is
 * when the server is asked. Before the end of its `wait` it is not called (§3.1): the user is shown the pending
 * state instead. A poll answered with a token creates the session (`"approved"`); one answered with only a
 * `continue` is pending again, with the server's new continuation and `wait` stored. A denial is `401`
 * (the grant is forgotten); an unavailable or failing server is `503` / `502` and the grant is kept for the next
 * navigation; any other refusal means the grant is over (`"gone"`: a new one is requested).
 */
const pollPending = async (
  c: Context,
  config: Resolved,
  wire: Wire,
  waiting: PendingPointer,
  poll: PendingPoll,
): Promise<Polled> => {
  const pointerName = pendingCookieName(config);

  if (nowSeconds(config) < poll.nb) return stillPending(c, waiting.ru, poll.nb - nowSeconds(config));
  let answer: GrantResponse;

  try {
    answer = await pollGrant(wire, { uri: poll.cu, token: poll.ct });
  } catch (error) {
    if (!(error instanceof GnapAuthError)) throw error;

    // Early by the server's clock: nothing is lost, the grant is still pending.
    if (error.code === "too_fast") return stillPending(c, waiting.ru, 1);

    if (error.status >= 500 || error.status === 408 || error.status === 429) {
      throw error.status === 429 || error.status === 503 || error.status === 504
        ? httpError(503, "The authorisation server is unavailable")
        : httpError(502, "The authorisation server did not answer the poll of the pending grant");
    }

    dropSessionCookie(c, config, pointerName);

    if (error.code !== undefined && failureStatus(error.code) === 401) {
      throw httpError(401, `GNAP interaction failed: ${error.code}`);
    }

    return "gone";
  }

  if (answer.token !== undefined) {
    dropSessionCookie(c, config, pointerName);
    await saveSession(c, config, answer.token, undefined, answer.continue);

    return "approved";
  }

  if (answer.continue === undefined) {
    dropSessionCookie(c, config, pointerName);

    throw httpError(502, "Authorisation server answered the poll with neither access nor a continuation");
  }

  const { uri, token, wait } = answer.continue;

  // +1: `nowSeconds` floors, the server's `wait` period ends inside the next second.
  await savePolling(c, config, { ...waiting, poll: { cu: uri, ct: token, nb: nowSeconds(config) + 1 + wait } });

  return stillPending(c, waiting.ru, wait);
};

const startGrant = async (c: Context, config: Resolved): Promise<Response | undefined> => {
  const { grantEndpoint, access } = config;

  if (grantEndpoint === undefined || access === undefined) {
    throw httpError(500, "GNAP grant endpoint and access are required");
  }

  const wire = await resolveWire(config);
  const endpoint = grantEndpoint instanceof Function ? await grantEndpoint(c) : grantEndpoint;

  const client =
    config.client ?? (wire.jwk === undefined ? undefined : { key: { proof: "httpsig" as const, jwk: wire.jwk } });

  if (client === undefined) throw httpError(500, "GNAP client (wallet address) or a JWK private key is required");

  const redirectUri = publicRedirectUri(c, config);

  // RFC 9635 §2.5.2: the callback URI is absolute without fragment, and (§2.5.2.1) HTTPS or local to the browser.
  if (!isCallbackUri(redirectUri)) {
    throw httpError(500, "The GNAP redirect URI must use HTTPS (or localhost) and have no fragment");
  }

  const accessItems = access instanceof Function ? await access(c) : access;
  const fingerprint = await grantFingerprint(endpoint, accessItems, redirectUri);
  // The browser is already waiting on a grant (a second tab, a reload): the same interaction, not a second grant.
  const waiting = await readPendingPointer(c, config, fingerprint);

  if (waiting?.poll !== undefined) {
    const polled = await pollPending(c, config, wire, waiting, waiting.poll);

    if (polled === "approved") return undefined;

    if (polled !== "gone") return polled;
  } else if (waiting?.ru !== undefined) {
    return c.redirect(waiting.ru);
  }

  const nonce = encodeBase64Url(crypto.getRandomValues(new Uint8Array(24)));
  let granted: GrantResponse;

  try {
    granted = await requestGrant(wire, { endpoint, access: accessItems, client, redirectUri, nonce });
  } catch (error) {
    // The server could not be asked (or is overloaded): 503, retry later. It answered no: 502.
    if (!(error instanceof GnapAuthError)) throw error;

    throw error.status === 429 || error.status === 503 || error.status === 504
      ? httpError(503, "The authorisation server is unavailable")
      : httpError(502, "The authorisation server refused the grant request");
  }

  if (granted.token !== undefined) {
    await saveSession(c, config, granted.token, undefined, granted.continue);

    return undefined;
  }

  const { interact, continue: next } = granted;
  const unusable = "Authorisation server neither granted access nor asked for a redirect interaction";

  if (next === undefined) throw httpError(502, unusable);

  // RFC 9635 §4.1.1: the interaction URI MUST be HTTPS or local to the browser; never send the user elsewhere.
  if (interact?.redirect !== undefined && !isSecureUri(interact.redirect)) {
    throw httpError(502, "Authorisation server sent an interaction URI that is neither HTTPS nor localhost");
  }

  // The state does not outlive the interaction: the server's `expires_in`, when it gave one, cuts the default short.
  // Whole seconds (a cookie's Max-Age is an integer); none left means the interaction cannot be used at all.
  const now = nowSeconds(config);
  const lifetime = Math.min(STATE_SECONDS, Math.floor(interact?.expires_in ?? STATE_SECONDS));

  if (lifetime <= 0) throw httpError(502, "Authorisation server sent an interaction that has already expired");

  // RFC 9635 §5.2: without `interact.finish` no callback comes back; the next navigation polls the grant.
  if (interact?.finish === undefined) {
    await savePolling(c, config, {
      fp: fingerprint,
      stexp: now + lifetime,
      // +1: `nowSeconds` floors, the server's `wait` period ends inside the next second.
      poll: { cu: next.uri, ct: next.token, nb: now + 1 + next.wait },
      ...(interact?.redirect !== undefined && { ru: interact.redirect }),
    });

    return stillPending(c, interact?.redirect, next.wait);
  }

  if (interact.redirect === undefined) throw httpError(502, unusable);

  const pending: PendingState = {
    cu: next.uri,
    ct: next.token,
    cn: nonce,
    sn: interact.finish,
    ge: endpoint,
    rt: publicRequestUrl(c, config),
    stexp: now + lifetime,
    // +1: `nowSeconds` floors, the server's `wait` period ends inside the next second.
    nb: now + 1 + next.wait,
  };

  await savePending(c, config, pending, { redirect: interact.redirect, fingerprint }, statePath(c, config));

  return c.redirect(interact.redirect);
};

/** A failed interaction that means "the user said no" (401), whichever way the server reports it. */
const failureStatus = (result: string): 400 | 401 =>
  result === "grant_rejected" || result === "request_denied" || result === "user_denied" ? 401 : 400;

/**
 * Handles the redirect back from the authorisation server: reads the state cookie, rejects a failed interaction
 * (`result=…`, Rafiki's convention) and a wrong `hash`, waits out `continue.wait`, continues the grant, stores the
 * session and redirects to where the user came from. A denial in the RFC 9635 manner (§4.2: the finish callback
 * comes anyway, the `continue` answers `user_denied`) is `401`, like Rafiki's `result=grant_rejected`. Other failures
 * throw an `HTTPException` (`400`, `401`, `504` when the server's `wait` is too long to sit out, else `502`).
 */
export const processGnapCallback = async (c: Context): Promise<Response> => {
  const config = getConfig(c);
  const cookie = getCookie(c, stateCookieName(config));

  deleteCookie(c, stateCookieName(config), cookieOptions(config, statePath(c, config)));
  dropSessionCookie(c, config, pendingCookieName(config));

  const state = cookie === undefined ? undefined : await readPending(config, cookie);

  if (state === undefined || state.stexp < nowSeconds(config)) {
    throw httpError(400, "Missing, invalid or expired login state");
  }

  const result = c.req.query("result");

  if (result !== undefined) {
    // Neither `result` nor `message` is trusted: the query string is the attacker's.
    throw httpError(
      failureStatus(result),
      failureStatus(result) === 401 ? `GNAP interaction failed: ${result}` : "GNAP interaction failed",
    );
  }

  const interactRef = c.req.query("interact_ref");
  const hash = c.req.query("hash");

  if (interactRef === undefined || hash === undefined) throw httpError(400, "Missing interact_ref or hash");

  const valid = await Effect.runPromise(
    verifyInteractionHash({ clientNonce: state.cn, serverNonce: state.sn, interactRef, grantEndpoint: state.ge, hash }),
  );

  if (!valid) throw httpError(401, "Invalid interaction hash");

  const wire = await resolveWire(config);

  try {
    const done = await continueGrant(wire, { uri: state.cu, token: state.ct }, interactRef, state.nb);

    await saveSession(c, config, done.token, undefined, done.continue);
  } catch (error) {
    if (!(error instanceof GnapAuthError)) throw error;

    if (error.code !== undefined && failureStatus(error.code) === 401) {
      throw httpError(401, `GNAP interaction failed: ${error.code}`);
    }

    throw new HTTPException(error.status === 401 || error.status === 504 ? error.status : 502, {
      message: `GNAP continue failed: ${error.message}`,
    });
  }

  return c.redirect(state.rt);
};

/** A navigation of the user's browser: the only request that may send the user off to log in. */
const isNavigation = (c: Context): boolean =>
  c.req.method === "GET" && [undefined, "navigate"].includes(c.req.header("Sec-Fetch-Mode"));

/**
 * Requires a GNAP session: valid session → handler; otherwise requests a grant and redirects the user to the
 * authorisation server (or, for a grant that needs no interaction, creates the session at once). Only a `GET`
 * navigation (`Sec-Fetch-Mode` absent or `navigate`) starts a grant; any other request without a session gets `401`.
 * Serves the callback itself when mounted on the `redirectUri` path. A grant the server does not finish with a
 * callback (no `interact.finish`, RFC 9635 §5.2) is polled by the browser's next navigations instead, no earlier than
 * the server's `wait`: while it is pending the user is sent to `interact.redirect` again (`202` with `Retry-After`
 * when the server offered no interaction), a denial is `401`, approval lets the request through with the session.
 */
export const gnapAuthMiddleware = (): MiddlewareHandler =>
  createMiddleware(async (c, next) => {
    const config = getConfig(c);

    if (isCallbackRequest(c, config)) return processGnapCallback(c);

    if ((await getGnapAuth(c)) === null) {
      if (!isNavigation(c)) throw httpError(401, "Authentication required");
      const redirect = await startGrant(c, config);

      if (redirect !== undefined) return redirect;
    }

    await next();

    // `c.header` copies a finalised response: one that came from `fetch()` or `Response.redirect()` is immutable.
    if (!c.res.headers.has("Cache-Control")) c.header("Cache-Control", "private, no-cache");
    // The handler may have returned a fresh Response: put a session set or rotated during this request on it.
    const cookie = c.get("gnapAuthCookie");
    const session = c.get("gnapAuth");

    if (cookie !== undefined && session) {
      setCookie(c, config.cookieName, cookie, {
        ...cookieOptions(config),
        maxAge: Math.max(session.ssnexp - nowSeconds(config), 1),
      });
    }
  });
