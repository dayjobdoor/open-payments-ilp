/**
 * The session and the pending-grant state in their cookies: sealing, reading, rotating and revoking.
 * @internal Not exported from the public entry point.
 */
import * as Schema from "effect/Schema";
import type { Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { CookieOptions } from "hono/utils/cookie";
import type { AccessItem, GrantRequestAccessItem } from "../gnap/index";
import { encodeBase64Url, sha256, utf8Encode } from "../internal/bytes";
import { accessItem } from "../open-payments/schemas";
import { getConfig, httpError, isSecureUri, nowSeconds, resolveWire, type Resolved } from "./config";
import { openCookie, sealCookie } from "./seal";
import { GnapAuthError, revokeCredential, rotateToken, type Credential, type IssuedToken, type Wire } from "./wire";

/**
 * The session in the cookie. Times are epoch seconds. The cookie is encrypted unless `encryptCookies` is `false`: then
 * it is only signed, and whoever holds it (the user's browser included) can read the tokens in it.
 */
export type GnapAuth = {
  /** The access token to present to resource servers. */
  accessToken: string;
  /** When the access token expires, when the server said so. */
  expiresAt?: number;
  /** The access the server granted. */
  access: ReadonlyArray<AccessItem>;
  /** Where and with which token the access token is rotated and revoked. */
  manage?: Credential;
  /** Where and with which token the grant is cancelled. */
  continue?: Credential;
  /** Rotate the access token once this has passed. */
  rtkexp: number;
  /** The session is over, and a new grant is requested, once this has passed. */
  ssnexp: number;
};

/**
 * Called when the authorisation server definitively refuses to rotate the access token (see {@link getGnapAuth}),
 * after the session cookie was dropped (oidc-auth parity). May throw to replace the re-login.
 */
export type GnapAuthRefreshErrorHook = (error: GnapAuthError, c: Context) => void | Promise<void>;

/** Short-lived state of a grant waiting for the user: lives in a (by default encrypted) cookie of the user's browser. */
export type PendingState = {
  /** The continue credential. */
  cu: string;
  ct: string;
  /** The nonce the client sent as `interact.finish.nonce`. */
  cn: string;
  /** The nonce the server returned as `interact.finish`. */
  sn: string;
  /** The grant endpoint the grant was requested at (an input of the interaction hash). */
  ge: string;
  /** Where to go after login. */
  rt: string;
  stexp: number;
  /** The end of the server's `wait` period (epoch seconds): the continuation URI is not called before. */
  nb: number;
};

/**
 * The pointer to a pending grant, in a cookie scoped like the session (sent to every path of the app): the interaction
 * URL the user was sent to, so that a second tab goes there instead of requesting a second grant, and, for a grant
 * without `interact.finish`, what the next navigation polls it with. The state of a grant that finishes with a callback
 * is not sent to every path (see {@link savePending}).
 */
export type PendingPointer = {
  /** What the grant asked for ({@link grantFingerprint}). */
  fp: string;
  /** The interaction URL the user was sent to; absent when the server offered none (approval out of band). */
  ru?: string;
  stexp: number;
  /** A grant without `interact.finish` (RFC 9635 §5.2): present when it has to be polled. */
  poll?: PendingPoll;
};

/** How a grant without `interact.finish` is polled. */
export type PendingPoll = {
  /** The continue credential. */
  cu: string;
  ct: string;
  /** The end of the server's `wait` period (epoch seconds): the continuation URI is not called before. */
  nb: number;
};

const credentialSchema = Schema.Struct({ uri: Schema.String, token: Schema.String });

const gnapAuthSchema: Schema.Codec<GnapAuth> = Schema.Struct({
  accessToken: Schema.String,
  expiresAt: Schema.optionalKey(Schema.Number),
  access: Schema.Array(accessItem),
  manage: Schema.optionalKey(credentialSchema),
  continue: Schema.optionalKey(credentialSchema),
  rtkexp: Schema.Number,
  ssnexp: Schema.Number,
});

const pendingStateSchema: Schema.Codec<PendingState> = Schema.Struct({
  cu: Schema.String,
  ct: Schema.String,
  cn: Schema.String,
  sn: Schema.String,
  ge: Schema.String,
  rt: Schema.String,
  stexp: Schema.Number,
  nb: Schema.Number,
});

const pendingPointerSchema: Schema.Codec<PendingPointer> = Schema.Struct({
  fp: Schema.String,
  ru: Schema.optionalKey(Schema.String),
  stexp: Schema.Number,
  poll: Schema.optionalKey(Schema.Struct({ cu: Schema.String, ct: Schema.String, nb: Schema.Number })),
});

export const STATE_SECONDS = 600;

const MAX_COOKIE_BYTES = 4096;

export const cookieOptions = (config: Resolved, path: string = config.cookiePath): CookieOptions => ({
  path,
  httpOnly: true,
  secure: true,
  sameSite: "Lax",
  ...(config.cookieDomain !== undefined && { domain: config.cookieDomain }),
});

export const stateCookieName = (config: Resolved): string => `${config.cookieName}-state`;

export const pendingCookieName = (config: Resolved): string => `${config.cookieName}-pending`;

// A sealed value is cookie-safe as it is (base64url and dots): what browsers measure is the name and the value.
const fitsInCookie = (name: string, value: string): boolean =>
  utf8Encode(`${name}=${value}`).length <= MAX_COOKIE_BYTES;

/** `url` without its query string and fragment. */
const withoutQuery = (url: string): string => {
  const bare = new URL(url);

  bare.search = "";
  bare.hash = "";

  return bare.toString();
};

/** Stores a session: seals it into the cookie, and remembers the value to re-set it after the handler ran. */
export const saveSession = async (
  c: Context,
  config: Resolved,
  token: IssuedToken,
  previous: GnapAuth | undefined,
  continueCredential: Credential | undefined,
): Promise<GnapAuth> => {
  const now = nowSeconds(config);
  // Rotate before the token expires, with a margin; never later than the refresh interval.
  const rotateIn = Math.min(config.refreshInterval, Math.max((token.expiresAt ?? Infinity) - now - 30, 0));
  const manage = token.manage ?? previous?.manage;

  // Only the credential is kept: a response's `wait` is the pending state's business, not the session's.
  const next =
    continueCredential === undefined
      ? previous?.continue
      : { uri: continueCredential.uri, token: continueCredential.token };

  const session: GnapAuth = {
    accessToken: token.accessToken,
    access: token.access ?? previous?.access ?? [],
    rtkexp: now + rotateIn,
    ssnexp: previous?.ssnexp ?? now + config.expires,
    ...(token.expiresAt !== undefined && { expiresAt: token.expiresAt }),
    ...(manage !== undefined && { manage }),
    ...(next !== undefined && { continue: next }),
  };

  const cookie = await sealCookie(config, "session", session);

  if (!fitsInCookie(config.cookieName, cookie)) {
    throw httpError(500, `The GNAP session does not fit in a cookie of ${MAX_COOKIE_BYTES} bytes`);
  }

  setCookie(c, config.cookieName, cookie, { ...cookieOptions(config), maxAge: Math.max(session.ssnexp - now, 1) });
  c.set("gnapAuthCookie", cookie);
  c.set("gnapAuth", session);

  return session;
};

/**
 * The `Path` of the login-state cookie. It is sent to the callback only; a `__Host-` name must have `Path=/`
 * (RFC 6265bis §4.1.3), so then it goes to every path.
 */
export const stateCookiePath = (config: Resolved, callbackPath: string): string =>
  config.cookieName.startsWith("__Host-") ? "/" : callbackPath;

/**
 * Deletes cookie `name` at `path`, with the attributes it was set with: `Secure` (a `__Secure-` or `__Host-` name is
 * invalid without it) and the `Domain` too, when there is one (a cookie of another scope is not touched).
 */
const deleteScoped = (c: Context, config: Resolved, name: string, path: string): void => {
  deleteCookie(c, name, { path, secure: true });

  if (config.cookieDomain !== undefined) deleteCookie(c, name, { path, secure: true, domain: config.cookieDomain });
};

/** Deletes cookie `name` (the session's by default), scoped like the cookies this module sets. */
export const dropSessionCookie = (c: Context, config: Resolved, name: string = config.cookieName): void =>
  deleteScoped(c, config, name, config.cookiePath);

/** Deletes the login-state cookie of a callback served at `callbackPath`. */
export const dropStateCookie = (c: Context, config: Resolved, callbackPath: string): void =>
  deleteScoped(c, config, stateCookieName(config), stateCookiePath(config, callbackPath));

const readSession = (config: Resolved, cookie: string): Promise<GnapAuth | undefined> =>
  openCookie(config, "session", cookie, gnapAuthSchema);

export const readPending = (config: Resolved, cookie: string): Promise<PendingState | undefined> =>
  openCookie(config, "state", cookie, pendingStateSchema);

/**
 * What a grant request asked for, as a short text: a pending grant is only reused by a request that would ask for the
 * same (another path of the app may need other access).
 */
export const grantFingerprint = async (
  endpoint: string,
  access: ReadonlyArray<GrantRequestAccessItem>,
  redirectUri: string,
): Promise<string> => encodeBase64Url(await sha256(utf8Encode(JSON.stringify([endpoint, access, redirectUri]))));

/** Writes the pointer cookie, scoped like the session, until `pointer.stexp`; `false` when it does not fit. */
const setPointer = async (c: Context, config: Resolved, pointer: PendingPointer): Promise<boolean> => {
  const name = pendingCookieName(config);
  const value = await sealCookie(config, "pending", pointer);

  if (!fitsInCookie(name, value)) return false;
  setCookie(c, name, value, { ...cookieOptions(config), maxAge: Math.max(pointer.stexp - nowSeconds(config), 1) });

  return true;
};

/**
 * Stores a grant waiting for the user's return. The state (continue credential and nonces) is scoped to the callback
 * `path`, the only place that needs it. Next to it goes a pointer to the interaction URL, scoped like the session, so
 * that another request of the browser (a second tab) is sent to the same interaction instead of requesting a second
 * grant, which would replace the state under the first one's feet. Neither outlives `state.stexp`. The state cookie
 * is scoped to `callbackPath` (to `/` with a `__Host-` name); a return URL whose query string does not fit the cookie
 * is stored without it, and one that still does not fit is an error.
 */
export const savePending = async (
  c: Context,
  config: Resolved,
  state: PendingState,
  reuse: { readonly redirect: string; readonly fingerprint: string },
  callbackPath: string,
): Promise<void> => {
  const name = stateCookieName(config);
  let value = await sealCookie(config, "state", state);

  // The return URL carries the page's query string, which may be any length: without it the login still works and
  // lands on the page, just without its query.
  if (!fitsInCookie(name, value)) {
    value = await sealCookie(config, "state", { ...state, rt: withoutQuery(state.rt) });

    if (!fitsInCookie(name, value)) {
      throw httpError(500, `The pending GNAP login does not fit in a cookie of ${MAX_COOKIE_BYTES} bytes`);
    }
  }

  setCookie(c, name, value, {
    ...cookieOptions(config, stateCookiePath(config, callbackPath)),
    maxAge: Math.max(state.stexp - nowSeconds(config), 1),
  });

  // A pointer that does not fit is left out (and an older one removed): the next request then asks for its own grant.
  if (!(await setPointer(c, config, { fp: reuse.fingerprint, ru: reuse.redirect, stexp: state.stexp }))) {
    dropSessionCookie(c, config, pendingCookieName(config));
  }
};

/**
 * Stores a grant without `interact.finish` (RFC 9635 §5.2): no callback comes, so the continue credential cannot wait
 * in the callback's own cookie. It goes into the pointer, the one cookie of the browser's next navigation to any
 * path. An interaction URL too long for the cookie is left out (later navigations are told the grant is pending
 * without being sent there again); a grant that cannot be stored at all cannot be polled, which is an error.
 */
export const savePolling = async (
  c: Context,
  config: Resolved,
  pointer: PendingPointer & { readonly poll: PendingPoll },
): Promise<void> => {
  const withoutRedirect = { fp: pointer.fp, stexp: pointer.stexp, poll: pointer.poll };

  if ((await setPointer(c, config, pointer)) || (await setPointer(c, config, withoutRedirect))) return;
  dropSessionCookie(c, config, pendingCookieName(config));

  throw httpError(500, `The pending GNAP grant does not fit in a cookie of ${MAX_COOKIE_BYTES} bytes`);
};

/**
 * The pointer of the grant this browser is already waiting on, when it is sealed with this secret, not expired, for the
 * same `fingerprint`, and usable (an interaction URL to go to, or a grant to poll).
 */
export const readPendingPointer = async (
  c: Context,
  config: Resolved,
  fingerprint: string,
): Promise<PendingPointer | undefined> => {
  const cookie = getCookie(c, pendingCookieName(config));

  if (cookie === undefined) return undefined;
  const pointer = await openCookie(config, "pending", cookie, pendingPointerSchema);

  const usable =
    pointer !== undefined &&
    pointer.fp === fingerprint &&
    pointer.stexp >= nowSeconds(config) &&
    (pointer.ru === undefined ? pointer.poll !== undefined : isSecureUri(pointer.ru));

  return usable ? pointer : undefined;
};

/**
 * A rotation answer that cannot be a lost race (another request rotated first: Rafiki answers `401`/`404` to the old
 * credential; RFC 9635 does not specify it) nor an outage (`429`, `5xx`, no answer, timeout): the server understood the
 * request and refuses it, so the session is gone. Every `4xx` but `401`, `404`, `408` and `429`.
 */
const refusesRotation = (error: GnapAuthError): boolean =>
  error.status >= 400 && error.status < 500 && ![401, 404, 408, 429].includes(error.status);

/**
 * Rotations in flight in this process, by a hash of the management credential: requests that carry the same cookie
 * (a page with several calls after the tab was idle) share one rotation instead of racing it, so that none of them
 * loses its token to another (the server revokes the old one when it rotates).
 */
const rotations = new Map<string, Promise<IssuedToken>>();

const rotateOnce = async (wire: Wire, manage: Credential): Promise<IssuedToken> => {
  const key = encodeBase64Url(await sha256(utf8Encode(`${manage.uri}\n${manage.token}`)));
  const running = rotations.get(key);

  if (running !== undefined) return running;
  const started = rotateToken(wire, manage).finally(() => rotations.delete(key));

  rotations.set(key, started);

  return started;
};

/** Requests whose rotation was refused as if another request had rotated first (`401`/`404`). */
const lostRaces = new WeakSet<Context>();

/**
 * Whether the session of this request could not be rotated because the server no longer knows its credential, which is
 * what a rotation by another request (another process, or one that finished just before this one began) looks like.
 * Only meaningful after {@link getGnapAuth}.
 */
export const lostRotationRace = (c: Context): boolean => lostRaces.has(c);

/** Marks a page load that was sent to the same URL once, to pick up a session rotated by another request. */
export const retryCookieName = (config: Resolved): string => `${config.cookieName}-retry`;

const RETRY_SECONDS = 30;

/** Sets the mark of {@link retryCookieName}. */
export const markRetry = (c: Context, config: Resolved): void =>
  setCookie(c, retryCookieName(config), "1", { ...cookieOptions(config), maxAge: RETRY_SECONDS });

/**
 * The current session, or `null` when there is none. Rotates the access token when the refresh interval (or the
 * token's lifetime) is over; when the session has expired (`ssnexp`), revokes it and returns `null`.
 *
 * Requests of this process that carry the same cookie share one rotation. A failed rotation does not end the
 * session: another request (of another process) may have rotated first (the winner's response sets the new cookie),
 * or the server may be unavailable. The request then goes on without a session (`null`) and
 * without touching the cookie. Only when the server definitively refuses (a `4xx` other than `401`, `404`, `408`,
 * `429`) is the cookie dropped and `gnapAuthRefreshErrorHook` called (set it with `c.set` before this runs; it may
 * throw to replace the re-login).
 */
export const getGnapAuth = async (c: Context): Promise<GnapAuth | null> => {
  const config = getConfig(c);
  const cached = c.get("gnapAuth");

  if (cached !== undefined) return cached;
  const jwt = getCookie(c, config.cookieName);

  if (jwt === undefined) return null;

  const stored = await readSession(config, jwt);

  if (stored === undefined) {
    dropSessionCookie(c, config);

    return null;
  }

  let session = stored;
  const now = nowSeconds(config);

  if (session.ssnexp < now) {
    // Best effort: a failing server must not turn an expired session into an error.
    await revokeGnapSession(c).catch(() => undefined);

    return null;
  }

  if (session.rtkexp <= now) {
    if (session.manage === undefined) {
      if (session.expiresAt !== undefined && session.expiresAt <= now) {
        dropSessionCookie(c, config);

        return null;
      }
    } else {
      try {
        const wire = await resolveWire(config);

        session = await saveSession(c, config, await rotateOnce(wire, session.manage), session, undefined);
      } catch (error) {
        if (!(error instanceof GnapAuthError)) throw error;
        c.set("gnapAuth", null);

        if (error.status === 401 || error.status === 404) lostRaces.add(c);

        if (refusesRotation(error)) {
          dropSessionCookie(c, config);
          await c.get("gnapAuthRefreshErrorHook")?.(error, c);
        }

        return null;
      }
    }
  }

  c.set("gnapAuth", session);

  return session;
};

/**
 * Ends the session: revokes the access token (`DELETE manage`), then cancels the grant (`DELETE continue`), tolerating
 * a server that already forgot either, and deletes the cookie. The two requests are sent one after the other, in that
 * order, so the authorisation server always sees them in the same order (signing is asynchronous: concurrent
 * requests would reach it in any order). A failure of the first does not skip the second; the first failure is
 * thrown once both were tried.
 */
export const revokeGnapSession = async (c: Context): Promise<void> => {
  const config = getConfig(c);
  const jwt = getCookie(c, config.cookieName);
  // The session of this request (rotated or created in it) wins over the cookie the browser sent.
  const current = c.get("gnapAuth");

  dropSessionCookie(c, config);
  c.set("gnapAuth", null);

  const session = current ?? (jwt === undefined ? undefined : await readSession(config, jwt));

  if (session === undefined) return;
  const wire = await resolveWire(config);
  const failures: Array<unknown> = [];

  for (const credential of [session.manage, session.continue]) {
    if (credential === undefined) continue;

    try {
      await revokeCredential(wire, credential);
    } catch (error) {
      failures.push(error);
    }
  }

  if (failures.length > 0) throw failures[0];
};
