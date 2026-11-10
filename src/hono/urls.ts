/**
 * The URLs of the app as the user sees them: behind a reverse proxy they are below `externalUrl`, not the origin the
 * app itself sees.
 * @internal Not exported from the public entry point.
 */
import type { Context } from "hono";
import { isLoopbackHost } from "../internal/url";
import { httpError, type Resolved } from "./config";

/**
 * Headers a reverse proxy adds. A loopback `Host` that comes with one is the proxy's upstream address, not where the
 * user's browser is.
 */
const PROXY_HEADERS = ["x-forwarded-host", "x-forwarded-proto", "x-forwarded-for", "forwarded"] as const;

/** Whether the request is the user's own loopback request: a loopback host, and no sign of a proxy in front. */
const isDirectLoopbackRequest = (c: Context): boolean =>
  isLoopbackHost(new URL(c.req.url).hostname) && PROXY_HEADERS.every((name) => c.req.header(name) === undefined);

/**
 * A relative callback is resolved against `externalUrl`, or against the request only when that host is loopback.
 * A public request host is not the finish origin: a proxy that copies `Host` would register the attacker's URL.
 */
const configuredOrigin = (c: Context, config: Resolved): string => {
  if (config.externalUrl !== undefined) return config.externalUrl;
  if (!isDirectLoopbackRequest(c)) {
    throw httpError(
      500,
      "Set externalUrl; the request host is neither the GNAP finish origin nor the origin of the post-login URL",
    );
  }

  return new URL(c.req.url).origin;
};

/** The URL the authorisation server sends the user back to: behind a proxy, below `externalUrl`. */
export const publicRedirectUri = (c: Context, config: Resolved): string =>
  config.redirectUri.startsWith("/")
    ? `${configuredOrigin(c, config).replace(/\/$/, "")}${config.redirectUri}`
    : new URL(config.redirectUri).toString();

/** The `Path` of the state cookie: that of the public callback URL, because that is where the browser sends it. */
export const statePath = (config: Resolved): string => {
  const uri = config.redirectUri.startsWith("/")
    ? `${(config.externalUrl ?? "https://localhost").replace(/\/$/, "")}${config.redirectUri}`
    : config.redirectUri;

  return new URL(uri).pathname;
};

/**
 * Whether the request is the redirect back from the authorisation server: on the public callback path, or on the
 * path the app itself serves it on. Paths only: behind a proxy the origin the app sees is not the public one.
 */
export const isCallbackRequest = (c: Context, config: Resolved): boolean => {
  // `URL.pathname` stays percent-encoded like `statePath`; `c.req.path` is decoded and may be changed by a custom `getPath`.
  const { pathname } = new URL(c.req.url);

  return (
    pathname === statePath(config) ||
    // Without `externalUrl` the public and the served path are the same, so the first test already covered it.
    (config.externalUrl !== undefined &&
      config.redirectUri.startsWith("/") &&
      pathname === new URL(config.redirectUri, "https://localhost").pathname)
  );
};

/** The URL of the request as the user sees it. */
export const publicRequestUrl = (c: Context, config: Resolved): string => {
  if (config.externalUrl === undefined) {
    if (!isDirectLoopbackRequest(c)) {
      throw httpError(500, "Set externalUrl; the request host is not used as the public origin");
    }

    return c.req.url;
  }
  const external = new URL(config.externalUrl);
  const original = new URL(c.req.url);

  external.pathname = `${external.pathname.replace(/\/$/, "")}${original.pathname}`;
  external.search = original.search;
  external.hash = original.hash;

  return external.toString();
};
