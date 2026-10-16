/**
 * The URLs of the app as the user sees them: behind a reverse proxy they are below `externalUrl`, not the origin the
 * app itself sees.
 * @internal Not exported from the public entry point.
 */
import type { Context } from "hono";
import type { Resolved } from "./config";

/** The URL the authorisation server sends the user back to: behind a proxy, below `externalUrl`. */
export const publicRedirectUri = (c: Context, config: Resolved): string =>
  config.externalUrl !== undefined && config.redirectUri.startsWith("/")
    ? `${config.externalUrl.replace(/\/$/, "")}${config.redirectUri}`
    : new URL(config.redirectUri, c.req.url).toString();

/** The `Path` of the state cookie: that of the public callback URL, because that is where the browser sends it. */
export const statePath = (c: Context, config: Resolved): string => new URL(publicRedirectUri(c, config)).pathname;

/**
 * Whether the request is the redirect back from the authorisation server: on the public callback path, or on the
 * path the app itself serves it on. Paths only: behind a proxy the origin the app sees is not the public one.
 */
export const isCallbackRequest = (c: Context, config: Resolved): boolean => {
  // `URL.pathname` stays percent-encoded like `statePath`; `c.req.path` is decoded and may be changed by a custom `getPath`.
  const { pathname } = new URL(c.req.url);

  return (
    pathname === statePath(c, config) ||
    // Without `externalUrl` the public and the served path are the same, so the first test already covered it.
    (config.externalUrl !== undefined &&
      config.redirectUri.startsWith("/") &&
      pathname === new URL(config.redirectUri, c.req.url).pathname)
  );
};

/** The URL of the request as the user sees it. */
export const publicRequestUrl = (c: Context, config: Resolved): string => {
  if (config.externalUrl === undefined) return c.req.url;
  const external = new URL(config.externalUrl);
  const original = new URL(c.req.url);

  external.pathname = `${external.pathname.replace(/\/$/, "")}${original.pathname}`;
  external.search = original.search;
  external.hash = original.hash;

  return external.toString();
};
