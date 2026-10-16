import * as Effect from "effect/Effect";
import type { Hono } from "hono";
import { vi } from "vite-plus/test";
import { createGnapServer, memoryGnapStore } from "../../src/gnap/server/index";
import { encodeBase64 } from "../../src/internal/bytes";
import {
  BASE_URL,
  CONSENT_URL,
  IDP_SECRET,
  WALLET,
  createClientKey,
  createClock,
  walletFetch,
  type ClientKey,
} from "../gnap-server/support";

export const APP = "https://app.test";

export const SECRET = "a-session-secret-of-at-least-32-characters";

/** An Ed25519 private key in the two formats the middleware accepts. */
export const exportPrivateKey = async (key: ClientKey) => {
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", key.signingKey.privateKey));
  const jwk = await crypto.subtle.exportKey("jwk", key.signingKey.privateKey);

  return {
    pem: `-----BEGIN PRIVATE KEY-----\n${encodeBase64(pkcs8)}\n-----END PRIVATE KEY-----`,
    jwk,
  };
};

interface StoredCookie {
  readonly name: string;
  readonly value: string;
  readonly domain: string;
  /** No `Domain` attribute: only the exact host gets it back. */
  readonly hostOnly: boolean;
  readonly path: string;
  readonly secure: boolean;
  /** Epoch milliseconds; `undefined` for a session cookie. */
  readonly expiresAt: number | undefined;
}

const domainMatches = (host: string, cookie: StoredCookie): boolean =>
  host === cookie.domain || (!cookie.hostOnly && host.endsWith(`.${cookie.domain}`));

/** RFC 6265 §5.1.4. */
const pathMatches = (requestPath: string, cookiePath: string): boolean =>
  requestPath === cookiePath ||
  (requestPath.startsWith(cookiePath) && (cookiePath.endsWith("/") || requestPath[cookiePath.length] === "/"));

/** RFC 6265 §5.1.4: the directory of the request path. */
const defaultPath = (requestPath: string): string => {
  const last = requestPath.lastIndexOf("/");

  return last <= 0 ? "/" : requestPath.slice(0, last);
};

/**
 * The cookie jar and manual redirects of a browser talking to one Hono app, RFC 6265: cookies are scoped by `Domain`
 * and `Path`, `Secure` ones only travel over https, and `Max-Age` / `Expires` are judged by `now`. The browser sees
 * the URLs it is given; `upstream` maps them to what the app sees (a reverse proxy).
 */
export const createBrowser = (
  app: Hono,
  options: { readonly now?: () => Date; readonly upstream?: (url: URL) => string } = {},
) => {
  const { now = () => new Date(), upstream = (url: URL) => url.toString() } = options;
  const jar = new Map<string, StoredCookie>();
  const key = (cookie: StoredCookie): string => `${cookie.domain}\n${cookie.path}\n${cookie.name}`;

  const live = (): Array<StoredCookie> => {
    for (const [id, cookie] of jar)
      if (cookie.expiresAt !== undefined && cookie.expiresAt <= now().getTime()) jar.delete(id);

    return [...jar.values()];
  };

  const absorb = (response: Response, url: URL): void => {
    for (const line of response.headers.getSetCookie()) {
      const [pair = "", ...attributes] = line.split(";").map((part) => part.trim());
      const [name = "", ...value] = pair.split("=");

      const attribute = (wanted: string): string | undefined =>
        attributes
          .find((entry) => entry.toLowerCase().split("=")[0] === wanted)
          ?.split("=")
          .slice(1)
          .join("=");

      const domainAttribute = attribute("domain")?.replace(/^\./, "").toLowerCase();
      const maxAge = attribute("max-age");
      const expires = attribute("expires");
      const secure = attributes.some((entry) => entry.toLowerCase() === "secure");
      const path = attribute("path");
      const host = url.hostname;

      // A browser refuses a cookie for another host, and a `Secure` one from an insecure origin.
      if (domainAttribute !== undefined && host !== domainAttribute && !host.endsWith(`.${domainAttribute}`)) continue;

      if (secure && url.protocol !== "https:") continue;

      const cookie: StoredCookie = {
        name,
        value: value.join("="),
        domain: domainAttribute ?? host,
        hostOnly: domainAttribute === undefined,
        path: path?.startsWith("/") === true ? path : defaultPath(url.pathname),
        secure,
        expiresAt:
          maxAge !== undefined
            ? now().getTime() + Number(maxAge) * 1000
            : expires === undefined
              ? undefined
              : Date.parse(expires),
      };

      jar.set(key(cookie), cookie);
    }

    live();
  };

  const header = (url: URL): string =>
    live()
      .filter(
        (cookie) =>
          domainMatches(url.hostname, cookie) &&
          pathMatches(url.pathname, cookie.path) &&
          (!cookie.secure || url.protocol === "https:"),
      )
      .sort((a, b) => b.path.length - a.path.length)
      .map((cookie) => `${cookie.name}=${cookie.value}`)
      .join("; ");

  return {
    /** The live cookies by name (what the browser stores, whatever URL they would be sent to). */
    get cookies(): Map<string, string> {
      return new Map(live().map((cookie) => [cookie.name, cookie.value]));
    },
    /** The cookie jar's stored cookies, `Path` and all. */
    stored: (): ReadonlyArray<StoredCookie> => live(),
    /** `GET` without following redirects. */
    get: async (url: string, headers: Record<string, string> = {}): Promise<Response> => {
      const target = new URL(url);
      const cookie = header(target);
      const requestHeaders = new Headers(headers);

      if (cookie !== "") requestHeaders.set("cookie", cookie);
      const response = await app.request(upstream(target), { headers: requestHeaders });

      absorb(response, target);

      return response;
    },
  };
};

/**
 * The browser's `fetch` runs on fake time: let the middleware's sleeps elapse (a second at a time) until `work` is
 * done. Fails when it is still pending after `MAX_PUMPS` rounds, instead of spinning on after a hang.
 */
const MAX_PUMPS = 1_000_000;

export const pump = async <T>(work: Promise<T>): Promise<T> => {
  let settled = false;

  const guarded = work.finally(() => {
    settled = true;
  });

  for (let round = 0; !settled; round += 1) {
    if (round >= MAX_PUMPS) throw new Error(`pump: still pending after ${MAX_PUMPS} rounds`);

    // Signing is real asynchronous work: let it run between the fake seconds.
    if (vi.getTimerCount() > 0) await vi.advanceTimersByTimeAsync(1000);
    await new Promise((resolve) => setImmediate(resolve));
  }

  return guarded;
};

/** A Rafiki-compatible authorisation server (the package's own) on an injectable clock. */
export const createRafikiHarness = async (clock: ReturnType<typeof createClock> = createClock()) => {
  const clientKey = await createClientKey();
  /** The keys the wallet address's `jwks.json` publishes: a key rotation announces the new key before using it. */
  const published: Array<ClientKey> = [clientKey];

  const server = createGnapServer({
    baseUrl: BASE_URL,
    clock: clock.now,
    store: memoryGnapStore(),
    fetch: walletFetch(published),
    interaction: { consentUrl: CONSENT_URL },
    idpSecret: IDP_SECRET,
  });

  const calls: Array<string> = [];
  const digests: Array<string> = [];
  /** `keyid` of the signature of every request, in order. */
  const keyIds: Array<string> = [];

  const fetch: typeof globalThis.fetch = async (input) => {
    const request = new Request(input);

    calls.push(`${request.method} ${new URL(request.url).pathname}`);

    const digest = request.headers.get("content-digest");

    if (digest !== null) digests.push(digest);
    keyIds.push(/keyid="([^"]+)"/.exec(request.headers.get("signature-input") ?? "")?.[1] ?? "");

    return Effect.runPromise(server.route(request));
  };

  /** The user's side: follows `interact.redirect`, consents through the back channel, returns the callback URL. */
  const consent = async (
    redirect: string,
    choice: "accept" | "reject" = "accept",
    elapsedSeconds = 6,
  ): Promise<string> => {
    const start = await Effect.runPromise(server.route(new Request(redirect, { redirect: "manual" })));
    const [interactId = "", nonce = ""] = new URL(redirect).pathname.split("/").slice(-2);
    const cookie = (start.headers.get("set-cookie") ?? "").split(";")[0] ?? "";

    await Effect.runPromise(
      server.route(
        new Request(`${BASE_URL}/grant/${interactId}/${nonce}/${choice}`, {
          method: "POST",
          headers: { "x-idp-secret": IDP_SECRET },
        }),
      ),
    );

    // Rafiki-style servers refuse to continue a grant within `wait` seconds of the last request.
    clock.advance(elapsedSeconds);

    const finish = await Effect.runPromise(
      server.route(
        new Request(`${BASE_URL}/interact/${interactId}/${nonce}/finish`, { redirect: "manual", headers: { cookie } }),
      ),
    );

    return finish.headers.get("location") ?? "";
  };

  return {
    clientKey,
    clock,
    server,
    fetch,
    calls,
    digests,
    keyIds,
    consent,
    wallet: WALLET,
    publish: (key: ClientKey): void => {
      published.push(key);
    },
  };
};
