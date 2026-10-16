import * as Effect from "effect/Effect";
import { Hono } from "hono";
import { sign } from "hono/jwt";
import { describe, expect, it, vi } from "vite-plus/test";
import {
  GnapAuthError,
  getGnapAuth,
  gnapAuthMiddleware,
  initGnapAuthMiddleware,
  revokeGnapSession,
  type GnapAuth,
  type GnapAuthConfig,
} from "../../src/hono/index";
import type { GrantRequestAccessItem } from "../../src/gnap/index";
import { BASE_URL, KEY_ID, createClientKey, outgoing } from "../gnap-server/support";
import { APP, SECRET, createBrowser, createRafikiHarness, exportPrivateKey, pump } from "./support";

const incoming: GrantRequestAccessItem = { type: "incoming-payment", actions: ["create", "read"] };

type Harness = Awaited<ReturnType<typeof createRafikiHarness>>;

/** One deployment of the app: the configuration of a service that talks to the harness's authorisation server. */
const buildApp = (h: Harness, pem: string, overrides: Partial<GnapAuthConfig> = {}) => {
  const app = new Hono();

  app.use(
    "*",
    initGnapAuthMiddleware({
      secret: SECRET,
      grantEndpoint: BASE_URL,
      access: [outgoing],
      client: h.wallet,
      keyId: KEY_ID,
      privateKey: pem,
      fetch: h.fetch,
      clock: h.clock.now,
      refreshInterval: 60,
      ...overrides,
    }),
  );

  app.get("/logout", async (c) => {
    await revokeGnapSession(c);

    return c.text("bye");
  });

  app.use("*", gnapAuthMiddleware());
  app.get("/", async (c) => c.json(await getGnapAuth(c)));

  return app;
};

const createApp = async (
  overrides: Partial<GnapAuthConfig> = {},
  clock?: Parameters<typeof createRafikiHarness>[0],
) => {
  const h = await createRafikiHarness(clock);
  const { pem } = await exportPrivateKey(h.clientKey);
  const app = buildApp(h, pem, overrides);

  return { ...h, app, browser: createBrowser(app), pem };
};

type TestApp = Awaited<ReturnType<typeof createApp>>;

const introspect = (h: TestApp, token: string) => Effect.runPromise(h.server.introspectToken(token));

/** Request → consent → callback: the browser ends up logged in. */
const login = async (h: TestApp) => {
  const first = await h.browser.get(`${APP}/`);
  const callback = await h.consent(first.headers.get("location") ?? "");
  const back = await h.browser.get(callback);

  return { first, back };
};

describe("Rafiki / Open Payments authorisation server", () => {
  it("logs in through the interaction, rotates after the refresh interval, and logs out by revoking", async () => {
    const h = await createApp();
    const { first, back } = await login(h);

    expect(first.status).toBe(302);
    expect(first.headers.get("location")).toContain(`${BASE_URL}/interact/`);
    expect(back.status).toBe(302);
    expect(back.headers.get("location")).toBe(`${APP}/`);

    const home = await h.browser.get(`${APP}/`);
    const session: GnapAuth = await home.json();

    expect(home.status).toBe(200);
    expect(await introspect(h, session.accessToken)).toMatchObject({ active: true });
    expect(session.access).toEqual([outgoing]);

    // Rafiki: `manage` is a URL, the access token itself is the management credential.
    expect(session.manage).toEqual({ uri: expect.stringContaining(`${BASE_URL}/token/`), token: session.accessToken });
    expect(session.continue?.uri).toContain(`${BASE_URL}/continue/`);

    h.clock.advance(61);
    const rotated: GnapAuth = await (await h.browser.get(`${APP}/`)).json();

    expect(rotated.accessToken).not.toBe(session.accessToken);
    expect(rotated.ssnexp).toBe(session.ssnexp);
    expect(await introspect(h, session.accessToken)).toEqual({ active: false });
    expect(await introspect(h, rotated.accessToken)).toMatchObject({ active: true });

    const out = await h.browser.get(`${APP}/logout`);

    expect(out.status).toBe(200);
    expect(await introspect(h, rotated.accessToken)).toEqual({ active: false });

    expect(h.calls.slice(-2)).toEqual([
      expect.stringMatching(/^DELETE .*\/token\//),
      expect.stringMatching(/^DELETE .*\/continue\//),
    ]);
    expect([...h.browser.cookies.keys()]).toEqual([]);
    expect((await h.browser.get(`${APP}/`)).status).toBe(302);
  });

  it("signs bodies with sha-512 like the official client when the client is a wallet address", async () => {
    const h = await createApp();

    await login(h);

    // The grant request and the continue request carry a body.
    expect(h.digests.map((digest) => digest.split("=")[0])).toEqual(["sha-512", "sha-512"]);
  });

  it("creates the session at once for a grant that needs no interaction", async () => {
    const h = await createApp({ access: [incoming] });
    const response = await h.browser.get(`${APP}/`);

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("private, no-cache");
    expect(response.headers.getSetCookie().join()).toContain("gnap-auth=");
    expect(h.calls).toEqual(["POST /gnap"]);
  });

  it("ends the session when it has expired and asks for a new grant", async () => {
    const h = await createApp({ expires: 100 });

    await login(h);
    h.clock.advance(101);
    const again = await h.browser.get(`${APP}/`);

    expect(again.status).toBe(302);
    expect(again.headers.get("location")).toContain("/interact/");
    expect(h.calls.filter((call) => call.startsWith("DELETE"))).toHaveLength(2);
  });

  it("tells the refresh error hook when the server refuses rotation for good, drops the cookie and logs in again", async () => {
    // The server refuses rotation: it understood the request and says no.
    const refusing = (h: TestApp): typeof globalThis.fetch => {
      return async (input) => {
        const request = new Request(input);

        return request.method === "POST" && new URL(request.url).pathname.includes("/token/")
          ? Response.json({ error: { code: "request_denied", description: "bad token" } }, { status: 403 })
          : h.fetch(request);
      };
    };

    const base = await createApp();
    const seen: Array<GnapAuthError> = [];
    const app = new Hono();

    app.use("*", async (c, next) => {
      c.set("gnapAuthRefreshErrorHook", (error) => {
        seen.push(error);
      });
      await next();
    });

    app.use(
      "*",
      initGnapAuthMiddleware({
        secret: SECRET,
        grantEndpoint: BASE_URL,
        access: [outgoing],
        client: base.wallet,
        keyId: KEY_ID,
        privateKey: base.pem,
        fetch: refusing(base),
        clock: base.clock.now,
        refreshInterval: 60,
      }),
    );

    app.use("*", gnapAuthMiddleware());
    app.get("/", (c) => c.text("ok"));

    const browser = createBrowser(app);
    const first = await browser.get(`${APP}/`);

    await browser.get(await base.consent(first.headers.get("location") ?? ""));
    expect((await browser.get(`${APP}/`)).status).toBe(200);

    base.clock.advance(61);
    const next = await browser.get(`${APP}/`);

    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ status: 403, code: "request_denied", message: "bad token" });
    expect(next.headers.getSetCookie().some((line) => line.startsWith("gnap-auth=;"))).toBe(true);
    expect(next.status).toBe(302);
    expect(next.headers.get("location")).toContain("/interact/");
  });
});

describe("a user who comes back inside the server's wait period", () => {
  it("is let in once the wait is over, without a wall-clock sleep", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "Date"] });

    try {
      // Server and middleware share the faked wall clock; `advance` is the timers' job here.
      const h = await createApp({}, { now: () => new Date(), advance: () => undefined });
      const first = await h.browser.get(`${APP}/`);
      const callback = await h.consent(first.headers.get("location") ?? "", "accept", 0);
      // Time only moves while the middleware is sleeping: it must sit out the wait before its one continue.
      const back = await pump(h.browser.get(callback));

      expect(back.status).toBe(302);
      expect(back.headers.get("location")).toBe(`${APP}/`);
      // Waited proactively: one continue, accepted; the one-time interact_ref is never sent twice.
      expect(h.calls.filter((call) => call.startsWith("POST /gnap/continue/"))).toHaveLength(1);
      expect((await h.browser.get(`${APP}/`)).status).toBe(200);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("callback protections", () => {
  it("rejects a wrong hash and leaves no session", async () => {
    const h = await createApp();
    const first = await h.browser.get(`${APP}/`);
    const callback = new URL(await h.consent(first.headers.get("location") ?? ""));

    callback.searchParams.set("hash", "AAAA");
    const response = await h.browser.get(callback.toString());

    expect(response.status).toBe(401);
    expect(await response.text()).toBe("Invalid interaction hash");
    expect([...h.browser.cookies.keys()]).toEqual([]);
  });

  it("rejects a missing, foreign or old-format state cookie, and one the server's clock says expired", async () => {
    const h = await createApp();
    const first = await h.browser.get(`${APP}/`);
    const callback = await h.consent(first.headers.get("location") ?? "");
    const state = [...h.browser.cookies.keys()].find((name) => name.endsWith("-state")) ?? "";
    const genuine = h.browser.cookies.get(state) ?? "";
    const nowSeconds = Math.floor(h.clock.now().getTime() / 1000);

    // The state cookie of another deployment (another secret), and a signed one of the format before cookies were
    // encrypted, written with the right secret.
    const stranger = await createApp({ secret: "another-secret-of-at-least-32-chars!" });

    await stranger.browser.get(`${APP}/`);
    const foreign = stranger.browser.cookies.get(state) ?? "";
    const pending = { cu: "x", ct: "x", cn: "x", sn: "x", ge: BASE_URL, rt: `${APP}/`, nb: 0 };
    const legacy = await sign({ ...pending, stexp: nowSeconds + 600 }, SECRET);

    const call = (cookie?: string) =>
      h.app.request(callback, { headers: cookie === undefined ? {} : { cookie: `${state}=${cookie}` } });

    expect((await call()).status).toBe(400);
    expect((await call(foreign)).status).toBe(400);
    expect((await call(legacy)).status).toBe(400);
    expect((await call()).headers.getSetCookie().join()).not.toContain("gnap-auth=");

    // The genuine cookie works in time (control) and is refused after the state's ten minutes, whatever the browser keeps.
    expect((await call(genuine)).status).toBe(302);
    h.clock.advance(601);
    expect((await call(genuine)).status).toBe(400);
  });

  it("reports a denied interaction as 401", async () => {
    const h = await createApp();
    const first = await h.browser.get(`${APP}/`);
    const callback = await h.consent(first.headers.get("location") ?? "", "reject");

    expect(new URL(callback).searchParams.get("result")).toBe("grant_rejected");
    const response = await h.browser.get(callback);

    expect(response.status).toBe(401);
    expect(await response.text()).toContain("grant_rejected");
  });

  it("maps other results to 400 and never echoes the query string of the callback", async () => {
    const h = await createApp();

    await h.browser.get(`${APP}/`);
    const response = await h.browser.get(`${APP}/callback?result=%3Cb%3Ex%3C%2Fb%3E&message=%3Cscript%3E`);
    const text = await response.text();

    expect(response.status).toBe(400);
    expect(text).not.toContain("<");
    expect(text).not.toContain("script");
  });
});

describe("swapping the signing key", () => {
  /** The browser talks to whatever is deployed: a redeploy replaces the app, the browser keeps its cookies. */
  const withRedeploy = async () => {
    const h = await createApp();
    const next = await createClientKey("alice-key-2");
    const swapped = buildApp(h, (await exportPrivateKey(next)).pem, { keyId: "alice-key-2" });
    let live = h.app;
    const gateway = new Hono().all("*", (c) => live.fetch(c.req.raw));
    const browser = createBrowser(gateway);

    const loggedIn = async (): Promise<GnapAuth> => {
      const first = await browser.get(`${APP}/`);

      await browser.get(await h.consent(first.headers.get("location") ?? ""));

      return (await browser.get(`${APP}/`)).json();
    };

    return {
      h,
      next,
      browser,
      loggedIn,
      deploy: (): void => {
        live = swapped;
      },
    };
  };

  it("keeps every session: the new key signs the rotation and the logout of a grant the old key started", async () => {
    const { h, next, browser, loggedIn, deploy } = await withRedeploy();
    const before = await loggedIn();

    // Open Payments: the wallet address publishes the new key next to the old one, then the service uses it.
    h.publish(next);
    deploy();
    h.clock.advance(61);
    const rotated: GnapAuth = await (await browser.get(`${APP}/`)).json();

    expect(rotated.accessToken).not.toBe(before.accessToken);
    expect(await introspect(h, before.accessToken)).toEqual({ active: false });
    expect(await introspect(h, rotated.accessToken)).toMatchObject({ active: true });
    expect((await browser.get(`${APP}/logout`)).status).toBe(200);
    expect(await introspect(h, rotated.accessToken)).toEqual({ active: false });

    // The grant and its continuation came from the old key; the rotation and both revocations from the new one.
    expect(h.keyIds).toEqual([KEY_ID, KEY_ID, "alice-key-2", "alice-key-2", "alice-key-2"]);
  });

  it("ends the sessions when the wallet address does not publish the new key yet: users log in again once it does", async () => {
    const { h, next, browser, loggedIn, deploy } = await withRedeploy();
    const before = await loggedIn();

    deploy();
    h.clock.advance(61);

    // The server knows no such key and refuses it (`400 invalid_client`): the rotation, and the new grant that follows.
    const refused = await browser.get(`${APP}/`);

    expect(refused.status).toBe(502);
    expect(browser.cookies.has("gnap-auth")).toBe(false);

    h.publish(next);
    const login = await browser.get(`${APP}/`);

    expect(login.status).toBe(302);
    await browser.get(await h.consent(login.headers.get("location") ?? ""));
    const again: GnapAuth = await (await browser.get(`${APP}/`)).json();

    expect(again.accessToken).not.toBe(before.accessToken);
    expect(await introspect(h, again.accessToken)).toMatchObject({ active: true });
    expect(h.keyIds.at(-1)).toBe("alice-key-2");
  });
});
