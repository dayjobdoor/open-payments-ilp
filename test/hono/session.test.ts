import * as Effect from "effect/Effect";
import { Hono } from "hono";
import { sign } from "hono/jwt";
import { afterEach, describe, expect, it, vi } from "vite-plus/test";
import type { GrantRequestAccessItem } from "../../src/gnap/index";
import {
  getGnapAuth,
  gnapAuthMiddleware,
  initGnapAuthMiddleware,
  processGnapCallback,
  revokeGnapSession,
  type GnapAuth,
  type GnapAuthConfig,
} from "../../src/hono/index";
import { decodeBase64Url, encodeBase64Url } from "../../src/internal/bytes";
import { BASE_URL, KEY_ID, createClientKey, outgoing } from "../gnap-server/support";
import { APP, SECRET, createBrowser, createRafikiHarness, exportPrivateKey } from "./support";

const incoming: GrantRequestAccessItem = { type: "incoming-payment", actions: ["create", "read"] };

/** What a script calling an API with `fetch()` sends: it never navigates. */
const XHR = { "Sec-Fetch-Mode": "cors" };

interface Setup {
  /** Mounted before the GNAP middleware is configured. */
  readonly before?: (app: Hono) => void;
  /** Mounted after the configuration, before the login middleware (a handler that serves the callback itself). */
  readonly early?: (app: Hono) => void;
  /** Mounted after the login middleware. */
  readonly routes?: (app: Hono) => void;
  readonly wrapFetch?: (inner: typeof globalThis.fetch) => typeof globalThis.fetch;
  readonly browser?: Parameters<typeof createBrowser>[1];
  /** The format of the client key in the config. Default `pem`. */
  readonly key?: "pem" | "jwk";
}

/** The package's own Rafiki-compatible authorisation server behind a Hono app that requires a login. */
const createApp = async (overrides: Partial<GnapAuthConfig> = {}, setup: Setup = {}) => {
  const h = await createRafikiHarness();
  const { pem, jwk } = await exportPrivateKey(h.clientKey);
  const app = new Hono();

  setup.before?.(app);

  app.use(
    "*",
    initGnapAuthMiddleware({
      secret: SECRET,
      grantEndpoint: BASE_URL,
      access: [outgoing],
      client: h.wallet,
      keyId: KEY_ID,
      ...(setup.key === "jwk" ? { privateJwk: jwk } : { privateKey: pem }),
      fetch: setup.wrapFetch?.(h.fetch) ?? h.fetch,
      clock: h.clock.now,
      refreshInterval: 60,
      ...overrides,
    }),
  );

  setup.early?.(app);
  app.use("*", gnapAuthMiddleware());
  app.get("/", async (c) => c.json(await getGnapAuth(c)));
  setup.routes?.(app);

  return { ...h, app, pem, jwk, browser: createBrowser(app, setup.browser) };
};

type TestApp = Awaited<ReturnType<typeof createApp>>;

/** Request → consent → callback. */
const login = async (h: TestApp, url = `${APP}/`) => {
  const first = await h.browser.get(url);
  const callback = await h.consent(first.headers.get("location") ?? "");
  const back = await h.browser.get(callback);

  return { first, back };
};

const introspect = (h: TestApp, token: string) => Effect.runPromise(h.server.introspectToken(token));

const cookieLine = (response: Response, name: string): string | undefined =>
  response.headers.getSetCookie().find((line) => line.startsWith(`${name}=`));

const attributesOf = (line: string | undefined): Array<string> =>
  (line ?? "")
    .split(";")
    .slice(1)
    .map((part) => part.trim().toLowerCase());

/** Whether the response tells the browser to forget cookie `name`. */
const deletes = (response: Response, name: string): boolean =>
  response.headers.getSetCookie().some((line) => line.startsWith(`${name}=;`) && /max-age=0/i.test(line));

const OTHER_SECRET = "another-secret-of-at-least-32-chars!";

/** Cookies that are only signed, as before cookies were encrypted: the opt-out `encryptCookies: false`. */
const SIGNED: Partial<GnapAuthConfig> = { encryptCookies: false };

/** The value with one character in the middle changed: whatever it protected, it is not the same value. */
const tamper = (value: string): string => {
  const middle = Math.floor(value.length / 2);

  return `${value.slice(0, middle)}${value[middle] === "A" ? "B" : "A"}${value.slice(middle + 1)}`;
};

/** What the owner of the browser can read in a cookie value: the text itself and each dot-separated base64url part. */
const readableIn = (value: string): string =>
  [
    value,
    ...value.split(".").map((part) => {
      try {
        return new TextDecoder().decode(decodeBase64Url(part));
      } catch {
        return "";
      }
    }),
  ].join("\n");

const grantRequests = (h: TestApp): number => h.calls.filter((call) => call === "POST /gnap").length;

/** The authorisation server tells how long the interaction lasts (RFC 9635 §3.3 `expires_in`). */
const expiringAfter =
  (seconds: number) =>
  (inner: typeof globalThis.fetch): typeof globalThis.fetch =>
  async (input, init) => {
    const response = await inner(input, init);
    const body = await response.clone().json();

    return body.interact === undefined
      ? response
      : Response.json({ ...body, interact: { ...body.interact, expires_in: seconds } }, { status: response.status });
  };

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("a signed session cookie (encryptCookies: false)", () => {
  const forge = (h: TestApp) => {
    const now = Math.floor(h.clock.now().getTime() / 1000);

    const session = (overrides: Partial<GnapAuth> = {}): GnapAuth => ({
      accessToken: "forged",
      access: [],
      rtkexp: now + 600,
      ssnexp: now + 3600,
      ...overrides,
    });

    const segment = (value: GnapAuth | Record<"alg" | "typ", string>): string =>
      encodeBase64Url(new TextEncoder().encode(JSON.stringify(value)));

    const visit = (jwt: string) => h.app.request(`${APP}/`, { headers: { cookie: `gnap-auth=${jwt}` } });

    return { session, segment, visit };
  };

  it("is accepted when it is signed with the secret (control for the forgeries below)", async () => {
    const h = await createApp(SIGNED);
    const { session, visit } = forge(h);
    const response = await visit(await sign(session(), SECRET));

    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ accessToken: "forged" });
  });

  it("is refused, cleared and answered with a new login when it was signed with another secret", async () => {
    const h = await createApp(SIGNED);
    const { session, visit } = forge(h);
    const response = await visit(await sign(session(), "another-secret-of-at-least-32-chars!"));

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toContain("/interact/");
    expect(deletes(response, "gnap-auth")).toBe(true);
  });

  it("is refused when its algorithm is none", async () => {
    const h = await createApp(SIGNED);
    const { session, segment, visit } = forge(h);
    const response = await visit(`${segment({ alg: "none", typ: "JWT" })}.${segment(session())}.`);

    expect(response.status).toBe(302);
    expect(deletes(response, "gnap-auth")).toBe(true);
  });

  it("is refused when its payload was changed after signing", async () => {
    const h = await createApp(SIGNED);
    const { session, segment, visit } = forge(h);
    const [header = "", , signature = ""] = (await sign(session(), SECRET)).split(".");
    const response = await visit(`${header}.${segment(session({ accessToken: "admin" }))}.${signature}`);

    expect(response.status).toBe(302);
    expect(deletes(response, "gnap-auth")).toBe(true);
  });

  it("is refused once its session expiry has passed, even when it is signed", async () => {
    const h = await createApp(SIGNED);
    const { session, visit } = forge(h);
    const now = Math.floor(h.clock.now().getTime() / 1000);
    const response = await visit(await sign(session({ ssnexp: now - 1 }), SECRET));

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toContain("/interact/");
    expect(deletes(response, "gnap-auth")).toBe(true);
  });
});

describe("the session cookie", () => {
  it("is httpOnly, secure and SameSite=Lax, like the state cookie, each scoped to its path", async () => {
    const h = await createApp();
    const { first, back } = await login(h);
    const state = attributesOf(cookieLine(first, "gnap-auth-state"));
    const session = attributesOf(cookieLine(back, "gnap-auth"));

    expect(state).toEqual(expect.arrayContaining(["httponly", "secure", "samesite=lax", "path=/callback"]));
    expect(state.some((attribute) => /^max-age=\d+$/.test(attribute))).toBe(true);
    expect(session).toEqual(expect.arrayContaining(["httponly", "secure", "samesite=lax", "path=/"]));
    expect(session.some((attribute) => /^max-age=\d+$/.test(attribute))).toBe(true);
  });

  it("takes a secret of 32 characters", async () => {
    const response = await (await createApp({ secret: "x".repeat(32) })).browser.get(`${APP}/`);

    expect(response.status).toBe(302);
  });
});

describe("cookie protection", () => {
  /** The cookies of a login while it waits for the user, and the session cookie once it is done. */
  const loginStages = async (config: Partial<GnapAuthConfig>) => {
    const h = await createApp(config);
    const first = await h.browser.get(`${APP}/`);
    const waiting = [...h.browser.cookies.values()];

    await h.browser.get(await h.consent(first.headers.get("location") ?? ""));
    const session: GnapAuth = await (await h.browser.get(`${APP}/`)).json();

    return { h, waiting, session, cookie: h.browser.cookies.get("gnap-auth") ?? "" };
  };

  const visitWith = (h: TestApp, cookie: string) =>
    h.app.request(`${APP}/`, { headers: { cookie: `gnap-auth=${cookie}` } });

  it.each([
    ["encrypts the cookies by default", {}, false],
    ["only signs them with encryptCookies: false", SIGNED, true],
  ] as const)("%s: the tokens and interaction URLs are readable in them: %s", async (_name, config, readable) => {
    const { waiting, session, cookie } = await loginStages(config);
    const text = [...waiting, cookie].map(readableIn).join("\n");

    // The waiting login holds the continue credential and the interaction URL, the session the tokens.
    for (const secret of [session.accessToken, session.manage?.uri, `${BASE_URL}/interact/`, `${BASE_URL}/continue/`]) {
      expect(text.includes(secret ?? "")).toBe(readable);
    }
  });

  it("reads back its own cookie", async () => {
    const { h, session, cookie } = await loginStages({});
    const response = await visitWith(h, cookie);

    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ accessToken: session.accessToken, ssnexp: session.ssnexp });
  });

  it.each([
    ["tampered with", ({ own }: Cookies) => tamper(own)],
    ["cut short", ({ own }: Cookies) => own.slice(0, Math.floor(own.length / 2))],
    ["empty after its version", () => "1."],
    ["not base64", () => "1.!!!"],
    ["of a version that does not exist yet", ({ own }: Cookies) => `2.${own.slice(2)}`],
    ["sealed with another secret", ({ foreign }: Cookies) => foreign],
    ["a signed JWT, as written before cookies were encrypted", ({ legacy }: Cookies) => legacy],
  ])("treats a session cookie that is %s as no session: cleared, a new login, no error", async (_name, alter) => {
    const { h, cookie: own } = await loginStages({});
    const { cookie: foreign } = await loginStages({ secret: OTHER_SECRET });
    const now = Math.floor(h.clock.now().getTime() / 1000);
    const legacy = await sign({ accessToken: "legacy", access: [], rtkexp: now + 600, ssnexp: now + 3600 }, SECRET);
    const response = await visitWith(h, alter({ own, foreign, legacy }));

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toContain("/interact/");
    expect(deletes(response, "gnap-auth")).toBe(true);
  });

  it("writes a signed JWT with encryptCookies: false, and each format discards the cookies of the other", async () => {
    const signed = await loginStages(SIGNED);
    const sealed = await loginStages({});

    expect(signed.cookie).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);
    expect(sealed.cookie).toMatch(/^1\.[\w-]+$/);
    expect((await visitWith(signed.h, signed.cookie)).status).toBe(200);
    expect((await visitWith(sealed.h, sealed.cookie)).status).toBe(200);

    // Switching the setting is like changing the secret: the cookies written before are no session, never an error.
    for (const [h, other] of [
      [signed.h, sealed.cookie],
      [sealed.h, signed.cookie],
    ] as const) {
      const response = await visitWith(h, other);

      expect(response.status).toBe(302);
      expect(deletes(response, "gnap-auth")).toBe(true);
    }
  });
});

/** The session cookie of a deployment (`own`), of another one (`foreign`), and one signed the old way (`legacy`). */
interface Cookies {
  readonly own: string;
  readonly foreign: string;
  readonly legacy: string;
}

describe("configuration passed to initGnapAuthMiddleware", () => {
  const passed: GnapAuthConfig = {
    secret: SECRET,
    grantEndpoint: BASE_URL,
    access: [outgoing],
    client: "https://wallet.test/alice",
    keyId: KEY_ID,
  };

  it("is accepted when it is valid", () => {
    expect(() => initGnapAuthMiddleware(passed)).not.toThrow();
  });

  it.each([
    ["a short secret", { secret: "x".repeat(31) }, "Session secrets must be at least 32 characters long"],
    ["a negative refresh interval", { refreshInterval: -1 }, "Invalid refresh interval or expiry"],
    ["a refresh interval that is no number", { refreshInterval: Number.NaN }, "Invalid refresh interval or expiry"],
    ["a session that lasts no time", { expires: 0 }, "Invalid refresh interval or expiry"],
    ["a session that outlasts the longest cookie", { expires: 34_560_001 }, "Session expiry must be at most"],
    ["a request timeout of zero", { requestTimeoutMs: 0 }, "Invalid request timeout"],
    ["an infinite request timeout", { requestTimeoutMs: Infinity }, "Invalid request timeout"],
    ["an external URL that is no URL", { externalUrl: "not a url" }, "The GNAP external URL is invalid"],
    ["a redirect URI that is neither path nor URL", { redirectUri: "callback" }, "The GNAP redirect URI is invalid"],
    ["an insecure redirect URI", { redirectUri: "http://app.test/callback" }, "must use HTTPS"],
    ["a redirect URI with a fragment", { redirectUri: `${APP}/callback#x` }, "no fragment"],
    ["a path below an insecure external URL", { externalUrl: "http://app.test/" }, "must use HTTPS"],
    ["a grant endpoint that is no URL", { grantEndpoint: "as" }, "The GNAP grant endpoint must be an http(s) URL"],
    ["a client that is no URL", { client: "alice" }, "The GNAP client must be the http(s) URL"],
    ["a key that is no PEM", { privateKey: "not a pem" }, "must be an unencrypted PKCS #8 PEM"],
    [
      "an encrypted PEM",
      { privateKey: "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----" },
      "PKCS #8 PEM",
    ],
    [
      "a JWK that is not Ed25519",
      { privateJwk: { kty: "OKP", crv: "X25519", x: "x", d: "d" } },
      "must be an Ed25519 key",
    ],
    [
      "a JWK without its private part",
      { privateJwk: { kty: "OKP", crv: "Ed25519", x: "x" } },
      "must be an Ed25519 key",
    ],
  ] as const)("is refused when it holds %s, before any request", (_name, override, message) => {
    expect(() => initGnapAuthMiddleware({ ...passed, ...override })).toThrow(message);
  });

  it("never quotes the key material in the error", () => {
    expect(() => initGnapAuthMiddleware({ ...passed, privateKey: "secret-key-material" })).toThrow(
      expect.objectContaining({ message: expect.not.stringContaining("secret-key-material") }),
    );
  });

  it("lets the environment provide what it leaves out, and checks that on the request", async () => {
    vi.stubEnv("GNAP_AUTH_SECRET", "short");

    const app = new Hono();

    // Nothing throws here: the secret is not in the config.
    app.use("*", initGnapAuthMiddleware({ grantEndpoint: BASE_URL, access: [outgoing] }));
    app.use("*", gnapAuthMiddleware());
    const response = await app.request(`${APP}/`);

    expect(response.status).toBe(500);
    expect(await response.text()).toBe("Session secrets must be at least 32 characters long");
  });
});

describe("configuration", () => {
  const request = (config: GnapAuthConfig, env: Record<string, string> = {}) => {
    for (const [name, value] of Object.entries(env)) vi.stubEnv(name, value);
    const app = new Hono();

    app.use("*", initGnapAuthMiddleware(config));
    app.use("*", gnapAuthMiddleware());

    return app.request(`${APP}/`);
  };

  const base: GnapAuthConfig = { grantEndpoint: BASE_URL, access: [outgoing] };
  const usable: GnapAuthConfig = { ...base, secret: SECRET };

  it.each([
    ["no secret", base, {}, "Session secret is not provided"],
    [
      "a short GNAP_AUTH_SECRET",
      base,
      { GNAP_AUTH_SECRET: "short" },
      "Session secrets must be at least 32 characters long",
    ],
    ["a negative refresh interval", usable, { GNAP_AUTH_REFRESH_INTERVAL: "-1" }, "Invalid refresh interval or expiry"],
    [
      "a refresh interval that is no number",
      usable,
      { GNAP_AUTH_REFRESH_INTERVAL: "soon" },
      "Invalid refresh interval",
    ],
    [
      "GNAP_AUTH_EXPIRES beyond the longest cookie",
      usable,
      { GNAP_AUTH_EXPIRES: "99999999" },
      "Session expiry must be at most",
    ],
    ["GNAP_AUTH_EXPIRES of zero", usable, { GNAP_AUTH_EXPIRES: "0" }, "Invalid refresh interval or expiry"],
    [
      "a GNAP_REDIRECT_URI that is not HTTPS",
      usable,
      { GNAP_REDIRECT_URI: "http://app.test/callback" },
      "The GNAP redirect URI must use HTTPS",
    ],
    [
      "a GNAP_GRANT_ENDPOINT that is no URL",
      { secret: SECRET, access: [outgoing] },
      { GNAP_GRANT_ENDPOINT: "not a url" },
      "grant endpoint must be",
    ],
    ["a GNAP_CLIENT that is no URL", usable, { GNAP_CLIENT: "alice" }, "The GNAP client must be"],
    [
      "GNAP_PRIVATE_KEY that is no PEM",
      usable,
      { GNAP_PRIVATE_KEY: "not a pem" },
      "must be an unencrypted PKCS #8 PEM",
    ],
    [
      "an external URL that is no URL",
      usable,
      { GNAP_AUTH_EXTERNAL_URL: "not a url" },
      "The GNAP external URL is invalid",
    ],
    [
      "a redirect URI that is neither path nor URL",
      usable,
      { GNAP_REDIRECT_URI: "callback" },
      "The GNAP redirect URI is invalid",
    ],
    [
      "GNAP_PRIVATE_JWK that is not JSON",
      usable,
      { GNAP_PRIVATE_JWK: "{not json" },
      "GNAP_PRIVATE_JWK is not valid JSON",
    ],
    ["GNAP_PRIVATE_JWK that is not an object", usable, { GNAP_PRIVATE_JWK: "[1]" }, "GNAP_PRIVATE_JWK must be a JWK"],
    ["no key", usable, { GNAP_KEY_ID: "k" }, "GNAP key id and private key are required"],
  ] as const)("answers 500 with a clear message for %s", async (_name, config, env, message) => {
    const response = await request(config, env);

    expect(response.status).toBe(500);
    expect(await response.text()).toContain(message);
  });

  it("answers 500 when the middleware is configured twice", async () => {
    const app = new Hono();

    app.use("*", initGnapAuthMiddleware(usable));
    app.use("*", initGnapAuthMiddleware(usable));
    app.use("*", gnapAuthMiddleware());
    const response = await app.request(`${APP}/`);

    expect(response.status).toBe(500);
    expect(await response.text()).toBe("GNAP auth is already configured");
  });

  it("does not quote a malformed GNAP_PRIVATE_JWK in its message", async () => {
    const response = await request(usable, { GNAP_PRIVATE_JWK: '{"d":"secret-key-material' });

    expect(await response.text()).not.toContain("secret-key-material");
  });

  it.each(["pem", "jwk"] as const)(
    "signs with the %s key of the config when both key variables hold something else",
    async (key) => {
      const stray = await createClientKey();

      // Signing with the variables' key would be refused by the server, or fail to import.
      vi.stubEnv("GNAP_PRIVATE_JWK", JSON.stringify((await exportPrivateKey(stray)).jwk));
      vi.stubEnv("GNAP_PRIVATE_KEY", "not a pem");
      const h = await createApp({}, { key });
      const response = await h.browser.get(`${APP}/`);

      expect(response.status).toBe(302);
      expect(response.headers.get("location")).toContain("/interact/");
    },
  );

  it("serves the callback it is mounted on directly", async () => {
    const h = await createApp(
      { redirectUri: "/auth/done" },
      { early: (app) => app.get("/auth/done", processGnapCallback) },
    );

    const { first, back } = await login(h);

    expect(first.status).toBe(302);
    expect(back.status).toBe(302);
    expect(back.headers.get("location")).toBe(`${APP}/`);
    expect((await h.browser.get(`${APP}/`)).status).toBe(200);
  });

  it("scopes the session cookie by the configured name, path and domain, and deletes it with the same scope", async () => {
    const h = await createApp(
      { cookieName: "sid", cookiePath: "/app", cookieDomain: "app.test" },
      {
        routes: (app) => {
          app.get("/app/page", (c) => c.text("page"));
          app.get("/other", (c) => c.text("other"));
          app.get("/app/logout", async (c) => {
            await revokeGnapSession(c);

            return c.text("bye");
          });
        },
      },
    );

    await login(h, `${APP}/app/page`);

    expect(h.browser.stored().find((cookie) => cookie.name === "sid")).toMatchObject({
      path: "/app",
      domain: "app.test",
      hostOnly: false,
    });

    expect(h.browser.cookies.has("sid-state")).toBe(false);
    expect((await h.browser.get(`${APP}/app/page`)).status).toBe(200);
    // Outside the cookie's path the browser sends nothing: no session.
    expect((await h.browser.get(`${APP}/other`)).status).toBe(302);

    expect((await h.browser.get(`${APP}/app/logout`)).status).toBe(200);
    expect(h.browser.cookies.has("sid")).toBe(false);
  });
});

describe("a deployment behind a reverse proxy", () => {
  const toInternal =
    (origin: string, prefix: string) =>
    (url: URL): string =>
      url.hostname === "public.example"
        ? `${origin}${url.pathname.replace(new RegExp(`^${prefix}`), "")}${url.search}`
        : url.toString();

  it("logs in below a path prefix: the state cookie is scoped to the public callback path", async () => {
    const h = await createApp(
      { externalUrl: "https://public.example/prefix" },
      { browser: { upstream: toInternal("https://internal.local:8080", "/prefix") } },
    );

    const first = await h.browser.get("https://public.example/prefix/?x=1");

    expect(first.status).toBe(302);
    expect(h.browser.stored().find((cookie) => cookie.name === "gnap-auth-state")?.path).toBe("/prefix/callback");

    const back = await h.browser.get(await h.consent(first.headers.get("location") ?? ""));

    expect(back.status).toBe(302);
    expect(back.headers.get("location")).toBe("https://public.example/prefix/?x=1");
    expect(h.browser.cookies.has("gnap-auth")).toBe(true);
    expect(h.browser.cookies.has("gnap-auth-state")).toBe(false);
    expect((await h.browser.get("https://public.example/prefix/")).status).toBe(200);
  });

  it("recognises the callback of an absolute redirect URI although the app sees another origin", async () => {
    const h = await createApp(
      { redirectUri: "https://public.example/auth/callback" },
      { browser: { upstream: toInternal("https://internal.local", "") } },
    );

    const first = await h.browser.get("https://public.example/");
    const back = await h.browser.get(await h.consent(first.headers.get("location") ?? ""));

    expect(back.status).toBe(302);
    expect(h.browser.cookies.has("gnap-auth")).toBe(true);
  });
});

describe("rotating the access token", () => {
  const rotation = (request: Request): boolean =>
    request.method === "POST" && new URL(request.url).pathname.includes("/token/");

  type Failure = "unavailable" | "overloaded" | "unreachable" | "silent";

  interface Flaky {
    failure: Failure | undefined;
  }

  const failing =
    (state: Flaky) =>
    (inner: typeof globalThis.fetch): typeof globalThis.fetch =>
    async (input, init) => {
      const request = new Request(input);

      if (!rotation(request) || state.failure === undefined) return inner(request);

      if (state.failure === "unavailable") return new Response("down", { status: 503 });

      if (state.failure === "overloaded") {
        return Response.json({ error: { code: "too_many_requests" } }, { status: 429 });
      }

      if (state.failure === "unreachable") throw new TypeError("network down");

      // Settles only when the middleware aborts the request.
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal?.reason));
      });
    };

  const withHook = (calls: Array<string>) => (app: Hono) => {
    app.use("*", async (c, next) => {
      c.set("gnapAuthRefreshErrorHook", (error) => {
        calls.push(String(error.status));
      });
      await next();
    });
  };

  it("keeps the session of the request that lost a race against another rotation", async () => {
    const hooked: Array<string> = [];
    const h = await createApp({}, { before: withHook(hooked) });

    await login(h);
    h.clock.advance(61);

    // Two requests with the same cookie, as a page with two API calls sends them after the tab was idle.
    const responses = await Promise.all([h.browser.get(`${APP}/`, XHR), h.browser.get(`${APP}/`, XHR)]);

    expect(responses.map((response) => response.status).sort((a, b) => a - b)).toEqual([200, 401]);

    for (const response of responses) expect(deletes(response, "gnap-auth")).toBe(false);

    expect(hooked).toEqual([]);
    expect(h.browser.cookies.has("gnap-auth")).toBe(true);

    const session: GnapAuth = await (await h.browser.get(`${APP}/`, XHR)).json();

    expect(await introspect(h, session.accessToken)).toMatchObject({ active: true });
  });

  it.each(["unavailable", "overloaded", "unreachable", "silent"] as const)(
    "keeps the session and the cookie when the server is %s, and rotates when it is back",
    async (failure) => {
      const state: Flaky = { failure: undefined };
      const hooked: Array<string> = [];
      const h = await createApp({ requestTimeoutMs: 20 }, { wrapFetch: failing(state), before: withHook(hooked) });

      await login(h);
      h.clock.advance(61);
      state.failure = failure;

      const api = await h.browser.get(`${APP}/`, XHR);

      expect(api.status).toBe(401);
      expect(deletes(api, "gnap-auth")).toBe(false);

      // A navigation is sent to log in again, without destroying the session it may still come back to.
      const page = await h.browser.get(`${APP}/`);

      expect(page.status).toBe(302);
      expect(deletes(page, "gnap-auth")).toBe(false);
      expect(h.browser.cookies.has("gnap-auth")).toBe(true);
      expect(hooked).toEqual([]);

      state.failure = undefined;
      const again = await h.browser.get(`${APP}/`, XHR);

      expect(again.status).toBe(200);
      expect(await again.json()).toMatchObject({ accessToken: expect.any(String) });
    },
  );
});

describe("logging out", () => {
  interface Seen {
    manage: string | undefined;
  }

  const logoutAfterLogin = (calls: Seen) => (app: Hono) => {
    app.get("/logout", async (c) => {
      calls.manage = (await getGnapAuth(c))?.manage?.uri;
      await revokeGnapSession(c);

      return c.text("bye");
    });
  };

  it("revokes the token rotated in the same request, not the one in the cookie the browser sent", async () => {
    const seen: Seen = { manage: undefined };
    const h = await createApp({}, { routes: logoutAfterLogin(seen) });

    await login(h);
    h.clock.advance(61);
    const out = await h.browser.get(`${APP}/logout`);

    expect(out.status).toBe(200);
    expect(seen.manage).toBeDefined();
    expect(h.calls).toContain(`DELETE ${new URL(seen.manage ?? "").pathname}`);
    expect(deletes(out, "gnap-auth")).toBe(true);
  });

  const answering =
    (fragment: string, status: number, code: string): NonNullable<Setup["wrapFetch"]> =>
    (inner) =>
    async (input) => {
      const request = new Request(input);

      return request.method === "DELETE" && new URL(request.url).pathname.includes(fragment)
        ? Response.json({ error: { code } }, { status })
        : inner(request);
    };

  it.each([
    ["a token the server forgot (404)", 200, "/token/", 404, "invalid_request"],
    ["a grant that was cancelled already (401 invalid_continuation)", 200, "/continue/", 401, "invalid_continuation"],
    ["a refused signature (401 invalid_client)", 500, "/token/", 401, "invalid_client"],
    ["a server that is down (503)", 500, "/continue/", 503, "internal_error"],
  ] as const)("when the server reports %s, logging out answers %d", async (_name, expected, fragment, status, code) => {
    const h = await createApp(
      {},
      { routes: logoutAfterLogin({ manage: undefined }), wrapFetch: answering(fragment, status, code) },
    );

    await login(h);
    const out = await h.browser.get(`${APP}/logout`);

    expect(out.status).toBe(expected);
    // Whatever the server said, the browser forgets the session.
    expect(deletes(out, "gnap-auth")).toBe(true);
  });

  it("revokes the access token before it cancels the grant, whatever the pace of the server", async () => {
    // The token's revocation is the slow one: sent together, the grant's would reach the server first.
    const slowToken: NonNullable<Setup["wrapFetch"]> = (inner) => async (input) => {
      const request = new Request(input);

      if (request.method === "DELETE" && new URL(request.url).pathname.includes("/token/")) {
        await new Promise((resolve) => setTimeout(resolve, 25));
      }

      return inner(request);
    };

    const h = await createApp({}, { routes: logoutAfterLogin({ manage: undefined }), wrapFetch: slowToken });

    await login(h);
    expect((await h.browser.get(`${APP}/logout`)).status).toBe(200);

    expect(h.calls.filter((call) => call.startsWith("DELETE"))).toEqual([
      expect.stringContaining("/token/"),
      expect.stringContaining("/continue/"),
    ]);
  });

  it("cancels the grant even when revoking the token failed, and reports the failure", async () => {
    const h = await createApp(
      {},
      { routes: logoutAfterLogin({ manage: undefined }), wrapFetch: answering("/token/", 503, "internal_error") },
    );

    await login(h);
    const out = await h.browser.get(`${APP}/logout`);

    expect(out.status).toBe(500);
    expect(h.calls.at(-1)).toMatch(/^DELETE .*\/continue\//);
    expect(deletes(out, "gnap-auth")).toBe(true);
  });
});

describe("a handler that returns an immutable response", () => {
  const routes = (app: Hono) => {
    app.get("/redirect", () => Response.redirect("https://elsewhere.test/", 302));
    app.get("/fetched", () => fetch("data:text/plain,hello"));
    app.get("/no-store", (c) => c.text("secret", 200, { "Cache-Control": "no-store" }));
  };

  it("still serves it, with the session created in the request and a Cache-Control", async () => {
    const h = await createApp({ access: [incoming] }, { routes });
    const response = await h.browser.get(`${APP}/redirect`);

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("https://elsewhere.test/");
    expect(response.headers.get("cache-control")).toBe("private, no-cache");
    expect(cookieLine(response, "gnap-auth")).toMatch(/^gnap-auth=[^;]+/);
  });

  it("copes with a fetched response as well", async () => {
    const h = await createApp({ access: [incoming] }, { routes });
    const response = await h.browser.get(`${APP}/fetched`);

    expect(response.status).toBe(200);
    expect(await response.text()).toBe("hello");
    expect(cookieLine(response, "gnap-auth")).toMatch(/^gnap-auth=[^;]+/);
  });

  it("keeps the Cache-Control of the handler", async () => {
    const h = await createApp({ access: [incoming] }, { routes });
    const response = await h.browser.get(`${APP}/no-store`);

    expect(response.headers.get("cache-control")).toBe("no-store");
  });
});

describe("the signing key", () => {
  /** How often an Ed25519 key is imported for signing: what the middleware does with its private key. */
  const countSigningKeyImports = (): (() => number) => {
    const spy = vi.spyOn(crypto.subtle, "importKey");
    const calls: ReadonlyArray<ReadonlyArray<unknown>> = spy.mock.calls;

    return () =>
      calls.filter(
        ([, , algorithm, , usages]) => JSON.stringify(algorithm).includes("Ed25519") && String(usages) === "sign",
      ).length;
  };

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it.each(["pem", "jwk"] as const)("is imported once for a login, a rotation and a logout (%s)", async (key) => {
    const imports = countSigningKeyImports();

    const h = await createApp(
      {},
      {
        key,
        routes: (app) =>
          app.get("/logout", async (c) => {
            await revokeGnapSession(c);

            return c.text("bye");
          }),
      },
    );

    await login(h);
    h.clock.advance(61);
    await h.browser.get(`${APP}/`);
    await h.browser.get(`${APP}/logout`);

    // The login signed twice (grant, continue), the visit rotated, the logout revoked.
    expect(h.calls.filter((call) => call.includes("/token/") || call.startsWith("DELETE"))).toHaveLength(3);
    expect(imports()).toBe(1);
  });

  it("is imported once from the environment, and again when the variable changes", async () => {
    const imports = countSigningKeyImports();
    const h = await createRafikiHarness();
    const stray = await createClientKey();

    vi.stubEnv("GNAP_AUTH_SECRET", SECRET);
    vi.stubEnv("GNAP_GRANT_ENDPOINT", BASE_URL);
    vi.stubEnv("GNAP_KEY_ID", KEY_ID);
    vi.stubEnv("GNAP_CLIENT", h.wallet);
    vi.stubEnv("GNAP_PRIVATE_JWK", JSON.stringify((await exportPrivateKey(h.clientKey)).jwk));

    const app = new Hono();

    app.use("*", initGnapAuthMiddleware({ access: [outgoing], fetch: h.fetch, clock: h.clock.now }));
    app.use("*", gnapAuthMiddleware());

    for (let visit = 0; visit < 3; visit += 1) {
      expect((await createBrowser(app).get(`${APP}/`)).status).toBe(302);
    }

    expect(imports()).toBe(1);

    // The server does not know this key: what counts is that the new text was imported.
    vi.stubEnv("GNAP_PRIVATE_JWK", JSON.stringify((await exportPrivateKey(stray)).jwk));
    await createBrowser(app).get(`${APP}/`);

    expect(imports()).toBe(2);
  });
});

describe("a second tab while a login is pending", () => {
  it("is sent to the interaction of the first tab instead of requesting another grant, and the login completes", async () => {
    const h = await createApp();
    const first = await h.browser.get(`${APP}/?tab=1`);
    const second = await h.browser.get(`${APP}/?tab=2`);

    expect(second.status).toBe(302);
    expect(second.headers.get("location")).toBe(first.headers.get("location"));
    expect(grantRequests(h)).toBe(1);

    const back = await h.browser.get(await h.consent(first.headers.get("location") ?? ""));

    expect(back.status).toBe(302);
    expect(back.headers.get("location")).toBe(`${APP}/?tab=1`);
    expect(h.browser.cookies.has("gnap-auth-state")).toBe(false);
    expect(h.browser.cookies.has("gnap-auth-pending")).toBe(false);
    expect((await h.browser.get(`${APP}/?tab=2`)).status).toBe(200);
  });

  it("does not outlive the interaction the server announced", async () => {
    const h = await createApp({}, { wrapFetch: expiringAfter(30) });
    const first = await h.browser.get(`${APP}/`);

    expect(attributesOf(cookieLine(first, "gnap-auth-state"))).toContain("max-age=30");
    expect(attributesOf(cookieLine(first, "gnap-auth-pending"))).toContain("max-age=30");

    h.clock.advance(31);
    await h.browser.get(`${APP}/`);

    expect(grantRequests(h)).toBe(2);
  });

  it.each([
    ["sealed with another secret", ({ foreign }: Pointers) => foreign],
    ["tampered with", ({ own }: Pointers) => tamper(own)],
    ["not a token", () => "garbage"],
  ])("starts a new grant, and does not follow it, for a pending cookie that is %s", async (_name, alter) => {
    const h = await createApp();
    const stranger = await createApp({ secret: OTHER_SECRET });
    const first = await h.browser.get(`${APP}/`);
    const foreignFirst = await stranger.browser.get(`${APP}/`);

    const pending = alter({
      own: h.browser.cookies.get("gnap-auth-pending") ?? "",
      foreign: stranger.browser.cookies.get("gnap-auth-pending") ?? "",
    });

    const response = await h.app.request(`${APP}/`, { headers: { cookie: `gnap-auth-pending=${pending}` } });
    const location = response.headers.get("location");

    expect(response.status).toBe(302);
    expect(location).toContain("/interact/");
    expect([first.headers.get("location"), foreignFirst.headers.get("location")]).not.toContain(location);
    expect(grantRequests(h)).toBe(2);
  });

  it("does not send a request that needs other access to the interaction of the first", async () => {
    const h = await createApp({
      access: (c) => [{ ...outgoing, actions: c.req.path === "/pay" ? ["read"] : ["create"] }],
    });

    const first = await h.browser.get(`${APP}/`);
    const second = await h.browser.get(`${APP}/pay`);
    const third = await h.browser.get(`${APP}/pay`);

    expect(second.headers.get("location")).not.toBe(first.headers.get("location"));
    expect(third.headers.get("location")).toBe(second.headers.get("location"));
    expect(grantRequests(h)).toBe(2);
  });

  it("forgets the pending interaction when the callback fails", async () => {
    const h = await createApp();

    await h.browser.get(`${APP}/`);
    expect(h.browser.cookies.has("gnap-auth-pending")).toBe(true);

    expect((await h.browser.get(`${APP}/callback?interact_ref=ref&hash=forged`)).status).toBe(401);
    expect(h.browser.cookies.has("gnap-auth-pending")).toBe(false);

    await h.browser.get(`${APP}/`);

    expect(grantRequests(h)).toBe(2);
  });

  it("asks for a grant again, without failing, when the interaction URL does not fit a cookie", async () => {
    const padded =
      (inner: typeof globalThis.fetch): typeof globalThis.fetch =>
      async (input, init) => {
        const response = await inner(input, init);
        const body = await response.clone().json();

        return body.interact === undefined
          ? response
          : Response.json(
              {
                ...body,
                interact: { ...body.interact, redirect: `${body.interact.redirect}?pad=${"a".repeat(5000)}` },
              },
              { status: response.status },
            );
      };

    const h = await createApp({}, { wrapFetch: padded });
    const first = await h.browser.get(`${APP}/`);

    expect(first.status).toBe(302);
    expect(h.browser.cookies.has("gnap-auth-state")).toBe(true);
    expect(h.browser.cookies.has("gnap-auth-pending")).toBe(false);

    await h.browser.get(`${APP}/`);

    expect(grantRequests(h)).toBe(2);
  });
});

/** The pending cookie of a deployment (`own`) and of another one (`foreign`). */
interface Pointers {
  readonly own: string;
  readonly foreign: string;
}

describe("the lifetime of a pending login (interact.expires_in)", () => {
  it.each([
    ["absent", undefined, 600],
    ["shorter than ten minutes", 30, 30],
    ["fractional", 30.7, 30],
    ["exactly ten minutes", 600, 600],
    ["longer than ten minutes", 86_400, 600],
  ] as const)("when it is %s, the login lives %d seconds", async (_name, expiresIn, lifetime) => {
    const h = await createApp({}, expiresIn === undefined ? {} : { wrapFetch: expiringAfter(expiresIn) });
    const first = await h.browser.get(`${APP}/`);

    expect(attributesOf(cookieLine(first, "gnap-auth-state"))).toContain(`max-age=${lifetime}`);
    expect(attributesOf(cookieLine(first, "gnap-auth-pending"))).toContain(`max-age=${lifetime}`);

    // A second tab is still sent to the same interaction at the very end of the lifetime, and gets a new grant after it.
    h.clock.advance(lifetime);
    expect((await h.browser.get(`${APP}/`)).headers.get("location")).toBe(first.headers.get("location"));
    expect(grantRequests(h)).toBe(1);

    h.clock.advance(1);
    await h.browser.get(`${APP}/`);

    expect(grantRequests(h)).toBe(2);
  });

  it.each([
    [24, 302],
    [25, 400],
  ] as const)(
    "accepts the callback until the announced 30 seconds are over (after %d more: %d)",
    async (more, status) => {
      const h = await createApp({}, { wrapFetch: expiringAfter(30) });
      const first = await h.browser.get(`${APP}/`);
      // The user's consent takes 6 seconds.
      const callback = await h.consent(first.headers.get("location") ?? "");

      h.clock.advance(more);

      expect((await h.browser.get(callback)).status).toBe(status);
    },
  );

  it.each([0, -5, 0.4])(
    "refuses an interaction that expires in %s seconds, before sending the user anywhere",
    async (seconds) => {
      const h = await createApp({}, { wrapFetch: expiringAfter(seconds) });
      const response = await h.browser.get(`${APP}/`);

      expect(response.status).toBe(502);
      expect(response.headers.get("location")).toBeNull();
      expect(response.headers.getSetCookie()).toEqual([]);
    },
  );
});
