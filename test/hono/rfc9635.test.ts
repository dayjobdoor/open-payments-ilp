import * as Effect from "effect/Effect";
import * as Result from "effect/Result";
import { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";
import { computeInteractionHash, type GrantRequestAccessItem } from "../../src/gnap/index";
import { verifyRequest } from "../../src/http-signatures/index";
import {
  getGnapAuth,
  gnapAuthMiddleware,
  initGnapAuthMiddleware,
  revokeGnapSession,
  type GnapAuth,
  type GnapAuthConfig,
} from "../../src/hono/index";
import { KEY_ID, createClientKey } from "../gnap-server/support";
import { APP, SECRET, createBrowser, exportPrivateKey, pump } from "./support";

const AS = "https://as.example";

const ENDPOINT = `${AS}/gnap`;

const REF = "ref-1";

const SERVER_NONCE = "server-nonce";

const access: ReadonlyArray<GrantRequestAccessItem> = [
  { type: "outgoing-payment", actions: ["read"], identifier: "https://w.example/a" },
];

interface Call {
  readonly method: string;
  readonly path: string;
  /** The authorisation server's clock (fake wall time, ms) when the request arrived. */
  readonly at: number;
  readonly authorization: string | null;
  readonly signatureInput: string | null;
  readonly contentDigest: string | null;
  readonly body:
    | {
        readonly client?: {
          readonly key?: { readonly proof?: string; readonly jwk?: JsonWebKey & { readonly kid?: string } };
        };
        readonly interact?: { readonly finish: { readonly uri: string; readonly nonce: string } };
        readonly interact_ref?: string;
      }
    | undefined;
}

interface AsOptions {
  /** `continue.wait` of the grant response; `undefined` omits it (RFC 9635 §3.1: five seconds). */
  readonly wait?: number | undefined;
  /** `wait` of each "not decided yet" continue answer handed out before the grant is approved. */
  readonly pending?: ReadonlyArray<number | undefined>;
  /** The resource owner's decision; a denial is reported as RFC 9635 §3.6 `user_denied` on the continue call. */
  readonly decision?: "approve" | "deny";
  /** How `user_denied` is spelled: `{error:{code}}` or `{error:"…"}` (both RFC 9635 §3.6). */
  readonly errorForm?: "object" | "string";
  /** `access_token` of the final answer: one object, an array (a violation: one token was requested), or bearer + key. */
  readonly tokenForm?: "object" | "array" | "bearer-with-key";
  /** Whether the access token has a `manage` object, and whether the final answer carries a `continue`. */
  readonly manage?: boolean;
  readonly finalContinue?: boolean;
  readonly expiresIn?: number;
  /** Extra characters on the access token, to make the session cookie large. */
  readonly tokenPadding?: number;
  /**
   * The grant response has no `interact.finish` (RFC 9635 §5.2: the client polls): `"redirect"` still offers an
   * interaction URL, `"none"` offers no interaction at all (approval out of band). The grant stays pending until the
   * test calls `decide` (or `decision` says otherwise).
   */
  readonly polling?: "redirect" | "none";
  /** `wait` of each "still pending" answer to a poll. Default 2. */
  readonly pollWait?: number;
  /** `interact.expires_in` of the grant response. */
  readonly interactExpiresIn?: number;
}

/**
 * A strict RFC 9635 authorisation server, nothing like Rafiki: continue tokens and URIs rotate on every answer, the
 * `wait` is enforced on its own (fake) clock, the finish hash is unpadded base64url, the access token has a `manage`
 * object with a distinct management token, and a denial reaches the client as `user_denied` on the continue call.
 * Everything the client does that RFC 9635 forbids is recorded in `violations` (and answered with an error): the key,
 * the HTTP message signature (§7.3.1: components, `created`, `tag`, no `alg`, a unique `nonce`, sha-256 digest), the
 * `Authorization: GNAP` header, stale tokens, an early continue (`too_fast`), an `interact_ref` sent twice or not
 * at all, and any continue request after the server stopped offering one.
 */
const createFakeAs = (options: AsOptions = {}) => {
  const { pending = [], errorForm = "object", tokenForm = "object", expiresIn = 600, polling, pollWait = 2 } = options;
  let decision: "approve" | "deny" | "pending" = options.decision ?? (polling === undefined ? "approve" : "pending");
  const calls: Array<Call> = [];
  const violations: Array<string> = [];
  const nonces = new Set<string>();
  const waits = options.wait;
  const queue = [...pending];
  let clientKey: JsonWebKey | undefined;
  let sequence = 0;
  let notBefore = 0;
  let refUsed = false;
  let continueOpen = true;

  /** A new continuation response; the previous token and URI stop working. */
  const issueContinue = (wait: number | undefined) => {
    sequence += 1;
    notBefore = Date.now() + (wait ?? 5) * 1000;

    return {
      uri: `${AS}/continue/${sequence}`,
      access_token: { value: `c${sequence}` },
      ...(wait !== undefined && { wait }),
    };
  };

  const finalAnswer = () => {
    const token = {
      value: `at1${"x".repeat(options.tokenPadding ?? 0)}`,
      expires_in: expiresIn,
      access,
      ...(options.manage !== false && { manage: { uri: `${AS}/token/m1`, access_token: { value: "mt1" } } }),
      ...(tokenForm === "bearer-with-key" && { flags: ["bearer"], key: "some-key-reference" }),
    };

    if (options.finalContinue === false) continueOpen = false;

    return {
      access_token: tokenForm === "array" ? [{ ...token, label: "t" }] : token,
      ...(options.finalContinue !== false && { continue: issueContinue(undefined) }),
    };
  };

  /** What RFC 9635 demands of every request a client instance makes. */
  const inspect = async (request: Request, verifying: Request, text: string): Promise<Array<string>> => {
    const problems: Array<string> = [];
    const authorization = request.headers.get("authorization");
    const input = request.headers.get("signature-input") ?? "";
    const body: Call["body"] = text === "" ? undefined : JSON.parse(text);
    const nonce = /;nonce="([^"]+)"/.exec(input)?.[1];
    const jwk = body?.client?.key?.jwk;

    if (jwk !== undefined) {
      clientKey = jwk;

      // §2.3, §7.1: an inline key is public, has `kid` and `alg`, and names its proofing method.
      if (
        jwk.d !== undefined ||
        jwk.kid === undefined ||
        jwk.alg === undefined ||
        body?.client?.key?.proof !== "httpsig"
      ) {
        problems.push("client.key is not a public httpsig JWK with kid and alg");
      }
    }

    if (authorization !== null && !/^GNAP [A-Za-z0-9\-._~+/]+=*$/.test(authorization)) {
      problems.push("Authorization is not the GNAP scheme");
    }

    if (text !== "" && request.headers.get("content-type") !== "application/json") problems.push("body is not JSON");

    if (text !== "" && request.headers.get("content-digest")?.startsWith("sha-256=") !== true) {
      problems.push("Content-Digest is not sha-256");
    }

    if (!input.includes(';tag="gnap"')) problems.push('signature has no tag="gnap"');

    if (/;alg=/.test(input)) problems.push("signature carries an explicit alg");

    if (nonce === undefined) problems.push("signature has no nonce");
    else if (nonces.has(nonce)) problems.push("signature nonce is reused");
    else nonces.add(nonce);

    const required = [
      "@method",
      "@target-uri",
      ...(text === "" ? [] : ["content-digest"]),
      ...(authorization === null ? [] : ["authorization"]),
    ];

    const verified = await Effect.runPromise(
      Effect.result(
        verifyRequest(verifying, {
          resolveKey: () => Effect.succeed(clientKey ?? {}),
          requiredComponents: required,
          maxAgeSeconds: 30,
          clock: () => new Date(),
          forbidAlg: true,
        }),
      ),
    );

    if (Result.isFailure(verified)) problems.push(`signature: ${verified.failure.message}`);

    return problems;
  };

  const fetch: typeof globalThis.fetch = async (input) => {
    const request = new Request(input);
    const verifying = request.clone();
    const text = await request.text();
    const path = new URL(request.url).pathname;
    const authorization = request.headers.get("authorization");
    const body: Call["body"] = text === "" ? undefined : JSON.parse(text);

    calls.push({
      method: request.method,
      path,
      at: Date.now(),
      authorization,
      signatureInput: request.headers.get("signature-input"),
      contentDigest: request.headers.get("content-digest"),
      body,
    });

    const refuse = (code: string, description: string, status = 400) => {
      violations.push(description);

      return Response.json({ error: { code, description } }, { status });
    };

    const problems = await inspect(request, verifying, text);

    if (problems.length > 0) return refuse("invalid_request", problems.join("; "));

    const route = `${request.method} ${path}`;
    const ok = (expected: string) => authorization === `GNAP ${expected}`;

    if (route === "POST /gnap") {
      const interact = body?.interact;
      const finish = interact?.finish;

      if (finish === undefined || !URL.canParse(finish.uri) || finish.uri.includes("#") || finish.nonce === "") {
        return refuse("invalid_request", "interact.finish needs an absolute uri without fragment and a nonce");
      }

      // A new grant is a new interaction, however many came before it.
      refUsed = false;
      continueOpen = true;

      return Response.json({
        ...(polling !== "none" && {
          interact: {
            redirect: `${AS}/interact/abc`,
            ...(polling === undefined && { finish: SERVER_NONCE }),
            ...(options.interactExpiresIn !== undefined && { expires_in: options.interactExpiresIn }),
          },
        }),
        continue: issueContinue(waits),
      });
    }

    if (route.startsWith("POST /continue/") || route.startsWith("DELETE /continue/")) {
      if (!continueOpen) return refuse("invalid_continuation", "no continuation was offered", 401);

      if (path !== `/continue/${sequence}` || !ok(`c${sequence}`)) {
        return refuse("invalid_continuation", "stale continuation URI or token", 401);
      }

      if (request.method === "DELETE") {
        // Already forgotten by the server: revocation must tolerate that.
        continueOpen = false;

        return new Response(null, { status: 404 });
      }

      if (Date.now() < notBefore) return refuse("too_fast", "continued before the announced wait was over");

      if (polling !== undefined) {
        // §5.2: a poll carries no message content.
        if (body !== undefined) return refuse("invalid_request", "a poll of a grant without finish carries no body");
      } else if (body?.interact_ref !== undefined) {
        if (refUsed) return refuse("too_many_attempts", "interact_ref was sent in a second request");
        refUsed = true;

        if (body.interact_ref !== REF) return refuse("invalid_interaction", "wrong interact_ref");
      } else if (!refUsed) {
        return refuse("invalid_continuation", "continued before the interaction finished");
      }

      if (decision === "deny") {
        // §3.6, §5.1: the error may carry the new continuation that lets the client modify its request.
        const error = errorForm === "string" ? "user_denied" : { code: "user_denied", description: "RO said no" };

        return Response.json({ error, continue: issueContinue(30) }, { status: 403 });
      }

      if (decision === "pending") return Response.json({ continue: issueContinue(pollWait) });

      if (queue.length === 0) return Response.json(finalAnswer());

      return Response.json({ continue: issueContinue(queue.shift()) });
    }

    if (route === "POST /token/m1" || route === "POST /token/m2") {
      const rotated = route.endsWith("m2");

      if (!ok(rotated ? "mt2" : "mt1") || text !== "") return refuse("invalid_rotation", "bad rotation request", 401);

      return Response.json({
        access_token: {
          value: "at2",
          expires_in: expiresIn,
          access,
          manage: { uri: `${AS}/token/m2`, access_token: { value: "mt2" } },
        },
      });
    }

    if (route === "DELETE /token/m2" && ok("mt2")) return new Response(null, { status: 204 });

    if (route === "DELETE /token/m1" && ok("mt1")) return new Response(null, { status: 204 });

    return refuse("invalid_request", `unexpected request ${route} with ${authorization}`, 404);
  };

  return {
    fetch,
    calls,
    violations,
    /** The resource owner decides, out of band, a grant that was pending. */
    decide: (next: "approve" | "deny"): void => {
      decision = next;
    },
  };
};

const createApp = async (
  options: AsOptions = {},
  config: Partial<Omit<GnapAuthConfig, "externalUrl">> & { externalUrl?: string | undefined } = {},
  /** Stands between the middleware and the authorisation server. */
  wrap: (inner: typeof globalThis.fetch) => typeof globalThis.fetch = (inner) => inner,
) => {
  const key = await createClientKey();
  const { jwk } = await exportPrivateKey(key);
  const as = createFakeAs(options);
  const app = new Hono();
  const { externalUrl, ...rest } = config;
  const pinned = "externalUrl" in config ? externalUrl : APP;

  app.use(
    "*",
    initGnapAuthMiddleware({
      secret: SECRET,
      ...(pinned !== undefined && { externalUrl: pinned }),
      grantEndpoint: ENDPOINT,
      access,
      keyId: KEY_ID,
      privateJwk: jwk,
      fetch: wrap(as.fetch),
      ...rest,
    }),
  );

  app.get("/logout", async (c) => {
    await revokeGnapSession(c);

    return c.text("bye");
  });

  app.use("*", gnapAuthMiddleware());
  app.get("/", async (c) => c.json(await getGnapAuth(c)));

  const browser = createBrowser(app);
  const visit = (url: string): Promise<Response> => pump(browser.get(url));

  /** The user follows `interact.redirect`, consents, and the authorisation server sends the browser back. */
  const callback = async (): Promise<string> => {
    // The newest grant request: a login may have started again.
    const finish = [...as.calls].reverse().find((call) => call.path === "/gnap")?.body?.interact?.finish;

    if (finish === undefined) throw new Error("no grant request was sent");

    const hash = await Effect.runPromise(
      computeInteractionHash({
        clientNonce: finish.nonce,
        serverNonce: SERVER_NONCE,
        interactRef: REF,
        grantEndpoint: ENDPOINT,
        encoding: "base64url",
      }),
    );

    return `${finish.uri}?interact_ref=${REF}&hash=${hash}`;
  };

  return { app, browser, visit, callback, as, key, jwk };
};

const seconds = (n: number): void => {
  vi.advanceTimersByTime(n * 1000);
};

const trace = (calls: ReadonlyArray<Call>): Array<string> =>
  calls.map((call) => `${call.method} ${call.path} ${call.authorization}`);

beforeEach(() => {
  // Authorisation server and middleware share the faked wall clock; only `pump` and `seconds` move it.
  vi.useFakeTimers({ toFake: ["setTimeout", "Date"] });
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllEnvs();
});

describe("RFC 9635 authorisation server", () => {
  it("logs in, rotates with the management token, and logs out, signing every request as §7.3.1 requires", async () => {
    const h = await createApp({ wait: 2, pending: [3] });
    const first = await h.visit(`${APP}/`);

    expect(first.status).toBe(302);
    expect(first.headers.get("location")).toBe(`${AS}/interact/abc`);

    // No wallet address: the grant request identifies the client by its inline public key.
    const grantCall = h.as.calls[0];

    expect(grantCall?.body).toMatchObject({
      access_token: { access },
      client: {
        key: { proof: "httpsig", jwk: { kty: "OKP", crv: "Ed25519", x: h.key.publicJwk.x, kid: KEY_ID, alg: "EdDSA" } },
      },
      interact: {
        start: ["redirect"],
        finish: { method: "redirect", uri: `${APP}/callback`, nonce: expect.any(String) },
      },
    });

    seconds(10);
    const back = await h.visit(await h.callback());

    expect(back.status).toBe(302);
    expect(back.headers.get("location")).toBe(`${APP}/`);

    // The first continue answered "pending, wait 3": the middleware waited, then used the rotated token c2, without
    // the one-time interact_ref.
    expect(trace(h.as.calls.slice(1))).toEqual(["POST /continue/1 GNAP c1", "POST /continue/2 GNAP c2"]);
    expect(h.as.calls[1]?.body).toEqual({ interact_ref: REF });
    expect(h.as.calls[2]?.body).toBeUndefined();
    expect((h.as.calls[2]?.at ?? 0) - (h.as.calls[1]?.at ?? 0)).toBeGreaterThanOrEqual(3000);

    const session: GnapAuth = await (await h.visit(`${APP}/`)).json();

    expect(session).toMatchObject({
      accessToken: "at1",
      access,
      manage: { uri: `${AS}/token/m1`, token: "mt1" },
      continue: { uri: `${AS}/continue/3`, token: "c3" },
    });

    // Rotation comes due before the 600s token expires (default interval 900s).
    seconds(571);
    const rotated: GnapAuth = await (await h.visit(`${APP}/`)).json();

    expect(rotated).toMatchObject({ accessToken: "at2", manage: { uri: `${AS}/token/m2`, token: "mt2" } });
    expect(rotated.ssnexp).toBe(session.ssnexp);

    // Logout: revoke with the newest management token, cancel the grant with the newest continue token; 404 is fine.
    const out = await h.visit(`${APP}/logout`);

    expect(out.status).toBe(200);
    expect(trace(h.as.calls.slice(-3))).toEqual([
      "POST /token/m1 GNAP mt1",
      "DELETE /token/m2 GNAP mt2",
      "DELETE /continue/3 GNAP c3",
    ]);
    expect([...h.browser.cookies.keys()]).toEqual([]);

    // The oracle checked components, tag, created, nonce, digest and key of every request.
    expect(h.as.violations).toEqual([]);
    expect(
      h.as.calls.every((call) =>
        /;created=\d+;keyid="alice-key-1";nonce="[^"]+";tag="gnap"$/.test(call.signatureInput ?? ""),
      ),
    ).toBe(true);
    expect(h.as.calls[0]?.signatureInput).toContain('("@method" "@target-uri" "content-digest"');
    expect(h.as.calls[0]?.contentDigest).toMatch(/^sha-256=:/);
    expect(h.as.calls[2]?.signatureInput).toContain('"authorization"');
  });

  it("waits five seconds, the RFC default, when the server announced no wait", async () => {
    const h = await createApp({ wait: undefined });

    await h.visit(`${APP}/`);
    seconds(1);
    const back = await h.visit(await h.callback());

    expect(back.status).toBe(302);
    // §3.1: omission of `wait` MUST be interpreted as five seconds, and the call must not come earlier.
    expect((h.as.calls[1]?.at ?? 0) - (h.as.calls[0]?.at ?? 0)).toBeGreaterThanOrEqual(5000);
    expect(h.as.violations).toEqual([]);
  });

  it("polls no earlier than five seconds after a pending answer that omits wait", async () => {
    const h = await createApp({ wait: 1, pending: [undefined] });

    await h.visit(`${APP}/`);
    seconds(10);
    expect((await h.visit(await h.callback())).status).toBe(302);
    expect(h.as.calls.map((call) => call.path)).toEqual(["/gnap", "/continue/1", "/continue/2"]);
    expect((h.as.calls[2]?.at ?? 0) - (h.as.calls[1]?.at ?? 0)).toBeGreaterThanOrEqual(5000);
    expect(h.as.violations).toEqual([]);
  });

  it("refuses to cut a long wait short: 504 without calling the server early", async () => {
    const h = await createApp({ wait: 60 });

    await h.visit(`${APP}/`);
    seconds(1);
    const back = await h.visit(await h.callback());

    expect(back.status).toBe(504);
    expect(await back.text()).toContain("wait");
    expect(h.as.calls.map((call) => call.path)).toEqual(["/gnap"]);
    expect([...h.browser.cookies.keys()]).toEqual([]);
  });

  it("continues at once when the user comes back after the whole wait", async () => {
    const h = await createApp({ wait: 60 });

    await h.visit(`${APP}/`);
    seconds(61);
    const back = await h.visit(await h.callback());

    expect(back.status).toBe(302);
    expect(h.as.calls.map((call) => call.path)).toEqual(["/gnap", "/continue/1"]);
    expect(h.as.violations).toEqual([]);
  });

  it("refuses to cut a long pending wait short", async () => {
    const h = await createApp({ wait: 1, pending: [60] });

    await h.visit(`${APP}/`);
    seconds(10);
    const back = await h.visit(await h.callback());

    expect(back.status).toBe(504);
    expect(h.as.calls.map((call) => call.path)).toEqual(["/gnap", "/continue/1"]);
    expect(h.as.violations).toEqual([]);
  });

  it.each(["object", "string"] as const)(
    "reports a denial (%s error) that arrives as user_denied on the continue call as 401",
    async (errorForm) => {
      const h = await createApp({ decision: "deny", errorForm });

      await h.visit(`${APP}/`);
      seconds(10);
      // §4.2: the AS still follows the finish method; the finish redirect of a denial carries hash and interact_ref.
      const response = await h.visit(await h.callback());

      expect(response.status).toBe(401);
      expect(await response.text()).toContain("user_denied");
      // The error's own continuation is not a reason to call again; no session was created.
      expect(h.as.calls.map((call) => call.path)).toEqual(["/gnap", "/continue/1"]);
      expect([...h.browser.cookies.keys()]).toEqual([]);
      expect(h.as.violations).toEqual([]);
    },
  );

  it("rejects an access_token array: one token was requested, §3.2.1 forbids the multiple-token structure", async () => {
    const h = await createApp({ tokenForm: "array" });

    await h.visit(`${APP}/`);
    seconds(10);
    const response = await h.visit(await h.callback());

    expect(response.status).toBe(502);
    expect([...h.browser.cookies.keys()]).toEqual([]);
  });

  it("rejects a bearer token that comes with a key (§3.2.1)", async () => {
    const h = await createApp({ tokenForm: "bearer-with-key" });

    await h.visit(`${APP}/`);
    seconds(10);
    const response = await h.visit(await h.callback());

    expect(response.status).toBe(502);
    expect(await response.text()).toContain("bearer");
    expect([...h.browser.cookies.keys()]).toEqual([]);
  });

  it("makes no further continuation request when the final answer offers none (§5)", async () => {
    const h = await createApp({ finalContinue: false });

    await h.visit(`${APP}/`);
    seconds(10);
    expect((await h.visit(await h.callback())).status).toBe(302);
    const session: GnapAuth = await (await h.visit(`${APP}/`)).json();

    expect(session.continue).toBeUndefined();
    expect((await h.visit(`${APP}/logout`)).status).toBe(200);
    expect(trace(h.as.calls.slice(-1))).toEqual(["DELETE /token/m1 GNAP mt1"]);
    expect(h.as.violations).toEqual([]);
  });

  it("does not use an access token past its expires_in (§3.2.1)", async () => {
    // No `manage`: the token cannot be rotated, so the session ends with it.
    const h = await createApp({ manage: false, expiresIn: 100 });

    await h.visit(`${APP}/`);
    seconds(10);
    await h.visit(await h.callback());

    seconds(89);
    expect((await h.visit(`${APP}/`)).status).toBe(200);

    seconds(12);
    const later = await h.visit(`${APP}/`);

    expect(later.status).toBe(302);
    expect(later.headers.get("location")).toBe(`${AS}/interact/abc`);
    expect(h.as.violations).toEqual([]);
  });

  it("does not send the interact_ref when the hash is wrong (§4.2.1)", async () => {
    const h = await createApp();

    await h.visit(`${APP}/`);
    seconds(10);
    const response = await h.visit((await h.callback()).replace(/hash=.*/, "hash=forged"));

    expect(response.status).toBe(401);
    expect(h.as.calls.map((call) => call.path)).toEqual(["/gnap"]);
  });

  it("is configured from the environment when no config is passed", async () => {
    const h = await createApp();
    const { jwk } = h;
    const app = new Hono();

    vi.stubEnv("GNAP_AUTH_SECRET", SECRET);
    vi.stubEnv("GNAP_GRANT_ENDPOINT", ENDPOINT);
    vi.stubEnv("GNAP_KEY_ID", "env-key");
    vi.stubEnv("GNAP_PRIVATE_JWK", JSON.stringify(jwk));
    vi.stubEnv("GNAP_REDIRECT_URI", "/back");
    vi.stubEnv("GNAP_AUTH_EXTERNAL_URL", APP);
    app.use("*", initGnapAuthMiddleware({ access, fetch: h.as.fetch }));
    app.use("*", gnapAuthMiddleware());

    const response = await app.request(`${APP}/page`);

    expect(response.status).toBe(302);
    expect(h.as.calls[0]?.body).toMatchObject({
      client: { key: { jwk: { kid: "env-key" } } },
      interact: { finish: { uri: `${APP}/back` } },
    });
  });
});

describe("front-channel URIs (RFC 9635 §2.5.2, §2.5.2.1, §4.1.1)", () => {
  it("refuses a callback URI that is not HTTPS or local to the browser, or has a fragment", async () => {
    const insecure = await createApp({}, { externalUrl: undefined });
    const local = await createApp({}, { externalUrl: undefined });

    // A fragment in a configured URI is refused when the middleware is created.
    await expect(createApp({}, { redirectUri: `${APP}/callback#x` })).rejects.toThrow("no fragment");
    expect((await insecure.visit("http://app.test/")).status).toBe(500);
    expect((await local.visit("http://localhost:3000/")).status).toBe(302);
    expect(insecure.as.calls).toHaveLength(0);
  });

  it("does not send the user to an interaction URI that is not HTTPS", async () => {
    const h = await createApp();

    const upgrade: typeof globalThis.fetch = async (input) => {
      const response = await h.as.fetch(input);
      const body = await response.json();

      return Response.json(
        body.interact === undefined
          ? body
          : { ...body, interact: { ...body.interact, redirect: "http://as.example/interact/abc" } },
        { status: response.status },
      );
    };

    const app = new Hono();

    app.use(
      "*",
      initGnapAuthMiddleware({
        secret: SECRET,
        externalUrl: APP,
        grantEndpoint: ENDPOINT,
        access,
        keyId: KEY_ID,
        privateJwk: h.jwk,
        fetch: upgrade,
      }),
    );

    app.use("*", gnapAuthMiddleware());
    const response = await pump(Promise.resolve(app.request(`${APP}/`)));

    expect(response.status).toBe(502);
    expect(response.headers.get("location")).toBeNull();
    expect(response.headers.getSetCookie()).toEqual([]);
  });
});

describe("when the authorisation server cannot be used to start a login", () => {
  const answering =
    (status: number): typeof globalThis.fetch =>
    async () =>
      Response.json({ error: { code: "request_denied" } }, { status });

  it.each([
    ["is overloaded", answering(429), 503],
    ["is down", answering(503), 503],
    ["cannot be reached", () => Promise.reject(new TypeError("network down")), 503],
    ["rejects the request", answering(400), 502],
  ] as const)("answers 502 or 503, never an uncaught error, when it %s", async (_name, unusable, status) => {
    const h = await createApp({}, { fetch: unusable });
    const response = await h.visit(`${APP}/`);

    expect(response.status).toBe(status);
    expect(response.headers.get("location")).toBeNull();
    expect(response.headers.getSetCookie()).toEqual([]);
  });

  it("gives up on a server that does not answer within requestTimeoutMs", async () => {
    // Settles only when the middleware aborts the request.
    const silent: typeof globalThis.fetch = (_input, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal?.reason));
      });

    const h = await createApp({}, { fetch: silent, requestTimeoutMs: 20 });
    const response = await h.visit(`${APP}/`);

    expect(response.status).toBe(503);
  });

  it("refuses an answer that is too large to be a GNAP response", async () => {
    const base = await createApp();

    const padded: typeof globalThis.fetch = async (input) => {
      const body = await (await base.as.fetch(input)).json();

      return Response.json({ ...body, padding: "x".repeat(100_000) });
    };

    const h = await createApp({}, { fetch: padded });
    const response = await h.visit(`${APP}/`);

    expect(response.status).toBe(502);
    expect(response.headers.get("location")).toBeNull();
  });

  it("starts a login only for a navigation of the browser: anything else is 401", async () => {
    const h = await createApp();

    for (const mode of ["cors", "same-origin", "no-cors"]) {
      const response = await pump(h.browser.get(`${APP}/`, { "Sec-Fetch-Mode": mode }));

      expect(response.status).toBe(401);
      expect(response.headers.get("location")).toBeNull();
    }

    for (const method of ["POST", "HEAD", "PUT"]) {
      const response = await pump(Promise.resolve(h.app.request(`${APP}/`, { method })));

      expect(response.status).toBe(401);
    }

    expect(h.as.calls).toEqual([]);
    expect(h.browser.cookies.size).toBe(0);
    expect((await h.visit(`${APP}/`)).status).toBe(302);
    expect((await pump(h.browser.get(`${APP}/`, { "Sec-Fetch-Mode": "navigate" }))).status).toBe(302);
  });

  it("measures the 4096 bytes of a cookie on the encrypted value: a session near the limit fits, a larger one does not", async () => {
    const near = await createApp({ tokenPadding: 2400 });

    await near.visit(`${APP}/`);
    seconds(10);
    expect((await near.visit(await near.callback())).status).toBe(302);
    const stored = `gnap-auth=${near.browser.cookies.get("gnap-auth")}`;

    expect(new TextEncoder().encode(stored).length).toBeGreaterThan(3500);
    expect(new TextEncoder().encode(stored).length).toBeLessThanOrEqual(4096);

    const over = await createApp({ tokenPadding: 3200 });

    await over.visit(`${APP}/`);
    seconds(10);

    expect((await over.visit(await over.callback())).status).toBe(500);
    expect(over.browser.cookies.has("gnap-auth")).toBe(false);
  });

  it("refuses to store a session that does not fit in a cookie, after the user consented", async () => {
    const h = await createApp({ tokenPadding: 4000 });

    await h.visit(`${APP}/`);
    seconds(10);
    const response = await h.visit(await h.callback());

    expect(response.status).toBe(500);
    expect(response.headers.getSetCookie().some((line) => line.startsWith("gnap-auth="))).toBe(false);
    expect(h.browser.cookies.has("gnap-auth")).toBe(false);
  });
});

describe("a grant the server does not finish with a callback (RFC 9635 §5.2, polling)", () => {
  const XHR = { "Sec-Fetch-Mode": "cors" };

  /** The first poll never reaches the authorisation server: the middleware gets `answer` instead. */
  const failingFirstPoll =
    (answer: () => Response) =>
    (inner: typeof globalThis.fetch): typeof globalThis.fetch => {
      let failed = false;

      return async (input) => {
        const request = new Request(input);

        if (!failed && new URL(request.url).pathname.startsWith("/continue/")) {
          failed = true;

          return answer();
        }

        return inner(request);
      };
    };

  /** The grant response has 5000 characters too many in its interaction URL, or in its continue token. */
  const padded =
    (where: "redirect" | "token") =>
    (inner: typeof globalThis.fetch): typeof globalThis.fetch =>
    async (input) => {
      const request = new Request(input);
      const response = await inner(request);

      if (new URL(request.url).pathname !== "/gnap") return response;
      const body = await response.json();

      if (where === "redirect") body.interact.redirect += `?pad=${"a".repeat(5000)}`;
      else body.continue.access_token.value += "x".repeat(5000);

      return Response.json(body, { status: response.status });
    };

  it("sends the user to the interaction, polls no earlier than the wait, and lets the user in once approved", async () => {
    const h = await createApp({ polling: "redirect", wait: 5, pollWait: 3 });
    const first = await h.visit(`${APP}/`);

    expect(first.status).toBe(302);
    expect(first.headers.get("location")).toBe(`${AS}/interact/abc`);
    // The request asked for a finish: the server offered none, so no callback follows. Only the pointer is kept.
    expect(h.as.calls[0]?.body?.interact?.finish).toBeDefined();
    expect([...h.browser.cookies.keys()]).toEqual(["gnap-auth-pending"]);

    // Back inside the server's wait: sent to the interaction again, the server is not called.
    seconds(2);
    const early = await h.visit(`${APP}/`);

    expect(early.status).toBe(302);
    expect(early.headers.get("location")).toBe(`${AS}/interact/abc`);
    expect(h.as.calls.map((call) => call.path)).toEqual(["/gnap"]);

    // After the wait, not approved yet: one poll, without body and with the continuation token, and the user is sent
    // to the interaction once more.
    seconds(5);
    const waiting = await h.visit(`${APP}/`);

    expect(waiting.status).toBe(302);
    expect(waiting.headers.get("location")).toBe(`${AS}/interact/abc`);
    expect(trace(h.as.calls.slice(1))).toEqual(["POST /continue/1 GNAP c1"]);
    expect(h.as.calls[1]?.body).toBeUndefined();

    // Only a navigation of the browser polls: a script's request is refused without calling the server.
    seconds(5);
    expect((await pump(h.browser.get(`${APP}/`, XHR))).status).toBe(401);
    expect(h.as.calls).toHaveLength(2);

    // The owner approves, out of band. The next poll (with the newest continuation token) brings the token, and the
    // request goes on to the handler.
    h.as.decide("approve");
    const done = await h.visit(`${APP}/`);

    expect(done.status).toBe(200);
    expect(await done.json()).toMatchObject({
      accessToken: "at1",
      manage: { uri: `${AS}/token/m1`, token: "mt1" },
      continue: { uri: `${AS}/continue/3`, token: "c3" },
    });

    expect(trace(h.as.calls.slice(2))).toEqual(["POST /continue/2 GNAP c2"]);
    expect([...h.browser.cookies.keys()]).toEqual(["gnap-auth"]);
    expect(h.as.violations).toEqual([]);

    // The session works like any other: it stays after the next navigation, and logging out cancels the grant.
    expect((await h.visit(`${APP}/`)).status).toBe(200);
    expect((await h.visit(`${APP}/logout`)).status).toBe(200);
    expect(trace(h.as.calls.slice(-2))).toEqual(["DELETE /token/m1 GNAP mt1", "DELETE /continue/3 GNAP c3"]);
  });

  it.each(["object", "string"] as const)(
    "reports a denial (%s error) as 401 like the callback does, forgets the grant, and asks for a new one next time",
    async (errorForm) => {
      const h = await createApp({ polling: "redirect", decision: "deny", errorForm });

      await h.visit(`${APP}/`);
      seconds(6);
      const denied = await h.visit(`${APP}/`);

      expect(denied.status).toBe(401);
      expect(await denied.text()).toContain("user_denied");
      expect(h.browser.cookies.has("gnap-auth-pending")).toBe(false);
      expect(h.as.calls.map((call) => call.path)).toEqual(["/gnap", "/continue/1"]);

      // The error's own continuation is not used, and the denial is not a reason to ask again by itself.
      const again = await h.visit(`${APP}/`);

      expect(again.status).toBe(302);
      expect(h.as.calls.map((call) => call.path)).toEqual(["/gnap", "/continue/1", "/gnap"]);
      expect(h.as.violations).toEqual([]);
    },
  );

  it("answers 202 with Retry-After while the server offers no interaction at all, and lets the user in once approved", async () => {
    const h = await createApp({ polling: "none", wait: 5, pollWait: 2 });
    const first = await h.visit(`${APP}/`);

    expect(first.status).toBe(202);
    expect(first.headers.get("location")).toBeNull();
    expect(first.headers.get("retry-after")).toBe("5");
    expect(first.headers.get("cache-control")).toBe("no-store");
    expect(await first.text()).toContain("pending");

    // The wait that remains is announced, and the server is not called before it is over.
    seconds(2);
    const early = await h.visit(`${APP}/`);

    expect(early.status).toBe(202);
    expect(Number(early.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
    expect(Number(early.headers.get("retry-after"))).toBeLessThanOrEqual(5);
    expect(h.as.calls.map((call) => call.path)).toEqual(["/gnap"]);

    seconds(5);
    const polled = await h.visit(`${APP}/`);

    expect(polled.status).toBe(202);
    expect(polled.headers.get("retry-after")).toBe("2");
    expect(h.as.calls.map((call) => call.path)).toEqual(["/gnap", "/continue/1"]);

    h.as.decide("approve");
    seconds(3);

    expect((await h.visit(`${APP}/`)).status).toBe(200);
    expect(h.as.violations).toEqual([]);
  });

  it.each([
    ["is unavailable (503)", () => new Response("down", { status: 503 }), 503],
    ["is overloaded (429)", () => Response.json({ error: { code: "too_many_requests" } }, { status: 429 }), 503],
    ["fails (500)", () => new Response("oops", { status: 500 }), 502],
    ["says too_fast", () => Response.json({ error: { code: "too_fast" } }, { status: 400 }), 302],
  ] as const)("keeps the grant for the next navigation when the server %s", async (_name, answer, status) => {
    const h = await createApp({ polling: "redirect" }, {}, failingFirstPoll(answer));

    await h.visit(`${APP}/`);
    seconds(6);
    const failed = await h.visit(`${APP}/`);

    expect(failed.status).toBe(status);
    expect(h.browser.cookies.has("gnap-auth-pending")).toBe(true);
    expect(h.as.calls.map((call) => call.path)).toEqual(["/gnap"]);

    // The server is back: the same continuation is polled, no new grant is requested.
    h.as.decide("approve");

    expect((await h.visit(`${APP}/`)).status).toBe(200);
    expect(h.as.calls.map((call) => call.path)).toEqual(["/gnap", "/continue/1"]);
  });

  it.each([
    ["a continuation it does not accept (401 invalid_continuation)", 401, "invalid_continuation"],
    ["a grant it does not know (404)", 404, "unknown_request"],
  ] as const)("asks for a new grant, at once, when the server answers %s", async (_name, status, code) => {
    const answer = () => Response.json({ error: { code } }, { status });
    const h = await createApp({ polling: "redirect" }, {}, failingFirstPoll(answer));

    await h.visit(`${APP}/`);
    seconds(6);
    const again = await h.visit(`${APP}/`);

    expect(again.status).toBe(302);
    expect(again.headers.get("location")).toBe(`${AS}/interact/abc`);
    expect(h.as.calls.map((call) => call.path)).toEqual(["/gnap", "/gnap"]);

    // The new grant is the one that is polled from now on.
    seconds(6);
    h.as.decide("approve");

    expect((await h.visit(`${APP}/`)).status).toBe(200);
    expect(h.as.calls.map((call) => call.path)).toEqual(["/gnap", "/gnap", "/continue/2"]);
  });

  it("does not poll a grant past interact.expires_in, nor one that was requested for other access", async () => {
    const h = await createApp(
      { polling: "redirect", interactExpiresIn: 30 },
      {
        access: (c) => [
          {
            type: "outgoing-payment",
            actions: [c.req.path === "/pay" ? "read" : "create"],
            identifier: "https://w.example/a",
          },
        ],
      },
    );

    const first = await h.visit(`${APP}/`);
    const cookie = h.browser.cookies.get("gnap-auth-pending") ?? "";

    expect(first.headers.getSetCookie().join()).toContain("Max-Age=30");

    // Other access: a grant of its own, not a poll of the first.
    seconds(6);
    await h.visit(`${APP}/pay`);
    expect(h.as.calls.map((call) => call.path)).toEqual(["/gnap", "/gnap"]);

    // The first grant's pointer, sent after its 30 seconds: a new grant, the server is not asked about the old one.
    seconds(30);
    await pump(Promise.resolve(h.app.request(`${APP}/`, { headers: { cookie: `gnap-auth-pending=${cookie}` } })));

    expect(h.as.calls.map((call) => call.path)).toEqual(["/gnap", "/gnap", "/gnap"]);
  });

  it("keeps polling a grant whose interaction URL is too long for a cookie, and says it is pending", async () => {
    const h = await createApp({ polling: "redirect" }, {}, padded("redirect"));
    const first = await h.visit(`${APP}/`);

    expect(first.status).toBe(302);
    expect(first.headers.get("location")).toContain("?pad=");
    expect(h.browser.cookies.has("gnap-auth-pending")).toBe(true);

    // The interaction URL is not remembered: later navigations get 202 until the grant is approved.
    seconds(6);
    expect((await h.visit(`${APP}/`)).status).toBe(202);
    h.as.decide("approve");
    seconds(3);

    expect((await h.visit(`${APP}/`)).status).toBe(200);
  });

  it("refuses a pending grant that cannot be stored at all, instead of leaving the user without a way back", async () => {
    const h = await createApp({ polling: "redirect" }, {}, padded("token"));
    const response = await h.visit(`${APP}/`);

    expect(response.status).toBe(500);
    expect(response.headers.get("location")).toBeNull();
    expect(h.browser.cookies.size).toBe(0);
  });
});

describe("swapping the signing key of a server that binds the grant to its inline key", () => {
  it("logs the user in again at the next token rotation, with the new key", async () => {
    const h = await createApp({ wait: 1 });
    const next = await createClientKey("alice-key-2");
    const { jwk } = await exportPrivateKey(next);
    const swapped = new Hono();

    // The same secret and cookies, another key: the redeployed service.
    swapped.use(
      "*",
      initGnapAuthMiddleware({
        secret: SECRET,
        externalUrl: APP,
        grantEndpoint: ENDPOINT,
        access,
        keyId: "alice-key-2",
        privateJwk: jwk,
        fetch: h.as.fetch,
      }),
    );

    swapped.use("*", gnapAuthMiddleware());
    swapped.get("/", async (c) => c.json(await getGnapAuth(c)));

    let live = h.app;
    const gateway = new Hono().all("*", (c) => live.fetch(c.req.raw));
    const browser = createBrowser(gateway);
    const visit = (url: string): Promise<Response> => pump(browser.get(url));

    await visit(`${APP}/`);
    seconds(10);
    await visit(await h.callback());
    expect((await visit(`${APP}/`)).status).toBe(200);

    live = swapped;
    seconds(571);

    // The server bound the grant to the first key and refuses the second one on the token: the session is over,
    // and the user is sent to log in with the new key.
    const refused = await visit(`${APP}/`);

    expect(refused.status).toBe(302);
    expect(refused.headers.get("location")).toBe(`${AS}/interact/abc`);
    expect(h.as.violations).toHaveLength(1);
    expect(h.as.calls.at(-1)?.body?.client?.key?.jwk?.kid).toBe("alice-key-2");

    seconds(10);
    expect((await visit(await h.callback())).status).toBe(302);
    const session: GnapAuth = await (await visit(`${APP}/`)).json();

    expect(session.accessToken).toBe("at1");
    expect(h.as.violations).toHaveLength(1);
  });
});
