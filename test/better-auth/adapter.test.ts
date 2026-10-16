/**
 * What the adapter adds to the core: the two-table schema, the Better Auth session as the consent principal, the
 * rate limits and `auth.api.gnapIntrospect`. The protocol itself is the core's (see test/gnap-server).
 */
import { createAuthClient } from "better-auth/client";
import * as Cause from "effect/Cause";
import * as Effect from "effect/Effect";
import { describe, expect, it } from "vite-plus/test";
import { gnapClient } from "../../src/better-auth/client";
import { gnapSchema } from "../../src/better-auth/index";
import { computeInteractionHash } from "../../src/gnap/index";
import { signRequest } from "../../src/http-signatures/index";
import {
  FINISH_URI,
  WALLET,
  errorOf,
  grantBody,
  incoming,
  interact,
  json,
  jsonBody,
  outgoing,
  withHeaders,
  withToken,
  type Pending,
} from "../gnap-server/support";
import { createHarness, type Harness } from "./support";

/** A pending interactive grant, started through the Better Auth handler. */
const startGrant = async (h: Harness, request = grantBody([outgoing], { interact })): Promise<Pending> => {
  const response = await h.signedCall(h.grantUrl, json("POST", request));

  const pending = await jsonBody<{
    interact: { redirect: string; finish: string };
    continue: { access_token: { value: string }; uri: string };
  }>(response);

  const [interactId = "", nonce = ""] = new URL(pending.interact.redirect).pathname.split("/").slice(-2);

  return {
    interactUrl: pending.interact.redirect,
    interactId,
    nonce,
    continueUri: pending.continue.uri,
    continueToken: pending.continue.access_token.value,
  };
};

const consentPath = (pending: Pending, suffix = ""): string =>
  `/gnap/interaction/${pending.interactId}/${pending.nonce}${suffix}`;

describe("schema", () => {
  it("is exactly three tables", () => {
    expect(Object.keys(gnapSchema)).toEqual(["gnapGrant", "gnapAccessToken", "gnapNonce"]);
  });

  it("has the unique lookups and indexes the server relies on", () => {
    const field = (model: string, name: string) => gnapSchema[model]?.fields[name];

    expect(field("gnapGrant", "continueId")?.unique).toBe(true);
    expect(field("gnapGrant", "interactId")?.unique).toBe(true);
    expect(field("gnapAccessToken", "valueHash")?.unique).toBe(true);
    expect(field("gnapAccessToken", "managementId")?.unique).toBe(true);
    expect(field("gnapAccessToken", "grantId")?.index).toBe(true);
  });

  it("stores the grant and its tokens as the two records, with hashes only", async () => {
    const h = await createHarness();
    const response = await h.signedCall(h.grantUrl, json("POST", grantBody([incoming])));

    const grant = await jsonBody<{ access_token: { value: string }; continue: { access_token: { value: string } } }>(
      response,
    );

    expect(h.db["gnapGrant"]).toHaveLength(1);
    expect(h.db["gnapAccessToken"]).toHaveLength(1);
    expect(JSON.stringify(h.db)).not.toContain(grant.access_token.value);
    expect(JSON.stringify(h.db)).not.toContain(grant.continue.access_token.value);
  });
});

/** The browser following `interact.redirect`: the session cookie the server binds it with. */
const browserCookie = async (h: Awaited<ReturnType<typeof createHarness>>, interactUrl: string): Promise<string> => {
  const response = await h.call(new Request(interactUrl, { redirect: "manual" }));

  return (response.headers.get("set-cookie") ?? "").split(";")[0] ?? "";
};

describe("consent by the signed-in user", () => {
  it("shows the interaction, records the user and answers the client's finish redirect", async () => {
    const h = await createHarness({ finishHashEncoding: "base64url" });
    const pending = await startGrant(h);

    const consent = await h.call(new Request(pending.interactUrl, { redirect: "manual" }));
    const cookie = (consent.headers.get("set-cookie") ?? "").split(";")[0] ?? "";
    const consentUrl = new URL(consent.headers.get("location") ?? "");

    expect(consentUrl.searchParams.get("interactId")).toBe(pending.interactId);
    expect(consentUrl.searchParams.get("nonce")).toBe(pending.nonce);

    const details = await h.asUser(consentPath(pending));

    expect(await details.json()).toEqual({
      grantId: expect.any(String),
      client: WALLET,
      access: [outgoing],
      state: "PENDING",
      finish: true,
      expiresAt: expect.any(String),
    });

    const accepted = await h.asUser(consentPath(pending, "/accept"), { method: "POST" });
    const { redirect } = await jsonBody<{ redirect: string }>(accepted);

    // The consent API answers where the browser goes next: `/finish`, which is what approves the grant.
    expect(accepted.status).toBe(200);
    expect(redirect).toBe(`${h.grantUrl}/interact/${pending.interactId}/${pending.nonce}/finish`);

    // SAFETY: the `gnapGrant` rows of the memory adapter are the `GrantRecord`-shaped rows the store wrote.
    const rows = h.db["gnapGrant"] as Array<{ state: string; userId: string }>;

    expect(rows[0]).toMatchObject({ state: "ACCEPTED", userId: await h.userId() });

    const finished = await h.call(new Request(redirect, { redirect: "manual", headers: { cookie } }));
    const finish = new URL(finished.headers.get("location") ?? "");

    expect(`${finish.origin}${finish.pathname}`).toBe(FINISH_URI);
    expect(rows[0]?.state).toBe("APPROVED");

    expect(finish.searchParams.get("hash")).toBe(
      await Effect.runPromise(
        computeInteractionHash({
          clientNonce: "client-nonce",
          serverNonce: pending.nonce,
          interactRef: finish.searchParams.get("interact_ref") ?? "",
          grantEndpoint: h.grantUrl,
          encoding: "base64url",
        }),
      ),
    );

    h.clock.advance(6);
    const ref = finish.searchParams.get("interact_ref") ?? "";

    const granted = await h.signedCall(
      pending.continueUri,
      withToken(json("POST", { interact_ref: ref }), pending.continueToken),
    );

    expect(granted.status).toBe(200);
  });

  it("rejects: the finish step redirects the client with grant_rejected", async () => {
    const h = await createHarness();
    const pending = await startGrant(h);
    const cookie = await browserCookie(h, pending.interactUrl);
    const rejected = await h.asUser(consentPath(pending, "/reject"), { method: "POST" });
    const { redirect } = await jsonBody<{ redirect: string }>(rejected);
    const finished = await h.call(new Request(redirect, { redirect: "manual", headers: { cookie } }));

    expect(new URL(finished.headers.get("location") ?? "").searchParams.get("result")).toBe("grant_rejected");
  });

  it("answers the finish URL for a client that polls too: finishing answers 202", async () => {
    const h = await createHarness();

    const response = await h.signedCall(
      h.grantUrl,
      json("POST", grantBody([outgoing], { interact: { start: ["redirect"] } })),
    );

    const pending = await jsonBody<{ interact: { redirect: string } }>(response);
    const [interactId = "", nonce = ""] = new URL(pending.interact.redirect).pathname.split("/").slice(-2);
    const cookie = await browserCookie(h, pending.interact.redirect);
    const accepted = await h.asUser(`/gnap/interaction/${interactId}/${nonce}/accept`, { method: "POST" });
    const { redirect } = await jsonBody<{ redirect: string }>(accepted);

    expect((await h.call(new Request(redirect, { redirect: "manual", headers: { cookie } }))).status).toBe(202);
  });

  it("needs a signed-in user", async () => {
    const h = await createHarness();
    const pending = await startGrant(h);

    expect((await h.auth.handler(new Request(`${h.baseURL}/api/auth${consentPath(pending)}`))).status).toBe(401);

    const anonymous = await h.auth.handler(
      new Request(`${h.baseURL}/api/auth${consentPath(pending, "/accept")}`, {
        method: "POST",
        headers: { origin: h.baseURL },
      }),
    );

    expect(anonymous.status).toBe(401);
  });

  it("needs the nonce: the interactId alone decides nothing", async () => {
    const h = await createHarness();
    const pending = await startGrant(h);
    const forged = await h.asUser(`/gnap/interaction/${pending.interactId}/wrong/accept`, { method: "POST" });

    expect(forged.status).toBe(404);
    expect(await forged.json()).toMatchObject({ code: "unknown_interaction" });
  });

  it("refuses a cross-site consent POST that carries the session cookie", async () => {
    const h = await createHarness();
    const pending = await startGrant(h);

    const forged = await h.auth.handler(
      new Request(`${h.baseURL}/api/auth${consentPath(pending, "/accept")}`, {
        method: "POST",
        headers: { cookie: h.cookie, origin: "https://evil.test" },
      }),
    );

    expect(forged.status).toBe(403);

    // Still undecided: the legitimate page can accept afterwards.
    expect((await h.asUser(consentPath(pending, "/accept"), { method: "POST" })).status).toBe(200);
  });

  it("can be decided only once, and expires", async () => {
    const h = await createHarness({ interaction: { consentUrl: "https://app.test/consent", expiresInSeconds: 30 } });
    const decided = await startGrant(h);

    await h.asUser(consentPath(decided, "/accept"), { method: "POST" });

    const again = await h.asUser(consentPath(decided, "/reject"), { method: "POST" });

    expect(again.status).toBe(400);
    expect(await again.json()).toMatchObject({ code: "invalid_interaction" });

    const late = await startGrant(h);

    h.clock.advance(31);

    const expired = await h.asUser(consentPath(late, "/accept"), { method: "POST" });

    expect(expired.status).toBe(400);
    expect(await expired.json()).toMatchObject({ code: "invalid_interaction" });
  });

  it("asks `interaction.authorize` before accepting", async () => {
    const asked: Array<{ userId: string; client: string }> = [];

    const h = await createHarness({
      interaction: {
        consentUrl: "https://app.test/consent",
        authorize: ({ userId, details }) => {
          asked.push({ userId, client: details.client });

          return Effect.succeed(false);
        },
      },
    });

    const pending = await startGrant(h);
    const forbidden = await h.asUser(consentPath(pending, "/accept"), { method: "POST" });

    expect(forbidden.status).toBe(403);
    expect(await forbidden.json()).toMatchObject({ code: "request_denied" });
    expect(asked).toEqual([{ userId: await h.userId(), client: WALLET }]);
  });

  describe("with the README's authorize hook, which checks access identifiers and subject ids", () => {
    // The README example, with `owns` answering for the wallet address of the harness client.
    const owns = (_userId: string, address?: string): boolean => address === WALLET;

    const authorize: NonNullable<NonNullable<Parameters<typeof createHarness>[0]>["interaction"]>["authorize"] = ({
      userId,
      details,
    }) => {
      const named = [
        ...details.access.map((item) => ("identifier" in item ? item.identifier : undefined)),
        ...(details.subject?.sub_ids.map((subId) => subId.id) ?? []),
      ];

      return Effect.succeed(named.length > 0 && named.every((address) => owns(userId, address)));
    };

    const subjectGrant = (id: string) => grantBody([], { subject: { sub_ids: [{ id, format: "uri" }] }, interact });

    const decide = async (request: ReturnType<typeof grantBody>) => {
      const h = await createHarness({ interaction: { consentUrl: "https://app.test/consent", authorize } });
      const pending = await startGrant(h, request);

      return (await h.asUser(consentPath(pending, "/accept"), { method: "POST" })).status;
    };

    it("refuses a subject-only grant that names another user's wallet address", async () => {
      expect(await decide(subjectGrant("https://wallet.test/mallory"))).toBe(403);
    });

    it("accepts a subject-only grant for the owner's own wallet address", async () => {
      expect(await decide(subjectGrant(WALLET))).toBe(200);
    });

    it("still decides access grants by their identifiers", async () => {
      expect(await decide(grantBody([outgoing], { interact }))).toBe(200);
      expect(await decide(grantBody([{ ...outgoing, identifier: "https://wallet.test/mallory" }], { interact }))).toBe(
        403,
      );
    });
  });

  it("refuses a signed-in user's decision while no authorize hook is configured", async () => {
    const h = await createHarness({ withoutConsentHook: true });
    const pending = await startGrant(h);

    const forbidden = await h.asUser(consentPath(pending, "/accept"), { method: "POST" });

    expect(forbidden.status).toBe(403);
    expect(await forbidden.json()).toMatchObject({ code: "request_denied" });
  });

  it("is also decidable through the identity provider back channel", async () => {
    const h = await createHarness();
    const pending = await startGrant(h);

    const accepted = await h.call(
      new Request(`${h.grantUrl}/grant/${pending.interactId}/${pending.nonce}/accept`, {
        method: "POST",
        headers: { "x-idp-secret": "idp-secret" },
      }),
    );

    expect(accepted.status).toBe(202);
  });
});

describe("introspection", () => {
  it("`auth.api.gnapIntrospect` answers inactive for unknown tokens and active for issued ones", async () => {
    const h = await createHarness();

    const issued = await jsonBody<{ access_token: { value: string } }>(
      await h.signedCall(h.grantUrl, json("POST", grantBody([incoming]))),
    );

    expect(await h.auth.api.gnapIntrospect({ body: { access_token: "unknown" } })).toEqual({ active: false });
    expect(
      await h.auth.api.gnapIntrospect({
        body: { access_token: issued.access_token.value, access: [{ type: "incoming-payment", actions: ["read"] }] },
      }),
    ).toMatchObject({ active: true, access: [incoming], client: { walletAddress: WALLET } });
  });

  it("serves HTTP introspection only when configured, to callers the hook authorizes", async () => {
    const off = await createHarness();

    expect(
      (await off.auth.handler(new Request(`${off.grantUrl}/introspect`, json("POST", { access_token: "x" })))).status,
    ).toBe(404);

    const h = await createHarness({
      introspection: {
        authorize: (request) => Effect.succeed(request.headers.get("authorization") === "Bearer rs-secret"),
      },
    });

    const issued = await jsonBody<{ access_token: { value: string } }>(
      await h.signedCall(h.grantUrl, json("POST", grantBody([incoming]))),
    );

    const introspect = (secret: string) =>
      h.auth.handler(
        new Request(`${h.grantUrl}/introspect`, {
          ...json("POST", { access_token: issued.access_token.value }),
          headers: { "content-type": "application/json", authorization: `Bearer ${secret}` },
        }),
      );

    expect(await jsonBody(await introspect("rs-secret"))).toMatchObject({ active: true });
    expect(await errorOf(await introspect("guess"))).toMatchObject({ status: 400, code: "invalid_resource_server" });
  });
});

describe("rate limits", () => {
  it("limit grant requests per client address", async () => {
    const h = await createHarness({ auth: { rateLimit: { enabled: true, storage: "memory" } } });

    const request = () =>
      h.auth.handler(new Request(h.grantUrl, { ...json("POST", {}), headers: { "x-forwarded-for": "203.0.113.7" } }));

    const statuses = [];

    for (let index = 0; index < 22; index += 1) statuses.push((await request()).status);

    expect(statuses.slice(0, 20).every((status) => status !== 429)).toBe(true);
    expect(statuses.slice(20)).toEqual([429, 429]);
  });
});

describe("multi-tenant mode", () => {
  const tenants = (id: string) =>
    Effect.succeed(id === "alpha" ? { consentUrl: "https://alpha.test/consent", idpSecret: "alpha-secret" } : null);

  it("takes the grant request at /gnap/:tenantId, stores the tenant, and has no /gnap grant endpoint", async () => {
    const h = await createHarness({ tenants });

    const granted = await h.signedCall(`${h.grantUrl}/alpha`, json("POST", grantBody([outgoing], { interact })));

    expect(granted.status).toBe(200);
    expect(h.db["gnapGrant"]).toMatchObject([{ tenantId: "alpha" }]);

    expect(
      (await h.auth.handler(new Request(h.grantUrl, json("POST", grantBody([outgoing], { interact }))))).status,
    ).toBe(404);

    expect(await errorOf(await h.signedCall(`${h.grantUrl}/nobody`, json("POST", grantBody([incoming]))))).toEqual({
      status: 404,
      code: "invalid_request",
      description: "Not Found",
    });
  });

  it("rate-limits the tenant grant endpoint like /gnap", async () => {
    const h = await createHarness({ tenants, auth: { rateLimit: { enabled: true, storage: "memory" } } });

    const request = () =>
      h.auth.handler(
        new Request(`${h.grantUrl}/alpha`, { ...json("POST", {}), headers: { "x-forwarded-for": "203.0.113.8" } }),
      );

    const statuses = [];

    for (let index = 0; index < 22; index += 1) statuses.push((await request()).status);

    expect(statuses.slice(20)).toEqual([429, 429]);
  });

  it("serves the identity provider routes with `tenants` and no top-level secret, each tenant with its own", async () => {
    const h = await createHarness({ tenants });
    const granted = await h.signedCall(`${h.grantUrl}/alpha`, json("POST", grantBody([outgoing], { interact })));

    const pending = await jsonBody<{ interact: { redirect: string } }>(granted);
    const [interactId = "", nonce = ""] = new URL(pending.interact.redirect).pathname.split("/").slice(-2);

    const idp = (secret: string) =>
      h.auth.handler(
        new Request(`${h.grantUrl}/grant/${interactId}/${nonce}/accept`, {
          method: "POST",
          headers: { "x-idp-secret": secret },
        }),
      );

    expect((await idp("wrong")).status).toBe(401);
    expect((await idp("alpha-secret")).status).toBe(202);
  });
});

describe("replay protection", () => {
  it("accepts a nonce-bearing signed grant request once and refuses its replay", async () => {
    const h = await createHarness();

    const signed = await Effect.runPromise(
      signRequest(new Request(h.grantUrl, json("POST", grantBody([incoming]))), h.clientKey.signingKey, {
        nonce: "n-1",
      }),
    );

    expect((await h.call(signed.clone())).status).toBe(200);
    expect(await errorOf(await h.call(signed.clone()))).toMatchObject({ status: 401, code: "invalid_client" });
    expect(h.db["gnapNonce"]).toHaveLength(1);
  });
});

describe("observing failures", () => {
  it("hands `onError` the cause of a defect behind a 500", async () => {
    const causes: Array<Cause.Cause<never>> = [];

    const h = await createHarness({
      resolveClientKeys: () => Effect.die(new Error("key store is down")),
      onError: (cause) =>
        Effect.sync(() => {
          causes.push(cause);
        }),
    });

    const signed = await Effect.runPromise(
      signRequest(new Request(h.grantUrl, json("POST", grantBody([incoming]))), h.clientKey.signingKey),
    );

    expect((await h.auth.handler(signed)).status).toBe(500);
    expect(causes).toHaveLength(1);
  });
});

describe("rate limit of the continuation endpoint", () => {
  it("allows 30 requests a minute per client address", async () => {
    const h = await createHarness({ auth: { rateLimit: { enabled: true, storage: "memory" } } });

    const request = () =>
      h.auth.handler(
        new Request(`${h.grantUrl}/continue/x`, { ...json("POST", {}), headers: { "x-forwarded-for": "203.0.113.9" } }),
      );

    const statuses = [];

    for (let index = 0; index < 31; index += 1) statuses.push((await request()).status);

    expect(statuses.slice(0, 30).every((status) => status !== 429)).toBe(true);
    expect(statuses[30]).toBe(429);
  });
});

describe("the client plugin (open-payments-ilp/better-auth/client)", () => {
  /** An auth client whose requests are answered by the handler, as the signed-in user or anonymously. */
  const clientOf = (h: Harness, signedIn = true) => {
    const seen: string[] = [];

    const authClient = createAuthClient({
      baseURL: h.baseURL,
      plugins: [gnapClient()],
      fetchOptions: {
        customFetchImpl: (input, init) => {
          const request = new Request(
            input,
            withHeaders(init ?? {}, { origin: h.baseURL, ...(signedIn && { cookie: h.cookie }) }),
          );

          seen.push(new URL(request.url).pathname);

          return h.auth.handler(request);
        },
      },
    });

    return { authClient, seen };
  };

  it("shows the interaction to the signed-in user", async () => {
    const h = await createHarness();
    const pending = await startGrant(h);
    const { authClient } = clientOf(h);
    const shown = await authClient.gnap.getInteraction(pending.interactId, pending.nonce);

    expect(shown.error).toBeNull();
    expect(shown.data).toMatchObject({ client: WALLET, access: [outgoing], state: "PENDING" });
  });

  it.each(["acceptInteraction", "rejectInteraction"] as const)(
    "%s answers where the browser goes next",
    async (action) => {
      const h = await createHarness();
      const pending = await startGrant(h);
      const { authClient } = clientOf(h);
      const decided = await authClient.gnap[action](pending.interactId, pending.nonce);

      expect(decided.data).toEqual({
        redirect: `${h.grantUrl}/interact/${pending.interactId}/${pending.nonce}/finish`,
      });
    },
  );

  it("sends an interactId that is not URL-safe encoded exactly once", async () => {
    const h = await createHarness();
    const { authClient, seen } = clientOf(h);

    await authClient.gnap.acceptInteraction("a/b?c", "n#1");

    expect(seen.map((path) => path.split("/").slice(-3).map(decodeURIComponent))).toEqual([["a/b?c", "n#1", "accept"]]);
  });

  it("is refused for an anonymous user", async () => {
    const h = await createHarness();
    const pending = await startGrant(h);
    const { authClient } = clientOf(h, false);

    expect((await authClient.gnap.getInteraction(pending.interactId, pending.nonce)).error?.status).toBe(401);
    expect((await authClient.gnap.acceptInteraction(pending.interactId, pending.nonce)).error?.status).toBe(401);
  });
});
