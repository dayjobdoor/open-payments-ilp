// oxlint-disable anti-slop/no-unknown-parameters -- Requests send arbitrary, including malformed, bodies by design.
/**
 * Rafiki v2 multi-tenancy (`tenants`): the grant request goes to `{baseUrl}/{tenantId}`, everything after it is
 * tenant-less and finds its tenant through the grant. Rafiki: `grant/routes.ts` (`createGrant`, `invalid tenant`),
 * `interaction/routes.ts` (per-tenant `idpSecret` / `idpConsentUrl`, finish `hash` over `authServerUrl/tenantId`).
 */
import * as Effect from "effect/Effect";
import { describe, expect, it } from "vite-plus/test";
import { computeInteractionHash } from "../../src/gnap/index";
import type { TenantConfig } from "../../src/gnap/server/index";
import { listen } from "../open-payments/fake-server";
import { describeReferenceClient } from "./reference-flows";
import {
  amount,
  browserFinish,
  browserStart,
  createServerHarness,
  errorOf,
  grantBody,
  idp,
  incoming,
  interact,
  json,
  jsonBody,
  outgoing,
  type Pending,
  type ServerHarness,
} from "./support";

const TENANTS = new Map<string, TenantConfig>([
  ["alpha", { consentUrl: "https://alpha.test/consent", idpSecret: "alpha-secret" }],
  ["beta", { consentUrl: "https://beta.test/consent", idpSecret: "beta-secret" }],
  ["bare", {}],
]);

const tenants = (id: string): Effect.Effect<TenantConfig | null> => Effect.succeed(TENANTS.get(id) ?? null);

const harness = (): Promise<ServerHarness> => createServerHarness({ tenants, without: ["interaction", "idpSecret"] });

const requestGrant = (h: ServerHarness, tenant: string, body: unknown = grantBody([outgoing], { interact })) =>
  h.signedCall(`${h.baseUrl}/${tenant}`, json("POST", body));

/** A pending interactive grant of `tenant`, as the pieces the browser and the identity provider need. */
const pendingOf = async (h: ServerHarness, tenant: string): Promise<Pending> => {
  const response = await requestGrant(h, tenant);

  expect(response.status).toBe(200);

  const body = await jsonBody<{
    interact: { redirect: string };
    continue: { uri: string; access_token: { value: string } };
  }>(response);

  const [interactId = "", nonce = ""] = new URL(body.interact.redirect).pathname.split("/").slice(-2);

  return {
    interactUrl: body.interact.redirect,
    interactId,
    nonce,
    continueUri: body.continue.uri,
    continueToken: body.continue.access_token.value,
  };
};

describe("multi-tenant grant requests", () => {
  it("serve POST /:tenantId; POST / is not a route", async () => {
    const h = await createServerHarness({ tenants, unvalidated: true });

    expect((await requestGrant(h, "alpha")).status).toBe(200);
    expect(await errorOf(await h.signedCall(h.baseUrl, json("POST", grantBody([outgoing], { interact }))))).toEqual({
      status: 404,
      code: "invalid_request",
      description: "not found",
    });
  });

  it("answer an unknown tenant 404 'Not Found', but only after the signature was checked (Rafiki's order)", async () => {
    const h = await harness();

    expect(await errorOf(await requestGrant(h, "nobody"))).toEqual({
      status: 404,
      code: "invalid_request",
      description: "Not Found",
    });

    const unsigned = await h.call(
      new Request(`${h.baseUrl}/nobody`, json("POST", grantBody([outgoing], { interact }))),
    );

    expect(await errorOf(unsigned)).toMatchObject({ status: 401, code: "invalid_client" });
  });

  it("need a tenant with a consent URL for interactive grants ('invalid tenant'), not for the others", async () => {
    const h = await harness();

    expect(await errorOf(await requestGrant(h, "bare"))).toEqual({
      status: 400,
      code: "invalid_request",
      description: "invalid tenant",
    });

    const immediate = await requestGrant(h, "bare", grantBody([incoming]));

    expect(immediate.status).toBe(200);
    expect(await jsonBody(immediate)).toMatchObject({ access_token: { value: expect.any(String) } });
  });

  it("keep POST /introspect ahead of a tenant segment", async () => {
    const h = await createServerHarness({
      tenants,
      introspection: { authorize: () => Effect.succeed(true) },
    });

    const response = await h.call(new Request(`${h.baseUrl}/introspect`, json("POST", { access_token: "unknown" })));

    expect(await jsonBody(response)).toEqual({ active: false });
  });

  describe("scoped introspection (`authorize` answering `{ tenantId }`)", () => {
    const scoped = (tenantId: string) =>
      createServerHarness({ tenants, introspection: { authorize: () => Effect.succeed({ tenantId }) } });

    /** An access token issued to `tenant`, introspected through `h`. */
    const introspectTokenOf = async (h: ServerHarness, tenant: string) => {
      const issued = await jsonBody<{ access_token: { value: string } }>(
        await requestGrant(h, tenant, grantBody([incoming])),
      );

      return jsonBody(
        await h.call(new Request(`${h.baseUrl}/introspect`, json("POST", { access_token: issued.access_token.value }))),
      );
    };

    it("reports a token of the caller's tenant", async () => {
      expect(await introspectTokenOf(await scoped("alpha"), "alpha")).toMatchObject({ active: true });
    });

    it("answers { active: false } for a token of another tenant, as for an unknown one", async () => {
      const h = await scoped("alpha");

      expect(await introspectTokenOf(h, "beta")).toEqual({ active: false });
    });

    it("leaves the in-process introspectToken unscoped", async () => {
      const h = await scoped("alpha");

      const issued = await jsonBody<{ access_token: { value: string } }>(
        await requestGrant(h, "beta", grantBody([incoming])),
      );

      expect(await Effect.runPromise(h.server.introspectToken(issued.access_token.value))).toMatchObject({
        active: true,
      });
    });
  });

  it("store the tenant in the grant", async () => {
    const h = await harness();
    const pending = await pendingOf(h, "beta");
    const grant = await Effect.runPromise(h.store.findGrant("interactId", pending.interactId));

    expect(grant?.tenantId).toBe("beta");
  });
});

describe("multi-tenant interaction", () => {
  it("sends the user to the consent URL of the grant's tenant", async () => {
    const h = await harness();

    for (const [tenant, consentUrl] of [
      ["alpha", "https://alpha.test/consent"],
      ["beta", "https://beta.test/consent"],
    ] as const) {
      const { location } = await browserStart(h, await pendingOf(h, tenant));

      expect(location.startsWith(`${consentUrl}?`)).toBe(true);
    }
  });

  it("authenticates the identity provider with the secret of the grant's tenant", async () => {
    const h = await harness();
    const pending = await pendingOf(h, "alpha");

    expect(await errorOf(await idp(h, pending, "accept", "beta-secret"))).toMatchObject({
      status: 401,
      code: "invalid_interaction",
    });

    expect((await idp(h, pending, "accept", "alpha-secret")).status).toBe(202);
  });

  it("has no identity provider back channel for a tenant without a secret", async () => {
    const h = await createServerHarness({
      tenants: (id) => Effect.succeed(id === "open" ? { consentUrl: "https://open.test/consent" } : null),
      without: ["interaction", "idpSecret"],
    });

    expect(await errorOf(await idp(h, await pendingOf(h, "open"), "accept", "anything"))).toMatchObject({
      status: 404,
      code: "unknown_interaction",
    });
  });

  it("computes the finish hash over the URL the grant was requested at, tenant segment included", async () => {
    const h = await harness();
    const pending = await pendingOf(h, "alpha");
    const { cookie } = await browserStart(h, pending);

    expect((await idp(h, pending, "accept", "alpha-secret")).status).toBe(202);
    const back = new URL((await browserFinish(h, pending, cookie)).headers.get("location") ?? "");
    const interactRef = back.searchParams.get("interact_ref") ?? "";

    const expected = (grantEndpoint: string) =>
      Effect.runPromise(
        computeInteractionHash({
          clientNonce: "client-nonce",
          serverNonce: pending.nonce,
          interactRef,
          grantEndpoint,
          encoding: "base64",
        }),
      );

    expect(back.searchParams.get("hash")).toBe(await expected(`${h.baseUrl}/alpha`));
    expect(back.searchParams.get("hash")).not.toBe(await expected(h.baseUrl));
  });

  it("continues, rotates and revokes without a tenant segment", async () => {
    const h = await harness();
    const pending = await pendingOf(h, "alpha");
    const { cookie } = await browserStart(h, pending);

    expect((await idp(h, pending, "accept", "alpha-secret")).status).toBe(202);
    const back = new URL((await browserFinish(h, pending, cookie)).headers.get("location") ?? "");
    h.clock.advance(6);

    const continued = await h.signedCall(pending.continueUri, {
      method: "POST",
      body: JSON.stringify({ interact_ref: back.searchParams.get("interact_ref") }),
      headers: { authorization: `GNAP ${pending.continueToken}`, "content-type": "application/json" },
    });

    expect(pending.continueUri.startsWith(`${h.baseUrl}/continue/`)).toBe(true);
    expect(await jsonBody(continued)).toMatchObject({
      access_token: { access: [{ type: "outgoing-payment", limits: { debitAmount: amount } }] },
    });
  });
});

describeReferenceClient("multi-tenant core over HTTP", async () => {
  let handle: (request: Request) => Promise<Response> = () => Promise.resolve(new Response(null, { status: 503 }));
  const listening = await listen((request) => handle(request));

  const h = await createServerHarness({
    baseUrl: `${listening.origin}/gnap`,
    tenants,
    without: ["interaction", "idpSecret"],
  });

  handle = h.call;

  return {
    authServer: h.baseUrl,
    grantUrl: `${h.baseUrl}/alpha`,
    clientKey: h.clientKey,
    idpSecret: "alpha-secret",
    advanceClock: h.clock.advance,
    introspect: (token, access) => Effect.runPromise(h.server.introspectToken(token, access)),
    close: listening.close,
  };
});
