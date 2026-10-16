// oxlint-disable anti-slop/no-runtime-typeof, anti-slop/no-unknown-parameters -- Cases send arbitrary, including malformed, bodies by design.
/**
 * Parity with Rafiki's auth server: its own route and service tests (`rafiki/packages/auth/src/…`) are the oracle,
 * ported as one table of cases run against `createGnapServer` on `memoryGnapStore`. Each case names the Rafiki test it
 * mirrors and asserts status, error code, description, body, redirect and stored state.
 *
 * Rafiki's route tests call the route handlers directly. Over the wire a request first passes its signature
 * middleware (`signature/middleware.ts`), and where the middleware answers before the route does, the case asserts what
 * a client really sees (noted as "wire"). A case marked `deviation` is one where this server deliberately answers
 * differently; it names the README Compatibility row, and asserts what this server does instead. Rafiki tests that
 * exercise only Rafiki's ORM, locks or logging have no case. The `mirrors:` titles are hand-typed and nothing checks
 * them against Rafiki: this table is a regression suite modelled on Rafiki's tests, not machine-checked parity.
 */
import * as Effect from "effect/Effect";
import { describe, expect, it } from "vite-plus/test";
import { hashToken, type AccessItem } from "../../src/gnap/index";
import {
  memoryGnapStore,
  type GnapGrantRequest,
  type GnapStore,
  type GrantRecord,
  type TokenRecord,
} from "../../src/gnap/server/index";
import { HttpSignatureError } from "../../src/http-signatures/index";
import {
  amount,
  BASE_URL,
  CONSENT_URL,
  FINISH_URI,
  IDP_SECRET,
  KEY_ID,
  WALLET,
  browserFinish,
  clientJwk,
  createClientKey,
  createServerHarness,
  errorOf,
  grantBody,
  idp,
  incoming,
  interact,
  json,
  jsonBody,
  outgoing,
  SEED,
  seedGrant,
  seedToken,
  withToken,
  type HarnessOptions,
  type Pending,
  type ServerHarness,
} from "./support";

interface ExpectedError {
  readonly status: number;
  readonly code: string;
  readonly description: string;
}

interface Case {
  /** The Rafiki test this mirrors, relative to `rafiki/packages/auth/src/`. */
  readonly mirrors: string;
  readonly name: string;
  /** Set when this server intentionally differs: the Compatibility row of the README that says why. */
  readonly deviation?: string;
  readonly options?: HarnessOptions;
  readonly act: (h: ServerHarness) => Promise<Response>;
  /** An error answer, or a check of the success response. */
  readonly expected: ExpectedError | ((response: Response, h: ServerHarness) => Promise<void>);
}

const runCases = (cases: ReadonlyArray<Case>): void => {
  it.each(
    cases.map(
      (candidate) =>
        [
          `${candidate.name}${candidate.deviation === undefined ? "" : ` [deviation: ${candidate.deviation}]`}  ← ${candidate.mirrors}`,
          candidate,
        ] as const,
    ),
  )("%s", async (_title, candidate) => {
    const h = await createServerHarness(candidate.options);
    const response = await candidate.act(h);

    if (typeof candidate.expected === "function") await candidate.expected(response, h);
    else expect(await errorOf(response)).toEqual(candidate.expected);
  });
};

const error = (status: number, code: string, description: string): ExpectedError => ({ status, code, description });

const post = (h: ServerHarness, body: unknown) => h.signedCall(h.baseUrl, json("POST", body));

const grantOf = async (h: ServerHarness, id: string): Promise<GrantRecord> => {
  const grant = await Effect.runPromise(h.store.findGrant("id", id));

  if (grant === null) throw new Error("grant not stored");

  return grant;
};

const dying = (overrides: Partial<GnapStore>): GnapStore => ({ ...memoryGnapStore(), ...overrides });

/** A continue request, signed by the harness client. `token: null` omits the Authorization header. */
const continueRequest = (
  h: ServerHarness,
  uri: string,
  { method = "POST", body, token }: { method?: string; body?: unknown; token: string | null },
) => h.signedCall(uri, token === null ? json(method, body) : withToken(json(method, body), token));

const accessItem: AccessItem = {
  type: "incoming-payment",
  actions: ["create", "read", "list"],
  identifier: `${WALLET}/incoming/1`,
};

const actionNames = (item: AccessItem): ReadonlyArray<string> => item.actions;

/** Rafiki's `canSkipInteraction` as a policy: `incomingPaymentInteraction`/`quoteInteraction` and `listAllInteraction`. */
const rafikiFlags = (resourceInteraction: boolean, listAllInteraction: boolean) => ({
  requiresInteraction: (request: GnapGrantRequest): boolean =>
    request.access.some(
      (item) =>
        item.type === "outgoing-payment" ||
        resourceInteraction ||
        (listAllInteraction && actionNames(item).includes("list-all")),
    ),
});

describe("grant routes — POST / (grant/routes.test.ts › /create)", () => {
  const matrix: Case[] = [];

  const accessTypes = {
    "incoming-payment": (listAll: boolean) => [
      {
        type: "incoming-payment",
        actions: listAll ? ["create", "list-all"] : ["create", "read"],
        identifier: `${WALLET}/incoming/1`,
      },
    ],
    quote: () => [{ type: "quote", actions: ["create", "read"] }],
  };

  // Rafiki: `describe.each(accessTypes)` x `describe.each(resourceInteractionFlagsEnabled, listAllInteractionFlagEnabled, listAllGrant)`.
  for (const [label, build] of [
    ["incoming-payment", (la: boolean) => accessTypes["incoming-payment"](la)],
    ["quote", () => accessTypes.quote()],
    ["incoming-payment and quote", (la: boolean) => [...accessTypes["incoming-payment"](la), ...accessTypes.quote()]],
  ] as const) {
    for (const [resourceFlags, listAllFlag, listAll] of [
      [true, false, false],
      [false, false, false],
      [true, false, true],
      [false, false, true],
      [true, true, true],
      [false, true, true],
    ] as const) {
      if (label === "quote" && listAll) continue; // Rafiki: "Quotes don't have list-all access type"
      const interactive = resourceFlags || (listAllFlag && listAll);

      matrix.push({
        mirrors: "grant/routes.test.ts › non-interactive grants › describe.each(accessTypes, interaction flags)",
        name: `${label}, resource interaction ${resourceFlags}, list-all interaction ${listAllFlag}, ${listAll ? "with" : "no"} list-all grant: ${interactive ? "needs interact" : "granted at once"}`,
        options: { policy: rafikiFlags(resourceFlags, listAllFlag) },
        act: (h) => post(h, grantBody(build(listAll))),
        expected: interactive
          ? error(400, "invalid_request", "missing required request field 'interact'")
          : async (response, h) => {
              const access = build(listAll);
              const body = await jsonBody<{ continue: { access_token: { value: string }; uri: string } }>(response);
              const continueId = body.continue.uri.split("/").at(-1) ?? "";
              const stored = await Effect.runPromise(h.store.findGrant("continueId", continueId));

              expect(response.status).toBe(200);
              expect(body).toEqual({
                access_token: {
                  value: expect.any(String),
                  manage: expect.stringMatching(`^${BASE_URL}/token/`),
                  access,
                  expires_in: 600,
                },
                continue: { access_token: { value: expect.any(String) }, uri: `${BASE_URL}/continue/${continueId}` },
              });

              expect(stored).toMatchObject({ client: WALLET, jwk: null, state: "APPROVED", access });
              expect(stored?.continueTokenHash).toBe(
                await Effect.runPromise(hashToken(body.continue.access_token.value)),
              );
            },
      });
    }
  }

  runCases(matrix);

  runCases([
    {
      mirrors: "grant/routes.test.ts › /create › Can create non-interactive grant with JWK client",
      name: "a JWK client gets a non-interactive grant",
      act: async (h) =>
        post(h, { client: { jwk: clientJwk(h.clientKey) }, access_token: { access: [{ ...incoming }] } }),
      expected: async (response, h) => {
        const body = await jsonBody<{ continue: { uri: string } }>(response);

        const stored = await Effect.runPromise(
          h.store.findGrant("continueId", body.continue.uri.split("/").at(-1) ?? ""),
        );

        expect(response.status).toBe(200);
        expect(stored?.client).toBeNull();
        expect(stored?.jwk).toMatchObject({ kid: KEY_ID, kty: "OKP" });
      },
    },
    {
      mirrors: "grant/routes.test.ts › /create › Rejects interactive grant with JWK client",
      name: "a JWK client cannot get an interactive grant",
      act: async (h) => post(h, grantBody([outgoing], { interact, client: { jwk: clientJwk(h.clientKey) } })),
      expected: error(400, "invalid_client", "JWK client identifier cannot be used for interactive grants"),
    },
    {
      mirrors: "grant/routes.test.ts › /create › Can initiate a grant request",
      name: "an interactive grant request answers the pending grant",
      act: (h) => post(h, grantBody([outgoing], { interact })),
      expected: async (response, h) => {
        const body = await jsonBody<{
          interact: { redirect: string; finish: string };
          continue: { access_token: { value: string }; uri: string; wait: number };
        }>(response);

        const redirect = new URL(body.interact.redirect);
        const [interactId = "", nonce = ""] = redirect.pathname.split("/").slice(-2);
        const stored = await Effect.runPromise(h.store.findGrant("interactId", interactId));

        expect(response.status).toBe(200);
        expect(`${redirect.origin}${redirect.pathname}`).toBe(`${BASE_URL}/interact/${interactId}/${nonce}`);
        expect(Object.fromEntries(redirect.searchParams)).toEqual({ clientName: "wallet.test", clientUri: WALLET });
        expect(body.interact.finish).toBe(nonce);
        expect(body.continue).toEqual({
          access_token: { value: expect.any(String) },
          uri: `${BASE_URL}/continue/${stored?.continueId}`,
          wait: 5,
        });

        expect(stored).toMatchObject({
          state: "PENDING",
          interactNonce: nonce,
          finishUri: FINISH_URI,
          clientNonce: "client-nonce",
          access: [outgoing],
        });
      },
    },
    {
      // Single tenant: "the tenant has no idp" becomes "the server has no `interaction` configured".
      mirrors: "grant/routes.test.ts › /create › Does not create interactive grant if tenant has no idp",
      name: "no interaction configured: interactive grants are refused",
      options: { without: ["interaction"] },
      act: (h) => post(h, grantBody([outgoing], { interact })),
      expected: error(400, "invalid_request", "invalid tenant"),
    },
    {
      mirrors: "grant/routes.test.ts › /create › Does not create grant if token issuance fails",
      name: "a failing token store is a 500 request_denied",
      options: { store: dying({ createToken: () => Effect.die(new Error("db down")) }) },
      act: (h) => post(h, grantBody([incoming])),
      expected: error(500, "request_denied", "internal server error"),
    },
    {
      mirrors: "grant/routes.test.ts › /create › Fails to initiate a grant w/o interact field",
      name: "interactive grant without `interact`",
      act: (h) => post(h, grantBody([outgoing])),
      expected: error(400, "invalid_request", "missing required request field 'interact'"),
    },
    {
      mirrors: "grant/routes.test.ts › /create › Does not create interactive grant if interaction creation fails",
      name: "a failing grant store is a 500 request_denied",
      options: { store: dying({ createGrant: () => Effect.die(new Error("db down")) }) },
      act: (h) => post(h, grantBody([outgoing], { interact })),
      expected: error(500, "request_denied", "internal server error"),
    },
    {
      mirrors:
        "grant/routes.test.ts › /create › Fails to initiate a grant w/o identifier field if interaction required",
      name: "list-all access without identifier",
      act: (h) => post(h, grantBody([{ type: "incoming-payment", actions: ["create", "list-all"] }], { interact })),
      expected: error(400, "invalid_request", "access identifier required"),
    },
    {
      // Rafiki fetches the wallet address document (and refuses one without `publicName`) after the middleware;
      // this server only fetches the keys, and answers the middleware's error when they cannot be had.
      mirrors: "grant/routes.test.ts › /create › Fails to initiate a grant if wallet address has no public name",
      name: "a client whose keys cannot be resolved",
      deviation: "Wallet address document",
      options: {
        resolveClientKeys: () => Effect.fail(new HttpSignatureError({ reason: "unknown-key", message: "no wallet" })),
      },
      act: (h) => post(h, grantBody([outgoing], { interact })),
      expected: error(400, "invalid_client", "could not determine client"),
    },
    {
      mirrors:
        "grant/routes.test.ts › /create › Fails to create a grant with at least one access having both receiveAmount and debitAmount as limits",
      name: "both debitAmount and receiveAmount",
      act: (h) =>
        post(
          h,
          grantBody(
            [
              {
                ...outgoing,
                limits: { debitAmount: amount, receiveAmount: amount },
              },
            ],
            { interact },
          ),
        ),
      expected: error(400, "invalid_request", "only one access amount allowed"),
    },
    {
      mirrors: "grant/utils.ts › canSkipInteraction: 'subject or access_token required'",
      name: "neither access nor subject",
      act: (h) => post(h, { client: WALLET, interact }),
      expected: error(400, "invalid_request", "subject or access_token required"),
    },
    {
      mirrors: "grant/utils.test.ts › parseRawClientField › normalizes a { walletAddress } client to { client }",
      name: "client given as { walletAddress }",
      act: (h) => post(h, { client: { walletAddress: WALLET }, access_token: { access: [{ ...incoming }] } }),
      expected: async (response, h) => {
        const body = await jsonBody<{ continue: { uri: string } }>(response);

        const stored = await Effect.runPromise(
          h.store.findGrant("continueId", body.continue.uri.split("/").at(-1) ?? ""),
        );

        expect(response.status).toBe(200);
        expect(stored).toMatchObject({ client: WALLET, jwk: null });
      },
    },
    {
      mirrors: "grant/utils.test.ts › parseRawClientField › throws on falsy input",
      name: "no client",
      act: (h) => post(h, { access_token: { access: [{ ...incoming }] } }),
      expected: error(400, "invalid_request", "Invalid client field"),
    },
    {
      mirrors: "grant/service.test.ts › create › Can initiate a grant (access that needs no consent, `interact` sent)",
      name: "incoming-payment access with `interact` is granted at once",
      act: (h) => post(h, grantBody([incoming], { interact })),
      expected: async (response) => {
        expect(response.status).toBe(200);
        expect(await jsonBody(response)).toEqual({
          access_token: {
            value: expect.any(String),
            manage: expect.stringMatching(`^${BASE_URL}/token/`),
            access: [incoming],
            expires_in: 600,
          },
          continue: {
            access_token: { value: expect.any(String) },
            uri: expect.stringContaining(`${BASE_URL}/continue/`),
          },
        });
      },
    },
    {
      mirrors: "grant/service.test.ts › create › create a grant with subject in pending state",
      name: "a subject grant is pending, with the interaction",
      act: (h) =>
        post(h, {
          client: WALLET,
          subject: { sub_ids: [{ id: `${WALLET}/alice`, format: "uri" as const }] },
          interact,
        }),
      expected: async (response, h) => {
        const body = await jsonBody<{ interact: { redirect: string }; continue: { uri: string; wait: number } }>(
          response,
        );

        const stored = await Effect.runPromise(
          h.store.findGrant("continueId", body.continue.uri.split("/").at(-1) ?? ""),
        );

        expect(response.status).toBe(200);
        expect(body.continue.wait).toBe(5);
        expect(body.interact.redirect).toContain("/interact/");
        expect(stored).toMatchObject({
          state: "PENDING",
          access: [],
          subject: { sub_ids: [{ id: `${WALLET}/alice` }] },
        });
      },
    },
    {
      mirrors:
        "grant/routes.test.ts › /create › Fails to initiate a grant without providing a tenant id (wire: not a route)",
      name: "multi-tenant: POST without tenant segment",
      options: { tenants: () => Effect.succeed({ consentUrl: CONSENT_URL }), unvalidated: true },
      act: (h) => post(h, grantBody([incoming])),
      expected: error(404, "invalid_request", "not found"),
    },
    {
      mirrors: "grant/routes.test.ts › /create › Fails to initiate a grant if the provided tenant does not exist",
      name: "multi-tenant: unknown tenant",
      options: { tenants: () => Effect.succeed(null) },
      act: (h) => h.signedCall(`${h.baseUrl}/${crypto.randomUUID()}`, json("POST", grantBody([incoming]))),
      expected: error(404, "invalid_request", "Not Found"),
    },
  ]);
});

describe("grant routes — continue (grant/routes.test.ts › /continue)", () => {
  const approved = (h: ServerHarness, overrides: Partial<GrantRecord> = {}) =>
    seedGrant(h, { state: "APPROVED", ...overrides });

  runCases([
    {
      mirrors: "grant/routes.test.ts › /continue › Can issue access token",
      name: "approved grant + interact_ref issues the access token",
      act: async (h) => {
        const s = await approved(h);

        return continueRequest(h, s.continueUri, {
          body: { interact_ref: s.grant.interactRef },
          token: s.continueToken,
        });
      },
      expected: async (response, h) => {
        const body = await jsonBody<{
          access_token: { value: string; manage: string };
          continue: { access_token: { value: string }; uri: string };
        }>(response);

        expect(response.status).toBe(200);
        expect(body).toEqual({
          access_token: {
            value: expect.any(String),
            manage: expect.stringMatching(`^${BASE_URL}/token/`),
            access: [accessItem],
            expires_in: 600,
          },
          continue: {
            access_token: { value: expect.any(String) },
            uri: expect.stringContaining(`${BASE_URL}/continue/`),
          },
        });

        // Only hashes are stored; the grant is finalised.
        const stored = await Effect.runPromise(
          h.store.findTokenWithGrant("valueHash", await Effect.runPromise(hashToken(body.access_token.value))),
        );

        expect(stored).not.toBeNull();
        expect((await grantOf(h, stored?.token.grantId ?? "")).state).toBe("FINALIZED");
      },
    },
    {
      // wire: Rafiki's middleware answers before the route's 404 'grant not found'.
      mirrors: "grant/routes.test.ts › /continue › Cannot issue access token if grant does not exist",
      name: "unknown continue id (wire: signature middleware)",
      act: (h) =>
        continueRequest(h, `${BASE_URL}/continue/${crypto.randomUUID()}`, {
          body: { interact_ref: "x" },
          token: "unknown",
        }),
      expected: error(401, "invalid_continuation", "invalid grant"),
    },
    {
      mirrors: "grant/routes.test.ts › /continue › Cannot issue access token if grant has not been granted",
      name: "pending grant + interact_ref",
      act: async (h) => {
        const s = await seedGrant(h);

        return continueRequest(h, s.continueUri, {
          body: { interact_ref: s.grant.interactRef },
          token: s.continueToken,
        });
      },
      expected: error(401, "request_denied", "grant interaction not approved"),
    },
    {
      // wire: Rafiki's middleware (`getByContinue` hides revoked grants) answers before the route's 404.
      mirrors: "grant/routes.test.ts › /continue › Cannot issue access token if grant has been revoked",
      name: "revoked grant (wire: signature middleware)",
      act: async (h) => {
        const s = await seedGrant(h, { state: "REVOKED" });

        return continueRequest(h, s.continueUri, {
          body: { interact_ref: s.grant.interactRef },
          token: s.continueToken,
        });
      },
      expected: error(401, "invalid_continuation", "invalid grant"),
    },
    {
      // wire: without `Authorization` Rafiki's middleware answers 'invalid signature headers'.
      mirrors: "grant/routes.test.ts › /continue › Cannot issue access token without continue token",
      name: "no continue token (wire: signature middleware)",
      act: async (h) => {
        const s = await approved(h);

        return continueRequest(h, s.continueUri, { body: { interact_ref: s.grant.interactRef }, token: null });
      },
      expected: error(401, "invalid_client", "invalid signature headers"),
    },
    {
      mirrors:
        "grant/routes.test.ts › /continue › Cannot issue access token if body provided without interaction reference",
      name: "a body without interact_ref",
      // Rafiki answers `invalid_request` here, a code auth-server.yaml does not list for POST /continue/{id}.
      options: { unvalidated: true },
      act: async (h) => {
        const s = await approved(h);

        return continueRequest(h, s.continueUri, { body: { other: "member" }, token: s.continueToken });
      },
      expected: error(401, "invalid_request", "missing interaction reference"),
    },
    {
      mirrors: "grant/routes.test.ts › /continue › Honors wait value when continuing too early",
      name: "continuing inside the wait period",
      act: async (h) => {
        const s = await seedGrant(h, { lastContinuedAt: h.clock.now().getTime() });

        return continueRequest(h, s.continueUri, {
          body: { interact_ref: s.grant.interactRef },
          token: s.continueToken,
        });
      },
      expected: error(400, "too_fast", 'continued grant faster than "wait" period'),
    },
    {
      mirrors: "grant/routes.test.ts › /continue › Polls correctly for continuation on a $description grant (pending)",
      name: "polling a pending grant answers the continuation with `wait` and counts as a poll",
      act: async (h) => {
        const s = await seedGrant(h, { finishUri: null, clientNonce: null });

        return continueRequest(h, s.continueUri, { token: s.continueToken });
      },
      expected: async (response, h) => {
        expect(response.status).toBe(200);
        expect(await jsonBody(response)).toEqual({
          continue: {
            access_token: { value: expect.any(String) },
            uri: expect.stringContaining("/continue/"),
            wait: 5,
          },
        });

        expect((await grantOf(h, SEED.id)).lastContinuedAt).toBe(h.clock.now().getTime());
      },
    },
    {
      mirrors: "grant/routes.test.ts › /continue › Polls correctly for continuation on a $description grant (approved)",
      name: "polling an approved grant issues the access token",
      act: async (h) => {
        const s = await approved(h, { finishUri: null, clientNonce: null });

        return continueRequest(h, s.continueUri, { token: s.continueToken });
      },
      expected: async (response) => {
        expect(response.status).toBe(200);
        expect(await jsonBody(response)).toEqual({
          access_token: {
            value: expect.any(String),
            manage: expect.stringContaining("/token/"),
            access: [accessItem],
            expires_in: 600,
          },
          continue: { access_token: { value: expect.any(String) }, uri: expect.stringContaining("/continue/") },
        });
      },
    },
    {
      mirrors: "grant/service.ts › create: a grant without interaction is APPROVED, so polling it issues a token",
      name: "polling a grant created without interaction",
      act: async (h) => {
        const created = await jsonBody<{ continue: { uri: string; access_token: { value: string } } }>(
          await post(h, grantBody([incoming])),
        );

        h.clock.advance(6);

        return continueRequest(h, created.continue.uri, { token: created.continue.access_token.value });
      },
      expected: async (response) => {
        expect(response.status).toBe(200);
        expect(await jsonBody(response)).toMatchObject({ access_token: { value: expect.any(String) } });
      },
    },
    {
      mirrors: "grant/routes.test.ts › /continue › Cannot poll a finalized grant",
      name: "polling a finalized grant",
      act: async (h) => {
        const s = await seedGrant(h, { state: "FINALIZED", finishUri: null, clientNonce: null });

        return continueRequest(h, s.continueUri, { token: s.continueToken });
      },
      expected: error(401, "request_denied", "grant cannot be continued"),
    },
    {
      mirrors: "grant/routes.test.ts › /continue › Cannot poll a grant with a finish method",
      name: "polling a grant that has a finish method",
      act: async (h) => {
        const s = await approved(h);

        return continueRequest(h, s.continueUri, { token: s.continueToken });
      },
      expected: error(401, "request_denied", "grant cannot be polled"),
    },
    {
      mirrors: "grant/routes.test.ts › /continue › Cannot poll a grant faster than its wait method",
      name: "polling inside the wait period",
      act: async (h) => {
        const s = await seedGrant(h, { finishUri: null, clientNonce: null, lastContinuedAt: h.clock.now().getTime() });

        return continueRequest(h, s.continueUri, { token: s.continueToken });
      },
      expected: error(400, "too_fast", 'polled grant faster than "wait" period'),
    },
    {
      mirrors: "grant/routes.test.ts › /continue › Can cancel a grant request / pending grant",
      name: "DELETE cancels a pending grant",
      act: async (h) => {
        const s = await seedGrant(h);

        return continueRequest(h, s.continueUri, { method: "DELETE", token: s.continueToken });
      },
      expected: async (response, h) => {
        expect(response.status).toBe(204);
        expect(await response.text()).toBe("");
        expect((await grantOf(h, SEED.id)).state).toBe("REVOKED");
      },
    },
    {
      mirrors: "grant/routes.test.ts › /continue › Can revoke an existing grant",
      name: "DELETE revokes an issued grant and its tokens",
      act: async (h) => {
        const s = await seedGrant(h, { state: "FINALIZED" });
        const value = "issued-token";

        await Effect.runPromise(
          h.store.createToken({
            id: crypto.randomUUID(),
            grantId: s.grant.id,
            valueHash: await Effect.runPromise(hashToken(value)),
            managementId: "m1",
            expiresAt: h.clock.now().getTime() + 600_000,
            revokedAt: null,
            createdAt: h.clock.now().getTime(),
          }),
        );

        const response = await continueRequest(h, s.continueUri, { method: "DELETE", token: s.continueToken });

        expect(await Effect.runPromise(h.server.introspectToken(value))).toEqual({ active: false });

        return response;
      },
      expected: async (response) => expect(response.status).toBe(204),
    },
    {
      // wire: Rafiki's middleware hides revoked grants before the route's 404 'unknown grant'.
      mirrors: "grant/routes.test.ts › /continue › Cannot revoke an already revoked grant",
      name: "DELETE of a revoked grant (wire: signature middleware)",
      act: async (h) => {
        const s = await seedGrant(h, { state: "REVOKED" });

        return continueRequest(h, s.continueUri, { method: "DELETE", token: s.continueToken });
      },
      expected: error(401, "invalid_continuation", "invalid grant"),
    },
    {
      mirrors: "grant/routes.test.ts › /continue › Cannot revoke non-existing grant",
      name: "DELETE of a grant that does not exist (wire: signature middleware)",
      act: (h) => continueRequest(h, `${BASE_URL}/continue/${crypto.randomUUID()}`, { method: "DELETE", token: "any" }),
      expected: error(401, "invalid_continuation", "invalid grant"),
    },
    {
      // Rafiki's ' matching' row ("Cannot delete without matching continueToken") revokes a random, unknown grant id
      // (route-level 404 'unknown grant'). Here the grant exists and the token is wrong, which Rafiki's signature
      // middleware answers over the wire with the 401 asserted below.
      mirrors: "grant/routes.test.ts › /continue › Cannot delete without$description continueToken (' matching')",
      name: "DELETE with a token that does not match (wire: signature middleware)",
      act: async (h) => {
        const s = await seedGrant(h);

        return continueRequest(h, s.continueUri, { method: "DELETE", token: "not-the-token" });
      },
      expected: error(401, "invalid_continuation", "invalid grant"),
    },
    {
      mirrors: "grant/routes.test.ts › /continue › Cannot delete without$description continueToken (' matching')",
      name: "DELETE with a continue token of the right length differing only in its first character",
      act: async (h) => {
        const s = await seedGrant(h);

        return continueRequest(h, s.continueUri, { method: "DELETE", token: `x${SEED.continueToken.slice(1)}` });
      },
      expected: error(401, "invalid_continuation", "invalid grant"),
    },
    {
      mirrors: "grant/routes.test.ts › /continue › Cannot delete without continueToken",
      name: "DELETE without Authorization (wire: signature middleware)",
      act: async (h) => {
        const s = await seedGrant(h);

        return continueRequest(h, s.continueUri, { method: "DELETE", token: null });
      },
      expected: error(401, "invalid_client", "invalid signature headers"),
    },
    {
      mirrors:
        "grant/routes.test.ts › /continue › Polls correctly for continuation on a $description grant (processing)",
      name: "polling a grant whose owner decided but has not finished: answered with `wait`",
      act: async (h) => {
        const s = await seedGrant(h, { state: "ACCEPTED", finishUri: null, clientNonce: null });

        return continueRequest(h, s.continueUri, { token: s.continueToken });
      },
      expected: async (response, h) => {
        expect(response.status).toBe(200);
        expect(await jsonBody(response)).toEqual({
          continue: {
            access_token: { value: expect.any(String) },
            uri: expect.stringContaining("/continue/"),
            wait: 5,
          },
        });

        expect((await grantOf(h, SEED.id)).lastContinuedAt).toBe(h.clock.now().getTime());
      },
    },
    {
      mirrors: "grant/routes.test.ts › /continue › Cannot issue access token without continue id ",
      name: "continue without an id",
      options: { unvalidated: true },
      act: async (h) => {
        const s = await approved(h);

        return continueRequest(h, `${BASE_URL}/continue/`, {
          body: { interact_ref: s.grant.interactRef },
          token: s.continueToken,
        });
      },
      expected: error(401, "invalid_continuation", "missing continuation information"),
    },
    {
      mirrors:
        "grant/routes.test.ts › /continue › Cannot issue access token if grant does not exist (unknown interact_ref)",
      name: "an interact_ref that no grant has",
      options: { unvalidated: true },
      act: async (h) => {
        const s = await approved(h);

        return continueRequest(h, s.continueUri, { body: { interact_ref: "nope" }, token: s.continueToken });
      },
      expected: error(404, "invalid_continuation", "grant not found"),
    },
    {
      mirrors: "grant/routes.test.ts › /continue › Can issue access token (a second time)",
      name: "continuing a grant whose token was issued",
      act: async (h) => {
        const s = await approved(h);

        const first = await continueRequest(h, s.continueUri, {
          body: { interact_ref: s.grant.interactRef },
          token: s.continueToken,
        });

        expect(first.status).toBe(200);

        return continueRequest(h, s.continueUri, {
          body: { interact_ref: s.grant.interactRef },
          token: s.continueToken,
        });
      },
      expected: error(401, "request_denied", "grant interaction not approved"),
    },
    {
      mirrors: "grant/utils.ts › toOpenPaymentsGrant: `subject` of a finished subject grant",
      name: "a subject grant continues with the subject and without an access token",
      act: async (h) => {
        const subject = { sub_ids: [{ id: `${WALLET}/alice`, format: "uri" as const }] };
        const s = await approved(h, { access: [], subject });

        return continueRequest(h, s.continueUri, {
          body: { interact_ref: s.grant.interactRef },
          token: s.continueToken,
        });
      },
      expected: async (response) => {
        expect(response.status).toBe(200);
        expect(await jsonBody(response)).toEqual({
          continue: { access_token: { value: expect.any(String) }, uri: expect.stringContaining("/continue/") },
          subject: { sub_ids: [{ id: `${WALLET}/alice`, format: "uri" as const }] },
        });
      },
    },
    {
      mirrors: "signature/middleware.test.ts › Validate grant continuation request with middleware (wallet address)",
      name: "continuation signed by the wallet address's key",
      act: async (h) => {
        const s = await approved(h);

        return continueRequest(h, s.continueUri, {
          body: { interact_ref: s.grant.interactRef },
          token: s.continueToken,
        });
      },
      expected: async (response) => expect(response.status).toBe(200),
    },
  ]);
});

const outgoingItem: AccessItem = {
  type: "outgoing-payment",
  actions: ["create", "read"],
  identifier: WALLET,
  limits: { debitAmount: { value: "1000", assetCode: "USD", assetScale: 2 } },
};

describe("token routes (accessToken/routes.test.ts)", () => {
  const issued = async (h: ServerHarness, grant: Partial<GrantRecord> = {}, token: Partial<TokenRecord> = {}) => {
    const s = await seedGrant(h, { state: "FINALIZED", access: [outgoingItem], ...grant });

    return { ...s, token: await seedToken(h, s.grant, token) };
  };

  const introspectCall = (h: ServerHarness, body: unknown) =>
    h.call(new Request(`${BASE_URL}/introspect`, json("POST", body)));

  const allowIntrospection: HarnessOptions = { introspection: { authorize: () => Effect.succeed(true) } };

  describe("Introspect", () => {
    runCases([
      {
        mirrors: "accessToken/routes.test.ts › Introspect › Cannot introspect fake token",
        name: "unknown token is inactive",
        options: allowIntrospection,
        act: (h) => introspectCall(h, { access_token: "fake" }),
        expected: async (response) => {
          expect(response.status).toBe(200);
          expect(await jsonBody(response)).toEqual({ active: false });
        },
      },
      {
        mirrors: "accessToken/routes.test.ts › Introspect › Successfully introspects valid token",
        name: "active token: grant, access, client",
        options: allowIntrospection,
        act: async (h) => introspectCall(h, { access_token: (await issued(h)).token.value }),
        expected: async (response) => {
          expect(response.status).toBe(200);
          // Without `access` in the request, Rafiki reports none (see the cases below for requested access).
          expect(await jsonBody(response)).toEqual({
            active: true,
            grant: expect.any(String),
            access: [],
            client: { walletAddress: WALLET },
          });
        },
      },
      {
        mirrors: "accessToken/routes.test.ts › Introspect › Successfully introspects expired token",
        name: "expired token is inactive",
        options: allowIntrospection,
        act: async (h) => {
          const { token } = await issued(h, {}, { expiresAt: h.clock.now().getTime() - 1 });

          return introspectCall(h, { access_token: token.value });
        },
        expected: async (response) => expect(await jsonBody(response)).toEqual({ active: false }),
      },
      {
        mirrors: "accessToken/routes.test.ts › Introspect › Successfully introspects token with correct access",
        name: "requested access that the grant covers",
        options: allowIntrospection,
        act: async (h) => introspectCall(h, { access_token: (await issued(h)).token.value, access: [outgoingItem] }),
        expected: async (response) =>
          expect(await jsonBody(response)).toMatchObject({ active: true, access: [outgoingItem] }),
      },
      {
        mirrors: "accessToken/routes.test.ts › Introspect › Successfully introspects token with partial access",
        name: "requested access that is a subset of the grant's",
        options: allowIntrospection,
        act: async (h) =>
          introspectCall(h, {
            access_token: (await issued(h)).token.value,
            access: [{ ...outgoingItem, actions: ["read"] }],
          }),
        expected: async (response) =>
          expect(await jsonBody(response)).toMatchObject({ active: true, access: [outgoingItem] }),
      },
      {
        mirrors:
          "accessToken/routes.test.ts › Introspect › Only returns requested access during successful introspection",
        name: "only the requested item of several",
        options: allowIntrospection,
        act: async (h) => {
          const { token } = await issued(h, { access: [outgoingItem, { type: "quote", actions: ["create", "read"] }] });

          return introspectCall(h, {
            access_token: token.value,
            access: [{ type: "quote", actions: ["create", "read"] }],
          });
        },
        expected: async (response) =>
          expect(await jsonBody(response)).toMatchObject({
            active: true,
            access: [{ type: "quote", actions: ["create", "read"] }],
          }),
      },
      {
        mirrors: "accessToken/routes.test.ts › Introspect › Has empty access for token with incorrect access",
        name: "requested access the grant does not cover",
        options: allowIntrospection,
        act: async (h) =>
          introspectCall(h, {
            access_token: (await issued(h)).token.value,
            access: [{ type: "incoming-payment", actions: ["read-all"], identifier: WALLET }],
          }),
        expected: async (response) =>
          expect(await jsonBody(response)).toMatchObject({
            active: true,
            access: [],
            client: { walletAddress: WALLET },
          }),
      },
      {
        mirrors:
          "accessToken/routes.test.ts › Introspect › Throws 500 error when introspecting token for grant with no client identity",
        name: "grant without client identity is a 500",
        options: { ...allowIntrospection, unvalidated: true },
        act: async (h) =>
          introspectCall(h, { access_token: (await issued(h, { client: null, jwk: null })).token.value }),
        expected: async (response) => expect(response.status).toBe(500),
      },
      {
        mirrors: "accessToken/routes.test.ts › Introspect › Successfully introspects token for JWK-based grant",
        name: "JWK client",
        options: allowIntrospection,
        act: async (h) => {
          const jwk = clientJwk(h.clientKey);

          return introspectCall(h, { access_token: (await issued(h, { client: null, jwk })).token.value });
        },
        expected: async (response, h) =>
          expect(await jsonBody(response)).toMatchObject({ active: true, client: { jwk: clientJwk(h.clientKey) } }),
      },
      {
        // Rafiki serves introspection on its own port without authentication (network isolation); here it is opt-in.
        mirrors: "RFC 9767 §3.5; Rafiki has no introspection auth, opt-in via `introspection.authorize` here",
        name: "introspection not enabled",
        deviation: "Introspection endpoint",
        options: { unvalidated: true },
        act: (h) => introspectCall(h, { access_token: "any" }),
        expected: error(404, "invalid_request", "not found"),
      },
      {
        mirrors: "RFC 9767 §3.5; Rafiki has no introspection auth, opt-in via `introspection.authorize` here",
        name: "caller refused by the authorize hook",
        deviation: "Introspection endpoint",
        options: { introspection: { authorize: () => Effect.succeed(false) }, unvalidated: true },
        act: (h) => introspectCall(h, { access_token: "any" }),
        expected: error(400, "invalid_resource_server", "introspection not authorized"),
      },
      {
        mirrors: "accessToken/service.test.ts › Introspect › Can introspect active token for revoked grant",
        name: "a token of a revoked grant is inactive",
        options: allowIntrospection,
        act: async (h) => introspectCall(h, { access_token: (await issued(h, { state: "REVOKED" })).token.value }),
        expected: async (response) => expect(await jsonBody(response)).toEqual({ active: false }),
      },
      {
        mirrors: "accessToken/service.test.ts › Introspect › Cannot introspect rotated access token",
        name: "a rotated-away token is inactive",
        options: allowIntrospection,
        act: async (h) => {
          const { token } = await issued(h);

          await h.signedCall(token.manage, withToken({ method: "POST" }, token.value));

          return introspectCall(h, { access_token: token.value });
        },
        expected: async (response) => expect(await jsonBody(response)).toEqual({ active: false }),
      },
    ]);
  });

  describe("Revocation", () => {
    runCases([
      {
        mirrors: "accessToken/routes.test.ts › Revocation › Returns status 204 if token has not expired",
        name: "DELETE revokes the token",
        act: async (h) => {
          const { token } = await issued(h);
          const response = await h.signedCall(token.manage, withToken({ method: "DELETE" }, token.value));

          expect(await Effect.runPromise(h.server.introspectToken(token.value))).toEqual({ active: false });

          return response;
        },
        expected: async (response) => {
          expect(response.status).toBe(204);
          expect(await response.text()).toBe("");
        },
      },
      {
        mirrors: "accessToken/routes.test.ts › Revocation › Returns status 204 if token has expired",
        name: "DELETE of an expired token",
        act: async (h) => {
          const { token } = await issued(h, {}, { expiresAt: h.clock.now().getTime() - 1 });

          return h.signedCall(token.manage, withToken({ method: "DELETE" }, token.value));
        },
        expected: async (response) => expect(response.status).toBe(204),
      },
      {
        // wire: a revoked token's management id is unknown to Rafiki's tokenHttpsigMiddleware.
        mirrors: "accessToken/routes.test.ts › Revocation › Returns status 204 even if token does not exist (wire)",
        name: "DELETE of an already revoked token",
        act: async (h) => {
          const { token } = await issued(h);

          await h.signedCall(token.manage, withToken({ method: "DELETE" }, token.value));

          return h.signedCall(token.manage, withToken({ method: "DELETE" }, token.value));
        },
        expected: error(401, "invalid_client", "invalid access token"),
      },
      {
        // wire: a rotated token's management id is unknown to Rafiki's tokenHttpsigMiddleware.
        mirrors: "accessToken/service.test.ts › Revoke › Revoke by token id › Cannot revoke rotated access token",
        name: "DELETE of the management URL of a rotated token",
        act: async (h) => {
          const { token } = await issued(h);

          await h.signedCall(token.manage, withToken({ method: "POST" }, token.value));

          return h.signedCall(token.manage, withToken({ method: "DELETE" }, token.value));
        },
        expected: error(401, "invalid_client", "invalid access token"),
      },
      {
        mirrors:
          "accessToken/routes.test.ts › Revocation › Returns status 204 if token has not expired (token not presented)",
        name: "DELETE with another token than the managed one",
        // Rafiki's tokenHttpsigMiddleware checks the signature only; RFC 9635 §6 has the token authorise its own management.
        deviation: "Token management",
        act: async (h) => {
          const { token } = await issued(h);

          return h.signedCall(token.manage, withToken({ method: "DELETE" }, "another-token"));
        },
        expected: error(401, "invalid_client", "invalid access token"),
      },
    ]);
  });

  describe("Rotation", () => {
    runCases([
      {
        mirrors: "accessToken/routes.test.ts › Rotation › Can rotate token",
        name: "POST rotates: new token, old one revoked",
        act: async (h) => {
          const { token } = await issued(h);
          const response = await h.signedCall(token.manage, withToken({ method: "POST" }, token.value));

          expect(await Effect.runPromise(h.server.introspectToken(token.value))).toEqual({ active: false });

          return response;
        },
        expected: async (response, h) => {
          const body = await jsonBody<{ access_token: { value: string } }>(response);

          expect(response.status).toBe(200);
          expect(body).toEqual({
            access_token: {
              value: expect.any(String),
              manage: expect.stringMatching(`^${BASE_URL}/token/`),
              access: [outgoingItem],
              expires_in: 600,
            },
          });

          expect(await Effect.runPromise(h.server.introspectToken(body.access_token.value))).toMatchObject({
            active: true,
          });
        },
      },
      {
        mirrors: "accessToken/routes.test.ts › Rotation › Can rotate an expired token",
        name: "POST rotates an expired token",
        act: async (h) => {
          const { token } = await issued(h, {}, { expiresAt: h.clock.now().getTime() - 1 });

          return h.signedCall(token.manage, withToken({ method: "POST" }, token.value));
        },
        expected: async (response) => expect(response.status).toBe(200),
      },
      {
        // Rafiki serialises rotations with a row lock on the grant; here the revocation of the old token is the claim.
        mirrors: "accessToken/routes.test.ts › Rotation › Locks grant during token rotation",
        name: "concurrent rotations: exactly one wins, one token stays active",
        act: async (h) => {
          const { token } = await issued(h);
          const rotate = () => h.signedCall(token.manage, withToken({ method: "POST" }, token.value));
          const responses = await Promise.all([rotate(), rotate()]);

          // The loser either lost the claim (404 invalid_rotation) or was already refused (401).
          const losers = await Promise.all(responses.filter((r) => r.status !== 200).map(errorOf));

          expect(responses.filter((r) => r.status === 200)).toHaveLength(1);
          expect(losers).toHaveLength(1);
          expect(losers[0]?.code === "invalid_rotation" || losers[0]?.code === "invalid_client").toBe(true);

          return responses.find((r) => r.status === 200) ?? responses[0] ?? new Response(null, { status: 500 });
        },
        expected: async (response) => expect(response.status).toBe(200),
      },
      {
        mirrors: "accessToken/routes.test.ts › Rotation › Returns status 404 if could not rotate token",
        name: "a rotation that cannot claim the old token is a 404 invalid_rotation",
        options: {
          store: (() => {
            const inner = memoryGnapStore();
            let first = true;

            return {
              ...inner,
              revokeTokens: (by: "id" | "grantId", value: string, at: number) => {
                if (by !== "id" || !first) return inner.revokeTokens(by, value, at);
                first = false;

                return Effect.succeed(0);
              },
            };
          })(),
        },
        act: async (h) => {
          const { token } = await issued(h);

          return h.signedCall(token.manage, withToken({ method: "POST" }, token.value));
        },
        expected: error(404, "invalid_rotation", "invalid access token"),
      },
    ]);
  });
});

/** The harness client's key does not match: a different key under the same `keyid`. */
const wrongKey = async () => (await createClientKey(KEY_ID)).signingKey;

describe("signature middleware (signature/middleware.test.ts)", () => {
  runCases([
    {
      mirrors: "signature/middleware.test.ts › Validate grant initiation request with middleware (wallet address)",
      name: "grant request signed by the wallet address's key",
      act: (h) => post(h, grantBody([incoming])),
      expected: async (response) => expect(response.status).toBe(200),
    },
    {
      mirrors: "signature/middleware.test.ts › Validate grant initiation request with middleware (JWK)",
      name: "grant request signed by the inline JWK",
      act: (h) => post(h, { client: { jwk: clientJwk(h.clientKey) }, access_token: { access: [incoming] } }),
      expected: async (response) => expect(response.status).toBe(200),
    },
    {
      mirrors:
        "signature/middleware.test.ts › Validate grant continuation request with middleware (wallet address / JWK)",
      name: "continuation signed by a JWK grant's key",
      act: async (h) => {
        const s = await seedGrant(h, { state: "APPROVED", client: null, jwk: clientJwk(h.clientKey), finishUri: null });

        return continueRequest(h, s.continueUri, { token: s.continueToken });
      },
      expected: async (response) => expect(response.status).toBe(200),
    },
    {
      mirrors: "signature/middleware.test.ts › Validate token management request with middleware",
      name: "token management signed by the grant's client",
      act: async (h) => {
        const s = await seedGrant(h, { state: "FINALIZED" });
        const token = await seedToken(h, s.grant);

        return h.signedCall(token.manage, withToken({ method: "POST" }, token.value));
      },
      expected: async (response) => expect(response.status).toBe(200),
    },
    {
      mirrors: "signature/middleware.test.ts › token management request fails if grant cannot be found",
      name: "token management for an unknown management id",
      act: (h) => h.signedCall(`${BASE_URL}/token/${crypto.randomUUID()}`, withToken({ method: "POST" }, "any")),
      expected: error(401, "invalid_client", "invalid access token"),
    },
    {
      mirrors: "signature/middleware.test.ts › httpsig middleware fails if headers are invalid",
      name: "unsigned grant request",
      act: (h) => h.call(new Request(h.baseUrl, json("POST", grantBody([incoming])))),
      expected: error(401, "invalid_client", "invalid signature headers"),
    },
    {
      mirrors: "signature/middleware.test.ts › middleware fails if signature is invalid",
      name: "signature by another key with the same keyid",
      act: async (h) => h.signedCall(h.baseUrl, json("POST", grantBody([incoming])), await wrongKey()),
      expected: error(401, "invalid_client", "invalid signature"),
    },
    {
      mirrors: "signature/middleware.test.ts › middleware fails if grant is revoked",
      name: "continuation of a revoked grant",
      act: async (h) => {
        const s = await seedGrant(h, { state: "REVOKED" });

        return continueRequest(h, s.continueUri, { token: s.continueToken });
      },
      expected: error(401, "invalid_continuation", "invalid grant"),
    },
    {
      mirrors: "signature/middleware.test.ts › middleware fails if client is invalid",
      name: "a keyid the client does not publish",
      act: async (h) =>
        h.signedCall(h.baseUrl, json("POST", grantBody([incoming])), (await createClientKey("other-kid")).signingKey),
      expected: error(400, "invalid_client", "could not determine client"),
    },
    {
      mirrors: "signature/middleware.test.ts › grant continuation middleware fails if grant has no client identity",
      name: "continuation of a grant without identity",
      options: { unvalidated: true },
      act: async (h) => {
        const s = await seedGrant(h, { client: null, jwk: null });

        return continueRequest(h, s.continueUri, { token: s.continueToken });
      },
      expected: error(500, "request_denied", "internal server error"),
    },
    {
      mirrors: "signature/middleware.test.ts › token management middleware fails if grant has no client identity",
      name: "token management of a grant without identity",
      options: { unvalidated: true },
      act: async (h) => {
        const s = await seedGrant(h, { state: "FINALIZED", client: null, jwk: null });
        const token = await seedToken(h, s.grant);

        return h.signedCall(token.manage, withToken({ method: "POST" }, token.value));
      },
      expected: error(500, "request_denied", "internal server error"),
    },
    {
      mirrors: "signature/middleware.test.ts › middleware fails if content-digest is invalid",
      name: "body changed after signing",
      act: async (h) => {
        const { signRequest } = await import("../../src/http-signatures/index");

        const signed = await Effect.runPromise(
          signRequest(new Request(h.baseUrl, json("POST", grantBody([incoming]))), h.clientKey.signingKey),
        );

        return h.call(
          new Request(signed, { method: "POST", body: JSON.stringify(grantBody([outgoing], { interact })) }),
        );
      },
      expected: error(401, "invalid_client", "invalid signature headers"),
    },
  ]);
});

describe("interaction routes", () => {
  const finishUrl = (params: Record<string, string>): string => {
    const url = new URL(FINISH_URI);

    for (const [name, value] of Object.entries(params)) url.searchParams.set(name, value);

    return url.toString();
  };

  const location = (response: Response): string => response.headers.get("location") ?? "";

  const startOf = (h: ServerHarness, s: Pending) => h.call(new Request(s.interactUrl, { redirect: "manual" }));

  describe("Client - interaction start (interaction/routes.test.ts)", () => {
    runCases([
      {
        mirrors:
          "interaction/routes.test.ts › Client - interaction start › Interaction start fails if tenant for finishable grant has no configured idp",
        name: "no consent page configured, finishable grant: the client is told on its finish URI",
        options: { without: ["interaction"] },
        act: async (h) => startOf(h, await seedGrant(h)),
        expected: async (response) => {
          expect(response.status).toBe(302);
          expect(location(response)).toBe(`${FINISH_URI}?result=request_denied&message=internal+server+error`);
        },
      },
      {
        mirrors:
          "interaction/routes.test.ts › Client - interaction start › Interaction start fails if tenant for unfinishable grant has no configured idp",
        name: "no consent page configured, unfinishable grant",
        options: { without: ["interaction"] },
        act: async (h) => startOf(h, await seedGrant(h, { finishUri: null, clientNonce: null })),
        expected: error(500, "request_denied", "internal server error"),
      },
      {
        mirrors:
          "interaction/routes.test.ts › Client - interaction start › Interaction start fails if interaction is invalid",
        name: "unknown interaction id",
        act: async (h) => {
          const s = await seedGrant(h);

          return h.call(new Request(`${BASE_URL}/interact/${crypto.randomUUID()}/${s.nonce}`, { redirect: "manual" }));
        },
        expected: error(400, "unknown_interaction", "unknown interaction"),
      },
      {
        mirrors:
          "interaction/routes.test.ts › Client - interaction start › Interaction start fails if finishable grant is revoked",
        name: "revoked, finishable grant",
        act: async (h) => startOf(h, await seedGrant(h, { state: "REVOKED" })),
        expected: async (response) => {
          expect(response.status).toBe(302);
          expect(location(response)).toBe(`${FINISH_URI}?result=invalid_interaction&message=invalid+interaction`);
        },
      },
      {
        mirrors:
          "interaction/routes.test.ts › Client - interaction start › Interaction start fails if unfinishable grant is revoked",
        name: "revoked, unfinishable grant",
        act: async (h) => startOf(h, await seedGrant(h, { state: "REVOKED", finishUri: null, clientNonce: null })),
        expected: error(403, "invalid_interaction", "invalid interaction"),
      },
      {
        mirrors: "interaction/routes.test.ts › Client - interaction start › Can start an interaction",
        name: "forwards to the consent page and binds the browser with a session cookie",
        act: async (h) => startOf(h, await seedGrant(h)),
        expected: async (response) => {
          const url = new URL(location(response));

          expect(response.status).toBe(302);
          expect(`${url.origin}${url.pathname}`).toBe("https://app.test/consent");
          expect(Object.keys(Object.fromEntries(url.searchParams))).toEqual([
            "interactId",
            "nonce",
            "clientName",
            "clientUri",
          ]);
          expect(url.searchParams.get("clientUri")).toBe(WALLET);
          expect(new Set((response.headers.get("set-cookie") ?? "").split("; "))).toEqual(
            new Set([
              `gnap-interaction-${SEED.interactId}=${SEED.nonce}`,
              `Path=/gnap/interact/${SEED.interactId}`,
              "Max-Age=600",
              "HttpOnly",
              "SameSite=Lax",
              "Secure",
            ]),
          );
        },
      },
      {
        // Rafiki's `markPending` write is its only failure point; here a started interaction needs no write.
        mirrors:
          "interaction/routes.test.ts › Client - interaction start › handles unexpected error for $description grant",
        name: "a failing grant write does not matter: starting writes nothing",
        deviation: "Interaction start",
        options: { store: dying({ updateGrant: () => Effect.die(new Error("db down")) }) },
        act: async (h) => startOf(h, await seedGrant(h)),
        expected: async (response) => {
          expect(response.status).toBe(302);
          expect(location(response)).toContain("https://app.test/consent");
        },
      },
      {
        // Rafiki ignores the age of the interaction at start (it checks at finish and at the identity provider).
        mirrors: "interaction/routes.ts › startInteraction: no expiry check",
        name: "starting an expired interaction",
        deviation: "Interaction start",
        act: async (h) => startOf(h, await seedGrant(h, { interactExpiresAt: h.clock.now().getTime() - 1 })),
        expected: async (response) => {
          expect(response.status).toBe(302);
          expect(location(response)).toBe(`${FINISH_URI}?result=invalid_interaction&message=invalid+interaction`);
        },
      },
      {
        // Rafiki puts the `clientName` / `clientUri` of the start URL's query on the consent URL, which anybody can edit.
        mirrors:
          "interaction/routes.test.ts › Client - interaction start › Can start an interaction (query clientName, clientUri)",
        name: "clientName and clientUri come from the grant, not from the query",
        deviation: "Wallet address document",
        act: async (h) => {
          const s = await seedGrant(h);

          return h.call(
            new Request(`${s.interactUrl}?clientName=Test+Client&clientUri=https://example.com`, {
              redirect: "manual",
            }),
          );
        },
        expected: async (response) => {
          const url = new URL(location(response));

          expect(url.searchParams.get("clientName")).toBe("wallet.test");
          expect(url.searchParams.get("clientUri")).toBe(WALLET);
        },
      },
    ]);
  });

  describe("Client - interaction complete (interaction/routes.test.ts)", () => {
    /** Finishes `s` the way the browser does: with the cookie `start` handed out (or `cookie` when given). */
    const finish = async (h: ServerHarness, s: Pending, cookie?: string) =>
      browserFinish(h, s, cookie ?? `gnap-interaction-${s.interactId}=${s.nonce}`);

    const base64Hash = async (data: string): Promise<string> =>
      btoa(
        String.fromCharCode(...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data)))),
      );

    runCases([
      {
        mirrors: "interaction/routes.test.ts › cannot finish interaction with missing id",
        name: "missing interaction id",
        act: async (h) => {
          const s = await seedGrant(h, { state: "APPROVED" });

          return h.call(new Request(`${BASE_URL}/interact//${s.nonce}/finish`, { redirect: "manual" }));
        },
        expected: error(404, "unknown_interaction", "unknown interaction"),
      },
      {
        mirrors: "interaction/routes.test.ts › Cannot finish interaction with invalid session",
        name: "session of another interaction",
        act: async (h) => finish(h, await seedGrant(h, { state: "APPROVED" }), "gnap-interaction-other=x"),
        expected: error(401, "invalid_request", "invalid session"),
      },
      {
        mirrors: "interaction/routes.test.ts › Cannot finish interaction with invalid session (wrong nonce in session)",
        name: "session with another nonce",
        act: async (h) => {
          const s = await seedGrant(h, { state: "APPROVED" });

          return finish(h, s, `gnap-interaction-${s.interactId}=other`);
        },
        expected: error(401, "invalid_request", "invalid session"),
      },
      {
        mirrors: "interaction/routes.test.ts › Cannot finish interaction with invalid session (wrong nonce in session)",
        name: "session nonce of the right length differing only in its first character",
        act: async (h) => {
          const s = await seedGrant(h, { state: "APPROVED" });

          return finish(h, s, `gnap-interaction-${s.interactId}=x${SEED.nonce.slice(1)}`);
        },
        expected: error(401, "invalid_request", "invalid session"),
      },
      {
        mirrors: "interaction/routes.test.ts › Cannot finish interaction that does not exist",
        name: "unknown interaction",
        act: async (h) => {
          const s = await seedGrant(h, { state: "APPROVED" });

          return browserFinish(
            h,
            { ...s.pending, interactId: crypto.randomUUID() },
            `gnap-interaction-${s.interactId}=${s.nonce}`,
          );
        },
        expected: error(404, "unknown_interaction", "unknown interaction"),
      },
      {
        mirrors:
          "interaction/routes.test.ts › Interactions for grant with finish method › Can finish accepted interaction",
        name: "finishable + accepted: grant approved, redirect with interact_ref and Rafiki's padded base64 hash",
        act: async (h) => {
          const s = await seedGrant(h, { state: "ACCEPTED" });
          const response = await finish(h, s);

          expect((await grantOf(h, s.grant.id)).state).toBe("APPROVED");

          return response;
        },
        expected: async (response) => {
          const back = new URL(location(response));

          expect(response.status).toBe(302);
          expect(back.origin + back.pathname).toBe(FINISH_URI);
          expect(back.searchParams.get("interact_ref")).toBe(SEED.interactRef);
          expect(back.searchParams.get("hash")).toBe(
            await base64Hash(`client-nonce\n${SEED.nonce}\n${SEED.interactRef}\n${BASE_URL}`),
          );
        },
      },
      {
        mirrors:
          "interaction/routes.test.ts › Interactions for grant with finish method › Can finish rejected interaction",
        name: "finishable + denied: grant rejected",
        act: async (h) => {
          const s = await seedGrant(h, { state: "DENIED" });
          const response = await finish(h, s);

          expect((await grantOf(h, s.grant.id)).state).toBe("REJECTED");

          return response;
        },
        expected: async (response) => expect(location(response)).toBe(finishUrl({ result: "grant_rejected" })),
      },
      {
        mirrors:
          "interaction/routes.test.ts › Interactions for grant with finish method › Cannot finish invalid interaction",
        name: "finishable + still pending",
        act: async (h) => finish(h, await seedGrant(h)),
        expected: async (response) => expect(location(response)).toBe(finishUrl({ result: "grant_invalid" })),
      },
      {
        mirrors:
          "interaction/routes.test.ts › Interactions for grant with finish method › Cannot finish interaction with revoked grant",
        name: "finishable + revoked",
        act: async (h) => finish(h, await seedGrant(h, { state: "REVOKED" })),
        expected: async (response) =>
          expect(location(response)).toBe(finishUrl({ result: "unknown_interaction", message: "unknown interaction" })),
      },
      {
        mirrors:
          "interaction/routes.test.ts › Interactions for grant with finish method › Cannot finish expired interaction",
        name: "finishable + expired",
        act: async (h) =>
          finish(h, await seedGrant(h, { state: "ACCEPTED", interactExpiresAt: h.clock.now().getTime() - 1 })),
        expected: async (response) =>
          expect(location(response)).toBe(finishUrl({ result: "invalid_interaction", message: "interaction expired" })),
      },
      {
        mirrors:
          "interaction/routes.test.ts › Interactions for grant without finish method › Can finish approved interaction",
        name: "unfinishable + accepted: 202, grant approved",
        act: async (h) => {
          const s = await seedGrant(h, { state: "ACCEPTED", finishUri: null, clientNonce: null });
          const response = await finish(h, s);

          expect((await grantOf(h, s.grant.id)).state).toBe("APPROVED");

          return response;
        },
        expected: async (response) => expect(response.status).toBe(202),
      },
      {
        mirrors:
          "interaction/routes.test.ts › Interactions for grant without finish method › Can finish rejected interaction",
        name: "unfinishable + denied: 202, grant rejected",
        act: async (h) => {
          const s = await seedGrant(h, { state: "DENIED", finishUri: null, clientNonce: null });
          const response = await finish(h, s);

          expect((await grantOf(h, s.grant.id)).state).toBe("REJECTED");

          return response;
        },
        expected: async (response) => expect(response.status).toBe(202),
      },
      {
        mirrors:
          "interaction/routes.test.ts › Interactions for grant without finish method › Cannot finish invalid interaction",
        name: "unfinishable + still pending",
        act: async (h) => finish(h, await seedGrant(h, { finishUri: null, clientNonce: null })),
        expected: error(401, "invalid_interaction", "interaction is not active"),
      },
      {
        mirrors:
          "interaction/routes.test.ts › Interactions for grant without finish method › Cannot finish interaction with revoked grant",
        name: "unfinishable + revoked",
        act: async (h) => finish(h, await seedGrant(h, { state: "REVOKED", finishUri: null, clientNonce: null })),
        expected: error(404, "unknown_interaction", "unknown interaction"),
      },
      {
        mirrors:
          "interaction/routes.test.ts › Interactions for grant without finish method › Cannot finish expired interaction",
        name: "unfinishable + expired",
        act: async (h) =>
          finish(
            h,
            await seedGrant(h, {
              state: "ACCEPTED",
              finishUri: null,
              clientNonce: null,
              interactExpiresAt: h.clock.now().getTime() - 1,
            }),
          ),
        expected: error(401, "invalid_interaction", "interaction expired"),
      },
      {
        mirrors: "interaction/routes.ts › handleFinishableGrant: approve() on an already finalized grant",
        name: "finishing again redirects again but does not reopen a finalized grant",
        deviation: "Repeated finish",
        act: async (h) => {
          const s = await seedGrant(h, { state: "FINALIZED" });
          const response = await finish(h, s);

          expect((await grantOf(h, s.grant.id)).state).toBe("FINALIZED");

          return response;
        },
        expected: async (response) => {
          expect(response.status).toBe(302);
          expect(new URL(location(response)).searchParams.get("interact_ref")).toBe(SEED.interactRef);
        },
      },
    ]);
  });

  describe("IDP - Grant details (interaction/routes.test.ts)", () => {
    const details = (h: ServerHarness, s: Pending, secret: string | null = "idp-secret") =>
      h.call(
        new Request(`${BASE_URL}/grant/${s.interactId}/${s.nonce}`, {
          headers: secret === null ? {} : { "x-idp-secret": secret },
        }),
      );

    runCases([
      {
        mirrors: "interaction/routes.test.ts › IDP - Grant details › Can get grant details",
        name: "grant id, access, state",
        act: async (h) => details(h, await seedGrant(h)),
        expected: async (response, h) => {
          const body = await jsonBody<{ grantId: string }>(response);

          expect(response.status).toBe(200);
          expect(body).toEqual({ grantId: expect.any(String), access: [accessItem], state: "PENDING" });
          expect((await grantOf(h, body.grantId)).state).toBe("PENDING");
        },
      },
      {
        mirrors:
          "interaction/routes.test.ts › IDP - Grant details › Cannot get grant details for nonexistent interaction",
        name: "unknown interaction",
        act: async (h) => {
          const s = await seedGrant(h);

          return details(h, { ...s.pending, interactId: crypto.randomUUID() });
        },
        expected: error(404, "unknown_interaction", "unknown interaction"),
      },
      {
        mirrors: "interaction/routes.test.ts › IDP - Grant details › Cannot get grant details for revoked grant",
        name: "revoked grant",
        act: async (h) => details(h, await seedGrant(h, { state: "REVOKED" })),
        expected: error(404, "unknown_interaction", "unknown interaction"),
      },
      {
        mirrors: "interaction/routes.test.ts › IDP - Grant details › Cannot get grant details without secret",
        name: "no x-idp-secret",
        act: async (h) => details(h, await seedGrant(h), null),
        expected: error(401, "invalid_request", "invalid x-idp-secret"),
      },
      {
        mirrors: "interaction/routes.test.ts › IDP - Grant details › Cannot get grant details with invalid secret",
        name: "wrong x-idp-secret",
        act: async (h) => details(h, await seedGrant(h), "wrong-secret"),
        expected: error(401, "invalid_request", "invalid x-idp-secret"),
      },
      {
        mirrors: "interaction/routes.test.ts › IDP - Grant details › Cannot get grant details with invalid secret",
        name: "x-idp-secret of the right length differing only in its first character",
        act: async (h) => details(h, await seedGrant(h), `x${IDP_SECRET.slice(1)}`),
        expected: error(401, "invalid_request", "invalid x-idp-secret"),
      },
      {
        mirrors: "interaction/routes.test.ts › IDP - Grant details › Can get grant details (with a subject)",
        name: "grant details of a subject grant",
        act: async (h) => {
          const subject = { sub_ids: [{ id: `${WALLET}/alice`, format: "uri" as const }] };

          return details(h, await seedGrant(h, { access: [], subject }));
        },
        expected: async (response) =>
          expect(await jsonBody(response)).toEqual({
            grantId: expect.any(String),
            access: [],
            subject: { sub_ids: [{ id: `${WALLET}/alice`, format: "uri" as const }] },
            state: "PENDING",
          }),
      },
    ]);
  });

  describe("IDP - accept/reject interaction (interaction/routes.test.ts)", () => {
    runCases([
      {
        mirrors:
          "interaction/routes.test.ts › IDP - accept/reject interaction › cannot accept/reject interaction with unconfigured tenant",
        name: "no idpSecret configured: the back channel is off",
        options: { without: ["idpSecret"] },
        act: async (h) => idp(h, await seedGrant(h), "accept"),
        expected: error(404, "unknown_interaction", "unknown interaction"),
      },
      {
        mirrors:
          "interaction/routes.test.ts › IDP - accept/reject interaction › cannot accept/reject interaction without secret",
        name: "no x-idp-secret",
        act: async (h) => {
          const s = await seedGrant(h);

          return h.call(new Request(`${BASE_URL}/grant/${s.interactId}/${s.nonce}/accept`, { method: "POST" }));
        },
        expected: error(401, "invalid_interaction", "invalid x-idp-secret"),
      },
      {
        mirrors:
          "interaction/routes.test.ts › IDP - accept/reject interaction › cannot accept/reject interacetion with invalid secret",
        name: "wrong x-idp-secret",
        act: async (h) => idp(h, await seedGrant(h), "accept", "wrong"),
        expected: error(401, "invalid_interaction", "invalid x-idp-secret"),
      },
      {
        mirrors: "interaction/routes.test.ts › IDP - accept/reject interaction › can accept interaction",
        name: "accept: 202, interaction approved (the grant is approved when finish is reached)",
        act: async (h) => {
          const s = await seedGrant(h);
          const response = await idp(h, s, "accept");

          expect((await grantOf(h, s.grant.id)).state).toBe("ACCEPTED");

          return response;
        },
        expected: async (response) => {
          expect(response.status).toBe(202);
          expect(await response.text()).toBe("");
        },
      },
      {
        mirrors:
          "interaction/routes.test.ts › IDP - accept/reject interaction › Cannot accept or reject grant if grant does not exist",
        name: "unknown interaction",
        act: async (h) => {
          const s = await seedGrant(h);

          return idp(h, { ...s.pending, interactId: crypto.randomUUID() }, "accept");
        },
        expected: error(404, "unknown_interaction", "unknown interaction"),
      },
      {
        mirrors: "interaction/routes.test.ts › IDP - accept/reject interaction › Can reject grant",
        name: "reject: 202, interaction denied; a second decision is invalid",
        act: async (h) => {
          const s = await seedGrant(h);
          const response = await idp(h, s, "reject");

          expect((await grantOf(h, s.grant.id)).state).toBe("DENIED");
          expect(await errorOf(await idp(h, s, "accept"))).toEqual(
            error(400, "invalid_interaction", "invalid interaction"),
          );

          return response;
        },
        expected: async (response) => expect(response.status).toBe(202),
      },
      {
        mirrors: "interaction/routes.ts › handleInteractionChoice: finalized grant that was not issued",
        name: "deciding on a grant rejected at finish: user_denied",
        act: async (h) => idp(h, await seedGrant(h, { state: "REJECTED" }), "accept"),
        expected: error(401, "user_denied", "user denied interaction"),
      },
      {
        mirrors: "interaction/routes.test.ts › IDP - accept/reject interaction › Cannot make invalid grant choice",
        name: "choice other than accept/reject",
        act: async (h) => idp(h, await seedGrant(h), "maybe"),
        expected: error(400, "invalid_request", "invalid interaction choice"),
      },
      {
        mirrors: "interaction/routes.ts › handleInteractionChoice: 'invalid interaction' (not pending)",
        name: "deciding twice",
        act: async (h) => {
          const s = await seedGrant(h);

          await idp(h, s, "accept");

          return idp(h, s, "reject");
        },
        expected: error(400, "invalid_interaction", "invalid interaction"),
      },
      {
        mirrors: "interaction/routes.ts › handleInteractionChoice: expired interaction",
        name: "deciding after the interaction expired",
        act: async (h) => idp(h, await seedGrant(h, { interactExpiresAt: h.clock.now().getTime() - 1 }), "accept"),
        expected: error(400, "invalid_interaction", "invalid interaction"),
      },
    ]);
  });
});
