/**
 * What a request costs a database-backed store: every `GnapStore` call is a round trip on D1 or Postgres, so the
 * hot operations have a budget. Counted on calls, not on timing.
 */
import * as Effect from "effect/Effect";
import { describe, expect, it } from "vite-plus/test";
import { hashToken } from "../../src/gnap/index";
import { memoryGnapStore, type GnapStore, type GrantRecord } from "../../src/gnap/server/index";
import {
  SEED,
  browserFinish,
  createServerHarness,
  idp,
  json,
  seedGrant,
  seedToken,
  withToken,
  type ServerHarness,
} from "./support";

/** Runs `run` without its store calls being counted: the setup of an `act` that needs more than the seeded grant. */
type Setup = <Result>(run: () => Promise<Result>) => Promise<Result>;

/**
 * Store calls spent by `act` alone (the grant it is seeded with and what it sets up are excluded) and the status it
 * answered. The store has no optional capability unless `interactionBinding` says so.
 */
const cost = async (
  seed: Parameters<typeof seedGrant>[1],
  act: (h: ServerHarness, setup: Setup, grant: GrantRecord) => Promise<Response>,
  { interactionBinding = false }: { readonly interactionBinding?: boolean } = {},
): Promise<{ readonly status: number; readonly calls: number }> => {
  const inner = memoryGnapStore();
  let counting = false;
  let calls = 0;

  const tap =
    <Args extends ReadonlyArray<unknown>, Result>(method: (...args: Args) => Result) =>
    (...args: Args): Result => {
      if (counting) calls += 1;

      return method(...args);
    };

  const store: GnapStore = {
    ...(interactionBinding && { interactionBinding: true as const }),
    createGrant: tap(inner.createGrant),
    findGrant: tap(inner.findGrant),
    updateGrant: tap(inner.updateGrant),
    createToken: tap(inner.createToken),
    findTokenWithGrant: tap(inner.findTokenWithGrant),
    revokeTokens: tap(inner.revokeTokens),
    claimNonce: tap(inner.claimNonce),
  };

  const h = await createServerHarness({ store });

  const { grant } = await seedGrant(h, seed);

  counting = true;

  const setup: Setup = async (run) => {
    counting = false;

    try {
      return await run();
    } finally {
      counting = true;
    }
  };

  const response = await act(h, setup, grant);

  return { status: response.status, calls };
};

const approved = { state: "APPROVED", finishUri: null } as const;

/** Each answer must stay within its round-trip budget (a budget, not an exact count: fewer calls is fine). */
describe("store round trips per request", () => {
  it("continuing an approved grant costs at most one read, the token insert and one conditional write", async () => {
    const result = await cost(approved, (h) =>
      h.signedCall(`${h.baseUrl}/continue/${SEED.continueId}`, withToken(json("POST", {}), SEED.continueToken)),
    );

    expect(result.status).toBe(200);
    expect(result.calls).toBeLessThanOrEqual(3);
  });

  it("cancelling a grant costs at most one read, one conditional write and one revocation", async () => {
    const result = await cost(approved, (h) =>
      h.signedCall(`${h.baseUrl}/continue/${SEED.continueId}`, withToken(json("DELETE"), SEED.continueToken)),
    );

    expect(result.status).toBe(204);
    expect(result.calls).toBeLessThanOrEqual(3);
  });

  it("introspecting a token costs one read", async () => {
    const result = await cost(approved, async (h, setup, grant) => {
      const token = await setup(() => seedToken(h, grant));
      const answer = await Effect.runPromise(h.server.introspectToken(token.value));

      return new Response(null, { status: answer.active ? 200 : 404 });
    });

    expect(result.status).toBe(200);
    expect(result.calls).toBe(1);
  });

  it("rotating a token costs at most one read, the new token and one conditional write", async () => {
    const result = await cost(approved, async (h, setup, grant) => {
      const token = await setup(() => seedToken(h, grant));

      return h.signedCall(token.manage, withToken(json("POST"), token.value));
    });

    expect(result.status).toBe(200);
    expect(result.calls).toBeLessThanOrEqual(3);
  });

  it.each([
    ["without a binding", false, undefined],
    ["with a binding", true, "binding-secret"],
  ])(
    "the owner's browser reaching /finish %s costs at most one read and one conditional write",
    async (_name, binding, secret) => {
      const interactBinding =
        secret === undefined ? {} : { interactBinding: await Effect.runPromise(hashToken(secret)) };

      const result = await cost(
        { state: "ACCEPTED", ...interactBinding },
        (h) =>
          browserFinish(
            h,
            { interactId: SEED.interactId, nonce: SEED.nonce, interactUrl: "", continueUri: "", continueToken: "" },
            `gnap-interaction-${SEED.interactId}=${SEED.nonce}; gnap-binding-${SEED.interactId}=${secret ?? ""}`,
          ),
        { interactionBinding: binding },
      );

      expect(result.status).toBe(302);
      expect(result.calls).toBeLessThanOrEqual(2);
    },
  );

  it.each([
    ["without a binding", false, 1],
    ["with a binding", true, 2],
  ])("opening the interaction %s costs at most %i store calls", async (_name, binding, calls) => {
    const result = await cost(
      {},
      (h) => h.call(new Request(`${h.baseUrl}/interact/${SEED.interactId}/${SEED.nonce}`, { redirect: "manual" })),
      { interactionBinding: binding },
    );

    expect(result.status).toBe(302);
    expect(result.calls).toBeLessThanOrEqual(calls);
  });

  it("the identity provider's decision costs at most one read and one conditional write", async () => {
    const result = await cost({}, (h) => idp(h, { interactId: SEED.interactId, nonce: SEED.nonce }, "accept"));

    expect(result.status).toBe(202);
    expect(result.calls).toBeLessThanOrEqual(2);
  });
});
