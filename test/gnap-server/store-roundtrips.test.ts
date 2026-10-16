/**
 * What a request costs a database-backed store: every `GnapStore` call is a round trip on D1 or Postgres, so the
 * hot operations have a budget. Counted on calls, not on timing.
 */
import { describe, expect, it } from "vite-plus/test";
import { memoryGnapStore, type GnapStore } from "../../src/gnap/server/index";
import { SEED, createServerHarness, idp, json, seedGrant, withToken, type ServerHarness } from "./support";

/** Store calls spent by `act` alone (setup excluded) and the status it answered. */
const cost = async (
  seed: Parameters<typeof seedGrant>[1],
  act: (h: ServerHarness) => Promise<Response>,
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
    createGrant: tap(inner.createGrant),
    findGrant: tap(inner.findGrant),
    updateGrant: tap(inner.updateGrant),
    createToken: tap(inner.createToken),
    findTokenWithGrant: tap(inner.findTokenWithGrant),
    revokeTokens: tap(inner.revokeTokens),
    claimNonce: tap(inner.claimNonce),
  };

  const h = await createServerHarness({ store });

  await seedGrant(h, seed);
  counting = true;
  const response = await act(h);

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

  it("the identity provider's decision costs at most one read and one conditional write", async () => {
    const result = await cost({}, (h) => idp(h, { interactId: SEED.interactId, nonce: SEED.nonce }, "accept"));

    expect(result.status).toBe(202);
    expect(result.calls).toBeLessThanOrEqual(2);
  });
});
