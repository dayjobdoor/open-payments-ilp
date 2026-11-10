/** Token management leaves no live token behind that nobody holds, and touches only the token it was asked about. */
import * as Effect from "effect/Effect";
import { describe, expect, it } from "vite-plus/test";
import { hashToken } from "../../src/gnap/index";
import { memoryGnapStore, type GnapStore } from "../../src/gnap/server/index";
import { createServerHarness, json, jsonBody, seedGrant, seedToken, withToken } from "./support";

describe("token management", () => {
  it("of concurrent rotations of one token keeps exactly one live token of the grant: a loser revokes the one it stored", async () => {
    const inner = memoryGnapStore();
    const handed: string[] = [];

    const store: GnapStore = {
      ...inner,
      createToken: (token) => (handed.push(token.valueHash), inner.createToken(token)),
    };

    const h = await createServerHarness({ unvalidated: true, store });
    const { grant } = await seedGrant(h, {
      state: "FINALIZED",
      interactId: null,
      interactNonce: null,
      interactRef: null,
    });
    const seeded = await seedToken(h, grant);
    const rotate = () => h.signedCall(seeded.manage, withToken(json("POST"), seeded.value));
    const responses = await Promise.all([rotate(), rotate(), rotate()]);

    expect(responses.map((response) => response.status).toSorted()).toEqual([200, 404, 404]);

    const winner = await jsonBody<{ access_token: { value: string } }>(
      responses.find((response) => response.status === 200) ?? new Response("{}"),
    );

    const live: string[] = [];

    for (const valueHash of handed) {
      const found = await Effect.runPromise(store.findTokenWithGrant("valueHash", valueHash));

      if (found?.token.revokedAt === null) live.push(valueHash);
    }

    // The seeded token and the two that lost are revoked; what the winner returned is the only one left.
    expect(handed).toHaveLength(4);
    expect(live).toEqual([await Effect.runPromise(hashToken(winner.access_token.value))]);
  });

  it("revokes the token it was asked about and no other token of the grant", async () => {
    const h = await createServerHarness({ unvalidated: true });
    const { grant } = await seedGrant(h, {
      state: "FINALIZED",
      interactId: null,
      interactNonce: null,
      interactRef: null,
    });
    const [first, second] = [await seedToken(h, grant), await seedToken(h, grant)];

    expect((await h.signedCall(first.manage, withToken({ method: "DELETE" }, first.value))).status).toBe(204);

    const active = (token: { readonly value: string }) =>
      Effect.runPromise(h.server.introspectToken(token.value)).then((result) => result.active);

    expect([await active(first), await active(second)]).toEqual([false, true]);
  });
});
