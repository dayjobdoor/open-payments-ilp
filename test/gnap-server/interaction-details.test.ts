/** What the consent page may read about an interaction (`getInteraction`): only for the id and nonce of a live one. */
import * as Effect from "effect/Effect";
import { describe, expect, it } from "vite-plus/test";
import { SEED, createServerHarness, seedGrant } from "./support";

const details = (h: Awaited<ReturnType<typeof createServerHarness>>, nonce: string = SEED.nonce) =>
  Effect.runPromise(Effect.result(h.server.getInteraction({ interactId: SEED.interactId, nonce })));

describe("getInteraction", () => {
  it("shows what the owner decides on, and what was decided", async () => {
    const h = await createServerHarness({ unvalidated: true });
    const { grant } = await seedGrant(h, { state: "PENDING" });
    const shown = await details(h);

    expect(shown).toMatchObject({
      _tag: "Success",
      success: { grantId: grant.id, state: "PENDING", finish: true, client: grant.client, access: grant.access },
    });
  });

  it("answers 404 unknown_interaction for another nonce and for a revoked grant", async () => {
    const h = await createServerHarness({ unvalidated: true });

    await seedGrant(h, { state: "REVOKED" });

    for (const attempt of [await details(h, "another-nonce"), await details(h)]) {
      expect(attempt).toMatchObject({ _tag: "Failure", failure: { status: 404, code: "unknown_interaction" } });
    }
  });
});

describe("the identity provider's back channel", () => {
  it("is off for an empty idpSecret: an empty x-idp-secret decides nothing and reads nothing", async () => {
    const h = await createServerHarness({ unvalidated: true, idpSecret: "" });
    const { pending } = await seedGrant(h, { state: "PENDING" });
    const url = `${h.baseUrl}/grant/${pending.interactId}/${pending.nonce}`;
    const headers = { "x-idp-secret": "" };

    for (const request of [
      new Request(url, { headers }),
      new Request(`${url}/accept`, { method: "POST", headers }),
      new Request(`${url}/accept`, { method: "POST" }),
    ]) {
      expect((await h.call(request)).status).toBe(404);
    }

    expect(await Effect.runPromise(h.store.findGrant("id", SEED.id))).toMatchObject({ state: "PENDING" });
  });
});
