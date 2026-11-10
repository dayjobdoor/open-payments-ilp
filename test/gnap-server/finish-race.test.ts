/** Two visits of the owner's browser to `/finish` race: the one that loses must not undo what the other led to. */
import * as Effect from "effect/Effect";
import { describe, expect, it } from "vite-plus/test";
import { memoryGnapStore, type GnapStore } from "../../src/gnap/server/index";
import {
  browserFinish,
  browserStart,
  continueWith,
  createServerHarness,
  errorOf,
  idp,
  jsonBody,
  startGrant,
  type Pending,
  type ServerHarness,
} from "./support";

/** Runs `beforeFirstWrite` once, between the moment a write of `state` is computed and the moment it is stored. */
const racingStore = (inner: GnapStore, state: string, beforeFirstWrite: () => Promise<void>): GnapStore => {
  let fired = false;

  return {
    ...inner,
    updateGrant: (id, version, patch) => {
      if (fired || patch.state !== state) return inner.updateGrant(id, version, patch);

      fired = true;

      return Effect.flatMap(Effect.promise(beforeFirstWrite), () => inner.updateGrant(id, version, patch));
    },
  };
};

describe("two visits to /finish race", () => {
  it("the loser does not move a grant the client has collected back to APPROVED, so its interact_ref stays single-use", async () => {
    let harness: ServerHarness | undefined;
    let pending: Pending | undefined;
    let cookie = "";
    let interactRef = "";
    let collected: Response | undefined;

    const store = racingStore(memoryGnapStore(), "APPROVED", async () => {
      if (harness === undefined || pending === undefined) throw new Error("race fired before the grant was started");

      // While this visit's move to APPROVED is on its way, another visit makes it and the client collects the tokens.
      const other = await browserFinish(harness, pending, cookie);

      interactRef = new URL(other.headers.get("location") ?? "").searchParams.get("interact_ref") ?? "";
      harness.clock.advance(60);
      collected = await continueWith(harness, pending, { interact_ref: interactRef });
    });

    harness = await createServerHarness({ unvalidated: true, store });
    pending = await startGrant(harness);
    cookie = (await browserStart(harness, pending)).cookie;

    expect((await idp(harness, pending, "accept")).status).toBe(202);

    const loser = await browserFinish(harness, pending, cookie);

    expect(collected?.status).toBe(200);
    expect(await jsonBody<{ access_token: unknown }>(collected ?? new Response("{}"))).toHaveProperty("access_token");
    expect(loser.status).toBe(302);
    expect((await Effect.runPromise(harness.store.findGrant("interactId", pending.interactId)))?.state).toBe(
      "FINALIZED",
    );

    harness.clock.advance(60);

    const again = await continueWith(harness, pending, { interact_ref: interactRef });

    expect(again.status).toBe(401);
    expect(await errorOf(again)).toMatchObject({ code: "request_denied" });
  });
});
