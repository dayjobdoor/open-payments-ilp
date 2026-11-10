import * as Effect from "effect/Effect";
import { describe, expect, it } from "vite-plus/test";
import { memoryGnapStore } from "../../src/gnap/server/index";
import { storeContract } from "../../src/gnap/server/testing/index";

storeContract({ describe, it }, "memoryGnapStore", () => memoryGnapStore());

describe("memoryGnapStore", () => {
  it("declares the two optional capabilities, since it keeps its records as they are", () => {
    expect(memoryGnapStore()).toMatchObject({ extendedRecords: true, interactionBinding: true });
  });

  it("keeps every live claim when it drops the expired ones, and frees a key whose claim expired", async () => {
    const store = memoryGnapStore();
    const now = 1_700_000_000_000;
    const claim = (key: string, expiresAt: number, at: number) =>
      Effect.runPromise(store.claimNonce(key, expiresAt, at));

    // More claims than the sweep threshold: the first 600 expire at `now + 10`, the rest at `now + 1000`.
    for (let index = 0; index < 1500; index += 1) {
      expect(await claim(`n${index}`, now + (index < 600 ? 10 : 1000), now)).toBe(true);
    }

    // This claim sweeps, with the first 600 expired.
    expect(await claim("fresh", now + 1000, now + 20)).toBe(true);

    expect(await claim("n700", now + 2000, now + 20)).toBe(false);
    expect(await claim("fresh", now + 2000, now + 20)).toBe(false);
    expect(await claim("n1", now + 2000, now + 20)).toBe(true);
  });
});
