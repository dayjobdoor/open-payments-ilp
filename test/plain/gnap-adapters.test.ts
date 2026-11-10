import * as Effect from "effect/Effect";
import { describe, expect, expectTypeOf, it } from "vite-plus/test";
import * as server from "../../src/gnap/server/index";
import { toEffectOptions, toEffectStore, toPromiseStore } from "../../src/internal/plain-gnap";
import * as plainServer from "../../src/plain/gnap-server";
import * as plainTesting from "../../src/plain/gnap-server-testing";
import * as plainBetterAuth from "../../src/plain/better-auth";
import type { GnapStore } from "../../src/plain/gnap-server";

type EffectStore = server.GnapStore;

/** A class-based Effect store: its methods only work when called on the instance (they read `this`). */
class ClassStore implements EffectStore {
  readonly inner = server.memoryGnapStore();
  readonly extendedRecords = true as const;
  readonly interactionBinding = true as const;
  calls = 0;

  createGrant(...args: Parameters<EffectStore["createGrant"]>): ReturnType<EffectStore["createGrant"]> {
    this.calls++;
    return this.inner.createGrant(...args);
  }
  findGrant(...args: Parameters<EffectStore["findGrant"]>): ReturnType<EffectStore["findGrant"]> {
    this.calls++;
    return this.inner.findGrant(...args);
  }
  updateGrant(...args: Parameters<EffectStore["updateGrant"]>): ReturnType<EffectStore["updateGrant"]> {
    this.calls++;
    return this.inner.updateGrant(...args);
  }
  createToken(...args: Parameters<EffectStore["createToken"]>): ReturnType<EffectStore["createToken"]> {
    this.calls++;
    return this.inner.createToken(...args);
  }
  findTokenWithGrant(
    ...args: Parameters<EffectStore["findTokenWithGrant"]>
  ): ReturnType<EffectStore["findTokenWithGrant"]> {
    this.calls++;
    return this.inner.findTokenWithGrant(...args);
  }
  revokeTokens(...args: Parameters<EffectStore["revokeTokens"]>): ReturnType<EffectStore["revokeTokens"]> {
    this.calls++;
    return this.inner.revokeTokens(...args);
  }
  claimNonce(...args: Parameters<EffectStore["claimNonce"]>): ReturnType<EffectStore["claimNonce"]> {
    this.calls++;
    return this.inner.claimNonce(...args);
  }
}

describe("plain gnap adapters (internal)", () => {
  it("toPromiseStore calls the methods of a class-based Effect store on the instance", async () => {
    const effectStore = new ClassStore();
    const store = toPromiseStore(effectStore);

    expect(await store.claimNonce("k", 2_000, 1_000)).toBe(true);
    expect(await store.claimNonce("k", 2_000, 1_000)).toBe(false);
    expect(await store.findGrant("id", "unknown")).toBeNull();
    expect(await store.findTokenWithGrant("valueHash", "unknown")).toBeNull();
    expect(effectStore.calls).toBe(4);
  });

  it("copies both capability flags in both directions", async () => {
    const promiseStore = toPromiseStore(new ClassStore());

    expect(promiseStore).toMatchObject({ extendedRecords: true, interactionBinding: true });
    expect(toEffectStore(promiseStore)).toMatchObject({
      extendedRecords: true,
      interactionBinding: true,
    });

    const bare = toPromiseStore({
      ...server.memoryGnapStore(),
      extendedRecords: undefined,
      interactionBinding: undefined,
    } as never);

    expect("extendedRecords" in bare).toBe(false);
    expect("interactionBinding" in bare).toBe(false);
    expect("extendedRecords" in toEffectStore(bare)).toBe(false);
    expect("interactionBinding" in toEffectStore(bare)).toBe(false);
  });

  it.each([
    ["extendedRecords", { extendedRecords: true }],
    ["interactionBinding", { interactionBinding: true }],
  ] as const)("copies %s alone, in both directions, without inventing the other flag", (name, flags) => {
    const inner = server.memoryGnapStore();

    const effectStore: EffectStore = {
      createGrant: inner.createGrant,
      findGrant: inner.findGrant,
      updateGrant: inner.updateGrant,
      createToken: inner.createToken,
      findTokenWithGrant: inner.findTokenWithGrant,
      revokeTokens: inner.revokeTokens,
      claimNonce: inner.claimNonce,
      ...flags,
    };

    const other = name === "extendedRecords" ? "interactionBinding" : "extendedRecords";
    const promiseStore = toPromiseStore(effectStore);
    const effectAgain = toEffectStore(promiseStore);

    for (const store of [promiseStore, effectAgain]) {
      expect(store[name]).toBe(true);
      expect(other in store).toBe(false);
    }
  });

  it("toEffectStore round-trips through toPromiseStore", async () => {
    const store = toEffectStore(plainServer.memoryGnapStore());

    expect(await Effect.runPromise(store.claimNonce("n", 2_000, 1_000))).toBe(true);
    expect(await Effect.runPromise(store.claimNonce("n", 2_000, 1_000))).toBe(false);
  });

  it("toEffectOptions leaves absent hooks absent and lifts the present ones to Effects", async () => {
    expect(toEffectOptions({})).toEqual({});

    const options = toEffectOptions({ tenants: async () => null, onError: () => undefined });

    expect(Effect.isEffect(options.tenants?.("t"))).toBe(true);
    expect(options.resolveClientKeys).toBeUndefined();
  });
});

describe("the plain server entry keeps up with the Effect one", () => {
  it("exports every runtime name of /gnap/server, as the very same function", () => {
    // A consent endpoint of a Promise-only application builds its decision from `bindingFromRequest`.
    expect(Object.keys(server).filter((name) => !(name in plainServer))).toEqual([]);
    expect(plainServer.bindingFromRequest).toBe(server.bindingFromRequest);
  });
});

describe("public plain gnap entries do not expose the Effect adapters", () => {
  it("has no toEffectStore, toPromiseStore or toEffectOptions export at runtime", () => {
    for (const entry of [plainServer, plainTesting, plainBetterAuth]) {
      const names = Object.keys(entry);

      expect(names).not.toContain("toEffectStore");
      expect(names).not.toContain("toPromiseStore");
      expect(names).not.toContain("toEffectOptions");
    }
  });

  it("types the exported GnapStore as the Promise port", () => {
    type NoAdapters<M> = Extract<keyof M, "toEffectStore" | "toPromiseStore" | "toEffectOptions">;

    expectTypeOf<NoAdapters<typeof plainServer>>().toEqualTypeOf<never>();
    expectTypeOf<NoAdapters<typeof plainTesting>>().toEqualTypeOf<never>();
    expectTypeOf<NoAdapters<typeof plainBetterAuth>>().toEqualTypeOf<never>();
    expectTypeOf<ReturnType<GnapStore["claimNonce"]>>().toEqualTypeOf<Promise<boolean>>();
    expectTypeOf<ReturnType<GnapStore["findGrant"]>>().toExtend<Promise<unknown>>();
    expect(true).toBe(true);
  });
});

// Every method, not a sample: one that is called off its instance throws here, and the flags of the store drive the extended cases.
plainTesting.storeContract({ describe, it }, "a class-based Effect store lowered to the Promise port", () =>
  toPromiseStore(new ClassStore()),
);
