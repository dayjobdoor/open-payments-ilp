import { describe, expect, it } from "vite-plus/test";
import { memo } from "../../src/stream/key-cache";

/** A promise settled by hand, so a test decides the order in which computations finish. */
function deferred<V>(): {
  promise: Promise<V>;
  resolve: (value: V) => void;
  reject: (reason: unknown) => void;
} {
  let resolve: (value: V) => void = () => undefined;
  let reject: (reason: unknown) => void = () => undefined;

  const promise = new Promise<V>((res, rej) => {
    resolve = res;
    reject = rej;
  });

  return { promise, resolve, reject };
}

/** Lets the `.then` handlers memo attached run. */
const settle = async (): Promise<void> => {
  for (let i = 0; i < 5; i++) await Promise.resolve();
};

const ids = (cache: Map<string, unknown>): string[] => [...cache.keys()];

describe("memo (the bounded least-recently-used cache behind every key derivation)", () => {
  it("computes once per id: a repeat or a concurrent miss shares the computation", async () => {
    const cache = new Map<string, Promise<number>>();
    let calls = 0;

    const create = async (): Promise<number> => {
      calls++;

      return 7;
    };

    const first = memo(cache, "a", create, 4);
    const concurrent = memo(cache, "a", create, 4);

    expect(concurrent).toBe(first);
    expect(await first).toBe(7);

    await settle();
    expect(memo(cache, "a", create, 4)).toBe(first);
    expect(calls).toBe(1);
  });

  it("evicts the least recently used entry beyond the capacity, and a hit makes an entry recent", async () => {
    const cache = new Map<string, Promise<string>>();
    const get = async (id: string): Promise<string> => memo(cache, id, async () => `value-${id}`, 3);

    for (const id of ["a", "b", "c"]) await get(id);
    await settle();
    expect(ids(cache)).toEqual(["a", "b", "c"]);

    // Touch `a`: `b` is now the oldest.
    await get("a");
    expect(ids(cache)).toEqual(["b", "c", "a"]);

    await get("d");
    await settle();
    expect(ids(cache)).toEqual(["c", "a", "d"]);

    await get("e");
    await settle();
    expect(ids(cache)).toEqual(["a", "d", "e"]);
  });

  it("never holds more settled entries than the capacity, whatever the order they finish in", async () => {
    const cache = new Map<string, Promise<number>>();
    const pending = Array.from({ length: 10 }, () => deferred<number>());

    const results = pending.map(({ promise }, i) => memo(cache, `k${i}`, () => promise, 4));

    // Finish them out of order. Settled entries are capped at 4; those still in flight are all kept.
    for (const [step, i] of [3, 0, 9, 5, 1, 8, 2, 7, 4, 6].entries()) {
      pending[i]!.resolve(i);
      await settle();
      expect(cache.size).toBe(Math.min(step + 1, 4) + (10 - (step + 1)));
    }

    await Promise.all(results);
    await settle();

    expect(cache.size).toBe(4);
  });

  it("does not cache a computation that rejects, and recomputes on the next call", async () => {
    const cache = new Map<string, Promise<number>>();
    let calls = 0;

    const create = async (): Promise<number> => {
      calls++;

      if (calls === 1) throw new Error("import failed");

      return 42;
    };

    await expect(memo(cache, "a", create, 4)).rejects.toThrow("import failed");
    await settle();
    expect(cache.has("a")).toBe(false);

    expect(await memo(cache, "a", create, 4)).toBe(42);
    expect(calls).toBe(2);
  });

  it("does not cache an undefined result (a token that did not authenticate)", async () => {
    const cache = new Map<string, Promise<number | undefined>>();
    let calls = 0;

    const create = async (): Promise<number | undefined> => {
      calls++;

      return undefined;
    };

    expect(await memo(cache, "bad", create, 4)).toBeUndefined();
    await settle();
    expect(cache.has("bad")).toBe(false);

    expect(await memo(cache, "bad", create, 4)).toBeUndefined();
    expect(calls).toBe(2);
  });

  it("a flood of failing lookups, still in flight, evicts no good entry", async () => {
    const cache = new Map<string, Promise<string | undefined>>();
    const good = ["g1", "g2", "g3"];

    for (const id of good) await memo(cache, id, async () => id, 3);
    await settle();

    const garbage = Array.from({ length: 50 }, () => deferred<string | undefined>());
    const lookups = garbage.map(({ promise }, i) => memo(cache, `bad${i}`, () => promise, 3));

    // One more good entry arrives while the garbage is pending; only now does the capacity come into play.
    await memo(cache, "g4", async () => "g4", 3);
    await settle();

    expect(good.slice(1).every((id) => cache.has(id))).toBe(true);
    expect(cache.has("g4")).toBe(true);

    for (const entry of garbage) entry.resolve(undefined);
    await Promise.all(lookups);
    await settle();

    expect(ids(cache)).toEqual(["g2", "g3", "g4"]);
  });

  it("a pending computation is not evicted by entries that settle after it started", async () => {
    const cache = new Map<string, Promise<string>>();
    const slow = deferred<string>();
    const slowResult = memo(cache, "slow", () => slow.promise, 2);

    for (const id of ["a", "b", "c", "d"]) await memo(cache, id, async () => id, 2);
    await settle();

    expect(cache.has("slow")).toBe(true);
    expect(memo(cache, "slow", async () => "recomputed", 2)).toBe(slowResult);

    slow.resolve("done");
    expect(await slowResult).toBe("done");
    await settle();

    // Now that it has settled it counts: two entries remain, the oldest settled one went.
    expect(cache.size).toBe(2);
    expect(cache.has("slow")).toBe(true);
  });

  it("a late failure never deletes the entry that replaced it", async () => {
    const cache = new Map<string, Promise<string>>();
    const stale = deferred<string>();

    memo(cache, "id", () => stale.promise, 4).catch(() => undefined);

    // Something evicts the pending entry (here: an explicit delete) and a good computation takes its place.
    cache.delete("id");
    const replacement = memo(cache, "id", async () => "good", 4);
    await replacement;
    await settle();

    stale.reject(new Error("late failure"));
    await settle();

    expect(cache.get("id")).toBe(replacement);
  });

  it("a late undefined never deletes the entry that replaced it either", async () => {
    const cache = new Map<string, Promise<string | undefined>>();
    const stale = deferred<string | undefined>();

    void memo(cache, "id", () => stale.promise, 4);
    cache.delete("id");
    const replacement = memo(cache, "id", async () => "good", 4);
    await replacement;
    await settle();

    stale.resolve(undefined);
    await settle();

    expect(cache.get("id")).toBe(replacement);
  });

  it("keeps separate caches separate", async () => {
    const one = new Map<string, Promise<number>>();
    const two = new Map<string, Promise<number>>();

    await memo(one, "a", async () => 1, 1);
    await memo(two, "a", async () => 2, 1);

    expect(await one.get("a")).toBe(1);
    expect(await two.get("a")).toBe(2);
  });
});
