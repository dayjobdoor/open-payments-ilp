import * as Effect from "effect/Effect";
import * as Result from "effect/Result";
import { describe, expect, expectTypeOf, it } from "vite-plus/test";
import { HttpSignatureError } from "../../src/http-signatures/errors";
import { attemptResolver, sync, task, type Promisified, type Sync, type Task } from "../../src/internal/plain";

const failure = new HttpSignatureError({ reason: "unknown-key", message: "no such key" });

describe("task", () => {
  it("runs the Effect when called, not before, and resolves to its value", async () => {
    let started = 0;
    const wrapped = task((n: number) =>
      Effect.sync(() => {
        started += 1;

        return n * 2;
      }),
    );

    expect(started).toBe(0);

    const pending = wrapped(21);

    expect(pending).toBeInstanceOf(Promise);
    expect(await pending).toBe(42);
    expect(started).toBe(1);
  });

  it("rejects with the tagged error itself", async () => {
    await expect(task(() => Effect.fail(failure))()).rejects.toBe(failure);
  });

  it("rejects with the thrown value of a defect", async () => {
    const boom = new Error("boom");

    await expect(task(() => Effect.die(boom))()).rejects.toBe(boom);
  });
});

describe("sync", () => {
  it("returns the value of a success", () => {
    expect(sync((n: number) => Result.succeed(n + 1))(1)).toBe(2);
  });

  it("throws the tagged error itself", () => {
    let thrown: unknown;

    try {
      sync(() => Result.fail(failure))();
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBe(failure);
  });
});

describe("attemptResolver", () => {
  it("passes a value, awaited, through", async () => {
    expect(await Effect.runPromise(attemptResolver(() => "key"))).toBe("key");
    expect(await Effect.runPromise(attemptResolver(async () => "key"))).toBe("key");
    expect(await Effect.runPromise(attemptResolver(() => null))).toBeNull();
  });

  it.each([
    [
      "thrown",
      () => {
        throw failure;
      },
    ],
    ["rejected", () => Promise.reject(failure)],
  ])("takes an HttpSignatureError %s as the expected failure", async (_how, run) => {
    const result = await Effect.runPromise(Effect.result(attemptResolver(run)));

    expect(Result.isFailure(result) && result.failure).toBe(failure);
  });

  it.each([
    [
      "thrown",
      (boom: Error) => () => {
        throw boom;
      },
    ],
    ["rejected", (boom: Error) => () => Promise.reject(boom)],
  ])("takes anything else %s as a defect, never as an unknown key", async (_how, make) => {
    const boom = new Error("resolver bug");

    await expect(Effect.runPromise(attemptResolver(make(boom)))).rejects.toBe(boom);
  });
});

describe("the adapter types", () => {
  it("turn an Effect return into a Promise, a Result return into a value, and leave the rest alone", () => {
    expectTypeOf<Task<(a: string) => Effect.Effect<number, Error>>>().toEqualTypeOf<(a: string) => Promise<number>>();
    expectTypeOf<Sync<(a: string) => Result.Result<number, Error>>>().toEqualTypeOf<(a: string) => number>();
    // A wrapper applied to the wrong kind of function is `never`, which the no-effect-leak test reports.
    expectTypeOf<Task<(a: string) => number>>().toEqualTypeOf<never>();
    expectTypeOf<Sync<(a: string) => Effect.Effect<number>>>().toEqualTypeOf<never>();

    expectTypeOf<
      Promisified<{
        readonly run: (a: string) => Effect.Effect<number, Error>;
        readonly name: string;
        readonly plain: () => 1;
      }>
    >().toEqualTypeOf<{
      readonly run: (a: string) => Promise<number>;
      readonly name: string;
      readonly plain: () => 1;
    }>();
  });
});
