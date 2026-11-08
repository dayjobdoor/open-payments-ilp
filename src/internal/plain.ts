import * as Effect from "effect/Effect";
import * as Result from "effect/Result";
import { HttpSignatureError } from "../http-signatures/errors";

/**
 * Adapters behind the `open-payments-ilp/plain/*` entry points: an `Effect` becomes a `Promise` that rejects with the
 * original tagged error, and a `Result` becomes a plain return value that throws that same error.
 */

/** An object whose `Effect`-returning methods return a `Promise` instead; other members are kept. */
export type Promisified<T> = {
  readonly [K in keyof T]: T[K] extends (...args: infer A) => Effect.Effect<infer R, infer _E>
    ? (...args: A) => Promise<R>
    : T[K];
};

/** `F` with its `Effect` return turned into a `Promise`. */
export type Task<F> = F extends (...args: infer A) => Effect.Effect<infer T, infer _E>
  ? (...args: A) => Promise<T>
  : never;

/** `F` with its `Result` return turned into the bare value. */
export type Sync<F> = F extends (...args: infer A) => Result.Result<infer T, infer _E> ? (...args: A) => T : never;

/** Wraps an `Effect`-returning function into an `async` function; failures reject with the tagged error itself. */
export const task =
  <A extends readonly unknown[], T>(fn: (...args: A) => Effect.Effect<T, unknown>): ((...args: A) => Promise<T>) =>
  async (...args) =>
    Effect.runPromise(fn(...args));

/** Wraps a `Result`-returning function into a function that returns the value or throws the tagged error. */
export const sync =
  <A extends readonly unknown[], T>(fn: (...args: A) => Result.Result<T, unknown>): ((...args: A) => T) =>
  (...args) =>
    Result.getOrThrow(fn(...args));

/**
 * Runs a plain (maybe async) key resolver as an `Effect`. A thrown or rejected `HttpSignatureError` is the expected
 * failure; any other throw is a defect, so a bug in the resolver is never reported as "unknown key".
 */
export const attemptResolver = <A>(run: () => A | PromiseLike<A>): Effect.Effect<A, HttpSignatureError> =>
  Effect.promise(async (): Promise<Result.Result<A, HttpSignatureError>> => {
    try {
      return Result.succeed(await run());
    } catch (error) {
      if (error instanceof HttpSignatureError) return Result.fail(error);
      throw error;
    }
  }).pipe(Effect.flatMap((result) => Effect.fromResult(result)));
