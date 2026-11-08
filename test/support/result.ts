import * as Result from "effect/Result";

/** The `reason` a codec call failed with, or `"success"` when it did not fail, so a mismatch reads clearly. */
export function reasonOf<A>(result: Result.Result<A, { readonly reason: string }>): string {
  return Result.isFailure(result) ? result.failure.reason : "success";
}
