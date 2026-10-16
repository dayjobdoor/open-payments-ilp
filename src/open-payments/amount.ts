import * as Result from "effect/Result";
import { OpenPaymentsError } from "./errors";
import type { Amount } from "./types";

/** Largest Open Payments amount value (`format: uint64`). */
export const UINT64_MAX: bigint = (1n << 64n) - 1n;

/** Largest accounting amount (TigerBeetle-style UINT128). */
export const UINT128_MAX: bigint = (1n << 128n) - 1n;

const invalid = (message: string): Result.Result<never, OpenPaymentsError> =>
  Result.fail(new OpenPaymentsError({ reason: "invalid-amount", message }));

/**
 * Parses an amount `value` string (unsigned decimal digits) into a bigint.
 * Fails with `reason: "invalid-amount"` when the text is not digits-only or exceeds `max` (default {@link UINT64_MAX}).
 */
export function parseAmountValue(value: string, max: bigint = UINT64_MAX): Result.Result<bigint, OpenPaymentsError> {
  if (!/^\d+$/.test(value)) return invalid(`Amount value is not an unsigned integer: ${JSON.stringify(value)}`);
  const parsed = BigInt(value);

  return parsed > max ? invalid(`Amount value exceeds ${max}`) : Result.succeed(parsed);
}

/** True when `value` is unsigned decimal digits not exceeding `max` (default {@link UINT64_MAX}). */
export function isAmountValue(value: string, max: bigint = UINT64_MAX): boolean {
  return Result.isSuccess(parseAmountValue(value, max));
}

/** True when `value` is a canonical positive integer (no leading zeros, at least 1) not exceeding `max` (default {@link UINT64_MAX}). */
export function isPositiveAmountValue(value: string, max: bigint = UINT64_MAX): boolean {
  return /^[1-9]\d*$/.test(value) && BigInt(value) <= max;
}

/** True when both amounts use the same `assetCode` and `assetScale`. */
export function isSameAsset(a: Amount, b: Amount): boolean {
  return a.assetCode === b.assetCode && a.assetScale === b.assetScale;
}

/**
 * Compares two amounts numerically: `-1`, `0` or `1`.
 * Fails with `reason: "invalid-amount"` when the assets differ or a value is malformed.
 */
export function compareAmounts(a: Amount, b: Amount): Result.Result<-1 | 0 | 1, OpenPaymentsError> {
  if (!isSameAsset(a, b)) return invalid("Cannot compare amounts of different assets");
  const left = parseAmountValue(a.value, UINT128_MAX);

  if (Result.isFailure(left)) return Result.fail(left.failure);
  const right = parseAmountValue(b.value, UINT128_MAX);

  if (Result.isFailure(right)) return Result.fail(right.failure);

  return Result.succeed(left.success < right.success ? -1 : left.success > right.success ? 1 : 0);
}

/**
 * Adds two amounts of the same asset. Fails with `reason: "invalid-amount"` when the assets differ,
 * a value is malformed, or the sum exceeds `max` (default {@link UINT64_MAX}).
 */
export function addAmounts(a: Amount, b: Amount, max: bigint = UINT64_MAX): Result.Result<Amount, OpenPaymentsError> {
  if (!isSameAsset(a, b)) return invalid("Cannot add amounts of different assets");
  const left = parseAmountValue(a.value, max);

  if (Result.isFailure(left)) return Result.fail(left.failure);
  const right = parseAmountValue(b.value, max);

  if (Result.isFailure(right)) return Result.fail(right.failure);
  const sum = left.success + right.success;

  if (sum > max) return invalid(`Amount sum exceeds ${max}`);

  return Result.succeed({ value: sum.toString(), assetCode: a.assetCode, assetScale: a.assetScale });
}

/** Fills a partial amount's missing `assetCode` / `assetScale` from `defaults`. */
export function normalizeAmount(
  amount: { value: string; assetCode?: string | undefined; assetScale?: number | undefined },
  defaults: { assetCode: string; assetScale: number },
): Amount {
  return {
    value: amount.value,
    assetCode: amount.assetCode ?? defaults.assetCode,
    assetScale: amount.assetScale ?? defaults.assetScale,
  };
}
