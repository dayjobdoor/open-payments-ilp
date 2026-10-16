import * as Result from "effect/Result";
import { describe, expect, it } from "vite-plus/test";
import {
  addAmounts,
  compareAmounts,
  isAmountValue,
  isPositiveAmountValue,
  isSameAsset,
  normalizeAmount,
  OpenPaymentsError,
  parseAmountValue,
  UINT128_MAX,
  UINT64_MAX,
} from "../../src/open-payments/index";

const usd = (value: string, assetScale = 2) => ({ value, assetCode: "USD", assetScale });

const failure = <A>(result: Result.Result<A, OpenPaymentsError>): OpenPaymentsError => {
  if (Result.isSuccess(result)) throw new Error("expected failure");

  return result.failure;
};

const success = <A>(result: Result.Result<A, OpenPaymentsError>): A => {
  if (Result.isFailure(result)) throw result.failure;

  return result.success;
};

describe("parseAmountValue / isAmountValue", () => {
  it("parses unsigned integers up to uint64 into bigint", () => {
    expect(success(parseAmountValue("0"))).toBe(0n);
    expect(success(parseAmountValue("999999999"))).toBe(999999999n);
    expect(success(parseAmountValue(UINT64_MAX.toString()))).toBe(UINT64_MAX);
  });

  it("rejects values above the maximum, which can be raised to uint128", () => {
    expect(isAmountValue((UINT64_MAX + 1n).toString())).toBe(false);
    expect(isAmountValue((UINT64_MAX + 1n).toString(), UINT128_MAX)).toBe(true);
    expect(isAmountValue((UINT128_MAX + 1n).toString(), UINT128_MAX)).toBe(false);
    expect(failure(parseAmountValue((UINT64_MAX + 1n).toString()))).toMatchObject({
      _tag: "OpenPaymentsError",
      reason: "invalid-amount",
    });
  });

  it.each(["", "-1", "1.5", "abc", "12a", " 123 ", "0x10", "1e3", "+1"])("rejects %j", (value) => {
    expect(isAmountValue(value)).toBe(false);
  });
});

describe("isPositiveAmountValue", () => {
  it("rejects zero, leading zeros and overflow", () => {
    expect(isPositiveAmountValue("0")).toBe(false);
    expect(isPositiveAmountValue("01")).toBe(false);
    expect(isPositiveAmountValue("1")).toBe(true);
    expect(isPositiveAmountValue(UINT128_MAX.toString(), UINT128_MAX)).toBe(true);
    expect(isPositiveAmountValue((UINT128_MAX + 1n).toString(), UINT128_MAX)).toBe(false);
    expect(isPositiveAmountValue(UINT64_MAX.toString())).toBe(true);
    expect(isPositiveAmountValue((UINT64_MAX + 1n).toString())).toBe(false);
  });
});

describe("asset checks", () => {
  it("compares assetCode and assetScale", () => {
    expect(isSameAsset(usd("1"), usd("2"))).toBe(true);
    expect(isSameAsset(usd("1"), usd("1", 4))).toBe(false);
    expect(isSameAsset(usd("1"), { ...usd("1"), assetCode: "EUR" })).toBe(false);
  });
});

describe("compareAmounts", () => {
  it("orders amounts of the same asset numerically, not lexically", () => {
    expect(success(compareAmounts(usd("9"), usd("10")))).toBe(-1);
    expect(success(compareAmounts(usd("10"), usd("10")))).toBe(0);
    expect(success(compareAmounts(usd("100"), usd("99")))).toBe(1);
  });

  it("refuses to compare different assets or malformed values", () => {
    expect(failure(compareAmounts(usd("1"), usd("1", 4))).reason).toBe("invalid-amount");
    expect(failure(compareAmounts(usd("x"), usd("1"))).reason).toBe("invalid-amount");
  });
});

describe("addAmounts", () => {
  it("adds without precision loss beyond 2^53", () => {
    expect(success(addAmounts(usd("9007199254740993"), usd("2")))).toEqual(usd("9007199254740995"));
  });

  it("fails on asset mismatch and on overflow", () => {
    expect(failure(addAmounts(usd("1"), usd("1", 4))).reason).toBe("invalid-amount");
    expect(failure(addAmounts(usd(UINT64_MAX.toString()), usd("1"))).reason).toBe("invalid-amount");
    expect(success(addAmounts(usd(UINT64_MAX.toString()), usd("1"), UINT128_MAX)).value).toBe(
      (UINT64_MAX + 1n).toString(),
    );
  });
});

describe("normalizeAmount", () => {
  const defaults = { assetCode: "USD", assetScale: 2 };

  it("fills only the missing asset fields", () => {
    expect(normalizeAmount({ value: "100" }, defaults)).toEqual({ value: "100", assetCode: "USD", assetScale: 2 });
    expect(normalizeAmount({ value: "100", assetCode: "JPY" }, defaults)).toEqual({
      value: "100",
      assetCode: "JPY",
      assetScale: 2,
    });
    expect(normalizeAmount({ value: "100", assetScale: 0 }, defaults)).toEqual({
      value: "100",
      assetCode: "USD",
      assetScale: 0,
    });
    expect(normalizeAmount({ value: "500", assetCode: "EUR", assetScale: 2 }, defaults)).toEqual({
      value: "500",
      assetCode: "EUR",
      assetScale: 2,
    });
  });
});
