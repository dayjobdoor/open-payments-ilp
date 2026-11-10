import { describe, it, expect } from "vite-plus/test";
import {
  compareRequestAndGrantAccessItems,
  currentAccessIntervalStart,
  parseAccessIntervalMs,
  validateOutgoingPaymentAmounts,
  validateOutgoingPaymentReceiver,
} from "../../src/gnap/index";
import { prng } from "../support/prng";

describe("compareRequestAndGrantAccessItems", () => {
  const grantAccesses = [
    { type: "incoming-payment", actions: ["create", "read", "complete"] },
    {
      type: "outgoing-payment",
      actions: ["create", "read"],
      identifier: "https://example.com/alice",
    },
    { type: "quote", actions: ["create", "read"] },
  ];

  it("returns all grant accesses when requestAccess is undefined", () => {
    const result = compareRequestAndGrantAccessItems(undefined, grantAccesses);
    expect(result).toHaveLength(3);
  });

  it("returns all grant accesses when requestAccess is empty", () => {
    const result = compareRequestAndGrantAccessItems([], grantAccesses);
    expect(result).toHaveLength(3);
  });

  it("returns matched access when type and actions match", () => {
    const request = [{ type: "incoming-payment", actions: ["create"] }];
    const result = compareRequestAndGrantAccessItems(request, grantAccesses);
    expect(result).toHaveLength(1);
    expect(result[0]!.type).toBe("incoming-payment");
  });

  it("returns matched access when multiple requested actions are subset of grant", () => {
    const request = [{ type: "incoming-payment", actions: ["create", "read"] }];
    const result = compareRequestAndGrantAccessItems(request, grantAccesses);
    expect(result).toHaveLength(1);
  });

  it("returns empty when requested action not in grant", () => {
    const request = [{ type: "incoming-payment", actions: ["list-all"] }];
    const result = compareRequestAndGrantAccessItems(request, grantAccesses);
    expect(result).toHaveLength(0);
  });

  it("returns matched access when identifier matches", () => {
    const request = [
      {
        type: "outgoing-payment",
        actions: ["create"],
        identifier: "https://example.com/alice",
      },
    ];

    const result = compareRequestAndGrantAccessItems(request, grantAccesses);
    expect(result).toHaveLength(1);
    expect(result[0]!.identifier).toBe("https://example.com/alice");
  });

  it("returns empty when grant has no identifier but request specifies wallet", () => {
    const grant = [{ type: "incoming-payment", actions: ["create"] }];

    const request = [
      {
        type: "incoming-payment",
        actions: ["create"],
        identifier: "https://wallet.example/op/default/victim",
      },
    ];

    expect(compareRequestAndGrantAccessItems(request, grant)).toHaveLength(0);
  });

  it("returns empty when identifiers differ", () => {
    const grant = [{ type: "incoming-payment", actions: ["create"], identifier: "https://example.com/alice" }];

    const request = [
      {
        type: "incoming-payment",
        actions: ["create"],
        identifier: "https://example.com/bob",
      },
    ];

    expect(compareRequestAndGrantAccessItems(request, grant)).toHaveLength(0);
  });

  it("returns multiple matches for multiple request items", () => {
    const request = [
      { type: "incoming-payment", actions: ["create"] },
      { type: "quote", actions: ["read"] },
    ];

    const result = compareRequestAndGrantAccessItems(request, grantAccesses);
    expect(result).toHaveLength(2);
  });
});

describe("outgoing-payment amount limits and intervals", () => {
  it("parses supported ISO-8601 durations", () => {
    expect(parseAccessIntervalMs("PT1H")).toBe(60 * 60 * 1000);
    expect(parseAccessIntervalMs("P1D")).toBe(24 * 60 * 60 * 1000);
    expect(parseAccessIntervalMs("P1W")).toBe(7 * 24 * 60 * 60 * 1000);
    expect(parseAccessIntervalMs("P0D")).toBeNull();
    expect(parseAccessIntervalMs("invalid")).toBeNull();
  });

  it("aligns current spend window to grant creation", () => {
    const anchor = new Date("2026-01-01T00:00:00.000Z");
    const now = new Date("2026-01-03T12:00:00.000Z");
    const monthAnchor = new Date("2026-01-31T00:00:00.000Z");
    expect(currentAccessIntervalStart(monthAnchor, "P1M", new Date("2026-02-27T00:00:00.000Z"))?.toISOString()).toBe(
      "2026-01-31T00:00:00.000Z",
    );
    expect(currentAccessIntervalStart(monthAnchor, "P1M", new Date("2026-02-28T00:00:00.000Z"))?.toISOString()).toBe(
      "2026-02-28T00:00:00.000Z",
    );
    expect(currentAccessIntervalStart(anchor, "P1D", now)?.toISOString()).toBe("2026-01-03T00:00:00.000Z");
  });

  // Expected windows are what Rafiki's `getInterval` (backend/src/open_payments/payment/outgoing/limits.ts, luxon)
  // returns for the same interval and instant.
  it.each([
    ["R12/2019-08-24T14:15:22Z/P1M", "2019-10-01T00:00:00Z", "2019-09-24T14:15:22.000Z"],
    ["R2/2019-08-24T14:15:22Z/P1M", "2019-11-30T00:00:00Z", null],
    ["R/2017-03-01T13:00:00Z/2018-05-11T15:30:00Z", "2019-01-01T00:00:00Z", "2018-05-11T15:30:00.000Z"],
    ["R-1/P1Y2M10DT2H30M/2022-05-11T15:30:00Z", "2020-01-01T00:00:00Z", "2019-12-22T10:30:00.000Z"],
    ["R/2022-01-31T00:00:00Z/P1M", "2022-04-15T00:00:00Z", "2022-03-28T00:00:00.000Z"],
    ["R/2030-01-01T00:00:00Z/P1M", "2029-06-01T00:00:00Z", null],
    ["R3/P1D/2022-05-11T00:00:00Z", "2022-05-08T12:00:00Z", "2022-05-08T00:00:00.000Z"],
    ["R3/P1D/2022-05-11T00:00:00Z", "2022-05-12T12:00:00Z", null],
  ])("finds the window of the repeating interval %s at %s", (interval, now, expected) => {
    // The anchor is ignored: a repeating interval carries its own start.
    expect(currentAccessIntervalStart(new Date(0), interval, new Date(now))?.toISOString() ?? null).toBe(expected);
  });

  it("measures a repeating interval by the length of its period", () => {
    expect(parseAccessIntervalMs("R12/2019-08-24T14:15:22Z/P1M")).toBe(30 * 24 * 60 * 60 * 1000);
    expect(parseAccessIntervalMs("R/2017-03-01T13:00:00Z/2017-03-02T13:00:00Z")).toBe(24 * 60 * 60 * 1000);
  });

  it.each([
    "R12/2019-08-24T14:15:22Z",
    "R-2/2019-08-24T14:15:22Z/P1M",
    "R/P1M/P1D",
    "R/2019-08-24/2019-08-23",
    "Rx/2019-08-24/P1D",
  ])("rejects the malformed repeating interval %s", (interval) => {
    expect(parseAccessIntervalMs(interval)).toBeNull();
    expect(currentAccessIntervalStart(new Date(0), interval, new Date("2020-01-01T00:00:00Z"))).toBeNull();
  });

  it("rejects a payment without a receive amount when the grant limits the receive amount", () => {
    const debit = { value: "100", assetCode: "USD", assetScale: 2 };
    const limited = [
      {
        type: "outgoing-payment",
        actions: ["create"],
        limits: { debitAmount: debit, receiveAmount: { value: "90", assetCode: "USD", assetScale: 2 } },
      },
    ];
    const unlimited = [{ type: "outgoing-payment", actions: ["create"], limits: { debitAmount: debit } }];

    expect(validateOutgoingPaymentAmounts(limited, debit, undefined)).toBe(false);
    expect(validateOutgoingPaymentAmounts(unlimited, debit, undefined)).toBe(true);
  });

  it("rejects per-payment debit and receive amounts above grant caps", () => {
    const access = [
      {
        type: "outgoing-payment",
        actions: ["create"],
        limits: {
          debitAmount: { value: "100", assetCode: "USD", assetScale: 2 },
          receiveAmount: { value: "90", assetCode: "USD", assetScale: 2 },
        },
      },
    ];

    expect(
      validateOutgoingPaymentAmounts(
        access,
        { value: "100", assetCode: "USD", assetScale: 2 },
        { value: "90", assetCode: "USD", assetScale: 2 },
      ),
    ).toBe(true);
    expect(
      validateOutgoingPaymentAmounts(
        access,
        { value: "101", assetCode: "USD", assetScale: 2 },
        { value: "90", assetCode: "USD", assetScale: 2 },
      ),
    ).toBe(false);
    expect(
      validateOutgoingPaymentAmounts(
        access,
        { value: "100", assetCode: "USD", assetScale: 2 },
        { value: "91", assetCode: "USD", assetScale: 2 },
      ),
    ).toBe(false);
  });
});

describe("validateOutgoingPaymentAmounts asset matching", () => {
  const usd = (value: string, assetScale = 2) => ({ value, assetCode: "USD", assetScale });

  it("rejects a debit cap in another asset code instead of treating it as unlimited", () => {
    const access = [
      { type: "outgoing-payment", limits: { debitAmount: { value: "100", assetCode: "EUR", assetScale: 2 } } },
    ];

    expect(validateOutgoingPaymentAmounts(access, usd("1000000"), undefined)).toBe(false);
  });

  it("rejects a cap whose scale differs from the payment amount", () => {
    // 1000000 at scale 4 is $100, but 100000 at scale 2 is $1000: comparing raw values would allow 10x.
    const access = [
      { type: "outgoing-payment", limits: { debitAmount: { value: "1000000", assetCode: "USD", assetScale: 4 } } },
    ];

    expect(validateOutgoingPaymentAmounts(access, usd("100000"), undefined)).toBe(false);
  });

  it("rejects a receive cap in another asset", () => {
    const access = [
      { type: "outgoing-payment", limits: { receiveAmount: { value: "100", assetCode: "EUR", assetScale: 2 } } },
    ];

    expect(validateOutgoingPaymentAmounts(access, usd("10"), usd("10"))).toBe(false);
  });
});

describe("validateOutgoingPaymentAmounts without a matching access item", () => {
  it("authorizes nothing", () => {
    expect(validateOutgoingPaymentAmounts([], { value: "1", assetCode: "USD", assetScale: 2 }, undefined)).toBe(false);
  });
});

describe("validateOutgoingPaymentReceiver", () => {
  it("returns false when matched access is empty", () => {
    expect(validateOutgoingPaymentReceiver([], "https://receiver.example/incoming")).toBe(false);
  });

  it("returns true when any access has no receiver limit", () => {
    const access = [{ type: "outgoing-payment", actions: ["create"] }];
    expect(validateOutgoingPaymentReceiver(access, "https://any.example/incoming")).toBe(true);
  });

  it("returns true when receiver matches limit exactly", () => {
    const access = [
      {
        type: "outgoing-payment",
        actions: ["create"],
        limits: { receiver: "https://allowed.example/incoming" },
      },
    ];

    expect(validateOutgoingPaymentReceiver(access, "https://allowed.example/incoming")).toBe(true);
  });

  it("returns true when receiver is prefix of limit (with trailing slash)", () => {
    const access = [
      {
        type: "outgoing-payment",
        actions: ["create"],
        limits: { receiver: "https://allowed.example/" },
      },
    ];

    expect(validateOutgoingPaymentReceiver(access, "https://allowed.example/incoming-payments/abc")).toBe(true);
  });

  it("returns true when receiver is prefix of limit (no trailing slash)", () => {
    const access = [
      {
        type: "outgoing-payment",
        actions: ["create"],
        limits: { receiver: "https://allowed.example" },
      },
    ];

    expect(validateOutgoingPaymentReceiver(access, "https://allowed.example/incoming-payments/abc")).toBe(true);
  });

  it("returns false when receiver host shares the limit prefix but is a different host", () => {
    const access = [
      {
        type: "outgoing-payment",
        actions: ["create"],
        limits: { receiver: "https://allowed.example" },
      },
    ];

    expect(validateOutgoingPaymentReceiver(access, "https://allowed.example.evil.com/incoming")).toBe(false);
  });

  it("returns false when receiver does not match limit", () => {
    const access = [
      {
        type: "outgoing-payment",
        actions: ["create"],
        limits: { receiver: "https://allowed.example/" },
      },
    ];

    expect(validateOutgoingPaymentReceiver(access, "https://other.example/incoming")).toBe(false);
  });

  it("returns true when one of multiple accesses allows receiver", () => {
    const access = [
      {
        type: "outgoing-payment",
        actions: ["create"],
        limits: { receiver: "https://denied.example/" },
      },
      {
        type: "outgoing-payment",
        actions: ["create"],
        limits: { receiver: "https://allowed.example/" },
      },
    ];

    expect(validateOutgoingPaymentReceiver(access, "https://allowed.example/incoming")).toBe(true);
  });
});

describe("compareRequestAndGrantAccessItems -all preference", () => {
  it("picks the item carrying the requested action's -all variant, not an unrelated -all", () => {
    const grantAccesses = [
      { type: "incoming-payment", actions: ["list", "read-all"] },
      { type: "incoming-payment", actions: ["list-all"] },
    ];

    const [matched] = compareRequestAndGrantAccessItems(
      [{ type: "incoming-payment", actions: ["list"] }],
      grantAccesses,
    );

    expect(matched?.actions).toContain("list-all");
  });

  it("falls back to the first candidate when none grants the -all variant", () => {
    const grantAccesses = [
      { type: "incoming-payment", actions: ["list", "read"] },
      { type: "incoming-payment", actions: ["list", "create"] },
    ];

    const [matched] = compareRequestAndGrantAccessItems(
      [{ type: "incoming-payment", actions: ["list"] }],
      grantAccesses,
    );

    expect(matched?.actions).toEqual(["list", "read"]);
  });
});

const allowed = "https://merchant.example/op/shop/w1/incoming-payments/INVOICE-1";

const access = [{ type: "outgoing-payment", actions: ["create"], identifier: "x", limits: { receiver: allowed } }];

describe("validateOutgoingPaymentReceiver canonical form", () => {
  it("accepts the exact URL and a child path", () => {
    expect(validateOutgoingPaymentReceiver(access, allowed)).toBe(true);
    expect(validateOutgoingPaymentReceiver(access, `${allowed}/child`)).toBe(true);
  });

  it.each([
    ["sibling id", "https://merchant.example/op/shop/w1/incoming-payments/ATTACKER-IP"],
    ["dot-segment escape", `${allowed}/../ATTACKER-IP`],
    ["encoded dot-segment escape", `${allowed}/%2e%2e/X`],
    ["mixed-case encoded dot-segment", `${allowed}/%2E./X`],
    ["credentials", "https://user@merchant.example/op/shop/w1/incoming-payments/INVOICE-1"],
    ["fragment", `${allowed}#frag`],
    ["upper-case host", "https://MERCHANT.example/op/shop/w1/incoming-payments/INVOICE-1"],
    ["encoded slash escape", `${allowed}/..%2FATTACKER-IP`],
    ["lower-case encoded slash escape", `${allowed}/..%2fATTACKER-IP`],
    ["encoded backslash escape", `${allowed}/..%5CATTACKER-IP`],
    ["backslash", `${allowed}\\..\\ATTACKER-IP`],
    ["not a URL", "not a url"],
  ])("rejects %s", (_name, receiver) => {
    expect(validateOutgoingPaymentReceiver(access, receiver)).toBe(false);
  });
});

describe("fractional years and months", () => {
  const anchor = new Date("2026-01-01T00:00:00Z");

  // A fractional year or month is elapsed time (365 / 30 days), as parseAccessIntervalMs counts it; it must not vanish
  // from the window (a `P0.5M1D` interval used to make one-day windows while reporting 16 days).
  it.each([
    ["P1.5M", "2026-03-15T00:00:00Z", "2026-02-16T00:00:00.000Z"],
    ["P0.5M1D", "2026-01-20T00:00:00Z", "2026-01-17T00:00:00.000Z"],
    ["P0.5Y", "2026-07-02T18:00:00Z", "2026-07-02T12:00:00.000Z"],
    ["P0.001M", "2026-01-01T01:00:00Z", "2026-01-01T00:43:12.000Z"],
  ])("makes the windows of %s as long as it says (%s)", (interval, now, expected) => {
    expect(currentAccessIntervalStart(anchor, interval, new Date(now))?.toISOString()).toBe(expected);
  });

  it("applies the fraction to a repeating interval too", () => {
    // Windows chain: 2020-01-01 + 1 month + 15 days each time, 50 of them, the 51st begins at `now`.
    expect(
      currentAccessIntervalStart(
        anchor,
        "R/2020-01-01T00:00:00Z/P1.5M",
        new Date("2026-03-15T00:00:00Z"),
      )?.toISOString(),
    ).toBe("2026-03-15T00:00:00.000Z");
    expect(parseAccessIntervalMs("R/2020-01-01T00:00:00Z/P1.5M")).toBe(45 * 24 * 60 * 60 * 1000);
  });
});

describe("currentAccessIntervalStart with an unusable instant", () => {
  it.each(["P1D", "P1M", "R/2020-01-01T00:00:00Z/P1D", "R/2020-01-01T00:00:00Z/2020-01-02T00:00:00Z"])(
    "has no window for %s at an invalid `now`, instead of an invalid Date",
    (interval) => {
      expect(currentAccessIntervalStart(new Date(0), interval, new Date(Number.NaN))).toBeNull();
    },
  );

  it.each([
    "R/2026-02-30T00:00:00Z/P1D",
    "R/2026-04-31/P1D",
    "R/2025-02-29/P1D",
    "R/2100-02-29/P1D",
    "R/2026-13-01/P1D",
    "R/2026-00-10/P1D",
    "R/P1D/2026-02-30T00:00:00Z",
    "R/2026-01-01/2026-02-30",
  ])("rejects %s: the date does not exist and must not roll over to the next month", (interval) => {
    expect(parseAccessIntervalMs(interval)).toBeNull();
    expect(currentAccessIntervalStart(new Date(0), interval, new Date("2026-06-01T00:00:00Z"))).toBeNull();
  });

  it.each(["R/2024-02-29/P1D", "R/2000-02-29/P1D", "R/2026-01-31T23:59:59.5+02:00/P1D"])("accepts %s", (interval) => {
    expect(parseAccessIntervalMs(interval)).toBe(24 * 60 * 60 * 1000);
  });
});

describe("validateOutgoingPaymentReceiver with an unusable limit", () => {
  it("allows no receiver when the limit is an empty string, instead of treating it as no limit", () => {
    const access = [{ type: "outgoing-payment", actions: ["create"], limits: { receiver: "" } }];

    expect(validateOutgoingPaymentReceiver(access, "https://any.example/incoming")).toBe(false);
  });

  it("allows no receiver when the limit is not a URL", () => {
    const access = [{ type: "outgoing-payment", actions: ["create"], limits: { receiver: "not a url" } }];

    expect(validateOutgoingPaymentReceiver(access, "https://any.example/incoming")).toBe(false);
  });
});

describe("several matched access items", () => {
  const usd = (value: string) => ({ value, assetCode: "USD", assetScale: 2 });

  const items = [
    {
      type: "outgoing-payment",
      actions: ["create"],
      limits: { debitAmount: usd("100"), receiver: "https://a.example/" },
    },
    {
      type: "outgoing-payment",
      actions: ["create"],
      limits: { debitAmount: usd("1000"), receiver: "https://b.example/" },
    },
  ];

  it("lets any item allow the receiver, but requires every item to allow the amount", () => {
    expect(validateOutgoingPaymentReceiver(items, "https://b.example/incoming")).toBe(true);
    expect(validateOutgoingPaymentAmounts(items, usd("100"), undefined)).toBe(true);
    expect(validateOutgoingPaymentAmounts(items, usd("101"), undefined)).toBe(false);
  });
});

describe("compareRequestAndGrantAccessItems with a partial match", () => {
  it("drops the request items the grant does not cover, so a caller compares the lengths", () => {
    const grant = [{ type: "incoming-payment", actions: ["create"] }];
    const request = [
      { type: "incoming-payment", actions: ["create"] },
      { type: "quote", actions: ["create"] },
    ];

    expect(compareRequestAndGrantAccessItems(request, grant)).toEqual(grant);
  });

  it("does not let a `-all` action stand in for a different action, nor a plain one for `-all`", () => {
    expect(
      compareRequestAndGrantAccessItems(
        [{ type: "incoming-payment", actions: ["read"] }],
        [{ type: "incoming-payment", actions: ["list-all"] }],
      ),
    ).toEqual([]);
    expect(
      compareRequestAndGrantAccessItems(
        [{ type: "incoming-payment", actions: ["read-all"] }],
        [{ type: "incoming-payment", actions: ["read"] }],
      ),
    ).toEqual([]);
  });
});

describe("fixed-length repeating windows", () => {
  const steps = [
    ["PT1S", 1000],
    ["PT6H", 6 * 60 * 60 * 1000],
    ["P1D", 24 * 60 * 60 * 1000],
    ["P2D", 2 * 24 * 60 * 60 * 1000],
    ["P1W", 7 * 24 * 60 * 60 * 1000],
  ] as const;

  it("finds the window a one-by-one walk finds, forward and backward, at and around every edge", () => {
    const next = prng(20_261_110);
    const mismatches: string[] = [];

    for (let run = 0; run < 3000; run++) {
      const [duration, length] = steps[next() % steps.length]!;
      const repetitions = ["", "-1", "0", "1", "2", "5"][next() % 6]!;
      const limit = repetitions === "" || repetitions === "-1" ? Number.POSITIVE_INFINITY : Number(repetitions);
      const start = Date.UTC(2022, 0, 1) + (next() % 1_000_000) * 1000;
      const forward = next() % 5 < 3;
      // Half the instants sit on a window edge (`start ± n * length`, give or take a millisecond), the rest anywhere
      // within six and a half windows either side.
      const edge = ((next() % 13) - 6) * length + [-1, 0, 0, 1][next() % 4]!;
      const anywhere = Math.floor(((next() % 1_300_000) / 100_000 - 6.5) * length);
      const now = start + (next() % 2 === 0 ? edge : anywhere);
      const spec = forward
        ? `R${repetitions}/${new Date(start).toISOString()}/${duration}`
        : `R${repetitions}/${duration}/${new Date(start).toISOString()}`;

      // Forward windows are [start + i * length, +length); backward ones end at `start`: [start - (i + 1) * length, +length).
      let expected: number | null = null;

      for (let i = 0; i <= Math.min(limit, 20); i++) {
        const windowStart = forward ? start + i * length : start - (i + 1) * length;

        if (windowStart <= now && now < windowStart + length) {
          expected = windowStart;
          break;
        }
      }

      const found = currentAccessIntervalStart(new Date(0), spec, new Date(now));

      if ((found?.getTime() ?? null) !== expected) {
        mismatches.push(
          `${spec} at ${new Date(now).toISOString()}: expected ${expected}, got ${found?.getTime() ?? null}`,
        );
      }
    }

    expect(mismatches).toEqual([]);
  });
});
