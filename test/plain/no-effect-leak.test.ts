import * as Effect from "effect/Effect";
import * as Result from "effect/Result";
import { describe, expect, expectTypeOf, it } from "vite-plus/test";
import * as plainBetterAuth from "../../src/plain/better-auth";
import * as plainGnap from "../../src/plain/gnap";
import * as plainGnapServer from "../../src/plain/gnap-server";
import * as plainGnapServerTesting from "../../src/plain/gnap-server-testing";
import * as plainHttpSignatures from "../../src/plain/http-signatures";
import * as plainIldcp from "../../src/plain/ildcp";
import * as plainIlp from "../../src/plain/ilp";
import * as plainOpenPayments from "../../src/plain/open-payments";
import * as plainStream from "../../src/plain/stream";
import * as plainWebhooks from "../../src/plain/webhooks";

/** Names of the exports whose call returns an `Effect` or a `Result` (a `Result` here would be a missed `sync`). */
type LeakingExports<M> = {
  [K in keyof M]: M[K] extends (...args: never[]) => infer R
    ? [R] extends [never]
      ? never
      : R extends Effect.Effect<unknown, unknown, unknown> | Result.Result<unknown, unknown>
        ? K
        : never
    : never;
}[keyof M];

/** Names of the function exports typed as returning `never` (a wrapper applied to the wrong kind of function). */
type NeverExports<M> = {
  [K in keyof M]: M[K] extends (...args: never[]) => infer R
    ? [R] extends [never]
      ? K
      : never
    : [M[K]] extends [never]
      ? K
      : never;
}[keyof M];

const isEffectShaped = (value: unknown): boolean => Effect.isEffect(value) || Result.isResult(value);

describe("no plain entry returns an Effect or a Result", () => {
  it("is guaranteed by types for every export of every plain entry", () => {
    expectTypeOf<LeakingExports<typeof plainBetterAuth>>().toEqualTypeOf<never>();
    expectTypeOf<LeakingExports<typeof plainGnap>>().toEqualTypeOf<never>();
    expectTypeOf<LeakingExports<typeof plainGnapServer>>().toEqualTypeOf<never>();
    expectTypeOf<LeakingExports<typeof plainGnapServerTesting>>().toEqualTypeOf<never>();
    expectTypeOf<LeakingExports<typeof plainHttpSignatures>>().toEqualTypeOf<never>();
    expectTypeOf<LeakingExports<typeof plainIldcp>>().toEqualTypeOf<never>();
    expectTypeOf<LeakingExports<typeof plainIlp>>().toEqualTypeOf<never>();
    expectTypeOf<LeakingExports<typeof plainOpenPayments>>().toEqualTypeOf<never>();
    expectTypeOf<LeakingExports<typeof plainStream>>().toEqualTypeOf<never>();
    expectTypeOf<LeakingExports<typeof plainWebhooks>>().toEqualTypeOf<never>();

    expectTypeOf<NeverExports<typeof plainGnap>>().toEqualTypeOf<never>();
    expectTypeOf<NeverExports<typeof plainHttpSignatures>>().toEqualTypeOf<never>();
    expectTypeOf<NeverExports<typeof plainIldcp>>().toEqualTypeOf<never>();
    expectTypeOf<NeverExports<typeof plainIlp>>().toEqualTypeOf<never>();
    expectTypeOf<NeverExports<typeof plainOpenPayments>>().toEqualTypeOf<never>();
    expectTypeOf<NeverExports<typeof plainStream>>().toEqualTypeOf<never>();
    expectTypeOf<NeverExports<typeof plainWebhooks>>().toEqualTypeOf<never>();
  });

  it("detects a Result or an Effect when one is returned (the check can fail)", () => {
    expectTypeOf<
      LeakingExports<{ a: () => Result.Result<1, 2>; b: () => Effect.Effect<1>; c: () => 1 }>
    >().toEqualTypeOf<"a" | "b">();
    expect(isEffectShaped(Result.succeed(1))).toBe(true);
    expect(isEffectShaped(Effect.succeed(1))).toBe(true);
    expect(isEffectShaped(1)).toBe(false);
  });

  it("returns plain values from sample calls of the codecs", () => {
    const request = new Request("https://rs.test/x", { method: "POST" });
    const amount = { value: "5", assetCode: "USD", assetScale: 2 };

    const samples: ReadonlyArray<readonly [string, () => unknown, unknown]> = [
      ["parseAmountValue", () => plainOpenPayments.parseAmountValue("12"), 12n],
      ["compareAmounts", () => plainOpenPayments.compareAmounts(amount, amount), 0],
      ["addAmounts", () => plainOpenPayments.addAmounts(amount, amount), { ...amount, value: "10" }],
      ["parseDictionary", () => plainHttpSignatures.parseDictionary("a=1"), expect.any(Array)],
      [
        "serializeItem",
        () => plainHttpSignatures.serializeItem({ value: { type: "integer", value: 1 }, params: [] }),
        "1",
      ],
      ["serializeInnerList", () => plainHttpSignatures.serializeInnerList({ items: [], params: [] }), "()"],
      ["serializeSignatureParams", () => plainHttpSignatures.serializeSignatureParams(["@method"], []), '("@method")'],
      [
        "createSignatureBase",
        () => plainHttpSignatures.createSignatureBase(request, ["@method"], []),
        '"@method": POST\n"@signature-params": ("@method")',
      ],
      ["canonicalizeJson", () => plainWebhooks.canonicalizeJson({ b: 1, a: 2 }), '{"a":2,"b":1}'],
      [
        "decodeStreamReceipt",
        () => plainStream.decodeStreamReceipt(new Uint8Array(58)),
        expect.objectContaining({ version: 0 }),
      ],
      ["parseClientField", () => plainGnap.parseClientField("https://wallet.test/a"), expect.anything()],
      [
        "serializeIldcpResponse",
        () =>
          plainIldcp.serializeIldcpResponse({
            clientAddress: "g.a",
            assetScale: 0,
            assetCode: "USD",
          }),
        expect.any(Uint8Array),
      ],
      [
        "serializeReject",
        () =>
          plainIlp.serializeReject({
            code: "F00",
            triggeredBy: "g.a",
            message: "",
            data: new Uint8Array(0),
          }),
        expect.any(Uint8Array),
      ],
    ];

    for (const [name, call, expected] of samples) {
      const value = call();

      expect(isEffectShaped(value), name).toBe(false);
      expect(value, name).toEqual(expected);
    }
  });

  it("returns Promises resolving to plain values from sample calls of the async helpers", async () => {
    const calls: ReadonlyArray<() => Promise<unknown>> = [
      () => plainHttpSignatures.generateEd25519KeyPair(),
      () => plainHttpSignatures.createContentDigest(new Uint8Array([1])),
      () => plainIlp.conditionFromFulfillment(new Uint8Array(32)),
      () => plainStream.deriveStreamKeys(new Uint8Array(32).fill(1)),
      () => plainGnap.hashToken("token"),
      () => plainWebhooks.isValidWebhookSignature({}, undefined, { secret: "s" }),
      () => plainIldcp.fetchIldcp(() => new Uint8Array(2)).catch(() => "rejected"),
    ];

    for (const call of calls) {
      const pending = call();

      expect(pending).toBeInstanceOf(Promise);
      expect(isEffectShaped(await pending)).toBe(false);
    }
  });
});
