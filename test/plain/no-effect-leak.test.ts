import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
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
import viteConfig from "../../vite.config";

/**
 * Every `plain/*` entry point, under the name `vite.config.ts` packs it as (and `package.json` exports it as). Adding
 * an entry there without adding it here fails "covers every plain entry" below: the checks of this file run over this
 * object, so an entry that is not in it is not checked at all.
 */
const plainEntries = {
  "plain/better-auth": plainBetterAuth,
  "plain/gnap": plainGnap,
  "plain/gnap/server": plainGnapServer,
  "plain/gnap/server/testing": plainGnapServerTesting,
  "plain/http-signatures": plainHttpSignatures,
  "plain/ildcp": plainIldcp,
  "plain/ilp": plainIlp,
  "plain/open-payments": plainOpenPayments,
  "plain/stream": plainStream,
  "plain/webhooks": plainWebhooks,
} as const;

type PlainEntries = typeof plainEntries;

type EffectLike = Effect.Effect<unknown, unknown, unknown> | Result.Result<unknown, unknown>;

/** Names of the exports whose call returns an `Effect` or a `Result` (a `Result` here would be a missed `sync`). */
type LeakingExports<M> = {
  [K in keyof M]: M[K] extends (...args: never[]) => infer R
    ? [R] extends [never]
      ? never
      : R extends EffectLike
        ? K
        : never
    : never;
}[keyof M];

/** Names of the exports that are an `Effect` or a `Result` themselves: a constant, not the result of a call. */
type LeakingValues<M> = { [K in keyof M]: M[K] extends EffectLike ? K : never }[keyof M];

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

/**
 * Dotted paths of the methods of `T`, down three levels of nested objects, whose call returns an `Effect` or a `Result`
 * or a `Promise` of one. What a factory such as `createGnapServer` builds is checked this way: the exports test above
 * only sees what the factory itself returns.
 */
type LeakingMethods<T, Level extends ReadonlyArray<unknown> = []> = Level["length"] extends 3
  ? never
  : {
      [K in keyof T & string]: T[K] extends (...args: never[]) => infer R
        ? [Extract<R | Awaited<R>, EffectLike>] extends [never]
          ? never
          : K
        : T[K] extends object
          ? `${K}.${LeakingMethods<T[K], [...Level, unknown]>}`
          : never;
    }[keyof T & string];

/** What a factory resolves to (or returns). */
type Built<F> = F extends (...args: never[]) => infer R ? Awaited<R> : never;

const isEffectShaped = (value: unknown): boolean => Effect.isEffect(value) || Result.isResult(value);

const root = fileURLToPath(new URL("../../", import.meta.url));

/** The entries of `vite.config.ts` that are `plain/*`, by name, with their source files. */
const configuredPlainEntries = (): Record<string, string> => {
  const { pack } = viteConfig;
  const entry = Array.isArray(pack) ? pack[0]?.entry : pack?.entry;

  if (entry === undefined || Array.isArray(entry) || typeof entry === "string") {
    throw new Error("vite.config.ts: expected `pack.entry` to be an object of entry names and files");
  }

  return Object.fromEntries(
    Object.entries(entry)
      .filter(([name]) => name.startsWith("plain/"))
      .map(([name, source]) => {
        if (typeof source !== "string") throw new Error(`vite.config.ts: ${name} is not one source file`);

        return [name, source];
      }),
  );
};

describe("every plain entry point is checked", () => {
  it("covers every plain entry of vite.config.ts", () => {
    const configured = Object.keys(configuredPlainEntries()).sort();

    expect(configured.length).toBeGreaterThan(0);
    expect(Object.keys(plainEntries).sort()).toEqual(configured);
  });

  it("covers every plain subpath that package.json exports", () => {
    const exported = Object.keys(JSON.parse(readFileSync(resolve(root, "package.json"), "utf8")).exports)
      .filter((subpath) => subpath.startsWith("./plain/"))
      .map((subpath) => subpath.slice(2))
      .sort();

    expect(Object.keys(plainEntries).sort()).toEqual(exported);
  });

  it.each(Object.entries(configuredPlainEntries()))(
    "checks the module that vite.config.ts packs as %s, not another one: %s",
    async (name, source) => {
      const packed: Record<string, unknown> = await import(/* @vite-ignore */ resolve(root, source));
      const checked: Record<string, unknown> = plainEntries[name as keyof PlainEntries];

      expect(Object.keys(checked).sort()).toEqual(Object.keys(packed).sort());

      for (const [exported, value] of Object.entries(checked)) expect(packed[exported], exported).toBe(value);
    },
  );
});

describe("no plain entry returns an Effect or a Result", () => {
  it("is guaranteed by types for every export of every plain entry", () => {
    expectTypeOf<{ [E in keyof PlainEntries]: LeakingExports<PlainEntries[E]> }>().toEqualTypeOf<{
      [E in keyof PlainEntries]: never;
    }>();

    expectTypeOf<{ [E in keyof PlainEntries]: LeakingValues<PlainEntries[E]> }>().toEqualTypeOf<{
      [E in keyof PlainEntries]: never;
    }>();

    expectTypeOf<{ [E in keyof PlainEntries]: NeverExports<PlainEntries[E]> }>().toEqualTypeOf<{
      [E in keyof PlainEntries]: never;
    }>();
  });

  it("is guaranteed by types for what the factories build", () => {
    expectTypeOf<LeakingMethods<Built<typeof plainGnapServer.createGnapServer>>>().toEqualTypeOf<never>();
    expectTypeOf<LeakingMethods<Built<typeof plainGnapServer.memoryGnapStore>>>().toEqualTypeOf<never>();
    expectTypeOf<LeakingMethods<Built<typeof plainBetterAuth.betterAuthGnapStore>>>().toEqualTypeOf<never>();
    expectTypeOf<LeakingMethods<Built<typeof plainOpenPayments.createAuthenticatedClient>>>().toEqualTypeOf<never>();
    expectTypeOf<LeakingMethods<Built<typeof plainOpenPayments.createUnauthenticatedClient>>>().toEqualTypeOf<never>();
  });

  it("detects a Result or an Effect when one is returned (the check can fail)", () => {
    expectTypeOf<
      LeakingExports<{ a: () => Result.Result<1, 2>; b: () => Effect.Effect<1>; c: () => 1 }>
    >().toEqualTypeOf<"a" | "b">();
    expectTypeOf<LeakingValues<{ a: Effect.Effect<1>; b: Result.Result<1, 2>; c: () => 1; d: 1 }>>().toEqualTypeOf<
      "a" | "b"
    >();
    expectTypeOf<
      LeakingMethods<{
        a: { b: () => Effect.Effect<1> };
        c: () => Promise<Result.Result<1, 2>>;
        d: () => 1;
        e: { f: () => Promise<1> };
      }>
    >().toEqualTypeOf<"a.b" | "c">();
    expect(isEffectShaped(Result.succeed(1))).toBe(true);
    expect(isEffectShaped(Effect.succeed(1))).toBe(true);
    expect(isEffectShaped(1)).toBe(false);
  });

  it("exports no value that is an Effect or a Result", () => {
    for (const [name, entry] of Object.entries(plainEntries)) {
      for (const [exported, value] of Object.entries(entry))
        expect(isEffectShaped(value), `${name}: ${exported}`).toBe(false);
    }
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
        "defaultRequiresInteraction",
        () =>
          plainGnapServer.defaultRequiresInteraction({
            client: plainGnap.parseClientField("https://wallet.test/a"),
            access: [],
          }),
        false,
      ],
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
      [
        "storeContract",
        () =>
          plainGnapServerTesting.storeContract(
            { describe: (_name, register) => register(), it: () => undefined },
            "memory",
            () => plainGnapServer.memoryGnapStore(),
          ),
        undefined,
      ],
      ["gnap (Better Auth plugin)", () => plainBetterAuth.gnap().id, "gnap"],
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
      () =>
        plainGnapServer
          .fetchClientKeys(async () => new Response("no", { status: 404 }))("https://wallet.test/a")
          .catch(() => "rejected"),
    ];

    for (const call of calls) {
      const pending = call();

      expect(pending).toBeInstanceOf(Promise);

      expect(isEffectShaped(await pending)).toBe(false);
    }
  });

  it("returns Promises resolving to plain values from what the factories build", async () => {
    const store = plainGnapServer.memoryGnapStore();
    const server = plainGnapServer.createGnapServer({ baseUrl: "https://as.test/gnap", store });

    const auth = betterAuth({
      baseURL: "https://as.test",
      secret: "x".repeat(40),
      plugins: [plainBetterAuth.gnap()],
      database: memoryAdapter(
        Object.fromEntries(
          ["user", "session", "account", "verification", "gnapGrant", "gnapAccessToken", "gnapNonce"].map((model) => [
            model,
            [],
          ]),
        ),
      ),
    });

    const authStore = plainBetterAuth.betterAuthGnapStore((await auth.$context).adapter);

    const calls: ReadonlyArray<readonly [string, () => Promise<unknown>]> = [
      ["memoryGnapStore().claimNonce", () => store.claimNonce("k", 2_000, 1_000)],
      ["memoryGnapStore().findGrant", () => store.findGrant("id", "none")],
      ["betterAuthGnapStore().claimNonce", () => authStore.claimNonce("k", 2_000, 1_000)],
      ["betterAuthGnapStore().findTokenWithGrant", () => authStore.findTokenWithGrant("valueHash", "none")],
      ["createGnapServer().route", () => server.route(new Request("https://as.test/gnap/nowhere"))],
      ["createGnapServer().introspectToken", () => server.introspectToken("none")],
    ];

    for (const [name, call] of calls) {
      const pending = call();

      expect(pending, name).toBeInstanceOf(Promise);
      expect(isEffectShaped(await pending), name).toBe(false);
    }
  });
});
