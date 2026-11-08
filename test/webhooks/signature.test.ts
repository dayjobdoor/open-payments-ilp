import { createHmac } from "node:crypto";
import * as Effect from "effect/Effect";
import { canonicalize } from "json-canonicalize";
import { describe, expect, it } from "vite-plus/test";
import {
  isValidWebhookSignature,
  signWebhook,
  verifyWebhookSignature,
  WebhookError,
  type JsonValue,
  type WebhookErrorReason,
} from "../../src/webhooks/index";

const NOW = 1_700_000_000_000;

const clock = { clock: () => new Date(NOW) };

const sign = (body: JsonValue, config: Parameters<typeof signWebhook>[1], timestamp = NOW): Promise<string> =>
  Effect.runPromise(signWebhook(body, { ...config, clock: () => new Date(timestamp) }));

const verifyReason = async (
  body: JsonValue,
  header: string | undefined,
  config: Parameters<typeof verifyWebhookSignature>[2],
): Promise<WebhookErrorReason | "ok"> => {
  const error = await Effect.runPromise(
    verifyWebhookSignature(body, header, config).pipe(
      Effect.as("ok" as const),
      Effect.catch((failure) => Effect.succeed(failure)),
    ),
  );

  return error === "ok" ? "ok" : error.reason;
};

// Reimplementation of rafiki/packages/backend/src/webhook/service.ts generateWebhookSignature.
const rafikiSign = (event: { id: string; type: string; data: object }, secret: string, version: number, t: number) =>
  `t=${t}, v${version}=${createHmac("sha256", secret)
    .update(`${t}.${canonicalize({ id: event.id, type: event.type, data: event.data })}`)
    .digest("hex")}`;

const event = {
  id: "e1",
  type: "incoming_payment.completed",
  data: { b: 2, a: 1, nested: { z: "日本語", y: [1.25, null] } },
};

describe("signWebhook", () => {
  it("produces exactly what Rafiki produces, for every version", async () => {
    for (const version of [1, 2, 3]) {
      expect(await sign(event, { secret: "s3cret", version }, NOW)).toBe(rafikiSign(event, "s3cret", version, NOW));
    }
  });

  it("defaults to Rafiki's version 1 and does not depend on key order", async () => {
    const reordered = { data: event.data, type: event.type, id: event.id };

    expect(await sign(event, { secret: "s" })).toBe(rafikiSign(event, "s", 1, NOW));
    expect(await sign(reordered, { secret: "s" })).toBe(await sign(event, { secret: "s" }));
  });

  it("fails for a body JSON cannot carry", async () => {
    const failure = await Effect.runPromise(Effect.flip(signWebhook(Number.NaN, { secret: "s", ...clock })));

    expect(failure).toBeInstanceOf(WebhookError);
    expect(failure.reason).toBe("unsupported-value");
  });

  it("fails with missing, not an untagged WebCrypto error, for an empty secret", async () => {
    const failure = await Effect.runPromise(Effect.flip(signWebhook(event, { secret: "", ...clock })));

    expect(failure).toBeInstanceOf(WebhookError);
    expect(failure.reason).toBe("missing");
  });

  it("fails with invalid-config when its clock returns an Invalid Date", async () => {
    const failure = await Effect.runPromise(
      Effect.flip(signWebhook(event, { secret: "s", clock: () => new Date(Number.NaN) })),
    );

    expect(failure.reason).toBe("invalid-config");
  });

  it("stamps the time its clock reads when the effect runs, not when it is built", async () => {
    let current = NOW;
    const signing = signWebhook(event, { secret: "s", clock: () => new Date(current) });

    current = NOW + 5_000;

    expect(await Effect.runPromise(signing)).toMatch(new RegExp(`^t=${NOW + 5_000}, `));
  });
});

describe("verifyWebhookSignature", () => {
  it("verifies a Rafiki-produced signature", async () => {
    expect(await verifyReason(event, rafikiSign(event, "s", 1, NOW), { secret: "s", version: 1, ...clock })).toBe("ok");
  });

  it("verifies its own signature regardless of key order", async () => {
    const header = await sign({ z: 1, a: "日本語", nested: { b: 2, a: 1 } }, { secret: "secret" });

    expect(
      await verifyReason({ nested: { a: 1, b: 2 }, a: "日本語", z: 1 }, header, { secret: "secret", ...clock }),
    ).toBe("ok");
  });

  it("names the reason a signature is rejected", async () => {
    const header = await sign({ amount: 1.25 }, { secret: "secret" });
    const config = { secret: "secret", ...clock };

    expect(await verifyReason({ amount: 1.26 }, header, config)).toBe("mismatch");
    expect(await verifyReason({ amount: 1.25 }, header, { ...config, secret: "other" })).toBe("mismatch");
    expect(await verifyReason({ amount: 1.25 }, header, { ...config, version: 2 })).toBe("version-mismatch");
    expect(await verifyReason({ amount: 1.25 }, undefined, config)).toBe("missing");
    expect(await verifyReason({ amount: 1.25 }, header, { ...config, secret: "" })).toBe("missing");
    expect(await verifyReason({ amount: 1.25 }, "garbage", config)).toBe("malformed");
    expect(await verifyReason({ amount: 1.25 }, header.toUpperCase(), config)).toBe("malformed");
    expect(await verifyReason({ amount: 1.25 }, `t=${"9".repeat(20)}, v2=${"0".repeat(64)}`, config)).toBe("malformed");
    expect(await verifyReason(Number.NaN, header, config)).toBe("unsupported-value");
  });

  it("enforces the replay window at its boundaries", async () => {
    const body = { amount: 1 };
    const config = { secret: "secret", ...clock };

    const at = (offset: number) => sign(body, { secret: "secret" }, NOW + offset);

    expect(await verifyReason(body, await at(-300_000), config)).toBe("ok");
    expect(await verifyReason(body, await at(-300_001), config)).toBe("expired");
    expect(await verifyReason(body, await at(30_000), config)).toBe("ok");
    expect(await verifyReason(body, await at(30_001), config)).toBe("future");
    expect(await verifyReason(body, await at(-1_000), { ...config, maxAgeMs: 500 })).toBe("expired");
    expect(await verifyReason(body, await at(2_000), { ...config, futureSkewMs: 1_000 })).toBe("future");
  });

  it("accepts the header with or without the space after the comma", async () => {
    const header = rafikiSign(event, "s", 1, NOW);

    expect(await verifyReason(event, header.replace(", ", ","), { secret: "s", ...clock })).toBe("ok");
  });

  it("collapses to a boolean with isValidWebhookSignature", async () => {
    const header = await sign(event, { secret: "s" });

    expect(await Effect.runPromise(isValidWebhookSignature(event, header, { secret: "s", ...clock }))).toBe(true);
    expect(await Effect.runPromise(isValidWebhookSignature(event, header, { secret: "x", ...clock }))).toBe(false);
    expect(await Effect.runPromise(isValidWebhookSignature(event, undefined, { secret: "s", ...clock }))).toBe(false);
  });

  it("reads the clock when the effect runs, not when it is built", async () => {
    const header = await sign(event, { secret: "s" });
    let current = NOW;
    const verification = verifyWebhookSignature(event, header, { secret: "s", clock: () => new Date(current) });

    current = NOW + 400_000;

    const outcome = await Effect.runPromise(
      verification.pipe(
        Effect.as("ok" as const),
        Effect.catch((failure) => Effect.succeed(failure.reason)),
      ),
    );

    expect(outcome).toBe("expired");
  });

  it("signs and verifies a body nested far deeper than any stack could recurse", async () => {
    let deep: JsonValue = [];

    for (let level = 0; level < 100_000; level++) deep = [deep];
    const header = await sign(deep, { secret: "s" });

    expect(await verifyReason(deep, header, { secret: "s", ...clock })).toBe("ok");
    expect(await verifyReason(deep, `t=${NOW}, v1=${"0".repeat(64)}`, { secret: "s", ...clock })).toBe("mismatch");
  });

  it("ignores whitespace around the header and nothing else", async () => {
    const header = rafikiSign(event, "s", 1, NOW);
    const config = { secret: "s", ...clock };

    expect(await verifyReason(event, `  ${header}\t\n`, config)).toBe("ok");
    expect(await verifyReason(event, header.replace("t=", "t= "), config)).toBe("malformed");
    expect(await verifyReason(event, header.replace(", v1", " ,v1"), config)).toBe("malformed");
    expect(await verifyReason(event, "   ", config)).toBe("malformed");
  });

  it("fails closed, with invalid-config, on a replay window or clock that would switch the checks off", async () => {
    const header = await sign(event, { secret: "s" }, NOW - 1_000_000);
    const config = { secret: "s", ...clock };

    for (const maxAgeMs of [Number.NaN, Number.POSITIVE_INFINITY, -1]) {
      expect(await verifyReason(event, header, { ...config, maxAgeMs })).toBe("invalid-config");
    }

    for (const futureSkewMs of [Number.NaN, Number.POSITIVE_INFINITY, -1]) {
      expect(await verifyReason(event, header, { ...config, futureSkewMs })).toBe("invalid-config");
    }

    expect(await verifyReason(event, header, { secret: "s", clock: () => new Date(Number.NaN) })).toBe(
      "invalid-config",
    );
    // The documented bounds themselves are fine: a zero window accepts only the current millisecond.
    expect(
      await verifyReason(event, await sign(event, { secret: "s" }), { ...config, maxAgeMs: 0, futureSkewMs: 0 }),
    ).toBe("ok");
  });

  it("verifies what Rafiki signs for metadata with a toJSON member, which json-canonicalize leaves unsorted", async () => {
    // SAFETY: deliberately outside JsonValue; metadata is chosen by the sender of the webhook.
    const metadata = { toJSON: 1, b: 1, a: 2 } as never;
    const withMetadata = { id: "e2", type: "incoming_payment.created", data: { metadata } };
    const header = rafikiSign(withMetadata, "s", 1, NOW);

    expect(await verifyReason(withMetadata, header, { secret: "s", version: 1, ...clock })).toBe("ok");
    expect(await sign(withMetadata, { secret: "s" })).toBe(header);
  });
});
