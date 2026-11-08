import { describe, expect, it } from "vite-plus/test";
import {
  canonicalizeJson,
  isValidWebhookSignature,
  signWebhook,
  verifyWebhookSignature,
  WebhookError,
} from "../../src/plain/webhooks";

const body = { id: "evt-1", type: "incoming_payment.completed", data: { b: 2, a: 1 } };
const config = { secret: "whsec", clock: () => new Date("2030-01-01T00:00:00.000Z") };

describe("plain webhooks", () => {
  it("signs and verifies a webhook body", async () => {
    const header = await signWebhook(body, config);

    await expect(verifyWebhookSignature(body, header, config)).resolves.toBeUndefined();
    expect(await isValidWebhookSignature(body, header, config)).toBe(true);
  });

  it("rejects with WebhookError for a wrong secret or a changed body, and reports false from isValid", async () => {
    const header = await signWebhook(body, config);

    await expect(verifyWebhookSignature(body, header, { ...config, secret: "other" })).rejects.toBeInstanceOf(
      WebhookError,
    );
    await expect(verifyWebhookSignature({ ...body, id: "evt-2" }, header, config)).rejects.toBeInstanceOf(WebhookError);
    await expect(verifyWebhookSignature(body, undefined, config)).rejects.toMatchObject({
      _tag: "WebhookError",
    });
    expect(await isValidWebhookSignature(body, header, { ...config, secret: "other" })).toBe(false);
  });

  it("canonicalizes JSON per RFC 8785 and throws WebhookError for values that cannot be", () => {
    expect(canonicalizeJson({ b: 2, a: [1, "x"] })).toBe('{"a":[1,"x"],"b":2}');
    expect(() => canonicalizeJson({ n: Number.NaN })).toThrow(WebhookError);
  });
});
