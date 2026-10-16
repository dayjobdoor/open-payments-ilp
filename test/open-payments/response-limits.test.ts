import * as Effect from "effect/Effect";
import { describe, expect, it } from "vite-plus/test";
import { generateEd25519KeyPair } from "../../src/http-signatures/index";
import {
  createAuthenticatedClient,
  createUnauthenticatedClient,
  OpenPaymentsError,
} from "../../src/open-payments/index";

const WALLET = "https://wallet.test/alice";

const walletAddress = {
  id: WALLET,
  publicName: "Alice",
  assetCode: "USD",
  assetScale: 2,
  authServer: "https://auth.test",
  resourceServer: "https://rs.test",
};

const getWallet = (fetch: typeof globalThis.fetch, maxResponseBytes?: number) =>
  createUnauthenticatedClient({ fetch, ...(maxResponseBytes !== undefined && { maxResponseBytes }) }).walletAddress.get(
    {
      url: WALLET,
    },
  );

describe("response size limit", () => {
  it("accepts a response within the limit", async () => {
    const wallet = await Effect.runPromise(getWallet(async () => Response.json(walletAddress), 10_000));

    expect(wallet.id).toBe(WALLET);
  });

  it("refuses a response that announces more than the limit", async () => {
    const fetch = async () => new Response(JSON.stringify(walletAddress), { headers: { "content-length": "10001" } });

    const error = await Effect.runPromise(Effect.flip(getWallet(fetch, 10_000)));

    expect(error).toBeInstanceOf(OpenPaymentsError);
    expect(error.reason).toBe("transport");
  });

  it("stops reading a body that never ends instead of buffering it", async () => {
    const endless = () =>
      new Response(
        new ReadableStream<Uint8Array>({
          pull: (controller) => {
            controller.enqueue(new Uint8Array(1024));
          },
        }),
      );

    const error = await Effect.runPromise(Effect.flip(getWallet(async () => endless(), 10_000)));

    expect(error).toBeInstanceOf(OpenPaymentsError);
    expect(error.reason).toBe("transport");
  });

  it("applies to error responses as well", async () => {
    const error = await Effect.runPromise(
      Effect.flip(getWallet(async () => new Response("x".repeat(20_000), { status: 500 }), 10_000)),
    );

    expect(error.reason).toBe("transport");
  });
});

describe("validateResponses: false", () => {
  it("reports a body the payment checks cannot read as a validation error, not a crash", async () => {
    const { privateKey } = await Effect.runPromise(generateEd25519KeyPair());

    const client = createAuthenticatedClient({
      walletAddressUrl: WALLET,
      keyId: "key-1",
      privateKey,
      validateResponses: false,
      fetch: async () => Response.json({ incomingAmount: { value: "1", assetCode: "USD", assetScale: 2 } }),
    });

    const error = await Effect.runPromise(
      Effect.flip(client.incomingPayment.get({ url: "https://rs.test/incoming-payments/1", accessToken: "token" })),
    );

    expect(error).toBeInstanceOf(OpenPaymentsError);
    expect(error.reason).toBe("validation");
  });
});
