import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { describe, expect, it } from "vite-plus/test";
import { betterAuthGnapStore, gnap, gnapSchema } from "../../src/plain/better-auth";
import { storeContract } from "../../src/plain/gnap-server-testing";
import { generateEd25519KeyPair, signRequest } from "../../src/plain/http-signatures";

const BASE_URL = "https://as.test";
const WALLET = "https://wallet.test/alice";
const MODELS = ["user", "session", "account", "verification", ...Object.keys(gnapSchema)];

const memoryDatabase = () => memoryAdapter(Object.fromEntries(MODELS.map((model) => [model, []])));

storeContract(
  { describe, it },
  "plain betterAuthGnapStore on Better Auth's memory adapter",
  async () => {
    const auth = betterAuth({
      baseURL: BASE_URL,
      secret: "x".repeat(40),
      plugins: [gnap()],
      database: memoryDatabase(),
    });

    return betterAuthGnapStore((await auth.$context).adapter);
  },
  { uniqueConstraints: false },
);

describe("plain better-auth plugin", () => {
  it("serves grants with async hooks instead of Effects", async () => {
    const { privateKey, publicJwk } = await generateEd25519KeyPair();
    const lookups: string[] = [];
    const auth = betterAuth({
      baseURL: BASE_URL,
      secret: "x".repeat(40),
      database: memoryDatabase(),
      plugins: [
        gnap({
          resolveClientKeys: async (walletAddress) => {
            lookups.push(walletAddress);

            return [
              {
                kty: "OKP",
                crv: "Ed25519",
                x: publicJwk.x ?? "",
                kid: "k1",
                alg: "EdDSA",
                use: "sig",
              },
            ];
          },
        }),
      ],
    });
    const request = await signRequest(
      new Request(`${BASE_URL}/api/auth/gnap`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          client: WALLET,
          access_token: { access: [{ type: "incoming-payment", actions: ["create", "read"] }] },
        }),
      }),
      { keyId: "k1", privateKey },
    );
    const response = await auth.handler(request);

    expect(response.status).toBe(200);
    expect(lookups).toEqual([WALLET]);
    expect(await response.json()).toHaveProperty("access_token.value");
  });
});
