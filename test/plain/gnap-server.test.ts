import { describe, expect, it } from "vite-plus/test";
import { generateEd25519KeyPair, signRequest, HttpSignatureError } from "../../src/plain/http-signatures";
import {
  createGnapServer,
  fetchClientKeys,
  GnapRouteError,
  memoryGnapStore,
  type GnapStore,
} from "../../src/plain/gnap-server";
import { storeContract } from "../../src/plain/gnap-server-testing";

const BASE_URL = "https://as.test/gnap";
const WALLET = "https://wallet.test/alice";
const KEY_ID = "alice-key-1";

const setup = async (overrides: Partial<Parameters<typeof createGnapServer>[0]> = {}) => {
  const { privateKey, publicJwk } = await generateEd25519KeyPair();
  const jwk = {
    kty: "OKP",
    crv: "Ed25519",
    x: publicJwk.x ?? "",
    kid: KEY_ID,
    alg: "EdDSA",
    use: "sig",
  } as const;
  const server = createGnapServer({
    baseUrl: BASE_URL,
    store: memoryGnapStore(),
    interaction: { consentUrl: "https://app.test/consent", authorize: async () => true },
    idpSecret: "idp-secret",
    resolveClientKeys: async (walletAddress) => (walletAddress === WALLET ? [jwk] : []),
    ...overrides,
  });
  const grantRequest = async (access: unknown[], extra: Record<string, unknown> = {}, url = BASE_URL) =>
    server.route(
      await signRequest(
        new Request(url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ client: WALLET, access_token: { access }, ...extra }),
        }),
        { keyId: KEY_ID, privateKey },
      ),
    );

  return { server, grantRequest, publicJwk: jwk };
};

const incoming = { type: "incoming-payment", actions: ["create", "read"] };

describe("plain gnap server", () => {
  it("grants a non-interactive request with an async client-key resolver and introspects the token", async () => {
    const { server, grantRequest } = await setup();
    const response = await grantRequest([incoming]);
    const grant = (await response.json()) as { access_token: { value: string } };

    expect(response.status).toBe(200);
    expect(await server.introspectToken(grant.access_token.value)).toMatchObject({ active: true });
    expect(await server.introspectToken("unknown")).toMatchObject({ active: false });
  });

  it.each([
    ["returns null", async () => null],
    ["returns undefined", async () => undefined],
    [
      "rejects with an HttpSignatureError",
      async () => {
        throw new HttpSignatureError({ reason: "unknown-key", message: "no such wallet" });
      },
    ],
  ])("answers 400 invalid_client when the key resolver %s", async (_name, resolveClientKeys) => {
    const reported: unknown[] = [];
    const { grantRequest } = await setup({
      resolveClientKeys,
      onError: (error) => void reported.push(error),
    });
    const response = await grantRequest([incoming]);

    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: { code: "invalid_client" } });
    expect(reported).toEqual([]);
  });

  it("treats any other throw of the key resolver as a defect: 500, reported to onError with the original error", async () => {
    const reported: unknown[] = [];
    const boom = new Error("directory down");
    const { grantRequest } = await setup({
      resolveClientKeys: async () => {
        throw boom;
      },
      onError: (error) => void reported.push(error),
    });
    const response = await grantRequest([incoming]);

    expect(response.status).toBe(500);
    expect(reported).toContain(boom);
  });

  it("serves POST /introspect to a caller the async authorize hook recognises", async () => {
    const { server, grantRequest } = await setup({
      introspection: { authorize: async (request) => request.headers.get("x-rs") === "secret" },
    });
    const grant = (await (await grantRequest([incoming])).json()) as {
      access_token: { value: string };
    };
    const ask = (headers: Record<string, string>) =>
      server.route(
        new Request(`${BASE_URL}/introspect`, {
          method: "POST",
          headers: { "content-type": "application/json", ...headers },
          body: JSON.stringify({ access_token: grant.access_token.value }),
        }),
      );

    expect(await (await ask({ "x-rs": "secret" })).json()).toMatchObject({ active: true });
    expect((await ask({})).status).toBe(400);
  });

  it("decides an interaction with Promise APIs and rejects with GnapRouteError for an unknown one", async () => {
    const { server, grantRequest } = await setup();
    const response = await grantRequest(
      [
        {
          type: "outgoing-payment",
          actions: ["create"],
          identifier: WALLET,
          limits: { debitAmount: { value: "100", assetCode: "USD", assetScale: 2 } },
        },
      ],
      {
        interact: {
          start: ["redirect"],
          finish: { method: "redirect", uri: "https://client.test/finish", nonce: "n" },
        },
      },
    );
    const pending = (await response.json()) as { interact: { redirect: string } };
    const [nonce, interactId] = new URL(pending.interact.redirect).pathname.split("/").reverse();

    expect(await server.getInteraction({ interactId: interactId!, nonce: nonce! })).toMatchObject({
      state: "PENDING",
    });
    expect(
      await server.decideInteraction({
        interactId: interactId!,
        nonce: nonce!,
        choice: "accept",
        userId: "u1",
      }),
    ).toHaveProperty("redirect");
    await expect(server.getInteraction({ interactId: "nope", nonce: "nope" })).rejects.toBeInstanceOf(GnapRouteError);
  });

  it("reports a failing store to onError with the original error and answers 500", async () => {
    const reported: unknown[] = [];
    const boom = new Error("db down");
    const store: GnapStore = {
      ...memoryGnapStore(),
      createGrant: async () => Promise.reject(boom),
    };
    const { grantRequest } = await setup({
      store,
      onError: async (error) => void reported.push(error),
    });
    const response = await grantRequest([incoming]);

    expect(response.status).toBe(500);
    expect(reported).toContain(boom);
  });

  it("serves a tenant resolved by an async hook", async () => {
    const { grantRequest } = await setup({
      tenants: async (id) => (id === "acme" ? { idpSecret: "s" } : null),
    });

    expect((await grantRequest([incoming], {}, `${BASE_URL}/acme`)).status).toBe(200);
    expect((await grantRequest([incoming], {}, `${BASE_URL}/ghost`)).status).toBe(404);
  });

  it("fetches client keys over the injected fetch, rejecting with HttpSignatureError for unusable addresses", async () => {
    const { publicJwk } = await setup();
    const keys = fetchClientKeys(async () => Response.json({ keys: [publicJwk] }));

    expect(await keys("https://wallet.example/alice")).toHaveLength(1);
    await expect(keys("http://127.0.0.1/alice")).rejects.toBeInstanceOf(HttpSignatureError);
  });
});

storeContract({ describe, it }, "plain memoryGnapStore", () => memoryGnapStore());
