import { beforeEach, describe, expect, it } from "vite-plus/test";
import { generateEd25519KeyPair, importPrivateKey } from "../../src/plain/http-signatures";
import {
  createAuthenticatedClient,
  createUnauthenticatedClient,
  OpenPaymentsError,
  type AuthenticatedClient,
} from "../../src/plain/open-payments";
import { createFakeServer, type FakeServer } from "../open-payments/fake-server";

const ORIGIN = "https://op.test";
const WALLET = `${ORIGIN}/alice`;
const resource = { url: `${ORIGIN}/rs`, accessToken: "TOKEN-123" };

let server: FakeServer;
let privateKey: CryptoKey;
let client: AuthenticatedClient;

const fetchFromServer = (input: RequestInfo | URL, init?: RequestInit): Promise<Response> =>
  server.handle(new Request(input, init));

beforeEach(async () => {
  const pair = await generateEd25519KeyPair();

  privateKey = pair.privateKey;
  server = await createFakeServer({ "test-key": pair.publicJwk });
  client = await createAuthenticatedClient({
    walletAddressUrl: WALLET,
    keyId: "test-key",
    privateKey,
    fetch: fetchFromServer,
  });
});

describe("plain open-payments client", () => {
  it("returns Promises and sends signed requests, like @interledger/open-payments", async () => {
    const created = client.incomingPayment.create(resource, {
      walletAddress: WALLET,
      incomingAmount: { value: "2500", assetCode: "USD", assetScale: 2 },
    });

    expect(created).toBeInstanceOf(Promise);
    expect((await created).methods[0]).toMatchObject({ type: "ilp" });
    expect(server.requests.at(-1)).toMatchObject({ method: "POST", signedBy: "test-key" });
    expect(server.requests.at(-1)?.headers.get("authorization")).toBe("GNAP TOKEN-123");
  });

  it("rejects with OpenPaymentsError instead of returning a failure", async () => {
    server.respondOnce("GET /alice", new Response("{}", { status: 404 }));

    const error = await client.walletAddress.get({ url: WALLET }).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(OpenPaymentsError);
    expect(error).toMatchObject({ _tag: "OpenPaymentsError", status: 404 });
  });

  it("retries with a Promise-returning sleep", async () => {
    const waits: number[] = [];
    let calls = 0;
    const retrying = await createAuthenticatedClient({
      walletAddressUrl: WALLET,
      keyId: "test-key",
      privateKey,
      retry: {
        maxAttempts: 3,
        sleep: async (ms) => {
          waits.push(ms);
        },
      },
      fetch: async (input, init) => {
        calls += 1;

        return calls < 3 ? new Response("busy", { status: 503 }) : fetchFromServer(input, init);
      },
    });

    expect(await retrying.walletAddress.get({ url: WALLET })).toMatchObject({ assetCode: "USD" });
    expect(calls).toBe(3);
    expect(waits).toHaveLength(2);
  });

  it("exposes every route group of the authenticated client", () => {
    expect(Object.keys(client).sort()).toEqual(
      ["grant", "incomingPayment", "outgoingPayment", "quote", "token", "walletAddress"].sort(),
    );
    expect(typeof client.grant.request).toBe("function");
  });

  it("accepts the private key as a JWK or a PEM string", async () => {
    const jwk = await crypto.subtle.exportKey("jwk", privateKey);
    const pem = `-----BEGIN PRIVATE KEY-----\n${btoa(
      String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey("pkcs8", privateKey))),
    )}\n-----END PRIVATE KEY-----`;

    expect(await importPrivateKey(privateKey)).toBe(privateKey);

    for (const input of [jwk, pem]) {
      const other = await createAuthenticatedClient({
        walletAddressUrl: WALLET,
        keyId: "test-key",
        privateKey: input,
        fetch: fetchFromServer,
      });

      await other.incomingPayment.get({ ...resource, url: `${ORIGIN}/rs/incoming-payments/1` });
      expect(server.requests.at(-1)?.signedBy).toBe("test-key");
    }
  });

  it("rejects with HttpSignatureError for a key that is not Ed25519", async () => {
    await expect(
      createAuthenticatedClient({ walletAddressUrl: WALLET, keyId: "k", privateKey: "not a pem" }),
    ).rejects.toMatchObject({ _tag: "HttpSignatureError" });
  });

  it("creates an unauthenticated client that never signs", async () => {
    const anonymous = await createUnauthenticatedClient({ fetch: fetchFromServer });

    expect(await anonymous.walletAddress.get({ url: WALLET })).toMatchObject({ assetCode: "USD" });
    expect(server.requests.at(-1)?.headers.has("signature")).toBe(false);
  });
});
