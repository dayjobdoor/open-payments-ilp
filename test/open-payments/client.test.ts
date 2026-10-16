import * as Effect from "effect/Effect";
import { beforeEach, describe, expect, it } from "vite-plus/test";
import { generateEd25519KeyPair } from "../../src/http-signatures/index";
import {
  createAuthenticatedClient,
  createUnauthenticatedClient,
  OpenPaymentsError,
  type AuthenticatedClient,
  type GrantRequestAccessItem,
} from "../../src/open-payments/index";
import { createFakeServer, type FakeServer } from "./fake-server";

const ORIGIN = "https://op.test";

const TOKEN = "TOKEN-123";

const WALLET = `${ORIGIN}/alice`;

let server: FakeServer;

let client: AuthenticatedClient;

let privateKey: CryptoKey;

const run = <A>(effect: Effect.Effect<A, OpenPaymentsError>): Promise<A> => Effect.runPromise(effect);

const fail = (effect: Effect.Effect<unknown, OpenPaymentsError>): Promise<OpenPaymentsError> =>
  Effect.runPromise(Effect.flip(effect));

const resource = { url: `${ORIGIN}/rs`, accessToken: TOKEN };

// A fresh server (no recorded requests, no queued overrides) for every test.
beforeEach(async () => {
  const pair = await Effect.runPromise(generateEd25519KeyPair());
  const { publicJwk } = pair;

  privateKey = pair.privateKey;
  server = await createFakeServer({ "test-key": publicJwk });
  client = createAuthenticatedClient({
    walletAddressUrl: WALLET,
    keyId: "test-key",
    privateKey,
    fetch: (input, init) => server.handle(new Request(input, init)),
  });
});

describe("wallet address routes", () => {
  it("fetch the wallet address, keys and DID document without signing", async () => {
    const unauthenticated = createUnauthenticatedClient({
      fetch: (input, init) => server.handle(new Request(input, init)),
    });

    const before = server.requests.length;

    expect(await run(unauthenticated.walletAddress.get({ url: WALLET }))).toMatchObject({
      publicName: "Alice",
      assetCode: "USD",
      assetScale: 2,
    });
    expect((await run(unauthenticated.walletAddress.getKeys({ url: WALLET }))).keys).toHaveLength(1);
    expect(await run(unauthenticated.walletAddress.getDIDDocument({ url: WALLET }))).toHaveProperty("id");

    const sent = server.requests.slice(before);

    expect(sent.map((request) => request.url)).toEqual([WALLET, `${WALLET}/jwks.json`, `${WALLET}/did.json`]);
    expect(sent.every((request) => !request.headers.has("signature"))).toBe(true);
  });

  it("keeps additional properties of the wallet address document", async () => {
    server.respondOnce(
      "GET /alice",
      Response.json({
        id: WALLET,
        assetCode: "USD",
        assetScale: 2,
        authServer: `${ORIGIN}/as`,
        resourceServer: `${ORIGIN}/rs`,
        extra: { kept: true },
      }),
    );

    expect(await run(client.walletAddress.get({ url: WALLET }))).toMatchObject({ extra: { kept: true } });
  });
});

describe("incoming payment routes", () => {
  it("creates an incoming payment with a signed, digest-protected request", async () => {
    const body = { walletAddress: WALLET, incomingAmount: { value: "2500", assetCode: "USD", assetScale: 2 } };
    const created = await run(client.incomingPayment.create(resource, body));

    expect(created.methods[0]).toMatchObject({ type: "ilp" });
    expect(created.receivedAmount.value).toBe("0");
    const sent = server.requests.at(-1);

    expect(sent).toMatchObject({ method: "POST", url: `${ORIGIN}/rs/incoming-payments`, signedBy: "test-key" });
    expect(sent?.headers.get("authorization")).toBe(`GNAP ${TOKEN}`);
    expect(sent?.headers.get("content-digest")).toMatch(/^sha-512=:/);
    expect(sent?.headers.get("signature-input")).toContain(`;tag="gnap"`);
    expect(JSON.parse(sent?.body ?? "")).toEqual(body);
  });

  it("stamps the signature with the time of its clock option", async () => {
    const seen: Request[] = [];

    const stamped = createAuthenticatedClient({
      walletAddressUrl: WALLET,
      keyId: "test-key",
      privateKey,
      clock: () => new Date(1_700_000_000_000),
      fetch: async (input, init) => {
        seen.push(new Request(input, init));

        return new Response("stop", { status: 500 });
      },
    });

    await fail(stamped.incomingPayment.complete({ ...resource, url: `${ORIGIN}/rs/incoming-payments/1` }));
    expect(seen.at(-1)?.headers.get("signature-input")).toContain("created=1700000000;");
  });

  it("gets an incoming payment with the token and a public one without credentials", async () => {
    const payment = await run(client.incomingPayment.get({ ...resource, url: `${ORIGIN}/rs/incoming-payments/1` }));

    expect(payment.id).toContain("/incoming-payments/");
    expect(server.requests.at(-1)).toMatchObject({ method: "GET", signedBy: "test-key" });

    server.respondOnce(
      "GET /rs/incoming-payments/{id}",
      Response.json({ authServer: `${ORIGIN}/as`, receivedAmount: { value: "1", assetCode: "USD", assetScale: 2 } }),
    );
    const publicView = await run(client.incomingPayment.getPublic({ url: `${ORIGIN}/rs/incoming-payments/1` }));

    expect(publicView.authServer).toBe(`${ORIGIN}/as`);
    expect(server.requests.at(-1)?.headers.has("authorization")).toBe(false);
    expect(server.requests.at(-1)?.headers.has("signature")).toBe(false);
  });

  it("completes an incoming payment", async () => {
    const payment = await run(
      client.incomingPayment.complete({ ...resource, url: `${ORIGIN}/rs/incoming-payments/1` }),
    );

    expect(payment.completed).toBe(true);
    expect(server.requests.at(-1)?.url).toBe(`${ORIGIN}/rs/incoming-payments/1/complete`);
  });

  it("lists with the wallet address and pagination in the query", async () => {
    const page = await run(
      client.incomingPayment.list(
        { ...resource, walletAddress: WALLET },
        { first: 5, cursor: "abc", "wallet-address": WALLET },
      ),
    );

    expect(page.result.length).toBeGreaterThan(0);
    expect(page.pagination.hasNextPage).toBe(true);
    const url = new URL(server.requests.at(-1)?.url ?? "");

    expect(Object.fromEntries(url.searchParams)).toEqual({ "wallet-address": WALLET, first: "5", cursor: "abc" });
  });

  it("rejects a created payment that already received money", async () => {
    server.respondOnce(
      "POST /rs/incoming-payments",
      Response.json(
        {
          id: `${ORIGIN}/rs/incoming-payments/1`,
          walletAddress: WALLET,
          completed: false,
          receivedAmount: { value: "5", assetCode: "USD", assetScale: 2 },
          createdAt: "2022-03-12T23:20:50.52Z",
          methods: [],
        },
        { status: 201 },
      ),
    );

    const error = await fail(client.incomingPayment.create(resource, { walletAddress: WALLET }));

    expect(error).toMatchObject({ reason: "validation", description: "Received amount is a non-zero value" });
  });
});

describe("quote and outgoing payment routes", () => {
  it("creates and gets a quote", async () => {
    const created = await run(
      client.quote.create(resource, {
        walletAddress: WALLET,
        receiver: `${ORIGIN}/bob/incoming-payments/1`,
        method: "ilp",
        debitAmount: { value: "2600", assetCode: "USD", assetScale: 2 },
      }),
    );

    expect(created.method).toBe("ilp");
    expect(server.requests.at(-1)).toMatchObject({ method: "POST", url: `${ORIGIN}/rs/quotes` });
    expect((await run(client.quote.get({ ...resource, url: `${ORIGIN}/rs/quotes/1` }))).id).toContain("/quotes/");
  });

  it("creates, gets and lists outgoing payments and reads grant spent amounts", async () => {
    const created = await run(client.outgoingPayment.create(resource, { walletAddress: WALLET, quoteId: "q1" }));

    expect(created.failed).toBe(false);
    expect(
      (await run(client.outgoingPayment.get({ ...resource, url: `${ORIGIN}/rs/outgoing-payments/1` }))).id,
    ).toBeTruthy();
    expect(
      (await run(client.outgoingPayment.list({ ...resource, walletAddress: WALLET }))).result.length,
    ).toBeGreaterThan(0);
    expect(await run(client.outgoingPayment.getGrantSpentAmounts(resource))).toMatchObject({
      spentDebitAmount: { assetCode: "USD" },
    });
    expect(server.requests.at(-1)?.url).toBe(`${ORIGIN}/rs/outgoing-payment-grant`);
  });

  it("rejects an outgoing payment that sent more than it was meant to", async () => {
    server.respondOnce(
      "GET /rs/outgoing-payments/{id}",
      Response.json({
        id: `${ORIGIN}/rs/outgoing-payments/1`,
        walletAddress: WALLET,
        failed: false,
        receiver: `${ORIGIN}/bob/incoming-payments/1`,
        receiveAmount: { value: "1", assetCode: "USD", assetScale: 2 },
        debitAmount: { value: "1", assetCode: "USD", assetScale: 2 },
        sentAmount: { value: "2", assetCode: "USD", assetScale: 2 },
        createdAt: "2022-03-12T23:20:50.52Z",
      }),
    );

    expect(
      await fail(client.outgoingPayment.get({ ...resource, url: `${ORIGIN}/rs/outgoing-payments/1` })),
    ).toMatchObject({
      reason: "validation",
      description: "Amount sent is larger than maximum amount to send",
    });
  });
});

describe("grant and token routes", () => {
  const access: GrantRequestAccessItem[] = [{ type: "incoming-payment", actions: ["create", "read"] }];

  it("requests a grant naming this client's wallet address", async () => {
    const grant = await run(
      client.grant.request({ url: `${ORIGIN}/as` }, { access_token: { access }, interact: { start: ["redirect"] } }),
    );

    expect("interact" in grant && grant.interact.redirect).toContain("https://");
    const sent = server.requests.at(-1);

    expect(sent?.signedBy).toBe("test-key");
    expect(JSON.parse(sent?.body ?? "")).toMatchObject({ client: WALLET, access_token: { access } });
  });

  it("continues, cancels, rotates and revokes with the right verbs and authorization", async () => {
    const continued = await run(
      client.grant.continue({ url: `${ORIGIN}/as/continue/1`, accessToken: TOKEN }, { interact_ref: "ref" }),
    );

    expect("access_token" in continued && continued.access_token?.value).toBeTruthy();
    expect(JSON.parse(server.requests.at(-1)?.body ?? "")).toEqual({ interact_ref: "ref" });

    await run(client.grant.cancel({ url: `${ORIGIN}/as/continue/1`, accessToken: TOKEN }));
    expect(server.requests.at(-1)).toMatchObject({ method: "DELETE", signedBy: "test-key" });

    expect(
      (await run(client.token.rotate({ url: `${ORIGIN}/as/token/1`, accessToken: TOKEN }))).access_token.value,
    ).toBeTruthy();
    expect(server.requests.at(-1)).toMatchObject({ method: "POST", signedBy: "test-key" });

    await run(client.token.revoke({ url: `${ORIGIN}/as/token/1`, accessToken: TOKEN }));
    expect(server.requests.at(-1)?.method).toBe("DELETE");
  });

  it("refuses a grant request without access_token and subject before any I/O", async () => {
    const before = server.requests.length;

    // SAFETY: deliberately invalid (no access_token or subject) to exercise the client-side refusal.
    const invalid = { interact: { start: ["redirect"] } } as never;
    const error = await fail(client.grant.request({ url: `${ORIGIN}/as` }, invalid));

    expect(error).toMatchObject({ reason: "invalid-request", message: "Invalid Grant Request" });
    expect(server.requests).toHaveLength(before);
  });

  it("refuses an outgoing limit with both debitAmount and receiveAmount", async () => {
    const amount = { value: "1", assetCode: "USD", assetScale: 2 };

    // SAFETY: deliberately invalid (both limits) to exercise the client-side refusal.
    const bothLimits = { debitAmount: amount, receiveAmount: amount } as never;

    const error = await fail(
      client.grant.request(
        { url: `${ORIGIN}/as` },
        {
          access_token: {
            access: [
              {
                type: "outgoing-payment",
                actions: ["create"],
                identifier: WALLET,
                limits: bothLimits,
              },
            ],
          },
        },
      ),
    );

    expect(error.reason).toBe("invalid-request");
  });
});

describe("failures", () => {
  it("maps an error response to OpenPaymentsError with status, code, description and details", async () => {
    server.respondOnce(
      "GET /rs/quotes/{id}",
      Response.json(
        { error: { code: "forbidden", description: "no access", details: { why: "scope" } } },
        { status: 403 },
      ),
    );

    const error = await fail(client.quote.get({ ...resource, url: `${ORIGIN}/rs/quotes/1` }));

    expect(error).toBeInstanceOf(OpenPaymentsError);
    expect(error).toMatchObject({
      _tag: "OpenPaymentsError",
      reason: "http",
      status: 403,
      code: "forbidden",
      description: "no access",
      details: { why: "scope" },
    });
  });

  it("falls back to the raw body when the error response is not the Open Payments shape", async () => {
    server.respondOnce("GET /rs/quotes/{id}", new Response("upstream exploded", { status: 502 }));

    expect(await fail(client.quote.get({ ...resource, url: `${ORIGIN}/rs/quotes/1` }))).toMatchObject({
      reason: "http",
      status: 502,
      description: "upstream exploded",
    });

    server.respondOnce("GET /rs/quotes/{id}", Response.json({ message: "nope" }, { status: 400 }));

    expect(await fail(client.quote.get({ ...resource, url: `${ORIGIN}/rs/quotes/1` }))).toMatchObject({
      status: 400,
      description: '{"message":"nope"}',
    });
  });

  it("returns the response as received, including members the schema does not know", async () => {
    // SAFETY: the OpenAPI example of an incoming payment is a JSON object.
    const payment = { ...(server.example("GET /rs/incoming-payments/{id}") as object), vendorField: 1 };

    server.respondOnce("GET /rs/incoming-payments/{id}", Response.json(payment));

    expect(await run(client.incomingPayment.get({ ...resource, url: `${ORIGIN}/rs/incoming-payments/1` }))).toEqual(
      payment,
    );
  });

  it("skips schema validation, but not the payment invariants, when validateResponses is false", async () => {
    const lenient = createAuthenticatedClient({
      walletAddressUrl: WALLET,
      keyId: "test-key",
      privateKey,
      validateResponses: false,
      fetch: (input, init) => server.handle(new Request(input, init)),
    });

    server.respondOnce("GET /rs/quotes/{id}", Response.json({ id: "x" }));
    expect(await run(lenient.quote.get({ ...resource, url: `${ORIGIN}/rs/quotes/1` }))).toEqual({ id: "x" });

    // SAFETY: the OpenAPI example of an incoming payment has an `incomingAmount`.
    const payment = server.example("GET /rs/incoming-payments/{id}") as {
      incomingAmount: { assetCode: string };
    };

    server.respondOnce(
      "GET /rs/incoming-payments/{id}",
      Response.json({ ...payment, incomingAmount: { ...payment.incomingAmount, assetCode: "XXX" } }),
    );
    expect(
      await fail(lenient.incomingPayment.get({ ...resource, url: `${ORIGIN}/rs/incoming-payments/1` })),
    ).toMatchObject({ reason: "validation" });
  });

  it("reports a response that does not match the schema as a validation failure", async () => {
    server.respondOnce("GET /rs/quotes/{id}", Response.json({ id: "x" }));

    const error = await fail(client.quote.get({ ...resource, url: `${ORIGIN}/rs/quotes/1` }));

    expect(error).toMatchObject({
      reason: "validation",
      status: 200,
      description: "Could not validate OpenAPI response",
    });
    expect(error.validationErrors?.[0]).toContain("walletAddress");
  });

  it("reports a non-JSON success body as a validation failure", async () => {
    server.respondOnce("GET /rs/quotes/{id}", new Response("<html>", { status: 200 }));

    expect(await fail(client.quote.get({ ...resource, url: `${ORIGIN}/rs/quotes/1` }))).toMatchObject({
      reason: "validation",
    });
  });

  it("reports fetch rejection as a transport failure", async () => {
    const offline = createAuthenticatedClient({
      walletAddressUrl: WALLET,
      keyId: "k",
      privateKey: (await Effect.runPromise(generateEd25519KeyPair())).privateKey,
      fetch: () => Promise.reject(new TypeError("connection refused")),
    });

    expect(await fail(offline.quote.get({ ...resource, url: `${ORIGIN}/rs/quotes/1` }))).toMatchObject({
      reason: "transport",
      description: "connection refused",
    });
  });

  it("reports an invalid URL as a transport failure", async () => {
    expect(await fail(client.quote.get({ ...resource, url: "not a url" }))).toMatchObject({ reason: "transport" });
  });

  it("aborts a request that outlives requestTimeoutMs", async () => {
    const slow = createUnauthenticatedClient({
      requestTimeoutMs: 20,
      fetch: (_input, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
        }),
    });

    expect(await fail(slow.walletAddress.get({ url: WALLET }))).toMatchObject({ reason: "transport" });
  });

  it("rewrites https to http when useHttp is set", async () => {
    const seen: string[] = [];

    const insecure = createUnauthenticatedClient({
      useHttp: true,
      fetch: (input, init) => {
        const request = new Request(input, init);

        seen.push(request.url);

        return server.handle(request);
      },
    });

    await run(insecure.walletAddress.get({ url: WALLET }));
    expect(seen).toEqual(["http://op.test/alice"]);
  });
});
