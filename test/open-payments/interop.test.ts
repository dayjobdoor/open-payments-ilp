/**
 * Differential test: this package's client and the reference `@interledger/open-payments` client talk to the
 * same HTTP server (built from the OpenAPI examples, verifying every signature) and must observe the same
 * results and the same failures.
 */
import { generateKeyPairSync } from "node:crypto";
import { createAuthenticatedClient as createReferenceClient } from "@interledger/open-payments";
import * as Effect from "effect/Effect";
import { afterEach, beforeEach, describe, expect, it } from "vite-plus/test";
import { createAuthenticatedClient, OpenPaymentsError, type GrantRequest } from "../../src/open-payments/index";
import { createFakeServer, listen, type FakeServer, type RecordedRequest } from "./fake-server";

type ReferenceClient = Awaited<ReturnType<typeof createReferenceClient>>;

type OurClient = ReturnType<typeof createAuthenticatedClient>;

const TOKEN = "TOKEN-123";

const KEY_ID = "interop-key";

let server: FakeServer;

let stop: () => Promise<void>;

let origin: string;

let reference: ReferenceClient;

let ours: OurClient;

const resource = () => ({ url: `${origin}/rs`, accessToken: TOKEN });

const amount = { value: "2500", assetCode: "USD", assetScale: 2 };

/** Runs the same operation through both clients and returns both outcomes. */
async function both<A>(
  theirs: (client: ReferenceClient) => Promise<A>,
  mine: (client: OurClient) => Effect.Effect<A, OpenPaymentsError>,
): Promise<{ theirs: A; mine: A }> {
  const start = server.requests.length;
  const theirResult = await theirs(reference);
  const middle = server.requests.length;
  const myResult = await Effect.runPromise(mine(ours));
  const theirRequests = server.requests.slice(start, middle);
  const myRequests = server.requests.slice(middle);

  const needsSignature = (request: RecordedRequest) =>
    request.method === "POST" || request.headers.has("authorization");

  // Both clients' requests verified against the one public key.
  for (const request of [...theirRequests, ...myRequests].filter(needsSignature)) {
    expect(request.signedBy).toBe(KEY_ID);
  }

  // The same bodies, URLs and Authorization header for this pair.
  const posts = (requests: RecordedRequest[]) => requests.filter((request) => request.method === "POST");

  expect(posts(myRequests).map((request) => [request.url, request.body, request.headers.get("authorization")])).toEqual(
    posts(theirRequests).map((request) => [request.url, request.body, request.headers.get("authorization")]),
  );

  return { theirs: theirResult, mine: myResult };
}

async function bothFail<A, B>(
  theirs: (client: ReferenceClient) => Promise<A>,
  mine: (client: OurClient) => Effect.Effect<B, OpenPaymentsError>,
): Promise<{
  theirs: { status?: number; code?: string; description: string; details?: unknown };
  mine: OpenPaymentsError;
}> {
  const theirError = await theirs(reference).then(
    () => {
      throw new Error("reference client unexpectedly succeeded");
    },
    (error: { status?: number; code?: string; description: string; details?: unknown }) => error,
  );

  return { theirs: theirError, mine: await Effect.runPromise(Effect.flip(mine(ours))) };
}

// A fresh server (no recorded requests, no queued overrides) for every test.
beforeEach(async () => {
  const pair = generateKeyPairSync("ed25519");
  const publicJwk: JsonWebKey = pair.publicKey.export({ format: "jwk" });

  server = await createFakeServer({ [KEY_ID]: publicJwk });
  const listening = await listen(server.handle);

  origin = listening.origin;
  stop = listening.close;

  reference = await createReferenceClient({
    walletAddressUrl: `${origin}/alice`,
    keyId: KEY_ID,
    privateKey: pair.privateKey,
    useHttp: true,
    logLevel: "silent",
  });

  ours = createAuthenticatedClient({
    walletAddressUrl: `${origin}/alice`,
    keyId: KEY_ID,
    privateKey: await crypto.subtle.importKey(
      "pkcs8",
      pair.privateKey.export({ format: "der", type: "pkcs8" }),
      "Ed25519",
      false,
      ["sign"],
    ),
    useHttp: true,
  });
});

afterEach(async () => {
  await stop();
});

describe("responses match the reference client", () => {
  it("wallet address, keys and DID document", async () => {
    const url = `${origin}/alice`;

    const walletAddress = await both(
      (client) => client.walletAddress.get({ url }),
      (client) => client.walletAddress.get({ url }),
    );

    expect(walletAddress.mine).toEqual(walletAddress.theirs);

    const keys = await both(
      (client) => client.walletAddress.getKeys({ url }),
      (client) => client.walletAddress.getKeys({ url }),
    );

    expect(keys.mine).toEqual(keys.theirs);

    const did = await both(
      (client) => client.walletAddress.getDIDDocument({ url }),
      (client) => client.walletAddress.getDIDDocument({ url }),
    );

    expect(did.mine).toEqual(did.theirs);
  });

  it("incoming payments: create, get, complete, list", async () => {
    const body = { walletAddress: `${origin}/alice`, incomingAmount: amount };

    const created = await both(
      (client) => client.incomingPayment.create(resource(), body),
      (client) => client.incomingPayment.create(resource(), body),
    );

    expect(created.mine).toEqual(created.theirs);
    const url = `${origin}/rs/incoming-payments/2f1b0150`;

    const got = await both(
      (client) => client.incomingPayment.get({ ...resource(), url }),
      (client) => client.incomingPayment.get({ ...resource(), url }),
    );

    expect(got.mine).toEqual(got.theirs);

    const completed = await both(
      (client) => client.incomingPayment.complete({ ...resource(), url }),
      (client) => client.incomingPayment.complete({ ...resource(), url }),
    );

    expect(completed.mine).toEqual(completed.theirs);
    const collection = { ...resource(), walletAddress: `${origin}/alice` };

    const listed = await both(
      (client) => client.incomingPayment.list(collection, { first: 2, "wallet-address": `${origin}/alice` }),
      (client) => client.incomingPayment.list(collection, { first: 2, "wallet-address": `${origin}/alice` }),
    );

    expect(listed.mine).toEqual(listed.theirs);
  });

  it("quotes and outgoing payments", async () => {
    const quoteArgs = {
      walletAddress: `${origin}/alice`,
      receiver: `${origin}/bob/incoming-payments/1`,
      method: "ilp",
      debitAmount: amount,
    } as const;

    const quote = await both(
      (client) => client.quote.create(resource(), quoteArgs),
      (client) => client.quote.create(resource(), quoteArgs),
    );

    expect(quote.mine).toEqual(quote.theirs);
    const outgoingArgs = { walletAddress: `${origin}/alice`, quoteId: "q1" };

    const created = await both(
      (client) => client.outgoingPayment.create(resource(), outgoingArgs),
      (client) => client.outgoingPayment.create(resource(), outgoingArgs),
    );

    expect(created.mine).toEqual(created.theirs);

    const spent = await both(
      (client) => client.outgoingPayment.getGrantSpentAmounts(resource()),
      (client) => client.outgoingPayment.getGrantSpentAmounts(resource()),
    );

    expect(spent.mine).toEqual(spent.theirs);
  });

  it("grant request, continuation, token rotation", async () => {
    const grantRequest: Omit<GrantRequest, "client"> = {
      access_token: { access: [{ type: "incoming-payment", actions: ["create", "read"] }] },
      interact: { start: ["redirect"] },
    };

    const grant = await both(
      (client) => client.grant.request({ url: `${origin}/as` }, grantRequest),
      (client) => client.grant.request({ url: `${origin}/as` }, grantRequest),
    );

    expect(grant.mine).toEqual(grant.theirs);
    const continuation = { url: `${origin}/as/continue/1`, accessToken: TOKEN };

    const continued = await both(
      (client) => client.grant.continue(continuation, { interact_ref: "ref" }),
      (client) => client.grant.continue(continuation, { interact_ref: "ref" }),
    );

    expect(continued.mine).toEqual(continued.theirs);
    const token = { url: `${origin}/as/token/1`, accessToken: TOKEN };

    const rotated = await both(
      (client) => client.token.rotate(token),
      (client) => client.token.rotate(token),
    );

    expect(rotated.mine).toEqual(rotated.theirs);
  });
});

describe("failures match the reference client", () => {
  it("surface status, code and description of an error response", async () => {
    const body = { error: { code: "forbidden", description: "no access" } };
    const url = `${origin}/rs/quotes/1`;

    server.respondOnce("GET /rs/quotes/{id}", Response.json(body, { status: 403 }));
    server.respondOnce("GET /rs/quotes/{id}", Response.json(body, { status: 403 }));

    const failed = await bothFail(
      (client) => client.quote.get({ ...resource(), url }),
      (client) => client.quote.get({ ...resource(), url }),
    );

    expect(failed.mine).toMatchObject({
      status: failed.theirs.status,
      code: failed.theirs.code,
      description: failed.theirs.description,
    });
  });

  it("refuse the same invalid grant request", async () => {
    // SAFETY: deliberately invalid (no access_token or subject) to compare both clients' refusal.
    const invalid = { interact: { start: ["redirect"] } } as never;

    const failed = await bothFail(
      (client) => client.grant.request({ url: `${origin}/as` }, invalid),
      (client) => client.grant.request({ url: `${origin}/as` }, invalid),
    );

    expect(failed.mine.description).toBe(failed.theirs.description);
  });
  it.each([
    ["an empty body", () => new Response(null, { status: 404 })],
    ["plain text", () => new Response("gone", { status: 404 })],
    ["an object without error.description", () => Response.json({ message: "nope" }, { status: 404 })],
    ["an empty error.description", () => Response.json({ error: { code: "x", description: "" } }, { status: 404 })],
    ["error.details", () => Response.json({ error: { code: "x", details: { a: 1 } } }, { status: 404 })],
  ])("describe %s like the reference client", async (_name, respond) => {
    const url = `${origin}/rs/quotes/1`;

    server.respondOnce("GET /rs/quotes/{id}", respond());
    server.respondOnce("GET /rs/quotes/{id}", respond());

    const failed = await bothFail(
      (client) => client.quote.get({ ...resource(), url }),
      (client) => client.quote.get({ ...resource(), url }),
    );

    expect(failed.mine.description).toBe(failed.theirs.description);
    expect(failed.mine.status).toBe(failed.theirs.status);
    expect(failed.mine.code).toBe(failed.theirs.code);
    expect(failed.mine.details).toEqual(failed.theirs.details);
  });

  it("keep the response members the schema does not know, like the reference client", async () => {
    // The incoming payment schema allows additional members; the quote schema forbids them (see the README's compat table).
    const url = `${origin}/rs/incoming-payments/1`;
    // SAFETY: the OpenAPI example of an incoming payment is a JSON object.
    const payment = { ...(server.example("GET /rs/incoming-payments/{id}") as object), extra: { kept: true } };

    server.respondOnce("GET /rs/incoming-payments/{id}", Response.json(payment));
    server.respondOnce("GET /rs/incoming-payments/{id}", Response.json(payment));

    const got = await both(
      (client) => client.incomingPayment.get({ ...resource(), url }),
      (client) => client.incomingPayment.get({ ...resource(), url }),
    );

    expect(got.mine).toEqual(got.theirs);
    expect(got.mine).toHaveProperty("extra", { kept: true });
  });
});
