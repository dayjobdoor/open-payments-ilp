import * as Effect from "effect/Effect";
import { beforeAll, describe, expect, it } from "vite-plus/test";
import { generateEd25519KeyPair } from "../../src/http-signatures/index";
import {
  createAuthenticatedClient,
  createUnauthenticatedClient,
  isFinalizedGrantWithAccessToken,
  isPendingGrant,
  UINT64_MAX,
  type ClientOptions,
  type OpenPaymentsError,
} from "../../src/open-payments/index";

const ORIGIN = "https://op.test";

const WALLET = `${ORIGIN}/alice`;

const walletBody = {
  id: WALLET,
  assetCode: "USD",
  assetScale: 2,
  authServer: `${ORIGIN}/as`,
  resourceServer: `${ORIGIN}/rs`,
};

const usd = (value: string) => ({ value, assetCode: "USD", assetScale: 2 });

const incomingBody = {
  id: `${ORIGIN}/rs/incoming-payments/1`,
  walletAddress: WALLET,
  completed: false,
  receivedAmount: usd("0"),
  createdAt: "2022-03-12T23:20:50.52Z",
  methods: [],
};

const outgoingBody = {
  id: `${ORIGIN}/rs/outgoing-payments/1`,
  walletAddress: WALLET,
  failed: false,
  receiver: `${ORIGIN}/bob/incoming-payments/1`,
  receiveAmount: usd("5"),
  debitAmount: usd("5"),
  sentAmount: usd("1"),
  createdAt: "2022-03-12T23:20:50.52Z",
};

const continuation = { access_token: { value: "c" }, uri: `${ORIGIN}/as/continue/1` };

const failure = (effect: Effect.Effect<unknown, OpenPaymentsError>): Promise<OpenPaymentsError> =>
  Effect.runPromise(Effect.flip(effect));

/** A `fetch` that answers every request with `respond()` and records requests and init objects. */
const recording = (respond: () => Response = () => Response.json(walletBody)) => {
  const calls: Request[] = [];
  const inits: Array<RequestInit | undefined> = [];

  const fetch: typeof globalThis.fetch = async (input, init) => {
    inits.push(init);
    calls.push(new Request(input, init));

    return respond();
  };

  return { fetch, calls, inits };
};

let privateKey: CryptoKey;

beforeAll(async () => {
  privateKey = (await Effect.runPromise(generateEd25519KeyPair())).privateKey;
});

const authenticated = (options: ClientOptions) =>
  createAuthenticatedClient({ walletAddressUrl: WALLET, keyId: "k", privateKey, ...options });

describe("request URLs come from untrusted documents", () => {
  it.each([
    ["file:", "file:///tmp/x.json"],
    ["data:", "data:application/json,%7B%7D"],
    ["javascript:", "javascript:alert(1)"],
    ["ftp:", "ftp://op.test/alice"],
    ["http: without useHttp", "http://op.test/alice"],
    ["credentials", "https://user:pw@op.test/alice"],
    ["a password only", "https://:pw@op.test/alice"],
    ["a user only", "https://user@op.test/alice"],
    ["a fragment", "https://op.test/alice#frag"],
    ["an empty fragment", "https://op.test/alice#"],
  ])("refuses %s before anything is sent", async (_name, url) => {
    const { fetch, calls } = recording();
    const client = createUnauthenticatedClient({ fetch });

    const error = await failure(client.walletAddress.get({ url }));

    expect(error).toMatchObject({ _tag: "OpenPaymentsError", reason: "invalid-request" });
    expect(error.description).toContain("URL refused");
    expect(calls).toHaveLength(0);
  });

  it("refuses them on every route, the suffixed ones included", async () => {
    const { fetch, calls } = recording();
    const client = authenticated({ fetch });
    const bad = "file:///etc/passwd";
    const resource = { url: bad, accessToken: "t" };

    const errors = await Promise.all([
      failure(createUnauthenticatedClient({ fetch }).walletAddress.getKeys({ url: `${WALLET}#x` })),
      failure(client.incomingPayment.get(resource)),
      failure(client.incomingPayment.create(resource, { walletAddress: WALLET })),
      failure(client.grant.request({ url: bad }, { access_token: { access: [] }, interact: { start: ["redirect"] } })),
      failure(client.grant.continue(resource, { interact_ref: "r" })),
      failure(client.grant.cancel(resource)),
      failure(client.token.rotate(resource)),
      failure(client.token.revoke(resource)),
    ]);

    expect(errors.map((error) => error.reason)).toEqual(Array(errors.length).fill("invalid-request"));
    expect(calls).toHaveLength(0);
  });

  it("refuses a bad URL once and does not retry it", async () => {
    const { fetch, calls } = recording();

    const client = createUnauthenticatedClient({
      fetch,
      retry: { maxAttempts: 3, sleep: () => Effect.void, jitter: "none" },
    });

    expect(await failure(client.walletAddress.get({ url: "file:///x" }))).toMatchObject({
      reason: "invalid-request",
      attempts: 1,
    });
    expect(calls).toHaveLength(0);
  });

  it("still reports a string that is no URL at all as a transport failure", async () => {
    const { fetch, calls } = recording();

    expect(await failure(createUnauthenticatedClient({ fetch }).walletAddress.get({ url: "not a url" }))).toMatchObject(
      {
        reason: "transport",
      },
    );
    expect(calls).toHaveLength(0);
  });

  it("with useHttp requests http: URLs and rewrites https: ones, but refuses the rest all the same", async () => {
    const { fetch, calls } = recording();
    const client = createUnauthenticatedClient({ fetch, useHttp: true });

    await Effect.runPromise(client.walletAddress.get({ url: "http://op.test/alice" }));
    await Effect.runPromise(client.walletAddress.get({ url: WALLET }));
    expect(calls.map((call) => call.url)).toEqual(["http://op.test/alice", "http://op.test/alice"]);

    for (const url of ["file:///x", "data:,x", "http://u:p@op.test/alice", "http://op.test/alice#f"]) {
      expect((await failure(client.walletAddress.get({ url }))).reason).toBe("invalid-request");
    }

    expect(calls).toHaveLength(2);
  });

  it("asks urlPolicy about the final URL, query and http rewrite included", async () => {
    const { fetch, calls } = recording(() =>
      Response.json({ pagination: { hasNextPage: false, hasPreviousPage: false }, result: [] }),
    );
    const seen: string[] = [];

    const client = authenticated({
      fetch,
      useHttp: true,
      urlPolicy: (url) => {
        seen.push(url.href);

        return url.hostname !== "internal.test";
      },
    });

    await Effect.runPromise(
      client.incomingPayment.list(
        { url: `${ORIGIN}/rs`, accessToken: "t", walletAddress: WALLET },
        { first: 2, "wallet-address": WALLET },
      ),
    );
    expect(seen).toEqual([`http://op.test/rs/incoming-payments?first=2&wallet-address=${encodeURIComponent(WALLET)}`]);

    const error = await failure(
      client.incomingPayment.get({ url: "https://internal.test/rs/incoming-payments/1", accessToken: "t" }),
    );

    expect(error).toMatchObject({ reason: "invalid-request" });
    expect(error.description).toContain("URL policy");
    expect(calls).toHaveLength(1);
  });
});

describe("redirects are never followed", () => {
  const redirect = (code: number) => () =>
    new Response(null, { status: code, headers: { Location: "https://evil.test/steal" } });

  it.each([301, 302, 303, 307, 308])("fails a %i as a transport error without a second request", async (code) => {
    const { fetch, calls, inits } = recording(redirect(code));
    const client = authenticated({ fetch });

    const error = await failure(
      client.incomingPayment.get({ url: `${ORIGIN}/rs/incoming-payments/1`, accessToken: "t" }),
    );

    expect(error).toMatchObject({ reason: "transport", description: "Redirects are not followed" });
    expect(error.status).toBeUndefined();
    expect(calls).toHaveLength(1);
    expect(calls[0]?.headers.get("authorization")).toBe("GNAP t");
    expect(inits.every((init) => init?.redirect === "manual")).toBe(true);
  });

  it("fails an opaque redirect the same way", async () => {
    const opaque = new Response(null, { status: 200 });

    Object.defineProperty(opaque, "type", { value: "opaqueredirect" });
    const { fetch, calls } = recording(() => opaque);

    expect(await failure(createUnauthenticatedClient({ fetch }).walletAddress.get({ url: WALLET }))).toMatchObject({
      reason: "transport",
      description: "Redirects are not followed",
    });
    expect(calls).toHaveLength(1);
  });

  it("does not retry a redirect, whatever the method", async () => {
    const { fetch, calls } = recording(redirect(307));

    const client = authenticated({
      fetch,
      retry: { maxAttempts: 3, sleep: () => Effect.void, jitter: "none", retryNonIdempotent: true },
    });

    const error = await failure(
      client.incomingPayment.get({ url: `${ORIGIN}/rs/incoming-payments/1`, accessToken: "t" }),
    );

    expect(error).toMatchObject({ reason: "transport", attempts: 1 });
    expect(calls).toHaveLength(1);
  });
});

describe("numeric options", () => {
  it.each([Number.NaN, Number.POSITIVE_INFINITY, -1])(
    "refuses requestTimeoutMs %s before fetch is called",
    async (value) => {
      const { fetch, calls } = recording();
      const client = createUnauthenticatedClient({ fetch, requestTimeoutMs: value });

      expect(await failure(client.walletAddress.get({ url: WALLET }))).toMatchObject({ reason: "invalid-request" });
      expect(calls).toHaveLength(0);
    },
  );

  it.each([Number.NaN, Number.POSITIVE_INFINITY, -1])(
    "refuses maxResponseBytes %s before fetch is called",
    async (value) => {
      const { fetch, calls } = recording();
      const client = createUnauthenticatedClient({ fetch, maxResponseBytes: value });

      expect(await failure(client.walletAddress.get({ url: WALLET }))).toMatchObject({ reason: "invalid-request" });
      expect(calls).toHaveLength(0);
    },
  );

  it("does not retry an invalid option", async () => {
    const { fetch, calls } = recording();

    const client = createUnauthenticatedClient({
      fetch,
      requestTimeoutMs: Number.NaN,
      retry: { maxAttempts: 3, sleep: () => Effect.void },
    });

    expect(await failure(client.walletAddress.get({ url: WALLET }))).toMatchObject({ attempts: 1 });
    expect(calls).toHaveLength(0);
  });

  it("accepts a response exactly as long as maxResponseBytes and refuses one byte more", async () => {
    const length = new TextEncoder().encode(JSON.stringify(walletBody)).length;
    const exact = createUnauthenticatedClient({ ...recording(), maxResponseBytes: length });
    const over = createUnauthenticatedClient({ ...recording(), maxResponseBytes: length - 1 });

    expect((await Effect.runPromise(exact.walletAddress.get({ url: WALLET }))).assetCode).toBe("USD");
    expect(await failure(over.walletAddress.get({ url: WALLET }))).toMatchObject({ reason: "transport" });
  });

  it("limits a response to 1 MiB by default, announced or streamed", async () => {
    const announced = new Response("{}", { headers: { "Content-Length": String(1024 * 1024 + 1) } });
    const streamed = new Response(" ".repeat(1024 * 1024 + 1));

    for (const response of [announced, streamed]) {
      const client = createUnauthenticatedClient({ fetch: recording(() => response).fetch });

      expect(await failure(client.walletAddress.get({ url: WALLET }))).toMatchObject({ reason: "transport" });
    }
  });

  it("fails signing, not freshness, when the clock returns an Invalid Date", async () => {
    const { fetch, calls } = recording();
    const client = authenticated({ fetch, clock: () => new Date(Number.NaN) });

    const error = await failure(
      client.incomingPayment.get({ url: `${ORIGIN}/rs/incoming-payments/1`, accessToken: "t" }),
    );

    expect(error).toMatchObject({ reason: "signing" });
    expect(error.cause).toMatchObject({ _tag: "HttpSignatureError", reason: "malformed" });
    expect(calls).toHaveLength(0);
  });
});

describe("response schemas follow the OpenAPI documents", () => {
  it.each([-1, 256, 999, 1.5])("refuses an assetScale of %s in a wallet address", async (assetScale) => {
    const client = createUnauthenticatedClient(recording(() => Response.json({ ...walletBody, assetScale })));

    expect(await failure(client.walletAddress.get({ url: WALLET }))).toMatchObject({ reason: "validation" });
  });

  it.each([0, 255])("accepts an assetScale of %s", async (assetScale) => {
    const client = createUnauthenticatedClient(recording(() => Response.json({ ...walletBody, assetScale })));

    expect((await Effect.runPromise(client.walletAddress.get({ url: WALLET }))).assetScale).toBe(assetScale);
  });

  it.each([(UINT64_MAX + 1n).toString(), "-1", "1.5", ""])("refuses the amount value %j", async (value) => {
    const client = authenticated(
      recording(() => Response.json({ ...incomingBody, receivedAmount: { ...usd("0"), value } }, { status: 201 })),
    );

    expect(
      await failure(
        client.incomingPayment.create({ url: `${ORIGIN}/rs`, accessToken: "t" }, { walletAddress: WALLET }),
      ),
    ).toMatchObject({
      reason: "validation",
    });
  });

  it("accepts the largest uint64 amount value", async () => {
    const client = authenticated(
      recording(() => Response.json({ ...incomingBody, receivedAmount: usd(UINT64_MAX.toString()) })),
    );

    const payment = await Effect.runPromise(
      client.incomingPayment.get({ url: `${ORIGIN}/rs/incoming-payments/1`, accessToken: "t" }),
    );

    expect(payment.receivedAmount.value).toBe(UINT64_MAX.toString());
  });

  it("reports an amount the invariants cannot read as validation, with the response schema check off", async () => {
    const client = authenticated({
      ...recording(() =>
        Response.json({ ...incomingBody, receivedAmount: usd((UINT64_MAX + 1n).toString()) }, { status: 201 }),
      ),
      validateResponses: false,
    });

    expect(
      await failure(
        client.incomingPayment.create({ url: `${ORIGIN}/rs`, accessToken: "t" }, { walletAddress: WALLET }),
      ),
    ).toMatchObject({
      reason: "validation",
    });
  });

  const grantRequest = { access_token: { access: [] }, interact: { start: ["redirect" as const] } };

  it("requires interact.finish in a pending grant, as interact-response does", async () => {
    const client = authenticated(
      recording(() => Response.json({ interact: { redirect: `${ORIGIN}/interact/1` }, continue: continuation })),
    );

    expect(await failure(client.grant.request({ url: `${ORIGIN}/as` }, grantRequest))).toMatchObject({
      reason: "validation",
    });
  });

  it("accepts a pending grant with redirect and finish, and a finalised grant", async () => {
    const pending = authenticated(
      recording(() =>
        Response.json({ interact: { redirect: `${ORIGIN}/interact/1`, finish: "nonce" }, continue: continuation }),
      ),
    );

    const finalized = authenticated(
      recording(() =>
        Response.json({
          access_token: { value: "v", manage: `${ORIGIN}/as/token/1`, access: [] },
          continue: continuation,
        }),
      ),
    );

    const first = await Effect.runPromise(pending.grant.request({ url: `${ORIGIN}/as` }, grantRequest));
    const second = await Effect.runPromise(finalized.grant.request({ url: `${ORIGIN}/as` }, grantRequest));

    expect(isPendingGrant(first)).toBe(true);
    expect(isPendingGrant(second)).toBe(false);
    expect(isFinalizedGrantWithAccessToken(second)).toBe(true);
  });
});

describe("payment invariants", () => {
  const run = (
    body: object,
    call: (client: ReturnType<typeof authenticated>) => Effect.Effect<unknown, OpenPaymentsError>,
  ) => failure(call(authenticated(recording(() => Response.json(body, { status: 201 })))));

  const resource = { url: `${ORIGIN}/rs/incoming-payments/1`, accessToken: "t" };

  it("rejects a created incoming payment that is already completed", async () => {
    const error = await run({ ...incomingBody, completed: true }, (client) =>
      client.incomingPayment.create({ url: `${ORIGIN}/rs`, accessToken: "t" }, { walletAddress: WALLET }),
    );

    expect(error).toMatchObject({ reason: "validation", description: "Can not create a completed incoming payment" });
  });

  it("rejects a completion that did not complete", async () => {
    const error = await run(incomingBody, (client) => client.incomingPayment.complete(resource));

    expect(error).toMatchObject({ reason: "validation", description: "Incoming payment could not be completed" });
  });

  it("rejects an incoming amount in another asset than the received amount", async () => {
    const error = await run({ ...incomingBody, incomingAmount: { ...usd("5"), assetCode: "EUR" } }, (client) =>
      client.incomingPayment.get(resource),
    );

    expect(error).toMatchObject({
      reason: "validation",
      description: "Incoming amount asset code or asset scale does not match up received amount",
    });
  });

  it("rejects a failed outgoing payment that nevertheless sent everything", async () => {
    const error = await run({ ...outgoingBody, failed: true, sentAmount: usd("5") }, (client) =>
      client.outgoingPayment.get({ url: `${ORIGIN}/rs/outgoing-payments/1`, accessToken: "t" }),
    );

    expect(error).toMatchObject({
      reason: "validation",
      description: "Amount to send matches sent amount but payment failed",
    });
  });

  it("rejects an outgoing payment whose sent amount is in another scale", async () => {
    const error = await run({ ...outgoingBody, sentAmount: { ...usd("1"), assetScale: 3 } }, (client) =>
      client.outgoingPayment.get({ url: `${ORIGIN}/rs/outgoing-payments/1`, accessToken: "t" }),
    );

    expect(error).toMatchObject({
      reason: "validation",
      description: "Asset code or asset scale of sending amount does not match sent amount",
    });
  });
});

describe("query", () => {
  it("leaves out falsy pagination values (0 and the empty cursor) instead of sending them", async () => {
    const { fetch, calls } = recording(() =>
      Response.json({ pagination: { hasNextPage: false, hasPreviousPage: false }, result: [] }),
    );

    await Effect.runPromise(
      authenticated({ fetch }).incomingPayment.list(
        { url: `${ORIGIN}/rs`, accessToken: "t", walletAddress: WALLET },
        { first: 0, cursor: "", "wallet-address": WALLET },
      ),
    );

    expect(Object.fromEntries(new URL(calls[0]?.url ?? "").searchParams)).toEqual({ "wallet-address": WALLET });
  });
});
