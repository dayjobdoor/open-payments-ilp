import * as Effect from "effect/Effect";
import { beforeEach, describe, expect, it } from "vite-plus/test";
import { generateEd25519KeyPair } from "../../src/http-signatures/index";
import {
  createAuthenticatedClient,
  createUnauthenticatedClient,
  OpenPaymentsError,
  type AuthenticatedClient,
  type RetryOptions,
} from "../../src/open-payments/index";
import { createFakeServer, type FakeServer } from "./fake-server";

const ORIGIN = "https://op.test";

const WALLET = `${ORIGIN}/alice`;

const resource = { url: `${ORIGIN}/rs/incoming-payments/1`, accessToken: "TOKEN-123" };

const walletBody = {
  id: WALLET,
  assetCode: "USD",
  assetScale: 2,
  authServer: `${ORIGIN}/as`,
  resourceServer: `${ORIGIN}/rs`,
};

const failure = (effect: Effect.Effect<unknown, OpenPaymentsError>): Promise<OpenPaymentsError> =>
  Effect.runPromise(Effect.flip(effect));

const status = (code: number, headers?: Record<string, string>): Response =>
  new Response("", { status: code, headers: headers ?? {} });

/** A `fetch` that plays `steps` (a response, or an error to reject with), then `fallback`; it records every request. */
const scripted = (
  steps: Array<Response | Error>,
  fallback: (request: Request) => Promise<Response> = async () => Response.json(walletBody),
) => {
  const seen: Request[] = [];

  const fetch: typeof globalThis.fetch = async (input, init) => {
    const request = new Request(input, init);

    seen.push(request);
    const step = steps.shift();

    if (step instanceof Error) throw step;

    return step ?? fallback(request);
  };

  return { fetch, seen };
};

/** Records the waits instead of sleeping; fixes the jitter. */
const instant = (extra: Partial<RetryOptions> = {}) => {
  const sleeps: number[] = [];

  const retry: RetryOptions = {
    maxAttempts: 3,
    sleep: (ms) => {
      sleeps.push(ms);

      return Effect.void;
    },
    jitter: "none",
    ...extra,
  };

  return { sleeps, retry };
};

const quoteArgs = { walletAddress: WALLET, receiver: `${ORIGIN}/rs/incoming-payments/1`, method: "ilp" } as const;

const getWallet = (client: ReturnType<typeof createUnauthenticatedClient>) => client.walletAddress.get({ url: WALLET });

describe("retry is opt-in", () => {
  it("makes one attempt without the option and reports no attempt count", async () => {
    const { fetch, seen } = scripted([status(503), status(503), status(503)]);
    const error = await failure(getWallet(createUnauthenticatedClient({ fetch })));

    expect(seen).toHaveLength(1);
    expect(error).toMatchObject({ reason: "http", status: 503 });
    expect(error.attempts).toBeUndefined();
  });

  it("signs without a nonce, as before", async () => {
    const { privateKey } = await Effect.runPromise(generateEd25519KeyPair());
    const { fetch, seen } = scripted([status(500)]);

    const client = createAuthenticatedClient({ walletAddressUrl: WALLET, keyId: "k", privateKey, fetch });

    await failure(client.token.revoke({ url: `${ORIGIN}/as/token/1`, accessToken: "t" }));
    expect(seen[0]?.headers.get("signature-input")).not.toContain("nonce=");
  });
});

describe("what is retried", () => {
  it.each([408, 429, 502, 503, 504])("retries a GET answered with %i", async (code) => {
    const { fetch, seen } = scripted([status(code)]);
    const { retry, sleeps } = instant();

    const wallet = await Effect.runPromise(getWallet(createUnauthenticatedClient({ fetch, retry })));

    expect(wallet.assetCode).toBe("USD");
    expect(seen).toHaveLength(2);
    expect(sleeps).toHaveLength(1);
  });

  it.each([400, 401, 403, 404, 409, 500, 501])("does not retry a GET answered with %i", async (code) => {
    const { fetch, seen } = scripted([status(code), status(code)]);
    const { retry, sleeps } = instant();
    const error = await failure(getWallet(createUnauthenticatedClient({ fetch, retry })));

    expect(seen).toHaveLength(1);
    expect(sleeps).toEqual([]);
    expect(error).toMatchObject({ reason: "http", status: code, attempts: 1 });
  });

  it("retries a rejected fetch (network error)", async () => {
    const { fetch, seen } = scripted([new TypeError("fetch failed")]);
    const wallet = await Effect.runPromise(getWallet(createUnauthenticatedClient({ fetch, retry: instant().retry })));

    expect(wallet.assetCode).toBe("USD");
    expect(seen).toHaveLength(2);
  });

  it("retries a timed-out attempt, each with its own timeout", async () => {
    let calls = 0;

    const fetch: typeof globalThis.fetch = (_input, init) => {
      if (++calls > 1) return Promise.resolve(Response.json(walletBody));

      return new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal?.reason));
      });
    };

    const client = createUnauthenticatedClient({ fetch, requestTimeoutMs: 5, retry: instant().retry });

    expect((await Effect.runPromise(getWallet(client))).assetCode).toBe("USD");
    expect(calls).toBe(2);
  });

  it("does not retry a response longer than maxResponseBytes", async () => {
    const { fetch, seen } = scripted([new Response("x".repeat(100), { status: 200 })]);

    const error = await failure(
      getWallet(createUnauthenticatedClient({ fetch, maxResponseBytes: 10, retry: instant().retry })),
    );

    expect(seen).toHaveLength(1);
    expect(error).toMatchObject({ reason: "transport", attempts: 1 });
  });

  it("does not retry a response that fails validation", async () => {
    const { fetch, seen } = scripted([Response.json({ nope: true })]);
    const error = await failure(getWallet(createUnauthenticatedClient({ fetch, retry: instant().retry })));

    expect(seen).toHaveLength(1);
    expect(error.reason).toBe("validation");
  });

  it("lets retryOn decide which errors are transient", async () => {
    const { fetch, seen } = scripted([status(500)]);

    const wallet = await Effect.runPromise(
      getWallet(
        createUnauthenticatedClient({
          fetch,
          retry: instant({ retryOn: (error) => error.status === 500 }).retry,
        }),
      ),
    );

    expect(wallet.assetCode).toBe("USD");
    expect(seen).toHaveLength(2);

    const refused = scripted([status(503)]);

    const error = await failure(
      getWallet(createUnauthenticatedClient({ fetch: refused.fetch, retry: instant({ retryOn: () => false }).retry })),
    );

    expect(error).toMatchObject({ status: 503, attempts: 1 });
  });

  it("stops after maxAttempts and reports the last error with the attempt count", async () => {
    const { fetch, seen } = scripted([
      status(503),
      status(502),
      new Response(JSON.stringify({ error: { code: "invalid_request", description: "last" } }), { status: 504 }),
      status(503),
    ]);

    const error = await failure(
      getWallet(createUnauthenticatedClient({ fetch, retry: instant({ maxAttempts: 3 }).retry })),
    );

    expect(seen).toHaveLength(3);
    expect(error).toBeInstanceOf(OpenPaymentsError);
    expect(error).toMatchObject({
      reason: "http",
      status: 504,
      code: "invalid_request",
      description: "last",
      attempts: 3,
    });
  });

  it.each([1, 0, -3, Number.NaN, Number.POSITIVE_INFINITY])(
    "makes a single attempt with maxAttempts %s",
    async (maxAttempts) => {
      const { fetch, seen } = scripted([status(503), status(503), status(503)]);

      const error = await failure(
        getWallet(createUnauthenticatedClient({ fetch, retry: instant({ maxAttempts }).retry })),
      );

      expect(seen).toHaveLength(1);
      expect(error.attempts).toBe(1);
    },
  );
});

describe("methods", () => {
  let server: FakeServer;
  let client: AuthenticatedClient;
  let privateKey: CryptoKey;

  beforeEach(async () => {
    const pair = await Effect.runPromise(generateEd25519KeyPair());

    privateKey = pair.privateKey;
    server = await createFakeServer({ k: pair.publicJwk });
  });

  const make = (steps: Array<Response | Error>, retry: RetryOptions) => {
    const flaky = scripted(steps, (request) => server.handle(request));

    client = createAuthenticatedClient({ walletAddressUrl: WALLET, keyId: "k", privateKey, fetch: flaky.fetch, retry });

    return flaky;
  };

  it("retries a DELETE", async () => {
    const { seen } = make([status(503)], instant().retry);

    await Effect.runPromise(client.token.revoke({ url: `${ORIGIN}/as/token/1`, accessToken: "t" }));
    expect(seen.map((request) => request.method)).toEqual(["DELETE", "DELETE"]);
    expect(server.requests.at(-1)).toMatchObject({ method: "DELETE", signedBy: "k" });
  });

  it.each([
    ["a 503", status(503)],
    ["a network error", new TypeError("fetch failed")],
  ])("does not retry a POST after %s unless asked to", async (_name, step) => {
    const { seen } = make([step, step], instant().retry);
    const error = await failure(client.incomingPayment.complete(resource));

    expect(seen).toHaveLength(1);
    expect(error).toMatchObject({ attempts: 1 });
  });

  it("retries a POST when the client option opts in", async () => {
    const { seen } = make([status(503)], instant({ retryNonIdempotent: true }).retry);

    const payment = await Effect.runPromise(client.incomingPayment.complete(resource));

    expect(payment.completed).toBe(true);
    expect(seen.map((request) => request.method)).toEqual(["POST", "POST"]);
  });

  it("retries a POST when the request opts in, and a request can opt out of the client option", async () => {
    const optedIn = make([new TypeError("lost")], instant().retry);

    await Effect.runPromise(client.incomingPayment.complete({ ...resource, retryNonIdempotent: true }));
    expect(optedIn.seen).toHaveLength(2);

    const optedOut = make([status(503), status(503)], instant({ retryNonIdempotent: true }).retry);

    await failure(client.incomingPayment.complete({ ...resource, retryNonIdempotent: false }));
    expect(optedOut.seen).toHaveLength(1);
  });

  const postRoutes: Array<[string, (optIn: boolean | undefined) => Effect.Effect<unknown, OpenPaymentsError>]> = [
    [
      "incomingPayment.create",
      (o) => client.incomingPayment.create({ ...resource, retryNonIdempotent: o }, { walletAddress: WALLET }),
    ],
    ["incomingPayment.complete", (o) => client.incomingPayment.complete({ ...resource, retryNonIdempotent: o })],
    [
      "outgoingPayment.create",
      (o) =>
        client.outgoingPayment.create(
          { ...resource, retryNonIdempotent: o },
          { walletAddress: WALLET, quoteId: `${ORIGIN}/rs/quotes/1` },
        ),
    ],
    ["quote.create", (o) => client.quote.create({ ...resource, retryNonIdempotent: o }, quoteArgs)],
    ["grant.continue", (o) => client.grant.continue({ ...resource, retryNonIdempotent: o }, { interact_ref: "r" })],
    [
      "grant.request",
      (o) =>
        client.grant.request(
          { url: ORIGIN, retryNonIdempotent: o },
          { access_token: { access: [] }, interact: { start: ["redirect"] } },
        ),
    ],
    ["token.rotate", (o) => client.token.rotate({ ...resource, retryNonIdempotent: o })],
  ];

  it.each(postRoutes)("%s repeats only on the request's opt-in", async (_name, call) => {
    const idle = make([status(503), status(503), status(503)], instant().retry);

    await failure(call(undefined));
    expect(idle.seen).toHaveLength(1);

    const asked = make([status(503), status(503), status(503)], instant().retry);

    await failure(call(true));
    expect(asked.seen).toHaveLength(3);
  });
});

describe("waiting", () => {
  it("backs off exponentially up to maxDelayMs, without jitter", async () => {
    const { fetch } = scripted(Array.from({ length: 6 }, () => status(503)));
    const { retry, sleeps } = instant({ maxAttempts: 6, baseDelayMs: 100, maxDelayMs: 700 });

    await failure(getWallet(createUnauthenticatedClient({ fetch, retry })));
    expect(sleeps).toEqual([100, 200, 400, 700, 700]);
  });

  it("scales the backoff by the injected random with full jitter (the default)", async () => {
    const { fetch } = scripted(Array.from({ length: 5 }, () => status(503)));
    const randoms = [0.5, 0.25, 1, 0];

    const { retry, sleeps } = instant({
      maxAttempts: 5,
      baseDelayMs: 100,
      maxDelayMs: 300,
      jitter: "full",
      random: () => randoms.shift() ?? 0,
    });

    await failure(getWallet(createUnauthenticatedClient({ fetch, retry })));
    expect(sleeps).toEqual([50, 50, 300, 0]);
  });

  it("really sleeps with the default sleep", async () => {
    const { fetch, seen } = scripted([status(503)]);

    const client = createUnauthenticatedClient({
      fetch,
      retry: { maxAttempts: 2, baseDelayMs: 1, jitter: "none" },
    });

    await Effect.runPromise(getWallet(client));
    expect(seen).toHaveLength(2);
  });

  it("accepts a promise-returning sleep", async () => {
    const { fetch } = scripted([status(503)]);
    const slept: number[] = [];

    const retry: RetryOptions = {
      maxAttempts: 2,
      baseDelayMs: 40,
      jitter: "none",
      sleep: async (ms) => {
        slept.push(ms);
      },
    };

    await Effect.runPromise(getWallet(createUnauthenticatedClient({ fetch, retry })));
    expect(slept).toEqual([40]);
  });

  describe("Retry-After", () => {
    const waitFor = async (code: number, retryAfter: string, extra: Partial<RetryOptions> = {}, now?: Date) => {
      const { fetch } = scripted([status(code, { "Retry-After": retryAfter })]);
      const { retry, sleeps } = instant({ baseDelayMs: 100, maxDelayMs: 5000, ...extra });
      const clock = now === undefined ? {} : { clock: () => now };

      await Effect.runPromise(getWallet(createUnauthenticatedClient({ fetch, retry, ...clock })));

      return sleeps;
    };

    it.each([429, 503])("waits the seconds a %i asks for, instead of the backoff", async (code) => {
      expect(await waitFor(code, "2")).toEqual([2000]);
      expect(await waitFor(code, "0")).toEqual([0]);
    });

    it("caps the wait at maxDelayMs", async () => {
      expect(await waitFor(429, "3600")).toEqual([5000]);
      expect(await waitFor(503, "10", { maxDelayMs: 1500 })).toEqual([1500]);
    });

    it("waits until an HTTP-date, measured on the clock option", async () => {
      const now = new Date("2026-01-01T00:00:00Z");

      expect(await waitFor(503, "Thu, 01 Jan 2026 00:00:03 GMT", {}, now)).toEqual([3000]);
      expect(await waitFor(503, "Thu, 01 Jan 2026 00:10:00 GMT", {}, now)).toEqual([5000]);
      expect(await waitFor(429, "Wed, 31 Dec 2025 23:00:00 GMT", {}, now)).toEqual([0]);
    });

    it("falls back to the backoff for a value that is no delay", async () => {
      expect(await waitFor(503, "soon")).toEqual([100]);
      expect(await waitFor(503, "-5")).toEqual([100]);
    });

    it("applies to 429 and 503 only", async () => {
      expect(await waitFor(502, "3")).toEqual([100]);
    });

    it("is not jittered", async () => {
      expect(await waitFor(429, "2", { jitter: "full", random: () => 0.1 })).toEqual([2000]);
    });
  });
});

describe("signing", () => {
  it("signs every attempt anew: fresh created, fresh nonce, a signature of its own", async () => {
    const { privateKey } = await Effect.runPromise(generateEd25519KeyPair());
    const { fetch, seen } = scripted([status(503), status(503), status(503)]);
    let second = 1_700_000_000;

    const client = createAuthenticatedClient({
      walletAddressUrl: WALLET,
      keyId: "k",
      privateKey,
      fetch,
      clock: () => new Date(second++ * 1000),
      retry: instant().retry,
    });

    await failure(client.token.revoke({ url: `${ORIGIN}/as/token/1`, accessToken: "t" }));

    const inputs = seen.map((request) => request.headers.get("signature-input") ?? "");
    const nonces = inputs.map((input) => /nonce="([^"]+)"/.exec(input)?.[1]);
    const created = inputs.map((input) => /created=(\d+)/.exec(input)?.[1]);

    expect(seen).toHaveLength(3);
    expect(new Set(nonces).size).toBe(3);
    expect(nonces.every((nonce) => nonce !== undefined)).toBe(true);
    expect(created.length).toBe(3);
    expect(new Set(created).size).toBe(3);
    expect(new Set(seen.map((request) => request.headers.get("signature"))).size).toBe(3);
  });

  it("re-signs a POST body with the retry opt-in", async () => {
    const { privateKey } = await Effect.runPromise(generateEd25519KeyPair());
    const { fetch, seen } = scripted([status(503), status(503), status(503)]);

    const client = createAuthenticatedClient({
      walletAddressUrl: WALLET,
      keyId: "k",
      privateKey,
      fetch,
      retry: instant({ retryNonIdempotent: true }).retry,
    });

    await failure(client.quote.create({ url: `${ORIGIN}/rs`, accessToken: "t" }, quoteArgs));
    expect(await Promise.all(seen.map((request) => request.text()))).toEqual(Array(3).fill(JSON.stringify(quoteArgs)));
    expect(new Set(seen.map((request) => request.headers.get("signature"))).size).toBe(3);
  });
});

describe("interruption", () => {
  it("cancels the wait and starts no further attempt", async () => {
    const { fetch, seen } = scripted([status(503), status(503), status(503)]);
    const controller = new AbortController();
    let cancelled = false;

    const retry: RetryOptions = {
      maxAttempts: 5,
      sleep: () =>
        Effect.suspend(() => {
          controller.abort();

          return Effect.never;
        }).pipe(Effect.onInterrupt(() => Effect.sync(() => (cancelled = true)))),
    };

    await expect(
      Effect.runPromise(getWallet(createUnauthenticatedClient({ fetch, retry })), { signal: controller.signal }),
    ).rejects.toBeDefined();
    expect(cancelled).toBe(true);
    expect(seen).toHaveLength(1);
  });

  it("aborts the in-flight fetch and does not retry it", async () => {
    const controller = new AbortController();
    let calls = 0;
    let fetchSignal: AbortSignal | undefined;

    const fetch: typeof globalThis.fetch = (_input, init) => {
      calls++;
      fetchSignal = init?.signal ?? undefined;
      queueMicrotask(() => controller.abort());

      return new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
      });
    };

    const { retry, sleeps } = instant();

    await expect(
      Effect.runPromise(getWallet(createUnauthenticatedClient({ fetch, retry })), { signal: controller.signal }),
    ).rejects.toBeDefined();
    expect(fetchSignal?.aborted).toBe(true);
    expect(calls).toBe(1);
    expect(sleeps).toEqual([]);
  });
});
