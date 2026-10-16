/** What operators can observe about failures, and that waiting on a peer ends when the request is interrupted. */
import * as Cause from "effect/Cause";
import * as Effect from "effect/Effect";
import * as Fiber from "effect/Fiber";
import { describe, expect, it } from "vite-plus/test";
import { HttpSignatureError, signRequest } from "../../src/http-signatures/index";
import { fetchClientKeys, memoryGnapStore, type GnapServerConfig } from "../../src/gnap/server/index";
import { readCapped } from "../../src/internal/http";
import {
  BASE_URL,
  WALLET,
  clientJwk,
  createClientKey,
  createServerHarness,
  errorOf,
  grantBody,
  incoming,
  json,
  walletFetch,
} from "./support";

type OnError = NonNullable<GnapServerConfig["onError"]>;

/** A hook that records the causes it is called with. */
const recorder = () => {
  const causes: Array<Cause.Cause<never>> = [];

  const onError: OnError = (cause) =>
    Effect.sync(() => {
      causes.push(cause);
    });

  return { causes, onError };
};

/** A store whose every write fails like a database outage would: as a defect. */
const brokenStore = () => ({
  ...memoryGnapStore(),
  createGrant: () => Effect.die(new Error("database is down: INSERT … VALUES ('secret-param')")),
});

const signedGrantRequest = async (h: Awaited<ReturnType<typeof createServerHarness>>) =>
  Effect.runPromise(
    signRequest(new Request(h.baseUrl, json("POST", grantBody([incoming]))), h.clientKey.signingKey, {
      created: h.clock.now(),
    }),
  );

describe("onError", () => {
  it("is told the cause of a defect that is answered as a 500, and the client learns nothing of it", async () => {
    const { causes, onError } = recorder();
    const h = await createServerHarness({ unvalidated: true, store: brokenStore(), onError });

    const response = await Effect.runPromise(h.server.route(await signedGrantRequest(h)));

    expect(response.status).toBe(500);
    expect(await response.text()).not.toContain("database");
    expect(causes).toHaveLength(1);

    const [cause] = causes;

    expect(cause && Cause.squash(cause)).toMatchObject({ message: expect.stringContaining("down") });
  });

  it("is not told about failures the server answers on purpose", async () => {
    const { causes, onError } = recorder();

    const h = await createServerHarness({
      unvalidated: true,
      onError,
      resolveClientKeys: () => Effect.fail(new HttpSignatureError({ reason: "unknown-key", message: "no keys" })),
    });

    expect((await h.call(new Request(`${BASE_URL}/no-such-route`))).status).toBe(404);
    expect(await errorOf(await h.signedCall(h.baseUrl, json("POST", grantBody([incoming]))))).toMatchObject({
      status: 400,
    });
    expect(causes).toEqual([]);
  });

  const misbehaving: ReadonlyArray<readonly [string, OnError]> = [
    ["dies", () => Effect.die(new Error("hook died"))],
    [
      "throws",
      () => {
        throw new Error("hook threw");
      },
    ],
  ];

  it.each(misbehaving)("never changes the response when the hook %s", async (_how, onError) => {
    const h = await createServerHarness({ unvalidated: true, store: brokenStore(), onError });
    const response = await Effect.runPromise(h.server.route(await signedGrantRequest(h)));

    expect(await errorOf(response)).toMatchObject({ status: 500, code: "request_denied" });
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("is optional: a defect is still a 500 without it", async () => {
    const h = await createServerHarness({ unvalidated: true, store: brokenStore() });
    const response = await Effect.runPromise(h.server.route(await signedGrantRequest(h)));

    expect(response.status).toBe(500);
  });
});

describe("the default key fetch's failures", () => {
  const failureOf = (fetchImpl: typeof globalThis.fetch) =>
    Effect.runPromise(Effect.flip(fetchClientKeys(fetchImpl)(WALLET)));

  it("are unknown-key errors whose cause says what went wrong", async () => {
    const key = await createClientKey();
    const timeout = new DOMException("The operation timed out", "TimeoutError");

    const failures = await Promise.all([
      failureOf(() => Promise.reject(timeout)),
      failureOf(async () => new Response("down", { status: 503 })),
      failureOf(async () => new Response(null, { status: 302, headers: { location: "https://elsewhere.test/" } })),
      failureOf(async () => Response.json({ keys: [clientJwk(key)], padding: "x".repeat(70_000) })),
      failureOf(async () => Response.json({ not: "a key set" })),
    ]);

    for (const failure of failures) {
      expect(failure).toBeInstanceOf(HttpSignatureError);
      expect(failure.reason).toBe("unknown-key");
    }

    expect(failures[0]?.cause).toBe(timeout);
    const causes = failures.map((failure) => failure.cause);

    expect(causes.every((cause) => cause instanceof Error)).toBe(true);
    expect(new Set(causes.map((cause) => (cause instanceof Error ? cause.message : ""))).size).toBe(5);
  });

  it("have no cause when the wallet address is refused before any request", async () => {
    const failure = await Effect.runPromise(Effect.flip(fetchClientKeys(walletFetch([]))("http://wallet.test/alice")));

    expect(failure.cause).toBeUndefined();
  });
});

describe("interrupting a request", () => {
  /** Resolves once `trigger` has been called. */
  const latch = () => {
    let trigger: () => void = () => undefined;
    const reached = new Promise<void>((resolve) => (trigger = resolve));

    return { reached, trigger };
  };

  it("aborts a stalled key fetch", async () => {
    const fetching = latch();
    let signal: AbortSignal | null | undefined;

    const fetchImpl: typeof globalThis.fetch = (_input, init) => {
      signal = init?.signal;
      fetching.trigger();

      return new Promise<Response>((_resolve, reject) =>
        init?.signal?.addEventListener("abort", () => reject(init.signal?.reason), { once: true }),
      );
    };

    const h = await createServerHarness({ unvalidated: true, fetch: fetchImpl });
    const fiber = Effect.runFork(h.server.route(await signedGrantRequest(h)));

    await fetching.reached;
    expect(signal?.aborted).toBe(false);

    await Effect.runPromise(Fiber.interrupt(fiber));

    expect(signal?.aborted).toBe(true);
  });

  it("cancels the stream of a stalled request body", async () => {
    const reading = latch();
    let cancelled = false;

    const body = new ReadableStream<Uint8Array>({
      pull: () => {
        reading.trigger();

        return new Promise<void>(() => undefined);
      },
      cancel: () => {
        cancelled = true;
      },
    });

    const h = await createServerHarness({ unvalidated: true });

    // `duplex` is required for a streaming body but missing from the DOM `RequestInit` type.
    const init: RequestInit & { duplex: "half" } = {
      method: "POST",
      body,
      duplex: "half",
      headers: { "content-type": "application/json" },
    };

    const fiber = Effect.runFork(h.server.route(new Request(h.baseUrl, init)));

    await reading.reached;
    expect(cancelled).toBe(false);

    await Effect.runPromise(Fiber.interrupt(fiber));

    expect(cancelled).toBe(true);
  });
});

describe("readCapped with a signal", () => {
  const stalled = () => {
    const state = { cancelled: false };

    const body = new ReadableStream<Uint8Array>({
      pull: () => new Promise<void>(() => undefined),
      cancel: () => {
        state.cancelled = true;
      },
    });

    return { body, state };
  };

  it("rejects with the signal's reason and cancels the stream when aborted mid-read", async () => {
    const { body, state } = stalled();
    const controller = new AbortController();
    const reading = readCapped(body, 1024, controller.signal);

    controller.abort(new Error("gone"));

    await expect(reading).rejects.toThrow("gone");
    expect(state.cancelled).toBe(true);
  });

  it("rejects without reading when the signal is already aborted", async () => {
    const { body, state } = stalled();

    await expect(readCapped(body, 1024, AbortSignal.abort(new Error("early")))).rejects.toThrow("early");
    expect(state.cancelled).toBe(true);
  });
});
