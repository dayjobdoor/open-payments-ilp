import * as Cause from "effect/Cause";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as Fiber from "effect/Fiber";

import { afterEach, describe, expect, it, vi } from "vite-plus/test";
import { IlpHttpError, postPrepare } from "../../src/ilp";

const prepare = new Uint8Array([1, 2, 3]);

const url = "https://peer.example/ilp";

/** The failure of `postPrepare`, or fails the test when it succeeded. */
const failure = async (
  fetch: typeof globalThis.fetch,
  options: { timeoutMs?: number; maxReplyBytes?: number; token?: string } = {},
) => {
  const exit = await Effect.runPromiseExit(postPrepare(prepare, { url, fetch, ...options }));

  if (!Exit.isFailure(exit)) throw new Error("expected a failure");

  const error = exit.cause.reasons.find((reason) => reason._tag === "Fail")?.error;

  if (!(error instanceof IlpHttpError)) throw new Error("expected an IlpHttpError");

  return error;
};

describe("postPrepare (ILP over HTTP, RFC 35)", () => {
  it("POSTs the Prepare as octet-stream with the bearer token and resolves with the reply bytes", async () => {
    const sent: RequestInit[] = [];

    const reply = await Effect.runPromise(
      postPrepare(prepare, {
        url,
        token: "t0ken",
        fetch: async (input, init) => {
          expect(input).toBe(url);
          sent.push(init ?? {});

          return new Response(new Uint8Array([4, 5, 6]));
        },
      }),
    );

    expect(reply).toEqual(new Uint8Array([4, 5, 6]));
    expect(sent).toEqual([
      {
        method: "POST",
        headers: { "Content-Type": "application/octet-stream", Authorization: "Bearer t0ken" },
        body: prepare,
        redirect: "manual",
        signal: expect.any(AbortSignal),
      },
    ]);
  });

  it("sends no Authorization header without a token", async () => {
    await Effect.runPromise(
      postPrepare(prepare, {
        url,
        fetch: async (_input, init) => {
          expect(init?.headers).toEqual({ "Content-Type": "application/octet-stream" });

          return new Response(new Uint8Array());
        },
      }),
    );
  });

  it("fails with reason status and the status code for a non-2xx answer", async () => {
    const error = await failure(async () => new Response("nope", { status: 404 }));

    expect(error).toMatchObject({ reason: "status", status: 404, message: "ILP over HTTP failed: 404" });
  });

  it.each([300, 301, 302, 303, 304, 307, 308])("does not follow a %i redirect and cancels its body", async (status) => {
    let cancelled = false;

    const body = new ReadableStream<Uint8Array>({
      cancel: () => {
        cancelled = true;
      },
    });

    const error = await failure(
      // A 304 cannot carry a body at all.
      async () =>
        new Response(status === 304 ? null : body, {
          status,
          headers: { location: "https://other.example" },
        }),
    );

    expect(error).toMatchObject({ reason: "network", message: "Redirects are not followed" });
    expect(error.status).toBeUndefined();
    expect(cancelled).toBe(status !== 304);
  });

  it("does not follow an opaque redirect either", async () => {
    const response = new Response(null);
    Object.defineProperty(response, "type", { value: "opaqueredirect" });

    const error = await failure(async () => response);

    expect(error).toMatchObject({ reason: "network", message: "Redirects are not followed" });
  });

  it.each([400, 401, 404, 500, 503])(
    "fails with reason status for %i, and the Reject-carrying 2xx range passes",
    async (status) => {
      const error = await failure(async () => new Response("no", { status }));

      expect(error).toMatchObject({ reason: "status", status });
    },
  );

  it.each([200, 201, 204, 299])("treats %i as a reply", async (status) => {
    const reply = await Effect.runPromise(
      postPrepare(prepare, {
        url,
        fetch: async () => new Response(status === 204 ? null : new Uint8Array([9]), { status }),
      }),
    );

    expect(reply).toEqual(status === 204 ? new Uint8Array() : new Uint8Array([9]));
  });

  it("fails with reason too-large for a reply over the cap, announced or streamed", async () => {
    const announced = await failure(
      async () => new Response(new Uint8Array(10), { headers: { "Content-Length": "100000" } }),
      { maxReplyBytes: 64 },
    );

    const streamed = await failure(async () => new Response(new Uint8Array(65)), { maxReplyBytes: 64 });

    expect(announced.reason).toBe("too-large");
    expect(streamed.reason).toBe("too-large");
  });

  it("accepts a reply of exactly the cap", async () => {
    const reply = await Effect.runPromise(
      postPrepare(prepare, { url, maxReplyBytes: 64, fetch: async () => new Response(new Uint8Array(64)) }),
    );

    expect(reply.byteLength).toBe(64);
  });

  it("fails with reason timeout when the peer does not answer within timeoutMs", async () => {
    const error = await failure(
      (_input, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(init.signal?.reason));
        }),
      { timeoutMs: 20 },
    );

    expect(error.reason).toBe("timeout");
  });

  it("fails with reason timeout when the body stalls after the headers", async () => {
    const stalled = new ReadableStream<Uint8Array>({ start: () => undefined });

    const error = await failure(async () => new Response(stalled), { timeoutMs: 20 });

    expect(error.reason).toBe("timeout");
  });
});

describe("postPrepare options", () => {
  const never = async (): Promise<Response> => {
    throw new Error("fetch must not be called");
  };

  it.each([
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["-Infinity", Number.NEGATIVE_INFINITY],
    ["a negative value", -1],
    ["one above the 2^31-1 timer limit", 2 ** 31],
  ])("refuses timeoutMs %s with reason invalid-option and sends nothing", async (_name, timeoutMs) => {
    const error = await failure(never, { timeoutMs });

    expect(error).toMatchObject({ reason: "invalid-option" });
    expect(error.message).toContain("timeoutMs");
  });

  it.each([
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["zero", 0],
    ["a negative value", -1],
  ])("refuses maxReplyBytes %s with reason invalid-option and sends nothing", async (_name, maxReplyBytes) => {
    const error = await failure(never, { maxReplyBytes });

    expect(error).toMatchObject({ reason: "invalid-option" });
    expect(error.message).toContain("maxReplyBytes");
  });

  it.each([
    ["a line break", "secret\nvalue"],
    ["a NUL", "secret\0value"],
    ["a tab", "secret\tvalue"],
    ["DEL", "secret\x7fvalue"],
    ["a character above Latin-1", "secret€value"],
  ])("refuses a token with %s as invalid-option, sends nothing and never quotes it", async (_name, token) => {
    const error = await failure(never, { token });

    expect(error).toMatchObject({ reason: "invalid-option" });
    expect(error.message).toContain("token");
    expect(error.message).not.toContain("secret");
    expect(error.cause).toBeUndefined();
  });

  it("sends a token made of visible ASCII and Latin-1 characters", async () => {
    const sent: HeadersInit[] = [];

    await Effect.runPromise(
      postPrepare(prepare, {
        url,
        token: "aZ09 !~\u00e9\u00ff",
        fetch: async (_input, init) => {
          sent.push(init?.headers ?? {});

          return new Response(new Uint8Array([1]));
        },
      }),
    );

    expect(sent).toEqual([{ "Content-Type": "application/octet-stream", Authorization: "Bearer aZ09 !~\u00e9\u00ff" }]);
  });

  it("still enforces a numeric maxReplyBytes cap (NaN used to remove it)", async () => {
    const error = await failure(async () => new Response(new Uint8Array(100)), { maxReplyBytes: 10 });

    expect(error.reason).toBe("too-large");
  });

  it("accepts the largest timer value, and a timeout of that size does not fire early", async () => {
    // Above 2^31-1 a Node timer fires after about 1 ms, so a 30 ms answer would have been aborted.
    const reply = await Effect.runPromise(
      postPrepare(prepare, {
        url,
        timeoutMs: 2 ** 31 - 1,
        fetch: (_input, init) =>
          new Promise<Response>((resolve, reject) => {
            init?.signal?.addEventListener("abort", () => reject(init.signal?.reason));
            setTimeout(() => resolve(new Response(new Uint8Array([7]))), 30);
          }),
      }),
    );

    expect(reply).toEqual(new Uint8Array([7]));
  });
});

describe("postPrepare timer", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  const fakeTimers = (): void => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  };

  it("is cleared once the exchange has ended, whether it succeeded or failed", async () => {
    fakeTimers();

    await Effect.runPromise(postPrepare(prepare, { url, fetch: async () => new Response(new Uint8Array([1])) }));
    expect(vi.getTimerCount()).toBe(0);

    await failure(async () => new Response("no", { status: 500 }));
    expect(vi.getTimerCount()).toBe(0);

    await failure(async () => Promise.reject(new TypeError("reset")));
    expect(vi.getTimerCount()).toBe(0);
  });

  it("is pending while the exchange runs, and fires after exactly timeoutMs with reason timeout", async () => {
    fakeTimers();
    let seen: AbortSignal | undefined;

    const result = Effect.runPromiseExit(
      postPrepare(prepare, {
        url,
        timeoutMs: 1_000,
        fetch: (_input, init) =>
          new Promise<Response>((_resolve, reject) => {
            seen = init?.signal ?? undefined;
            init?.signal?.addEventListener("abort", () => reject(init.signal?.reason));
          }),
      }),
    );

    await vi.advanceTimersByTimeAsync(999);
    expect(vi.getTimerCount()).toBe(1);
    expect(seen?.aborted).toBe(false);

    await vi.advanceTimersByTimeAsync(1);
    expect(seen?.aborted).toBe(true);

    const exit = await result;

    expect(Exit.isFailure(exit) && exit.cause.reasons[0]).toMatchObject({ error: { reason: "timeout" } });
    expect(vi.getTimerCount()).toBe(0);
  });

  it("does not time out an answer that takes longer than the default when timeoutMs is 0", async () => {
    fakeTimers();
    let signal: AbortSignal | undefined;
    let timersDuringFetch = -1;
    let answer: (response: Response) => void = () => undefined;

    const result = Effect.runPromise(
      postPrepare(prepare, {
        url,
        timeoutMs: 0,
        fetch: (_input, init) =>
          new Promise<Response>((resolve) => {
            signal = init?.signal ?? undefined;
            timersDuringFetch = vi.getTimerCount();
            answer = resolve;
          }),
      }),
    );

    await vi.advanceTimersByTimeAsync(10 * 60_000);
    expect(signal?.aborted).toBe(false);
    expect(timersDuringFetch).toBe(0);

    answer(new Response(new Uint8Array([5])));

    expect(await result).toEqual(new Uint8Array([5]));
  });

  it("applies the 30 s default when timeoutMs is not given", async () => {
    fakeTimers();
    let signal: AbortSignal | undefined;

    const result = Effect.runPromiseExit(
      postPrepare(prepare, {
        url,
        fetch: (_input, init) =>
          new Promise<Response>((_resolve, reject) => {
            signal = init?.signal ?? undefined;
            init?.signal?.addEventListener("abort", () => reject(init.signal?.reason));
          }),
      }),
    );

    await vi.advanceTimersByTimeAsync(29_999);
    expect(signal?.aborted).toBe(false);

    await vi.advanceTimersByTimeAsync(1);
    expect(signal?.aborted).toBe(true);
    const exit = await result;

    expect(Exit.isFailure(exit) && exit.cause.reasons[0]).toMatchObject({ error: { reason: "timeout" } });
  });

  it("aborts the request and clears the timer when the effect is interrupted", async () => {
    fakeTimers();
    let signal: AbortSignal | undefined;

    const fiber = Effect.runFork(
      postPrepare(prepare, {
        url,
        fetch: (_input, init) =>
          new Promise<Response>((_resolve, reject) => {
            signal = init?.signal ?? undefined;
            init?.signal?.addEventListener("abort", () => reject(init.signal?.reason));
          }),
      }),
    );

    await vi.advanceTimersByTimeAsync(5);
    expect(signal?.aborted).toBe(false);

    await Effect.runPromise(Fiber.interrupt(fiber));
    const exit = await Effect.runPromise(Fiber.await(fiber));

    expect(Exit.isFailure(exit) && Cause.hasInterrupts(exit.cause)).toBe(true);
    expect(signal?.aborted).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe("postPrepare failures", () => {
  it("fails with reason network and the cause when fetch rejects", async () => {
    const cause = new TypeError("connection reset");
    const error = await failure(async () => Promise.reject(cause));

    expect(error).toMatchObject({ reason: "network", message: "connection reset" });
    expect(error.cause).toBe(cause);
  });
});
