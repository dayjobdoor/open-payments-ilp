import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";

import { describe, expect, it } from "vite-plus/test";
import { IlpHttpError, postPrepare } from "../../src/ilp";

const prepare = new Uint8Array([1, 2, 3]);

const url = "https://peer.example/ilp";

/** The failure of `postPrepare`, or fails the test when it succeeded. */
const failure = async (
  fetch: typeof globalThis.fetch,
  options: { timeoutMs?: number; maxReplyBytes?: number } = {},
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

  it("applies no timeout with timeoutMs 0", async () => {
    await Effect.runPromise(
      postPrepare(prepare, {
        url,
        timeoutMs: 0,
        fetch: async (_input, init) => {
          expect(init?.signal?.aborted).toBe(false);

          return new Response(new Uint8Array());
        },
      }),
    );
  });

  it("fails with reason network and the cause when fetch rejects", async () => {
    const cause = new TypeError("connection reset");
    const error = await failure(async () => Promise.reject(cause));

    expect(error).toMatchObject({ reason: "network", message: "connection reset" });
    expect(error.cause).toBe(cause);
  });
});
