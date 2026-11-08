import { describe, expect, it } from "vite-plus/test";
import { announcesMoreThan, bufferResponse, readCapped } from "../../src/internal/http";

/** A stream that yields `chunks`, then stays open until cancelled; `cancelled` reports whether it was. */
function streamOf(...chunks: Uint8Array[]): {
  body: ReadableStream<Uint8Array>;
  cancelled: () => boolean;
} {
  let cancelled = false;
  let index = 0;

  const body = new ReadableStream<Uint8Array>({
    pull: (controller) => {
      const chunk = chunks[index++];

      if (chunk === undefined) controller.close();
      else controller.enqueue(chunk);
    },
    cancel: () => {
      cancelled = true;
    },
  });

  return { body, cancelled: () => cancelled };
}

describe("announcesMoreThan", () => {
  const headers = (value?: string) => new Headers(value === undefined ? {} : { "content-length": value });

  it("compares the announced length with the cap", () => {
    expect(announcesMoreThan(headers("101"), 100)).toBe(true);
    expect(announcesMoreThan(headers("100"), 100)).toBe(false);
    expect(announcesMoreThan(headers("0"), 100)).toBe(false);
  });

  it("does not announce anything without a usable header", () => {
    expect(announcesMoreThan(headers(), 100)).toBe(false);
    expect(announcesMoreThan(headers("not a number"), 100)).toBe(false);
    expect(announcesMoreThan(headers(""), 100)).toBe(false);
  });
});

describe("readCapped", () => {
  it("reads a body of exactly the cap, across chunks", async () => {
    const { body } = streamOf(Uint8Array.of(1, 2), Uint8Array.of(3, 4));

    expect(await readCapped(body, 4)).toEqual(Uint8Array.of(1, 2, 3, 4));
  });

  it("is empty for no body or an empty one", async () => {
    expect(await readCapped(null, 4)).toEqual(new Uint8Array());
    expect(await readCapped(streamOf().body, 4)).toEqual(new Uint8Array());
  });

  it("returns null and cancels the stream as soon as the cap is exceeded, without draining it", async () => {
    const { body, cancelled } = streamOf(Uint8Array.of(1, 2, 3), Uint8Array.of(4, 5), Uint8Array.of(6));

    expect(await readCapped(body, 4)).toBeNull();
    expect(cancelled()).toBe(true);
  });

  it("rejects with the signal's reason when the signal aborts, and cancels the stream", async () => {
    const stalled = new ReadableStream<Uint8Array>({
      start: () => undefined,
      cancel: () => undefined,
    });
    const controller = new AbortController();
    const reason = new DOMException("too slow", "TimeoutError");
    const pending = readCapped(stalled, 10, controller.signal);

    controller.abort(reason);

    await expect(pending).rejects.toBe(reason);
  });

  it("rejects at once when the signal is already aborted", async () => {
    const reason = new Error("already");

    await expect(readCapped(streamOf(Uint8Array.of(1)).body, 10, AbortSignal.abort(reason))).rejects.toBe(reason);
  });
});

describe("bufferResponse", () => {
  const read = async (response: Response, max = 1000) => {
    const buffered = await bufferResponse(response, max);

    if (buffered === null) throw new Error("expected a response");

    return buffered;
  };

  it("returns a plain Response with the same status, text and headers whose body can be read again", async () => {
    const original = new Response('{"a":1}', {
      status: 201,
      statusText: "Created",
      headers: { "x-id": "7" },
    });
    const buffered = await read(original);

    expect(buffered.status).toBe(201);
    expect(buffered.statusText).toBe("Created");
    expect(buffered.headers.get("x-id")).toBe("7");
    expect(await buffered.json()).toEqual({ a: 1 });
  });

  it("returns null for a body that announces or streams more than the cap, cancelling it", async () => {
    expect(await bufferResponse(new Response("x".repeat(50), { headers: { "content-length": "50" } }), 10)).toBeNull();

    const { body, cancelled } = streamOf(new Uint8Array(6), new Uint8Array(6));

    expect(await bufferResponse(new Response(body), 10)).toBeNull();
    expect(cancelled()).toBe(true);
  });

  it("accepts a body of exactly the cap", async () => {
    const buffered = await read(new Response("x".repeat(10)), 10);

    expect((await buffered.arrayBuffer()).byteLength).toBe(10);
  });

  // `new Response(bytes, { status: 204 })` throws a TypeError ("null body status"): the copy must have no body.
  it.each([204, 205, 304])("copies a %i, which cannot carry a body, without throwing", async (status) => {
    const buffered = await read(new Response(null, { status }));

    expect(buffered.status).toBe(status);
    expect(buffered.body).toBeNull();
    expect(await buffered.text()).toBe("");
  });

  it.each([200, 202, 400, 404, 500])("keeps status %i and the body of its answer", async (status) => {
    const buffered = await read(new Response("body", { status }));

    expect(buffered.status).toBe(status);
    expect(await buffered.text()).toBe("body");
  });

  it("propagates an abort while reading", async () => {
    const stalled = new ReadableStream<Uint8Array>({ start: () => undefined });
    const reason = new DOMException("stalled", "TimeoutError");

    await expect(bufferResponse(new Response(stalled), 10, AbortSignal.abort(reason))).rejects.toBe(reason);
  });
});
