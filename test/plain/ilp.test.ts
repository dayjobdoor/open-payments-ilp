import * as Result from "effect/Result";
import { describe, expect, it } from "vite-plus/test";
import * as packets from "../../src/ilp/packets";
import {
  conditionFromFulfillment,
  deserializeFulfill,
  deserializeIlpPacket,
  deserializeIlpPrepare,
  deserializeIlpReply,
  fulfillmentMatchesCondition,
  IlpCodecError,
  isFulfill,
  isReject,
  postPrepare,
  IlpHttpError,
  serializeIlpFulfill,
  serializeIlpPrepare,
  serializeIlpReject,
  serializeFulfill,
  serializePrepare,
  serializeReject,
  serializeReply,
  deserializePacket,
  deserializePrepare,
  deserializeReject,
  deserializeReply,
  type IlpPrepare,
} from "../../src/plain/ilp";

const fulfillment = new Uint8Array(32).fill(7);

const prepare = async (): Promise<IlpPrepare> => ({
  amount: 100n,
  expiresAt: new Date("2030-01-01T00:00:00.000Z"),
  executionCondition: await conditionFromFulfillment(fulfillment),
  destination: "g.alice.wallet",
  data: new Uint8Array([1, 2, 3]),
});

describe("plain ilp codecs", () => {
  it("round-trips a Prepare and returns values instead of Results", async () => {
    const original = await prepare();

    expect(deserializeIlpPrepare(serializeIlpPrepare(original))).toEqual(original);
    expect(serializePrepare).toBe(serializeIlpPrepare);
  });

  it("throws the tagged IlpCodecError on bad input", async () => {
    const bad = { ...(await prepare()), destination: "not an address!" };

    expect(() => serializePrepare(bad)).toThrow(IlpCodecError);
    expect(() => serializePrepare(bad)).toThrow(expect.objectContaining({ _tag: "IlpCodecError" }));
    expect(() => deserializeIlpPrepare(new Uint8Array([1, 2]))).toThrow(
      expect.objectContaining({ _tag: "IlpCodecError" }),
    );
  });

  it("distinguishes Fulfill and Reject replies", () => {
    const fulfill = deserializeIlpReply(serializeIlpFulfill({ fulfillment, data: new Uint8Array(0) }));
    const reject = deserializeIlpReply(
      serializeIlpReject({
        code: "F99",
        triggeredBy: "g.alice",
        message: "no",
        data: new Uint8Array(0),
      }),
    );

    expect(isFulfill(fulfill)).toBe(true);
    expect(isReject(reject)).toBe(true);
    expect(deserializeIlpPacket(serializeIlpFulfill({ fulfillment, data: new Uint8Array(0) }))).toMatchObject({
      type: 13,
      data: { fulfillment },
    });
  });
});

describe("plain ilp async helpers", () => {
  it("checks a fulfillment against its condition", async () => {
    const condition = await conditionFromFulfillment(fulfillment);

    expect(await fulfillmentMatchesCondition(fulfillment, condition)).toBe(true);
    expect(await fulfillmentMatchesCondition(new Uint8Array(32), condition)).toBe(false);
  });

  it("rejects with IlpCodecError for a fulfillment of the wrong length", async () => {
    await expect(conditionFromFulfillment(new Uint8Array(5))).rejects.toBeInstanceOf(IlpCodecError);
  });

  it("posts a Prepare and resolves with the reply bytes; failures reject with IlpHttpError", async () => {
    const reply = serializeIlpFulfill({ fulfillment, data: new Uint8Array(0) });
    const seen: Request[] = [];
    const ok = await postPrepare(serializeIlpPrepare(await prepare()), {
      url: "https://peer.test/ilp",
      token: "secret",
      fetch: async (input, init) => {
        seen.push(new Request(input, init));
        return new Response(reply, { headers: { "content-type": "application/octet-stream" } });
      },
    });

    expect(ok).toEqual(reply);
    expect(seen[0]?.headers.get("authorization")).toBe("Bearer secret");

    await expect(
      postPrepare(serializeIlpPrepare(await prepare()), {
        url: "https://peer.test/ilp",
        fetch: async () => new Response("nope", { status: 500 }),
      }),
    ).rejects.toBeInstanceOf(IlpHttpError);
  });
});

describe("plain ilp codecs are the matching Effect codecs, unwrapped", () => {
  const fulfill = { fulfillment, data: new Uint8Array([4, 5]) };
  const reject = { code: "F99", triggeredBy: "g.alice", message: "no", data: new Uint8Array([6]) };

  it("Fulfill", () => {
    expect(serializeFulfill(fulfill)).toEqual(Result.getOrThrow(packets.serializeFulfill(fulfill)));
    expect(deserializeFulfill(serializeFulfill(fulfill))).toEqual(fulfill);
    expect(() => serializeFulfill({ ...fulfill, fulfillment: new Uint8Array(2) })).toThrow(
      expect.objectContaining({ _tag: "IlpCodecError" }),
    );
    expect(() => deserializeFulfill(serializeReject(reject))).toThrow(
      expect.objectContaining({ _tag: "IlpCodecError" }),
    );
  });

  it("Reject", () => {
    expect(serializeReject(reject)).toEqual(Result.getOrThrow(packets.serializeReject(reject)));
    expect(deserializeReject(serializeReject(reject))).toEqual(reject);
    expect(() => deserializeReject(serializeFulfill(fulfill))).toThrow(
      expect.objectContaining({ _tag: "IlpCodecError" }),
    );
  });

  it("Reply and Packet", async () => {
    expect(deserializeReply(serializeReply(fulfill))).toEqual(fulfill);
    expect(deserializeReply(serializeReply(reject))).toEqual(reject);
    const prepareBytes = serializePrepare(await prepare());

    expect(() => deserializeReply(prepareBytes)).toThrow(expect.objectContaining({ _tag: "IlpCodecError" }));
    expect(deserializePacket(serializeReject(reject))).toMatchObject({ type: 14, data: reject });
    expect(deserializePrepare(prepareBytes)).toEqual(await prepare());
  });
});
