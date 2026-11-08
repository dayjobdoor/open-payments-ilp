import { describe, expect, it } from "vite-plus/test";
import { IlpCodecError } from "../../src/plain/ilp";
import {
  deserializeIldcpRequest,
  deserializeIldcpResponse,
  fetchIldcp,
  serializeIldcpResponse,
  serveIldcp,
} from "../../src/plain/ildcp";
import { serializeFulfill, serializeReply } from "../../src/ilp/packets";
import * as Result from "effect/Result";

const response = { clientAddress: "g.hub.alice", assetScale: 6, assetCode: "USD" };
const now = new Date("2030-01-01T00:00:00.000Z");

describe("plain ildcp", () => {
  it("round-trips a response by returning values", () => {
    expect(deserializeIldcpResponse(serializeIldcpResponse(response))).toEqual(response);
  });

  it("fetches this node's address through a send callback", async () => {
    let requested: Uint8Array | undefined;

    const result = await fetchIldcp(
      async (prepare) => {
        requested = prepare;
        const reply = serveIldcp({ requestPacket: prepare, serverAddress: "g.hub", response, now });

        return Result.getOrThrow(serializeReply(reply));
      },
      { clock: () => now, ttlMs: 5_000 },
    );

    expect(result).toEqual(response);
    expect(deserializeIldcpRequest(requested!).expiresAt).toEqual(new Date(now.getTime() + 5_000));
  });

  it("uses a 30 s request lifetime by default, reading now from the clock, and accepts a synchronous sendData", async () => {
    let requested: Uint8Array | undefined;

    const result = await fetchIldcp(
      (prepare) => {
        requested = prepare;

        return Result.getOrThrow(
          serializeReply(serveIldcp({ requestPacket: prepare, serverAddress: "g.hub", response, now })),
        );
      },
      { clock: () => now },
    );

    expect(result).toEqual(response);
    expect(deserializeIldcpRequest(requested!).expiresAt).toEqual(new Date(now.getTime() + 30_000));
  });

  it("rejects with IlpCodecError naming the code and message when the connector answers with a Reject", async () => {
    const reject = Result.getOrThrow(
      serializeReply({
        code: "F00",
        triggeredBy: "g.hub",
        message: "no config for you",
        data: new Uint8Array(0),
      }),
    );
    const error = await fetchIldcp(async () => reject).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(IlpCodecError);
    expect(error).toMatchObject({ _tag: "IlpCodecError", reason: "invalid-type" });
    expect((error as IlpCodecError).message).toContain("F00");
    expect((error as IlpCodecError).message).toContain("no config for you");
  });

  it("throws IlpCodecError when the connector answers with garbage", async () => {
    await expect(fetchIldcp(async () => new Uint8Array([9, 9]))).rejects.toBeInstanceOf(IlpCodecError);
    await expect(
      fetchIldcp(async () =>
        Result.getOrThrow(serializeFulfill({ fulfillment: new Uint8Array(32).fill(1), data: new Uint8Array(0) })),
      ),
    ).rejects.toMatchObject({ _tag: "IlpCodecError", reason: "invalid-field" });
  });

  it("lets a failure of sendData through unchanged", async () => {
    const boom = new Error("link down");

    await expect(
      fetchIldcp(async () => {
        throw boom;
      }),
    ).rejects.toBe(boom);
  });
});
