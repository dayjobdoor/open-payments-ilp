import * as IlpPacket from "ilp-packet";
import * as Reference from "ilp-protocol-ildcp";
import * as Result from "effect/Result";
import { describe, expect, it } from "vite-plus/test";
import { deserializeFulfill, IlpErrorCode, isFulfill, isReject, serializeFulfill, serializeReply } from "../../src/ilp";
import {
  deserializeIldcpRequest,
  deserializeIldcpResponse,
  ILDCP_DESTINATION,
  serializeIldcpRequest,
  serializeIldcpResponse,
  serveIldcp,
  type IldcpResponse,
} from "../../src/ildcp";

const FAR_FUTURE = new Date(Date.UTC(2099, 0, 1));

const NOW = new Date(Date.UTC(2026, 9, 11, 12, 0, 0));

// Expired relative to any real clock, because the reference reads Date.now().
const LONG_PAST = new Date(Date.UTC(2000, 0, 1));

const responses: IldcpResponse[] = [
  { clientAddress: "test.operator.peer", assetScale: 2, assetCode: "USD" },
  { clientAddress: "g.a", assetScale: 0, assetCode: "" },
  { clientAddress: "private.x.y_z-1~2", assetScale: 255, assetCode: "ＪＰＹ€" },
];

describe("IL-DCP request codec matches ilp-protocol-ildcp", () => {
  it("serializes byte for byte", () => {
    for (const data of [undefined, Uint8Array.of(1, 2, 3)]) {
      const mine = Result.getOrThrow(serializeIldcpRequest({ expiresAt: FAR_FUTURE, ...(data && { data }) }));

      const theirs = Reference.serializeIldcpRequest({
        expiresAt: FAR_FUTURE,
        ...(data && { data: Buffer.from(data) }),
      });

      expect(Buffer.from(mine).equals(theirs)).toBe(true);
    }
  });

  it("parses what the reference serializes, and the reference parses what we serialize", () => {
    const theirs = Reference.serializeIldcpRequest({ expiresAt: FAR_FUTURE, data: Buffer.from([9]) });
    const mine = Result.getOrThrow(serializeIldcpRequest({ expiresAt: FAR_FUTURE, data: Uint8Array.of(9) }));

    expect(Result.getOrThrow(deserializeIldcpRequest(theirs))).toEqual({
      expiresAt: FAR_FUTURE,
      data: Uint8Array.of(9),
    });
    expect(Reference.deserializeIldcpRequest(Buffer.from(mine)).expiresAt).toEqual(FAR_FUTURE);
  });

  it("targets peer.config with amount 0", () => {
    const prepare = IlpPacket.deserializeIlpPrepare(
      Buffer.from(Result.getOrThrow(serializeIldcpRequest({ expiresAt: FAR_FUTURE }))),
    );

    expect(prepare.destination).toBe(ILDCP_DESTINATION);
    expect(prepare.amount).toBe("0");
  });

  it("rejects a Prepare for another destination or with another condition", () => {
    const base = {
      amount: "0",
      expiresAt: FAR_FUTURE,
      data: Buffer.alloc(0),
      executionCondition: Buffer.from(Reference.serializeIldcpRequest({ expiresAt: FAR_FUTURE }).subarray(0, 0)),
    };

    const elsewhere = IlpPacket.serializeIlpPrepare({
      ...base,
      destination: "peer.other",
      executionCondition: IlpPacket.deserializeIlpPrepare(Reference.serializeIldcpRequest({ expiresAt: FAR_FUTURE }))
        .executionCondition,
    });

    const wrongCondition = IlpPacket.serializeIlpPrepare({
      ...base,
      destination: ILDCP_DESTINATION,
      executionCondition: Buffer.alloc(32),
    });

    expect(Result.isFailure(deserializeIldcpRequest(elsewhere))).toBe(true);
    expect(Result.isFailure(deserializeIldcpRequest(wrongCondition))).toBe(true);
  });
});

describe("IL-DCP response codec matches ilp-protocol-ildcp", () => {
  it.each(responses.map((r, i) => [i, r] as const))(
    "serializes response #%i byte for byte and round-trips",
    (_i, response) => {
      const mine = Result.getOrThrow(serializeIldcpResponse(response));

      expect(Buffer.from(mine).equals(Reference.serializeIldcpResponse(response))).toBe(true);
      expect(Result.getOrThrow(deserializeIldcpResponse(mine))).toEqual(response);
      expect(Reference.deserializeIldcpResponse(Buffer.from(mine))).toEqual(response);
      expect(Result.getOrThrow(deserializeIldcpResponse(Reference.serializeIldcpResponse(response)))).toEqual(response);
    },
  );

  it("refuses an invalid address or an out-of-range scale", () => {
    expect(Result.isFailure(serializeIldcpResponse({ ...responses[0]!, clientAddress: "nope" }))).toBe(true);
    expect(Result.isFailure(serializeIldcpResponse({ ...responses[0]!, assetScale: 256 }))).toBe(true);
    expect(Result.isFailure(serializeIldcpResponse({ ...responses[0]!, assetScale: -1 }))).toBe(true);
    expect(Result.isFailure(serializeIldcpResponse({ ...responses[0]!, assetScale: 1.5 }))).toBe(true);
  });

  it("rejects a Fulfill whose fulfillment is not all zero, and truncated data", () => {
    const wrongFulfillment = serializeFulfill({
      fulfillment: new Uint8Array(32).fill(1),
      data: Result.getOrThrow(deserializeFulfill(Result.getOrThrow(serializeIldcpResponse(responses[0]!)))).data,
    });

    const truncated = serializeFulfill({ fulfillment: new Uint8Array(32), data: Uint8Array.of(2, 0x67) });

    expect(Result.isFailure(deserializeIldcpResponse(Result.getOrThrow(wrongFulfillment)))).toBe(true);
    expect(Result.isFailure(deserializeIldcpResponse(Result.getOrThrow(truncated)))).toBe(true);
  });
});

describe("serveIldcp", () => {
  const response = responses[0]!;
  const serverAddress = "test.operator";

  it("answers a valid request exactly like ilp-protocol-ildcp's serve", async () => {
    const request = Reference.serializeIldcpRequest({ expiresAt: FAR_FUTURE });
    const theirs = await Reference.serve({ requestPacket: request, serverAddress, handler: async () => response });
    const mine = serveIldcp({ requestPacket: request, serverAddress, response, now: NOW });

    expect(isFulfill(mine)).toBe(true);
    expect(Result.getOrThrow(deserializeFulfill(theirs))).toEqual(mine);
    expect(
      Result.getOrThrow(
        deserializeIldcpResponse(
          Result.getOrThrow(
            serializeFulfill(isFulfill(mine) ? mine : { fulfillment: new Uint8Array(32), data: new Uint8Array(0) }),
          ),
        ),
      ),
    ).toEqual(response);
  });

  it("answers an expired request with F00 triggered by the server, as the reference does", async () => {
    const request = Reference.serializeIldcpRequest({ expiresAt: LONG_PAST });

    const theirs = IlpPacket.deserializeIlpReject(
      await Reference.serve({ requestPacket: request, serverAddress, handler: async () => response }),
    );

    const mine = serveIldcp({ requestPacket: request, serverAddress, response, now: NOW });

    expect(isReject(mine) && mine.code).toBe(IlpErrorCode.F00_BAD_REQUEST);
    expect(isReject(mine) && mine.triggeredBy).toBe(serverAddress);
    expect(isReject(mine) && mine.message).toBe(theirs.message);
    expect(theirs.code).toBe("F00");
  });

  it("does not treat a request expiring exactly now as expired", () => {
    const request = Result.getOrThrow(serializeIldcpRequest({ expiresAt: NOW }));

    expect(isFulfill(serveIldcp({ requestPacket: request, serverAddress, response, now: NOW }))).toBe(true);
  });

  it.each([
    ["garbage", Uint8Array.of(1, 2, 3)],
    ["a Fulfill", Result.getOrThrow(serializeIldcpResponse(responses[0]!))],
    [
      "a foreign Prepare",
      IlpPacket.serializeIlpPrepare({
        amount: "0",
        expiresAt: FAR_FUTURE,
        executionCondition: Buffer.alloc(32),
        destination: "g.a",
        data: Buffer.alloc(0),
      }),
    ],
  ])("answers %s with an F00 Reject", (_name, requestPacket) => {
    const reply = serveIldcp({ requestPacket, serverAddress, response, now: NOW });

    expect(isReject(reply) && reply.code).toBe("F00");
    expect(isReject(reply) && reply.triggeredBy).toBe(serverAddress);
  });

  it("answers F00 instead of throwing when the configured response is invalid", () => {
    const request = Reference.serializeIldcpRequest({ expiresAt: FAR_FUTURE });

    const reply = serveIldcp({
      requestPacket: request,
      serverAddress,
      response: { ...response, clientAddress: "bad" },
      now: NOW,
    });

    expect(isReject(reply) && reply.code).toBe("F00");
    expect(Result.isSuccess(serializeReply(reply))).toBe(true);
  });
});
