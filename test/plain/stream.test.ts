import { createHash, createHmac } from "node:crypto";
import { describe, expect, it } from "vite-plus/test";
import { IlpCodecError } from "../../src/plain/ilp";
import {
  buildStreamPrepare,
  createStreamReply,
  decodeStreamFrame,
  decodeStreamPacket,
  decodeStreamPaymentTag,
  decodeStreamReceipt,
  decryptStreamData,
  decryptStreamPacket,
  deriveStreamKeys,
  encodeStreamFrame,
  encodeStreamPacket,
  encryptStreamData,
  generateStreamCondition,
  generateStreamCredentials,
  generateStreamFulfillment,
  STREAM_ENCRYPTION_OVERHEAD,
  StreamError,
  StreamFrameType,
  verifyStreamReceipt,
} from "../../src/plain/stream";

const server = {
  serverSecret: crypto.getRandomValues(new Uint8Array(32)),
  serverAddress: "g.example.receiver",
};

const prepareFor = async (amount = 500n) => {
  const credentials = await generateStreamCredentials(server, { asset: { code: "USD", scale: 2 } });
  const prepare = await buildStreamPrepare({
    destination: credentials.ilpAddress,
    sharedSecret: credentials.sharedSecret,
    amount,
    sequence: 1n,
    sourceAddress: "g.example.sender",
    expiresAt: new Date(Date.now() + 30_000),
  });

  return { credentials, prepare };
};

describe("plain stream", () => {
  it("accepts a payment through Promise-returning decisions", async () => {
    const { prepare } = await prepareFor();
    const reply = await createStreamReply(server, prepare);

    expect(reply.type).toBe("pending");
    if (reply.type !== "pending") return;

    const fulfill = reply.accept();

    expect(fulfill).toBeInstanceOf(Promise);
    expect((await fulfill).fulfillment).toHaveLength(32);
  });

  it("declines with a Reject, temporary or final", async () => {
    const { prepare } = await prepareFor();
    const reply = await createStreamReply(server, prepare);

    if (reply.type !== "pending") throw new Error("expected a pending reply");

    expect(await reply.temporaryDecline()).toMatchObject({ code: "T00" });
    expect(await reply.finalDecline("no thanks")).toMatchObject({ code: "F99" });
  });

  it("answers a Prepare for another server with a final reject", async () => {
    const { prepare } = await prepareFor();
    const other = {
      serverSecret: crypto.getRandomValues(new Uint8Array(32)),
      serverAddress: "g.example.other",
    };
    const reply = await createStreamReply(other, prepare);

    expect(reply.type).toBe("final");
  });

  it("rejects with StreamError for an unusable server configuration", async () => {
    const { prepare } = await prepareFor();

    await expect(
      createStreamReply({ serverSecret: new Uint8Array(3), serverAddress: "g.x" }, prepare),
    ).rejects.toBeInstanceOf(StreamError);
  });

  it("reads the payment tag of a destination", async () => {
    const credentials = await generateStreamCredentials(server, { paymentTag: "order-7" });

    expect(await decodeStreamPaymentTag(server, credentials.ilpAddress)).toBe("order-7");
  });

  it("round-trips packets and frames as plain values, and decrypts them", async () => {
    const { credentials, prepare } = await prepareFor();
    const frame = { type: "StreamMoney", streamId: 1n, shares: 1n } as const;

    expect(decodeStreamFrame(encodeStreamFrame(frame))).toMatchObject({ streamId: 1n });
    expect(StreamFrameType.StreamMoney).toBe(0x11);

    const decrypted = await decryptStreamPacket(credentials.sharedSecret, prepare.data);

    expect(decrypted.sequence).toBe(1n);
  });

  it("throws IlpCodecError for malformed packet bytes", () => {
    expect(() => decodeStreamPacket(new Uint8Array([1, 2, 3]))).toThrow(IlpCodecError);
  });
});

const hmacSha256 = (key: Uint8Array, data: Uint8Array): Uint8Array =>
  new Uint8Array(createHmac("sha256", key).update(data).digest());
const sha256 = (data: Uint8Array): Uint8Array => new Uint8Array(createHash("sha256").update(data).digest());

describe("plain stream wrappers call the matching Effect functions", () => {
  const secret = new Uint8Array(32).fill(7);
  const data = new TextEncoder().encode("stream payload");

  it("deriveStreamKeys derives the RFC 29 keys", async () => {
    const keys = await deriveStreamKeys(secret);

    expect(keys.encryptionKey).toEqual(hmacSha256(secret, new TextEncoder().encode("ilp_stream_encryption")));
    expect(keys.fulfillmentKey).toEqual(hmacSha256(secret, new TextEncoder().encode("ilp_stream_fulfillment")));
    await expect(deriveStreamKeys(new Uint8Array(0))).rejects.toMatchObject({
      _tag: "StreamError",
      reason: "invalid-key",
    });
  });

  it("encryptStreamData and decryptStreamData round-trip, and fail with StreamError", async () => {
    const { encryptionKey } = await deriveStreamKeys(secret);
    const sealed = await encryptStreamData(encryptionKey, data);

    expect(sealed).toHaveLength(data.length + STREAM_ENCRYPTION_OVERHEAD);
    expect(await decryptStreamData(encryptionKey, sealed)).toEqual(data);
    await expect(decryptStreamData(encryptionKey, sealed.slice(0, 5))).rejects.toMatchObject({
      _tag: "StreamError",
      reason: "decryption-failed",
    });
    await expect(decryptStreamData(new Uint8Array(3), sealed)).rejects.toMatchObject({
      reason: "invalid-key",
    });
    await expect(encryptStreamData(new Uint8Array(3), data)).rejects.toMatchObject({
      reason: "invalid-key",
    });
  });

  it("generateStreamFulfillment is HMAC-SHA256 and generateStreamCondition its SHA-256", async () => {
    const { fulfillmentKey } = await deriveStreamKeys(secret);
    const fulfillment = await generateStreamFulfillment(fulfillmentKey, data);

    expect(fulfillment).toEqual(hmacSha256(fulfillmentKey, data));
    expect(await generateStreamCondition(fulfillmentKey, data)).toEqual(sha256(fulfillment));
    await expect(generateStreamFulfillment(new Uint8Array(0), data)).rejects.toMatchObject({
      reason: "invalid-key",
    });
    await expect(generateStreamCondition(new Uint8Array(0), data)).rejects.toMatchObject({
      reason: "invalid-key",
    });
  });

  it("verifyStreamReceipt authenticates a receipt that decodeStreamReceipt parses", async () => {
    const receipt = new Uint8Array(58);
    const nonce = new Uint8Array(16).fill(3);

    receipt[0] = 1;
    receipt.set(nonce, 1);
    receipt[17] = 1;
    new DataView(receipt.buffer).setBigUint64(18, 1234n);
    receipt.set(hmacSha256(secret, receipt.subarray(0, 26)), 26);

    expect(decodeStreamReceipt(receipt)).toMatchObject({
      version: 1,
      streamId: 1,
      totalReceived: 1234n,
    });
    expect(await verifyStreamReceipt(receipt, secret)).toMatchObject({ totalReceived: 1234n });
    await expect(verifyStreamReceipt(receipt, new Uint8Array(32).fill(8))).rejects.toMatchObject({
      _tag: "StreamError",
      reason: "receipt-hmac-mismatch",
    });
    expect(() => decodeStreamReceipt(receipt.subarray(1))).toThrow(expect.objectContaining({ _tag: "IlpCodecError" }));
  });

  it("encodeStreamPacket and decodeStreamPacket round-trip and throw IlpCodecError", () => {
    const packet = {
      sequence: 9n,
      ilpPacketType: 12,
      prepareAmount: 100n,
      frames: [{ type: "StreamMoney", streamId: 1n, shares: 1n }],
    } as const;

    expect(decodeStreamPacket(encodeStreamPacket(packet))).toMatchObject({
      sequence: 9n,
      prepareAmount: 100n,
    });
    expect(() => encodeStreamPacket({ ...packet, sequence: -1n })).toThrow(
      expect.objectContaining({ _tag: "IlpCodecError" }),
    );
  });
});
