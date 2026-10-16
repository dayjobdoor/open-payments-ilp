import { createHmac, randomBytes } from "node:crypto";
import * as Effect from "effect/Effect";
import * as Result from "effect/Result";
import { createReceipt, decodeReceipt, verifyReceipt } from "ilp-protocol-stream/dist/src/util/receipt";
import { describe, expect, it } from "vite-plus/test";
import { IlpErrorCode, IlpPacketType, type IlpPrepare } from "../../src/ilp";
import {
  buildStreamPrepare,
  createStreamReply,
  decodeStreamReceipt,
  decryptStreamPacket,
  deriveStreamKeys,
  encryptStreamData,
  generateStreamCredentials,
  StreamError,
  verifyStreamReceipt,
} from "../../src/stream";
import { referencePrepare, StreamServer } from "../support/stream-oracle";

const SERVER_ADDRESS = "test.receiver";

const EXPIRES = new Date(Date.UTC(2099, 0, 1));

const bytes = (length: number): Uint8Array => new Uint8Array(randomBytes(length));

const run = Effect.runPromise;

const failure = async <A, E>(effect: Effect.Effect<A, E>): Promise<E | undefined> => {
  const result = await run(Effect.result(effect));

  return Result.isFailure(result) ? result.failure : undefined;
};

describe("STREAM receipts (RFC 39) interoperate with ilp-protocol-stream", () => {
  const nonce = bytes(16);
  const secret = bytes(32);

  it.each([0n, 1n, 40n, 2n ** 53n + 1n, (1n << 64n) - 1n])(
    "verifies and decodes the reference's receipt for %s received",
    async (totalReceived) => {
      const theirs = createReceipt({
        nonce: Buffer.from(nonce),
        secret: Buffer.from(secret),
        streamId: 1,
        totalReceived: totalReceived.toString(),
      });

      const decoded = Result.getOrThrow(decodeStreamReceipt(theirs));
      // The reference reports the stream id as a decimal string and keeps the HMAC (absent from its typings).
      // SAFETY: decodeReceipt returns the decoded receipt including `hmac`; only its declared type omits the field.
      const reference = decodeReceipt(theirs) as ReturnType<typeof decodeReceipt> & { hmac: Buffer };

      expect(decoded.totalReceived).toBe(totalReceived);
      expect(reference.totalReceived.toString()).toBe(totalReceived.toString());
      expect(String(decoded.streamId)).toBe(String(reference.streamId));
      expect(decoded.version).toBe(1);
      expect(Buffer.from(decoded.nonce).equals(reference.nonce)).toBe(true);
      expect(Buffer.from(decoded.hmac).equals(reference.hmac)).toBe(true);
      expect(await run(verifyStreamReceipt(theirs, secret))).toEqual(decoded);
    },
  );

  it("accepts a secret chosen per nonce, as the reference does", async () => {
    const theirs = createReceipt({
      nonce: Buffer.from(nonce),
      secret: Buffer.from(secret),
      streamId: 1,
      totalReceived: "7",
    });

    const seen: Uint8Array[] = [];

    const verified = await run(
      verifyStreamReceipt(theirs, (receipt) => {
        seen.push(receipt.nonce);

        return secret;
      }),
    );

    expect(verified.totalReceived).toBe(7n);
    expect(seen).toEqual([nonce]);
  });

  it("fails exactly where the reference throws", async () => {
    const good = createReceipt({
      nonce: Buffer.from(nonce),
      secret: Buffer.from(secret),
      streamId: 1,
      totalReceived: "40",
    });

    const flipped = (index: number): Uint8Array => good.map((byte, i) => (i === index ? byte ^ 1 : byte));
    // Version 2 with a correct HMAC: only the version is wrong.
    const futureVersion = Uint8Array.from(good);
    futureVersion[0] = 2;
    futureVersion.set(createHmac("sha256", secret).update(futureVersion.subarray(0, 26)).digest(), 26);

    const cases: ReadonlyArray<readonly [string, Uint8Array, Uint8Array, string]> = [
      ["too short", good.subarray(0, 57), secret, "invalid-receipt"],
      ["too long", Uint8Array.of(...good, 0), secret, "invalid-receipt"],
      ["empty", new Uint8Array(0), secret, "invalid-receipt"],
      ["a version other than 1", futureVersion, secret, "invalid-receipt"],
      ["a tampered total", flipped(25), secret, "receipt-hmac-mismatch"],
      ["a tampered nonce", flipped(3), secret, "receipt-hmac-mismatch"],
      ["a tampered HMAC", flipped(57), secret, "receipt-hmac-mismatch"],
      ["another secret", good, bytes(32), "receipt-hmac-mismatch"],
    ];

    for (const [name, receipt, key, reason] of cases) {
      expect(() => verifyReceipt(Buffer.from(receipt), Buffer.from(key)), name).toThrow();
      const error = await failure(verifyStreamReceipt(receipt, key));

      expect(error, name).toBeInstanceOf(StreamError);
      expect(error?.reason, name).toBe(reason);
    }

    expect((await failure(verifyStreamReceipt(good, new Uint8Array(0))))?.reason).toBe("invalid-key");
  });

  it("decodes only 58-byte receipts", () => {
    expect(Result.isFailure(decodeStreamReceipt(new Uint8Array(57)))).toBe(true);
    expect(Result.isFailure(decodeStreamReceipt(new Uint8Array(59)))).toBe(true);
    expect(Result.isSuccess(decodeStreamReceipt(new Uint8Array(58)))).toBe(true);
  });
});

describe("receipts issued by createStreamReply", () => {
  const serverSecret = bytes(32);
  const config = { serverSecret, serverAddress: SERVER_ADDRESS };

  async function pendingWithReceipt(amount: bigint, receipt: { nonce: Uint8Array; secret: Uint8Array }) {
    const credentials = await run(generateStreamCredentials(config, { receipt }));

    const prepare = await run(
      buildStreamPrepare({
        destination: credentials.ilpAddress,
        sharedSecret: credentials.sharedSecret,
        amount,
        sequence: 1n,
        sourceAddress: "test.sender",
        expiresAt: EXPIRES,
      }),
    );

    const reply = await run(createStreamReply(config, prepare));

    if (reply.type !== "pending") throw new Error("expected a pending reply");

    return { reply, credentials };
  }

  it("verify with verifyStreamReceipt after the sender reads them out of the Fulfill", async () => {
    const receipt = { nonce: bytes(16), secret: bytes(32) };
    const { reply, credentials } = await pendingWithReceipt(25n, receipt);
    const fulfill = await run(reply.accept({ totalReceived: 25n }));
    const packet = await run(decryptStreamPacket(credentials.sharedSecret, fulfill.data));
    const frame = packet.frames.find((f) => f.type === "StreamReceipt");

    expect(packet.ilpPacketType).toBe(IlpPacketType.Fulfill);
    expect(packet.prepareAmount).toBe(25n);

    if (frame?.type !== "StreamReceipt") throw new Error("no receipt frame");
    const verified = await run(verifyStreamReceipt(frame.receipt, receipt.secret));

    expect(verified.totalReceived).toBe(25n);
    expect(Buffer.from(verified.nonce).equals(Buffer.from(receipt.nonce))).toBe(true);
  });

  it.each([-1n, 1n << 64n])("refuses to issue a receipt for the impossible total %s", async (totalReceived) => {
    const { reply } = await pendingWithReceipt(25n, { nonce: bytes(16), secret: bytes(32) });
    const error = await failure(reply.accept({ totalReceived }));

    expect(error?.reason).toBe("invalid-option");
  });

  it("issues a receipt for the largest total", async () => {
    const { reply } = await pendingWithReceipt(25n, { nonce: bytes(16), secret: bytes(32) });

    expect((await run(reply.accept({ totalReceived: (1n << 64n) - 1n }))).data.length).toBeGreaterThan(0);
  });
});

describe("rate probes and reply decoding (what @interledger/pay needs from a sender)", () => {
  const serverSecret = bytes(32);
  const config = { serverSecret, serverAddress: SERVER_ADDRESS };
  const theirServer = new StreamServer({ serverSecret: Buffer.from(serverSecret), serverAddress: SERVER_ADDRESS });

  async function connection() {
    return run(generateStreamCredentials(config));
  }

  async function build(
    credentials: { ilpAddress: string; sharedSecret: Uint8Array },
    options: { amount: bigint; minDestinationAmount?: bigint; unfulfillable?: boolean },
  ): Promise<IlpPrepare> {
    return run(
      buildStreamPrepare({
        destination: credentials.ilpAddress,
        sharedSecret: credentials.sharedSecret,
        sequence: 2n,
        sourceAddress: "test.sender",
        expiresAt: EXPIRES,
        ...options,
      }),
    );
  }

  it("an unfulfillable Prepare is answered F05 with the amount that arrived, by both receivers", async () => {
    const credentials = await connection();
    const probe = await build(credentials, { amount: 321n, minDestinationAmount: 0n, unfulfillable: true });
    const theirs = theirServer.createReply(referencePrepare(probe));
    const mine = await run(createStreamReply(config, probe));

    if (mine.type !== "final" || "accept" in theirs) throw new Error("expected a final reject");

    if (!("code" in mine.reply) || !("code" in theirs)) throw new Error("expected rejects");

    expect([mine.reply.code, theirs.code]).toEqual([
      IlpErrorCode.F05_WRONG_CONDITION,
      IlpErrorCode.F05_WRONG_CONDITION,
    ]);

    for (const data of [mine.reply.data, new Uint8Array(theirs.data)]) {
      const packet = await run(decryptStreamPacket(credentials.sharedSecret, data));

      expect(packet.ilpPacketType).toBe(IlpPacketType.Reject);
      expect(packet.sequence).toBe(2n);
      expect(packet.prepareAmount).toBe(321n);
    }
  });

  it("uses a different random condition every time and never one the shared secret can fulfill", async () => {
    const credentials = await connection();
    const a = await build(credentials, { amount: 5n, unfulfillable: true });
    const b = await build(credentials, { amount: 5n, unfulfillable: true });
    const real = await build(credentials, { amount: 5n });

    expect(a.executionCondition).toHaveLength(32);
    expect(Buffer.from(a.executionCondition).equals(Buffer.from(b.executionCondition))).toBe(false);

    const keys = await run(deriveStreamKeys(credentials.sharedSecret));
    const fulfillable = createHmac("sha256", keys.fulfillmentKey).update(real.data).digest();
    const condition = Buffer.from(await crypto.subtle.digest("SHA-256", fulfillable));

    expect(Buffer.from(real.executionCondition).equals(condition)).toBe(true);
    expect(Buffer.from(a.executionCondition).equals(condition)).toBe(false);
  });

  it("minDestinationAmount sets the packet's minimum, which both receivers enforce with F04", async () => {
    const credentials = await connection();
    const accepted = await build(credentials, { amount: 100n, minDestinationAmount: 40n });
    const refused = await build(credentials, { amount: 100n, minDestinationAmount: 101n });
    const plain = await build(credentials, { amount: 100n });

    const minimum = async (prepare: IlpPrepare) =>
      (await run(decryptStreamPacket(credentials.sharedSecret, prepare.data))).prepareAmount;

    expect([await minimum(accepted), await minimum(refused), await minimum(plain)]).toEqual([40n, 101n, 100n]);
    expect(await run(createStreamReply(config, accepted))).toMatchObject({ type: "pending" });

    const reply = await run(createStreamReply(config, refused));
    const theirs = theirServer.createReply(referencePrepare(refused));

    expect(reply).toMatchObject({ type: "final", reply: { code: IlpErrorCode.F04_INSUFFICIENT_DESTINATION_AMOUNT } });
    expect(theirs).toMatchObject({ code: IlpErrorCode.F04_INSUFFICIENT_DESTINATION_AMOUNT });
    expect(await run(createStreamReply(config, plain))).toMatchObject({ type: "pending" });
  });

  describe("decryptStreamPacket", () => {
    it("reads Prepares from this builder and replies from either receiver", async () => {
      const credentials = await connection();
      const prepare = await build(credentials, { amount: 9n });
      const packet = await run(decryptStreamPacket(credentials.sharedSecret, prepare.data));

      expect(packet).toMatchObject({ sequence: 2n, ilpPacketType: IlpPacketType.Prepare, prepareAmount: 9n });
      expect(packet.frames.map((f) => f.type)).toEqual(["StreamMoney"]);

      const theirs = theirServer.createReply(referencePrepare(prepare));

      if (!("accept" in theirs)) throw new Error("expected the reference to accept");
      const reply = await run(decryptStreamPacket(credentials.sharedSecret, new Uint8Array(theirs.accept().data)));

      expect(reply).toMatchObject({ ilpPacketType: IlpPacketType.Fulfill, prepareAmount: 9n });
    });

    it("fails with StreamError for an empty secret, short data, a wrong secret and tampered data", async () => {
      const credentials = await connection();
      const prepare = await build(credentials, { amount: 9n });
      const tampered = prepare.data.map((byte, i) => (i === 30 ? byte ^ 1 : byte));

      const reasons = await Promise.all(
        [
          [new Uint8Array(0), prepare.data],
          [credentials.sharedSecret, prepare.data.subarray(0, 27)],
          [bytes(32), prepare.data],
          [credentials.sharedSecret, tampered],
        ].map(async ([secret, data]) => (await failure(decryptStreamPacket(secret!, data!)))?.reason),
      );

      expect(reasons).toEqual(["invalid-key", "decryption-failed", "decryption-failed", "decryption-failed"]);
    });

    it("fails with IlpCodecError when authentic data is not a STREAM packet", async () => {
      const credentials = await connection();
      const { encryptionKey } = await run(deriveStreamKeys(credentials.sharedSecret));
      const sealed = await run(encryptStreamData(encryptionKey, Uint8Array.of(2)));
      const result = await run(Effect.result(decryptStreamPacket(credentials.sharedSecret, sealed)));

      expect(Result.isFailure(result) && result.failure._tag).toBe("IlpCodecError");
    });
  });
});

describe("credential caching never changes the answer", () => {
  it("keeps working past the cache capacities, for many servers and many connections", async () => {
    const servers = Array.from({ length: 24 }, () => ({ serverSecret: bytes(32), serverAddress: SERVER_ADDRESS }));

    // Two passes: the second one meets every secret again after the first evicted the oldest.
    for (let pass = 0; pass < 2; pass++) {
      for (const server of servers) {
        const credentials = await run(generateStreamCredentials(server));

        const prepare = await run(
          buildStreamPrepare({
            destination: credentials.ilpAddress,
            sharedSecret: credentials.sharedSecret,
            amount: 3n,
            sequence: 1n,
            sourceAddress: "test.sender",
            expiresAt: EXPIRES,
          }),
        );

        expect(await run(createStreamReply(server, prepare))).toMatchObject({ type: "pending" });
      }
    }
  });

  it("is not fooled by a caller reusing and rewriting one secret array", async () => {
    const secret = bytes(32);
    const config = { serverSecret: bytes(32), serverAddress: SERVER_ADDRESS };
    const first = await run(generateStreamCredentials(config));
    const second = await run(generateStreamCredentials(config));

    const prepareWith = (credentials: typeof first) =>
      run(
        buildStreamPrepare({
          destination: credentials.ilpAddress,
          sharedSecret: secret,
          amount: 3n,
          sequence: 1n,
          sourceAddress: "test.sender",
          expiresAt: EXPIRES,
        }),
      );

    secret.set(first.sharedSecret);
    const toFirst = await prepareWith(first);
    secret.set(second.sharedSecret);
    const toSecond = await prepareWith(second);

    expect(await run(createStreamReply(config, toFirst))).toMatchObject({ type: "pending" });
    expect(await run(createStreamReply(config, toSecond))).toMatchObject({ type: "pending" });
    // The first connection's packet is not valid for the second connection's address.
    expect(await run(createStreamReply(config, { ...toFirst, destination: second.ilpAddress }))).toMatchObject({
      type: "final",
      reply: { code: IlpErrorCode.F06_UNEXPECTED_PAYMENT },
    });
  });

  it("serves several server addresses from one secret", async () => {
    const serverSecret = bytes(32);
    const a = { serverSecret, serverAddress: "test.tenant.a" };
    const b = { serverSecret, serverAddress: "test.tenant.b" };
    const credentials = await run(generateStreamCredentials(a));

    const prepare = await run(
      buildStreamPrepare({
        destination: credentials.ilpAddress,
        sharedSecret: credentials.sharedSecret,
        amount: 3n,
        sequence: 1n,
        sourceAddress: "test.sender",
        expiresAt: EXPIRES,
      }),
    );

    expect(await run(createStreamReply(a, prepare))).toMatchObject({ type: "pending" });
    // Same token under the other tenant's address: unreachable there, never mistaken for its own.
    expect(await run(createStreamReply(b, prepare))).toMatchObject({
      type: "final",
      reply: { code: IlpErrorCode.F02_UNREACHABLE, triggeredBy: "test.tenant.b" },
    });
    expect(
      await run(
        createStreamReply(b, { ...prepare, destination: `test.tenant.b.${prepare.destination.split(".").pop()}` }),
      ),
    ).toMatchObject({ type: "pending" });
  });
});

describe("generateStreamCredentials treats an empty payment tag as no tag, like stream-receiver", () => {
  it("issues the same 29-byte token and no tag", async () => {
    const serverSecret = bytes(32);
    const config = { serverSecret, serverAddress: SERVER_ADDRESS };
    const theirServer = new StreamServer({ serverSecret: Buffer.from(serverSecret), serverAddress: SERVER_ADDRESS });
    const mine = await run(generateStreamCredentials(config, { paymentTag: "" }));
    const theirs = theirServer.generateCredentials({ paymentTag: "" });
    const token = (address: string) => Buffer.from(address.slice(address.lastIndexOf(".") + 1), "base64url");

    expect(token(mine.ilpAddress)).toHaveLength(token(theirs.ilpAddress).length);
    expect(theirServer.decodePaymentTag(mine.ilpAddress)).toBeUndefined();
  });
});
