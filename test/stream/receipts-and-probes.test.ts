import { createHash, createHmac } from "node:crypto";
import * as Effect from "effect/Effect";
import * as Result from "effect/Result";
import { createReceipt, decodeReceipt, verifyReceipt } from "ilp-protocol-stream/dist/src/util/receipt";
import { describe, expect, it } from "vite-plus/test";
import { IlpErrorCode, IlpPacketType, isReject, type IlpPrepare } from "../../src/ilp";
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
import { byteSource } from "../support/prng";
import { reasonOf } from "../support/result";
import { referencePrepare, StreamServer } from "../support/stream-oracle";

const SERVER_ADDRESS = "test.receiver";

const EXPIRES = new Date(Date.UTC(2099, 0, 1));

const bytes = byteSource(0x4ec3);

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
      const reference = decodeReceipt(theirs) as ReturnType<typeof decodeReceipt> & {
        hmac: Buffer;
      };

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

  describe("a secret function", () => {
    const receipt = createReceipt({
      nonce: Buffer.from(nonce),
      secret: Buffer.from(secret),
      streamId: 1,
      totalReceived: "12",
    });

    it("may return a promise, as a database lookup does", async () => {
      const verified = await run(verifyStreamReceipt(receipt, async () => secret));

      expect(verified.totalReceived).toBe(12n);
    });

    it.each([
      [
        "throws",
        () => {
          throw new Error("unknown nonce");
        },
      ],
      ["rejects", async () => Promise.reject(new Error("unknown nonce"))],
    ])("that %s becomes an invalid-key failure instead of escaping the Effect", async (_how, lookup) => {
      // Building the Effect must not throw either: the lookup runs when the Effect does.
      const effect = verifyStreamReceipt(receipt, lookup);
      const error = await failure(effect);

      expect(error).toBeInstanceOf(StreamError);
      expect(error).toMatchObject({ reason: "invalid-key" });
      expect(error?.message).toContain("unknown nonce");
    });

    it("that returns an empty or a wrong secret fails as invalid-key or receipt-hmac-mismatch", async () => {
      expect((await failure(verifyStreamReceipt(receipt, async () => new Uint8Array(0))))?.reason).toBe("invalid-key");
      expect((await failure(verifyStreamReceipt(receipt, () => bytes(32))))?.reason).toBe("receipt-hmac-mismatch");
    });

    it.each([
      ["undefined", () => undefined],
      ["null", async () => null],
      ["a string", () => "secret"],
    ])("that returns %s (an unknown nonce) fails as invalid-key, not as a defect", async (_what, lookup) => {
      // SAFETY: simulates a lookup written without types, which answers an unknown nonce with no bytes.
      const error = await failure(verifyStreamReceipt(receipt, lookup as never));

      expect(error).toBeInstanceOf(StreamError);
      expect(error).toMatchObject({ reason: "invalid-key" });
    });

    it("is not called for a receipt that is malformed or of another version", async () => {
      let calls = 0;

      const lookup = () => {
        calls++;

        return secret;
      };

      await failure(verifyStreamReceipt(receipt.subarray(0, 57), lookup));
      expect(calls).toBe(0);
    });
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
    expect(reasonOf(decodeStreamReceipt(new Uint8Array(57)))).toBe("invalid-field");
    expect(reasonOf(decodeStreamReceipt(new Uint8Array(59)))).toBe("invalid-field");
    expect(reasonOf(decodeStreamReceipt(new Uint8Array(58)))).toBe("success");
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
    options: {
      amount: bigint;
      sequence?: bigint;
      minDestinationAmount?: bigint;
      unfulfillable?: boolean;
    },
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

    // The condition a sender holding the secret would have chosen for exactly this packet's data.
    const conditionFor = (data: Uint8Array) =>
      createHash("sha256").update(createHmac("sha256", keys.fulfillmentKey).update(data).digest()).digest();

    expect(Buffer.from(real.executionCondition).equals(conditionFor(real.data))).toBe(true);

    // A fresh IV already makes conditions differ between packets, so each probe is compared with its own data's.
    expect(Buffer.from(a.executionCondition).equals(conditionFor(a.data))).toBe(false);
    expect(Buffer.from(b.executionCondition).equals(conditionFor(b.data))).toBe(false);
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

    describe("binds a reply to its request with `expect`", () => {
      const rejectFor = async (prepare: IlpPrepare) => {
        const reply = await run(createStreamReply(config, prepare));

        if (reply.type !== "final" || !isReject(reply.reply)) throw new Error("expected a final reject");

        return reply.reply.data;
      };

      it("passes a reply with the expected sequence and ILP packet type, checking only what is given", async () => {
        const credentials = await connection();
        const probe = await build(credentials, { amount: 50n, sequence: 5n, unfulfillable: true });
        const data = await rejectFor(probe);

        const checked = await run(
          decryptStreamPacket(credentials.sharedSecret, data, {
            expect: { sequence: 5n, ilpPacketType: IlpPacketType.Reject },
          }),
        );

        expect(checked).toMatchObject({ sequence: 5n, ilpPacketType: IlpPacketType.Reject, prepareAmount: 50n });

        for (const expectation of [{}, { sequence: 5n }, { ilpPacketType: IlpPacketType.Reject }]) {
          expect(await run(decryptStreamPacket(credentials.sharedSecret, data, { expect: expectation }))).toEqual(
            checked,
          );
        }

        expect(await run(decryptStreamPacket(credentials.sharedSecret, data, {}))).toEqual(checked);
      });

      it("refuses an older reply replayed for a later request, which would spoof the delivered amount", async () => {
        const credentials = await connection();
        const first = await rejectFor(await build(credentials, { amount: 900n, sequence: 5n, unfulfillable: true }));
        const second = await rejectFor(await build(credentials, { amount: 7n, sequence: 6n, unfulfillable: true }));

        // Without `expect` the replay is indistinguishable from the real answer, and claims 900 arrived.
        expect((await run(decryptStreamPacket(credentials.sharedSecret, first))).prepareAmount).toBe(900n);

        const replayed = await failure(
          decryptStreamPacket(credentials.sharedSecret, first, { expect: { sequence: 6n } }),
        );

        expect(replayed).toBeInstanceOf(StreamError);
        expect(replayed).toMatchObject({ reason: "unexpected-packet" });
        expect(replayed?.message).toContain("sequence");

        const genuine = await run(decryptStreamPacket(credentials.sharedSecret, second, { expect: { sequence: 6n } }));

        expect(genuine.prepareAmount).toBe(7n);
      });

      it("refuses a Reject's data presented as a Fulfill's, and the other way round", async () => {
        const credentials = await connection();
        const reject = await rejectFor(await build(credentials, { amount: 5n, unfulfillable: true }));
        const theirs = theirServer.createReply(referencePrepare(await build(credentials, { amount: 5n })));

        if (!("accept" in theirs)) throw new Error("expected the reference to accept");
        const fulfill = new Uint8Array(theirs.accept().data);

        const asFulfill = await failure(
          decryptStreamPacket(credentials.sharedSecret, reject, { expect: { ilpPacketType: IlpPacketType.Fulfill } }),
        );

        const asReject = await failure(
          decryptStreamPacket(credentials.sharedSecret, fulfill, { expect: { ilpPacketType: IlpPacketType.Reject } }),
        );

        expect(asFulfill).toMatchObject({ _tag: "StreamError", reason: "unexpected-packet" });
        expect(asFulfill?.message).toContain("packet type");
        expect(asReject).toMatchObject({ _tag: "StreamError", reason: "unexpected-packet" });

        expect(
          await run(
            decryptStreamPacket(credentials.sharedSecret, fulfill, {
              expect: { ilpPacketType: IlpPacketType.Fulfill },
            }),
          ),
        ).toMatchObject({ ilpPacketType: IlpPacketType.Fulfill });
      });

      it("still reports undecryptable data as decryption-failed before comparing anything", async () => {
        const credentials = await connection();
        const error = await failure(
          decryptStreamPacket(credentials.sharedSecret, new Uint8Array(40), { expect: { sequence: 1n } }),
        );

        expect(error?.reason).toBe("decryption-failed");
      });
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
  it("keeps working past the server-secret cache capacity (16), with 24 servers", async () => {
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

  it("keeps working past the connection cache capacity (256), with 300 connections to one server", async () => {
    const server = { serverSecret: bytes(32), serverAddress: SERVER_ADDRESS };

    const connections = await Promise.all(
      Array.from({ length: 300 }, async () => {
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

        return prepare;
      }),
    );

    // The first connections were evicted by the later ones; each is still answered correctly when it returns.
    for (const prepare of [...connections, ...connections.slice().reverse()]) {
      expect(await run(createStreamReply(server, prepare))).toMatchObject({ type: "pending" });
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
        createStreamReply(b, {
          ...prepare,
          destination: `test.tenant.b.${prepare.destination.split(".").pop()}`,
        }),
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
