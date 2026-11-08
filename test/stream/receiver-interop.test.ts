import { createHash } from "node:crypto";
import type { IncomingMoney } from "@interledger/stream-receiver";
import * as Effect from "effect/Effect";
import * as Result from "effect/Result";
import { describe, expect, it } from "vite-plus/test";
import {
  fulfillmentMatchesCondition,
  IlpPacketType,
  isFulfill,
  isReject,
  MAX_ILP_DATA_LENGTH,
  serializeReject,
  type IlpPrepare,
  type IlpReject,
  type IlpReply,
} from "../../src/ilp";
import {
  buildStreamPrepare,
  createStreamReply,
  decodeStreamPacket,
  decryptStreamData,
  deriveStreamKeys,
  generateStreamCredentials,
  StreamError,
  StreamErrorCode,
  type StreamCredentialOptions,
  type StreamFrame,
  type StreamPacket,
  type StreamPendingReply,
  type StreamReply,
} from "../../src/stream";
import { byteSource } from "../support/prng";
import { IlpPacket, referencePrepare, referenceRequest, StreamServer } from "../support/stream-oracle";

const bytes = byteSource(0x5ec2);

const SERVER_ADDRESS = "test.receiver";

const EXPIRES = new Date(Date.UTC(2099, 0, 1));

const serverSecret = bytes(32);

const config = { serverSecret, serverAddress: SERVER_ADDRESS };

const theirServer = new StreamServer({ serverSecret: Buffer.from(serverSecret), serverAddress: SERVER_ADDRESS });

interface NormalizedReply {
  readonly kind: "fulfill" | "reject";
  readonly code: string | undefined;
  readonly triggeredBy: string | undefined;
  readonly message: string | undefined;
  readonly fulfillment: string | undefined;
  readonly stream: StreamPacket | undefined;
}

/** Decrypts the STREAM packet in a reply so replies with random IVs compare by content. */
async function normalize(
  reply: IlpReply | IlpPacket.IlpFulfill | IlpPacket.IlpReject,
  sharedSecret: Uint8Array,
): Promise<NormalizedReply> {
  const { encryptionKey } = await Effect.runPromise(deriveStreamKeys(sharedSecret));
  const data = new Uint8Array(reply.data);

  const stream =
    data.length === 0
      ? undefined
      : Result.getOrThrow(decodeStreamPacket(await Effect.runPromise(decryptStreamData(encryptionKey, data))));

  const fulfilled = "fulfillment" in reply;

  return {
    kind: fulfilled ? "fulfill" : "reject",
    code: "code" in reply ? reply.code : undefined,
    triggeredBy: "triggeredBy" in reply ? reply.triggeredBy : undefined,
    message: "message" in reply ? reply.message : undefined,
    fulfillment: fulfilled ? Buffer.from(reply.fulfillment).toString("hex") : undefined,
    stream,
  };
}

interface Scenario {
  readonly name: string;
  readonly amount: bigint;
  readonly packet: Partial<StreamPacket>;
  /** Reject code (or "fulfill") the receiver must answer without the application; absent when it must ask. */
  readonly final?: string;
  readonly options?: StreamCredentialOptions;
  /** Mutates the prepare after it was built correctly. */
  readonly tamper?: (prepare: IlpPrepare) => IlpPrepare;
}

const wrongCondition = (prepare: IlpPrepare): IlpPrepare => ({
  ...prepare,
  executionCondition: new Uint8Array(32).fill(9),
});

const money = (shares: bigint): StreamFrame => ({ type: "StreamMoney", streamId: 1n, shares });

const newAddress: StreamFrame = { type: "ConnectionNewAddress", sourceAccount: "test.sender" };

const scenarios: Scenario[] = [
  {
    name: "accepts an exact-minimum payment",
    amount: 100n,
    packet: { prepareAmount: 100n, frames: [newAddress, money(100n)] },
  },
  {
    name: "accepts more than the minimum",
    amount: 250n,
    packet: { prepareAmount: 100n, frames: [money(100n)] },
  },
  {
    name: "accepts the maximum uint64 amount",
    amount: (1n << 64n) - 1n,
    packet: { prepareAmount: 1n, frames: [money(1n)] },
  },
  {
    name: "fulfills a zero-amount packet without asking the application",
    final: "fulfill",
    amount: 0n,
    packet: { prepareAmount: 0n, frames: [] },
  },
  {
    name: "rejects below the minimum destination amount with F04",
    final: "F04",
    amount: 99n,
    packet: { prepareAmount: 100n, frames: [money(99n)] },
  },
  {
    name: "rejects a wrong execution condition with F05",
    final: "F05",
    amount: 10n,
    packet: { prepareAmount: 1n, frames: [money(10n)] },
    tamper: (prepare) => ({ ...prepare, executionCondition: new Uint8Array(32).fill(9) }),
  },
  {
    name: "closes on a ConnectionClose frame with F99",
    final: "F99",
    amount: 10n,
    packet: {
      prepareAmount: 1n,
      frames: [
        {
          type: "ConnectionClose",
          errorCode: StreamErrorCode.ApplicationError,
          errorMessage: "done",
        },
      ],
    },
  },
  {
    name: "answers a new address with asset details when the credentials carry them",
    amount: 10n,
    packet: { prepareAmount: 1n, frames: [newAddress, money(10n)] },
    options: { asset: { code: "EUR", scale: 4 } },
  },
  {
    name: "ignores unknown-asset credentials without a new address",
    amount: 10n,
    packet: { prepareAmount: 1n, frames: [money(10n)] },
    options: { asset: { code: "EUR", scale: 4 } },
  },
  {
    name: "rejects a STREAM packet that is not a Prepare with an empty-data F00",
    final: "F00",
    amount: 10n,
    packet: { ilpPacketType: IlpPacketType.Fulfill, prepareAmount: 1n, frames: [money(10n)] },
  },
  {
    name: "rejects data that does not decrypt with F06",
    final: "F06",
    amount: 10n,
    packet: { prepareAmount: 1n, frames: [money(10n)] },
    tamper: (prepare) => ({ ...prepare, data: prepare.data.map((byte, i) => (i === 40 ? byte ^ 1 : byte)) }),
  },
  {
    name: "rejects a destination outside the server address with F02",
    final: "F02",
    amount: 10n,
    packet: { prepareAmount: 1n, frames: [money(10n)] },
    tamper: (prepare) => ({ ...prepare, destination: "test.other.abc" }),
  },
  {
    name: "rejects a token that does not authenticate with F06",
    final: "F06",
    amount: 10n,
    packet: { prepareAmount: 1n, frames: [money(10n)] },
    tamper: (prepare) => ({
      ...prepare,
      destination: `${SERVER_ADDRESS}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`,
    }),
  },
  {
    name: "rejects a destination equal to the server address with F02",
    final: "F02",
    amount: 10n,
    packet: { prepareAmount: 1n, frames: [money(10n)] },
    tamper: (prepare) => ({ ...prepare, destination: SERVER_ADDRESS }),
  },
  // The order of the checks decides which reply a packet with several faults gets.
  {
    name: "answers ConnectionClose before it checks the condition (F99, not F05)",
    final: "F99",
    amount: 10n,
    packet: {
      prepareAmount: 1n,
      frames: [{ type: "ConnectionClose", errorCode: StreamErrorCode.NoError, errorMessage: "" }],
    },
    tamper: wrongCondition,
  },
  {
    name: "answers a packet that is not a Prepare with F00 before it looks at ConnectionClose",
    final: "F00",
    amount: 10n,
    packet: {
      ilpPacketType: IlpPacketType.Reject,
      prepareAmount: 1n,
      frames: [{ type: "ConnectionClose", errorCode: StreamErrorCode.NoError, errorMessage: "" }],
    },
  },
  {
    name: "checks the condition before a zero amount (F05, not a Fulfill)",
    final: "F05",
    amount: 0n,
    packet: { prepareAmount: 0n, frames: [] },
    tamper: wrongCondition,
  },
  {
    name: "fulfills a zero amount even below the minimum destination amount (no F04)",
    final: "fulfill",
    amount: 0n,
    packet: { prepareAmount: 100n, frames: [money(0n)] },
  },
  {
    name: "checks the condition before the minimum destination amount (F05, not F04)",
    final: "F05",
    amount: 5n,
    packet: { prepareAmount: 100n, frames: [money(5n)] },
    tamper: wrongCondition,
  },
  {
    name: "adds the asset details to an F05 reply to a new address",
    final: "F05",
    amount: 10n,
    packet: { prepareAmount: 1n, frames: [newAddress, money(10n)] },
    options: { asset: { code: "EUR", scale: 4 } },
    tamper: wrongCondition,
  },
  {
    name: "adds the asset details to an F04 reply to a new address",
    final: "F04",
    amount: 5n,
    packet: { prepareAmount: 100n, frames: [newAddress, money(5n)] },
    options: { asset: { code: "EUR", scale: 4 } },
  },
  {
    name: "answers a destination with trailing address segments like the bare credential",
    amount: 10n,
    packet: { prepareAmount: 1n, frames: [money(10n)] },
    tamper: (prepare) => ({ ...prepare, destination: `${prepare.destination}.extra.segments` }),
  },
];

async function prepareFor(scenario: Scenario): Promise<{ prepare: IlpPrepare; sharedSecret: Uint8Array }> {
  const credentials = await Effect.runPromise(generateStreamCredentials(config, scenario.options));

  const packet: StreamPacket = {
    sequence: 7n,
    ilpPacketType: IlpPacketType.Prepare,
    prepareAmount: 0n,
    frames: [],
    ...scenario.packet,
  };

  const request = await referenceRequest(credentials.sharedSecret, packet);

  const prepare: IlpPrepare = {
    amount: scenario.amount,
    expiresAt: EXPIRES,
    executionCondition: request.condition,
    destination: credentials.ilpAddress,
    data: request.data,
  };

  return { prepare: scenario.tamper ? scenario.tamper(prepare) : prepare, sharedSecret: credentials.sharedSecret };
}

const mineReply = (prepare: IlpPrepare): Promise<StreamReply> => Effect.runPromise(createStreamReply(config, prepare));

async function minePending(prepare: IlpPrepare): Promise<StreamPendingReply> {
  const reply = await mineReply(prepare);

  if (reply.type !== "pending") throw new Error("expected a pending reply");

  return reply;
}

function theirsPending(prepare: IlpPrepare): IncomingMoney {
  const reply = theirServer.createReply(referencePrepare(prepare));

  if (!("accept" in reply)) throw new Error("expected the reference to accept");

  return reply;
}

describe("createStreamReply decides like @interledger/stream-receiver's createReply", () => {
  it.each(scenarios.map((scenario) => [scenario.name, scenario] as const))("%s", async (_name, scenario) => {
    const { prepare, sharedSecret } = await prepareFor(scenario);
    const theirs = theirServer.createReply(referencePrepare(prepare));
    const mine = await mineReply(prepare);

    if ("accept" in theirs) {
      expect(scenario.final).toBeUndefined();

      if (mine.type !== "pending") throw new Error("expected a pending reply");

      expect(mine.connectionId).toBe(theirs.connectionId);
      expect(mine.paymentTag).toBe(theirs.paymentTag);
      expect(mine.dataFrames).toEqual([]);
      expect(await normalize(await Effect.runPromise(mine.accept()), sharedSecret)).toEqual(
        await normalize(theirs.accept(), sharedSecret),
      );
    } else {
      if (mine.type !== "final") throw new Error("expected a final reply");

      expect(isFulfill(mine.reply) ? "fulfill" : isReject(mine.reply) && mine.reply.code).toBe(scenario.final);
      expect(await normalize(mine.reply, sharedSecret)).toEqual(await normalize(theirs, sharedSecret));
    }
  });

  it("computes the replies of temporaryDecline and finalDecline like the reference", async () => {
    const { prepare, sharedSecret } = await prepareFor(scenarios[0]!);

    const cases: Array<
      [(p: StreamPendingReply) => Effect.Effect<IlpReply, unknown>, (t: IncomingMoney) => IlpPacket.IlpReply]
    > = [
      [(p) => p.temporaryDecline(), (t) => t.temporaryDecline()],
      [(p) => p.finalDecline(), (t) => t.finalDecline()],
      [(p) => p.finalDecline("no thanks"), (t) => t.finalDecline("no thanks")],
      [(p) => p.finalDecline(Uint8Array.of(1, 2, 3)), (t) => t.finalDecline(Buffer.from([1, 2, 3]))],
    ];

    for (const [mineOf, theirsOf] of cases) {
      const mine = await normalize(await Effect.runPromise(mineOf(await minePending(prepare))), sharedSecret);
      const theirs = await normalize(theirsOf(theirsPending(prepare)), sharedSecret);

      expect(mine).toEqual(theirs);
    }
  });

  it("passes StreamData frames and the payment tag through to the application", async () => {
    const options: StreamCredentialOptions = { paymentTag: "order-42" };
    const dataFrame: StreamFrame = { type: "StreamData", streamId: 1n, offset: 0n, data: Uint8Array.of(7, 8, 9) };

    const { prepare } = await prepareFor({
      name: "x",
      amount: 5n,
      options,
      packet: { prepareAmount: 1n, frames: [money(5n), dataFrame] },
    });

    const theirs = theirsPending(prepare);
    const mine = await minePending(prepare);

    expect(mine.paymentTag).toBe("order-42");
    expect(mine.paymentTag).toBe(theirs.paymentTag);
    expect(mine.dataFrames).toEqual([dataFrame]);
    expect(theirs.dataFrames?.map((f) => f.data.toString("hex"))).toEqual(["070809"]);
  });

  it("adds a verifiable StreamReceipt when the credentials carry a receipt setup", async () => {
    const nonce = bytes(16);
    const secret = bytes(32);

    const scenario: Scenario = {
      name: "receipt",
      amount: 40n,
      options: { receipt: { nonce, secret } },
      packet: { prepareAmount: 1n, frames: [money(40n)] },
    };

    const { prepare, sharedSecret } = await prepareFor(scenario);
    const theirs = theirsPending(prepare);
    theirs.setTotalReceived("40");

    const mine = await minePending(prepare);
    const mineReply = await normalize(await Effect.runPromise(mine.accept({ totalReceived: 40n })), sharedSecret);
    const theirsReply = await normalize(theirs.accept(), sharedSecret);
    const receiptFrame = mineReply.stream?.frames.find((frame) => frame.type === "StreamReceipt");

    expect(mineReply).toEqual(theirsReply);
    expect(receiptFrame).toBeDefined();

    const { verifyReceipt } = await import("ilp-protocol-stream/dist/src/util/receipt");

    const verified = verifyReceipt(
      Buffer.from(receiptFrame?.type === "StreamReceipt" ? receiptFrame.receipt : []),
      Buffer.from(secret),
    );

    expect(verified.totalReceived.toString()).toBe("40");
    expect(verified.nonce.equals(Buffer.from(nonce))).toBe(true);
  });

  it("omits the receipt when no total is supplied or the credentials carry no setup", async () => {
    const withSetup = await prepareFor({
      name: "r",
      amount: 40n,
      options: { receipt: { nonce: new Uint8Array(16), secret: new Uint8Array(32) } },
      packet: { prepareAmount: 1n, frames: [money(40n)] },
    });

    const withoutSetup = await prepareFor(scenarios[0]!);
    const a = await minePending(withSetup.prepare);
    const b = await minePending(withoutSetup.prepare);
    const noTotal = await normalize(await Effect.runPromise(a.accept()), withSetup.sharedSecret);

    const noSetup = await normalize(
      await Effect.runPromise(b.accept({ totalReceived: 5n })),
      withoutSetup.sharedSecret,
    );

    expect(noTotal.stream?.frames).toEqual([]);
    expect(noSetup.stream?.frames).toEqual([]);
  });

  it("fails with StreamError when the server config is invalid", async () => {
    const { prepare } = await prepareFor(scenarios[0]!);

    const short = await Effect.runPromise(
      Effect.result(createStreamReply({ ...config, serverSecret: new Uint8Array(31) }, prepare)),
    );

    const badAddress = await Effect.runPromise(
      Effect.result(createStreamReply({ ...config, serverAddress: "nope" }, prepare)),
    );

    expect(Result.isFailure(short) && short.failure.reason).toBe("invalid-key");
    expect(Result.isFailure(badAddress) && badAddress.failure.reason).toBe("invalid-address");
  });
});

describe("our sender against their receiver", () => {
  it("builds Prepares that @interledger/stream-receiver fulfills, with the amount it saw", async () => {
    const { ilpAddress, sharedSecret } = theirServer.generateCredentials();
    const additionalData = Uint8Array.of(1, 2, 3, 4);

    for (const [sequence, amount, data] of [
      [1n, 1000n, additionalData],
      [2n, 1n, undefined],
      [3n, (1n << 64n) - 1n, undefined],
    ] as const) {
      const prepare = await Effect.runPromise(
        buildStreamPrepare({
          destination: ilpAddress,
          sharedSecret: new Uint8Array(sharedSecret),
          amount,
          sequence,
          sourceAddress: "test.sender",
          expiresAt: EXPIRES,
          ...(data && { additionalData: data }),
        }),
      );

      const reply = theirsPending(prepare);

      expect(reply.dataFrames?.[0]?.data.equals(Buffer.from(data ?? []))).toBe(data ? true : undefined);

      const fulfill = reply.accept();
      const normalized = await normalize(fulfill, new Uint8Array(sharedSecret));

      expect(normalized.stream?.sequence).toBe(sequence);
      expect(normalized.stream?.prepareAmount).toBe(amount);
      expect(
        await Effect.runPromise(
          fulfillmentMatchesCondition(new Uint8Array(fulfill.fulfillment), prepare.executionCondition),
        ),
      ).toBe(true);
    }
  });

  it("puts ConnectionNewAddress, StreamMoney and StreamData in the packet exactly as the reference sender did", async () => {
    const { ilpAddress, sharedSecret } = theirServer.generateCredentials();

    const build = (sequence: bigint, additionalData?: Uint8Array) =>
      Effect.runPromise(
        buildStreamPrepare({
          destination: ilpAddress,
          sharedSecret: new Uint8Array(sharedSecret),
          amount: 55n,
          sequence,
          sourceAddress: "test.sender",
          expiresAt: EXPIRES,
          ...(additionalData && { additionalData }),
        }),
      );

    const { encryptionKey } = await Effect.runPromise(deriveStreamKeys(new Uint8Array(sharedSecret)));

    const frames = async (prepare: IlpPrepare) =>
      Result.getOrThrow(
        decodeStreamPacket(await Effect.runPromise(decryptStreamData(encryptionKey, prepare.data))),
      ).frames.map((f) => f.type);

    expect(await frames(await build(1n, Uint8Array.of(1)))).toEqual([
      "ConnectionNewAddress",
      "StreamMoney",
      "StreamData",
    ]);
    expect(await frames(await build(2n, Uint8Array.of(1)))).toEqual(["StreamMoney", "StreamData"]);
    expect(await frames(await build(2n, new Uint8Array(0)))).toEqual(["StreamMoney"]);
  });

  it("refuses unencodable inputs with a tagged failure", async () => {
    const { ilpAddress, sharedSecret } = theirServer.generateCredentials();

    const base = {
      destination: ilpAddress,
      sharedSecret: new Uint8Array(sharedSecret),
      amount: 1n,
      sequence: 1n,
      sourceAddress: "test.sender",
      expiresAt: EXPIRES,
    };

    const failures = await Promise.all(
      [
        { ...base, sharedSecret: new Uint8Array(0) },
        { ...base, amount: 1n << 64n },
        { ...base, sourceAddress: "bad address" },
        { ...base, sequence: -1n },
      ].map((options) => Effect.runPromise(Effect.result(buildStreamPrepare(options)))),
    );

    expect(failures.every(Result.isFailure)).toBe(true);
    expect(failures.map((f) => (Result.isFailure(f) ? [f.failure._tag, f.failure.reason] : []))).toEqual([
      ["StreamError", "invalid-key"],
      ["IlpCodecError", "out-of-range"],
      ["IlpCodecError", "invalid-address"],
      ["IlpCodecError", "out-of-range"],
    ]);
  });
});

describe("asset details are announced literally", () => {
  const issuers = {
    ours: (asset: { code: string; scale: number }) => Effect.runPromise(generateStreamCredentials(config, { asset })),
    theirs: async (asset: { code: string; scale: number }) => {
      const { ilpAddress, sharedSecret } = theirServer.generateCredentials({ asset });

      return { ilpAddress, sharedSecret: new Uint8Array(sharedSecret) };
    },
  };

  const build = (credentials: { ilpAddress: string; sharedSecret: Uint8Array }, sequence: bigint) =>
    Effect.runPromise(
      buildStreamPrepare({
        destination: credentials.ilpAddress,
        sharedSecret: credentials.sharedSecret,
        amount: 10n,
        sequence,
        expiresAt: EXPIRES,
      }),
    );

  // Each side reads the other's token, so comparing them to each other would agree on a wrong value; the expected
  // frame is written out here instead.
  it.each([
    ["ours", { code: "EUR", scale: 4 }],
    ["theirs", { code: "EUR", scale: 4 }],
    ["ours", { code: "JPY", scale: 0 }],
    ["theirs", { code: "BTC", scale: 255 }],
    ["ours", { code: "€UR", scale: 2 }],
  ] as const)("a token issued by %s for %j gets exactly that frame back on the first packet", async (issuer, asset) => {
    const credentials = await issuers[issuer](asset);
    const prepare = await build(credentials, 1n);
    const expected: StreamFrame = {
      type: "ConnectionAssetDetails",
      sourceAssetCode: asset.code,
      sourceAssetScale: asset.scale,
    };

    const mine = await minePending(prepare);
    const mineReply = await normalize(await Effect.runPromise(mine.accept()), credentials.sharedSecret);
    const theirsReply = await normalize(theirsPending(prepare).accept(), credentials.sharedSecret);

    expect(mineReply.stream?.frames).toEqual([expected]);
    expect(theirsReply.stream?.frames).toEqual([expected]);
  });

  it("sends no asset details after the first packet, or when the credentials carry none", async () => {
    const withAsset = await issuers.ours({ code: "EUR", scale: 4 });
    const later = await minePending(await build(withAsset, 2n));

    expect((await normalize(await Effect.runPromise(later.accept()), withAsset.sharedSecret)).stream?.frames).toEqual(
      [],
    );

    const bare = await Effect.runPromise(generateStreamCredentials(config));
    const first = await minePending(await build(bare, 1n));

    expect((await normalize(await Effect.runPromise(first.accept()), bare.sharedSecret)).stream?.frames).toEqual([]);
  });
});

describe("one connection, many destinations", () => {
  const TOKEN_CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

  it("answers token spellings that differ only in unused trailing bits, each with its own connectionId", async () => {
    const { ilpAddress, sharedSecret } = await Effect.runPromise(
      generateStreamCredentials(config, { paymentTag: "order-1" }),
    );

    const prepare = await Effect.runPromise(
      buildStreamPrepare({ destination: ilpAddress, sharedSecret, amount: 10n, sequence: 1n, expiresAt: EXPIRES }),
    );

    // This 37-byte token (IV, tag, flags, tag length and 7 tag bytes) is 50 base64url characters carrying 296 of
    // 300 bits: the last four bits are free, so 16 spellings decode to the same bytes.
    const token = ilpAddress.slice(SERVER_ADDRESS.length + 1);
    const lastIndex = TOKEN_CHARACTERS.indexOf(token.slice(-1));
    const sibling = TOKEN_CHARACTERS[(lastIndex & ~15) | ((lastIndex + 1) & 15)]!;
    const respelled = `${ilpAddress.slice(0, -1)}${sibling}`;

    expect(token).toHaveLength(50);
    expect(respelled).not.toBe(ilpAddress);

    const original = await minePending(prepare);
    const other = await minePending({ ...prepare, destination: respelled });
    const theirs = theirsPending({ ...prepare, destination: respelled });

    expect(other.paymentTag).toBe("order-1");
    expect(other.connectionId).not.toBe(original.connectionId);
    expect(other.connectionId).toBe(theirs.connectionId);
  });

  it("hashes the whole destination, so trailing segments change the connectionId too", async () => {
    const { ilpAddress, sharedSecret } = await Effect.runPromise(generateStreamCredentials(config));

    const prepare = await Effect.runPromise(
      buildStreamPrepare({ destination: ilpAddress, sharedSecret, amount: 10n, sequence: 1n, expiresAt: EXPIRES }),
    );

    const bare = await minePending(prepare);
    const extended = await minePending({ ...prepare, destination: `${ilpAddress}.more` });

    expect(bare.connectionId).toBe(createHash("sha256").update(ilpAddress).digest("hex"));
    expect(extended.connectionId).toBe(createHash("sha256").update(`${ilpAddress}.more`).digest("hex"));
  });
});

describe("finalDecline and the Prepare amount are validated", () => {
  const pendingReply = async (): Promise<StreamPendingReply> => minePending((await prepareFor(scenarios[0]!)).prepare);

  const outcome = async (effect: Effect.Effect<IlpReply, StreamError>) => {
    const result = await Effect.runPromise(Effect.result(effect));

    return Result.isFailure(result) ? result.failure : result.success;
  };

  it("fails with invalid-option for application data that cannot fit in a Reject, as bytes or as a string", async () => {
    const pending = await pendingReply();

    for (const data of [new Uint8Array(40_000), "x".repeat(40_000), "é".repeat(20_000)]) {
      const failed = await outcome(pending.finalDecline(data));

      expect(failed).toBeInstanceOf(StreamError);
      expect(failed).toMatchObject({ reason: "invalid-option" });
    }
  });

  it("finds the exact limit: the largest data that fits serializes, one byte more fails", async () => {
    const pending = await pendingReply();
    let low = 0;
    let high = 33_000;

    // Smallest size that fails.
    while (low < high) {
      const middle = Math.floor((low + high) / 2);

      if ((await outcome(pending.finalDecline(new Uint8Array(middle)))) instanceof StreamError) high = middle;
      else low = middle + 1;
    }

    const fits = await outcome(pending.finalDecline(new Uint8Array(low - 1)));

    expect(low).toBeGreaterThan(32_000);
    expect(fits).not.toBeInstanceOf(StreamError);
    expect(Result.isSuccess(serializeReject(fits as IlpReject))).toBe(true);
    expect((fits as IlpReject).data.length).toBe(MAX_ILP_DATA_LENGTH);
    expect(await outcome(pending.finalDecline(new Uint8Array(low)))).toBeInstanceOf(StreamError);
  });

  it("fails with invalid-option instead of dying when the Prepare amount is outside uint64", async () => {
    const { prepare } = await prepareFor(scenarios[0]!);

    for (const amount of [1n << 64n, -1n]) {
      const result = await Effect.runPromise(Effect.result(createStreamReply(config, { ...prepare, amount })));

      expect(Result.isFailure(result) && result.failure).toMatchObject({
        _tag: "StreamError",
        reason: "invalid-option",
      });
    }
  });
});
