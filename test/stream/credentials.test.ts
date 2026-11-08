import * as Effect from "effect/Effect";
import * as Result from "effect/Result";
import { describe, expect, it } from "vite-plus/test";
import { isValidIlpAddress } from "../../src/ilp";
import {
  buildStreamPrepare,
  decodeStreamPaymentTag,
  generateStreamCredentials,
  type StreamCredentialOptions,
} from "../../src/stream";
import { decodeBase64Url } from "../../src/internal/bytes";
import { byteSource } from "../support/prng";
import { referencePrepare, StreamServer } from "../support/stream-oracle";

const bytes = byteSource(0xc4ed);

const serverSecret = bytes(32);

const serverAddress = "test.receiver";

const config = { serverSecret, serverAddress };

const run = (options?: StreamCredentialOptions) => Effect.runPromise(generateStreamCredentials(config, options));

const reason = async (cfg: typeof config, options?: StreamCredentialOptions) => {
  const result = await Effect.runPromise(Effect.result(generateStreamCredentials(cfg, options)));

  return Result.isFailure(result) ? result.failure.reason : "ok";
};

const theirServer = new StreamServer({ serverSecret: Buffer.from(serverSecret), serverAddress });

describe("SPSP credentials", () => {
  it("issues a valid ILP address under the server address and a 32-byte shared secret", async () => {
    const { ilpAddress, sharedSecret } = await run();

    expect(ilpAddress.startsWith(`${serverAddress}.`)).toBe(true);
    expect(isValidIlpAddress(ilpAddress)).toBe(true);
    expect(sharedSecret).toHaveLength(32);
  });

  it("issues a token of IV + tag + 1 flag byte (29 bytes) without options, like stream-receiver", async () => {
    const mine = await run();
    const theirs = theirServer.generateCredentials();

    expect(decodeBase64Url(mine.ilpAddress.slice(serverAddress.length + 1))).toHaveLength(29);
    expect(decodeBase64Url(theirs.ilpAddress.slice(serverAddress.length + 1))).toHaveLength(29);
    expect(mine.ilpAddress.length).toBe(theirs.ilpAddress.length);
  });

  it("is non-deterministic: every call uses a fresh IV", async () => {
    expect((await run()).ilpAddress).not.toBe((await run()).ilpAddress);
  });

  it("derives a shared secret that stream-receiver's server accepts for its payment tag decoding", async () => {
    const { ilpAddress } = await run({ paymentTag: "invoice-7" });

    expect(theirServer.decodePaymentTag(ilpAddress)).toBe("invoice-7");
    expect(theirServer.decodePaymentTag((await run()).ilpAddress)).toBeUndefined();
  });

  it("issues credentials whose token stream-receiver decrypts, with every option combination", async () => {
    const receipt = { nonce: bytes(16), secret: bytes(32) };
    const asset = { code: "JPY", scale: 0 };

    for (const options of [{}, { paymentTag: "a" }, { receipt }, { asset }, { paymentTag: "tag", receipt, asset }]) {
      const { ilpAddress } = await run(options);

      expect(theirServer.decodePaymentTag(ilpAddress)).toBe("paymentTag" in options ? options.paymentTag : undefined);
    }
  });

  // `decodePaymentTag` is also `undefined` for a token that does not authenticate, so on its own it cannot tell
  // a good token without a tag from garbage. A packet through the reference receiver can: F06 means garbage.
  it("issues tokens the reference receiver authenticates, and refuses the same token with one character changed", async () => {
    const receipt = { nonce: bytes(16), secret: bytes(32) };
    const asset = { code: "JPY", scale: 0 };

    for (const options of [{}, { paymentTag: "a" }, { receipt }, { asset }, { paymentTag: "tag", receipt, asset }]) {
      const { ilpAddress, sharedSecret } = await run(options);

      const prepare = await Effect.runPromise(
        buildStreamPrepare({
          destination: ilpAddress,
          sharedSecret,
          amount: 5n,
          sequence: 2n,
          expiresAt: new Date(Date.UTC(2099, 0, 1)),
        }),
      );

      expect("accept" in theirServer.createReply(referencePrepare(prepare))).toBe(true);

      const middle = serverAddress.length + 1 + 10;
      const changed = ilpAddress[middle] === "A" ? "B" : "A";
      const garbage = `${ilpAddress.slice(0, middle)}${changed}${ilpAddress.slice(middle + 1)}`;

      expect(theirServer.createReply(referencePrepare({ ...prepare, destination: garbage }))).toMatchObject({
        code: "F06",
      });

      expect(await Effect.runPromise(decodeStreamPaymentTag(config, garbage))).toBeUndefined();
    }
  });

  it("matches stream-receiver's shared secret derivation for the same token", async () => {
    const theirs = theirServer.generateCredentials();
    const { createHmac } = await import("node:crypto");
    const token = Buffer.from(theirs.ilpAddress.slice(serverAddress.length + 1), "base64url");
    const keyGen = createHmac("sha256", serverSecret).update("ilp_stream_shared_secret").digest();

    expect(createHmac("sha256", keyGen).update(token).digest().equals(theirs.sharedSecret)).toBe(true);
  });

  it("fails with StreamError for a wrong-size server secret", async () => {
    expect(await reason({ ...config, serverSecret: new Uint8Array(31) })).toBe("invalid-key");
    expect(await reason({ ...config, serverSecret: new Uint8Array(33) })).toBe("invalid-key");
    expect(() => new StreamServer({ serverSecret: Buffer.alloc(33), serverAddress })).toThrow();
  });

  it("fails with StreamError for an invalid server address", async () => {
    expect(await reason({ ...config, serverAddress: "" })).toBe("invalid-address");
    expect(await reason({ ...config, serverAddress: "not an address" })).toBe("invalid-address");
  });

  it("fails with StreamError for malformed options", async () => {
    expect(await reason(config, { receipt: { nonce: new Uint8Array(15), secret: new Uint8Array(32) } })).toBe(
      "invalid-option",
    );
    expect(await reason(config, { receipt: { nonce: new Uint8Array(16), secret: new Uint8Array(31) } })).toBe(
      "invalid-option",
    );
    expect(await reason(config, { asset: { code: "USD", scale: 256 } })).toBe("invalid-option");
    expect(await reason(config, { paymentTag: "é" })).toBe("invalid-option");
  });

  it("fails when the token would not fit in an ILP address", async () => {
    expect(await reason({ ...config, serverAddress: `test.${"a".repeat(990)}` }, { paymentTag: "x".repeat(60) })).toBe(
      "invalid-address",
    );
  });

  // The limit is 1023 characters (RFC 15). The check predicts the token's length before encrypting, so it must be
  // exact: one address character too many fails, and the longest that passes really is 1023 characters long.
  it.each(["", "a", "ab", "abc", "abcd", "x".repeat(40)])(
    "accepts a server address up to exactly 1023 characters with the tag %j, and refuses one more",
    async (paymentTag) => {
      const options = paymentTag === "" ? {} : { paymentTag };
      const sample = await run(options);
      const tokenLength = sample.ilpAddress.length - serverAddress.length - 1;
      const longest = 1023 - 1 - tokenLength;
      const base = (length: number) => `test.${"a".repeat(length - "test.".length)}`;

      const fits = await Effect.runPromise(
        generateStreamCredentials({ ...config, serverAddress: base(longest) }, options),
      );

      expect(fits.ilpAddress).toHaveLength(1023);
      expect(isValidIlpAddress(fits.ilpAddress)).toBe(true);
      expect(await reason({ ...config, serverAddress: base(longest + 1) }, options)).toBe("invalid-address");
    },
  );
});

describe("their credentials against our receiver", () => {
  it("are recognised: a packet built with their shared secret is accepted by createStreamReply", async () => {
    const { buildStreamPrepare, createStreamReply } = await import("../../src/stream");
    const theirs = theirServer.generateCredentials();

    const prepare = await Effect.runPromise(
      buildStreamPrepare({
        destination: theirs.ilpAddress,
        sharedSecret: new Uint8Array(theirs.sharedSecret),
        amount: 321n,
        sequence: 1n,
        sourceAddress: "test.sender",
        expiresAt: new Date(Date.UTC(2099, 0, 1)),
      }),
    );

    const reply = await Effect.runPromise(createStreamReply(config, prepare));

    expect(reply.type).toBe("pending");
  });
});

describe("decodeStreamPaymentTag matches stream-receiver's decodePaymentTag", () => {
  const mine = (destination: string, cfg = config) => Effect.runPromise(decodeStreamPaymentTag(cfg, destination));

  it("returns the tag of our credentials and of theirs", async () => {
    const ours = await run({ paymentTag: "incoming-payment-1" });
    const theirs = theirServer.generateCredentials({ paymentTag: "incoming-payment-2" });

    expect(await mine(ours.ilpAddress)).toBe("incoming-payment-1");
    expect(await mine(theirs.ilpAddress)).toBe("incoming-payment-2");
  });

  it("returns undefined where the reference does: no tag, foreign address, bad token, trailing segments", async () => {
    const untagged = await run();
    const tagged = await run({ paymentTag: "tag" });

    const destinations = [
      untagged.ilpAddress,
      "test.other.abc",
      serverAddress,
      `${serverAddress}.`,
      `${serverAddress}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`,
      `${serverAddress}.!!!`,
    ];

    for (const destination of destinations) {
      expect(await mine(destination), destination).toBeUndefined();
      expect(theirServer.decodePaymentTag(destination), destination).toBeUndefined();
    }

    // A connection's destination may be extended with further segments; the token is the first one.
    expect(await mine(`${tagged.ilpAddress}.extra.segments`)).toBe("tag");
    expect(theirServer.decodePaymentTag(`${tagged.ilpAddress}.extra.segments`)).toBe("tag");
  });

  it("does not decode tokens issued under another server secret", async () => {
    const other = { serverSecret: bytes(32), serverAddress };
    const foreign = await Effect.runPromise(generateStreamCredentials(other, { paymentTag: "tag" }));

    expect(await mine(foreign.ilpAddress)).toBeUndefined();
  });

  it("fails with StreamError for an invalid server config", async () => {
    const result = await Effect.runPromise(
      Effect.result(decodeStreamPaymentTag({ serverSecret: new Uint8Array(8), serverAddress }, "test.receiver.x")),
    );

    expect(Result.isFailure(result) && result.failure.reason).toBe("invalid-key");
  });
});
