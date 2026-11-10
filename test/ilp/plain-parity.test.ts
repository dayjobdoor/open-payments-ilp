import { describe, expect, it } from "vite-plus/test";
import * as effect from "../../src/ilp";
import * as plain from "../../src/plain/ilp";

/** The runtime export names of `module` that `other` lacks. */
const missingFrom = (module: object, other: object): string[] =>
  Object.keys(module)
    .filter((name) => !(name in other))
    .sort();

describe("/plain/ilp mirrors /ilp", () => {
  it("lacks only the OER primitives, which README documents as staying Result-based", () => {
    expect(missingFrom(effect, plain)).toEqual(["OerReader", "OerWriter", "readOer", "writeOer"]);
  });

  it("adds only the ilp-packet spellings of the packet codecs, and each is its codec", () => {
    expect(missingFrom(plain, effect)).toEqual([
      "deserializeIlpFulfill",
      "deserializeIlpPacket",
      "deserializeIlpPrepare",
      "deserializeIlpReject",
      "deserializeIlpReply",
      "serializeIlpFulfill",
      "serializeIlpPrepare",
      "serializeIlpReject",
      "serializeIlpReply",
    ]);

    expect(plain.serializeIlpPrepare).toBe(plain.serializePrepare);
    expect(plain.deserializeIlpPrepare).toBe(plain.deserializePrepare);
    expect(plain.serializeIlpFulfill).toBe(plain.serializeFulfill);
    expect(plain.deserializeIlpFulfill).toBe(plain.deserializeFulfill);
    expect(plain.serializeIlpReject).toBe(plain.serializeReject);
    expect(plain.deserializeIlpReject).toBe(plain.deserializeReject);
    expect(plain.serializeIlpReply).toBe(plain.serializeReply);
    expect(plain.deserializeIlpReply).toBe(plain.deserializeReply);
    expect(plain.deserializeIlpPacket).toBe(plain.deserializePacket);
  });

  it("re-exports the values and error classes themselves, so `instanceof` works across both entries", () => {
    expect(plain.IlpCodecError).toBe(effect.IlpCodecError);
    expect(plain.IlpHttpError).toBe(effect.IlpHttpError);
    expect(plain.IlpErrorCode).toBe(effect.IlpErrorCode);
    expect(plain.IlpPacketType).toBe(effect.IlpPacketType);
    expect(plain.isValidIlpAddress).toBe(effect.isValidIlpAddress);
    expect(plain.MAX_ILP_DATA_LENGTH).toBe(effect.MAX_ILP_DATA_LENGTH);
    expect(plain.DEFAULT_ILP_HTTP_TIMEOUT_MS).toBe(effect.DEFAULT_ILP_HTTP_TIMEOUT_MS);
    expect(plain.DEFAULT_ILP_HTTP_MAX_REPLY_BYTES).toBe(effect.DEFAULT_ILP_HTTP_MAX_REPLY_BYTES);
  });
});
