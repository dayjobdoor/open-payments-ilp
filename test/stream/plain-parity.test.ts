import { describe, expect, expectTypeOf, it } from "vite-plus/test";
import * as effect from "../../src/stream";
import * as plain from "../../src/plain/stream";

describe("/plain/stream mirrors /stream", () => {
  it("exports exactly the names of /stream", () => {
    const names = (module: object): string[] => Object.keys(module).sort();

    expect(names(plain)).toEqual(names(effect));
  });

  it("re-exports the values, constants and error class themselves", () => {
    expect(plain.StreamError).toBe(effect.StreamError);
    expect(plain.StreamErrorCode).toBe(effect.StreamErrorCode);
    expect(plain.StreamFrameType).toBe(effect.StreamFrameType);
    expect(plain.STREAM_ENCRYPTION_OVERHEAD).toBe(effect.STREAM_ENCRYPTION_OVERHEAD);
    expect(plain.planStreamChunks).toBe(effect.planStreamChunks);
  });

  it("exports the same types, including the options of decryptStreamPacket", () => {
    expectTypeOf<plain.DecryptStreamPacketOptions>().toEqualTypeOf<effect.DecryptStreamPacketOptions>();
    expectTypeOf<plain.ExpectedStreamPacket>().toEqualTypeOf<effect.ExpectedStreamPacket>();
    expectTypeOf<plain.StreamPacket>().toEqualTypeOf<effect.StreamPacket>();
    expectTypeOf<plain.StreamReceipt>().toEqualTypeOf<effect.StreamReceipt>();
    expectTypeOf<plain.StreamFrame>().toEqualTypeOf<effect.StreamFrame>();
    expectTypeOf<plain.StreamCredentials>().toEqualTypeOf<effect.StreamCredentials>();
    expectTypeOf<plain.BuildStreamPrepareOptions>().toEqualTypeOf<effect.BuildStreamPrepareOptions>();

    // Control: the comparison fails for types that differ.
    expectTypeOf<plain.StreamPacket>().not.toEqualTypeOf<plain.StreamReceipt>();

    // The third argument of `decryptStreamPacket` is the very options type that is exported.
    expectTypeOf<Parameters<typeof plain.decryptStreamPacket>[2]>().toEqualTypeOf<
      plain.DecryptStreamPacketOptions | undefined
    >();
  });
});
