import { describe, expect, it } from "vite-plus/test";
import * as effect from "../../src/http-signatures";
import * as plain from "../../src/plain/http-signatures";

describe("/plain/http-signatures mirrors /http-signatures", () => {
  it("exports every name of /http-signatures, plus importPrivateKey, which README documents", () => {
    const names = (module: object): string[] => Object.keys(module).sort();

    expect(names(plain).filter((name) => !(name in effect))).toEqual(["importPrivateKey"]);
    expect(names(effect).filter((name) => !(name in plain))).toEqual([]);
  });

  it("re-exports the error class and the replay window themselves", () => {
    expect(plain.HttpSignatureError).toBe(effect.HttpSignatureError);
    expect(plain.SIGNATURE_REPLAY_WINDOW_SECONDS).toBe(effect.SIGNATURE_REPLAY_WINDOW_SECONDS);
  });
});
