import { describe, expect, it } from "vite-plus/test";
import * as effect from "../../src/ildcp";
import { IlpCodecError } from "../../src/ilp";
import * as plain from "../../src/plain/ildcp";

describe("/plain/ildcp mirrors /ildcp", () => {
  it("exports every name of /ildcp, plus the codec error it throws", () => {
    const names = (module: object): string[] => Object.keys(module).sort();

    expect(names(plain).filter((name) => !(name in effect))).toEqual(["IlpCodecError"]);
    expect(names(effect).filter((name) => !(name in plain))).toEqual([]);
    expect(plain.IlpCodecError).toBe(IlpCodecError);
  });

  it("re-exports the constant and the (non-Effect) server function themselves", () => {
    expect(plain.ILDCP_DESTINATION).toBe(effect.ILDCP_DESTINATION);
    expect(plain.serveIldcp).toBe(effect.serveIldcp);
  });
});
