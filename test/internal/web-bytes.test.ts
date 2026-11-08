import { describe, expect, it } from "vite-plus/test";
import { owned } from "../../src/internal/web-bytes";

describe("owned", () => {
  it("returns an ArrayBuffer-backed array itself, view included", () => {
    const bytes = Uint8Array.of(1, 2, 3);
    const view = bytes.subarray(1);

    expect(owned(bytes)).toBe(bytes);
    expect(owned(view)).toBe(view);
  });

  it("copies an array backed by a SharedArrayBuffer into an ArrayBuffer-backed one", () => {
    const shared = new Uint8Array(new SharedArrayBuffer(4));
    shared.set([9, 8, 7, 6]);
    const copy = owned(shared.subarray(1, 3));

    expect(copy).toEqual(Uint8Array.of(8, 7));
    expect(copy.buffer).toBeInstanceOf(ArrayBuffer);

    shared[1] = 0;

    expect(copy[0]).toBe(8);
  });
});
