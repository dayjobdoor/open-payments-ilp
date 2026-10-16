import { describe, expect, it } from "vite-plus/test";
import { gnapErrorBody } from "../../src/gnap/index";

describe("gnapErrorBody", () => {
  it("nests the code and description the way auth-server.yaml does", () => {
    expect(gnapErrorBody("invalid_client", "bad key")).toEqual({
      error: { code: "invalid_client", description: "bad key" },
    });
  });

  it("accepts codes outside the GNAP registry", () => {
    expect(gnapErrorBody("not_found", "tenant not found").error.code).toBe("not_found");
  });
});
