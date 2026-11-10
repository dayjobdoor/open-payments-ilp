import { describe, expect, it } from "vite-plus/test";
import { gnapErrorBody, type GnapErrorCode } from "../../src/gnap/index";

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

describe("GnapErrorCode", () => {
  // The "GNAP Error Codes" registry of RFC 9635 §10.15.2 and the "GNAP RS-Facing Error Codes" of RFC 9767 §5.9.
  // Typed, so a code dropped from the union stops the type check of this file.
  const registry: ReadonlyArray<GnapErrorCode> = [
    "invalid_request",
    "invalid_client",
    "invalid_interaction",
    "invalid_flag",
    "invalid_rotation",
    "key_rotation_not_supported",
    "invalid_continuation",
    "user_denied",
    "request_denied",
    "unknown_user",
    "unknown_interaction",
    "too_fast",
    "too_many_attempts",
    "invalid_resource_server",
    "invalid_access",
  ];

  it.each(registry)("builds a body for %s", (code) => {
    expect(gnapErrorBody(code, "d")).toEqual({ error: { code, description: "d" } });
  });
});
