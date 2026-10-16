import { describe, expect, it } from "vite-plus/test";
import { expectConformsToSpec } from "./openapi";

describe("OpenAPI response check (the harness is not vacuous)", () => {
  const request = new Request("https://as.test/gnap/continue/x", { method: "POST" });

  it("accepts a documented success response", async () => {
    const body = { continue: { access_token: { value: "v" }, uri: "https://as.test/gnap/continue/x" } };

    await expectConformsToSpec(request, "/continue/x", Response.json(body));
  });

  it("rejects a body that violates the schema", async () => {
    await expect(expectConformsToSpec(request, "/continue/x", Response.json({ continue: { uri: 5 } }))).rejects.toThrow(
      /violates \/continue\/\{id\}/,
    );
  });

  it("rejects an error code the document does not list", async () => {
    await expect(
      expectConformsToSpec(
        request,
        "/continue/x",
        Response.json({ error: { code: "bogus", description: "x" } }, { status: 401 }),
      ),
    ).rejects.toThrow(/violates/);
  });

  it("rejects an undocumented status", async () => {
    await expect(expectConformsToSpec(request, "/continue/x", new Response(null, { status: 418 }))).rejects.toThrow();
  });
});
