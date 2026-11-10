// oxlint-disable anti-slop/no-unknown-parameters, anti-slop/no-unsafe-dictionary-type, anti-slop/no-known-value-widening -- Tests send arbitrary, including malformed, request bodies by design.
/** What the server does with the `interact` of a grant request, and what it shows the policy of it. */
import { describe, expect, it } from "vite-plus/test";
import type { GnapGrantRequest } from "../../src/gnap/server/index";
import {
  amount,
  createServerHarness,
  errorOf,
  FINISH_URI,
  grantBody,
  incoming,
  interact,
  json,
  jsonBody,
  outgoing,
  withToken,
} from "./support";

const policyHarness = async () => {
  const seen: GnapGrantRequest[] = [];

  const h = await createServerHarness({
    policy: {
      requiresInteraction: (request) => {
        seen.push(request);

        return false;
      },
    },
    unvalidated: true,
  });

  return { h, seen };
};

describe("the request shown to policy.requiresInteraction", () => {
  const finish = { method: "redirect", uri: FINISH_URI, nonce: "client-nonce" };

  it("carries the interact the server acts on, and none for a client that does not offer a redirect", async () => {
    const { h, seen } = await policyHarness();

    for (const offered of [
      { start: ["app"], finish: { ...finish, uri: "javascript:alert(1)" } },
      { start: ["app"] },
      { start: [], finish },
    ]) {
      expect((await h.signedCall(h.baseUrl, json("POST", grantBody([incoming], { interact: offered })))).status).toBe(
        200,
      );
    }

    expect(seen.map((request) => request.interact)).toEqual([undefined, undefined, undefined]);
  });

  it("carries the redirect start and the finish of a client that offers both, and only the redirect of several starts", async () => {
    const { h, seen } = await policyHarness();

    await h.signedCall(h.baseUrl, json("POST", grantBody([incoming], { interact: { start: ["redirect"], finish } })));
    await h.signedCall(h.baseUrl, json("POST", grantBody([incoming], { interact: { start: ["app", "redirect"] } })));

    expect(seen.map((request) => request.interact)).toEqual([{ start: ["redirect"], finish }, { start: ["redirect"] }]);
  });

  it("is the same for a modification", async () => {
    const { h, seen } = await policyHarness();

    const granted = await jsonBody<{ continue: { uri: string; access_token: { value: string } } }>(
      await h.signedCall(h.baseUrl, json("POST", grantBody([incoming]))),
    );

    const modified = await h.signedCall(
      granted.continue.uri,
      withToken(
        json("PATCH", {
          access_token: { access: [{ type: "quote", actions: ["create"] }] },
          interact: { start: ["app"], finish: { ...finish, uri: "javascript:alert(1)" } },
        }),
        granted.continue.access_token.value,
      ),
    );

    expect(modified.status).toBe(200);
    expect(seen.map((request) => request.interact)).toEqual([undefined, undefined]);
  });
});

describe("a policy.requiresInteraction that does not answer with a boolean", () => {
  // SAFETY: a JavaScript caller (or a function that forgot its `return`) answers with what the types forbid.
  const notABoolean = (answer: () => unknown) => answer as () => boolean;

  it.each([
    ["undefined", () => undefined],
    ["null", () => null],
    ["a Promise of false", async () => false],
  ])("needs the owner's consent when it answers %s", async (_name, answer) => {
    const h = await createServerHarness({ policy: { requiresInteraction: notABoolean(answer) }, unvalidated: true });

    // The request alone would be granted at once (plain incoming-payment access).
    const bare = await h.signedCall(h.baseUrl, json("POST", grantBody([incoming])));

    expect(await errorOf(bare)).toMatchObject({
      status: 400,
      code: "invalid_request",
      description: "missing required request field 'interact'",
    });

    const asked = await h.signedCall(h.baseUrl, json("POST", grantBody([incoming], { interact })));

    expect(await jsonBody(asked)).toHaveProperty("interact.redirect");
  });

  it("lets a policy that answers false grant at once", async () => {
    const { h } = await policyHarness();

    const response = await h.signedCall(h.baseUrl, json("POST", grantBody([outgoing], { interact })));

    expect(await jsonBody(response)).toHaveProperty("access_token.value");
  });
});

describe("interact.finish.uri", () => {
  it.each(["redirect", "push"])("is refused with a bare # as a fragment (%s)", async (method) => {
    const h = await createServerHarness({ unvalidated: true });

    const response = await h.signedCall(
      h.baseUrl,
      json(
        "POST",
        grantBody([outgoing], { interact: { ...interact, finish: { method, uri: `${FINISH_URI}#`, nonce: "n" } } }),
      ),
    );

    expect(await errorOf(response)).toMatchObject({
      status: 400,
      code: "invalid_request",
      description: "invalid interact.finish",
    });
  });
});

describe("limits.receiver of an outgoing payment access item", () => {
  const request = async (limits: object) => {
    const h = await createServerHarness({ unvalidated: true });
    const item = { ...outgoing, limits: { debitAmount: amount, ...limits } };

    return errorOf(await h.signedCall(h.baseUrl, json("POST", grantBody([item], { interact }))));
  };

  it.each([
    ["is not a URL", "nope"],
    ["is not an incoming payment URL", "https://wallet.test/alice"],
    ["is not http(s)", "ftp://wallet.test/incoming-payments/1"],
    ["is empty", ""],
  ])("refuses a receiver that %s, as Rafiki's OpenAPI validation does", async (_name, receiver) => {
    expect(await request({ receiver })).toMatchObject({ status: 400, code: "invalid_request" });
  });

  it("accepts an incoming payment URL, and any interval string (the spec has no pattern for it)", async () => {
    expect(
      (await request({ receiver: "https://wallet.test/incoming-payments/1", interval: "R/2026-01-01T00:00:00Z/P1M" }))
        .status,
    ).toBe(200);
    expect((await request({ interval: "garbage" })).status).toBe(200);
  });
});
