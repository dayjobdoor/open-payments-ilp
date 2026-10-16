/** RFC 9635 / RFC 9767 requirements of the authorisation server that Open Payments clients never exercise. */
import * as Effect from "effect/Effect";
import { describe, expect, it } from "vite-plus/test";
import { computeInteractionHash, verifyInteractionHash } from "../../src/gnap/index";
import type { GrantRecord } from "../../src/gnap/server/index";
import type { SigningKey } from "../../src/http-signatures";
import { createContentDigest } from "../../src/http-signatures/digest";
import { createSignatureBase, serializeSignatureParams } from "../../src/http-signatures/signature-base";
import { encodeBase64, utf8Encode } from "../../src/internal/bytes";
import {
  BASE_URL,
  CONSENT_URL,
  SEED,
  approve,
  browserFinish,
  browserStart,
  continueWith,
  createClientKey,
  createServerHarness,
  errorOf,
  grantBody,
  incoming,
  interact,
  json,
  jsonBody,
  outgoing,
  seedGrant,
  seedToken,
  startGrant,
  walletFetch,
  withToken,
  type HarnessOptions,
  type ServerHarness,
} from "./support";

type Wire = NonNullable<Parameters<typeof grantBody>[1]>;

const cacheControl = (response: Response): string | null => response.headers.get("cache-control");

describe("Cache-Control: no-store (RFC 9635 §3)", () => {
  it("is on every kind of response", async () => {
    const h = await createServerHarness();
    const nonInteractive = await h.signedCall(h.baseUrl, json("POST", grantBody([incoming])));
    const badRequest = await h.signedCall(h.baseUrl, json("POST", { client: "nope" }));
    const pending = await startGrant(h);
    const poll = await continueWith(h, pending);
    const start = await h.call(new Request(pending.interactUrl));

    const s = await seedGrant(h, { state: "FINALIZED" });
    const token = await seedToken(h, s.grant);
    const rotated = await h.signedCall(token.manage, withToken({ method: "POST" }, token.value));
    const rotatedValue = (await jsonBody<{ access_token: { value: string } }>(rotated)).access_token.value;
    const revoked = await h.signedCall(token.manage, withToken({ method: "DELETE" }, rotatedValue));

    for (const response of [nonInteractive, badRequest, poll, start, rotated, revoked]) {
      expect(cacheControl(response)).toBe("no-store");
    }

    expect([nonInteractive.status, badRequest.status, poll.status, start.status, rotated.status]).toEqual([
      200, 400, 400, 302, 200,
    ]);
  });
});

describe("grant request validation", () => {
  const rejected = async (body: Wire, options: HarnessOptions = {}) => {
    const h = await createServerHarness({ unvalidated: true, ...options });

    return errorOf(await h.signedCall(h.baseUrl, json("POST", body)));
  };

  it("requires an application/json body (§2)", async () => {
    const h = await createServerHarness({ unvalidated: true });
    const body = JSON.stringify(grantBody([incoming]));

    const wrong = await h.signedCall(h.baseUrl, { method: "POST", body, headers: { "content-type": "text/plain" } });

    const charset = await h.signedCall(h.baseUrl, {
      method: "POST",
      body,
      headers: { "content-type": "application/json; charset=utf-8" },
    });

    expect(await errorOf(wrong)).toMatchObject({ status: 400, code: "invalid_request" });
    expect(charset.status).toBe(200);
  });

  it("requires interact.start (§2.5)", async () => {
    expect(
      await rejected(
        grantBody([outgoing], { interact: { finish: { method: "redirect", uri: "https://c.test/f", nonce: "n" } } }),
      ),
    ).toMatchObject({ status: 400, code: "invalid_request" });
  });

  it.each([
    ["a fragment in finish.uri", { ...interact.finish, uri: "https://c.test/r#x" }],
    ["an empty finish.nonce", { ...interact.finish, nonce: "" }],
    ["an unknown hash_method", { ...interact.finish, hash_method: "md5" }],
  ])("rejects %s", async (_name, finish) => {
    expect(await rejected(grantBody([outgoing], { interact: { ...interact, finish } }))).toMatchObject({
      status: 400,
      code: "invalid_request",
    });
  });

  it.each([
    [
      "more than 3 access items",
      [
        incoming,
        { type: "quote", actions: ["create"] },
        { ...incoming, actions: ["read"] },
        { ...incoming, actions: ["list"] },
      ],
    ],
    ["duplicate access items", [incoming, { ...incoming }]],
  ])("rejects %s", async (_name, access) => {
    expect(await rejected(grantBody(access))).toMatchObject({ status: 400, code: "invalid_request" });
  });

  it.each([
    [[]],
    [
      [
        { format: "uri", id: "https://a.test/1" },
        { format: "uri", id: "https://a.test/2" },
      ],
    ],
  ])("rejects subject.sub_ids %j", async (subIds) => {
    expect(await rejected(grantBody([], { subject: { sub_ids: subIds }, interact }))).toMatchObject({
      status: 400,
      code: "invalid_request",
    });
  });

  it("rejects repeated and unsupported access token flags (§2.1.1)", async () => {
    for (const flags of [["bearer", "bearer"], ["bearer"], ["durable", "durable"]]) {
      expect(
        await rejected({ client: "https://wallet.test/alice", access_token: { access: [incoming], flags } }),
      ).toMatchObject({
        status: 400,
        code: "invalid_flag",
      });
    }
  });

  it("echoes access_token.label on issued and rotated tokens, and only then", async () => {
    const h = await createServerHarness({ unvalidated: true });

    const labelled = await jsonBody<{ access_token: { value: string; manage: string; label?: string } }>(
      await h.signedCall(
        h.baseUrl,
        json("POST", { client: "https://wallet.test/alice", access_token: { access: [incoming], label: "t1" } }),
      ),
    );

    const rotated = await jsonBody<{ access_token: { label?: string } }>(
      await h.signedCall(labelled.access_token.manage, withToken({ method: "POST" }, labelled.access_token.value)),
    );

    const plain = await jsonBody<{ access_token: { label?: string } }>(
      await h.signedCall(h.baseUrl, json("POST", grantBody([incoming]))),
    );

    expect(labelled.access_token.label).toBe("t1");
    expect(rotated.access_token.label).toBe("t1");
    expect("label" in plain.access_token).toBe(false);
  });

  it("never advertises a wait below five seconds (§3.1)", async () => {
    const h = await createServerHarness({ waitSeconds: 1 });
    const response = await h.signedCall(h.baseUrl, json("POST", grantBody([outgoing], { interact })));

    expect((await jsonBody<{ continue: { wait: number } }>(response)).continue.wait).toBe(5);
  });
});

describe("continuation and token management authentication", () => {
  it("requires the GNAP scheme on a continuation, case-insensitively (§7.2)", async () => {
    const h = await createServerHarness();
    const pending = await startGrant(h);
    const url = pending.continueUri;

    h.clock.advance(6);
    const bare = await h.signedCall(url, { method: "POST", headers: { authorization: pending.continueToken } });

    const lower = await h.signedCall(url, {
      method: "POST",
      headers: { authorization: `gnap ${pending.continueToken}` },
    });

    // The scheme-less token is not authenticated; the lower-case scheme is, and then the finish grant cannot be polled.
    expect((await errorOf(bare)).code).toBe("invalid_continuation");
    expect((await errorOf(lower)).code).toBe("request_denied");
  });

  it("refuses a key rotation request instead of rotating the value (§6.1.1)", async () => {
    const h = await createServerHarness({ unvalidated: true });
    const s = await seedGrant(h, { state: "FINALIZED" });
    const token = await seedToken(h, s.grant);
    const body = { key: { proof: "httpsig", jwk: h.clientKey.signingKey.keyId } };
    const response = await h.signedCall(token.manage, withToken(json("POST", body), token.value));

    expect(await errorOf(response)).toMatchObject({ status: 400, code: "key_rotation_not_supported" });
    expect(await Effect.runPromise(h.server.introspectToken(token.value))).toMatchObject({ active: true });
  });
});

describe("finish hash (§2.5.2, §4.2.3)", () => {
  it("uses the hash_method the client asked for", async () => {
    const h = await createServerHarness();
    const finish = { ...interact.finish, hash_method: "sha-512" };
    const pending = await startGrant(h, grantBody([outgoing], { interact: { ...interact, finish } }));
    const start = await browserStart(h, pending);

    await approve(h, pending);
    const back = new URL((await browserFinish(h, pending, start.cookie)).headers.get("location") ?? "");

    const input = {
      clientNonce: "client-nonce",
      serverNonce: pending.nonce,
      interactRef: back.searchParams.get("interact_ref") ?? "",
      grantEndpoint: BASE_URL,
    };

    expect(back.searchParams.get("hash")).toBe(
      await Effect.runPromise(computeInteractionHash({ ...input, method: "sha-512", encoding: "base64" })),
    );

    expect(
      await Effect.runPromise(verifyInteractionHash({ ...input, hash: back.searchParams.get("hash") ?? "" })),
    ).toBe(false);
  });

  it("verifyInteractionHash accepts both the base64url and the padded base64 form, and only those", async () => {
    const input = { clientNonce: "c", serverNonce: "s", interactRef: "r", grantEndpoint: BASE_URL };
    const verify = (hash: string) => Effect.runPromise(verifyInteractionHash({ ...input, hash }));
    const url = await Effect.runPromise(computeInteractionHash(input));
    const padded = await Effect.runPromise(computeInteractionHash({ ...input, encoding: "base64" }));

    expect(await verify(url)).toBe(true);
    expect(await verify(padded)).toBe(true);
    expect(await verify(`${url.slice(0, -1)}${url.endsWith("A") ? "B" : "A"}`)).toBe(false);
    expect(await Effect.runPromise(verifyInteractionHash({ ...input, serverNonce: "x", hash: url }))).toBe(false);
  });
});

describe("who may decide (RFC 9635 §3.4)", () => {
  const decide = (h: ServerHarness, userId?: string) =>
    Effect.runPromise(
      Effect.result(
        h.server.decideInteraction({
          interactId: SEED.interactId,
          nonce: SEED.nonce,
          choice: "accept",
          ...(userId !== undefined && { userId }),
        }),
      ),
    );

  const grantsOfAnotherParty: ReadonlyArray<readonly [string, Partial<GrantRecord>]> = [
    ["a subject", { subject: { sub_ids: [{ format: "uri", id: "https://a.test/1" }] } }],
    ["outgoing-payment access", { access: [outgoing] }],
  ];

  it.each(grantsOfAnotherParty)(
    "refuses a signed-in user's decision on %s while no authorize hook is configured",
    async (_name, overrides) => {
      const h = await createServerHarness();

      await seedGrant(h, overrides);

      expect(await decide(h, "u1")).toMatchObject({
        _tag: "Failure",
        failure: { status: 403, code: "request_denied" },
      });
      expect(await Effect.runPromise(h.store.findGrant("id", SEED.id))).toMatchObject({ state: "PENDING" });
    },
  );

  it("records the decision of a signed-in user the authorize hook allows", async () => {
    const h = await createServerHarness({
      interaction: { consentUrl: CONSENT_URL, authorize: () => Effect.succeed(true) },
    });

    await seedGrant(h, { access: [outgoing] });

    expect((await decide(h, "u1"))._tag).toBe("Success");
    expect(await Effect.runPromise(h.store.findGrant("id", SEED.id))).toMatchObject({
      state: "ACCEPTED",
      userId: "u1",
    });
  });

  it("leaves a decision without a userId to the caller that vouches for it", async () => {
    const h = await createServerHarness();

    await seedGrant(h, { access: [outgoing] });

    expect((await decide(h))._tag).toBe("Success");
  });

  it.each([undefined, 0, "", "ok", { tenantId: undefined }, null])(
    "refuses a decision when the hook answers %j instead of true",
    async (answer) => {
      const h = await createServerHarness({
        interaction: {
          consentUrl: CONSENT_URL,
          // SAFETY: a JavaScript hook can answer anything; the server must not read that as consent.
          authorize: () => Effect.succeed(answer as never),
        },
      });

      await seedGrant(h, { access: [outgoing] });

      expect(await decide(h, "u1")).toMatchObject({
        _tag: "Failure",
        failure: { status: 403, code: "request_denied" },
      });
    },
  );
});

describe("introspection (RFC 9767 §3.3, §3.5)", () => {
  const options: HarnessOptions = { introspection: { authorize: () => Effect.succeed(true) }, unvalidated: true };

  it.each([undefined, 0, "", "ok", { tenantId: undefined }, null])(
    "refuses an introspection caller whose hook answers %j",
    async (answer) => {
      const h = await createServerHarness({
        unvalidated: true,
        // SAFETY: a JavaScript hook can answer anything; the server must not read that as an unscoped caller.
        introspection: { authorize: () => Effect.succeed(answer as never) },
      });

      expect(
        await errorOf(await h.call(new Request(`${BASE_URL}/introspect`, json("POST", { access_token: "x" })))),
      ).toMatchObject({
        status: 400,
        code: "invalid_resource_server",
      });
    },
  );

  const introspect = (h: ServerHarness, body: Wire) =>
    h.call(new Request(`${BASE_URL}/introspect`, json("POST", body)));

  it("is inactive for a proof the token is not bound with, active otherwise", async () => {
    const h = await createServerHarness(options);
    const s = await seedGrant(h, { state: "FINALIZED" });
    const token = await seedToken(h, s.grant);

    expect(await jsonBody(await introspect(h, { access_token: token.value, proof: "mtls" }))).toEqual({
      active: false,
    });
    expect(await jsonBody(await introspect(h, { access_token: token.value, proof: "httpsig" }))).toMatchObject({
      active: true,
    });
    expect(await jsonBody(await introspect(h, { access_token: token.value }))).toMatchObject({ active: true });
  });

  it("treats a token as expired from the very second it expires", async () => {
    const h = await createServerHarness(options);
    const s = await seedGrant(h, { state: "FINALIZED" });
    const now = h.clock.now().getTime();
    const lastSecond = await seedToken(h, s.grant, { expiresAt: now + 1 });
    const expiring = await seedToken(h, s.grant, { expiresAt: now });

    expect(await Effect.runPromise(h.server.introspectToken(lastSecond.value))).toMatchObject({ active: true });
    expect(await Effect.runPromise(h.server.introspectToken(expiring.value))).toEqual({ active: false });
  });

  it("is inactive for the tokens of a rejected grant", async () => {
    const h = await createServerHarness(options);
    const s = await seedGrant(h, { state: "REJECTED" });
    const token = await seedToken(h, s.grant);

    expect(await Effect.runPromise(h.server.introspectToken(token.value))).toEqual({ active: false });
  });
});

/** Signs a body-carrying POST by hand, with extra signature parameters and a chosen label. */
const signedPost = async (
  h: ServerHarness,
  body: Wire,
  extra: Array<readonly [string, string | number]>,
  label = "sig1",
  created = h.clock.now(),
  key: SigningKey = h.clientKey.signingKey,
) => {
  const text = JSON.stringify(body);
  const bytes = utf8Encode(text);
  const headers = new Headers({ "content-type": "application/json", "content-length": String(bytes.byteLength) });

  headers.set("content-digest", await Effect.runPromise(createContentDigest(bytes, "sha-512")));
  const components = ["@method", "@target-uri", "content-digest", "content-length", "content-type"];

  const params: Array<readonly [string, string | number]> = [
    ["created", Math.floor(created.getTime() / 1000)],
    ["keyid", key.keyId],
    ...extra,
  ];

  const message = { method: "POST", url: BASE_URL, headers };
  const base = await Effect.runPromise(Effect.fromResult(createSignatureBase(message, components, params)));
  const input = await Effect.runPromise(Effect.fromResult(serializeSignatureParams(components, params)));
  const signature = await crypto.subtle.sign("Ed25519", key.privateKey, utf8Encode(base));

  headers.set("signature-input", `${label}=${input}`);
  headers.set("signature", `${label}=:${encodeBase64(new Uint8Array(signature))}:`);

  return () => h.call(new Request(BASE_URL, { method: "POST", body: text, headers }));
};

describe("HTTP message signatures (§7.3.1)", () => {
  const body = grantBody([incoming]);

  it("accepts an explicit ed25519 alg parameter like Rafiki does and refuses another algorithm", async () => {
    const h = await createServerHarness({ unvalidated: true });
    const explicit = await signedPost(h, body, [["alg", "ed25519"]]);

    expect((await explicit()).status).toBe(200);

    const other = await signedPost(h, body, [["alg", "rsa-pss-sha512"]]);

    expect(await errorOf(await other())).toMatchObject({ status: 401, code: "invalid_client" });
  });

  it("accepts a valid signature under a label other than sig1", async () => {
    const h = await createServerHarness({ unvalidated: true });
    const send = await signedPost(h, body, [], "sig2");

    expect((await send()).status).toBe(200);
  });

  it("accepts a nonce once and refuses its replay until the window has passed", async () => {
    const h = await createServerHarness({ unvalidated: true });
    const send = await signedPost(h, body, [["nonce", "n-1"]]);

    expect((await send()).status).toBe(200);
    expect(await errorOf(await send())).toMatchObject({ status: 401, code: "invalid_client" });

    const other = await signedPost(h, body, [["nonce", "n-2"]]);

    expect((await other()).status).toBe(200);
  });

  it.each([
    ["nonce", 5],
    ["tag", 5],
  ] as const)("refuses a request whose %s parameter is %j instead of a string", async (name, value) => {
    const h = await createServerHarness({ unvalidated: true });
    const send = await signedPost(h, body, [[name, value]]);

    expect(await errorOf(await send())).toMatchObject({ status: 401, code: "invalid_client" });
  });

  it("forgets a nonce after the replay window", async () => {
    const h = await createServerHarness({ unvalidated: true });
    const send = await signedPost(h, body, [["nonce", "n-1"]]);

    expect((await send()).status).toBe(200);
    h.clock.advance(400);
    const fresh = await signedPost(h, body, [["nonce", "n-1"]]);

    expect((await fresh()).status).toBe(200);
  });

  it("still refuses a replay at the end of the window when the signer's clock runs 30 s ahead", async () => {
    const h = await createServerHarness({ unvalidated: true });
    // 30 s ahead is the most the verifier tolerates; that signature is acceptable until `created + 300` s is over.
    const send = await signedPost(h, body, [["nonce", "n-1"]], "sig1", new Date(h.clock.now().getTime() + 30_000));

    expect((await send()).status).toBe(200);
    h.clock.advance(330);

    expect(await errorOf(await send())).toMatchObject({ status: 401, code: "invalid_client" });
  });

  it("scopes a nonce to the key that used it", async () => {
    const primary = await createClientKey();
    const second = await createClientKey("alice-key-2");
    const h = await createServerHarness({ unvalidated: true, fetch: walletFetch([primary, second]) });
    const first = await signedPost(h, body, [["nonce", "shared"]], "sig1", h.clock.now(), primary.signingKey);
    const other = await signedPost(h, body, [["nonce", "shared"]], "sig1", h.clock.now(), second.signingKey);

    expect((await first()).status).toBe(200);
    expect((await other()).status).toBe(200);
  });

  it("does not spend a nonce on a request whose signature is wrong", async () => {
    const h = await createServerHarness({ unvalidated: true });
    const forger = await createClientKey();
    const forged = await signedPost(h, body, [["nonce", "n-1"]], "sig1", h.clock.now(), forger.signingKey);
    const genuine = await signedPost(h, body, [["nonce", "n-1"]]);

    expect(await errorOf(await forged())).toMatchObject({ status: 401, code: "invalid_client" });
    expect((await genuine()).status).toBe(200);
  });
});

describe("server options", () => {
  type Granted = { access_token: { value: string; manage: string; expires_in: number }; continue: { wait?: number } };

  const grantOf = async (h: ServerHarness, body = grantBody([incoming])) =>
    jsonBody<Granted>(await h.signedCall(BASE_URL, json("POST", body)));

  it("issues tokens that live for accessTokenExpiresInSeconds", async () => {
    const h = await createServerHarness({ accessTokenExpiresInSeconds: 30 });
    const { access_token: token } = await grantOf(h);

    expect(token.expires_in).toBe(30);
    expect(await Effect.runPromise(h.server.introspectToken(token.value))).toMatchObject({ active: true });
    h.clock.advance(30);
    expect(await Effect.runPromise(h.server.introspectToken(token.value))).toEqual({ active: false });
  });

  it("takes access token values from generateToken", async () => {
    let issued = 0;
    const h = await createServerHarness({ generateToken: () => `custom-${++issued}` });

    expect((await grantOf(h)).access_token.value).toMatch(/^custom-\d+$/);
  });

  it("tells a client to wait waitSeconds, and never less than five seconds", async () => {
    const interactive = grantBody([outgoing], { interact });
    const slow = await createServerHarness({ waitSeconds: 12 });
    const eager = await createServerHarness({ waitSeconds: 1 });

    expect((await grantOf(slow, interactive)).continue.wait).toBe(12);
    expect((await grantOf(eager, interactive)).continue.wait).toBe(5);
  });

  it("serves a baseUrl with a trailing slash like one without", async () => {
    const h = await createServerHarness({ baseUrl: `${BASE_URL}/`, unvalidated: true });

    expect((await grantOf(h)).access_token.manage).toMatch(/^https:\/\/as\.test\/gnap\/token\/[^/]+$/);
  });
});
