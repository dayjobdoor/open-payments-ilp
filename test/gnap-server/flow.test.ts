import * as Effect from "effect/Effect";
import { describe, expect, it } from "vite-plus/test";
import { computeInteractionHash, hashToken } from "../../src/gnap/index";
import {
  BASE_URL,
  CONSENT_URL,
  FINISH_URI,
  WALLET,
  approve,
  browserFinish,
  browserStart,
  continueWith,
  createServerHarness,
  errorOf,
  grantBody,
  idp,
  incoming,
  interact,
  json,
  jsonBody,
  outgoing,
  startGrant,
  withToken,
} from "./support";

describe("interactive flow with the identity provider back channel", () => {
  it("start → consent → finish → continue → rotate → revoke, with the hash a client verifies", async () => {
    const h = await createServerHarness();
    const pending = await startGrant(h);

    const start = await browserStart(h, pending);
    const consent = new URL(start.location);

    expect(`${consent.origin}${consent.pathname}`).toBe(CONSENT_URL);
    expect(consent.searchParams.get("interactId")).toBe(pending.interactId);
    expect(consent.searchParams.get("nonce")).toBe(pending.nonce);

    const details = await h.call(
      new Request(`${BASE_URL}/grant/${pending.interactId}/${pending.nonce}`, {
        headers: { "x-idp-secret": "idp-secret" },
      }),
    );

    expect(await jsonBody(details)).toEqual({ grantId: expect.any(String), access: [outgoing], state: "PENDING" });

    expect((await idp(h, pending, "accept")).status).toBe(202);
    const finish = await browserFinish(h, pending, start.cookie);
    const back = new URL(finish.headers.get("location") ?? "");
    const interactRef = back.searchParams.get("interact_ref") ?? "";

    expect(finish.status).toBe(302);

    expect(back.searchParams.get("hash")).toBe(
      await Effect.runPromise(
        computeInteractionHash({
          clientNonce: "client-nonce",
          serverNonce: pending.nonce,
          interactRef,
          grantEndpoint: BASE_URL,
          encoding: "base64",
        }),
      ),
    );

    h.clock.advance(6);
    const granted = await continueWith(h, pending, { interact_ref: interactRef });

    const body = await jsonBody<{
      access_token: { value: string; manage: string };
      continue: { access_token: { value: string } };
    }>(granted);

    expect(granted.status).toBe(200);
    expect(await Effect.runPromise(h.server.introspectToken(body.access_token.value, [outgoing]))).toMatchObject({
      active: true,
      access: [outgoing],
      client: { walletAddress: WALLET },
    });

    // Like Rafiki the continue token is not rotated, and the finalized grant cannot be continued again.
    expect(body.continue.access_token.value).toBe(pending.continueToken);
    h.clock.advance(6);

    expect(await errorOf(await continueWith(h, pending, { interact_ref: interactRef }))).toMatchObject({
      status: 401,
      code: "request_denied",
      description: "grant interaction not approved",
    });

    const rotated = await h.signedCall(
      body.access_token.manage,
      withToken({ method: "POST" }, body.access_token.value),
    );

    const next = (await jsonBody<{ access_token: { value: string; manage: string } }>(rotated)).access_token;

    expect(await Effect.runPromise(h.server.introspectToken(body.access_token.value))).toEqual({ active: false });

    const revoked = await h.signedCall(next.manage, withToken({ method: "DELETE" }, next.value));

    expect(revoked.status).toBe(204);
    expect(await Effect.runPromise(h.server.introspectToken(next.value))).toEqual({ active: false });
  });

  it("emits the unpadded base64url hash when configured", async () => {
    const h = await createServerHarness({ finishHashEncoding: "base64url" });
    const pending = await startGrant(h);
    const { hash, interactRef } = await approve(h, pending);

    expect(hash).toBe(
      await Effect.runPromise(
        computeInteractionHash({
          clientNonce: "client-nonce",
          serverNonce: pending.nonce,
          interactRef,
          grantEndpoint: BASE_URL,
          encoding: "base64url",
        }),
      ),
    );

    expect(hash).not.toMatch(/[=+/]/);
  });

  it("is refused with the rejected finish redirect, and the grant cannot be continued", async () => {
    const h = await createServerHarness();
    const pending = await startGrant(h);
    const { cookie } = await browserStart(h, pending);

    expect((await idp(h, pending, "reject")).status).toBe(202);

    const finish = await browserFinish(h, pending, cookie);

    expect(finish.headers.get("location")).toBe(`${FINISH_URI}?result=grant_rejected`);

    h.clock.advance(6);
    expect(await errorOf(await continueWith(h, pending, { interact_ref: "x" }))).toMatchObject({
      status: 404,
      code: "invalid_continuation",
    });
  });

  it("serves a polling client: continue without a body; the grant is approved when the browser reaches finish", async () => {
    const h = await createServerHarness();
    const pending = await startGrant(h, grantBody([outgoing], { interact: { start: ["redirect"] } }));
    const { cookie } = await browserStart(h, pending);

    h.clock.advance(6);
    const waiting = await continueWith(h, pending);

    expect(await jsonBody(waiting)).toEqual({
      continue: { access_token: { value: pending.continueToken }, uri: pending.continueUri, wait: 5 },
    });

    // Accepted, but like Rafiki the grant only becomes approvable when `/finish` is reached: still a pending poll.
    await idp(h, pending, "accept");
    h.clock.advance(6);
    expect(await jsonBody(await continueWith(h, pending))).toHaveProperty("continue.wait", 5);

    expect((await browserFinish(h, pending, cookie)).status).toBe(202);
    h.clock.advance(6);

    const granted = await continueWith(h, pending);

    expect(granted.status).toBe(200);
    expect(await jsonBody(granted)).toMatchObject({ access_token: { access: [outgoing] } });
  });

  it("answers too_fast inside the wait period and accepts the retry after it", async () => {
    const h = await createServerHarness();
    const pending = await startGrant(h);
    const { interactRef } = await approve(h, pending);

    expect(await errorOf(await continueWith(h, pending, { interact_ref: interactRef }))).toMatchObject({
      status: 400,
      code: "too_fast",
    });

    h.clock.advance(5);
    expect((await continueWith(h, pending, { interact_ref: interactRef })).status).toBe(200);
  });

  it("serves a subject-only grant after consent", async () => {
    const h = await createServerHarness();

    const pending = await startGrant(h, {
      client: WALLET,
      subject: { sub_ids: [{ id: "https://wallet.test/alice", format: "uri" }] },
      interact,
    });

    const { interactRef } = await approve(h, pending);

    h.clock.advance(6);
    const granted = await jsonBody(await continueWith(h, pending, { interact_ref: interactRef }));

    expect(granted).toMatchObject({ subject: { sub_ids: [{ id: "https://wallet.test/alice" }] } });
    expect(granted).not.toHaveProperty("access_token");
  });

  it("honours a consentUrl function", async () => {
    const h = await createServerHarness({
      interaction: { consentUrl: ({ interactId, nonce }) => `https://app.test/c/${interactId}/${nonce}` },
    });

    const pending = await startGrant(h);

    expect((await browserStart(h, pending)).location).toBe(`https://app.test/c/${pending.interactId}/${pending.nonce}`);
  });

  it("serves under a base path behind a proxy: signature bases use baseUrl", async () => {
    const h = await createServerHarness({ baseUrl: "https://public.example/op/auth" });
    const response = await h.signedCall("https://public.example/op/auth", json("POST", grantBody([incoming])));

    expect(response.status).toBe(200);
    expect((await jsonBody<{ continue: { uri: string } }>(response)).continue.uri).toMatch(
      /^https:\/\/public\.example\/op\/auth\/continue\//,
    );
  });

  it("answers unknown routes with 404", async () => {
    const h = await createServerHarness({ unvalidated: true });

    expect((await h.call(new Request(`${BASE_URL}/nope`))).status).toBe(404);
    expect((await h.call(new Request("https://other.test/elsewhere", { method: "POST" }))).status).toBe(404);
    expect((await h.call(new Request(`${BASE_URL}/continue/x%zz`, { method: "POST" }))).status).toBe(404);
  });

  it("never stores a secret: only hashes of continue and access tokens", async () => {
    const h = await createServerHarness();
    const response = await h.signedCall(h.baseUrl, json("POST", grantBody([incoming])));

    const body = await jsonBody<{
      access_token: { value: string };
      continue: { access_token: { value: string }; uri: string };
    }>(response);

    const grant = await Effect.runPromise(h.store.findGrant("continueId", body.continue.uri.split("/").at(-1) ?? ""));

    const stored = await Effect.runPromise(
      h.store.findTokenWithGrant("valueHash", await Effect.runPromise(hashToken(body.access_token.value))),
    );

    expect(JSON.stringify([grant, stored])).not.toContain(body.access_token.value);
    expect(JSON.stringify([grant, stored])).not.toContain(body.continue.access_token.value);
    expect(grant?.continueTokenHash).toBe(await Effect.runPromise(hashToken(body.continue.access_token.value)));
  });
});
