// oxlint-disable anti-slop/no-unknown-parameters, anti-slop/no-unsafe-dictionary-type, anti-slop/no-known-value-widening -- Tests send arbitrary, including malformed, request bodies by design.
/** RFC 9635 §5.3: `PATCH /continue/:id` replaces the requested access and evaluates the request again. */
import * as Effect from "effect/Effect";
import { describe, expect, it } from "vite-plus/test";
import {
  WALLET,
  approve,
  continueWith,
  createServerHarness,
  errorOf,
  grantBody,
  idp,
  incoming,
  interact,
  json,
  jsonBody,
  legacyStore,
  outgoing,
  seedGrant,
  startGrant,
  withToken,
  type Pending,
  type ServerHarness,
} from "./support";

const quote = { type: "quote", actions: ["create", "read"] };

interface Wire {
  readonly access_token?: { readonly value: string; readonly access: ReadonlyArray<unknown> };
  readonly interact?: { readonly redirect: string };
  readonly continue?: { readonly access_token: { readonly value: string } };
}

const patch = (h: ServerHarness, pending: Pick<Pending, "continueUri" | "continueToken">, body?: unknown) =>
  h.signedCall(pending.continueUri, withToken(json("PATCH", body), pending.continueToken));

const introspect = (h: ServerHarness, value: string, access: unknown[]) =>
  // SAFETY: the access items of the tests are plain wire items.
  Effect.runPromise(h.server.introspectToken(value, access as never));

/** A grant that needed no consent and already holds a token for incoming payments. */
const grantedIncoming = async (h: ServerHarness) => {
  const response = await h.signedCall(h.baseUrl, json("POST", grantBody([incoming])));

  const body = await jsonBody<Wire & { continue: { uri: string; access_token: { value: string } } }>(response);

  return {
    token: body.access_token?.value ?? "",
    pending: { continueUri: body.continue.uri, continueToken: body.continue.access_token.value },
  };
};

describe("PATCH /continue/:id (RFC 9635 §5.3)", () => {
  it("replaces the access of a granted request and hands out a new token, leaving the old one as it was", async () => {
    const h = await createServerHarness({ unvalidated: true });
    const first = await grantedIncoming(h);

    const response = await patch(h, first.pending, { access_token: { access: [quote] } });
    const body = await jsonBody<Wire>(response);

    expect(response.status).toBe(200);
    expect(body.access_token?.access).toEqual([quote]);
    expect(body.access_token?.value).not.toBe(first.token);
    // The continuation stays usable with the same token.
    expect(body.continue?.access_token.value).toBe(first.pending.continueToken);

    // §5.3: earlier tokens are not altered, neither narrowed nor widened by the new request.
    expect(await introspect(h, first.token, [incoming, quote])).toMatchObject({ active: true, access: [incoming] });
    expect(await introspect(h, body.access_token?.value ?? "", [incoming, quote])).toMatchObject({
      active: true,
      access: [quote],
    });
  });

  it("asks the owner again for more access: a new interaction, and the old token gains nothing before consent", async () => {
    const h = await createServerHarness({ unvalidated: true });
    const first = await grantedIncoming(h);

    const response = await patch(h, first.pending, { access_token: { access: [incoming, outgoing] }, interact });
    const body = await jsonBody<Wire>(response);

    expect(response.status).toBe(200);
    expect(body.interact?.redirect).toContain("/interact/");
    expect(body.access_token).toBeUndefined();
    expect(await introspect(h, first.token, [outgoing])).toMatchObject({ active: true, access: [] });

    const [interactId = "", nonce = ""] = new URL(body.interact?.redirect ?? "").pathname.split("/").slice(-2);
    const stepUp: Pending = { ...first.pending, interactUrl: body.interact?.redirect ?? "", interactId, nonce };
    const { interactRef } = await approve(h, stepUp);

    h.clock.advance(6);
    const granted = await jsonBody<Wire>(await continueWith(h, stepUp, { interact_ref: interactRef }));

    expect(granted.access_token?.access).toEqual([incoming, outgoing]);
    expect(await introspect(h, granted.access_token?.value ?? "", [outgoing])).toMatchObject({ access: [outgoing] });
    expect(await introspect(h, first.token, [outgoing])).toMatchObject({ active: true, access: [] });
  });

  it("needs an interact capability when the new request needs the owner", async () => {
    const h = await createServerHarness({ unvalidated: true });
    const first = await grantedIncoming(h);

    expect(await errorOf(await patch(h, first.pending, { access_token: { access: [outgoing] } }))).toEqual({
      status: 400,
      code: "invalid_request",
      description: "missing required request field 'interact'",
    });
  });

  it("replaces a pending request with a new interaction: the owner who saw the old one cannot decide it", async () => {
    const h = await createServerHarness({ unvalidated: true });
    const pending = await startGrant(h);
    const wider = { ...outgoing, limits: { debitAmount: { value: "9999", assetCode: "USD", assetScale: 2 } } };

    const response = await patch(h, pending, { access_token: { access: [wider] }, interact });
    const body = await jsonBody<Wire>(response);

    expect(response.status).toBe(200);
    expect(body.interact?.redirect).not.toBe(pending.interactUrl);

    // The consent page of the first request is dead; deciding on it can no longer approve the wider access.
    expect((await idp(h, pending, "accept")).status).toBe(404);

    const [interactId = "", nonce = ""] = new URL(body.interact?.redirect ?? "").pathname.split("/").slice(-2);

    expect(await Effect.runPromise(h.server.getInteraction({ interactId, nonce }))).toMatchObject({
      access: [wider],
      state: "PENDING",
    });
  });

  it("approves a pending request at once when the new one needs no consent, and kills its interaction", async () => {
    const h = await createServerHarness({ unvalidated: true });
    const pending = await startGrant(h);

    const response = await patch(h, pending, { access_token: { access: [incoming] } });
    const body = await jsonBody<Wire>(response);

    expect(response.status).toBe(200);
    expect(body.access_token?.access).toEqual([incoming]);
    expect((await idp(h, pending, "accept")).status).toBe(404);
  });

  it("refuses a grant that is finished, revoked or decided, and a stranger", async () => {
    const h = await createServerHarness({ unvalidated: true });
    const seeded = await seedGrant(h, { state: "FINALIZED" });
    const body = { access_token: { access: [quote] } };

    expect(await errorOf(await patch(h, seeded.pending, body))).toEqual({
      status: 401,
      code: "request_denied",
      description: "grant cannot be modified",
    });

    for (const state of ["ACCEPTED", "DENIED", "REJECTED"] as const) {
      const other = await createServerHarness({ unvalidated: true });
      const decided = await seedGrant(other, { state });

      expect((await errorOf(await patch(other, decided.pending, body))).code).toBe("request_denied");
    }

    const revoked = await createServerHarness({ unvalidated: true });
    const gone = await seedGrant(revoked, { state: "REVOKED" });

    expect((await errorOf(await patch(revoked, gone.pending, body))).code).toBe("invalid_continuation");

    const fresh = await createServerHarness({ unvalidated: true });
    const live = await seedGrant(fresh, { state: "APPROVED" });

    expect((await errorOf(await patch(fresh, { ...live.pending, continueToken: "wrong" }, body))).code).toBe(
      "invalid_continuation",
    );

    expect((await fresh.call(new Request(live.continueUri, json("PATCH", body)))).status).toBe(401);
  });

  it("refuses what §5.3 forbids in a modification, and nothing to modify", async () => {
    const h = await createServerHarness({ unvalidated: true });
    const { pending } = await grantedIncoming(h);

    const refusals = [
      { client: WALLET, access_token: { access: [quote] } },
      { interact_ref: "x" },
      { access_token: { access: [{ type: "quote", actions: ["nonsense"] }] } },
      { access_token: { access: [quote], flags: ["bearer"] } },
      { access_token: { access: [] } },
      {},
    ];

    for (const body of refusals) {
      expect((await patch(h, pending, body)).status).toBe(400);
    }
  });

  it("is answered 501 invalid_request by a store without extendedRecords", async () => {
    const h = await createServerHarness({ unvalidated: true, store: legacyStore() });
    const first = await grantedIncoming(h);

    expect(await errorOf(await patch(h, first.pending, { access_token: { access: [quote] } }))).toEqual({
      status: 501,
      code: "invalid_request",
      description: "grant modification not supported",
    });

    // Nothing was changed: the grant keeps its token and keeps being continued as before.
    expect(await introspect(h, first.token, [incoming])).toMatchObject({ active: true, access: [incoming] });
  });
});
