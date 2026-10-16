// oxlint-disable anti-slop/no-unknown-parameters, anti-slop/no-unsafe-dictionary-type, anti-slop/no-known-value-widening -- Tests send arbitrary, including malformed, request bodies by design.
/** RFC 9635 §2.1.2 / §3.2.2: an `access_token` array asks for several labelled tokens in one grant. */
import * as Effect from "effect/Effect";
import { describe, expect, it } from "vite-plus/test";
import {
  WALLET,
  approve,
  continueWith,
  createServerHarness,
  errorOf,
  incoming,
  interact,
  json,
  jsonBody,
  legacyStore,
  outgoing,
  startGrant,
  withToken,
  type ServerHarness,
} from "./support";

const quote = { type: "quote", actions: ["create", "read"] };

interface WireToken {
  readonly value: string;
  readonly manage: string;
  readonly label?: string;
  readonly access: ReadonlyArray<unknown>;
}

const twoTokens = {
  client: WALLET,
  access_token: [
    { label: "pay-in", access: [incoming] },
    { label: "quotes", access: [quote] },
  ],
};

const introspect = (h: ServerHarness, value: string, access: unknown[]) =>
  // SAFETY: the access items of the tests are plain wire items.
  Effect.runPromise(h.server.introspectToken(value, access as never));

describe("multiple access tokens (RFC 9635 §2.1.2, §3.2.2)", () => {
  it("issues one labelled token per requested one, each with its own access and no more", async () => {
    const h = await createServerHarness({ unvalidated: true });
    const response = await h.signedCall(h.baseUrl, json("POST", twoTokens));
    const body = await jsonBody<{ access_token: ReadonlyArray<WireToken> }>(response);

    expect(response.status).toBe(200);
    expect(body.access_token.map(({ label, access }) => ({ label, access }))).toEqual([
      { label: "pay-in", access: [incoming] },
      { label: "quotes", access: [quote] },
    ]);

    const [payIn, quotes] = body.access_token;

    expect(payIn?.value).not.toBe(quotes?.value);
    expect(payIn?.manage).not.toBe(quotes?.manage);

    // The first token covers the incoming payments only, the second the quotes only.
    expect(await introspect(h, payIn?.value ?? "", [incoming])).toMatchObject({ active: true, access: [incoming] });
    expect(await introspect(h, payIn?.value ?? "", [quote])).toMatchObject({ active: true, access: [] });
    expect(await introspect(h, quotes?.value ?? "", [quote])).toMatchObject({ active: true, access: [quote] });
    expect(await introspect(h, quotes?.value ?? "", [incoming])).toMatchObject({ active: true, access: [] });
  });

  it("answers an array of one token with an array, and a single token request with a single token", async () => {
    const h = await createServerHarness({ unvalidated: true });

    const array = await h.signedCall(
      h.baseUrl,
      json("POST", { client: WALLET, access_token: [{ label: "only", access: [incoming] }] }),
    );

    const single = await h.signedCall(
      h.baseUrl,
      json("POST", { client: WALLET, access_token: { label: "only", access: [incoming] } }),
    );

    expect(Array.isArray((await jsonBody<{ access_token: unknown }>(array)).access_token)).toBe(true);
    expect(Array.isArray((await jsonBody<{ access_token: unknown }>(single)).access_token)).toBe(false);
  });

  it("rotating one token keeps its own access and label, not the whole grant's", async () => {
    const h = await createServerHarness({ unvalidated: true });
    const grant = await h.signedCall(h.baseUrl, json("POST", twoTokens));
    const [, quotes] = (await jsonBody<{ access_token: ReadonlyArray<WireToken> }>(grant)).access_token;

    const rotated = await h.signedCall(quotes?.manage ?? "", withToken({ method: "POST" }, quotes?.value ?? ""));

    const { access_token: next } = await jsonBody<{ access_token: WireToken }>(rotated);

    expect(rotated.status).toBe(200);
    expect(next).toMatchObject({ label: "quotes", access: [quote] });
    expect(await introspect(h, next.value, [incoming])).toMatchObject({ active: true, access: [] });
    expect(await introspect(h, quotes?.value ?? "", [quote])).toEqual({ active: false });
  });

  it("revoking the grant revokes every token of it", async () => {
    const h = await createServerHarness({ unvalidated: true });
    const grant = await h.signedCall(h.baseUrl, json("POST", twoTokens));

    const body = await jsonBody<{
      access_token: ReadonlyArray<WireToken>;
      continue: { uri: string; access_token: { value: string } };
    }>(grant);

    const cancelled = await h.signedCall(
      body.continue.uri,
      withToken({ method: "DELETE" }, body.continue.access_token.value),
    );

    expect(cancelled.status).toBe(204);

    for (const { value } of body.access_token) {
      expect(await introspect(h, value, [incoming, quote])).toEqual({ active: false });
    }
  });

  it("after the owner's consent hands out every token at once, the grant showing the union to approve", async () => {
    const h = await createServerHarness({ unvalidated: true });

    const pending = await startGrant(h, {
      client: WALLET,
      interact,
      access_token: [
        { label: "pay", access: [outgoing] },
        { label: "in", access: [incoming] },
      ],
    });

    const details = await h.call(
      new Request(`${h.baseUrl}/grant/${pending.interactId}/${pending.nonce}`, {
        headers: { "x-idp-secret": "idp-secret" },
      }),
    );

    expect((await jsonBody<{ access: unknown[] }>(details)).access).toEqual([outgoing, incoming]);

    const { interactRef } = await approve(h, pending);

    h.clock.advance(6);
    const granted = await continueWith(h, pending, { interact_ref: interactRef });
    const { access_token: tokens } = await jsonBody<{ access_token: ReadonlyArray<WireToken> }>(granted);

    expect(tokens.map(({ label, access }) => ({ label, access }))).toEqual([
      { label: "pay", access: [outgoing] },
      { label: "in", access: [incoming] },
    ]);

    // The token for incoming payments cannot spend: the consent to `outgoing` belongs to the other token.
    expect(await introspect(h, tokens[1]?.value ?? "", [outgoing])).toMatchObject({ active: true, access: [] });
    expect(await introspect(h, tokens[0]?.value ?? "", [outgoing])).toMatchObject({ active: true, access: [outgoing] });
  });

  it("refuses what RFC 9635 §2.1.2 forbids, and bearer tokens", async () => {
    const h = await createServerHarness({ unvalidated: true });

    const ask = async (accessToken: unknown) =>
      errorOf(await h.signedCall(h.baseUrl, json("POST", { client: WALLET, access_token: accessToken })));

    const invalid = { status: 400, code: "invalid_request" };

    expect(await ask([{ access: [incoming] }, { label: "b", access: [quote] }])).toMatchObject(invalid);

    expect(
      await ask([
        { label: "a", access: [incoming] },
        { label: "a", access: [quote] },
      ]),
    ).toMatchObject(invalid);
    expect(await ask([{ label: "", access: [incoming] }])).toMatchObject(invalid);
    expect(await ask([])).toMatchObject(invalid);
    expect(await ask([{ label: "a", access: [] }])).toMatchObject(invalid);

    expect(
      await ask(Array.from({ length: 11 }, (_, index) => ({ label: `t${index}`, access: [incoming] }))),
    ).toMatchObject({ ...invalid, description: "too many access tokens" });

    expect(await ask([{ label: "a", access: [incoming], flags: ["bearer"] }])).toMatchObject({
      status: 400,
      code: "invalid_flag",
    });
  });

  it("is answered 501 invalid_request by a store without extendedRecords, while single tokens still work", async () => {
    const h = await createServerHarness({ unvalidated: true, store: legacyStore() });

    expect(await errorOf(await h.signedCall(h.baseUrl, json("POST", twoTokens)))).toEqual({
      status: 501,
      code: "invalid_request",
      description: "multiple access tokens not supported",
    });

    const single = await h.signedCall(
      h.baseUrl,
      json("POST", { client: WALLET, access_token: { label: "x", access: [incoming] } }),
    );

    expect(single.status).toBe(200);
    expect(await jsonBody(single)).toMatchObject({ access_token: { label: "x", access: [incoming] } });
  });
});
