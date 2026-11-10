// oxlint-disable anti-slop/no-unknown-parameters, anti-slop/no-unsafe-dictionary-type, anti-slop/no-known-value-widening -- Tests send arbitrary request bodies by design.
/** The owner's decision applies to the request the owner was shown, even when the client replaces it meanwhile. */
import * as Effect from "effect/Effect";
import { describe, expect, it } from "vite-plus/test";
import type { GnapStore, TokenRecord } from "../../src/gnap/server/index";
import { memoryGnapStore } from "../../src/gnap/server/index";
import {
  CONSENT_URL,
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
  type Pending,
  type ServerHarness,
} from "./support";

const WIDER = { ...outgoing, limits: { debitAmount: { value: "99999999", assetCode: "USD", assetScale: 2 } } };

interface Replaced {
  readonly interact: { readonly redirect: string };
}

/** Runs `beforeFirstWrite` once, between the moment a write to one of `states` is computed and the moment it is stored. */
const racingStore = (
  inner: GnapStore,
  states: ReadonlyArray<string>,
  beforeFirstWrite: () => Promise<void>,
): GnapStore => {
  let fired = false;

  return {
    ...inner,
    updateGrant: (id, version, patch) => {
      if (fired || patch.state === undefined || !states.includes(patch.state)) {
        return inner.updateGrant(id, version, patch);
      }

      fired = true;

      return Effect.flatMap(Effect.promise(beforeFirstWrite), () => inner.updateGrant(id, version, patch));
    },
  };
};

const replaceRequest = async (h: ServerHarness, pending: Pending): Promise<Pending> => {
  const response = await h.signedCall(
    pending.continueUri,
    withToken(json("PATCH", { access_token: { access: [WIDER] }, interact }), pending.continueToken),
  );
  const body = await jsonBody<Replaced>(response);
  const [interactId = "", nonce = ""] = new URL(body.interact.redirect).pathname.split("/").slice(-2);

  return { ...pending, interactId, nonce, interactUrl: body.interact.redirect };
};

const setup = async (options: { readonly authorize?: boolean } = {}) => {
  let harness: ServerHarness | undefined;
  let pending: Pending | undefined;
  let replaced: Pending | undefined;

  const store = racingStore(memoryGnapStore(), ["ACCEPTED", "DENIED"], async () => {
    if (harness === undefined || pending === undefined) throw new Error("race fired before the grant was started");

    // The client replaces the pending request with a wider one (a new interaction) while the owner's decision is saved.
    replaced = await replaceRequest(harness, pending);
  });

  harness = await createServerHarness({
    store,
    unvalidated: true,
    ...(options.authorize === true && {
      interaction: { consentUrl: CONSENT_URL, authorize: () => Effect.succeed(true) },
    }),
  });
  pending = await startGrant(harness);

  const newInteraction = async () =>
    Effect.runPromise(
      harness.server.getInteraction({ interactId: replaced?.interactId ?? "", nonce: replaced?.nonce ?? "" }),
    );

  return { h: harness, pending, newInteraction, wasReplaced: () => replaced !== undefined };
};

describe("an owner's decision races with a replaced request", () => {
  it("does not approve the replacement through the identity provider back channel", async () => {
    const { h, pending, newInteraction, wasReplaced } = await setup();

    const response = await idp(h, pending, "accept");

    expect(wasReplaced()).toBe(true);
    expect(response.status).toBe(400);
    expect(await newInteraction()).toMatchObject({ state: "PENDING", access: [WIDER] });
  });

  it("does not approve the replacement through decideInteraction with a signed-in user", async () => {
    const { h, pending, newInteraction, wasReplaced } = await setup({ authorize: true });

    const outcome = await Effect.runPromise(
      Effect.result(
        h.server.decideInteraction({
          interactId: pending.interactId,
          nonce: pending.nonce,
          choice: "accept",
          userId: "alice",
        }),
      ),
    );

    expect(wasReplaced()).toBe(true);
    expect(outcome._tag).toBe("Failure");
    expect(await newInteraction()).toMatchObject({ state: "PENDING", access: [WIDER] });
  });
});

describe("two modifications of one grant race", () => {
  it("refuses the one that was computed from a grant the other changed, instead of overwriting it", async () => {
    const inner = memoryGnapStore();
    let harness: ServerHarness | undefined;
    let first: { continueUri: string; continueToken: string } | undefined;

    // Modification A is computed; before it is stored, modification B replaces the access of the same grant.
    const store = racingStore(inner, ["APPROVED"], async () => {
      if (harness === undefined || first === undefined) throw new Error("race fired before the grant was granted");

      await harness.signedCall(
        first.continueUri,
        withToken(
          json("PATCH", { access_token: { access: [{ type: "quote", actions: ["create"] }] } }),
          first.continueToken,
        ),
      );
    });

    harness = await createServerHarness({ store, unvalidated: true });

    const granted = await jsonBody<{ continue: { uri: string; access_token: { value: string } } }>(
      await harness.signedCall(harness.baseUrl, json("POST", grantBody([incoming]))),
    );

    first = { continueUri: granted.continue.uri, continueToken: granted.continue.access_token.value };

    const responseA = await harness.signedCall(
      first.continueUri,
      withToken(
        json("PATCH", { access_token: { access: [{ type: "quote", actions: ["read"] }] } }),
        first.continueToken,
      ),
    );

    // A saw the grant before B changed it: it must not write its access over B's.
    expect(responseA.status).toBe(401);

    const stored = await Effect.runPromise(
      inner.findGrant("continueId", new URL(first.continueUri).pathname.split("/").at(-1) ?? ""),
    );

    expect(stored?.access).toEqual([{ type: "quote", actions: ["create"] }]);
  });
});

describe("a continuation races with a modification", () => {
  it("does not hand out the tokens of the request the client has just replaced", async () => {
    const inner = memoryGnapStore();
    const issued: TokenRecord[] = [];
    let harness: ServerHarness | undefined;
    let first: { continueUri: string; continueToken: string } | undefined;

    // The poll issues its tokens for the incoming-payment request; before it claims the grant, the client replaces
    // that request with a quote request, which needs no consent and so is approved at once.
    const racing = racingStore(inner, ["FINALIZED"], async () => {
      if (harness === undefined || first === undefined) throw new Error("race fired before the grant was granted");

      await harness.signedCall(
        first.continueUri,
        withToken(
          json("PATCH", { access_token: { access: [{ type: "quote", actions: ["create"] }] } }),
          first.continueToken,
        ),
      );
    });

    const store: GnapStore = {
      ...racing,
      createToken: (record) => {
        issued.push(record);

        return racing.createToken(record);
      },
    };

    harness = await createServerHarness({ store, unvalidated: true });

    const granted = await jsonBody<{ continue: { uri: string; access_token: { value: string } } }>(
      await harness.signedCall(harness.baseUrl, json("POST", grantBody([incoming]))),
    );

    first = { continueUri: granted.continue.uri, continueToken: granted.continue.access_token.value };
    harness.clock.advance(6);

    const polled = await harness.signedCall(first.continueUri, withToken(json("POST"), first.continueToken));

    // The incoming-payment token (the grant's, then the poll's) was issued for a request that no longer stands.
    expect(await errorOf(polled)).toMatchObject({ status: 401, code: "request_denied" });
    expect(issued).toHaveLength(3);

    const [creation, polledToken, replacement] = await Promise.all(
      issued.map((record) => Effect.runPromise(inner.findTokenWithGrant("valueHash", record.valueHash))),
    );

    expect(creation?.token.revokedAt).toBeNull();
    expect(polledToken?.token.revokedAt).not.toBeNull();
    expect(replacement?.token.revokedAt).toBeNull();
    expect(replacement?.token.access).toEqual([{ type: "quote", actions: ["create"] }]);
    expect(replacement?.grant.state).toBe("APPROVED");
  });
});
