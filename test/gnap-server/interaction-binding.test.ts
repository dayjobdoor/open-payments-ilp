// oxlint-disable anti-slop/no-unknown-parameters, anti-slop/no-unsafe-dictionary-type, anti-slop/no-known-value-widening -- Tests send arbitrary request bodies by design.
/**
 * The browser that opens `interact.redirect` is the only one that can finish the interaction, and the only one a
 * signed-in user can decide in: the nonce in the URLs is not a secret (the consent URL carries it).
 */
import * as Effect from "effect/Effect";
import { describe, expect, it } from "vite-plus/test";
import { hashToken } from "../../src/gnap/index";
import { memoryGnapStore, type GnapStore } from "../../src/gnap/server/index";
import {
  CONSENT_URL,
  browserFinish,
  browserStart,
  cookiesOf,
  createServerHarness,
  idp,
  interact,
  json,
  jsonBody,
  outgoing,
  startGrant,
  unboundStore,
  withToken,
  type Pending,
  type ServerHarness,
} from "./support";

const withAuthorize = { interaction: { consentUrl: CONSENT_URL, authorize: () => Effect.succeed(true) } };

const bindingOf = (cookie: string, interactId: string): string | undefined =>
  cookie
    .split("; ")
    .find((pair) => pair.startsWith(`gnap-binding-${interactId}=`))
    ?.slice(`gnap-binding-${interactId}=`.length);

/** A cookie header a hand-made request sends: the nonce cookie anybody who saw the URL can build. */
const nonceCookie = (pending: Pending) => `gnap-interaction-${pending.interactId}=${pending.nonce}`;

const decide = (h: ServerHarness, pending: Pending, binding?: string) =>
  Effect.runPromise(
    Effect.result(
      h.server.decideInteraction({
        interactId: pending.interactId,
        nonce: pending.nonce,
        choice: "accept",
        userId: "victim",
        ...(binding !== undefined && { binding }),
      }),
    ),
  );

describe("interaction binding", () => {
  it("gives the first browser a random secret cookie and stores only its hash", async () => {
    const h = await createServerHarness({ unvalidated: true });
    const pending = await startGrant(h);
    const start = await browserStart(h, pending);
    const secret = bindingOf(start.cookie, pending.interactId);
    const setCookie = start.response.headers.getSetCookie().find((line) => line.startsWith("gnap-binding-")) ?? "";

    expect(secret).toMatch(/^[\w-]{20,}$/);
    expect(secret).not.toBe(pending.nonce);
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("SameSite=Lax");
    expect(setCookie).toContain("Path=/gnap;");

    const stored = await Effect.runPromise(h.store.findGrant("interactId", pending.interactId));

    expect(stored?.interactBinding).toBe(await Effect.runPromise(hashToken(secret ?? "")));
    expect(JSON.stringify(stored)).not.toContain(secret ?? "-");
  });

  it("keeps the first binding: a second browser gets none, and the first one keeps its own on a reload", async () => {
    const h = await createServerHarness({ unvalidated: true });
    const pending = await startGrant(h);
    const first = await browserStart(h, pending);
    const second = await browserStart(h, pending);
    const reload = await h.call(
      new Request(pending.interactUrl, { redirect: "manual", headers: { cookie: first.cookie } }),
    );

    expect(second.response.status).toBe(302);
    expect(bindingOf(second.cookie, pending.interactId)).toBeUndefined();
    expect(bindingOf(cookiesOf(reload), pending.interactId)).toBe(bindingOf(first.cookie, pending.interactId));
  });

  it("refuses /finish to a browser that only knows the nonce, even after the owner approved", async () => {
    const h = await createServerHarness({ unvalidated: true });
    const pending = await startGrant(h);
    const start = await browserStart(h, pending);

    expect((await idp(h, pending, "accept")).status).toBe(202);

    const forged = await browserFinish(h, pending, nonceCookie(pending));
    const genuine = await browserFinish(h, pending, start.cookie);

    expect(forged.status).toBe(401);
    expect(forged.headers.get("location")).toBeNull();
    expect(genuine.status).toBe(302);
    expect(new URL(genuine.headers.get("location") ?? "").searchParams.get("interact_ref")).toBeTruthy();
  });

  it("refuses /finish for an interaction nobody opened, nonce cookie or not", async () => {
    const h = await createServerHarness({ unvalidated: true });
    const pending = await startGrant(h);

    expect((await idp(h, pending, "accept")).status).toBe(202);
    expect((await browserFinish(h, pending, nonceCookie(pending))).status).toBe(401);
  });

  it("does not let the attacker collect the grant a victim approved through the consent URL", async () => {
    const h = await createServerHarness({ unvalidated: true, ...withAuthorize });
    const pending = await startGrant(h);
    // The attacker's browser is the one the client sent to `interact.redirect`: it holds the binding.
    const attacker = await browserStart(h, pending);

    // The victim opens the consent URL (id and nonce are in it) in another browser and approves there.
    const victimDecision = await decide(h, pending);

    expect(victimDecision._tag).toBe("Failure");
    expect(
      await jsonBody<{ state: string }>(await idp(h, pending, "reject").then(() => idpDetails(h, pending))),
    ).toMatchObject({
      state: "DENIED",
    });

    // Nothing was approved by the victim, so the attacker has nothing to collect.
    const stored = await Effect.runPromise(h.store.findGrant("interactId", pending.interactId));

    expect(stored?.userId).toBeNull();
    expect((await browserFinish(h, pending, attacker.cookie)).status).not.toBe(200);
  });

  it("lets the user decide in the browser that opened the interaction", async () => {
    const h = await createServerHarness({ unvalidated: true, ...withAuthorize });
    const pending = await startGrant(h);
    const start = await browserStart(h, pending);
    const binding = bindingOf(start.cookie, pending.interactId);

    expect((await decide(h, pending, "wrong-secret"))._tag).toBe("Failure");
    expect((await decide(h, pending, binding))._tag).toBe("Success");
    expect((await browserFinish(h, pending, start.cookie)).status).toBe(302);
  });

  it("starts a replaced interaction unbound", async () => {
    const h = await createServerHarness({ unvalidated: true });
    const pending = await startGrant(h);
    const old = await browserStart(h, pending);

    const response = await h.signedCall(
      pending.continueUri,
      withToken(json("PATCH", { access_token: { access: [outgoing] }, interact }), pending.continueToken),
    );
    const body = await jsonBody<{ interact: { redirect: string } }>(response);
    const [interactId = "", nonce = ""] = new URL(body.interact.redirect).pathname.split("/").slice(-2);
    const replaced: Pending = { ...pending, interactId, nonce, interactUrl: body.interact.redirect };

    expect((await Effect.runPromise(h.store.findGrant("interactId", interactId)))?.interactBinding).toBeNull();
    // The old browser's secret is for the old interaction; the new one needs its own visit.
    const fresh = await browserStart(h, replaced);

    expect((await idp(h, replaced, "accept")).status).toBe(202);
    expect((await browserFinish(h, replaced, old.cookie)).status).toBe(401);
    expect((await browserFinish(h, replaced, fresh.cookie)).status).toBe(302);
  });

  it("is answered 500 and told to onError when the store cannot record the binding at start", async () => {
    const causes: unknown[] = [];
    const inner = memoryGnapStore();
    let failing = false;
    const store: GnapStore = {
      ...inner,
      updateGrant: (id, version, patch) =>
        failing ? Effect.die(new Error("db down")) : inner.updateGrant(id, version, patch),
    };
    const h = await createServerHarness({
      unvalidated: true,
      store,
      onError: (cause) => Effect.sync(() => void causes.push(cause)),
    });
    const pending = await startGrant(h);

    failing = true;

    expect((await browserStart(h, pending)).response.status).toBe(500);
    expect(causes).toHaveLength(1);
  });

  it("keeps Rafiki's nonce-cookie check for a store that does not persist the binding", async () => {
    const h = await createServerHarness({ unvalidated: true, store: unboundStore() });
    const pending = await startGrant(h);
    const start = await browserStart(h, pending);

    expect(bindingOf(start.cookie, pending.interactId)).toBeUndefined();
    expect((await idp(h, pending, "accept")).status).toBe(202);
    expect((await browserFinish(h, pending, nonceCookie(pending))).status).toBe(302);
  });
});

const idpDetails = (h: ServerHarness, pending: Pending) =>
  h.call(
    new Request(`${h.baseUrl}/grant/${pending.interactId}/${pending.nonce}`, {
      headers: { "x-idp-secret": "idp-secret" },
    }),
  );
