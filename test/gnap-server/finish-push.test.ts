// oxlint-disable anti-slop/no-unknown-parameters, anti-slop/no-unsafe-dictionary-type, anti-slop/no-known-value-widening -- Tests send arbitrary, including malformed, request bodies by design.
/** RFC 9635 §2.5.2.2 / §4.2.2: with `finish.method: "push"` the server POSTs `hash` and `interact_ref` to the client. */
import * as Effect from "effect/Effect";
import * as Cause from "effect/Cause";
import { afterEach, describe, expect, it, vi } from "vite-plus/test";
import { verifyInteractionHash } from "../../src/gnap/index";
import {
  BASE_URL,
  browserFinish,
  browserStart,
  continueWith,
  createServerHarness,
  errorOf,
  grantBody,
  idp,
  json,
  legacyStore,
  outgoing,
  startGrant,
  unboundStore,
  type HarnessOptions,
  type ServerHarness,
} from "./support";

const PUSH_URI = "https://client.test/push/554321";

const pushInteract = (uri: string = PUSH_URI) => ({
  start: ["redirect"],
  finish: { method: "push", uri, nonce: "client-nonce" },
});

interface Push {
  readonly url: string;
  readonly init: RequestInit | undefined;
}

/** A client that records what the server pushes and answers with `answer`. */
const pushingClient = (
  answer: (push: Push) => Response | Promise<Response> = () => new Response(null, { status: 204 }),
) => {
  const pushes: Push[] = [];

  return {
    pushes,
    outbound: (url: string, init: RequestInit | undefined) => {
      pushes.push({ url, init });

      return answer({ url, init });
    },
  };
};

/** The grant is decided by the owner and the browser comes back to `/finish`: returns that last response. */
const decideAndFinish = async (
  h: ServerHarness,
  pending: Awaited<ReturnType<typeof startGrant>>,
  choice = "accept",
) => {
  const { cookie } = await browserStart(h, pending);

  expect((await idp(h, pending, choice)).status).toBe(202);

  return browserFinish(h, pending, cookie);
};

const withPush = async (options: HarnessOptions = {}) => {
  const client = pushingClient();
  const h = await createServerHarness({ unvalidated: true, outbound: client.outbound, ...options });
  const pending = await startGrant(h, grantBody([outgoing], { interact: pushInteract() }));

  return { h, pending, client };
};

describe("interact.finish.method push (RFC 9635 §4.2.2)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("POSTs the interact_ref and a hash the client verifies, then the client continues with them", async () => {
    const { h, pending, client } = await withPush();

    const finish = await decideAndFinish(h, pending);

    // The browser is not redirected anywhere: the client is told over the back channel.
    expect(finish.status).toBe(202);
    expect(finish.headers.get("location")).toBeNull();
    expect(client.pushes).toHaveLength(1);

    const [push] = client.pushes;
    const payload: { hash: string; interact_ref: string } = JSON.parse(await new Response(push?.init?.body).text());

    expect(push?.url).toBe(PUSH_URI);
    expect(push?.init?.method).toBe("POST");
    expect(new Headers(push?.init?.headers).get("content-type")).toBe("application/json");
    expect(Object.keys(payload).sort()).toEqual(["hash", "interact_ref"]);

    expect(
      await Effect.runPromise(
        verifyInteractionHash({
          clientNonce: "client-nonce",
          serverNonce: pending.nonce,
          interactRef: payload.interact_ref,
          grantEndpoint: BASE_URL,
          hash: payload.hash,
        }),
      ),
    ).toBe(true);

    h.clock.advance(6);
    const granted = await continueWith(h, pending, { interact_ref: payload.interact_ref });

    expect(granted.status).toBe(200);
    expect(await granted.json()).toMatchObject({ access_token: { access: [outgoing] } });
  });

  it("never follows a redirect of the client: the request asks for it to be refused", async () => {
    const { h, pending, client } = await withPush();

    await decideAndFinish(h, pending);

    expect(client.pushes[0]?.init?.redirect).toBe("manual");
  });

  it("pushes again when the bound browser comes back before the client continued, with the same payload", async () => {
    const { h, pending, client } = await withPush();
    const { cookie } = await browserStart(h, pending);

    await idp(h, pending, "accept");
    await browserFinish(h, pending, cookie);
    const again = await browserFinish(h, pending, cookie);

    expect(again.status).toBe(202);
    expect(client.pushes).toHaveLength(2);
    expect(client.pushes[1]?.init?.body).toEqual(client.pushes[0]?.init?.body);
  });

  it("repeats a push that failed: the client gets its interact_ref on the next visit", async () => {
    let up = false;
    const answers: number[] = [];
    const client = pushingClient(() => {
      const status = up ? 204 : 503;

      answers.push(status);

      return new Response(null, { status });
    });
    const h = await createServerHarness({ unvalidated: true, outbound: client.outbound });
    const pending = await startGrant(h, grantBody([outgoing], { interact: pushInteract() }));
    const { cookie } = await browserStart(h, pending);

    await idp(h, pending, "accept");
    await browserFinish(h, pending, cookie);
    up = true;
    await browserFinish(h, pending, cookie);

    expect(answers).toEqual([503, 204]);
  });

  it("does not push again for a browser that is not the bound one", async () => {
    const { h, pending, client } = await withPush();
    const { cookie } = await browserStart(h, pending);

    await idp(h, pending, "accept");
    await browserFinish(h, pending, cookie);
    const stranger = await browserFinish(h, pending, `gnap-interaction-${pending.interactId}=${pending.nonce}`);

    expect(stranger.status).toBe(401);
    expect(client.pushes).toHaveLength(1);
  });

  it("pushes once for a store without interactionBinding: nobody is bound, so a visit alone does not resend", async () => {
    const { h, pending, client } = await withPush({ store: unboundStore() });
    const { cookie } = await browserStart(h, pending);

    await idp(h, pending, "accept");
    await browserFinish(h, pending, cookie);
    const again = await browserFinish(h, pending, cookie);

    expect(again.status).toBe(202);
    expect(client.pushes).toHaveLength(1);
  });

  it("does not send the browser of a push client to its push endpoint when the interaction cannot start", async () => {
    const { h, pending, client } = await withPush();

    h.clock.advance(601);
    const start = await browserStart(h, pending);

    expect(start.response.status).toBe(403);
    expect(start.location).toBe("");
    expect(client.pushes).toHaveLength(0);
  });

  it("does not push a refusal, and does not push before the owner decided", async () => {
    const { h, pending, client } = await withPush();
    const { cookie } = await browserStart(h, pending);

    const early = await browserFinish(h, pending, cookie);

    expect(early.status).toBe(401);
    expect(await errorOf(early)).toMatchObject({ code: "invalid_interaction" });

    await idp(h, pending, "reject");
    const finish = await browserFinish(h, pending, cookie);

    expect(finish.status).toBe(202);
    expect(client.pushes).toHaveLength(0);
  });

  it.each([
    ["the client is down", () => Promise.reject(new TypeError("fetch failed https://client.test/push/554321"))],
    ["the client answers 500", () => new Response("boom", { status: 500 })],
    [
      "the client answers with a redirect",
      () => new Response(null, { status: 302, headers: { location: "https://elsewhere.test/" } }),
    ],
  ])("keeps the owner's decision and tells onError, when %s", async (_name, answer) => {
    const client = pushingClient(answer);
    const causes: Cause.Cause<never>[] = [];

    const h = await createServerHarness({
      unvalidated: true,
      outbound: client.outbound,
      onError: (cause) =>
        Effect.sync(() => {
          causes.push(cause);
        }),
    });

    const pending = await startGrant(h, grantBody([outgoing], { interact: pushInteract() }));
    const finish = await decideAndFinish(h, pending);

    expect(finish.status).toBe(202);
    expect(client.pushes).toHaveLength(1);
    expect(causes).toHaveLength(1);

    // What `onError` gets names the reason and never the client's URL or the payload.
    const text = Cause.pretty(causes[0] ?? Cause.die("none"));

    expect(text).toContain("finish push failed");
    expect(text).not.toContain("client.test");

    expect(await Effect.runPromise(h.server.getInteraction(pending))).toMatchObject({ state: "APPROVED" });
  });

  it("gives up on a client that does not answer within 5 seconds, and tells onError", async () => {
    const deadline = new AbortController();
    const timeouts: number[] = [];

    // The deadline of every `AbortSignal.timeout` is the one this test fires, when the push is under way.
    vi.spyOn(AbortSignal, "timeout").mockImplementation((milliseconds) => {
      timeouts.push(milliseconds);

      return deadline.signal;
    });

    const client = pushingClient(
      ({ init }) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(init.signal?.reason), { once: true });
          deadline.abort(new DOMException("The operation timed out", "TimeoutError"));
        }),
    );

    const causes: Cause.Cause<never>[] = [];

    const h = await createServerHarness({
      unvalidated: true,
      outbound: client.outbound,
      onError: (cause) =>
        Effect.sync(() => {
          causes.push(cause);
        }),
    });

    const pending = await startGrant(h, grantBody([outgoing], { interact: pushInteract() }));
    const finish = await decideAndFinish(h, pending);

    expect(finish.status).toBe(202);
    expect(timeouts.at(-1)).toBe(5000);
    expect(causes).toHaveLength(1);
    expect(Cause.pretty(causes[0] ?? Cause.die("none"))).toContain("timed out");
  });

  it("is not made for a URL the server must not contact: refused at the grant request", async () => {
    const h = await createServerHarness({ unvalidated: true, outbound: pushingClient().outbound });

    for (const uri of [
      "http://client.test/push",
      "https://127.0.0.1/push",
      "https://localhost/push",
      "https://printer.local/push",
      "https://user:pw@client.test/push",
      "https://client.test/push#fragment",
      "not a url",
    ]) {
      const response = await h.signedCall(
        h.baseUrl,
        json("POST", grantBody([outgoing], { interact: pushInteract(uri) })),
      );

      expect(await errorOf(response)).toEqual({
        status: 400,
        code: "invalid_request",
        description: "invalid interact.finish",
      });
    }

    // Ordinary query strings are fine: a client may route pushes by `?session=…`.
    const ok = await h.signedCall(
      h.baseUrl,
      json("POST", grantBody([outgoing], { interact: pushInteract("https://client.test/push?session=1") })),
    );

    expect(ok.status).toBe(200);
  });

  it("is answered 501 invalid_request by a store without extendedRecords, redirect finish unaffected", async () => {
    const h = await createServerHarness({
      unvalidated: true,
      store: legacyStore(),
      outbound: pushingClient().outbound,
    });

    expect(
      await errorOf(await h.signedCall(h.baseUrl, json("POST", grantBody([outgoing], { interact: pushInteract() })))),
    ).toEqual({ status: 501, code: "invalid_request", description: "finish method push not supported" });

    const pending = await startGrant(h);

    expect((await idp(h, pending, "accept")).status).toBe(202);
  });

  it("cannot be polled: a push client waits for the push, as a redirect client waits for the redirect", async () => {
    const { h, pending } = await withPush();

    h.clock.advance(6);

    expect(await errorOf(await continueWith(h, pending))).toMatchObject({ status: 401, code: "request_denied" });
  });
});
