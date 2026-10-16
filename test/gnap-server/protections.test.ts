/** Hardening: request body cap, SSRF-safe key fetch, concurrency of the single-use steps. */
import * as Effect from "effect/Effect";
import { describe, expect, it } from "vite-plus/test";
import { memoryGnapStore } from "../../src/gnap/server/index";
import {
  KEY_ID,
  WALLET,
  approve,
  clientJwk,
  continueWith,
  createClientKey,
  createServerHarness,
  errorOf,
  grantBody,
  incoming,
  json,
  jsonBody,
  startGrant,
  walletFetch,
  withToken,
  type ClientKey,
  type ServerHarness,
} from "./support";

const grantJson = (client: string = WALLET): string => JSON.stringify({ client, access_token: { access: [incoming] } });

const jsonInit = (body: string): RequestInit => ({
  method: "POST",
  body,
  headers: { "content-type": "application/json" },
});

/** A `fetch` that records its calls and answers with `respond`. */
const recordingFetch = (respond: (url: string) => Response | Promise<Response>) => {
  const calls: Array<{ readonly url: string; readonly init: RequestInit | undefined }> = [];

  const fetch: typeof globalThis.fetch = async (input, init) => {
    const url = new Request(input).url;

    calls.push({ url, init });

    return respond(url);
  };

  return { fetch, calls };
};

const grantRequest = (h: ServerHarness, client: string) => h.signedCall(h.baseUrl, jsonInit(grantJson(client)));

describe("request body cap", () => {
  const neverCalled = () => {
    const calls: string[] = [];

    return {
      calls,
      resolveClientKeys: (walletAddress: string) => {
        calls.push(walletAddress);

        return Effect.succeed([]);
      },
    };
  };

  // The OpenAPI documents do not describe 413: these cases are not validated.
  it("answers 413 for an oversized body (Content-Length) before resolving any key", async () => {
    const keys = neverCalled();
    const h = await createServerHarness({ resolveClientKeys: keys.resolveClientKeys, unvalidated: true });
    const response = await h.signedCall(h.baseUrl, jsonInit("x".repeat(70_000)));

    expect(await errorOf(response)).toMatchObject({ status: 413, code: "invalid_request" });
    expect(keys.calls).toEqual([]);
  });

  it("stops reading a streamed body once past the cap", async () => {
    const keys = neverCalled();

    const h = await createServerHarness({
      maxBodyBytes: 100,
      resolveClientKeys: keys.resolveClientKeys,
      unvalidated: true,
    });

    let pulled = 0;

    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulled += 1;
        controller.enqueue(new Uint8Array(50));

        if (pulled === 20) controller.close();
      },
    });

    const init: RequestInit & { duplex: "half" } = {
      method: "POST",
      body,
      duplex: "half",
      headers: { "content-type": "application/json" },
    };

    const response = await h.call(new Request(h.baseUrl, init));

    expect(await errorOf(response)).toMatchObject({ status: 413, code: "invalid_request" });
    expect(pulled).toBeLessThan(20);
    expect(keys.calls).toEqual([]);
  });

  it("accepts a body of exactly maxBodyBytes and refuses one byte more", async () => {
    const body = grantJson();
    const size = new TextEncoder().encode(body).byteLength;

    const exact = await createServerHarness({ maxBodyBytes: size });

    expect((await exact.signedCall(exact.baseUrl, jsonInit(body))).status).toBe(200);

    const tight = await createServerHarness({ maxBodyBytes: size - 1, unvalidated: true });

    expect(await errorOf(await tight.signedCall(tight.baseUrl, jsonInit(body)))).toMatchObject({
      status: 413,
      code: "invalid_request",
    });
  });

  it("caps continuation, cancellation and token management bodies too", async () => {
    const resolved: string[] = [];
    let published: ClientKey[] = [];

    const h = await createServerHarness({
      maxBodyBytes: 200,
      unvalidated: true,
      resolveClientKeys: (walletAddress) => {
        resolved.push(walletAddress);

        return Effect.succeed(published.map(clientJwk));
      },
    });

    published = [h.clientKey];

    const grant = await jsonBody<{
      access_token: { value: string; manage: string };
      continue: { access_token: { value: string }; uri: string };
    }>(await h.signedCall(h.baseUrl, jsonInit(grantJson())));

    const oversized = (url: string, method: string, token: string) =>
      h.signedCall(url, {
        method,
        body: "x".repeat(300),
        headers: { "content-type": "application/json", authorization: `GNAP ${token}` },
      });

    resolved.length = 0;

    for (const response of [
      await oversized(grant.continue.uri, "POST", grant.continue.access_token.value),
      await oversized(grant.continue.uri, "DELETE", grant.continue.access_token.value),
      await oversized(grant.access_token.manage, "POST", grant.access_token.value),
      await oversized(grant.access_token.manage, "DELETE", grant.access_token.value),
    ]) {
      expect(await errorOf(response)).toMatchObject({ status: 413, code: "invalid_request" });
    }

    expect(resolved).toEqual([]);
  });

  it("caps the introspection body before the authorize hook runs", async () => {
    const authorized: Request[] = [];

    const h = await createServerHarness({
      maxBodyBytes: 100,
      unvalidated: true,
      introspection: {
        authorize: (request) => {
          authorized.push(request);

          return Effect.succeed(true);
        },
      },
    });

    const response = await h.call(
      new Request(`${h.baseUrl}/introspect`, jsonInit(JSON.stringify({ access_token: "x".repeat(200) }))),
    );

    expect(await errorOf(response)).toMatchObject({ status: 413, code: "invalid_request" });
    expect(authorized).toEqual([]);
  });

  it("hands the introspection hook the untouched request", async () => {
    let seen = "";

    const h = await createServerHarness({
      introspection: {
        authorize: (request) =>
          Effect.promise(async () => {
            seen = await request.text();

            return true;
          }),
      },
    });

    const body = JSON.stringify({ access_token: "anything" });
    const response = await h.call(new Request(`${h.baseUrl}/introspect`, jsonInit(body)));

    expect(await jsonBody(response)).toEqual({ active: false });
    expect(seen).toBe(body);
  });
});

describe("default client key fetch", () => {
  it("never fetches http, credentialed, IP-literal, local, single-label or trailing-dot wallet addresses", async () => {
    const wallet = recordingFetch(() => new Response("unreachable", { status: 500 }));
    const h = await createServerHarness({ fetch: wallet.fetch });

    for (const client of [
      "http://wallet.test/alice",
      "https://user:secret@wallet.test/alice",
      "https://127.0.0.1/alice",
      "https://169.254.169.254/latest",
      "https://2130706433/alice",
      "https://0x7f.1/alice",
      "https://[::1]/alice",
      "https://[2001:db8::1]/alice",
      "https://localhost/alice",
      "https://app.localhost/alice",
      "https://printer.local/alice",
      "https://db.internal/alice",
      "https://intranet/alice",
      "https://wallet.test./alice",
    ]) {
      expect(await errorOf(await grantRequest(h, client))).toMatchObject({ status: 400, code: "invalid_client" });
    }

    expect(wallet.calls).toEqual([]);
  });

  it("fetches the keys without following redirects", async () => {
    let keys: ClientKey[] = [];
    const wallet = recordingFetch((url) => walletFetch(keys)(url));
    const h = await createServerHarness({ fetch: wallet.fetch });

    keys = [h.clientKey];

    expect((await grantRequest(h, WALLET)).status).toBe(200);
    expect(wallet.calls.map((call) => call.url)).toEqual([`${WALLET}/jwks.json`]);
    expect(wallet.calls[0]?.init?.redirect).toBe("manual");
  });

  it("builds the key URL from the parsed address: a query or fragment is refused, a trailing slash is not", async () => {
    const wallet = recordingFetch((url) => walletFetch([])(url));
    const h = await createServerHarness({ fetch: wallet.fetch });

    for (const client of [`${WALLET}?x=`, `${WALLET}#x`]) {
      expect(await errorOf(await grantRequest(h, client))).toMatchObject({ status: 400, code: "invalid_client" });
    }

    expect(wallet.calls).toEqual([]);
    await grantRequest(h, `${WALLET}/`);
    expect(wallet.calls.map((call) => call.url)).toEqual([`${WALLET}/jwks.json`]);
  });

  it("treats a redirect as a failure", async () => {
    const wallet = recordingFetch(
      () => new Response(null, { status: 302, headers: { location: "https://169.254.169.254/jwks.json" } }),
    );

    const h = await createServerHarness({ fetch: wallet.fetch });

    expect(await errorOf(await grantRequest(h, WALLET))).toMatchObject({ status: 400, code: "invalid_client" });
    expect(wallet.calls).toHaveLength(1);
  });

  it("rejects a key set larger than 64 KiB, announced or streamed", async () => {
    const key = await createClientKey();
    const jwk = clientJwk(key);

    const announced = recordingFetch(() =>
      Response.json({ keys: [jwk] }, { headers: { "content-length": String(70_000) } }),
    );

    const streamed = recordingFetch(() => Response.json({ keys: [jwk], padding: "x".repeat(70_000) }));

    for (const wallet of [announced, streamed]) {
      const h = await createServerHarness({ fetch: wallet.fetch });

      expect(await errorOf(await grantRequest(h, WALLET))).toMatchObject({ status: 400, code: "invalid_client" });
    }
  });
});

describe("authentication of the wallet's key", () => {
  it("only trusts the key whose kid is the signature's keyid", async () => {
    const h = await createServerHarness();
    const other = await createClientKey("not-published");

    expect(
      await errorOf(await h.signedCall(h.baseUrl, json("POST", grantBody([incoming])), other.signingKey)),
    ).toMatchObject({
      status: 400,
      code: "invalid_client",
    });
  });

  it("refuses a signature made with another key under the published keyid", async () => {
    const h = await createServerHarness();
    const impostor = await createClientKey(KEY_ID);

    expect(
      await errorOf(await h.signedCall(h.baseUrl, json("POST", grantBody([incoming])), impostor.signingKey)),
    ).toMatchObject({
      status: 401,
      code: "invalid_client",
    });
  });

  it("refuses a token management request that presents another token", async () => {
    const h = await createServerHarness();

    const issue = async () =>
      (
        await jsonBody<{ access_token: { value: string; manage: string } }>(
          await h.signedCall(h.baseUrl, json("POST", grantBody([incoming]))),
        )
      ).access_token;

    const first = await issue();
    const second = await issue();
    const crossed = await h.signedCall(first.manage, withToken({ method: "POST" }, second.value));

    expect(await errorOf(crossed)).toMatchObject({ status: 401, code: "invalid_client" });
  });
});

describe("single-use steps under concurrency", () => {
  it("of concurrent continues with one interact_ref exactly one gets the access token, and no other token stays active", async () => {
    const inner = memoryGnapStore();
    const issued: string[] = [];

    const h = await createServerHarness({
      store: {
        ...inner,
        createToken: (token) => {
          issued.push(token.managementId);

          return inner.createToken(token);
        },
      },
    });

    const pending = await startGrant(h);
    const { interactRef } = await approve(h, pending);

    h.clock.advance(6);

    const responses = await Promise.all(
      Array.from({ length: 4 }, () => continueWith(h, pending, { interact_ref: interactRef })),
    );

    expect(responses.filter((response) => response.status === 200)).toHaveLength(1);

    // Whatever the losing attempts issued was revoked again: exactly one issued token is still valid.
    const found = await Promise.all(
      issued.map((managementId) => Effect.runPromise(inner.findTokenWithGrant("managementId", managementId))),
    );

    expect(found.filter((entry) => entry !== null && entry.token.revokedAt === null)).toHaveLength(1);
  });

  it("of two concurrent decisions exactly one is recorded", async () => {
    const h = await createServerHarness();
    const pending = await startGrant(h);

    const decide = (choice: string) =>
      h.call(
        new Request(`${h.baseUrl}/grant/${pending.interactId}/${pending.nonce}/${choice}`, {
          method: "POST",
          headers: { "x-idp-secret": "idp-secret" },
        }),
      );

    const statuses = (await Promise.all([decide("accept"), decide("reject")]))
      .map((response) => response.status)
      .sort((left, right) => left - right);

    expect(statuses).toEqual([202, 400]);
  });
});
