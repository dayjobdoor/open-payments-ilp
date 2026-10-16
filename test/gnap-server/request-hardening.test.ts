import * as Effect from "effect/Effect";
import { describe, expect, it } from "vite-plus/test";
import { signRequest } from "../../src/http-signatures/index";
import {
  BASE_URL,
  clientJwk,
  createClientKey,
  createServerHarness,
  errorOf,
  grantBody,
  incoming,
  seedGrant,
  seedToken,
  withToken,
  type ClientKey,
} from "./support";

/** 64 zero bytes: a well-formed signature value that no key ever produced. */
const GARBAGE_SIGNATURE = `:${"A".repeat(86)}==:`;

const NOT_UTF8 = new Uint8Array([0xc3, 0x28]);

const JSON_HEADERS = { "content-type": "application/json" };

/** A server that counts how often it is asked for the client's keys. */
const countingHarness = async () => {
  const key = await createClientKey();
  const lookups = { count: 0 };

  const h = await createServerHarness({
    unvalidated: true,
    resolveClientKeys: () =>
      Effect.sync(() => {
        lookups.count += 1;

        return [clientJwk(key)];
      }),
  });

  return { h, key, lookups };
};

/**
 * A signed grant request whose `Signature` / `Signature-Input` carry one entry per label: the genuine signature
 * under `validLabel` (none when undefined), garbage under every other.
 */
const withLabels = async (key: ClientKey, labels: ReadonlyArray<string>, validLabel: string | undefined) => {
  const text = JSON.stringify(grantBody([incoming]));

  const signed = await Effect.runPromise(
    signRequest(new Request(BASE_URL, { method: "POST", body: text, headers: JSON_HEADERS }), key.signingKey),
  );

  const input = /^sig1=(.*)$/.exec(signed.headers.get("signature-input") ?? "")?.[1] ?? "";
  const signature = /^sig1=(.*)$/.exec(signed.headers.get("signature") ?? "")?.[1] ?? "";
  const headers = new Headers(signed.headers);

  headers.set("signature-input", labels.map((label) => `${label}=${input}`).join(", "));

  headers.set(
    "signature",
    labels.map((label) => `${label}=${label === validLabel ? signature : GARBAGE_SIGNATURE}`).join(", "),
  );

  return new Request(BASE_URL, { method: "POST", body: text, headers });
};

describe("signatures of one request", () => {
  it("cost one key lookup however many of them are tried", async () => {
    const { h, key, lookups } = await countingHarness();
    const response = await h.call(await withLabels(key, ["sig1", "sig2", "sig3"], undefined));

    expect(await errorOf(response)).toMatchObject({ status: 401, code: "invalid_client" });
    expect(lookups.count).toBe(1);
  });

  it("are only the first three of the header", async () => {
    const { h, key } = await countingHarness();
    const labels = ["sig1", "sig2", "sig3", "sig4"];

    expect((await h.call(await withLabels(key, labels, "sig3"))).status).toBe(200);

    const beyond = await h.call(await withLabels(key, labels, "sig4"));

    expect(await errorOf(beyond)).toMatchObject({ status: 401, code: "invalid_client" });
  });
});

describe("a request body that is not UTF-8", () => {
  it("is a 400 for a grant request, not a server error", async () => {
    const h = await createServerHarness({ unvalidated: true });
    const response = await h.call(new Request(BASE_URL, { method: "POST", body: NOT_UTF8, headers: JSON_HEADERS }));

    expect(await errorOf(response)).toMatchObject({ status: 400, code: "invalid_request" });
  });

  it("is a 400 for a token rotation, not a server error", async () => {
    const h = await createServerHarness({ unvalidated: true });
    const { grant } = await seedGrant(h, { state: "FINALIZED" });
    const token = await seedToken(h, grant);

    const response = await h.signedCall(
      token.manage,
      withToken({ method: "POST", body: NOT_UTF8, headers: JSON_HEADERS }, token.value),
    );

    expect(await errorOf(response)).toMatchObject({ status: 400, code: "invalid_request" });
  });
});

describe("a request to no route", () => {
  it("is a 404 that must not be cached (RFC 9635 §3)", async () => {
    const h = await createServerHarness({ unvalidated: true });
    const response = await h.call(new Request(`${BASE_URL}/no-such-route`));

    expect(response.status).toBe(404);
    expect(response.headers.get("cache-control")).toBe("no-store");
  });
});
