import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { createRequire } from "node:module";
import { Effect } from "effect";
import { describe, expect, it } from "vite-plus/test";
import { importEd25519PrivateJwk, signRequest, verifyRequest } from "../../src/http-signatures";

// The reference implementation is a transitive dependency of @interledger/open-payments.
const requireFromOpenPayments = createRequire(createRequire(import.meta.url).resolve("@interledger/open-payments"));

const reference: {
  createHeaders: (args: {
    request: { method: string; url: string; headers: Record<string, string>; body?: string };
    privateKey: KeyObject;
    keyId: string;
  }) => Promise<Record<string, string>>;
  validateSignature: (
    key: JsonWebKey,
    request: { method: string; url: string; headers: Record<string, string>; body?: unknown },
  ) => Promise<boolean>;
  validateSignatureHeaders: (request: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: unknown;
  }) => boolean;
} = requireFromOpenPayments("@interledger/http-signature-utils");

const keyId = "interop-key";

const pair = generateKeyPairSync("ed25519");

const publicJwk = pair.publicKey.export({ format: "jwk" });

const privateJwk = pair.privateKey.export({ format: "jwk" });

const clock = () => new Date();

const url = "https://auth.example.com/grant?x=1";

function lowercased(headers: Headers): Record<string, string> {
  return Object.fromEntries([...headers].map(([name, value]) => [name.toLowerCase(), value]));
}

const resolveKey = () => Effect.succeed(publicJwk);

describe("signing with this library, verifying with @interledger/http-signature-utils", () => {
  it("accepts a signed JSON POST carrying Authorization", async () => {
    const privateKey = await Effect.runPromise(importEd25519PrivateJwk(privateJwk));
    const body = JSON.stringify({ access_token: { access: [{ type: "incoming-payment", actions: ["create"] }] } });

    const signed = await Effect.runPromise(
      signRequest(
        new Request(url, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: "GNAP t" },
          body,
        }),
        { keyId, privateKey },
      ),
    );

    const headers = lowercased(signed.headers);
    expect(headers["signature-input"]).toContain('"authorization" "content-digest" "content-length" "content-type"');
    const request = { method: "POST", url, headers, body };

    expect(reference.validateSignatureHeaders(request)).toBe(true);
    expect(await reference.validateSignature(publicJwk, request)).toBe(true);
  });

  it("accepts a signed GET without body", async () => {
    const privateKey = await Effect.runPromise(importEd25519PrivateJwk(privateJwk));
    const signed = await Effect.runPromise(signRequest(new Request(url), { keyId, privateKey }));
    const request = { method: "GET", url, headers: lowercased(signed.headers) };

    expect(await reference.validateSignature(publicJwk, request)).toBe(true);
  });
});

describe("signing with @interledger/http-signature-utils, verifying with this library", () => {
  it("accepts a JSON POST with Authorization", async () => {
    const body = JSON.stringify({ hello: "world" });
    const request = { method: "POST", url, headers: { Authorization: "GNAP t" }, body };
    const headers = await reference.createHeaders({ request, privateKey: pair.privateKey, keyId });

    const verified = await Effect.runPromise(
      verifyRequest(new Request(url, { method: "POST", headers: { Authorization: "GNAP t", ...headers }, body }), {
        resolveKey,
        clock,
        requiredComponents: ["@method", "@target-uri", "authorization"],
      }),
    );

    expect(verified.keyId).toBe(keyId);
    expect(verified.components).toEqual([
      "@method",
      "@target-uri",
      "authorization",
      "content-digest",
      "content-length",
      "content-type",
    ]);
  });

  it("accepts a GET", async () => {
    const headers = await reference.createHeaders({
      request: { method: "GET", url, headers: {} },
      privateKey: pair.privateKey,
      keyId,
    });

    const verified = await Effect.runPromise(verifyRequest(new Request(url, { headers }), { resolveKey, clock }));

    expect(verified.components).toEqual(["@method", "@target-uri"]);
  });

  it("rejects a body swapped after signing", async () => {
    const body = JSON.stringify({ hello: "world" });

    const headers = await reference.createHeaders({
      request: { method: "POST", url, headers: {}, body },
      privateKey: pair.privateKey,
      keyId,
    });

    const error = await Effect.runPromise(
      Effect.flip(
        verifyRequest(new Request(url, { method: "POST", headers, body: JSON.stringify({ hello: "evil" }) }), {
          resolveKey,
          clock,
        }),
      ),
    );

    expect(error.reason).toBe("digest-mismatch");
  });
});

describe("tampered requests are rejected by this library and by @interledger/http-signature-utils alike", () => {
  const body = JSON.stringify({ hello: "world" });

  type Sent = { method: string; url: string; headers: Record<string, string>; body: string };

  /** A request the reference signer produced, with the signed fields exposed so a test can alter one of them. */
  async function signed(): Promise<Sent> {
    const headers = await reference.createHeaders({
      request: { method: "POST", url, headers: { Authorization: "GNAP t" }, body },
      privateKey: pair.privateKey,
      keyId,
    });

    return { method: "POST", url, headers: { authorization: "GNAP t", ...lowercased(new Headers(headers)) }, body };
  }

  const tampers: ReadonlyArray<readonly [string, (request: Sent) => Sent]> = [
    ["another method", (request) => ({ ...request, method: "PUT" })],
    ["another target URI", (request) => ({ ...request, url: `${url}&evil=1` })],
    [
      "another Authorization value",
      (request) => ({ ...request, headers: { ...request.headers, authorization: "GNAP x" } }),
    ],
    [
      "a flipped signature bit",
      (request) => ({
        ...request,
        headers: {
          ...request.headers,
          signature: (request.headers["signature"] ?? "").replace(
            /^(sig1=:.{5})(.)/,
            (_, head: string, bit: string) => head + (bit === "A" ? "B" : "A"),
          ),
        },
      }),
    ],
  ];

  it.each(tampers)("with %s", async (_name, tamper) => {
    const request = tamper(await signed());

    const theirs = await reference.validateSignature(publicJwk, request);

    const ours = await Effect.runPromise(
      verifyRequest(
        new Request(request.url, { method: request.method, headers: request.headers, body: request.body }),
        {
          resolveKey,
          clock,
        },
      ).pipe(
        Effect.as(true),
        Effect.catch(() => Effect.succeed(false)),
      ),
    );

    expect([theirs, ours]).toEqual([false, false]);
  });
});
