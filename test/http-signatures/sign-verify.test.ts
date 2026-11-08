import { Effect, type Result } from "effect";
import { describe, expect, it } from "vite-plus/test";
import {
  HttpSignatureError,
  SIGNATURE_REPLAY_WINDOW_SECONDS,
  createSignatureBase,
  exportPublicJwk,
  generateEd25519KeyPair,
  importEd25519PrivateJwk,
  serializeSignatureParams,
  signRequest,
  verifyRequest,
} from "../../src/http-signatures";
import { encodeBase64, utf8Encode } from "../../src/internal/bytes";

const created = new Date("2026-01-01T00:00:00Z");

const at = (seconds: number) => () => new Date(created.getTime() + seconds * 1000);

const url = "https://rs.example.com/incoming-payments?limit=2";

async function setup() {
  const { privateKey, publicJwk } = await Effect.runPromise(generateEd25519KeyPair());

  return { key: { keyId: "k1", privateKey }, publicJwk };
}

async function sign(init: RequestInit, extra: { tag?: string } = {}) {
  const { key, publicJwk } = await setup();
  const request = await Effect.runPromise(signRequest(new Request(url, init), key, { created, ...extra }));

  return { request, publicJwk, key };
}

function verify(request: Request, publicJwk: JsonWebKey, options: Partial<Parameters<typeof verifyRequest>[1]> = {}) {
  return Effect.runPromise(
    Effect.result(verifyRequest(request, { resolveKey: () => Effect.succeed(publicJwk), clock: at(10), ...options })),
  );
}

function failureOf<A>(result: Result.Result<A, HttpSignatureError>): string | undefined {
  return result._tag === "Failure" ? result.failure.reason : undefined;
}

describe("signRequest", () => {
  it("covers authorization and body headers and sets digest and length", async () => {
    const { request } = await sign({
      method: "POST",
      headers: { Authorization: "GNAP t", "Content-Type": "application/json" },
      body: '{"a":1}',
    });

    expect(request.headers.get("Signature-Input")).toBe(
      'sig1=("@method" "@target-uri" "authorization" "content-digest" "content-length" "content-type");created=1767225600;keyid="k1"',
    );
    expect(request.headers.get("Content-Length")).toBe("7");
    expect(request.headers.get("Content-Digest")).toMatch(/^sha-512=:[A-Za-z0-9+/]{86}==:$/);
    expect(await request.text()).toBe('{"a":1}');
  });

  it("covers only method and target for a bare GET and records the tag", async () => {
    const { request } = await sign({}, { tag: "open-payments" });

    expect(request.headers.get("Signature-Input")).toBe(
      'sig1=("@method" "@target-uri");created=1767225600;keyid="k1";tag="open-payments"',
    );
    expect(request.headers.has("Content-Digest")).toBe(false);
  });

  it("fails for a keyid that cannot be serialized", async () => {
    const { key } = await setup();
    const result = await Effect.runPromise(Effect.result(signRequest(new Request(url), { ...key, keyId: "ключ" })));

    expect(failureOf(result)).toBe("malformed");
  });
});

describe("verifyRequest", () => {
  it("round-trips a signed request and returns what was signed", async () => {
    const { request, publicJwk } = await sign({ method: "POST", body: "x", headers: { "Content-Type": "text/plain" } });
    const result = await verify(request, publicJwk);

    expect(result).toMatchObject({
      _tag: "Success",
      success: {
        keyId: "k1",
        label: "sig1",
        created,
        components: ["@method", "@target-uri", "content-digest", "content-length", "content-type"],
      },
    });
  });

  it("exportPublicJwk emits kty/crv/x only, and a public JWK is not a signing key", async () => {
    const { privateKey } = await Effect.runPromise(generateEd25519KeyPair());
    const publicJwk = await Effect.runPromise(exportPublicJwk(privateKey));
    expect(Object.keys(publicJwk).sort()).toEqual(["crv", "kty", "x"]);
    await expect(Effect.runPromise(importEd25519PrivateJwk(publicJwk))).rejects.toBeInstanceOf(HttpSignatureError);
  });

  it("rejects a signature from another key", async () => {
    const { request } = await sign({});
    const other = await setup();

    expect(failureOf(await verify(request, other.publicJwk))).toBe("invalid");
  });

  it("rejects a tampered URL", async () => {
    const { request, publicJwk } = await sign({});
    const moved = new Request("https://rs.example.com/outgoing-payments", { headers: request.headers });

    expect(failureOf(await verify(moved, publicJwk))).toBe("invalid");
  });

  it("rejects a body swapped after signing", async () => {
    const { request, publicJwk } = await sign({ method: "POST", body: "a" });
    const swapped = new Request(url, { method: "POST", headers: request.headers, body: "b" });

    expect(failureOf(await verify(swapped, publicJwk))).toBe("digest-mismatch");
  });

  it("rejects a body the signature does not cover", async () => {
    const { request, publicJwk } = await sign({});
    const withBody = new Request(url, { method: "POST", headers: request.headers, body: "evil" });

    expect(failureOf(await verify(withBody, publicJwk))).toBe("digest-mismatch");
  });

  it("requires Authorization to be covered whenever the request carries it", async () => {
    const { request, publicJwk } = await sign({});
    const headers = new Headers(request.headers);
    headers.set("Authorization", "GNAP other");

    expect(failureOf(await verify(new Request(url, { headers }), publicJwk))).toBe("invalid");
  });

  it("enforces requiredComponents", async () => {
    const { request, publicJwk } = await sign({});

    expect(failureOf(await verify(request, publicJwk, { requiredComponents: ["@method", "authorization"] }))).toBe(
      "invalid",
    );
  });

  it("rejects a request whose covered header was removed in transit", async () => {
    const { request, publicJwk } = await sign({ headers: { Authorization: "GNAP token" } });
    const headers = new Headers(request.headers);
    headers.delete("Authorization");

    expect(failureOf(await verify(new Request(url, { headers }), publicJwk))).toBe("missing");
  });

  it("accepts a signature exactly at the maximum age and skew, and rejects one second beyond", async () => {
    const { request, publicJwk } = await sign({});

    expect(failureOf(await verify(request, publicJwk, { clock: at(300) }))).toBe(undefined);
    expect(failureOf(await verify(request, publicJwk, { clock: at(301) }))).toBe("expired");
    expect(failureOf(await verify(request, publicJwk, { clock: at(301), maxAgeSeconds: 400 }))).toBe(undefined);
    expect(failureOf(await verify(request, publicJwk, { clock: at(-30) }))).toBe(undefined);
    expect(failureOf(await verify(request, publicJwk, { clock: at(-31) }))).toBe("invalid");
  });

  describe("signature parameters", () => {
    const createdSeconds = created.getTime() / 1000;

    /** Signs a bare GET with the given extra parameters (which `signRequest` cannot emit). */
    async function signedWith(extra: ReadonlyArray<readonly [string, string | number]>) {
      const { key, publicJwk } = await setup();
      const components = ["@method", "@target-uri"];

      const params: ReadonlyArray<readonly [string, string | number]> = [
        ["created", createdSeconds],
        ["keyid", key.keyId],
        ...extra,
      ];

      const base = await Effect.runPromise(
        Effect.fromResult(createSignatureBase({ method: "GET", url, headers: new Headers() }, components, params)),
      );

      const value = await Effect.runPromise(Effect.fromResult(serializeSignatureParams(components, params)));
      const signature = await crypto.subtle.sign("Ed25519", key.privateKey, utf8Encode(base));

      const request = new Request(url, {
        headers: { "Signature-Input": `sig1=${value}`, Signature: `sig1=:${encodeBase64(new Uint8Array(signature))}:` },
      });

      return { request, publicJwk };
    }

    it("accepts an expires that is now or later and rejects one in the past", async () => {
      const { request, publicJwk } = await signedWith([["expires", createdSeconds + 10]]);

      expect(failureOf(await verify(request, publicJwk, { clock: at(9) }))).toBe(undefined);
      expect(failureOf(await verify(request, publicJwk, { clock: at(10) }))).toBe(undefined);
      expect(failureOf(await verify(request, publicJwk, { clock: at(11) }))).toBe("expired");
    });

    it("rejects any alg parameter when forbidAlg is set and accepts ed25519 otherwise", async () => {
      const { request, publicJwk } = await signedWith([["alg", "ed25519"]]);

      expect(failureOf(await verify(request, publicJwk))).toBe(undefined);
      expect(failureOf(await verify(request, publicJwk, { forbidAlg: true }))).toBe("invalid");
    });

    it("rejects an empty keyid", async () => {
      const { request, publicJwk } = await signedWith([]);

      const emptied = new Request(url, {
        headers: {
          Signature: request.headers.get("Signature") ?? "",
          "Signature-Input": (request.headers.get("Signature-Input") ?? "").replace('keyid="k1"', 'keyid=""'),
        },
      });

      expect(failureOf(await verify(emptied, publicJwk))).toBe("malformed");
    });

    it.each([["nonce"], ["tag"]])("rejects a %s that is not a string", async (name) => {
      const { request, publicJwk } = await signedWith([[name, 5]]);

      expect(failureOf(await verify(request, publicJwk))).toBe("malformed");
    });
  });

  it("rejects missing headers and missing labels", async () => {
    const { request, publicJwk } = await sign({});

    const noSignature = new Request(url, {
      headers: { "Signature-Input": request.headers.get("Signature-Input") ?? "" },
    });

    const otherLabel = new Request(url, { headers: request.headers });

    expect(failureOf(await verify(noSignature, publicJwk))).toBe("missing");
    expect(failureOf(await verify(otherLabel, publicJwk, { label: "sig2" }))).toBe("missing");
  });

  it("rejects duplicated signature members", async () => {
    const { request, publicJwk } = await sign({});
    const headers = new Headers(request.headers);
    headers.set("Signature", `${request.headers.get("Signature")}, ${request.headers.get("Signature")}`);

    expect(failureOf(await verify(new Request(url, { headers }), publicJwk))).toBe("malformed");
  });

  it("rejects unsupported algorithms and component parameters", async () => {
    const { request, publicJwk } = await sign({});
    const input = request.headers.get("Signature-Input") ?? "";

    const withInput = (value: string) => {
      const headers = new Headers(request.headers);
      headers.set("Signature-Input", value);

      return new Request(url, { headers });
    };

    const withAlg = withInput(`${input};alg="rsa-v1_5-sha256"`);
    const withParam = withInput(input.replace('"@method"', '"@method";req'));

    expect(failureOf(await verify(withAlg, publicJwk))).toBe("unsupported");
    expect(failureOf(await verify(withParam, publicJwk))).toBe("unsupported");
  });

  it("does not resolve the key before structural checks pass", async () => {
    const { request } = await sign({});
    let lookups = 0;

    const result = await Effect.runPromise(
      Effect.result(
        verifyRequest(request, {
          clock: at(1000),
          resolveKey: () => Effect.sync(() => lookups++).pipe(Effect.andThen(Effect.never)),
        }),
      ),
    );

    expect(failureOf(result)).toBe("expired");
    expect(lookups).toBe(0);
  });

  it("propagates the key resolver's error", async () => {
    const { request } = await sign({});
    const error = new HttpSignatureError({ reason: "unknown-key", message: "no such key" });

    const result = await Effect.runPromise(
      Effect.result(verifyRequest(request, { clock: at(1), resolveKey: () => Effect.fail(error) })),
    );

    expect(result).toMatchObject({ _tag: "Failure", failure: error });
  });

  it("leaves the request body readable", async () => {
    const { request, publicJwk } = await sign({ method: "POST", body: "payload" });
    await verify(request, publicJwk);

    expect(await request.text()).toBe("payload");
  });
});

describe("signRequest options", () => {
  it("adds the nonce parameter before the tag, and verifyRequest reports it", async () => {
    const { key, publicJwk } = await setup();

    const request = await Effect.runPromise(
      signRequest(new Request(url), key, { created, nonce: "n-123", tag: "open-payments" }),
    );

    expect(request.headers.get("Signature-Input")).toBe(
      'sig1=("@method" "@target-uri");created=1767225600;keyid="k1";nonce="n-123";tag="open-payments"',
    );
    expect(await verify(request, publicJwk)).toMatchObject({ _tag: "Success", success: { nonce: "n-123" } });
  });

  it("reports no nonce member when the signer sent none", async () => {
    const { request, publicJwk } = await sign({});
    const result = await verify(request, publicJwk);

    expect(result._tag === "Success" && result.success).not.toHaveProperty("nonce");
  });

  it("digests the body with sha-256 on request, and with sha-512 otherwise", async () => {
    const { key, publicJwk } = await setup();
    const init = { method: "POST", body: "payload" };

    const sha256 = await Effect.runPromise(signRequest(new Request(url, init), key, { created, digest: "sha-256" }));
    const sha512 = await Effect.runPromise(signRequest(new Request(url, init), key, { created }));

    expect(sha256.headers.get("Content-Digest")).toMatch(/^sha-256=:[A-Za-z0-9+/]{43}=:$/);
    expect(sha512.headers.get("Content-Digest")).toMatch(/^sha-512=:/);
    expect(failureOf(await verify(sha256, publicJwk))).toBeUndefined();
    expect(failureOf(await verify(sha512, publicJwk))).toBeUndefined();
  });

  it("fails with malformed for a created that is an Invalid Date", async () => {
    const { key } = await setup();

    const result = await Effect.runPromise(
      Effect.result(signRequest(new Request(url), key, { created: new Date(Number.NaN) })),
    );

    expect(failureOf(result)).toBe("malformed");
  });

  it("signs the URL without its fragment, which fetch would not send", async () => {
    const { key, publicJwk } = await setup();
    const withFragment = new Request(`${url}#section`);
    const signed = await Effect.runPromise(signRequest(withFragment, key, { created }));

    expect(withFragment.url).toContain("#section");
    // What a server sees: the same request without the fragment.
    expect(failureOf(await verify(new Request(url, { headers: signed.headers }), publicJwk))).toBeUndefined();
    expect(failureOf(await verify(signed, publicJwk))).toBeUndefined();
  });
});

describe("verifyRequest replay window", () => {
  it("keeps the default window constant and reports the window the verification actually used", async () => {
    const { request, publicJwk } = await sign({});

    expect(SIGNATURE_REPLAY_WINDOW_SECONDS).toBe(331);

    for (const [maxAgeSeconds, window] of [
      [undefined, 331],
      [0, 31],
      [600, 631],
    ] as const) {
      const options = maxAgeSeconds === undefined ? {} : { maxAgeSeconds };

      expect(await verify(request, publicJwk, { ...options, clock: at(0) })).toMatchObject({
        _tag: "Success",
        success: { replayWindowSeconds: window },
      });
    }
  });
});

describe("verifyRequest options", () => {
  it.each([Number.NaN, Number.POSITIVE_INFINITY, -1])(
    "fails with invalid-config instead of skipping the age check for maxAgeSeconds %s",
    async (maxAgeSeconds) => {
      const { request, publicJwk } = await sign({});

      // A signature far older than any window: it must not pass because the limit is unusable.
      expect(failureOf(await verify(request, publicJwk, { maxAgeSeconds, clock: at(100_000) }))).toBe("invalid-config");
    },
  );

  it.each([Number.NaN, Number.POSITIVE_INFINITY, -1])(
    "fails with invalid-config for maxBodyBytes %s",
    async (maxBodyBytes) => {
      const { request, publicJwk } = await sign({});

      expect(failureOf(await verify(request, publicJwk, { maxBodyBytes }))).toBe("invalid-config");
    },
  );

  it("fails with invalid-config instead of skipping the age check when the clock returns an Invalid Date", async () => {
    const { request, publicJwk } = await sign({});

    expect(failureOf(await verify(request, publicJwk, { clock: () => new Date(Number.NaN) }))).toBe("invalid-config");
  });
});

describe("verifyRequest body limit", () => {
  const post = (body: string) => sign({ method: "POST", body, headers: { "Content-Type": "text/plain" } });

  it("accepts a body of exactly maxBodyBytes and refuses one byte more as malformed", async () => {
    const { request, publicJwk } = await post("0123456789");

    expect(failureOf(await verify(request, publicJwk, { maxBodyBytes: 10 }))).toBeUndefined();
    expect(failureOf(await verify(request, publicJwk, { maxBodyBytes: 9 }))).toBe("malformed");
  });

  it("limits the body to 64 KiB by default", async () => {
    const atLimit = await post("x".repeat(64 * 1024));
    const over = await post("x".repeat(64 * 1024 + 1));

    expect(failureOf(await verify(atLimit.request, atLimit.publicJwk))).toBeUndefined();
    expect(failureOf(await verify(over.request, over.publicJwk))).toBe("malformed");
    expect(failureOf(await verify(over.request, over.publicJwk, { maxBodyBytes: 1024 * 1024 }))).toBeUndefined();
  });

  it("stops reading a streamed body that is longer than the limit, whatever Content-Length says", async () => {
    const { key, publicJwk } = await setup();
    const signed = await Effect.runPromise(
      signRequest(new Request(url, { method: "POST", body: "tiny" }), key, { created }),
    );

    let pulls = 0;

    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls++;
        controller.enqueue(new Uint8Array(1024));

        if (pulls === 10_000) controller.close();
      },
    });

    // The signed headers announce 4 bytes; the real body is not that.
    const headers = new Headers(signed.headers);
    const lying = new Request(url, { method: "POST", headers, body: stream, duplex: "half" } as RequestInit);

    expect(failureOf(await verify(lying, publicJwk, { maxBodyBytes: 4096 }))).toBe("malformed");
    expect(pulls).toBeLessThan(100);
  });

  /** A signed POST whose signature covers neither `content-digest` nor a body, then sent with one. */
  async function uncoveredBody(pulled: { count: number }, chunks: number) {
    const { key, publicJwk } = await setup();
    const components = ["@method", "@target-uri"];

    const params: ReadonlyArray<readonly [string, string | number]> = [
      ["created", created.getTime() / 1000],
      ["keyid", key.keyId],
    ];

    const message = { method: "POST", url, headers: new Headers() };
    const base = await Effect.runPromise(Effect.fromResult(createSignatureBase(message, components, params)));
    const value = await Effect.runPromise(Effect.fromResult(serializeSignatureParams(components, params)));
    const signature = await crypto.subtle.sign("Ed25519", key.privateKey, utf8Encode(base));
    let sent = 0;

    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulled.count++;
        controller.enqueue(new Uint8Array(512));

        if (++sent === chunks) controller.close();
      },
    });

    const request = new Request(url, {
      method: "POST",
      headers: { "Signature-Input": `sig1=${value}`, Signature: `sig1=:${encodeBase64(new Uint8Array(signature))}:` },
      body: stream,
      duplex: "half",
    } as RequestInit);

    return { request, publicJwk };
  }

  it("does not read the body at all when no digest check is required", async () => {
    const pulled = { count: 0 };
    const { request, publicJwk } = await uncoveredBody(pulled, 100);

    // Constructing a request primes its stream with one pull; verification must add none.
    const primed = pulled.count;

    expect(await verify(request, publicJwk, { requireBodyDigest: false })).toMatchObject({ _tag: "Success" });
    expect(pulled.count).toBe(primed);
  });

  it("finds out that an uncovered body is not empty without draining it", async () => {
    const pulled = { count: 0 };
    const { request, publicJwk } = await uncoveredBody(pulled, 10_000);

    expect(failureOf(await verify(request, publicJwk))).toBe("digest-mismatch");
    expect(pulled.count).toBeLessThan(10);
  });
});

describe("verifyRequest header shapes", () => {
  const input = 'sig1=("@method" "@target-uri");created=1767225600;keyid="k1"';

  async function withHeaders(headers: { input?: string; signature?: string }) {
    const { request, publicJwk } = await sign({});

    return {
      publicJwk,
      request: new Request(url, {
        headers: {
          "Signature-Input": headers.input ?? request.headers.get("Signature-Input") ?? "",
          Signature: headers.signature ?? request.headers.get("Signature") ?? "",
        },
      }),
    };
  }

  it("starts from a request that verifies, so the cases below fail because of what they change", async () => {
    const { request, publicJwk } = await withHeaders({});

    expect(failureOf(await verify(request, publicJwk))).toBeUndefined();
  });

  it.each([
    ["an item where an inner list is required", "sig1=:AAAA:", "malformed"],
    ["an unterminated inner list", "sig1=(", "malformed"],
    ["a trailing comma", `${input},`, "malformed"],
    ["no created parameter", 'sig1=("@method" "@target-uri");keyid="k1"', "malformed"],
    ["no keyid parameter", 'sig1=("@method" "@target-uri");created=1767225600', "malformed"],
    ["a covered component that is not a string", 'sig1=(5);created=1767225600;keyid="k1"', "malformed"],
    ["a created that is a string", 'sig1=("@method");created="x";keyid="k1"', "malformed"],
    ["a decimal created", 'sig1=("@method");created=1767225600.5;keyid="k1"', "unsupported"],
    ["a binary parameter", `${input};x=:AAAA:`, "unsupported"],
  ])("rejects a Signature-Input with %s", async (_name, value, reason) => {
    const { request, publicJwk } = await withHeaders({ input: value });

    expect(failureOf(await verify(request, publicJwk))).toBe(reason);
  });

  it.each([
    ["a token", "sig1=token", "malformed"],
    ["an inner list", 'sig1=("a")', "malformed"],
    ["an unterminated byte sequence", "sig1=:AAAA", "malformed"],
    ["a byte sequence of the wrong length", "sig1=:AAAA:", "invalid"],
    ["an empty value", "", "missing"],
  ])("rejects a Signature that is %s", async (_name, value, reason) => {
    const { request, publicJwk } = await withHeaders({ signature: value });

    expect(failureOf(await verify(request, publicJwk))).toBe(reason);
  });
});
