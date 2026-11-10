/**
 * Executes the README examples. Every `ts` code block of README.md must appear here verbatim (whitespace and
 * trailing commas aside) with its imports mapped from `open-payments-ilp/<name>` to `src/<name>`, so the
 * README cannot drift from code that type-checks and runs.
 */
import { existsSync, readFileSync } from "node:fs";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { createAuthClient } from "better-auth/client";
import * as Cause from "effect/Cause";
import * as Effect from "effect/Effect";
import { Hono } from "hono";
import * as Result from "effect/Result";
import { describe, expect, it } from "vite-plus/test";
import { gnap, gnapSchema } from "../src/better-auth/index";
import { gnapClient } from "../src/better-auth/client";
import {
  createGnapServer,
  fetchClientKeys,
  memoryGnapStore,
  type GnapStore as ServerGnapStore,
  type GrantPatch,
  type GrantRecord,
  type TokenRecord,
} from "../src/gnap/server/index";
import { storeContract } from "../src/gnap/server/testing/index";
import { computeInteractionHash, extractGnapToken, verifyInteractionHash } from "../src/gnap/index";
import {
  getGnapAuth,
  gnapAuthMiddleware,
  initGnapAuthMiddleware,
  revokeGnapSession,
  type GnapAuthRefreshErrorHook,
} from "../src/hono/index";
import {
  generateEd25519KeyPair,
  SIGNATURE_REPLAY_WINDOW_SECONDS,
  signRequest,
  verifyRequest,
} from "../src/http-signatures/index";
import { deserializeIldcpResponse, serializeIldcpRequest, serveIldcp } from "../src/ildcp/index";
import {
  DEFAULT_ILP_HTTP_MAX_REPLY_BYTES,
  DEFAULT_ILP_HTTP_TIMEOUT_MS,
  deserializePrepare,
  deserializeReply,
  MAX_ILP_DATA_LENGTH,
  postPrepare,
  serializePrepare,
  serializeReply,
} from "../src/ilp/index";
import { addAmounts, createUnauthenticatedClient, parseAmountValue } from "../src/open-payments/index";
import {
  buildStreamPrepare,
  createStreamReply,
  generateStreamCredentials,
  STREAM_ENCRYPTION_OVERHEAD,
} from "../src/stream/index";
import { signWebhook, verifyWebhookSignature } from "../src/webhooks/index";
import { deserializeIlpPrepare, serializeIlpPrepare } from "../src/plain/ilp";
import { createAuthenticatedClient } from "../src/plain/open-payments";
import { encodeBase64 } from "../src/internal/bytes";

/** An Ed25519 key in the two formats the hono examples use as `privateKeyPem` and `privateJwk`. */
const createPrivateKeys = async () => {
  const { privateKey } = await Effect.runPromise(generateEd25519KeyPair());
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", privateKey));

  return {
    privateKeyPem: `-----BEGIN PRIVATE KEY-----\n${encodeBase64(pkcs8)}\n-----END PRIVATE KEY-----`,
    privateJwk: await crypto.subtle.exportKey("jwk", privateKey),
  };
};

// The custom-store README block, run against the memory store.
const freshDatabase = async (): Promise<undefined> => undefined;

const createMyStore = (_database: undefined) => memoryGnapStore();

storeContract({ describe, it }, "my database", async () => createMyStore(await freshDatabase()));

describe("README examples", () => {
  it("ilp", () => {
    const wire = serializePrepare({
      amount: 100n,
      expiresAt: new Date("2030-01-01T00:00:00Z"),
      executionCondition: new Uint8Array(32),
      destination: "g.example.alice",
      data: new Uint8Array(),
    });

    if (Result.isFailure(wire)) throw wire.failure;
    const prepare = deserializePrepare(wire.success);

    expect(Result.isSuccess(prepare) && prepare.success.amount).toBe(100n);
  });

  it("ilp over http", async () => {
    const wire = serializePrepare({
      amount: 100n,
      expiresAt: new Date("2030-01-01T00:00:00Z"),
      executionCondition: new Uint8Array(32),
      destination: "g.example.alice",
      data: new Uint8Array(),
    });

    if (Result.isFailure(wire)) throw wire.failure;
    const token = "secret";
    const realFetch = globalThis.fetch;

    globalThis.fetch = async () =>
      new Response(
        Result.getOrThrow(
          serializeReply({ code: "F99", triggeredBy: "g.example", message: "", data: new Uint8Array() }),
        ),
      );

    try {
      const reply = await Effect.runPromise(postPrepare(wire.success, { url: "https://peer.example/ilp", token }));
      const packet = deserializeReply(reply);

      expect(Result.isSuccess(packet) && "code" in packet.success && packet.success.code).toBe("F99");
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  it("ildcp", () => {
    const request = Result.getOrThrow(serializeIldcpRequest({ expiresAt: new Date(Date.now() + 30_000) }));

    const reply = serveIldcp({
      requestPacket: request,
      serverAddress: "g.example",
      response: { clientAddress: "g.example.client", assetCode: "USD", assetScale: 2 },
      now: new Date(),
    });

    const config = deserializeIldcpResponse(Result.getOrThrow(serializeReply(reply)));

    expect(Result.getOrThrow(config)).toEqual({
      clientAddress: "g.example.client",
      assetScale: 2,
      assetCode: "USD",
    });
  });

  it("stream", async () => {
    const server = {
      serverSecret: crypto.getRandomValues(new Uint8Array(32)),
      serverAddress: "g.example.receiver",
    };

    // Receiver: issue credentials for one payment.
    const { ilpAddress, sharedSecret } = await Effect.runPromise(
      generateStreamCredentials(server, { asset: { code: "USD", scale: 2 } }),
    );

    // Sender: build a Prepare for 500 units.
    const prepare = await Effect.runPromise(
      buildStreamPrepare({
        destination: ilpAddress,
        sharedSecret,
        amount: 500n,
        sequence: 1n,
        sourceAddress: "g.example.sender",
        expiresAt: new Date(Date.now() + 30_000),
      }),
    );

    // Receiver: authenticate the Prepare, then decide.
    const reply = await Effect.runPromise(createStreamReply(server, prepare));
    const fulfill = reply.type === "pending" ? await Effect.runPromise(reply.accept()) : undefined;

    expect(fulfill?.fulfillment).toHaveLength(32);
  });

  it("http-signatures", async () => {
    const { privateKey, publicJwk } = await Effect.runPromise(generateEd25519KeyPair());

    const signed = await Effect.runPromise(
      signRequest(new Request("https://wallet.example/quotes", { method: "POST", body: '{"hello":"world"}' }), {
        keyId: "key-1",
        privateKey,
      }),
    );

    const verified = await Effect.runPromise(verifyRequest(signed, { resolveKey: () => Effect.succeed(publicJwk) }));

    expect(verified.keyId).toBe("key-1");
  });

  it("open-payments", async () => {
    const total = addAmounts(
      { value: "100", assetCode: "USD", assetScale: 2 },
      { value: "250", assetCode: "USD", assetScale: 2 },
    );

    const client = createUnauthenticatedClient({
      fetch: async () =>
        Response.json({
          id: "https://wallet.example/alice",
          assetCode: "USD",
          assetScale: 2,
          authServer: "https://auth.example",
          resourceServer: "https://wallet.example",
        }),
    });

    const wallet = await Effect.runPromise(client.walletAddress.get({ url: "https://wallet.example/alice" }));

    expect(Result.getOrThrow(total).value).toBe("350");
    expect(Result.getOrThrow(parseAmountValue("350"))).toBe(350n);
    expect(wallet.authServer).toBe("https://auth.example");
  });

  it("gnap", async () => {
    const input = {
      clientNonce: "client-nonce",
      serverNonce: "server-nonce",
      interactRef: "ref-1",
      grantEndpoint: "https://auth.example/",
    };

    const hash = await Effect.runPromise(computeInteractionHash(input));
    const ok = await Effect.runPromise(verifyInteractionHash({ ...input, hash }));
    const token = extractGnapToken("GNAP abc123");

    expect(ok).toBe(true);
    expect(token).toBe("abc123");
  });

  it("gnap server", async () => {
    const server = createGnapServer({
      baseUrl: "https://auth.example/gnap",
      store: memoryGnapStore(),
      interaction: { consentUrl: "https://app.example/consent" },
      idpSecret: "change-me-to-a-random-secret",
    });

    const response = await Effect.runPromise(
      server.route(new Request("https://auth.example/gnap/continue/unknown", { method: "POST" })),
    );

    expect(response.status).toBe(401);
  });

  it("gnap server, observing failures", async () => {
    const fetchKeys = fetchClientKeys(globalThis.fetch);

    const observed = createGnapServer({
      baseUrl: "https://auth.example/gnap",
      store: memoryGnapStore(),
      onError: (cause) => Effect.sync(() => console.error("gnap failure", Cause.pretty(cause))),
      resolveClientKeys: (walletAddress) =>
        fetchKeys(walletAddress).pipe(
          Effect.tapError((error) => Effect.sync(() => console.warn("gnap keys", walletAddress, error.cause))),
        ),
    });

    const response = await Effect.runPromise(
      observed.route(new Request("https://auth.example/gnap/nowhere", { method: "POST" })),
    );

    expect(response.status).toBe(404);
  });

  it("better-auth server", async () => {
    // Yours: whether the user owns the wallet address.
    const owns = (userId: string, walletAddress?: string): boolean => walletAddress?.endsWith(`/${userId}`) === true;

    const auth = betterAuth({
      // Replace with your database adapter and run the Better Auth migration to create the GNAP tables.
      database: memoryAdapter({
        user: [],
        session: [],
        account: [],
        verification: [],
        gnapGrant: [],
        gnapAccessToken: [],
        gnapNonce: [],
      }),
      baseURL: "https://auth.example",
      secret: "change-me-to-a-random-secret-of-32-or-more-characters",
      emailAndPassword: { enabled: true },
      plugins: [
        gnap({
          interaction: {
            consentUrl: "https://app.example/consent",
            // Required for consent by a signed-in user: without it every decision is refused.
            authorize: ({ userId, details }) => {
              const named = [
                ...details.access.map((item) => ("identifier" in item ? item.identifier : undefined)),
                ...(details.subject?.sub_ids.map((subId) => subId.id) ?? []),
              ];

              return Effect.succeed(named.length > 0 && named.every((address) => owns(userId, address)));
            },
          },
        }),
      ],
    });

    expect(await auth.api.gnapIntrospect({ body: { access_token: "unknown" } })).toEqual({ active: false });
  });

  it("better-auth client", () => {
    // On the consent page, after sign-in: await authClient.gnap.acceptInteraction(interactId, nonce)
    const authClient = createAuthClient({ baseURL: "https://auth.example", plugins: [gnapClient()] });

    expect(authClient.gnap.acceptInteraction).toBeInstanceOf(Function);
  });

  it("hono, Open Payments / Rafiki", async () => {
    const { privateKeyPem } = await createPrivateKeys();
    const app = new Hono();

    app.use(
      "*",
      initGnapAuthMiddleware({
        secret: "a-session-secret-of-at-least-32-characters",
        externalUrl: "https://app.example",
        grantEndpoint: "https://auth.wallet.example",
        access: [{ type: "incoming-payment", actions: ["create", "read"] }],
        client: "https://wallet.example/alice",
        keyId: "my-key-1",
        privateKey: privateKeyPem,
      }),
    );

    app.post("/logout", async (c) => {
      await revokeGnapSession(c);

      return c.text("You have been logged out");
    });

    app.use("*", gnapAuthMiddleware());

    app.get("/", async (c) => {
      const auth = await getGnapAuth(c);

      return c.text(`Access token: ${auth?.accessToken}`);
    });

    expect(await (await app.request("https://app.example/logout", { method: "POST" })).text()).toBe(
      "You have been logged out",
    );
  });

  it("hono, RFC 9635", async () => {
    const { privateJwk } = await createPrivateKeys();
    const app = new Hono();

    app.use(
      "*",
      initGnapAuthMiddleware({
        secret: "a-session-secret-of-at-least-32-characters",
        externalUrl: "https://app.example",
        grantEndpoint: "https://as.example/gnap",
        access: [{ type: "outgoing-payment", actions: ["read"], identifier: "https://wallet.example/alice" }],
        keyId: "my-key-1",
        privateJwk,
      }),
    );

    app.use("*", gnapAuthMiddleware());

    // No request is made: the key is used when the middleware talks to the server (covered by test/hono).
    expect((await app.request("https://app.example/", { method: "POST" })).status).toBe(401);
  });

  it("hono, refresh error hook", async () => {
    const app = new Hono();

    const gnapAuthRefreshErrorHook: GnapAuthRefreshErrorHook = (error) => {
      console.warn(`GNAP rotation refused: ${error.status} ${error.code}`);
    };

    app.use("*", async (c, next) => {
      c.set("gnapAuthRefreshErrorHook", gnapAuthRefreshErrorHook);
      await next();
    });

    // Runs the middleware chain: it only stores the hook for the refresh code, so a request reaches the 404.
    expect((await app.request("https://app.example/")).status).toBe(404);
  });

  it("webhooks", async () => {
    const config = { secret: "shared-secret" };
    const event = { id: "evt-1", type: "incoming_payment.completed", data: { id: "ip-1" } };
    const header = await Effect.runPromise(signWebhook(event, config));

    await Effect.runPromise(verifyWebhookSignature(event, header, config));

    expect(header).toMatch(/^t=\d+, v1=[0-9a-f]{64}$/);
  });
});

describe("README is in sync with this file", () => {
  // Whitespace and a trailing comma before a closing bracket are formatting; everything else must match, token for
  // token (`a b` is not `ab`).
  // A backtick outside a template literal unbalances the pairing below: write it as `\x60` in a regex.
  const tokens = (text: string): string[] => {
    const all = text.match(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`|\w+|[^\s\w]/g) ?? [];

    return all.filter((token, index) => !(token === "," && [")", "}", "]"].includes(all[index + 1] ?? "")));
  };

  const contains = (haystack: string[], needle: string[]): boolean =>
    needle.length > 0 &&
    haystack.some((_, start) => needle.every((token, offset) => haystack[start + offset] === token));

  const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");

  const source = readFileSync(new URL(import.meta.url), "utf8");

  const blocks = [...readme.matchAll(/```ts\n([\s\S]*?)```/g)].map((match) => match[1]!);

  const manifest: { exports: object; peerDependencies: Record<string, string> } = JSON.parse(
    readFileSync(new URL("../package.json", import.meta.url), "utf8"),
  );

  const exported = Object.keys(manifest.exports);

  // Named imports of this file, per module specifier.
  const available = new Map<string, Set<string>>();

  for (const [, names, specifier] of source.matchAll(/import\s+(?:type\s+)?\{([^}]*)\}\s+from\s+"([^"]+)"/g)) {
    available.set(specifier!, new Set(names!.split(",").map((name) => name.trim().replace(/^type\s+/, ""))));
  }

  it("compares tokens, not characters", () => {
    expect(contains(tokens("const ab = f(a, b,)"), tokens("const ab = f(a, b)"))).toBe(true);
    expect(contains(tokens("const a b = 1"), tokens("const ab = 1"))).toBe(false);
    expect(contains(tokens("f(1, 2)"), tokens("f(1, 3)"))).toBe(false);
  });

  it("lists the tables of gnapSchema", () => {
    const sentence = /migration to create the \w+ tables \(([^)]*)\)/.exec(readme)?.[1] ?? "";

    expect([...sentence.matchAll(/`(gnap[A-Z]\w*)`/g)].map((match) => match[1]).sort()).toEqual(
      Object.keys(gnapSchema).sort(),
    );
  });

  const flatReadme = readme.replace(/\s+/g, " ");

  // The `### open-payments-ilp/<subpath>` sections of the README, by subpath.
  const sections = new Map<string, string>();

  for (const part of readme.split(/\n(?=#{2,3} )/)) {
    const subpath = /^### \x60open-payments-ilp\/([^\x60]+)\x60/.exec(part)?.[1];

    if (subpath !== undefined) sections.set(subpath, part);
  }

  // The contract kit has no heading of its own: the `/gnap/server` section describes it.
  const sectionOf = (subpath: string): string =>
    sections.get(subpath === "gnap/server/testing" ? "gnap/server" : subpath) ?? "";

  const entries = {
    ilp: () => import("../src/ilp/index"),
    ildcp: () => import("../src/ildcp/index"),
    stream: () => import("../src/stream/index"),
    "http-signatures": () => import("../src/http-signatures/index"),
    "open-payments": () => import("../src/open-payments/index"),
    gnap: () => import("../src/gnap/index"),
    "gnap/server": () => import("../src/gnap/server/index"),
    "gnap/server/testing": () => import("../src/gnap/server/testing/index"),
    webhooks: () => import("../src/webhooks/index"),
    "better-auth": () => import("../src/better-auth/index"),
    "better-auth/client": () => import("../src/better-auth/client"),
    hono: () => import("../src/hono/index"),
  };

  it("documents every exported subpath", () => {
    const plainRows = readme
      .split("\n")
      .filter((line) => line.startsWith("| `/plain/"))
      .join("\n");

    for (const key of exported.filter((subpath) => subpath !== "./package.json")) {
      const name = key.slice(2);

      if (name.startsWith("plain/")) {
        expect(plainRows, `/${name} in the table of plain entries`).toContain(`\`/${name}\``);
      } else {
        expect(sectionOf(name), `a section for open-payments-ilp/${name}`).toContain(`open-payments-ilp/${name}`);
      }
    }
  });

  it("covers every subpath of the package with an entry for the next test", () => {
    expect(Object.keys(entries).sort()).toEqual(
      exported
        .map((subpath) => subpath.slice(2))
        .filter((name) => name !== "package.json" && !name.startsWith("plain/"))
        .sort(),
    );
  });

  it.each(Object.entries(entries))(
    "names every runtime export of open-payments-ilp/%s in its section",
    async (name, load) => {
      const section = sectionOf(name);
      const unnamed = Object.keys(await load()).filter(
        (exportName) => !new RegExp(`\\b${exportName}\\b`).test(section),
      );

      expect(unnamed).toEqual([]);
    },
  );

  it("links to headings and files that exist", () => {
    // GitHub's anchor of a heading: lower case, punctuation dropped, spaces to hyphens.
    const prose = readme.replace(/\x60{3}[\s\S]*?\x60{3}/g, "");
    const anchors = new Set(
      [...prose.matchAll(/^#{1,6} (.+)$/gm)].map((match) =>
        match[1]!
          .toLowerCase()
          .replace(/[^\w\- ]/g, "")
          .replaceAll(" ", "-"),
      ),
    );

    for (const [, anchor] of prose.matchAll(/\]\(#([^)]+)\)/g)) expect(anchors.has(anchor!), `#${anchor}`).toBe(true);

    for (const [, file] of prose.matchAll(/\]\((?!https?:|#)([^)]+)\)/g)) {
      expect(existsSync(new URL(`../${file}`, import.meta.url)), file).toBe(true);
    }
  });

  it("states the peer dependency ranges of package.json", () => {
    expect(Object.keys(manifest.peerDependencies).length).toBeGreaterThan(0);

    for (const [name, range] of Object.entries(manifest.peerDependencies)) {
      expect(flatReadme, name).toContain(`\`${name}\` (\`${range}\`)`);
    }
  });

  it("states the exported defaults and limits as the code has them", () => {
    expect(SIGNATURE_REPLAY_WINDOW_SECONDS).toBe(331);
    expect(flatReadme).toContain("`SIGNATURE_REPLAY_WINDOW_SECONDS` (331 s");
    expect(DEFAULT_ILP_HTTP_TIMEOUT_MS).toBe(30_000);
    expect(flatReadme).toContain("`timeoutMs` defaults to 30 s");
    expect(DEFAULT_ILP_HTTP_MAX_REPLY_BYTES).toBe(64 * 1024);
    expect(flatReadme).toContain("`maxReplyBytes`, default 64 KiB");
    expect(MAX_ILP_DATA_LENGTH).toBe(32_767);
    expect(flatReadme).toContain("`MAX_ILP_DATA_LENGTH`, 32767");
    expect(STREAM_ENCRYPTION_OVERHEAD).toBe(28);
    expect(flatReadme).toContain("`STREAM_ENCRYPTION_OVERHEAD` of 28 bytes");
  });

  it("shows the GnapStore interface that the server declares", () => {
    type Effect<A> = Effect.Effect<A>;

    interface GnapStore {
      createGrant(grant: GrantRecord): Effect<void>; // `id`, `continueId`, `interactId` unique
      findGrant(by: "id" | "continueId" | "interactId", value: string): Effect<GrantRecord | null>;
      /** Compare-and-set: applies `patch`, increments `version`, and returns true only if `version` still matched. */
      updateGrant(id: string, version: number, patch: GrantPatch): Effect<boolean>;
      createToken(token: TokenRecord): Effect<void>; // `id`, `valueHash`, `managementId` unique
      /** A token (revoked or expired too) with its grant: one lookup, as the server needs both. */
      findTokenWithGrant(
        by: "valueHash" | "managementId",
        value: string,
      ): Effect<{ token: TokenRecord; grant: GrantRecord } | null>;
      /** Sets `revokedAt` on the unrevoked tokens of a token or a grant; returns how many it changed. Atomic. */
      revokeTokens(by: "id" | "grantId", value: string, at: number): Effect<number>;
      /** Replay guard for signature nonces: claims `key` until `expiresAt` unless an unexpired claim exists. Atomic. */
      claimNonce(key: string, expiresAt: number, now: number): Effect<boolean>;
      /** Set to `true` by a store that persists every optional field of the two records (see **Extended records**). */
      extendedRecords?: true;
      /** Set to `true` by a store that persists `GrantRecord.interactBinding` (see **Interaction binding**). */
      interactionBinding?: true;
    }

    // Assignable both ways: a method added, dropped or retyped on either side no longer compiles.
    const asDocumented = (store: ServerGnapStore): GnapStore => store;
    const asDeclared = (store: GnapStore): ServerGnapStore => store;

    expect([asDocumented, asDeclared]).toHaveLength(2);
  });

  it("plain", async () => {
    const wire = serializeIlpPrepare({
      amount: 100n,
      expiresAt: new Date("2030-01-01T00:00:00.000Z"),
      executionCondition: new Uint8Array(32),
      destination: "g.alice",
      data: new Uint8Array(0),
    });
    const prepare = deserializeIlpPrepare(wire); // throws IlpCodecError on malformed bytes

    expect(prepare).toMatchObject({ amount: 100n, destination: "g.alice" });

    const { privateKey } = await Effect.runPromise(generateEd25519KeyPair());
    const accessToken = "TOKEN-123";
    const original = globalThis.fetch;

    globalThis.fetch = async () =>
      Response.json(
        {
          id: "https://wallet.example/rs/incoming-payments/1",
          walletAddress: "https://wallet.example/alice",
          completed: false,
          receivedAmount: { value: "0", assetCode: "USD", assetScale: 2 },
          createdAt: "2022-03-12T23:20:50.52Z",
          methods: [],
        },
        { status: 201 },
      );

    try {
      const client = await createAuthenticatedClient({
        walletAddressUrl: "https://wallet.example/alice",
        keyId: "my-key",
        privateKey, // CryptoKey, private JWK or PKCS#8 PEM string
      });
      const incomingPayment = await client.incomingPayment.create(
        { url: "https://wallet.example/rs", accessToken },
        { walletAddress: "https://wallet.example/alice" },
      );

      expect(incomingPayment.completed).toBe(false);
    } finally {
      globalThis.fetch = original;
    }
  });

  it("has ts blocks", () => {
    expect(blocks.length).toBeGreaterThan(0);
  });

  it.each(blocks.map((block, index) => [index, block] as const))("block %i", (_, block) => {
    const imports = [...block.matchAll(/^import\s[^;]*;$/gm)].map((match) => match[0]);
    const body = block.replace(/^import\s[^;]*;$/gm, "");

    for (const statement of imports) {
      const named = /^import\s+(?:type\s+)?\{([^}]*)\}\s+from\s+"([^"]+)";$/.exec(statement);

      if (!named) {
        // `import * as X from "effect/…"`: must be present verbatim.
        expect(contains(tokens(source), tokens(statement)), statement).toBe(true);
        continue;
      }

      const specifier = named[2]!;

      // The README names the test runner of its readers; this file runs on Vite+.
      const local = specifier
        .replace(/^vitest$/, "vite-plus/test")
        .replace(/^open-payments-ilp\/better-auth\/client$/, "../src/better-auth/client")
        .replace(
          /^open-payments-ilp\/plain\/(.+)$/,
          (_, entry: string) =>
            `../src/plain/${entry.replace(/^gnap\/server(\/testing)?$/, (_m, testing?: string) => `gnap-server${testing ? "-testing" : ""}`)}`,
        )
        .replace(/^open-payments-ilp\/(.+)$/, "../src/$1/index");

      if (specifier.startsWith("open-payments-ilp/")) {
        expect(exported).toContain(`./${specifier.split("/").slice(1).join("/")}`);
      }

      for (const name of named[1]!.split(",").map((item) => item.trim().replace(/^type\s+/, ""))) {
        expect(available.get(local)?.has(name), `${name} imported from ${local}`).toBe(true);
      }
    }

    expect(contains(tokens(source), tokens(body)), "this README block is not written out in this file").toBe(true);
  });
});
