// oxlint-disable anti-slop/no-unknown-parameters, anti-slop/no-unsafe-dictionary-type, anti-slop/no-known-value-widening -- Tests send arbitrary, including malformed, request bodies by design.
import * as Effect from "effect/Effect";
import { hashToken, type AccessItem } from "../../src/gnap/index";
import {
  createGnapServer,
  memoryGnapStore,
  type GnapServerConfig,
  type GnapStore,
  type GrantRecord,
  type TokenRecord,
} from "../../src/gnap/server/index";
import { generateEd25519KeyPair, signRequest, type SigningKey } from "../../src/http-signatures/index";
import { expectConformsToSpec } from "./openapi";

export const BASE_URL = "https://as.test/gnap";

export const WALLET = "https://wallet.test/alice";

export const KEY_ID = "alice-key-1";

export const CONSENT_URL = "https://app.test/consent";

export const FINISH_URI = "https://client.test/finish";

export const IDP_SECRET = "idp-secret";

/** A client key pair; the public half is published as the JWKS of `WALLET`. */
export interface ClientKey {
  readonly signingKey: SigningKey;
  readonly publicJwk: JsonWebKey;
}

export const createClientKey = async (keyId = KEY_ID): Promise<ClientKey> => {
  const { privateKey, publicJwk } = await Effect.runPromise(generateEd25519KeyPair());

  return { signingKey: { keyId, privateKey }, publicJwk };
};

/** The client's public key as the JWK a wallet address publishes (and a JWK client sends inline). */
export const clientJwk = (key: ClientKey) =>
  ({
    kty: "OKP",
    crv: "Ed25519",
    x: key.publicJwk.x ?? "",
    kid: key.signingKey.keyId,
    alg: "EdDSA",
    use: "sig",
  }) as const;

/** Wallet address JWKS as a `fetch`: `GET {WALLET}/jwks.json`. */
export const walletFetch =
  (keys: ReadonlyArray<ClientKey>): typeof globalThis.fetch =>
  async (input) => {
    const url = new Request(input).url;

    if (url !== `${WALLET}/jwks.json`) return new Response("not found", { status: 404 });

    return Response.json({ keys: keys.map(clientJwk) });
  };

/** A manually advanced clock. It starts at the real time so that real `created` timestamps in signatures are fresh. */
export const createClock = () => {
  let current = Date.now();

  return {
    now: () => new Date(current),
    advance: (seconds: number) => {
      current += seconds * 1000;
    },
  };
};

/** The JSON body of a response, typed by the caller. */
export const jsonBody = async <T>(response: Response): Promise<T> => response.json();

export const json = (method: string, body?: unknown): RequestInit =>
  body === undefined
    ? { method }
    : { method, body: JSON.stringify(body), headers: { "content-type": "application/json" } };

export const withHeaders = (init: RequestInit, extra: Record<string, string>): RequestInit => {
  const headers = new Headers(init.headers);

  for (const [name, value] of Object.entries(extra)) headers.set(name, value);

  return { ...init, headers };
};

export const withToken = (init: RequestInit, token: string): RequestInit =>
  withHeaders(init, { authorization: `GNAP ${token}` });

export interface HarnessOptions extends Partial<GnapServerConfig> {
  /** Skips the OpenAPI check of responses (for answers the documents do not describe). */
  readonly unvalidated?: boolean;
  /** Configuration the harness provides by default but this test wants absent. */
  readonly without?: ReadonlyArray<"interaction" | "idpSecret">;
  /** Answers the requests the server makes to anything but the wallet's JWKS (the finish push). */
  readonly outbound?: (url: string, init: RequestInit | undefined) => Response | Promise<Response>;
}

/** A store as the ones written before the optional record fields: the same behaviour, without `extendedRecords`. */
export const legacyStore = (): GnapStore => {
  const store = memoryGnapStore();

  return {
    createGrant: store.createGrant,
    findGrant: store.findGrant,
    updateGrant: store.updateGrant,
    createToken: store.createToken,
    findTokenWithGrant: store.findTokenWithGrant,
    revokeTokens: store.revokeTokens,
    claimNonce: store.claimNonce,
  };
};

/**
 * The server on an in-memory store with a controllable clock, the wallet's JWKS served from memory, and every
 * response of `call` validated against the Open Payments OpenAPI documents.
 */
export const createServerHarness = async (options: HarnessOptions = {}) => {
  const { unvalidated = false, without = [], outbound, ...config } = options;
  const clientKey = await createClientKey();
  const clock = createClock();
  const store = config.store ?? memoryGnapStore();
  const keys = walletFetch([clientKey]);

  const server = createGnapServer({
    baseUrl: BASE_URL,
    clock: clock.now,
    fetch:
      outbound === undefined
        ? keys
        : async (input, init) => {
            const url = new Request(input).url;

            return url === `${WALLET}/jwks.json` ? keys(input, init) : outbound(url, init);
          },
    ...(!without.includes("interaction") && { interaction: { consentUrl: CONSENT_URL } }),
    ...(!without.includes("idpSecret") && { idpSecret: IDP_SECRET }),
    ...config,
    store,
  });

  const basePath = new URL(config.baseUrl ?? BASE_URL).pathname;

  /** Sends `request` to the server; throws when the response is not what the OpenAPI documents allow. */
  const call = async (request: Request): Promise<Response> => {
    const response = await Effect.runPromise(server.route(request));

    if (!unvalidated) {
      await expectConformsToSpec(request, new URL(request.url).pathname.slice(basePath.length), response.clone());
    }

    return response;
  };

  /** Signs `init` with `key` (default: the harness client's) and sends it. */
  const signedCall = async (url: string, init: RequestInit, key: SigningKey = clientKey.signingKey) =>
    call(await Effect.runPromise(signRequest(new Request(url, init), key, { created: clock.now() })));

  return { server, store, clock, clientKey, call, signedCall, baseUrl: config.baseUrl ?? BASE_URL };
};

export type ServerHarness = Awaited<ReturnType<typeof createServerHarness>>;

export const amount = { value: "1000", assetCode: "USD", assetScale: 2 };

export const incoming = { type: "incoming-payment", actions: ["create", "read"] };

export const outgoing: Extract<AccessItem, { type: "outgoing-payment" }> = {
  type: "outgoing-payment",
  actions: ["create", "read"],
  identifier: WALLET,
  limits: { debitAmount: amount },
};

export const interact = { start: ["redirect"], finish: { method: "redirect", uri: FINISH_URI, nonce: "client-nonce" } };

type Body = Record<string, unknown>;

export const grantBody = (access: unknown[], extra: Body = {}): Body => ({
  client: WALLET,
  access_token: { access },
  ...extra,
});

export const errorOf = async (
  response: Response,
): Promise<{ status: number; code: string | undefined; description: string | undefined }> => {
  const body = await jsonBody<{ error?: { code?: string; description?: string } }>(response);

  return { status: response.status, code: body.error?.code, description: body.error?.description };
};

export interface Pending {
  readonly interactUrl: string;
  readonly interactId: string;
  readonly nonce: string;
  readonly continueUri: string;
  readonly continueToken: string;
}

/** A signed grant request that must come back as a pending grant. */
export const startGrant = async (
  h: ServerHarness,
  body: Body = grantBody([outgoing], { interact }),
): Promise<Pending> => {
  const response = await h.signedCall(h.baseUrl, json("POST", body));

  const pending = await jsonBody<{
    interact: { redirect: string; finish: string };
    continue: { access_token: { value: string }; uri: string };
  }>(response);

  if (response.status !== 200) throw new Error(`grant request answered ${response.status}`);
  const [interactId = "", nonce = ""] = new URL(pending.interact.redirect).pathname.split("/").slice(-2);

  return {
    interactUrl: pending.interact.redirect,
    interactId,
    nonce,
    continueUri: pending.continue.uri,
    continueToken: pending.continue.access_token.value,
  };
};

/** `x-idp-secret` back channel call. */
export const idp = (
  h: ServerHarness,
  pending: Pick<Pending, "interactId" | "nonce">,
  choice: string,
  secret = IDP_SECRET,
) =>
  h.call(
    new Request(`${h.baseUrl}/grant/${pending.interactId}/${pending.nonce}/${choice}`, {
      method: "POST",
      headers: { "x-idp-secret": secret },
    }),
  );

/** The browser following `interact.redirect`: returns the consent redirect and the session cookie it was given. */
export const browserStart = async (h: ServerHarness, pending: Pending) => {
  const response = await h.call(new Request(pending.interactUrl, { redirect: "manual" }));

  return {
    response,
    location: response.headers.get("location") ?? "",
    cookie: (response.headers.get("set-cookie") ?? "").split(";")[0] ?? "",
  };
};

/** The browser coming back to `/interact/:id/:nonce/finish` with its session cookie. */
export const browserFinish = (h: ServerHarness, pending: Pending, cookie: string) =>
  h.call(
    new Request(`${h.baseUrl}/interact/${pending.interactId}/${pending.nonce}/finish`, {
      redirect: "manual",
      headers: { cookie },
    }),
  );

/** Start, consent through the back channel, finish: returns the `interact_ref` and `hash` of the finish redirect. */
export const approve = async (h: ServerHarness, pending: Pending) => {
  const { cookie } = await browserStart(h, pending);

  expectStatus(await idp(h, pending, "accept"), 202);
  const finish = await browserFinish(h, pending, cookie);
  const back = new URL(finish.headers.get("location") ?? "");

  return {
    finish,
    interactRef: back.searchParams.get("interact_ref") ?? "",
    hash: back.searchParams.get("hash") ?? "",
  };
};

const expectStatus = (response: Response, status: number): void => {
  if (response.status !== status) throw new Error(`expected ${status}, got ${response.status}`);
};

/** Signed continue (POST) with an optional body. */
export const continueWith = (h: ServerHarness, pending: Pending, body?: Body, token = pending.continueToken) =>
  h.signedCall(pending.continueUri, withToken(json("POST", body), token));

/** Rafiki's `generateBaseGrant`: a stored grant in any state, with its secrets known to the test. */
/** The fixed secrets and ids of {@link seedGrant}'s defaults (one seeded grant per harness). */
export const SEED = {
  id: "grant-1",
  interactId: "interact-1",
  nonce: "nonce-1",
  interactRef: "ref-1",
  continueId: "continue-1",
  continueToken: "continue-token-1",
} as const;

export const seedGrant = async (h: ServerHarness, overrides: Partial<GrantRecord> = {}) => {
  const now = h.clock.now().getTime();

  const grant: GrantRecord = {
    id: SEED.id,
    version: 0,
    state: "PENDING",
    tenantId: null,
    client: WALLET,
    jwk: null,
    access: [{ type: "incoming-payment", actions: ["create", "read", "list"], identifier: `${WALLET}/incoming/1` }],
    subject: null,
    interactId: SEED.interactId,
    interactNonce: SEED.nonce,
    interactRef: SEED.interactRef,
    interactExpiresAt: now + 600_000,
    finishUri: FINISH_URI,
    clientNonce: "client-nonce",
    finishHashMethod: null,
    label: null,
    userId: null,
    continueId: SEED.continueId,
    continueTokenHash: await Effect.runPromise(hashToken(SEED.continueToken)),
    // The wait period has passed, as in Rafiki's fake timers.
    lastContinuedAt: now - 6000,
    createdAt: now - 6000,
    updatedAt: now - 6000,
    ...overrides,
  };

  await Effect.runPromise(h.store.createGrant(grant));

  const pending: Pending = {
    interactUrl: `${h.baseUrl}/interact/${SEED.interactId}/${SEED.nonce}`,
    interactId: SEED.interactId,
    nonce: SEED.nonce,
    continueUri: `${h.baseUrl}/continue/${SEED.continueId}`,
    continueToken: SEED.continueToken,
  };

  return { grant, ...pending, pending };
};

/** A stored token of `grant`, as Rafiki's `AccessToken.query().insert`. */
export const seedToken = async (h: ServerHarness, grant: GrantRecord, overrides: Partial<TokenRecord> = {}) => {
  const value = `token-${crypto.randomUUID()}`;
  const now = h.clock.now().getTime();

  const record: TokenRecord = {
    id: crypto.randomUUID(),
    grantId: grant.id,
    valueHash: await Effect.runPromise(hashToken(value)),
    managementId: crypto.randomUUID(),
    expiresAt: now + 600_000,
    revokedAt: null,
    createdAt: now,
    ...overrides,
  };

  await Effect.runPromise(h.store.createToken(record));

  return { value, record, manage: `${BASE_URL}/token/${record.managementId}` };
};
