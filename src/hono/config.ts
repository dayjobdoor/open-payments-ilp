/**
 * Resolves the middleware's configuration: the config passed in, the environment, the defaults, and their checks.
 * @internal Not exported from the public entry point.
 */
import * as Effect from "effect/Effect";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import type { Context } from "hono";
import { env } from "hono/adapter";
import { HTTPException } from "hono/http-exception";
import type { GrantRequestAccessItem } from "../gnap/index";
import { importEd25519PrivateJwk, importEd25519PrivateKeyPem } from "../http-signatures/index";
import type { JWK } from "../open-payments/types";
import { isLoopbackHost } from "../internal/url";
import type { Wire } from "./wire";

/**
 * Configuration; every field but `access`, `requestTimeoutMs` and `encryptCookies` can come from the environment instead
 * (`GNAP_AUTH_SECRET`, `GNAP_GRANT_ENDPOINT`, `GNAP_KEY_ID`, `GNAP_PRIVATE_KEY`, `GNAP_PRIVATE_JWK` (JSON),
 * `GNAP_CLIENT`, `GNAP_REDIRECT_URI`, `GNAP_COOKIE_NAME`, `GNAP_COOKIE_PATH`, `GNAP_COOKIE_DOMAIN`,
 * `GNAP_AUTH_REFRESH_INTERVAL`, `GNAP_AUTH_EXPIRES`, `GNAP_AUTH_EXTERNAL_URL`); configuration passed in wins. The
 * private key is resolved as a unit: passing `privateKey` or `privateJwk` ignores both key variables.
 */
export interface GnapAuthConfig {
  /**
   * Protects the cookies (AES-256-GCM key derived with HKDF, or the HS256 key with `encryptCookies: false`); at least 32
   * characters, random. Changing it logs every user out.
   */
  readonly secret?: string;
  /**
   * Whether the cookies (session, login state and pending-grant pointer) are encrypted with AES-256-GCM, so that the
   * user's browser cannot read the tokens in them. Default `true`; `false` stores them as signed (readable) HS256 JWTs.
   * Switching it, like changing the `secret`, discards the cookies written before: users log in again.
   */
  readonly encryptCookies?: boolean;
  /** The grant endpoint; a function when it is looked up per request (an Open Payments wallet address's `authServer`). */
  readonly grantEndpoint?: string | ((c: Context) => string | Promise<string>);
  /** `access_token.access` of the grant request; a function of the request context for per-user access. */
  readonly access?:
    | ReadonlyArray<GrantRequestAccessItem>
    | ((c: Context) => ReadonlyArray<GrantRequestAccessItem> | Promise<ReadonlyArray<GrantRequestAccessItem>>);
  /**
   * Open Payments / Rafiki: the wallet address URL, whose `jwks.json` publishes the key. Omit for an RFC 9635 server:
   * the grant request then carries the public key inline (`privateJwk` is required).
   */
  readonly client?: string;
  /**
   * `keyid` of the signatures (and `kid` of the inline key). The signing key is read on every request and the session
   * does not remember it: a new `keyId` and `privateKey`/`privateJwk` apply from the next request, without a logout,
   * when the authorisation server accepts the new key for the grants and tokens already issued (see the README).
   */
  readonly keyId?: string;
  /** Ed25519 private key as an unencrypted PKCS #8 PEM (`-----BEGIN PRIVATE KEY-----`). */
  readonly privateKey?: string;
  /** Ed25519 private key as a JWK (with `d`); needed to send the public key inline when there is no `client`. */
  readonly privateJwk?: JsonWebKey;
  /** Where the authorisation server sends the user back; a path or a URL. Default `/callback`. */
  readonly redirectUri?: string;
  /** Default `gnap-auth`. */
  readonly cookieName?: string;
  /** Default `/`. */
  readonly cookiePath?: string;
  readonly cookieDomain?: string;
  /** Seconds between access token rotations. Default 900. Rotation also happens when the token expires sooner. */
  readonly refreshInterval?: number;
  /** Seconds a session lasts. Default 86400; at most 34560000 (400 days, the longest a cookie may live). */
  readonly expires?: number;
  /** Public base URL of the app behind a reverse proxy, with any path prefix. */
  readonly externalUrl?: string;
  /** Default: global `fetch`. */
  readonly fetch?: typeof globalThis.fetch;
  /** Milliseconds after which a request to the authorisation server (answer body included) is aborted. Default 10000. */
  readonly requestTimeoutMs?: number;
  /** Default: `new Date()`. */
  readonly clock?: () => Date;
}

type GnapAuthEnv = {
  GNAP_AUTH_SECRET?: string;
  GNAP_GRANT_ENDPOINT?: string;
  GNAP_KEY_ID?: string;
  GNAP_PRIVATE_KEY?: string;
  GNAP_PRIVATE_JWK?: string;
  GNAP_CLIENT?: string;
  GNAP_REDIRECT_URI?: string;
  GNAP_COOKIE_NAME?: string;
  GNAP_COOKIE_PATH?: string;
  GNAP_COOKIE_DOMAIN?: string;
  GNAP_AUTH_REFRESH_INTERVAL?: string;
  GNAP_AUTH_EXPIRES?: string;
  GNAP_AUTH_EXTERNAL_URL?: string;
};

export const httpError = (status: 400 | 401 | 500 | 502 | 503, message: string): HTTPException =>
  new HTTPException(status, { message });

/** The longest a cookie may live (RFC 6265bis §5.5), and the largest name-and-value browsers store. */
const MAX_COOKIE_SECONDS = 34_560_000;

const privateJwkSchema = Schema.Struct({
  kty: Schema.String,
  crv: Schema.String,
  x: Schema.String,
  d: Schema.String,
});

const decodePrivateJwk = Schema.decodeUnknownResult(privateJwkSchema);

/** `GNAP_PRIVATE_JWK`: an Ed25519 private JWK, or a configuration error (never the parse error: it may quote the key). */
const parseJwkVariable = (text: string | undefined): JsonWebKey | undefined => {
  if (text === undefined) return undefined;
  let json: unknown;

  try {
    json = JSON.parse(text);
  } catch {
    throw httpError(500, "GNAP_PRIVATE_JWK is not valid JSON");
  }

  const decoded = decodePrivateJwk(json);

  if (Result.isFailure(decoded)) throw httpError(500, "GNAP_PRIVATE_JWK must be a JWK with kty, crv, x and d");

  return decoded.success;
};

/** RFC 9635 §2.5.2.1, §4.1.1: front-channel URIs are HTTPS, or local to the user's browser. */
export const isSecureUri = (uri: string): boolean => {
  if (!URL.canParse(uri)) return false;
  const { protocol, hostname } = new URL(uri);

  return protocol === "https:" || (protocol === "http:" && isLoopbackHost(hostname));
};

/** Whether `uri` may be the callback of a grant: RFC 9635 §2.5.2 (absolute, no fragment) and §2.5.2.1 (HTTPS or local). */
export const isCallbackUri = (uri: string): boolean => isSecureUri(uri) && !uri.includes("#");

const isHttpUrl = (value: string): boolean => URL.canParse(value) && /^https?:$/.test(new URL(value).protocol);

/** The signing key as the config or the environment gives it. */
type KeyMaterial = { readonly pem: string } | { readonly jwk: JsonWebKey };

/** The shape of a private key, without importing it (the import is asynchronous). */
const PEM_PKCS8 = /^-----BEGIN PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END PRIVATE KEY-----$/;

/** What the checks look at: every field is optional, and only the ones set are checked. */
type Checked = {
  readonly [
    K in
      | "secret"
      | "refreshInterval"
      | "expires"
      | "requestTimeoutMs"
      | "externalUrl"
      | "redirectUri"
      | "grantEndpoint"
      | "client"
      | "privateKey"
      | "privateJwk"
  ]?: GnapAuthConfig[K] | undefined;
};

/**
 * The one set of checks of the configuration: run on what is passed to `initGnapAuthMiddleware` when it is called, and
 * on the configuration of each request (config and environment merged), where the values the environment provides are
 * seen for the first time. Throws a `500` `HTTPException`; its message never quotes a secret.
 */
export const validateConfig = (config: Checked): void => {
  const { secret, refreshInterval, expires, requestTimeoutMs, externalUrl, redirectUri, grantEndpoint, client } =
    config;

  if (secret !== undefined && secret.length < 32) {
    throw httpError(500, "Session secrets must be at least 32 characters long");
  }

  if ((refreshInterval !== undefined && !(refreshInterval >= 0)) || (expires !== undefined && !(expires > 0))) {
    throw httpError(500, "Invalid refresh interval or expiry");
  }

  if (expires !== undefined && expires > MAX_COOKIE_SECONDS) {
    throw httpError(500, `Session expiry must be at most ${MAX_COOKIE_SECONDS} seconds (400 days)`);
  }

  if (requestTimeoutMs !== undefined && !(requestTimeoutMs > 0 && Number.isFinite(requestTimeoutMs))) {
    throw httpError(500, "Invalid request timeout");
  }

  if (externalUrl !== undefined && !URL.canParse(externalUrl)) {
    throw httpError(500, "The GNAP external URL is invalid. It must be a full URL.");
  }

  if (redirectUri !== undefined && !redirectUri.startsWith("/") && !URL.canParse(redirectUri)) {
    throw httpError(500, "The GNAP redirect URI is invalid. It must be a full URL or an absolute path");
  }

  // Where the callback is known without a request: an absolute URI, or a path below `externalUrl`. A path on the
  // origin of the request is checked when the grant is started.
  const callback =
    redirectUri?.startsWith("/") === false
      ? redirectUri
      : externalUrl === undefined
        ? undefined
        : `${externalUrl.replace(/\/$/, "")}${redirectUri ?? "/callback"}`;

  if (callback !== undefined && URL.canParse(callback) && !isCallbackUri(callback)) {
    throw httpError(500, "The GNAP redirect URI must use HTTPS (or localhost) and have no fragment");
  }

  if (grantEndpoint !== undefined && !(grantEndpoint instanceof Function) && !isHttpUrl(grantEndpoint)) {
    throw httpError(500, "The GNAP grant endpoint must be an http(s) URL");
  }

  if (client !== undefined && !isHttpUrl(client)) {
    throw httpError(500, "The GNAP client must be the http(s) URL of a wallet address");
  }

  const { privateKey, privateJwk } = config;

  if (privateJwk !== undefined) {
    if (privateJwk.kty !== "OKP" || privateJwk.crv !== "Ed25519" || !privateJwk.x || !privateJwk.d) {
      throw httpError(500, "The GNAP private JWK must be an Ed25519 key (kty OKP, crv Ed25519, with x and d)");
    }
  } else if (privateKey !== undefined && !PEM_PKCS8.test(privateKey.trim())) {
    throw httpError(500, "The GNAP private key must be an unencrypted PKCS #8 PEM (-----BEGIN PRIVATE KEY-----)");
  }
};

/** Imports a key, or throws a `500` that names the problem and never the key. */
const importKey = async (material: KeyMaterial): Promise<CryptoKey> => {
  const imported = await Effect.runPromise(
    Effect.result("pem" in material ? importEd25519PrivateKeyPem(material.pem) : importEd25519PrivateJwk(material.jwk)),
  );

  if (Result.isFailure(imported)) throw httpError(500, imported.failure.message);

  return imported.success;
};

export type KeyImporter = (material: KeyMaterial) => Promise<CryptoKey>;

/** Imports a key once per distinct key: only the latest is remembered, so the memory in use cannot grow. */
export const createKeyImporter = (): KeyImporter => {
  let last: { readonly id: string; readonly key: Promise<CryptoKey> } | undefined;

  return (material) => {
    const id = "pem" in material ? `pem:${material.pem}` : `jwk:${JSON.stringify(material.jwk)}`;

    if (last?.id !== id) last = { id, key: importKey(material) };

    return last.key;
  };
};

const defaultKeyImporter = createKeyImporter();

export const setConfig = (c: Context, config: GnapAuthConfig, importer: KeyImporter): void => {
  if (c.get("gnapAuthConfig") !== undefined) throw httpError(500, "GNAP auth is already configured");

  const ev = env<GnapAuthEnv>(c);
  const number = (value: string | undefined): number | undefined => (value === undefined ? undefined : Number(value));
  // The key is resolved as a unit: a key in the config means the environment's key variables are not consulted.
  const keyInConfig = config.privateKey !== undefined || config.privateJwk !== undefined;
  const privateKey = keyInConfig ? config.privateKey : ev.GNAP_PRIVATE_KEY;
  const privateJwk = keyInConfig ? config.privateJwk : parseJwkVariable(ev.GNAP_PRIVATE_JWK);

  const secret = config.secret ?? ev.GNAP_AUTH_SECRET;

  if (secret === undefined) throw httpError(500, "Session secret is not provided");
  const refreshInterval = config.refreshInterval ?? number(ev.GNAP_AUTH_REFRESH_INTERVAL) ?? 900;
  const expires = config.expires ?? number(ev.GNAP_AUTH_EXPIRES) ?? 86_400;
  const externalUrl = config.externalUrl ?? ev.GNAP_AUTH_EXTERNAL_URL;
  const redirectUri = config.redirectUri ?? ev.GNAP_REDIRECT_URI ?? "/callback";
  const cookieDomain = config.cookieDomain ?? ev.GNAP_COOKIE_DOMAIN;
  const grantEndpoint = config.grantEndpoint ?? ev.GNAP_GRANT_ENDPOINT;
  const client = config.client ?? ev.GNAP_CLIENT;
  const keyId = config.keyId ?? ev.GNAP_KEY_ID;

  validateConfig({
    secret,
    refreshInterval,
    expires,
    redirectUri,
    requestTimeoutMs: config.requestTimeoutMs,
    externalUrl,
    grantEndpoint,
    client,
    privateKey,
    privateJwk,
  });

  const resolved: Resolved = {
    ...config,
    secret,
    refreshInterval,
    expires,
    redirectUri,
    importKey: importer,
    // Only an explicit `false` turns encryption off: a missing or malformed value keeps the cookies protected.
    encryptCookies: config.encryptCookies !== false,
    cookieName: config.cookieName ?? ev.GNAP_COOKIE_NAME ?? "gnap-auth",
    cookiePath: config.cookiePath ?? ev.GNAP_COOKIE_PATH ?? "/",
    ...(cookieDomain !== undefined && { cookieDomain }),
    ...(externalUrl !== undefined && { externalUrl }),
    ...(grantEndpoint !== undefined && { grantEndpoint }),
    ...(client !== undefined && { client }),
    ...(keyId !== undefined && { keyId }),
    ...(privateKey !== undefined && { privateKey }),
    ...(privateJwk !== undefined && { privateJwk }),
  };

  c.set("gnapAuthConfig", resolved);
};

export type Resolved = GnapAuthConfig & {
  readonly secret: string;
  readonly cookieName: string;
  readonly cookiePath: string;
  readonly redirectUri: string;
  readonly refreshInterval: number;
  readonly expires: number;
  /** Whether the cookies are encrypted (default) or only signed. */
  readonly encryptCookies: boolean;
  /** Imports the signing key once for as long as the key does not change. */
  readonly importKey: KeyImporter;
};

export const getConfig = (c: Context): Resolved => {
  if (c.get("gnapAuthConfig") === undefined) setConfig(c, {}, defaultKeyImporter);

  // SAFETY: setConfig above stores the defaulted fields.
  return c.get("gnapAuthConfig") as Resolved;
};

export const nowSeconds = (config: GnapAuthConfig): number =>
  Math.floor((config.clock?.() ?? new Date()).getTime() / 1000);

export const resolveWire = async (config: Resolved): Promise<Wire & { readonly jwk?: JWK }> => {
  const { privateKey, privateJwk, keyId } = config;

  if (keyId === undefined || (privateKey === undefined && privateJwk === undefined)) {
    throw httpError(500, "GNAP key id and private key are required");
  }

  const key = await config.importKey(privateJwk === undefined ? { pem: privateKey ?? "" } : { jwk: privateJwk });

  return {
    fetch: config.fetch ?? globalThis.fetch.bind(globalThis),
    clock: config.clock ?? (() => new Date()),
    key: { keyId, privateKey: key },
    // RFC 9635 §7.3.1 fixes sha-256 for an inline key; a wallet-address client signs sha-512 like the official client.
    digest: config.client === undefined ? "sha-256" : "sha-512",
    timeoutMs: config.requestTimeoutMs ?? 10_000,
    ...(privateJwk?.x !== undefined && {
      jwk: { kty: "OKP", crv: "Ed25519", x: privateJwk.x, kid: keyId, alg: "EdDSA" },
    }),
  };
};
