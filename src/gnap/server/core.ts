import * as Effect from "effect/Effect";
import * as Result from "effect/Result";
import { hashToken } from "../token";
import type { ParsedClientField } from "../client-field";
import type { AccessItem, GrantAccessToken } from "../index";
import { HttpSignatureError } from "../../http-signatures/errors";
import { parseDictionary } from "../../http-signatures/structured-fields";
import { SIGNATURE_REPLAY_WINDOW_SECONDS, verifyRequest } from "../../http-signatures/verify";
import { encodeBase64Url } from "../../internal/bytes";
import type { JWK } from "../../open-payments/types";
import type { GnapServerConfig, TenantConfig } from "./config";
import { fetchClientKeys, selectKey } from "./client-keys";
import { fail, GnapRouteError } from "./http";
import type { GnapStore, GrantPatch, GrantRecord, TokenRecord } from "./store";

/** The configuration with defaults applied, shared by every handler. */
export interface Core {
  readonly config: GnapServerConfig;
  readonly store: GnapStore;
  /** `config.baseUrl` without trailing slash. */
  readonly baseUrl: string;
  /** The path of `baseUrl` without trailing slash (`""` at the origin root). */
  readonly basePath: string;
  readonly now: () => number;
  readonly generateToken: () => string;
  readonly waitSeconds: number;
  readonly accessTokenExpiresInSeconds: number;
  readonly interactionExpiresInSeconds: number;
  readonly maxBodyBytes: number;
}

/** 256 random bits as base64url. */
const randomToken = (): string => encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));

export const createCore = (config: GnapServerConfig): Core => {
  const baseUrl = config.baseUrl.replace(/\/+$/, "");

  return {
    config,
    store: config.store,
    baseUrl,
    basePath: new URL(baseUrl).pathname.replace(/\/+$/, ""),
    now: () => (config.clock ?? (() => new Date()))().getTime(),
    generateToken: config.generateToken ?? randomToken,
    // RFC 9635 §3.1: `wait` SHOULD NOT be less than five seconds.
    waitSeconds: Math.max(5, config.waitSeconds ?? 5),
    accessTokenExpiresInSeconds: config.accessTokenExpiresInSeconds ?? 600,
    interactionExpiresInSeconds: config.interaction?.expiresInSeconds ?? 600,
    maxBodyBytes: config.maxBodyBytes ?? 64 * 1024,
  };
};

/** The path of `request` below the base path (`""` for the root), or `null` when it is outside it. */
export const relativePath = (core: Core, request: Request): string | null => {
  const { pathname } = new URL(request.url);

  if (!pathname.startsWith(core.basePath)) return null;
  const rest = pathname.slice(core.basePath.length);

  return rest === "" || rest.startsWith("/") ? rest : null;
};

/**
 * The URL the client addressed, rebuilt from `baseUrl`: signature bases use what the server told the client, not
 * whatever proxy-rewritten URL reached the handler.
 */
export const publicUrl = (core: Core, request: Request): string => {
  const rest = relativePath(core, request);

  return rest === null ? request.url : `${core.baseUrl}${rest}${new URL(request.url).search}`;
};

const signatureFailure = (error: HttpSignatureError): GnapRouteError =>
  error.reason === "unknown-key"
    ? new GnapRouteError({ status: 400, code: "invalid_client", description: "could not determine client" })
    : new GnapRouteError({
        status: 401,
        code: "invalid_client",
        description:
          // Rafiki's `validateSignatureHeaders` also checks the body against `Content-Digest`.
          error.reason === "missing" || error.reason === "malformed" || error.reason === "digest-mismatch"
            ? "invalid signature headers"
            : "invalid signature",
      });

/** `401 invalid_client` unless the request carries `Signature` and `Signature-Input`. */
export const requireSignatureHeaders = (request: Request): Effect.Effect<void, GnapRouteError> =>
  request.headers.has("signature") && request.headers.has("signature-input")
    ? Effect.void
    : fail(401, "invalid_client", "invalid signature headers");

/** Signatures of one request tried at most: each costs a verification, and the header is attacker-sized. */
const MAX_SIGNATURE_LABELS = 3;

/** Signature labels of `request` to try: `sig1` (what Open Payments clients use) first, then a few others. */
const signatureLabels = (request: Request): ReadonlyArray<string> => {
  const parsed = parseDictionary(request.headers.get("signature-input") ?? "");
  const labels = Result.isSuccess(parsed) ? parsed.success.map(([label]) => label) : [];

  return ["sig1", ...labels.filter((label) => label !== "sig1")].slice(0, MAX_SIGNATURE_LABELS);
};

/**
 * Verifies the RFC 9421 signature of `request` as `identity`, against the body already read. Any one acceptable
 * signature of several suffices (RFC 9635 §7.3.1); a `nonce` may be used once (a replay is `401`).
 */
export const verifyClient = (
  core: Core,
  request: Request,
  identity: ParsedClientField,
  body: Uint8Array<ArrayBuffer>,
): Effect.Effect<void, GnapRouteError> =>
  Effect.gen(function* () {
    // The client's keys are looked up once per request, however many signatures are tried (a failure is kept too).
    const clientKeys = yield* Effect.cached(
      identity.jwk === undefined
        ? (core.config.resolveClientKeys ?? fetchClientKeys(core.config.fetch))(identity.client)
        : Effect.succeed<ReadonlyArray<JWK>>([identity.jwk]),
    );

    let failure: HttpSignatureError | undefined;

    for (const label of signatureLabels(request)) {
      const result = yield* Effect.result(
        verifyRequest(
          new Request(publicUrl(core, request), {
            method: request.method,
            headers: request.headers,
            ...(body.byteLength > 0 && { body }),
          }),
          {
            label,
            resolveKey: (keyId) => Effect.flatMap(clientKeys, (candidates) => selectKey(candidates, keyId)),
            clock: () => new Date(core.now()),
          },
        ),
      );

      if (Result.isFailure(result)) {
        // The first failure (`sig1`'s) is the one worth reporting.
        failure ??= result.failure;
        continue;
      }

      const { keyId, nonce } = result.success;

      if (nonce === undefined) return;
      const now = core.now();

      // The nonce is only remembered once the signature verified, so nobody can burn another client's nonces.
      if (yield* core.store.claimNonce(`${keyId}\n${nonce}`, now + SIGNATURE_REPLAY_WINDOW_SECONDS * 1000, now)) return;

      return yield* fail(401, "invalid_client", "invalid signature");
    }

    return yield* failure === undefined
      ? fail(401, "invalid_client", "invalid signature headers")
      : Effect.fail(signatureFailure(failure));
  });

/**
 * Changes a grant atomically, starting from `initial` (already read by the caller: no extra round trip). `decide`
 * sees the grant and returns the patch (or fails); if somebody else changed the grant meanwhile, the write loses and
 * `decide` runs again on the freshly read grant, up to three times.
 */
export const updateGrant = <E>(
  core: Core,
  initial: GrantRecord,
  decide: (grant: GrantRecord) => Effect.Effect<GrantPatch, E>,
): Effect.Effect<GrantRecord, E | GnapRouteError> =>
  Effect.gen(function* () {
    let grant: GrantRecord | null = initial;

    for (let attempt = 0; attempt < 3; attempt += 1) {
      if (attempt > 0) grant = yield* core.store.findGrant("id", initial.id);

      if (grant === null) return yield* fail(404, "invalid_continuation", "grant not found");
      const patch = { ...(yield* decide(grant)), updatedAt: core.now() };

      if (yield* core.store.updateGrant(grant.id, grant.version, patch)) {
        return { ...grant, ...patch, version: grant.version + 1 };
      }
    }

    return yield* fail(500, "request_denied", "internal server error");
  });

/**
 * The identity provider settings that apply to a grant of `tenantId`: the top-level `interaction.consentUrl` and
 * `idpSecret` for the single-tenant server (`null`), `tenants(tenantId)` otherwise. `null` when the tenant is unknown.
 */
export const tenantConfig = (core: Core, tenantId: string | null): Effect.Effect<TenantConfig | null> =>
  tenantId === null
    ? Effect.succeed({
        ...(core.config.interaction?.consentUrl !== undefined && { consentUrl: core.config.interaction.consentUrl }),
        ...(core.config.idpSecret !== undefined && { idpSecret: core.config.idpSecret }),
      })
    : (core.config.tenants?.(tenantId) ?? Effect.succeed(null));

/**
 * The URL the grant request was POSTed to (`baseUrl`, plus the tenant segment in multi-tenant mode): the grant
 * endpoint the interaction finish `hash` is computed over, as in Rafiki.
 */
export const grantEndpoint = (core: Core, grant: GrantRecord): string =>
  grant.tenantId === null ? core.baseUrl : `${core.baseUrl}/${encodeURIComponent(grant.tenantId)}`;

/** A freshly stored access token: its record id (to undo it) and the wire form; the plaintext is never stored. */
export interface IssuedToken {
  readonly id: string;
  readonly token: GrantAccessToken;
}

/** What a token carries: its access items and its `label` (`null`: none). */
export interface TokenSpec {
  readonly access: ReadonlyArray<AccessItem>;
  readonly label: string | null;
}

/** Whether the store persists the optional record fields (see {@link GnapStore.extendedRecords}). */
export const hasExtendedRecords = (core: Core): boolean => core.store.extendedRecords === true;

/** Issues one token for `grant`: of the grant's access and label unless `spec` says otherwise. */
export const issueToken = (
  core: Core,
  grant: GrantRecord,
  spec: TokenSpec = { access: grant.access, label: grant.label },
): Effect.Effect<IssuedToken> =>
  Effect.gen(function* () {
    const now = core.now();
    const value = core.generateToken();

    const record: TokenRecord = {
      id: crypto.randomUUID(),
      grantId: grant.id,
      valueHash: yield* hashToken(value),
      managementId: crypto.randomUUID(),
      expiresAt: now + core.accessTokenExpiresInSeconds * 1000,
      revokedAt: null,
      createdAt: now,
      // A store that drops the optional fields never sees them: the token then carries the grant's access.
      ...(hasExtendedRecords(core) && { access: spec.access, label: spec.label }),
    };

    yield* core.store.createToken(record);

    return {
      id: record.id,
      token: {
        value,
        manage: `${core.baseUrl}/token/${record.managementId}`,
        expires_in: core.accessTokenExpiresInSeconds,
        access: [...spec.access],
        ...(spec.label !== null && { label: spec.label }),
      },
    };
  });
