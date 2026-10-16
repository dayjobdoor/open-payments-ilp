import * as Effect from "effect/Effect";
import * as Equal from "effect/Equal";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import { getGrantClientIdentity, parseClientField, type ParsedClientField } from "../client-field";
import { extractGnapToken, hashToken } from "../token";
import type { AccessItem, GrantContinue, GrantContinuation, PendingGrant } from "../index";
import { constantTimeEqualText } from "../../internal/bytes";
import { isLoopbackHost } from "../../internal/url";
import * as schemas from "../../open-payments/schemas";
import { isPublicHttpsUrl } from "./client-keys";
import type { GnapGrantRequest, GnapInteractRequest, TenantConfig } from "./config";
import {
  hasExtendedRecords,
  issueToken,
  requireSignatureHeaders,
  tenantConfig,
  updateGrant,
  verifyClient,
  type Core,
  type IssuedToken,
} from "./core";
import { decodeJson, fail, noContent, readBody, respond, type ParamHandler } from "./http";
import type { GrantPatch, GrantRecord, TokenRequest } from "./store";

const tokenBody = Schema.Struct({
  access: Schema.Array(Schema.Unknown),
  label: Schema.optionalKey(Schema.String),
  flags: Schema.optionalKey(Schema.Array(Schema.String)),
});

// One token, or (RFC 9635 §2.1.2) an array of labelled ones.
const accessTokenBody = Schema.Union([tokenBody, Schema.Array(tokenBody)]);

const interactBody = Schema.Struct({
  start: Schema.Array(Schema.String),
  finish: Schema.optionalKey(
    Schema.Struct({
      method: Schema.Literals(["redirect", "push"]),
      uri: Schema.String,
      nonce: Schema.String,
      hash_method: Schema.optionalKey(Schema.Literals(["sha-256", "sha-384", "sha-512"])),
    }),
  ),
});

const grantBody = Schema.Struct({
  client: Schema.optionalKey(Schema.Unknown),
  access_token: Schema.optionalKey(accessTokenBody),
  subject: Schema.optionalKey(schemas.subject),
  interact: Schema.optionalKey(interactBody),
});

const decodeGrantBody = Schema.decodeUnknownResult(Schema.fromJsonString(grantBody));

// RFC 9635 §5.3: the fields of a modification; `client` and the post-interaction `interact_ref` are read to be refused.
const modifyBody = Schema.Struct({
  client: Schema.optionalKey(Schema.Unknown),
  interact_ref: Schema.optionalKey(Schema.Unknown),
  access_token: Schema.optionalKey(accessTokenBody),
  subject: Schema.optionalKey(schemas.subject),
  interact: Schema.optionalKey(interactBody),
});

const decodeModifyBody = Schema.decodeUnknownResult(Schema.fromJsonString(modifyBody));

// Any JSON object: like Rafiki, an empty one polls and every other one must carry the `interact_ref`.
const decodeContinueBody = Schema.decodeUnknownResult(
  Schema.fromJsonString(Schema.Record(Schema.String, Schema.Unknown)),
);

// Unknown members of an access item are errors: a misspelled limit must not silently disappear.
const decodeAccessItem = Schema.decodeUnknownResult(schemas.accessItem, { onExcessProperty: "error" });

/** The finish redirect must be `https` (plain `http` only for loopback development). */
const isFinishUri = (uri: string): boolean => {
  if (!URL.canParse(uri)) return false;
  const { protocol, hostname } = new URL(uri);

  // RFC 9635 §2.5.2: absolute, and no fragment.
  return new URL(uri).hash === "" && (protocol === "https:" || (protocol === "http:" && isLoopbackHost(hostname)));
};

/** A usable `interact.finish`: a nonce, and a URI the method may reach (a push also has to pass the SSRF rule). */
const isAcceptableFinish = (finish: {
  readonly method: "redirect" | "push";
  readonly uri: string;
  readonly nonce: string;
}) => finish.nonce !== "" && (finish.method === "push" ? isPublicHttpsUrl(finish.uri) : isFinishUri(finish.uri));

/** Rafiki's rule for one item: outgoing payments and `list-all` access need the owner's consent. */
const itemNeedsInteraction = (item: AccessItem): boolean =>
  // SAFETY: widening the action literals of every access item type to `string` for a membership test.
  item.type === "outgoing-payment" || (item.actions as ReadonlyArray<string>).includes("list-all");

/** Rafiki's default policy: a subject, or any item that {@link itemNeedsInteraction}, needs the owner's consent. */
export const defaultRequiresInteraction = (request: GnapGrantRequest): boolean =>
  request.subject !== undefined || request.access.some(itemNeedsInteraction);

/** Whether a raw access item limits both `debitAmount` and `receiveAmount` (Rafiki's `OnlyOneAccessAmountAllowed`). */
const hasBothAmounts = Schema.is(
  Schema.Struct({ limits: Schema.Struct({ debitAmount: Schema.Unknown, receiveAmount: Schema.Unknown }) }),
);

const isString = Schema.is(Schema.String);

/** Most tokens one `access_token` array may ask for. */
const MAX_ACCESS_TOKENS = 10;

type TokenBody = typeof tokenBody.Type;

/** The checked access items of one requested token. */
const parseAccessItems = (token: TokenBody) =>
  Effect.gen(function* () {
    const flags = token.flags ?? [];

    // RFC 9635 §2.1.1: a repeated flag is `invalid_flag`; `bearer` tokens are not issued, `durable` is always true.
    if (new Set(flags).size !== flags.length || flags.some((flag) => flag !== "durable")) {
      return yield* fail(400, "invalid_flag", "invalid access token flags");
    }

    // auth-server.yaml: `access` has at most 3 items.
    if (token.access.length > 3) return yield* fail(400, "invalid_request", "too many access items");

    const access: AccessItem[] = [];

    for (const raw of token.access) {
      if (hasBothAmounts(raw)) return yield* fail(400, "invalid_request", "only one access amount allowed");
      const item = decodeAccessItem(raw);

      if (Result.isFailure(item)) return yield* fail(400, "invalid_request", "invalid access item");
      const parsed = item.success;

      if (itemNeedsInteraction(parsed) && (!("identifier" in parsed) || !parsed.identifier)) {
        return yield* fail(400, "invalid_request", "access identifier required");
      }

      access.push(parsed);
    }

    if (access.some((item, index) => access.findIndex((other) => Equal.equals(item, other)) !== index)) {
      return yield* fail(400, "invalid_request", "duplicate access items");
    }

    return access;
  });

/**
 * The `access_token` of a request: the access items (for several tokens the union of theirs, without duplicates),
 * the `label` of a single token, and `tokens` for an array (RFC 9635 §2.1.2: at least one, each with a unique label).
 */
const parseAccessToken = (accessToken: typeof accessTokenBody.Type | undefined) =>
  Effect.gen(function* () {
    if (accessToken === undefined) {
      const none: AccessItem[] = [];

      return { access: none, label: undefined, tokens: undefined };
    }

    if ("access" in accessToken) {
      return { access: yield* parseAccessItems(accessToken), label: accessToken.label, tokens: undefined };
    }

    if (accessToken.length === 0) return yield* fail(400, "invalid_request", "access_token must not be empty");

    if (accessToken.length > MAX_ACCESS_TOKENS) return yield* fail(400, "invalid_request", "too many access tokens");

    const tokens: TokenRequest[] = [];

    for (const entry of accessToken) {
      const access = yield* parseAccessItems(entry);

      if (entry.label === undefined || entry.label === "" || tokens.some(({ label }) => label === entry.label)) {
        return yield* fail(400, "invalid_request", "every access token needs a unique label");
      }

      if (access.length === 0) return yield* fail(400, "invalid_request", "every access token needs access");

      tokens.push({ label: entry.label, access });
    }

    const union = tokens
      .flatMap(({ access }) => access)
      .filter((item, index, all) => all.findIndex((other) => Equal.equals(item, other)) === index);

    return { access: union, label: undefined, tokens };
  });

/** `400 invalid_request` unless the subject asks for exactly one identifier. */
const checkSubject = (subject: typeof schemas.subject.Type | undefined) =>
  subject !== undefined && subject.sub_ids.length !== 1
    ? fail(400, "invalid_request", "subject.sub_ids must have exactly one item")
    : Effect.void;

/** The `interact` the server acts on: one without the `redirect` start mode is as good as none. */
const usableInteract = (interact: typeof interactBody.Type | undefined) =>
  interact?.start.includes("redirect") === false ? undefined : interact;

const interactRequestOf = (interact: typeof interactBody.Type | undefined): { interact?: GnapInteractRequest } =>
  interact === undefined
    ? {}
    : { interact: { start: ["redirect"], ...(interact.finish !== undefined && { finish: interact.finish }) } };

/** `501 invalid_request` unless the store persists the optional record fields the `feature` needs. */
const requireExtended = (core: Core, feature: string) =>
  hasExtendedRecords(core) ? Effect.void : fail(501, "invalid_request", `${feature} not supported`);

/** Parses and validates a grant request body; fails `400 invalid_request` / `invalid_client`. */
const parseGrantRequest = (bytes: Uint8Array<ArrayBuffer>) =>
  Effect.gen(function* () {
    const body = yield* decodeJson(decodeGrantBody, bytes);
    const client = parseClientField(body.client);

    if (Result.isFailure(client)) return yield* fail(400, "invalid_request", client.failure.message);
    const { access, label, tokens } = yield* parseAccessToken(body.access_token);

    yield* checkSubject(body.subject);

    const subject = body.subject;
    const interact = usableInteract(body.interact);

    if (access.length === 0 && subject === undefined) {
      return yield* fail(400, "invalid_request", "subject or access_token required");
    }

    if (interact?.finish !== undefined && !isAcceptableFinish(interact.finish)) {
      return yield* fail(400, "invalid_request", "invalid interact.finish");
    }

    const request: GnapGrantRequest = {
      client: client.success,
      access,
      ...(subject !== undefined && { subject }),
      ...interactRequestOf(body.interact),
    };

    return { request, finish: interact?.finish, label, tokens, hasInteract: interact !== undefined };
  });

const continueBlock = (core: Core, grant: GrantRecord, token: string, wait?: number): GrantContinue => ({
  access_token: { value: token },
  uri: `${core.baseUrl}/continue/${grant.continueId}`,
  ...(wait !== undefined && { wait }),
});

/** The identity a stored grant's requests must be signed by. */
export const grantIdentity = (grant: GrantRecord): Effect.Effect<ParsedClientField, never> => {
  const identity = getGrantClientIdentity({ client: grant.client, jwk: grant.jwk });

  // A stored grant always has one of the two (the request parser guarantees it).
  return Result.isSuccess(identity) ? Effect.succeed(identity.success) : Effect.die("grant without client identity");
};

/**
 * The checks that decide whether a request is served and whether it needs the owner, for a new request and for a
 * modification alike. Returns whether the owner has to consent. `canInteract`: the request carries a usable `interact`.
 */
const requireRules = (core: Core, request: GnapGrantRequest, tenant: TenantConfig, canInteract: boolean) =>
  Effect.gen(function* () {
    const interactive = (core.config.policy?.requiresInteraction ?? defaultRequiresInteraction)(request);

    if (interactive) {
      if (!canInteract) return yield* fail(400, "invalid_request", "missing required request field 'interact'");

      if (tenant.consentUrl === undefined) return yield* fail(400, "invalid_request", "invalid tenant");

      if (request.client.client === undefined) {
        return yield* fail(400, "invalid_client", "JWK client identifier cannot be used for interactive grants");
      }
    } else if (request.access.length === 0) {
      return yield* fail(400, "invalid_request", "subject requires interaction");
    }

    return interactive;
  });

/** The tokens of an `access_token` array request; `undefined` for the single token form. */
const requestedTokens = (grant: GrantRecord): ReadonlyArray<TokenRequest> | undefined =>
  grant.tokenRequests ?? undefined;

/** Issues what the grant asks for: a token per requested one, the single token, or none (subject only). */
const issueGrantTokens = (core: Core, grant: GrantRecord): Effect.Effect<ReadonlyArray<IssuedToken>> => {
  const requested = requestedTokens(grant);

  return requested !== undefined
    ? Effect.forEach(requested, ({ access, label }) => issueToken(core, grant, { access, label }))
    : grant.access.length > 0
      ? Effect.map(issueToken(core, grant), (issued) => [issued])
      : Effect.succeed([]);
};

/** Undoes {@link issueGrantTokens}. */
const revokeIssued = (core: Core, issued: ReadonlyArray<IssuedToken>) =>
  Effect.forEach(issued, ({ id }) => core.store.revokeTokens("id", id, core.now()), { discard: true });

/** The `access_token` member of a response: an array only when the request used one (RFC 9635 §3.2.2). */
const accessTokenField = (grant: GrantRecord, issued: ReadonlyArray<IssuedToken>) =>
  requestedTokens(grant) !== undefined
    ? { access_token: issued.map(({ token }) => token) }
    : issued[0] === undefined
      ? {}
      : { access_token: issued[0].token };

/** `interact` and `continue` of a grant waiting for its owner. */
const pendingResponse = (core: Core, grant: GrantRecord, continueToken: string): PendingGrant => {
  const redirect = new URL(`${core.baseUrl}/interact/${grant.interactId}/${grant.interactNonce}`);
  const client = grant.client ?? "";

  redirect.searchParams.set("clientName", URL.canParse(client) ? new URL(client).hostname : client);
  redirect.searchParams.set("clientUri", client);

  return {
    interact: { redirect: redirect.toString(), finish: grant.interactNonce ?? "" },
    continue: continueBlock(core, grant, continueToken, core.waitSeconds),
  };
};

const createGrantResponse = (core: Core, request: Request, tenantId: string | undefined) =>
  Effect.gen(function* () {
    const bytes = yield* readBody(request, core.maxBodyBytes);
    const { request: parsed, finish, label, tokens, hasInteract } = yield* parseGrantRequest(bytes);

    yield* requireSignatureHeaders(request);
    yield* verifyClient(core, request, parsed.client, bytes);

    if (tokens !== undefined) yield* requireExtended(core, "multiple access tokens");

    if (finish?.method === "push") yield* requireExtended(core, "finish method push");

    // Single-tenant: no tenant segment, the top-level settings. Multi-tenant: the segment must name a tenant.
    const tenant = yield* tenantId === undefined && core.config.tenants !== undefined
      ? Effect.succeed(null)
      : tenantConfig(core, tenantId ?? null);

    if (tenant === null) return yield* fail(404, "invalid_request", "Not Found");
    const interactive = yield* requireRules(core, parsed, tenant, hasInteract);

    const now = core.now();
    const continueToken = core.generateToken();

    const grant: GrantRecord = {
      id: crypto.randomUUID(),
      version: 0,
      state: interactive ? "PENDING" : "APPROVED",
      tenantId: tenantId ?? null,
      client: parsed.client.client ?? null,
      jwk: parsed.client.jwk ?? null,
      access: parsed.access,
      subject: parsed.subject ?? null,
      interactId: interactive ? crypto.randomUUID() : null,
      interactNonce: interactive ? core.generateToken() : null,
      interactRef: interactive ? core.generateToken() : null,
      interactExpiresAt: interactive ? now + core.interactionExpiresInSeconds * 1000 : null,
      finishUri: finish?.uri ?? null,
      clientNonce: finish?.nonce ?? null,
      finishHashMethod: finish?.hash_method ?? null,
      label: label ?? null,
      userId: null,
      continueId: crypto.randomUUID(),
      continueTokenHash: yield* hashToken(continueToken),
      lastContinuedAt: now,
      createdAt: now,
      updatedAt: now,
      // A store without the optional fields never sees them (the single-token redirect request needs none).
      ...(hasExtendedRecords(core) && { finishMethod: finish?.method ?? null, tokenRequests: tokens ?? null }),
    };

    yield* core.store.createGrant(grant);

    if (!interactive) {
      return Response.json({
        ...accessTokenField(grant, yield* issueGrantTokens(core, grant)),
        continue: continueBlock(core, grant, continueToken),
      });
    }

    return Response.json(pendingResponse(core, grant, continueToken));
  });

/**
 * Authenticates a continuation request like Rafiki's middleware: signature headers and a `GNAP` token, a grant
 * (not revoked) whose continue token matches, and a signature by the grant's client. Returns the grant and the token.
 */
const authenticateContinue = (core: Core, request: Request, continueId: string, bytes: Uint8Array<ArrayBuffer>) =>
  Effect.gen(function* () {
    yield* requireSignatureHeaders(request);
    const authorization = request.headers.get("authorization");

    if (authorization === null) return yield* fail(401, "invalid_client", "invalid signature headers");
    const token = extractGnapToken(authorization);

    if (token === null || continueId === "") {
      return yield* fail(401, "invalid_continuation", "missing continuation information");
    }

    const grant = yield* core.store.findGrant("continueId", continueId);

    if (
      grant === null ||
      grant.state === "REVOKED" ||
      !constantTimeEqualText(yield* hashToken(token), grant.continueTokenHash)
    ) {
      return yield* fail(401, "invalid_continuation", "invalid grant");
    }

    yield* verifyClient(core, request, yield* grantIdentity(grant), bytes);

    return { grant, token };
  });

const stillWaiting = (core: Core, grant: GrantRecord): boolean =>
  core.now() < grant.lastContinuedAt + core.waitSeconds * 1000;

/**
 * Issues the access token(s) of an approved grant. Order: tokens first, then the claim that the grant is still
 * `APPROVED`; a lost race revokes the tokens again, a crash leaves unreferenced tokens and a grant the client can
 * still continue. As in Rafiki the continue token stays the same.
 */
const finalizeGrant = (core: Core, grant: GrantRecord, continueToken: string) =>
  Effect.gen(function* () {
    const issued = yield* issueGrantTokens(core, grant);

    const finalized = yield* updateGrant(core, grant, (current) =>
      current.state === "APPROVED"
        ? Effect.succeed({ state: "FINALIZED" as const })
        : fail(404, "invalid_continuation", "grant not found"),
    ).pipe(Effect.tapError(() => revokeIssued(core, issued)));

    return Response.json({
      ...accessTokenField(finalized, issued),
      continue: continueBlock(core, finalized, continueToken),
      ...(finalized.subject !== null && { subject: finalized.subject }),
    });
  });

/** Rafiki's `PENDING` / `PROCESSING` grant: the owner has not finished (`/finish`) the interaction. */
const isUndecided = (grant: GrantRecord): boolean =>
  grant.state === "PENDING" || grant.state === "ACCEPTED" || grant.state === "DENIED";

/** Polling, as Rafiki does it: the same checks in the same order, for a body-less continue. */
const pollGrant = (core: Core, grant: GrantRecord, token: string) =>
  Effect.gen(function* () {
    if (stillWaiting(core, grant)) return yield* fail(400, "too_fast", 'polled grant faster than "wait" period');

    if (grant.finishUri !== null) return yield* fail(401, "request_denied", "grant cannot be polled");

    if (isUndecided(grant)) {
      // Best effort: losing against a concurrent decision only means the next poll sees the new state.
      yield* core.store.updateGrant(grant.id, grant.version, { lastContinuedAt: core.now(), updatedAt: core.now() });

      return Response.json({
        continue: continueBlock(core, grant, token, core.waitSeconds),
      } satisfies GrantContinuation);
    }

    if (grant.state !== "APPROVED") return yield* fail(401, "request_denied", "grant cannot be continued");

    return yield* finalizeGrant(core, grant, token);
  });

const continueGrant = (core: Core, request: Request, continueId: string) =>
  Effect.gen(function* () {
    const bytes = yield* readBody(request, core.maxBodyBytes);
    const { grant, token } = yield* authenticateContinue(core, request, continueId, bytes);
    const body = bytes.byteLength === 0 ? {} : yield* decodeJson(decodeContinueBody, bytes);

    if (Object.keys(body).length === 0) return yield* pollGrant(core, grant, token);
    const interactRef = body["interact_ref"];

    if (!isString(interactRef)) return yield* fail(401, "invalid_request", "missing interaction reference");

    if (
      grant.interactRef === null ||
      grant.state === "REJECTED" ||
      !constantTimeEqualText(interactRef, grant.interactRef)
    ) {
      return yield* fail(404, "invalid_continuation", "grant not found");
    }

    if (stillWaiting(core, grant)) return yield* fail(400, "too_fast", 'continued grant faster than "wait" period');

    if (grant.state !== "APPROVED") return yield* fail(401, "request_denied", "grant interaction not approved");

    return yield* finalizeGrant(core, grant, token);
  });

/** RFC 9635 §5.3: only a grant request that is pending or approved can be modified. */
const isModifiable = (grant: GrantRecord): boolean => grant.state === "PENDING" || grant.state === "APPROVED";

/** Fields an owner-less grant carries once nothing is left to decide. */
const NO_INTERACTION = {
  interactId: null,
  interactNonce: null,
  interactRef: null,
  interactExpiresAt: null,
  finishUri: null,
  clientNonce: null,
  finishHashMethod: null,
  finishMethod: null,
} satisfies GrantPatch;

/**
 * `PATCH /continue/:id` (RFC 9635 §5.3): `access_token` and `subject` replace the requested ones, `interact` the
 * client's interaction capabilities, and the request is evaluated again as if it were new. What needs the owner's
 * consent starts a new interaction (the old consent URL stops working, so an owner deciding on the old request never
 * consents to the new one) and answers like a pending grant; what does not is approved at once and answers with its
 * new access token(s). Tokens issued earlier are not touched: they carry the access they were issued with.
 */
const modifyGrant = (core: Core, request: Request, continueId: string) =>
  Effect.gen(function* () {
    const bytes = yield* readBody(request, core.maxBodyBytes);
    const { grant, token } = yield* authenticateContinue(core, request, continueId, bytes);

    yield* requireExtended(core, "grant modification");

    if (!isModifiable(grant)) return yield* fail(401, "request_denied", "grant cannot be modified");

    const body = yield* decodeJson(decodeModifyBody, bytes);

    if (body.client !== undefined) return yield* fail(400, "invalid_request", "client cannot be modified");

    if (body.interact_ref !== undefined) {
      return yield* fail(400, "invalid_request", "interact_ref cannot be part of a modification");
    }

    if (body.access_token === undefined && body.subject === undefined && body.interact === undefined) {
      return yield* fail(400, "invalid_request", "nothing to modify");
    }

    // Fields that are not sent stay as they are.
    const requested = yield* parseAccessToken(body.access_token);
    const replaced = body.access_token !== undefined;
    const access = replaced ? requested.access : grant.access;
    const label = replaced ? requested.label : (grant.label ?? undefined);
    const tokens = replaced ? requested.tokens : (grant.tokenRequests ?? undefined);

    yield* checkSubject(body.subject);
    const subject = body.subject ?? grant.subject ?? undefined;
    const interact = usableInteract(body.interact);
    const finish = interact?.finish;

    if (access.length === 0 && subject === undefined) {
      return yield* fail(400, "invalid_request", "subject or access_token required");
    }

    if (finish !== undefined && !isAcceptableFinish(finish)) {
      return yield* fail(400, "invalid_request", "invalid interact.finish");
    }

    const tenant = yield* tenantConfig(core, grant.tenantId);

    if (tenant === null) return yield* fail(400, "invalid_request", "invalid tenant");

    const interactive = yield* requireRules(
      core,
      {
        client: yield* grantIdentity(grant),
        access,
        ...(subject !== undefined && { subject }),
        ...interactRequestOf(body.interact),
      },
      tenant,
      interact !== undefined,
    );

    const now = core.now();

    const patch: GrantPatch = {
      access,
      subject: subject ?? null,
      label: label ?? null,
      tokenRequests: tokens ?? null,
      userId: null,
      lastContinuedAt: now,
      ...(interactive
        ? {
            state: "PENDING" as const,
            interactId: crypto.randomUUID(),
            interactNonce: core.generateToken(),
            interactRef: core.generateToken(),
            interactExpiresAt: now + core.interactionExpiresInSeconds * 1000,
            finishUri: finish?.uri ?? null,
            clientNonce: finish?.nonce ?? null,
            finishHashMethod: finish?.hash_method ?? null,
            finishMethod: finish?.method ?? null,
          }
        : { state: "APPROVED" as const, ...NO_INTERACTION }),
    };

    const decide = (current: GrantRecord) =>
      isModifiable(current) ? Effect.succeed(patch) : fail(401, "request_denied", "grant cannot be modified");

    if (interactive) return Response.json(pendingResponse(core, yield* updateGrant(core, grant, decide), token));

    // Approved at once: like a first request, the token(s) come back now. Issued first, undone when the claim is lost.
    const issued = yield* issueGrantTokens(core, { ...grant, ...patch });

    const updated = yield* updateGrant(core, grant, decide).pipe(Effect.tapError(() => revokeIssued(core, issued)));

    return Response.json({ ...accessTokenField(updated, issued), continue: continueBlock(core, updated, token) });
  });

const cancelGrant = (core: Core, request: Request, continueId: string) =>
  Effect.gen(function* () {
    const bytes = yield* readBody(request, core.maxBodyBytes);
    const { grant } = yield* authenticateContinue(core, request, continueId, bytes);

    yield* updateGrant(core, grant, () => Effect.succeed({ state: "REVOKED" as const }));
    yield* core.store.revokeTokens("grantId", grant.id, core.now());

    return noContent();
  });

export interface GrantHandlers {
  /** `params.tenantId` is the path segment of `POST /:tenantId` (multi-tenant mode); absent on `POST /`. */
  readonly createGrant: (request: Request, params?: { readonly tenantId?: string }) => Effect.Effect<Response>;
  readonly continueGrant: ParamHandler<{ readonly id: string }>;
  readonly modifyGrant: ParamHandler<{ readonly id: string }>;
  readonly cancelGrant: ParamHandler<{ readonly id: string }>;
}

/** Handlers of `POST /` (or `POST /:tenantId`), `POST|PATCH|DELETE /continue/:id`. */
export const grantHandlers = (core: Core): GrantHandlers => ({
  createGrant: (request, params) => respond(core, createGrantResponse(core, request, params?.tenantId)),
  continueGrant: (request, params) => respond(core, continueGrant(core, request, params.id)),
  modifyGrant: (request, params) => respond(core, modifyGrant(core, request, params.id)),
  cancelGrant: (request, params) => respond(core, cancelGrant(core, request, params.id)),
});
