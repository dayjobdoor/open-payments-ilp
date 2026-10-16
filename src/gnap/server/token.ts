import * as Effect from "effect/Effect";
import * as Equal from "effect/Equal";
import * as Predicate from "effect/Predicate";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import type { AccessMatchItem } from "../access";
import { toTokenInfoClient } from "../client-field";
import { extractGnapToken, hashToken } from "../token";
import type { AccessItem, AccessToken, TokenIntrospectionResponse } from "../index";
import { constantTimeEqualText } from "../../internal/bytes";
import * as schemas from "../../open-payments/schemas";
import { issueToken, requireSignatureHeaders, verifyClient, type Core } from "./core";
import { grantIdentity } from "./grant";
import {
  decodeJson,
  fail,
  noContent,
  readBody,
  respond,
  utf8Text,
  type ParamHandler,
  type RequestHandler,
} from "./http";

/** Authenticates a token management request like Rafiki's middleware, and also checks the presented `GNAP` token. */
const authenticateManagement = (core: Core, request: Request, managementId: string) =>
  Effect.gen(function* () {
    yield* requireSignatureHeaders(request);
    const bytes = yield* readBody(request, core.maxBodyBytes);
    const found = yield* core.store.findTokenWithGrant("managementId", managementId);
    const presented = extractGnapToken(request.headers.get("authorization") ?? undefined);

    if (
      found === null ||
      found.token.revokedAt !== null ||
      presented === null ||
      !constantTimeEqualText(yield* hashToken(presented), found.token.valueHash)
    ) {
      return yield* fail(401, "invalid_client", "invalid access token");
    }

    yield* verifyClient(core, request, yield* grantIdentity(found.grant), bytes);

    return { ...found, bytes };
  });

/**
 * Rotation: the new token is stored first, then the old one is claimed (`revokeTokens` hands it to exactly one
 * caller). Losing revokes the new token again; a crash in between leaves the old token valid and one unreferenced token.
 */
const rotateToken = (core: Core, request: Request, managementId: string) =>
  Effect.gen(function* () {
    const { token, grant, bytes } = yield* authenticateManagement(core, request, managementId);

    // RFC 9635 §6.1.1: a request to change the bound key is not served, never silently turned into a plain rotation.
    if (bytes.byteLength > 0 && Result.isSuccess(decodeKeyRotation(yield* utf8Text(bytes)))) {
      return yield* fail(400, "key_rotation_not_supported", "key rotation is not supported");
    }

    // The new token carries what the rotated one did (its own access and label, not the grant's current ones).
    const issued = yield* issueToken(core, grant, {
      access: token.access ?? grant.access,
      label: token.label === undefined ? grant.label : token.label,
    });

    if ((yield* core.store.revokeTokens("id", token.id, core.now())) === 0) {
      yield* core.store.revokeTokens("id", issued.id, core.now());

      return yield* fail(404, "invalid_rotation", "invalid access token");
    }

    const body: AccessToken = { access_token: issued.token };

    return Response.json(body);
  });

const revokeToken = (core: Core, request: Request, managementId: string) =>
  Effect.gen(function* () {
    const { token } = yield* authenticateManagement(core, request, managementId);

    yield* core.store.revokeTokens("id", token.id, core.now());

    return noContent();
  });

/** Body of the introspection request. */
interface IntrospectionInput {
  readonly access_token: string;
  readonly access?: ReadonlyArray<AccessItem>;
}

const introspectionBody = Schema.Struct({
  access_token: Schema.String,
  access: Schema.optionalKey(Schema.Array(schemas.accessItem)),
  proof: Schema.optionalKey(Schema.String),
});

const decodeKeyRotation = Schema.decodeUnknownResult(Schema.fromJsonString(Schema.Struct({ key: Schema.Unknown })));

const decodeIntrospection = Schema.decodeUnknownResult(Schema.fromJsonString(introspectionBody));

/**
 * Whether the `granted` item satisfies the `requested` one, exactly as Rafiki's introspection decides it
 * (`auth/src/access/utils.ts`): same type; every requested action granted (`read-all` covers `read`, `list-all`
 * covers `list`); `limits`, when requested, deep-equal to the grant's; and `identifier`s only conflict when both
 * items have one. The RS-side matcher `compareRequestAndGrantAccessItems` is stricter on purpose (an item without
 * identifier does not cover a request that names a wallet address); the introspection answer must not be, or a token
 * for "create incoming payments" would not cover the wallet address the resource server asks about.
 */
const covers = (granted: AccessMatchItem, requested: AccessMatchItem): boolean => {
  const grantedActions = granted.actions ?? [];

  return (
    requested.type === granted.type &&
    (requested.actions ?? []).every(
      (action) =>
        grantedActions.includes(action) ||
        (action === "read" && grantedActions.includes("read-all")) ||
        (action === "list" && grantedActions.includes("list-all")),
    ) &&
    (!requested.limits || Equal.equals(requested.limits, granted.limits)) &&
    !(requested.identifier && granted.identifier && requested.identifier !== granted.identifier)
  );
};

/**
 * The in-process introspection answer: the wire answer ({@link TokenIntrospectionResponse}) and, for an active token,
 * what the host needs about it without another read: the tenant and the token's whole access.
 */
export type TokenIntrospection =
  | { readonly active: false }
  | (Extract<TokenIntrospectionResponse, { active: true }> & {
      /** The tenant the grant belongs to; `null` for the single-tenant server. */
      readonly tenantId: string | null;
      /** Every access item of the token (`access` holds only the ones the request asked about): the grant's when the token has none of its own. */
      readonly grantAccess: ReadonlyArray<AccessItem>;
    });

/**
 * Introspection result for `accessToken`; any token that is unknown, expired or revoked is `inactive`, and with a
 * `tenantId` so is one whose grant belongs to another tenant.
 */
export const introspect = (
  core: Core,
  accessToken: string,
  access: IntrospectionInput["access"],
  tenantId?: string,
): Effect.Effect<TokenIntrospection> =>
  Effect.gen(function* () {
    const found = yield* core.store.findTokenWithGrant("valueHash", yield* hashToken(accessToken));

    if (found === null || found.token.revokedAt !== null || found.token.expiresAt <= core.now()) {
      return { active: false };
    }

    const { grant } = found;
    // A token of an extended store carries its own access (several tokens, modified grants); else the grant's.
    const tokenAccess = found.token.access ?? found.grant.access;

    if (grant.state === "REJECTED" || grant.state === "REVOKED") return { active: false };

    if (tenantId !== undefined && grant.tenantId !== tenantId) return { active: false };

    const identity = yield* grantIdentity(grant);

    // Like Rafiki, only items the request asked about are reported (none when `access` is omitted or empty), in
    // request order, each as the first grant item that covers it.
    const matched = (access ?? []).flatMap((requested) => {
      const found = tokenAccess.find((granted) => covers(granted, requested));

      return found === undefined ? [] : [found];
    });

    return {
      active: true,
      grant: grant.id,
      access: matched,
      client: toTokenInfoClient(identity),
      tenantId: grant.tenantId,
      grantAccess: tokenAccess,
    };
  });

const introspectRequest = (core: Core, request: Request) =>
  Effect.gen(function* () {
    const introspection = core.config.introspection;

    if (introspection === undefined) return yield* fail(404, "invalid_request", "not found");
    // Capped on a clone: `authorize` still gets the untouched request (e.g. to verify its digest).
    const bytes = yield* readBody(request.clone(), core.maxBodyBytes);

    // RFC 9767 §3.5: an RS that is not recognised or whose signature does not verify.
    const caller = yield* introspection.authorize(request);

    // Default-deny: only `true` or an object with a string `tenantId` is a recognised caller (JS hooks may return anything).
    if (caller !== true && !(Predicate.isObject(caller) && Predicate.isString(caller.tenantId))) {
      return yield* fail(400, "invalid_resource_server", "introspection not authorized");
    }

    const body = yield* decodeJson(decodeIntrospection, bytes);

    // RFC 9767 §3.3: a token is only active for the proofing method it is bound with.
    if (body.proof !== undefined && body.proof !== "httpsig") return Response.json({ active: false });

    const result = yield* introspect(
      core,
      body.access_token,
      body.access,
      caller === true ? undefined : caller.tenantId,
    );

    // The wire answer is the RFC 9767 one; `tenantId` and `grantAccess` stay in process.
    return Response.json(
      result.active ? { active: true, grant: result.grant, access: result.access, client: result.client } : result,
    );
  });

export interface TokenHandlers {
  readonly rotateToken: ParamHandler<{ readonly id: string }>;
  readonly revokeToken: ParamHandler<{ readonly id: string }>;
  readonly introspect: RequestHandler;
}

/** Handlers of `POST|DELETE /token/:id` and `POST /introspect`. */
export const tokenHandlers = (core: Core): TokenHandlers => ({
  rotateToken: (request, params) => respond(core, rotateToken(core, request, params.id)),
  revokeToken: (request, params) => respond(core, revokeToken(core, request, params.id)),
  introspect: (request) => respond(core, introspectRequest(core, request)),
});
