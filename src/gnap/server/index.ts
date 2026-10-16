/**
 * A framework-agnostic GNAP authorisation server for Open Payments, wire-compatible with Rafiki's auth server:
 * Web `Request` in, Web `Response` out, Effect throughout, persistence behind the seven-method {@link GnapStore}.
 *
 * ```ts
 * const server = createGnapServer({ baseUrl: "https://auth.example/gnap", store: memoryGnapStore() });
 * const response = await Effect.runPromise(server.route(request)); // mount under /gnap
 * ```
 *
 * Routes below the path of `baseUrl` (Rafiki's layout): `POST /` grant request (`POST /:tenantId` with `tenants`) ·
 * `POST|PATCH|DELETE /continue/:id` (`PATCH`, grant modification, needs a store with `extendedRecords`) ·
 * `POST|DELETE /token/:id` · `GET /interact/:id/:nonce` (start) · `GET /interact/:id/:nonce/finish` ·
 * `GET /grant/:id/:nonce` and `POST /grant/:id/:nonce/:choice` (identity provider back channel, `x-idp-secret`) ·
 * `POST /introspect` (token introspection; Rafiki serves it on a separate port at `/`).
 *
 * @see https://openpayments.dev/apis/auth-server/
 * @see https://www.rfc-editor.org/rfc/rfc9635
 * @module
 */
import * as Effect from "effect/Effect";
import type { AccessItem } from "../index";
import type { GnapServerConfig, InteractionDetails } from "./config";
import { createCore, relativePath } from "./core";
import { grantHandlers, type GrantHandlers } from "./grant";
import { fail, respond, type GnapRouteError, type ParamHandler, type RequestHandler } from "./http";
import { decideInteraction, getInteraction, interactionHandlers } from "./interaction";
import { introspect, tokenHandlers, type TokenIntrospection } from "./token";

export { fetchClientKeys } from "./client-keys";

export type {
  ConsentUrlParams,
  GnapGrantRequest,
  GnapInteractRequest,
  GnapServerConfig,
  InteractionDetails,
  TenantConfig,
} from "./config";

export { defaultRequiresInteraction } from "./grant";

export { GnapRouteError } from "./http";

export { memoryGnapStore } from "./memory-store";

export type { GnapStore, GrantPatch, GrantRecord, GrantState, TokenRecord, TokenRequest } from "./store";

export type { TokenIntrospection } from "./token";

/** Handlers by route; each takes the Web `Request` (and the route's path parameters) and never fails. */
export interface GnapHandlers {
  /** `POST /` (or `POST /:tenantId` with `tenants`; pass `{ tenantId }` then) */
  readonly createGrant: GrantHandlers["createGrant"];
  /** `POST /continue/:id` */
  readonly continueGrant: ParamHandler<{ readonly id: string }>;
  /** `PATCH /continue/:id` (RFC 9635 §5.3); `501` unless the store has `extendedRecords`. */
  readonly modifyGrant: ParamHandler<{ readonly id: string }>;
  /** `DELETE /continue/:id` */
  readonly cancelGrant: ParamHandler<{ readonly id: string }>;
  /** `POST /token/:id` */
  readonly rotateToken: ParamHandler<{ readonly id: string }>;
  /** `DELETE /token/:id` */
  readonly revokeToken: ParamHandler<{ readonly id: string }>;
  /** `GET /interact/:id/:nonce` */
  readonly startInteraction: ParamHandler<{ readonly id: string; readonly nonce: string }>;
  /** `GET /interact/:id/:nonce/finish` */
  readonly finishInteraction: ParamHandler<{ readonly id: string; readonly nonce: string }>;
  /** `GET /grant/:id/:nonce` (needs `x-idp-secret`) */
  readonly idpGetGrant: ParamHandler<{ readonly id: string; readonly nonce: string }>;
  /** `POST /grant/:id/:nonce/:choice` (needs `x-idp-secret`) */
  readonly idpDecide: ParamHandler<{ readonly id: string; readonly nonce: string; readonly choice: string }>;
  /** `POST /introspect`; `404` unless `introspection` is configured. */
  readonly introspect: RequestHandler;
}

/** The server returned by {@link createGnapServer}. */
export interface GnapServer {
  /** Dispatches by method and path below the base path; unknown routes are `404`. Never fails. */
  readonly route: RequestHandler;
  readonly handlers: GnapHandlers;
  /** What the consent UI shows for an interaction (`interactId` and `nonce` of the consent URL). */
  readonly getInteraction: (args: {
    readonly interactId: string;
    readonly nonce: string;
  }) => Effect.Effect<InteractionDetails, GnapRouteError>;
  /**
   * Records the decision (`choice` is `accept` or `reject`) of the resource owner, for a consent page that
   * authenticates them itself. With their `userId` `interaction.authorize` must allow it (no hook: `403`); without a
   * `userId` the caller vouches for the decision. Returns the URL of
   * `/interact/:id/:nonce/finish`, where the owner's browser goes next (it carries the session cookie of the start step).
   */
  readonly decideInteraction: (args: {
    readonly interactId: string;
    readonly nonce: string;
    readonly choice: string;
    readonly userId?: string;
  }) => Effect.Effect<{ readonly redirect: string }, GnapRouteError>;
  /**
   * Introspection result for an access token value; unknown, expired and revoked tokens are `{ active: false }`.
   * An active answer also carries the grant's `tenantId` and the token's whole `grantAccess` (not part of `POST /introspect`).
   */
  readonly introspectToken: (
    accessToken: string,
    access?: ReadonlyArray<AccessItem>,
  ) => Effect.Effect<TokenIntrospection>;
}

interface Params {
  id: string;
  nonce: string;
  choice: string;
  tenantId: string;
}

interface Route {
  readonly method: string;
  /** Path below the base path; `:name` segments are parameters. */
  readonly path: string;
  readonly handle: (request: Request, params: Params) => Effect.Effect<Response>;
}

/** Creates the authorisation server. See {@link GnapServerConfig}. */
export function createGnapServer(config: GnapServerConfig): GnapServer {
  const core = createCore(config);

  const handlers: GnapHandlers = {
    ...grantHandlers(core),
    ...tokenHandlers(core),
    ...interactionHandlers(core),
  };

  const routes: ReadonlyArray<Route> = [
    ...(config.tenants === undefined
      ? [{ method: "POST", path: "", handle: (request: Request) => handlers.createGrant(request) }]
      : []),
    { method: "POST", path: "continue/:id", handle: handlers.continueGrant },
    { method: "PATCH", path: "continue/:id", handle: handlers.modifyGrant },
    { method: "DELETE", path: "continue/:id", handle: handlers.cancelGrant },
    { method: "POST", path: "token/:id", handle: handlers.rotateToken },
    { method: "DELETE", path: "token/:id", handle: handlers.revokeToken },
    { method: "GET", path: "interact/:id/:nonce", handle: handlers.startInteraction },
    { method: "GET", path: "interact/:id/:nonce/finish", handle: handlers.finishInteraction },
    { method: "GET", path: "grant/:id/:nonce", handle: handlers.idpGetGrant },
    { method: "POST", path: "grant/:id/:nonce/:choice", handle: handlers.idpDecide },
    { method: "POST", path: "introspect", handle: (request) => handlers.introspect(request) },
    // Last, so the fixed single-segment routes win over a tenant of the same name.
    ...(config.tenants === undefined
      ? []
      : [
          {
            method: "POST",
            path: ":tenantId",
            handle: (request: Request, params: Params) => handlers.createGrant(request, { tenantId: params.tenantId }),
          },
        ]),
  ];

  /** The parameters of `segments` against `path`, or `null` when they do not match. */
  const match = (path: string, segments: ReadonlyArray<string>): Params | null => {
    const pattern = path === "" ? [] : path.split("/");
    const params: Params = { id: "", nonce: "", choice: "", tenantId: "" };

    if (pattern.length !== segments.length) return null;

    for (const [index, part] of pattern.entries()) {
      const segment = segments[index] ?? "";

      if (part.startsWith(":")) {
        // SAFETY: `part` is one of the `:id` / `:nonce` / `:choice` placeholders of the route table below.
        params[part.slice(1) as keyof Params] = segment;
      } else if (part !== segment) return null;
    }

    return params;
  };

  const route: RequestHandler = (request) => {
    const rest = relativePath(core, request);

    try {
      // `""` and `"/"` are the root; below it a trailing slash is a different (unknown) path.
      const segments = (rest === "/" || rest === "" || rest === null ? "" : rest.slice(1))
        .split("/")
        .filter((segment, index, all) => all.length > 1 || segment !== "")
        .map(decodeURIComponent);

      for (const candidate of rest === null ? [] : routes) {
        const params = candidate.method === request.method ? match(candidate.path, segments) : null;

        if (params !== null) return candidate.handle(request, params);
      }
    } catch {
      // Malformed percent-encoding: no route.
    }

    return respond(core, fail(404, "invalid_request", "not found"));
  };

  return {
    route,
    handlers,
    getInteraction: (args) => getInteraction(core, args),
    decideInteraction: (args) => decideInteraction(core, args),
    introspectToken: (accessToken, access) => introspect(core, accessToken, access),
  };
}
