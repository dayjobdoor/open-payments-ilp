/**
 * Better Auth plugin that turns a Better Auth server into an Open Payments GNAP authorisation server: a thin
 * adapter over `open-payments-ilp/gnap/server` (all protocol logic lives there). Requires the optional peer
 * `better-auth`.
 *
 * Mount it in the `plugins` of `betterAuth(...)`. The GNAP routes of the core live under `{baseURL}/gnap`
 * (`/api/auth/gnap` by default): `POST /gnap` grant request (`POST /gnap/:tenantId` with `tenants`), `POST|DELETE /gnap/continue/:id`,
 * `POST|DELETE /gnap/token/:id`, `GET /gnap/interact/:id/:nonce[/finish]`, the identity provider back channel
 * `GET /gnap/grant/:id/:nonce` and `POST /gnap/grant/:id/:nonce/:choice` (with `idpSecret` or `tenants`) and
 * `POST /gnap/introspect` (with `introspection`). Consent by the signed-in Better Auth user is added on top:
 * `GET /gnap/interaction/:id/:nonce` and `POST /gnap/interaction/:id/:nonce/accept|reject`; all three ask
 * `interaction.authorize` about the signed-in user (no hook: `403`), the GET included, because it shows the grant's
 * access list and the client.
 * Run the Better Auth migration to create the `gnapGrant`, `gnapAccessToken` and `gnapNonce` tables.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9635
 * @see https://openpayments.dev/apis/auth-server/operations/post-request/
 * @module
 */
import { APIError, createAuthEndpoint, sensitiveSessionMiddleware, type AuthEndpoint } from "better-auth/api";
import type { BetterAuthPlugin } from "better-auth/types";
import * as Effect from "effect/Effect";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import type { StandardSchemaV1 } from "effect/StandardSchema";
import type { AccessItem, TokenIntrospectionResponse } from "../gnap/index";
import {
  bindingFromRequest,
  createGnapServer,
  type GnapRouteError,
  type GnapServer,
  type GnapServerConfig,
} from "../gnap/server/index";
import * as schemas from "../open-payments/schemas";
import { GNAP_ERROR_CODES, gnapSchema } from "./schema";
import { betterAuthGnapStore, revokeUserGrants, type GnapDb } from "./store";

export { GNAP_ERROR_CODES, gnapSchema } from "./schema";

export { betterAuthGnapStore, revokeUserGrants, type GnapDb } from "./store";

export type { GnapRouteError, InteractionDetails } from "../gnap/server/index";

/**
 * Options of the plugin: the configuration of the core (`open-payments-ilp/gnap/server`) without `baseUrl` (the
 * Better Auth base URL plus `/gnap`) and `store` (Better Auth's database).
 */
export type GnapOptions = Omit<GnapServerConfig, "baseUrl" | "store"> & {
  /**
   * The plugin's limits on the unauthenticated GNAP endpoints, as Better Auth rate-limit rules: `grantRequest` for
   * `POST /gnap` (`POST /gnap/:tenantId` with `tenants`), default 20 requests a minute, and `continue` for
   * `/gnap/continue/*`, default 30 a minute; `false` leaves both to you (Better Auth's own `rateLimit.customRules`
   * apply either way, and its global limit when no rule matches).
   *
   * Better Auth counts per client IP address and path, before the signature is checked. Without a client IP header
   * (a direct deployment) every client shares one bucket, so one caller can exhaust it for all; behind a proxy,
   * configure `advanced.ipAddress` (`ipAddressHeaders`, trusted proxies) or a client-chosen `X-Forwarded-For` is
   * believed. A client app that sends all its users' logins from one address needs a higher `max`.
   */
  readonly rateLimit?: GnapRateLimit | false;
};

/** One Better Auth rate-limit rule: at most `max` requests per `window` seconds, per client address and path. */
export interface GnapRateLimitRule {
  /** Seconds. */
  readonly window: number;
  readonly max: number;
}

/** The rules of the plugin's rate limit; a missing one keeps its default. */
export interface GnapRateLimit {
  /** The grant request. Default: 20 a minute. */
  readonly grantRequest?: GnapRateLimitRule;
  /** Continuing, rotating... a grant: `/gnap/continue/*`. Default: 30 a minute. */
  readonly continue?: GnapRateLimitRule;
}

/** An endpoint as stored in `BetterAuthPlugin.endpoints`. */
type AnyEndpoint = NonNullable<BetterAuthPlugin["endpoints"]>[string];

/** Body of `auth.api.gnapIntrospect`. */
export interface IntrospectionInput {
  readonly access_token: string;
  readonly access?: ReadonlyArray<AccessItem>;
}

const introspectionBody = Schema.toStandardSchemaV1(
  Schema.Struct({ access_token: Schema.String, access: Schema.optionalKey(Schema.Array(schemas.accessItem)) }),
);

/** `auth.api.gnapIntrospect`. */
export type GnapIntrospectEndpoint = AuthEndpoint<
  string,
  { method: "POST"; body: StandardSchemaV1<IntrospectionInput, IntrospectionInput> },
  TokenIntrospectionResponse
>;

/** Every endpoint of the plugin, by name (`auth.api.<name>`); the HTTP routes are listed in the module docs. */
export type GnapEndpoints = {
  readonly gnapGrantRequest: AnyEndpoint;
  readonly gnapContinueGrant: AnyEndpoint;
  readonly gnapCancelGrant: AnyEndpoint;
  readonly gnapRotateToken: AnyEndpoint;
  readonly gnapRevokeToken: AnyEndpoint;
  readonly gnapStartInteraction: AnyEndpoint;
  readonly gnapFinishInteraction: AnyEndpoint;
  /** Identity provider back channel; present when `idpSecret` or `tenants` is set. */
  readonly gnapIdpGetGrant?: AnyEndpoint;
  readonly gnapIdpDecide?: AnyEndpoint;
  /** `POST /gnap/introspect`; only present with `introspection`. */
  readonly gnapIntrospectRequest?: AnyEndpoint;
  /** Server-side only. */
  readonly gnapIntrospect: GnapIntrospectEndpoint;
  readonly gnapGetInteraction: AnyEndpoint;
  readonly gnapAcceptInteraction: AnyEndpoint;
  readonly gnapRejectInteraction: AnyEndpoint;
};

/** The Better Auth plugin returned by {@link gnap}. */
export interface GnapPlugin extends BetterAuthPlugin {
  readonly id: "gnap";
  readonly endpoints: GnapEndpoints;
}

const PER_MINUTE = 60;

const DEFAULT_GRANT_REQUEST_LIMIT: GnapRateLimitRule = { window: PER_MINUTE, max: 20 };

const DEFAULT_CONTINUE_LIMIT: GnapRateLimitRule = { window: PER_MINUTE, max: 30 };

/**
 * A consent failure of the core as the Better Auth error of the same status, except that a denial (`user_denied`,
 * `401` in the GNAP answers) is `403` here: `401` is what Better Auth answers an anonymous user, and a consent page
 * must not take a denial for "sign in".
 */
const apiError = ({ status, code, description }: GnapRouteError): APIError =>
  // SAFETY: Better Auth types `status` as a literal union; the core only produces statuses of that union (4xx/5xx).
  new APIError((code === "user_denied" ? 403 : status) as 400, { code, message: description });

/** Runs a core program at the Better Auth boundary; its failures become `APIError`s. */
const runOrThrow = async <A>(program: Effect.Effect<A, GnapRouteError>): Promise<A> => {
  const result = await Effect.runPromise(Effect.result(program));

  if (Result.isFailure(result)) throw apiError(result.failure);

  return result.success;
};

type Method = "GET" | "POST" | "DELETE";

/**
 * Creates the GNAP authorisation server plugin. See {@link GnapOptions}.
 *
 * `auth.api.gnapIntrospect({ body: { access_token, access? } })` returns the in-process introspection result
 * (`{ active: false }` or `{ active: true, grant, access, client, tenantId, grantAccess }`; `grantAccess` is the grant's
 * whole access list). It is not tenant-scoped and not the RFC 9767 shape that `POST /gnap/introspect` answers, so do
 * not forward it as an HTTP response.
 */
export function gnap(options: GnapOptions = {}): GnapPlugin {
  const { rateLimit, ...serverOptions } = options;

  /** The core on this request's database and base URL. Cheap: closures only. */
  const serverFor = (context: { readonly baseURL: string; readonly adapter: GnapDb }): GnapServer =>
    createGnapServer({
      ...serverOptions,
      baseUrl: `${context.baseURL}/gnap`,
      store: betterAuthGnapStore(context.adapter),
    });

  /** An endpoint that hands the raw request to the core's router. */
  const route = (path: string, method: Method): AnyEndpoint =>
    createAuthEndpoint(
      path,
      { method, disableBody: true, requireRequest: true, metadata: { scope: "http" } },
      async (ctx) => Effect.runPromise(serverFor(ctx.context).route(ctx.request)),
    );

  /** `userId` of the signed-in user plus the interaction named in the path. */
  const decide = (choice: "accept" | "reject") =>
    createAuthEndpoint(
      `/gnap/interaction/:id/:nonce/${choice}`,
      { method: "POST", use: [sensitiveSessionMiddleware], requireRequest: true, metadata: { scope: "http" } },
      async (ctx) => {
        // The decision is made in the browser that opened the interaction: its binding cookie is sent along.
        const binding = ctx.request === undefined ? undefined : bindingFromRequest(ctx.request, ctx.params.id);

        return ctx.json(
          await runOrThrow(
            serverFor(ctx.context).decideInteraction({
              interactId: ctx.params.id,
              nonce: ctx.params.nonce,
              choice,
              userId: ctx.context.session.user.id,
              ...(binding !== undefined && { binding }),
            }),
          ),
        );
      },
    );

  const gnapGetInteraction = createAuthEndpoint(
    "/gnap/interaction/:id/:nonce",
    { method: "GET", use: [sensitiveSessionMiddleware], metadata: { scope: "http" } },
    async (ctx) => {
      const details = await runOrThrow(
        serverFor(ctx.context).getInteraction({ interactId: ctx.params.id, nonce: ctx.params.nonce }),
      );

      // The details name the client and the access (wallet addresses): the user the hook refuses may not read them
      // either, as the decision is theirs only when the hook says so (the same rule as `decideInteraction`).
      const authorize = options.interaction?.authorize;

      const allowed =
        authorize === undefined
          ? false
          : await Effect.runPromise(authorize({ userId: ctx.context.session.user.id, details }));

      if (allowed !== true) throw APIError.from(403, GNAP_ERROR_CODES.REQUEST_DENIED);

      return ctx.json(details);
    },
  );

  const gnapIntrospect = createAuthEndpoint.serverOnly(
    { method: "POST", body: introspectionBody },
    async (ctx): Promise<TokenIntrospectionResponse> =>
      Effect.runPromise(serverFor(ctx.context).introspectToken(ctx.body.access_token, ctx.body.access)),
  );

  return {
    id: "gnap",
    schema: gnapSchema,
    // Deleting a user ends what the user authorised, whether or not the database cascades the foreign key.
    init: (context) => ({
      options: {
        databaseHooks: {
          user: {
            delete: {
              before: async (user) => {
                await revokeUserGrants(context.adapter, user.id, (options.clock?.() ?? new Date()).getTime());
              },
            },
          },
        },
      },
    }),
    endpoints: {
      gnapGrantRequest: route(options.tenants === undefined ? "/gnap" : "/gnap/:tenantId", "POST"),
      gnapContinueGrant: route("/gnap/continue/:id", "POST"),
      gnapCancelGrant: route("/gnap/continue/:id", "DELETE"),
      gnapRotateToken: route("/gnap/token/:id", "POST"),
      gnapRevokeToken: route("/gnap/token/:id", "DELETE"),
      gnapStartInteraction: route("/gnap/interact/:id/:nonce", "GET"),
      gnapFinishInteraction: route("/gnap/interact/:id/:nonce/finish", "GET"),
      ...((options.idpSecret !== undefined || options.tenants !== undefined) && {
        gnapIdpGetGrant: route("/gnap/grant/:id/:nonce", "GET"),
        gnapIdpDecide: route("/gnap/grant/:id/:nonce/:choice", "POST"),
      }),
      ...(options.introspection !== undefined && { gnapIntrospectRequest: route("/gnap/introspect", "POST") }),
      gnapIntrospect,
      gnapGetInteraction,
      gnapAcceptInteraction: decide("accept"),
      gnapRejectInteraction: decide("reject"),
    },
    rateLimit:
      rateLimit === false
        ? []
        : [
            {
              // With `tenants` the grant request is `POST /gnap/:tenantId` (one segment; `/gnap/introspect` is not it).
              pathMatcher: (path) =>
                path === "/gnap" ||
                (options.tenants !== undefined && /^\/gnap\/[^/]+$/.test(path) && path !== "/gnap/introspect"),
              ...(rateLimit?.grantRequest ?? DEFAULT_GRANT_REQUEST_LIMIT),
            },
            {
              pathMatcher: (path) => path.startsWith("/gnap/continue/"),
              ...(rateLimit?.continue ?? DEFAULT_CONTINUE_LIMIT),
            },
          ],
    $ERROR_CODES: GNAP_ERROR_CODES,
  };
}
