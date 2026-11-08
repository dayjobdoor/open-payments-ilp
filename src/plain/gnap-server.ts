import { toEffectOptions, toEffectStore, toPromiseStore } from "../internal/plain-gnap";
import { task, type Promisified } from "../internal/plain";
import type { JWK } from "../open-payments/types";
import { fetchClientKeys as fetchClientKeysEffect } from "../gnap/server/client-keys";
import * as server from "../gnap/server/index";

/**
 * Promise flavour of `open-payments-ilp/gnap/server`: request handlers and the in-process helpers return a `Promise`
 * and the {@link GnapStore} port is implemented with `async` methods. The hooks `tenants`, `resolveClientKeys`,
 * `interaction.authorize`, `introspection.authorize` and `onError` may be plain or `async` functions; `clock`,
 * `generateToken`, `policy.requiresInteraction` and `interaction.consentUrl` stay synchronous. `getInteraction` and
 * `decideInteraction` reject with `GnapRouteError`.
 */

export { defaultRequiresInteraction, GnapRouteError } from "../gnap/server/index";
export type {
  ConsentUrlParams,
  GnapGrantRequest,
  GnapInteractRequest,
  GrantPatch,
  GrantRecord,
  GrantState,
  InteractionDetails,
  TenantConfig,
  TokenIntrospection,
  TokenRecord,
  TokenRequest,
} from "../gnap/server/index";

type MaybePromise<T> = T | Promise<T>;

type EffectConfig = server.GnapServerConfig;

/** Persistence port: the same operations as the Effect `GnapStore`, each returning a `Promise`. */
export type GnapStore = Promisified<server.GnapStore>;

/** Configuration of {@link createGnapServer}; hooks may return a value or a `Promise`. */
export interface GnapServerConfig extends Omit<
  EffectConfig,
  "store" | "tenants" | "resolveClientKeys" | "interaction" | "introspection" | "onError"
> {
  readonly store: GnapStore;
  readonly tenants?: (tenantId: string) => MaybePromise<server.TenantConfig | null>;
  /**
   * Public keys of the client's wallet address. Return `null`/`undefined` or throw an `HttpSignatureError` to answer
   * `400 invalid_client`; any other throw is a defect: `500`, reported to `onError`.
   */
  readonly resolveClientKeys?: (walletAddress: string) => MaybePromise<ReadonlyArray<JWK> | null | undefined>;
  readonly interaction?: Omit<NonNullable<EffectConfig["interaction"]>, "authorize"> & {
    readonly authorize?: (args: {
      readonly userId: string;
      readonly details: server.InteractionDetails;
    }) => MaybePromise<boolean>;
  };
  readonly introspection?: {
    readonly authorize: (request: Request) => MaybePromise<boolean | { readonly tenantId: string }>;
  };
  /**
   * Receives the error behind a defect that ends in a `500`: a store outage, a throwing hook, a bug (the squashed
   * cause). The server's own `500` answers (exhausted concurrency retries, a grant without its finish URI) do not
   * reach it. Its own failure is ignored.
   */
  readonly onError?: (error: unknown) => MaybePromise<void>;
}

/** The server's options except `baseUrl` and `store` (the hooks and every other setting), as the Better Auth plugin takes them. */
export type GnapServerOptions = Omit<GnapServerConfig, "baseUrl" | "store">;

export type GnapHandlers = Promisified<server.GnapHandlers>;

export interface GnapServer extends Promisified<Omit<server.GnapServer, "handlers">> {
  readonly handlers: GnapHandlers;
}

/** The OAuth-style GNAP authorisation server (RFC 9635/9767) on Web Standard `Request`/`Response`. */
export function createGnapServer(config: GnapServerConfig): GnapServer {
  const { baseUrl, store, ...options } = config;
  const built = server.createGnapServer({
    ...toEffectOptions(options),
    baseUrl,
    store: toEffectStore(store),
  });

  return {
    route: task(built.route),
    handlers: {
      createGrant: task(built.handlers.createGrant),
      continueGrant: task(built.handlers.continueGrant),
      modifyGrant: task(built.handlers.modifyGrant),
      cancelGrant: task(built.handlers.cancelGrant),
      rotateToken: task(built.handlers.rotateToken),
      revokeToken: task(built.handlers.revokeToken),
      startInteraction: task(built.handlers.startInteraction),
      finishInteraction: task(built.handlers.finishInteraction),
      idpGetGrant: task(built.handlers.idpGetGrant),
      idpDecide: task(built.handlers.idpDecide),
      introspect: task(built.handlers.introspect),
    },
    getInteraction: task(built.getInteraction),
    decideInteraction: task(built.decideInteraction),
    introspectToken: task(built.introspectToken),
  };
}

/** An in-memory {@link GnapStore} for tests and local development: nothing is persisted and nothing is shared between processes. */
export const memoryGnapStore = (): GnapStore => toPromiseStore(server.memoryGnapStore());

/**
 * The default client-key lookup, `GET {walletAddress}/jwks.json`. Pass the result as `resolveClientKeys`, or call it
 * yourself; failures reject with `HttpSignatureError`.
 *
 * SSRF caveat: only `https` wallet addresses with a dotted, public-looking host name are fetched, redirects are
 * refused and responses over 64 KiB are cut off. Host names are NOT resolved, so a name that points at a private
 * address, or one that DNS rebinding switches to a private address between checks, is not caught. Pass your own
 * `resolveClientKeys` (a pinned resolver or an egress proxy) if clients are untrusted.
 */
export const fetchClientKeys = (
  fetchImpl: typeof globalThis.fetch | undefined,
): ((walletAddress: string) => Promise<ReadonlyArray<JWK>>) => task(fetchClientKeysEffect(fetchImpl));
