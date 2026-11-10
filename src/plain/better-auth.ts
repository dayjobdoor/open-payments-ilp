import {
  gnap as effectGnap,
  betterAuthGnapStore as effectBetterAuthGnapStore,
  type GnapDb,
} from "../better-auth/index";
import type { GnapPlugin, GnapRateLimit } from "../better-auth/index";
import { toEffectOptions, toPromiseStore } from "../internal/plain-gnap";
import type { GnapServerOptions, GnapStore } from "./gnap-server";

/**
 * `open-payments-ilp/better-auth` with plain hooks: the `tenants`, `resolveClientKeys`, `interaction.authorize`,
 * `introspection.authorize` and `onError` options may be (async) functions instead of Effect-returning ones. The
 * plugin itself is the same Better Auth plugin; Better Auth is a required peer of this entry point.
 */

export {
  GNAP_ERROR_CODES,
  gnapSchema,
  type GnapDb,
  type GnapEndpoints,
  type GnapIntrospectEndpoint,
  type GnapPlugin,
  type GnapRateLimit,
  type GnapRateLimitRule,
  type IntrospectionInput,
} from "../better-auth/index";
export type { GnapRouteError, InteractionDetails } from "../gnap/server/index";

/** The plain server options plus the plugin's `rateLimit` (see `open-payments-ilp/better-auth`). */
export type GnapOptions = GnapServerOptions & { readonly rateLimit?: GnapRateLimit | false };

/** The Better Auth plugin serving the GNAP authorisation server under `{baseURL}/gnap`. */
export const gnap = (options: GnapOptions = {}): GnapPlugin => {
  const { rateLimit, ...serverOptions } = options;
  return effectGnap({ ...toEffectOptions(serverOptions), ...(rateLimit === undefined ? {} : { rateLimit }) });
};

/** A {@link GnapStore} on Better Auth's database adapter. */
export const betterAuthGnapStore = (db: GnapDb): GnapStore => toPromiseStore(effectBetterAuthGnapStore(db));
