import * as Cause from "effect/Cause";
import * as Effect from "effect/Effect";
import { HttpSignatureError } from "../http-signatures/errors";
import type * as server from "../gnap/server/index";
import type { GnapServerOptions, GnapStore } from "../plain/gnap-server";
import { attemptResolver } from "./plain";

/**
 * Adapters between the Promise-flavoured GNAP server types of `open-payments-ilp/plain/gnap/server` and the Effect
 * ones. Internal: only the `plain/*` modules import this, so no Effect type reaches a public plain entry point.
 */

type EffectConfig = server.GnapServerConfig;

/** Lifts a Promise store to the Effect `GnapStore` the server runs on. A rejecting method is a defect, as in the Effect store. */
export const toEffectStore = (store: GnapStore): server.GnapStore => ({
  createGrant: (grant) => Effect.promise(async () => store.createGrant(grant)),
  findGrant: (by, value) => Effect.promise(async () => store.findGrant(by, value)),
  updateGrant: (id, version, patch) => Effect.promise(async () => store.updateGrant(id, version, patch)),
  createToken: (token) => Effect.promise(async () => store.createToken(token)),
  findTokenWithGrant: (by, value) => Effect.promise(async () => store.findTokenWithGrant(by, value)),
  revokeTokens: (by, value, at) => Effect.promise(async () => store.revokeTokens(by, value, at)),
  claimNonce: (key, expiresAt, now) => Effect.promise(async () => store.claimNonce(key, expiresAt, now)),
  ...(store.extendedRecords === undefined ? {} : { extendedRecords: store.extendedRecords }),
  ...(store.interactionBinding === undefined ? {} : { interactionBinding: store.interactionBinding }),
});

/** Lowers an Effect `GnapStore` to the Promise port. Every method is called on `store`, so class-based stores work. */
export const toPromiseStore = (store: server.GnapStore): GnapStore => ({
  createGrant: async (grant) => Effect.runPromise(store.createGrant(grant)),
  findGrant: async (by, value) => Effect.runPromise(store.findGrant(by, value)),
  updateGrant: async (id, version, patch) => Effect.runPromise(store.updateGrant(id, version, patch)),
  createToken: async (token) => Effect.runPromise(store.createToken(token)),
  findTokenWithGrant: async (by, value) => Effect.runPromise(store.findTokenWithGrant(by, value)),
  revokeTokens: async (by, value, at) => Effect.runPromise(store.revokeTokens(by, value, at)),
  claimNonce: async (key, expiresAt, now) => Effect.runPromise(store.claimNonce(key, expiresAt, now)),
  ...(store.extendedRecords === undefined ? {} : { extendedRecords: store.extendedRecords }),
  ...(store.interactionBinding === undefined ? {} : { interactionBinding: store.interactionBinding }),
});

/**
 * Lifts the hooks of a plain configuration to the Effect `GnapServerConfig` fields. `resolveClientKeys` returning
 * `null`/`undefined` or throwing an `HttpSignatureError` is an expected failure (`unknown-key`, answered `400`); any
 * other throw is a defect (`500`, reported to `onError`).
 */
export const toEffectOptions = (options: GnapServerOptions): Omit<EffectConfig, "baseUrl" | "store"> => {
  const { tenants, resolveClientKeys, interaction, introspection, onError, ...rest } = options;
  const { authorize, ...interactionRest } = interaction ?? {};

  return {
    ...rest,
    ...(tenants === undefined ? {} : { tenants: (tenantId) => Effect.promise(async () => tenants(tenantId)) }),
    ...(resolveClientKeys === undefined
      ? {}
      : {
          resolveClientKeys: (walletAddress) =>
            attemptResolver(() => resolveClientKeys(walletAddress)).pipe(
              Effect.flatMap((keys) =>
                keys == null
                  ? Effect.fail(
                      new HttpSignatureError({
                        reason: "unknown-key",
                        message: "Client keys not found",
                      }),
                    )
                  : Effect.succeed(keys),
              ),
            ),
        }),
    ...(interaction === undefined
      ? {}
      : {
          interaction: {
            ...interactionRest,
            ...(authorize === undefined ? {} : { authorize: (args) => Effect.promise(async () => authorize(args)) }),
          },
        }),
    ...(introspection === undefined
      ? {}
      : {
          introspection: {
            authorize: (request) => Effect.promise(async () => introspection.authorize(request)),
          },
        }),
    ...(onError === undefined ? {} : { onError: (cause) => Effect.promise(async () => onError(Cause.squash(cause))) }),
  };
};
