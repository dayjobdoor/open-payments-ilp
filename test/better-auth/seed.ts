import * as Effect from "effect/Effect";
import type { GnapStore } from "../../src/gnap/server/index";

/**
 * An approved grant `g{n}` of `userId` with one live token `t{n}` (value hash `v{n}`); `n` is 1 unless given, so the
 * grant of a test that seeds one is `g1` and its token's hash `v1`.
 */
export const seedApprovedGrant = async (store: GnapStore, userId: string, n = 1): Promise<void> => {
  await Effect.runPromise(
    store.createGrant({
      id: `g${n}`,
      version: 0,
      tenantId: null,
      state: "APPROVED",
      client: "https://wallet.example/alice",
      jwk: null,
      access: [{ type: "incoming-payment", actions: ["read"] }],
      subject: null,
      interactId: null,
      interactNonce: null,
      interactRef: null,
      interactExpiresAt: null,
      finishUri: null,
      clientNonce: null,
      finishHashMethod: null,
      label: null,
      userId,
      continueId: `c${n}`,
      continueTokenHash: "h",
      lastContinuedAt: 1,
      createdAt: 1,
      updatedAt: 1,
    }),
  );
  await Effect.runPromise(
    store.createToken({
      id: `t${n}`,
      grantId: `g${n}`,
      valueHash: `v${n}`,
      managementId: `m${n}`,
      expiresAt: Date.now() + 60_000,
      revokedAt: null,
      createdAt: 1,
    }),
  );
};
