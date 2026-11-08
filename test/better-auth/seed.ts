import * as Effect from "effect/Effect";
import type { GnapStore } from "../../src/gnap/server/index";

/** An approved grant `g1` of `userId` with one live token `t1` (value hash `v1`). */
export const seedApprovedGrant = async (store: GnapStore, userId: string): Promise<void> => {
  await Effect.runPromise(
    store.createGrant({
      id: "g1",
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
      continueId: "c1",
      continueTokenHash: "h",
      lastContinuedAt: 1,
      createdAt: 1,
      updatedAt: 1,
    }),
  );
  await Effect.runPromise(
    store.createToken({
      id: "t1",
      grantId: "g1",
      valueHash: "v1",
      managementId: "m1",
      expiresAt: Date.now() + 60_000,
      revokedAt: null,
      createdAt: 1,
    }),
  );
};
