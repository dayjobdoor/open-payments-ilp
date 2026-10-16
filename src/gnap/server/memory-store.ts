import * as Effect from "effect/Effect";
import type { GnapStore, GrantRecord, TokenRecord } from "./store";

/**
 * A {@link GnapStore} in process memory, for tests and local development. Nothing survives a restart and lookups
 * scan every record (O(n)); use a database-backed store in production.
 */
export function memoryGnapStore(): GnapStore {
  const grants = new Map<string, GrantRecord>();
  const tokens = new Map<string, TokenRecord>();
  const nonces = new Map<string, number>();

  const unique = <R extends { readonly id: string }>(
    records: Map<string, R>,
    record: R,
    columns: ReadonlyArray<keyof R>,
  ) => {
    for (const other of records.values()) {
      for (const column of columns) {
        if (other[column] !== null && other[column] === record[column]) throw new Error(`duplicate ${String(column)}`);
      }
    }
  };

  return {
    // Records are kept as they are, so every optional field of them survives.
    extendedRecords: true,
    createGrant: (grant) =>
      Effect.sync(() => {
        unique(grants, grant, ["id", "continueId", "interactId"]);
        grants.set(grant.id, grant);
      }),
    findGrant: (by, value) => Effect.sync(() => [...grants.values()].find((grant) => grant[by] === value) ?? null),
    // Synchronous, so atomic: nothing can run between the version check and the write.
    updateGrant: (id, version, patch) =>
      Effect.sync(() => {
        const grant = grants.get(id);

        if (grant === undefined || grant.version !== version) return false;
        grants.set(id, { ...grant, ...patch, version: version + 1 });

        return true;
      }),
    createToken: (token) =>
      Effect.sync(() => {
        unique(tokens, token, ["id", "valueHash", "managementId"]);
        tokens.set(token.id, token);
      }),
    findTokenWithGrant: (by, value) =>
      Effect.sync(() => {
        const token = [...tokens.values()].find((candidate) => candidate[by] === value);
        const grant = token === undefined ? undefined : grants.get(token.grantId);

        return token === undefined || grant === undefined ? null : { token, grant };
      }),
    revokeTokens: (by, value, at) =>
      Effect.sync(() => {
        let revoked = 0;

        for (const token of tokens.values()) {
          if (token[by] !== value || token.revokedAt !== null) continue;
          tokens.set(token.id, { ...token, revokedAt: at });
          revoked += 1;
        }

        return revoked;
      }),
    claimNonce: (key, expiresAt, now) =>
      Effect.sync(() => {
        const claimed = nonces.get(key);

        if (claimed !== undefined && claimed > now) return false;
        nonces.set(key, expiresAt);

        return true;
      }),
  };
}
