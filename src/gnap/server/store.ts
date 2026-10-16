import type * as Effect from "effect/Effect";
import type { AccessItem, Subject } from "../index";
import type { JWK } from "../../open-payments/types";

/**
 * Lifecycle of a grant, Rafiki's grant state, finalization reason and interaction state in one value.
 *
 * `PENDING` waits for the resource owner · `ACCEPTED` / `DENIED` the owner decided (Rafiki's interaction state), the
 * browser has not reached `/finish` yet · `APPROVED` `/finish` was reached for an accepted interaction, the client
 * may collect the access token (grants that need no consent are created `APPROVED`, and like in Rafiki a poll of
 * one issues another token) · `REJECTED` `/finish` was reached for a denied one · `FINALIZED` the access token was
 * issued through a continuation · `REVOKED` cancelled by the client; every token of it is revoked.
 */
export type GrantState = "PENDING" | "ACCEPTED" | "DENIED" | "APPROVED" | "REJECTED" | "FINALIZED" | "REVOKED";

/**
 * A grant, interaction included. Plain JSON: strings, numbers (timestamps are epoch milliseconds), `null` and the
 * JSON columns `jwk`, `access` and `subject`. Only the SHA-256 of the continue token is stored.
 */
export interface GrantRecord {
  readonly id: string;
  /** Optimistic-concurrency counter: `0` on creation, `+1` on every successful {@link GnapStore.updateGrant}. */
  readonly version: number;
  /**
   * Tenant the grant was requested for (Rafiki v2 multi-tenancy, {@link GnapServerConfig.tenants}); `null` on a
   * single-tenant server. Never changes.
   */
  readonly tenantId: string | null;
  readonly state: GrantState;
  /** Wallet address of the client; `null` for a JWK client. */
  readonly client: string | null;
  /** Inline public key of a JWK client; `null` for a wallet address client. */
  readonly jwk: JWK | null;
  readonly access: ReadonlyArray<AccessItem>;
  readonly subject: Subject | null;
  /** Path segment of the interaction URL; `null` for grants without interaction. Unique. */
  readonly interactId: string | null;
  /** Server nonce returned as `interact.finish` and part of the interaction URL. */
  readonly interactNonce: string | null;
  /** The `interact_ref` handed to the client on finish; single use. */
  readonly interactRef: string | null;
  readonly interactExpiresAt: number | null;
  /** `interact.finish.uri` the client asked to be redirected to; `null` when the client polls instead. */
  readonly finishUri: string | null;
  /** `interact.finish.nonce` the client sent. */
  readonly clientNonce: string | null;
  /** `interact.finish.hash_method` the client asked for (RFC 9635 §2.5.2); `null` means `sha-256`. */
  readonly finishHashMethod: "sha-256" | "sha-384" | "sha-512" | null;
  /** `access_token.label` of the request, echoed on every token issued for the grant (RFC 9635 §2.1.1). */
  readonly label: string | null;
  /**
   * Optional, persisted only by stores that set {@link GnapStore.extendedRecords}. `interact.finish.method` of the
   * request: `redirect` (also what `null` and an absent value mean) or `push` (RFC 9635 §2.5.2.2: the server POSTs
   * the finish payload to {@link GrantRecord.finishUri} instead of redirecting the browser).
   */
  readonly finishMethod?: "redirect" | "push" | null;
  /**
   * Optional, persisted only by stores that set {@link GnapStore.extendedRecords}. The tokens of an `access_token`
   * array request (RFC 9635 §2.1.2), one entry per requested token; `access` of the grant is then the union of their
   * items. `null` and an absent value mean the single token form (`access` and `label` of the grant).
   */
  readonly tokenRequests?: ReadonlyArray<TokenRequest> | null;
  /** The resource owner that decided, when the consent came with an authenticated principal. */
  readonly userId: string | null;
  /** Path segment of the continue URL. Unique. */
  readonly continueId: string;
  readonly continueTokenHash: string;
  readonly lastContinuedAt: number;
  readonly createdAt: number;
  readonly updatedAt: number;
}

/** One token of an `access_token` array request: its unique `label` and its own access items. */
export interface TokenRequest {
  readonly label: string;
  readonly access: ReadonlyArray<AccessItem>;
}

/** The fields {@link GnapStore.updateGrant} may change. */
export type GrantPatch = Partial<Omit<GrantRecord, "id" | "version" | "tenantId" | "continueId" | "createdAt">>;

/** An access token. Only the SHA-256 of its value is stored. */
export interface TokenRecord {
  readonly id: string;
  readonly grantId: string;
  /** SHA-256 hex of the token value. Unique. */
  readonly valueHash: string;
  /** Path segment of the token's management URL. Unique. */
  readonly managementId: string;
  readonly expiresAt: number;
  /** Set when the token was revoked or rotated away; `null` while it can still be managed. */
  readonly revokedAt: number | null;
  readonly createdAt: number;
  /**
   * Optional, persisted only by stores that set {@link GnapStore.extendedRecords}. The access this token carries
   * (grants of several tokens, and grants whose request was modified, hold tokens of different access). `null` and an
   * absent value mean the access of the grant.
   */
  readonly access?: ReadonlyArray<AccessItem> | null;
  /** Optional like {@link TokenRecord.access}: the `label` echoed with this token. `null`: none (or the grant's). */
  readonly label?: string | null;
}

/**
 * Everything the authorisation server persists: two record types and seven methods.
 *
 * All methods are Effect programs that cannot fail: a database error is a defect (`Effect.die`), which the server
 * answers as `500`. Records are plain JSON; unknown columns an implementation adds are ignored.
 *
 * The server never needs a transaction: every multi-step change is ordered so that a crash between steps leaves a
 * harmless leftover (an unreferenced token), never a lost or doubled grant. Only the three conditional writes
 * ({@link updateGrant}, {@link revokeTokens} and {@link claimNonce}) must be atomic.
 *
 * The contract kit (`storeContract` from `open-payments-ilp/gnap/server/testing`, which takes your test runner's
 * `describe` and `it`) checks an implementation.
 *
 * ## SQL reference (SQLite / D1 / Postgres)
 *
 * One row per record, one column per field (camelCase names are snake_cased); the `jwk`, `access` and `subject`
 * columns hold JSON text (`jsonb` on Postgres) and timestamps are epoch-millisecond integers (`BIGINT` on Postgres).
 * Map a column back to its field on every read, and `null` to `null`.
 *
 * ```sql
 * CREATE TABLE gnap_grant (
 *   id TEXT PRIMARY KEY, version INTEGER NOT NULL, state TEXT NOT NULL, tenant_id TEXT,
 *   client TEXT, jwk TEXT, access TEXT NOT NULL, subject TEXT,
 *   interact_id TEXT UNIQUE, interact_nonce TEXT, interact_ref TEXT, interact_expires_at INTEGER,
 *   finish_uri TEXT, client_nonce TEXT, finish_hash_method TEXT, label TEXT, user_id TEXT,
 *   continue_id TEXT NOT NULL UNIQUE, continue_token_hash TEXT NOT NULL,
 *   last_continued_at INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
 * );
 * CREATE TABLE gnap_access_token (
 *   id TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES gnap_grant (id) ON DELETE CASCADE,
 *   value_hash TEXT NOT NULL UNIQUE, management_id TEXT NOT NULL UNIQUE,
 *   expires_at INTEGER NOT NULL, revoked_at INTEGER, created_at INTEGER NOT NULL
 * );
 * CREATE INDEX gnap_access_token_grant_id ON gnap_access_token (grant_id);
 * CREATE TABLE gnap_nonce (key TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
 * ```
 *
 * - `createGrant` / `createToken`: a plain `INSERT`; the unique constraints turn a duplicate into the defect.
 * - `findGrant`: `SELECT * FROM gnap_grant WHERE <column> = ?`. `<column>` comes from `by`, a closed
 *   union: map it through a fixed table, never interpolate it from outside.
 * - `findTokenWithGrant`: the same for a token, joined to its grant in ONE statement:
 *   `SELECT … FROM gnap_access_token t JOIN gnap_grant g ON g.id = t.grant_id WHERE t.<column> = ?`.
 * - `updateGrant`: set the columns of the keys present in `patch` (a key is only present when it changes) and bump
 *   the counter in the same statement, then return whether a row changed. The `version` guard is the whole
 *   concurrency control of the server:
 *   `UPDATE gnap_grant SET state = ?, updated_at = ?, version = version + 1 WHERE id = ? AND version = ?`.
 * - `revokeTokens`: `UPDATE gnap_access_token SET revoked_at = ? WHERE <id | grant_id> = ? AND revoked_at IS NULL`,
 *   returning the affected-row count (`meta.changes` on D1, `rowCount` on `pg`).
 * - `claimNonce`: `INSERT INTO gnap_nonce (key, expires_at) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET
 *   expires_at = excluded.expires_at WHERE gnap_nonce.expires_at <= ?` (the last `?` is `now`), then whether a row
 *   changed.
 *
 * No transaction is needed anywhere, and the server never lists or counts records, so retention is yours: a token
 * can be deleted once it expired, a nonce row once its `expires_at` passed, a grant once it has no live token and its client no longer continues it.
 *
 * ## Optional capabilities
 *
 * A store that also persists {@link GrantRecord.finishMethod}, {@link GrantRecord.tokenRequests},
 * {@link TokenRecord.access} and {@link TokenRecord.label} (four more nullable columns, JSON text for the two
 * arrays: `finish_method TEXT, token_requests TEXT` on the grant table, `access TEXT, label TEXT` on the token
 * table) sets {@link GnapStore.extendedRecords} and gets the features that need them: `PATCH /continue/:id` (grant
 * modification, RFC 9635 §5.3), `access_token` arrays (§2.1.2) and `finish.method: "push"` (§2.5.2.2). Without it
 * the server never writes those fields, and a request for such a feature is answered `501 invalid_request`
 * (records that silently dropped them would turn a modified or multi-token grant into a privilege escalation).
 */
export interface GnapStore {
  /** Inserts a grant. A duplicate `id`, `continueId` or `interactId` is a defect. */
  readonly createGrant: (grant: GrantRecord) => Effect.Effect<void>;
  /** The grant whose unique column `by` equals `value`, or `null`. */
  readonly findGrant: (by: "id" | "continueId" | "interactId", value: string) => Effect.Effect<GrantRecord | null>;
  /**
   * Compare-and-set. If the grant `id` exists and its `version` is `version`, applies `patch`, sets `version` to
   * `version + 1` and returns `true` — in ONE atomic step (e.g. `UPDATE … SET …, version = version + 1 WHERE id = ?
   * AND version = ?` and check the affected-row count). Otherwise changes nothing and returns `false`. Of several
   * concurrent calls with the same `version`, exactly one returns `true`.
   */
  readonly updateGrant: (id: string, version: number, patch: GrantPatch) => Effect.Effect<boolean>;
  /** Inserts a token. A duplicate `id`, `valueHash` or `managementId` is a defect. */
  readonly createToken: (token: TokenRecord) => Effect.Effect<void>;
  /**
   * The token whose unique column `by` equals `value`, with its grant, or `null`. Revoked and expired tokens are
   * returned too. One lookup (a join): every token request needs both records.
   */
  readonly findTokenWithGrant: (
    by: "valueHash" | "managementId",
    value: string,
  ) => Effect.Effect<{ readonly token: TokenRecord; readonly grant: GrantRecord } | null>;
  /**
   * Sets `revokedAt = at` on every token whose column `by` equals `value` and whose `revokedAt` is still `null`,
   * in ONE atomic step (e.g. `UPDATE … SET revokedAt = ? WHERE id = ? AND revokedAt IS NULL`), and returns how many
   * it changed. Of several concurrent calls for the same token, exactly one gets `1`; the rest get `0`.
   */
  readonly revokeTokens: (by: "id" | "grantId", value: string, at: number) => Effect.Effect<number>;
  /**
   * Replay guard for signature nonces (RFC 9635 §7.3.1). Claims `key` until `expiresAt` and returns `true`, unless
   * `key` is already claimed and that claim has not expired at `now` (`expiresAt > now`): then changes nothing and
   * returns `false`. ONE atomic step; of several concurrent calls for a free key exactly one gets `true`.
   */
  readonly claimNonce: (key: string, expiresAt: number, now: number) => Effect.Effect<boolean>;
  /**
   * Set to `true` by a store that persists and returns every optional field of {@link GrantRecord} and
   * {@link TokenRecord} (see "Optional capabilities" above). `storeContract` then checks that round trip.
   */
  readonly extendedRecords?: true;
}
