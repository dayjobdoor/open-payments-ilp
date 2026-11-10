// oxlint-disable anti-slop/no-unsafe-dictionary-type, anti-slop/no-object-parameters, anti-slop/no-runtime-typeof -- Rows cross the adapter boundary as column-name keyed values; the date columns are converted by name.
import type { DBTransactionAdapter, Where } from "better-auth/types";
import * as Effect from "effect/Effect";
import type { GnapStore, GrantRecord, TokenRecord } from "../gnap/server/index";

const GRANT_DATES: ReadonlyArray<string> = ["interactExpiresAt", "lastContinuedAt", "createdAt", "updatedAt"];

const TOKEN_DATES: ReadonlyArray<string> = ["expiresAt", "revokedAt", "createdAt"];

type Row = Record<string, unknown>;

/** The `json` columns of the grant table (see `gnapSchema`). */
const GRANT_JSON: ReadonlyArray<string> = ["jwk", "access", "subject"];

/**
 * `GnapStore` timestamps are epoch milliseconds; the tables use `date` columns. A `json` column gets its value as JSON
 * text: Better Auth hands an array to PostgreSQL's driver as it is, which writes it as a PostgreSQL array
 * (`invalid input syntax for type json`), while the other dialects store the text and read it back parsed.
 */
const toRow = (record: object, dates: ReadonlyArray<string>, json: ReadonlyArray<string> = []): Row =>
  Object.fromEntries(
    Object.entries(record).map(([key, value]) => [
      key,
      dates.includes(key) && typeof value === "number"
        ? new Date(value)
        : json.includes(key) && typeof value === "object" && value !== null
          ? JSON.stringify(value)
          : value,
    ]),
  );

const fromRow = (row: Row, dates: ReadonlyArray<string>): Row =>
  Object.fromEntries(
    Object.entries(row).map(([key, value]) => [
      key,
      dates.includes(key) && value instanceof Date ? value.getTime() : value,
    ]),
  );

const equals = (field: string, value: string | number | null): Where => ({ field, value });

/**
 * The part of Better Auth's `DBAdapter` (or its transaction adapter) the store uses. `deleteMany` is optional: without
 * it expired nonces are not deleted.
 */
export type GnapDb = Pick<DBTransactionAdapter, "create" | "findOne" | "incrementOne" | "updateMany"> &
  Partial<Pick<DBTransactionAdapter, "deleteMany">>;

/**
 * A {@link GnapStore} on Better Auth's database adapter: the `gnapGrant`, `gnapAccessToken` and `gnapNonce` tables of
 * `gnapSchema`. `updateGrant` is `incrementOne` guarded by the version, `revokeTokens` an `updateMany`
 * guarded by `revokedAt IS NULL`: one conditional statement each.
 */
export const betterAuthGnapStore = (db: GnapDb): GnapStore => {
  const find = <R>(model: string, dates: ReadonlyArray<string>, by: string, value: string) =>
    Effect.promise(async () => {
      const row = await db.findOne<Row>({ model, where: [equals(by, value)] });

      // SAFETY: rows of these two models hold exactly the columns of `GrantRecord` / `TokenRecord` (plus `id`), which
      // `gnapSchema` declares; the adapter hands back JSON columns parsed.
      return row === null ? null : (fromRow(row, dates) as R);
    });

  const claim = async (key: string, expiresAt: number, now: number): Promise<boolean> => {
    const find = () => db.findOne<Row>({ model: "gnapNonce", where: [equals("key", key)] });

    if ((await find()) === null) {
      try {
        await db.create({ model: "gnapNonce", data: { key, expiresAt: new Date(expiresAt) } });

        return true;
      } catch (error) {
        // The unique `key` column makes the loser of a concurrent claim fail here (a replay); any other failure
        // (the database is down) is not a replay and must not look like one.
        if ((await find()) === null) throw error;

        return false;
      }
    }

    // An expired claim is taken over by one conditional update: only one concurrent caller changes the row.
    return (
      (await db.updateMany({
        model: "gnapNonce",
        where: [equals("key", key), { field: "expiresAt", value: new Date(now), operator: "lte" }],
        update: { expiresAt: new Date(expiresAt) },
      })) > 0
    );
  };

  return {
    // The grant table has the `interactBinding` column of `gnapSchema`.
    interactionBinding: true,
    createGrant: (grant) =>
      Effect.promise(() =>
        db.create({ model: "gnapGrant", data: toRow(grant, GRANT_DATES, GRANT_JSON), forceAllowId: true }),
      ).pipe(Effect.asVoid),
    findGrant: (by, value) => find<GrantRecord>("gnapGrant", GRANT_DATES, by, value),
    updateGrant: (id, version, patch) =>
      Effect.promise(
        async () =>
          (await db.incrementOne({
            model: "gnapGrant",
            where: [equals("id", id), equals("version", version)],
            increment: { version: 1 },
            set: toRow(patch, GRANT_DATES, GRANT_JSON),
          })) !== null,
      ),
    createToken: (token) =>
      Effect.promise(() =>
        db.create({ model: "gnapAccessToken", data: toRow(token, TOKEN_DATES), forceAllowId: true }),
      ).pipe(Effect.asVoid),
    findTokenWithGrant: (by, value) =>
      Effect.gen(function* () {
        const token = yield* find<TokenRecord>("gnapAccessToken", TOKEN_DATES, by, value);
        const grant = token === null ? null : yield* find<GrantRecord>("gnapGrant", GRANT_DATES, "id", token.grantId);

        return token === null || grant === null ? null : { token, grant };
      }),
    revokeTokens: (by, value, at) =>
      Effect.promise(() =>
        db.updateMany({
          model: "gnapAccessToken",
          where: [equals(by, value), equals("revokedAt", null)],
          update: { revokedAt: new Date(at) },
        }),
      ),
    claimNonce: (key, expiresAt, now) =>
      Effect.promise(async () => {
        const claimed = await claim(key, expiresAt, now);

        if (claimed) await sweepExpiredNonces(db, now);

        return claimed;
      }),
  };
};

/**
 * Housekeeping at most once a minute per database: claims whose `expiresAt` passed can never block anything again. The
 * marker belongs to the adapter object, not to the process: a process that serves several Better Auth instances (a
 * database per tenant) must clean each of them, however much busier one is than the others.
 */
const SWEEP_EVERY_MS = 60_000;

const lastSweepAt = new WeakMap<GnapDb, number>();

const sweepExpiredNonces = async (db: GnapDb, now: number): Promise<void> => {
  const last = lastSweepAt.get(db);

  // A clock that went backwards sweeps again: the marker is no longer a time to measure from.
  if (last !== undefined && now >= last && now - last < SWEEP_EVERY_MS) return;
  lastSweepAt.set(db, now);

  // Best effort: a failed cleanup, a throw before a promise exists included, must not turn a claim that succeeded into
  // an error.
  try {
    await db.deleteMany?.({
      model: "gnapNonce",
      where: [{ field: "expiresAt", value: new Date(now), operator: "lt" }],
    });
  } catch {
    // The next claim a minute on tries again.
  }
};

/** Grants read per round trip: without a `limit`, Better Auth's `findMany` returns at most 100 rows. */
const GRANTS_PER_PAGE = 100;

/**
 * Revokes every grant `userId` approved and their live tokens, in statements that need no foreign key: the deletion of
 * a user must end what the user authorised on adapters that do not cascade (the memory adapter, MongoDB).
 *
 * A grant goes to `REVOKED` first, with `version + 1`: the server treats the tokens of a revoked grant as inactive, and
 * an `updateGrant` that read the grant before loses the version guard instead of writing its state over `REVOKED`.
 * The tokens' own `revokedAt` follows.
 */
export const revokeUserGrants = async (
  db: Pick<DBTransactionAdapter, "findMany" | "incrementOne" | "updateMany">,
  userId: string,
  now: number,
): Promise<void> => {
  const at = new Date(now);

  for (let offset = 0; ; offset += GRANTS_PER_PAGE) {
    // Ordered by `id`, and `userId` is not what the loop changes: the pages do not shift under the offset.
    const page = await db.findMany<{ id: string }>({
      model: "gnapGrant",
      where: [equals("userId", userId)],
      sortBy: { field: "id", direction: "asc" },
      limit: GRANTS_PER_PAGE,
      offset,
    });

    for (const { id } of page) {
      await db.incrementOne({
        model: "gnapGrant",
        where: [equals("id", id)],
        increment: { version: 1 },
        set: { state: "REVOKED", updatedAt: at },
      });
      await db.updateMany({
        model: "gnapAccessToken",
        where: [equals("grantId", id), equals("revokedAt", null)],
        update: { revokedAt: at },
      });
    }

    if (page.length < GRANTS_PER_PAGE) return;
  }
};
