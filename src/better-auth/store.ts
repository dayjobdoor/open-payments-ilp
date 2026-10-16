// oxlint-disable anti-slop/no-unsafe-dictionary-type, anti-slop/no-object-parameters, anti-slop/no-runtime-typeof -- Rows cross the adapter boundary as column-name keyed values; the date columns are converted by name.
import type { DBTransactionAdapter, Where } from "better-auth/types";
import * as Effect from "effect/Effect";
import type { GnapStore, GrantRecord, TokenRecord } from "../gnap/server/index";

const GRANT_DATES: ReadonlyArray<string> = ["interactExpiresAt", "lastContinuedAt", "createdAt", "updatedAt"];

const TOKEN_DATES: ReadonlyArray<string> = ["expiresAt", "revokedAt", "createdAt"];

type Row = Record<string, unknown>;

/** `GnapStore` timestamps are epoch milliseconds; the tables use `date` columns. */
const toRow = (record: object, dates: ReadonlyArray<string>): Row =>
  Object.fromEntries(
    Object.entries(record).map(([key, value]) => [
      key,
      dates.includes(key) && typeof value === "number" ? new Date(value) : value,
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

/** The part of Better Auth's `DBAdapter` (or its transaction adapter) the store uses. */
export type GnapDb = Pick<DBTransactionAdapter, "create" | "findOne" | "incrementOne" | "updateMany">;

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

  return {
    createGrant: (grant) =>
      Effect.promise(() => db.create({ model: "gnapGrant", data: toRow(grant, GRANT_DATES), forceAllowId: true })).pipe(
        Effect.asVoid,
      ),
    findGrant: (by, value) => find<GrantRecord>("gnapGrant", GRANT_DATES, by, value),
    updateGrant: (id, version, patch) =>
      Effect.promise(
        async () =>
          (await db.incrementOne({
            model: "gnapGrant",
            where: [equals("id", id), equals("version", version)],
            increment: { version: 1 },
            set: toRow(patch, GRANT_DATES),
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
      }),
  };
};
