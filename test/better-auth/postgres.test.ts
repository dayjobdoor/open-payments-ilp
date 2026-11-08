/**
 * The Better Auth store on a real PostgreSQL: unique constraints, conditional updates, and a transaction in which a
 * duplicate nonce must be reported as a replay instead of aborting it. Runs only when `GNAP_TEST_POSTGRES_URL` is set
 * (a server the tests may create schemas in, e.g. `postgres://postgres:pw@127.0.0.1:55432/postgres`); CI sets it.
 */
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import * as Effect from "effect/Effect";
import { Pool } from "pg";
import { afterAll, describe, expect, it } from "vite-plus/test";
import { gnap } from "../../src/better-auth/index";
import { betterAuthGnapStore } from "../../src/better-auth/store";
import { storeContract } from "../../src/gnap/server/testing/index";

const url = process.env["GNAP_TEST_POSTGRES_URL"];
const pools: Pool[] = [];

/** A better-auth instance on a schema of its own, with the GNAP tables created by Better Auth's migration. */
const freshAuth = async (url: string) => {
  const schema = `gnap_${crypto.randomUUID().replaceAll("-", "")}`;
  const admin = new Pool({ connectionString: url, max: 1 });

  await admin.query(`CREATE SCHEMA ${schema}`);
  await admin.end();

  const pool = new Pool({ connectionString: url, options: `-c search_path=${schema}` });

  pools.push(pool);

  const options: BetterAuthOptions = {
    baseURL: "https://as.test",
    secret: "x".repeat(40),
    plugins: [gnap()],
    database: pool,
  };
  const auth = betterAuth(options);

  await (await getMigrations(auth.options)).runMigrations();

  return { auth, pool };
};

afterAll(async () => {
  await Promise.all(pools.map((pool) => pool.end()));
});

if (url === undefined) {
  describe("betterAuthGnapStore on PostgreSQL", () => {
    it.skip("needs GNAP_TEST_POSTGRES_URL", () => undefined);
  });
} else {
  storeContract({ describe, it }, "betterAuthGnapStore on PostgreSQL", async () => {
    const { auth, pool } = await freshAuth(url);
    const { adapter } = await auth.$context;
    const now = new Date();

    // `gnapGrant.userId` references `user.id`; the contract's default `userId` is "user-1".
    await adapter.create({
      model: "user",
      data: {
        id: "user-1",
        name: "Owner",
        email: "owner@example.com",
        emailVerified: true,
        createdAt: now,
        updatedAt: now,
      },
      forceAllowId: true,
    });
    void pool;

    return betterAuthGnapStore(adapter);
  });

  describe("claimNonce inside a transaction on PostgreSQL", () => {
    it("reports a replay instead of failing the transaction", async () => {
      const { auth } = await freshAuth(url);
      const { adapter } = await auth.$context;

      const outcome = await adapter.transaction(async (trx) => {
        const store = betterAuthGnapStore(trx);
        const first = await Effect.runPromise(store.claimNonce("replayed", 2_000, 1_000));
        const second = await Effect.runPromise(store.claimNonce("replayed", 2_000, 1_000));
        const other = await Effect.runPromise(store.claimNonce("fresh", 2_000, 1_000));

        return [first, second, other];
      });

      expect(outcome).toEqual([true, false, true]);
    });
  });
}
