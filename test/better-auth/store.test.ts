import { DatabaseSync } from "node:sqlite";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import * as Effect from "effect/Effect";
import { describe, expect, it } from "vite-plus/test";
import { gnap } from "../../src/better-auth/index";
import { betterAuthGnapStore } from "../../src/better-auth/store";
import { storeContract } from "../../src/gnap/server/testing/index";

const MODELS = ["user", "session", "account", "verification", "gnapGrant", "gnapAccessToken", "gnapNonce"];

const options: BetterAuthOptions = { baseURL: "https://as.test", secret: "x".repeat(40), plugins: [gnap()] };

// Better Auth's in-memory adapter (what the adapter tests run on).
storeContract(
  { describe, it },
  "betterAuthGnapStore on Better Auth's memory adapter",
  async () => {
    const auth = betterAuth({
      ...options,
      database: memoryAdapter(Object.fromEntries(MODELS.map((model) => [model, []]))),
    });

    return betterAuthGnapStore((await auth.$context).adapter);
  },
  { uniqueConstraints: false },
);

// A real SQL database: the tables are created by Better Auth's own migration from `gnapSchema`, so the unique
// constraints, the foreign keys and the conditional UPDATEs are the database's.
storeContract({ describe, it }, "betterAuthGnapStore on SQLite (migrated from gnapSchema)", async () => {
  const auth = betterAuth({ ...options, database: new DatabaseSync(":memory:") });

  await (await getMigrations(auth.options)).runMigrations();
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

  return betterAuthGnapStore(adapter);
});

describe("claimNonce when the database fails", () => {
  it("does not report a replay: the failure is raised", async () => {
    const auth = betterAuth({
      ...options,
      database: memoryAdapter(Object.fromEntries(MODELS.map((model) => [model, []]))),
    });

    const { adapter } = await auth.$context;

    const store = betterAuthGnapStore({
      ...adapter,
      create: () => Promise.reject(new Error("database unavailable")),
    });

    await expect(Effect.runPromise(store.claimNonce("key", 2_000, 1_000))).rejects.toThrow("database unavailable");
  });
});
