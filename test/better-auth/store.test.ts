import { DatabaseSync } from "node:sqlite";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import * as Effect from "effect/Effect";
import { describe, expect, it } from "vite-plus/test";
import { gnap } from "../../src/better-auth/index";
import { betterAuthGnapStore } from "../../src/better-auth/store";
import { storeContract } from "../../src/gnap/server/testing/index";
import { seedApprovedGrant } from "./seed";

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

describe("claimNonce housekeeping", () => {
  it("drops claims that have expired, at most once a minute, and keeps the live ones", async () => {
    const auth = betterAuth({
      ...options,
      database: memoryAdapter(Object.fromEntries(MODELS.map((model) => [model, []]))),
    });
    const { adapter } = await auth.$context;
    const store = betterAuthGnapStore(adapter);
    // Larger than the times of the other tests, so a sweep done by one of them does not hide this one.
    const base = 4_000_000_000_000;
    const has = async (key: string) =>
      (await adapter.findOne({ model: "gnapNonce", where: [{ field: "key", value: key }] })) !== null;

    await Effect.runPromise(store.claimNonce("old", base + 1_000, base));
    await Effect.runPromise(store.claimNonce("live", base + 10 * 60_000, base + 120_000));

    expect(await has("old")).toBe(false);
    expect(await has("live")).toBe(true);

    // A sweep ran 1 s ago: an expired claim stays until the next one.
    await Effect.runPromise(store.claimNonce("short", base + 120_500, base + 120_000));
    await Effect.runPromise(store.claimNonce("later", base + 10 * 60_000, base + 121_000));

    expect(await has("short")).toBe(true);
  });
});

describe("deleting a user", () => {
  it("takes the grants the user approved, and their tokens, along: nothing they authorised keeps working", async () => {
    const auth = betterAuth({ ...options, database: new DatabaseSync(":memory:") });

    await (await getMigrations(auth.options)).runMigrations();
    const { adapter } = await auth.$context;
    const store = betterAuthGnapStore(adapter);
    const now = new Date();

    await adapter.create({
      model: "user",
      data: { id: "owner", name: "Owner", email: "o@example.com", emailVerified: true, createdAt: now, updatedAt: now },
      forceAllowId: true,
    });
    await seedApprovedGrant(store, "owner");

    await adapter.delete({ model: "user", where: [{ field: "id", value: "owner" }] });

    expect(await Effect.runPromise(store.findGrant("id", "g1"))).toBeNull();
    expect(await Effect.runPromise(store.findTokenWithGrant("valueHash", "v1"))).toBeNull();
  });
});

describe("deleting a user on an adapter without foreign keys", () => {
  it("revokes what the user authorised, through the plugin's database hook", async () => {
    const auth = betterAuth({
      ...options,
      database: memoryAdapter(Object.fromEntries(MODELS.map((model) => [model, []]))),
    });
    const context = await auth.$context;
    const store = betterAuthGnapStore(context.adapter);
    const now = new Date();

    await context.adapter.create({
      model: "user",
      data: { id: "owner", name: "Owner", email: "o@example.com", emailVerified: true, createdAt: now, updatedAt: now },
      forceAllowId: true,
    });
    await seedApprovedGrant(store, "owner");

    await context.internalAdapter.deleteUser("owner");

    const found = await Effect.runPromise(store.findTokenWithGrant("valueHash", "v1"));

    expect(found?.token.revokedAt).not.toBeNull();
    expect(found?.grant.state).toBe("REVOKED");
  });

  it("runs next to a user.delete hook of the application", async () => {
    const calls: string[] = [];
    const auth = betterAuth({
      ...options,
      database: memoryAdapter(Object.fromEntries(MODELS.map((model) => [model, []]))),
      databaseHooks: {
        user: {
          delete: {
            before: async () => {
              calls.push("app");
            },
          },
        },
      },
    });
    const context = await auth.$context;
    const store = betterAuthGnapStore(context.adapter);
    const now = new Date();

    await context.adapter.create({
      model: "user",
      data: { id: "owner", name: "Owner", email: "o@example.com", emailVerified: true, createdAt: now, updatedAt: now },
      forceAllowId: true,
    });
    await seedApprovedGrant(store, "owner");
    await context.internalAdapter.deleteUser("owner");

    expect(calls).toEqual(["app"]);
    expect((await Effect.runPromise(store.findTokenWithGrant("valueHash", "v1")))?.grant.state).toBe("REVOKED");
  });
});
