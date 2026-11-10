import { DatabaseSync } from "node:sqlite";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getMigrations } from "better-auth/db/migration";
import * as Effect from "effect/Effect";
import { describe, expect, it } from "vite-plus/test";
import { gnap } from "../../src/better-auth/index";
import { betterAuthGnapStore, revokeUserGrants } from "../../src/better-auth/store";
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

/** A fresh Better Auth instance on the memory adapter: its own database, so its own sweep schedule. */
const memoryContext = async () =>
  await betterAuth({
    ...options,
    database: memoryAdapter(Object.fromEntries(MODELS.map((model) => [model, []]))),
  }).$context;

const hasNonce = async (db: Awaited<ReturnType<typeof memoryContext>>["adapter"], key: string) =>
  (await db.findOne({ model: "gnapNonce", where: [{ field: "key", value: key }] })) !== null;

describe("claimNonce housekeeping", () => {
  const MINUTE = 60_000;
  const BASE = 1_000_000;

  it("drops claims that have expired, at most once a minute, and keeps the live ones", async () => {
    const { adapter } = await memoryContext();
    const store = betterAuthGnapStore(adapter);

    await Effect.runPromise(store.claimNonce("old", BASE + 1_000, BASE));
    await Effect.runPromise(store.claimNonce("live", BASE + 10 * MINUTE, BASE + 2 * MINUTE));

    expect(await hasNonce(adapter, "old")).toBe(false);
    expect(await hasNonce(adapter, "live")).toBe(true);

    // A sweep ran 1 s ago: an expired claim stays until the next one.
    await Effect.runPromise(store.claimNonce("short", BASE + 2 * MINUTE + 500, BASE + 2 * MINUTE));
    await Effect.runPromise(store.claimNonce("later", BASE + 10 * MINUTE, BASE + 2 * MINUTE + 1_000));

    expect(await hasNonce(adapter, "short")).toBe(true);
  });

  it("sweeps on the schedule of each database: a busier one does not take the turn of the others", async () => {
    const busy = await memoryContext();
    const quiet = await memoryContext();
    const busyStore = betterAuthGnapStore(busy.adapter);
    const quietStore = betterAuthGnapStore(quiet.adapter);

    await Effect.runPromise(quietStore.claimNonce("quiet-old", BASE + 1_000, BASE));

    // Each minute the busy database claims first (and cleans itself), the quiet one a second later.
    for (const minute of [1, 2, 3]) {
      await Effect.runPromise(busyStore.claimNonce(`busy-${minute}`, BASE + 10 * MINUTE, BASE + minute * MINUTE));
      await Effect.runPromise(
        quietStore.claimNonce(`quiet-${minute}`, BASE + 10 * MINUTE, BASE + minute * MINUTE + 1_000),
      );
    }

    expect(await hasNonce(quiet.adapter, "quiet-old")).toBe(false);
  });

  it("sweeps again when the clock went backwards", async () => {
    const { adapter } = await memoryContext();
    const store = betterAuthGnapStore(adapter);

    await Effect.runPromise(store.claimNonce("first", BASE + 10 * MINUTE, BASE + 5 * MINUTE));
    await Effect.runPromise(store.claimNonce("expired", BASE + 1_000, BASE + 5 * MINUTE + 1_000));
    await Effect.runPromise(store.claimNonce("rewound", BASE + 10 * MINUTE, BASE + 2 * MINUTE));

    expect(await hasNonce(adapter, "expired")).toBe(false);
  });

  it.each([
    ["rejects", () => Promise.reject(new Error("cleanup failed"))],
    [
      "throws before it returns a promise",
      () => {
        throw new Error("cleanup failed");
      },
    ],
  ])("keeps a claim that succeeded a success when the cleanup %s", async (_name, deleteMany) => {
    const { adapter } = await memoryContext();
    const store = betterAuthGnapStore({ ...adapter, deleteMany });

    expect(await Effect.runPromise(store.claimNonce("k", BASE + 1_000, BASE))).toBe(true);
    expect(await Effect.runPromise(store.claimNonce("k", BASE + 1_000, BASE))).toBe(false);
    // The next claim a minute on tries the cleanup again, and the claim is a success again.
    expect(await Effect.runPromise(store.claimNonce("l", BASE + 10 * MINUTE, BASE + 2 * MINUTE))).toBe(true);
  });

  it("claims without cleaning when the adapter has no deleteMany", async () => {
    const { adapter } = await memoryContext();
    const { deleteMany: _unused, ...withoutDeleteMany } = adapter;
    const store = betterAuthGnapStore(withoutDeleteMany);

    await Effect.runPromise(store.claimNonce("old", BASE + 1_000, BASE));

    expect(await Effect.runPromise(store.claimNonce("new", BASE + 10 * MINUTE, BASE + 2 * MINUTE))).toBe(true);
    expect(await hasNonce(adapter, "old")).toBe(true);
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

describe("revokeUserGrants", () => {
  const NOW = Date.UTC(2030, 0, 1);

  it("revokes every grant of the user and their tokens, however many (Better Auth reads 100 rows at most), and no one else's", async () => {
    const { adapter } = await memoryContext();
    const store = betterAuthGnapStore(adapter);
    const owned = Array.from({ length: 230 }, (_, index) => index + 1);

    for (const n of owned) await seedApprovedGrant(store, "owner", n);
    await seedApprovedGrant(store, "someone-else", 1_000);

    await revokeUserGrants(adapter, "owner", NOW);

    for (const n of owned) {
      const found = await Effect.runPromise(store.findTokenWithGrant("valueHash", `v${n}`));

      expect(found?.grant.state, `g${n}`).toBe("REVOKED");
      expect(found?.grant.updatedAt, `g${n}`).toBe(NOW);
      expect(found?.token.revokedAt, `t${n}`).toBe(NOW);
    }

    const other = await Effect.runPromise(store.findTokenWithGrant("valueHash", "v1000"));

    expect(other?.grant.state).toBe("APPROVED");
    expect(other?.grant.version).toBe(0);
    expect(other?.token.revokedAt).toBeNull();
  });

  it("bumps the version: a write that read the grant before is refused, not laid over REVOKED", async () => {
    const { adapter } = await memoryContext();
    const store = betterAuthGnapStore(adapter);

    await seedApprovedGrant(store, "owner");
    await revokeUserGrants(adapter, "owner", NOW);

    expect(await Effect.runPromise(store.updateGrant("g1", 0, { state: "FINALIZED" }))).toBe(false);

    const found = await Effect.runPromise(store.findTokenWithGrant("valueHash", "v1"));

    expect(found?.grant.state).toBe("REVOKED");
    expect(found?.grant.version).toBe(1);
  });

  it("does nothing for a user who approved nothing", async () => {
    const { adapter } = await memoryContext();

    await expect(revokeUserGrants(adapter, "nobody", NOW)).resolves.toBeUndefined();
  });

  it("is what the plugin's user.delete hook runs, stamped with the plugin's clock", async () => {
    const auth = betterAuth({
      ...options,
      plugins: [gnap({ clock: () => new Date(NOW) })],
      database: memoryAdapter(Object.fromEntries(MODELS.map((model) => [model, []]))),
    });
    const context = await auth.$context;
    const store = betterAuthGnapStore(context.adapter);
    const created = new Date();

    await context.adapter.create({
      model: "user",
      data: {
        id: "owner",
        name: "Owner",
        email: "o@example.com",
        emailVerified: true,
        createdAt: created,
        updatedAt: created,
      },
      forceAllowId: true,
    });
    await seedApprovedGrant(store, "owner");
    await context.internalAdapter.deleteUser("owner");

    const found = await Effect.runPromise(store.findTokenWithGrant("valueHash", "v1"));

    expect(found?.token.revokedAt).toBe(NOW);
    expect(found?.grant.state).toBe("REVOKED");
  });
});
