/**
 * Conformance tests for a {@link GnapStore}, for the authors of custom stores (D1, Postgres, Redis, ...). The kit is
 * framework-neutral: pass the `describe` and `it` of your test runner (Vitest, `bun:test`, `node:test`, ...).
 *
 * ```ts
 * import { describe, it } from "vitest";
 * import { storeContract } from "open-payments-ilp/gnap/server/testing";
 *
 * storeContract({ describe, it }, "my database", async () => createMyStore(await freshDatabase()));
 * ```
 *
 * `makeStore` must return an empty store each time it is called. The cases cover round trips, expiry, unique
 * constraints and the atomicity of {@link GnapStore.updateGrant}, {@link GnapStore.revokeTokens} and
 * {@link GnapStore.claimNonce} under concurrent calls.
 *
 * @module
 */
import * as Effect from "effect/Effect";
import type { GnapStore, GrantRecord, TokenRecord } from "../store";

/** The two functions of the host test runner that the kit needs. */
export interface StoreContractHost {
  readonly describe: (name: string, register: () => void) => void;
  readonly it: (name: string, test: () => Promise<void>) => void;
}

export interface StoreContractOptions {
  /** `userId` value the store accepts, when it enforces a foreign key to a users table. Default `"user-1"`. */
  readonly userId?: string;
  /** `false` for a store that does not enforce unique columns (Better Auth's memory adapter): skips races on inserts. */
  readonly uniqueConstraints?: boolean;
}

const run = <A>(effect: Effect.Effect<A>): Promise<A> => Effect.runPromise(effect);

/**
 * Key-sorted JSON: records compare by structure, `undefined` fields count as absent. So do the optional record
 * fields (see `GnapStore.extendedRecords`) when `null`: a store that has the columns reads `null` back for a record
 * written without them, one that has not reads nothing.
 */
const canonical = <A>(value: A): string =>
  JSON.stringify(value, (_key, item) => {
    if (item?.constructor !== Object) return item;

    const optional =
      "continueId" in item ? ["finishMethod", "tokenRequests"] : "valueHash" in item ? ["access", "label"] : [];

    return Object.fromEntries(
      Object.entries(item)
        .filter(([key, field]) => !(optional.includes(key) && field === null))
        .sort(([a], [b]) => (a < b ? -1 : 1)),
    );
  }) ?? "undefined";

function equal<A>(actual: A, expected: A): void {
  const [got, want] = [canonical(actual), canonical(expected)];

  if (got !== want) throw new Error(`expected ${want}\n     got ${got}`);
}

async function rejects(promise: Promise<unknown>): Promise<void> {
  const settled = await promise.then(
    () => true,
    () => false,
  );

  if (settled) throw new Error("expected the call to fail, but it succeeded");
}

const T0 = 1_700_000_000_000;

const grant = (id: string, overrides: Partial<GrantRecord> = {}): GrantRecord => ({
  id,
  version: 0,
  state: "PENDING",
  tenantId: null,
  client: "https://wallet.example/alice",
  jwk: null,
  access: [
    {
      type: "outgoing-payment",
      actions: ["create", "read"],
      identifier: "https://wallet.example/alice",
      limits: {
        debitAmount: { value: "1000", assetCode: "USD", assetScale: 2 },
        interval: "R/2030-01-01T00:00:00Z/P1M",
      },
    },
  ],
  subject: null,
  interactId: `interact-${id}`,
  interactNonce: `nonce-${id}`,
  interactRef: `ref-${id}`,
  interactExpiresAt: T0 + 600_000,
  finishUri: "https://client.example/finish",
  clientNonce: "client-nonce",
  finishHashMethod: null,
  label: null,
  userId: null,
  continueId: `continue-${id}`,
  continueTokenHash: `hash-${id}`,
  lastContinuedAt: T0,
  createdAt: T0,
  updatedAt: T0,
  ...overrides,
});

const token = (id: string, grantId: string, overrides: Partial<TokenRecord> = {}): TokenRecord => ({
  id,
  grantId,
  valueHash: `value-${id}`,
  managementId: `manage-${id}`,
  expiresAt: T0 + 600_000,
  revokedAt: null,
  createdAt: T0,
  ...overrides,
});

/** Registers the contract tests of a `GnapStore` under `describe(name)` of the host runner. */
export function storeContract(
  { describe, it }: StoreContractHost,
  name: string,
  makeStore: () => GnapStore | Promise<GnapStore>,
  { userId = "user-1", uniqueConstraints = true }: StoreContractOptions = {},
): void {
  describe(`GnapStore contract: ${name}`, () => {
    describe("grants", () => {
      it("finds a created grant by id, continueId and interactId, field for field", async () => {
        const store = await makeStore();

        const jwkGrant = grant("g2", {
          tenantId: "tenant-1",
          client: null,
          jwk: { kty: "OKP", crv: "Ed25519", alg: "EdDSA", kid: "k1", x: "AAAA" },
          subject: { sub_ids: [{ id: "https://wallet.example/alice", format: "uri" }] },
          interactId: null,
          interactNonce: null,
          interactRef: null,
          interactExpiresAt: null,
          finishUri: null,
          clientNonce: null,
        });

        await run(store.createGrant(grant("g1")));
        await run(store.createGrant(jwkGrant));

        equal(await run(store.findGrant("id", "g1")), grant("g1"));
        equal(await run(store.findGrant("continueId", "continue-g1")), grant("g1"));
        equal(await run(store.findGrant("interactId", "interact-g1")), grant("g1"));
        equal(await run(store.findGrant("id", "g2")), jwkGrant);
      });

      it("returns null for unknown values, and never matches a null interactId", async () => {
        const store = await makeStore();

        await run(store.createGrant(grant("g1", { interactId: null })));

        equal(await run(store.findGrant("id", "nope")), null);
        equal(await run(store.findGrant("continueId", "nope")), null);
        equal(await run(store.findGrant("interactId", "nope")), null);
      });

      it("keeps grants without an interactId side by side", async () => {
        const store = await makeStore();

        await run(store.createGrant(grant("g1", { interactId: null })));
        await run(store.createGrant(grant("g2", { interactId: null })));

        equal((await run(store.findGrant("id", "g2")))?.id, "g2");
      });

      if (uniqueConstraints) {
        it("refuses a second grant with the same continueId or interactId", async () => {
          const store = await makeStore();

          await run(store.createGrant(grant("g1")));

          await rejects(run(store.createGrant(grant("g2", { continueId: "continue-g1" }))));
          await rejects(run(store.createGrant(grant("g3", { interactId: "interact-g1" }))));
        });
      }

      it("updateGrant applies the patch and increments the version when the version matches", async () => {
        const store = await makeStore();

        await run(store.createGrant(grant("g1")));

        equal(await run(store.updateGrant("g1", 0, { state: "APPROVED", userId, updatedAt: T0 + 1 })), true);

        equal(
          await run(store.findGrant("id", "g1")),
          grant("g1", { version: 1, state: "APPROVED", userId, updatedAt: T0 + 1 }),
        );
      });

      it("updateGrant changes nothing and returns false for a stale version or an unknown grant", async () => {
        const store = await makeStore();

        await run(store.createGrant(grant("g1")));
        await run(store.updateGrant("g1", 0, { state: "APPROVED" }));

        equal(await run(store.updateGrant("g1", 0, { state: "REJECTED" })), false);
        equal(await run(store.updateGrant("missing", 0, { state: "REJECTED" })), false);
        equal((await run(store.findGrant("id", "g1")))?.state, "APPROVED");
        equal((await run(store.findGrant("id", "g1")))?.version, 1);
      });

      it("updateGrant can set nullable fields to null and replace the continue token hash", async () => {
        const store = await makeStore();

        await run(store.createGrant(grant("g1", { userId })));
        await run(
          store.updateGrant("g1", 0, { userId: null, continueTokenHash: "rotated", lastContinuedAt: T0 + 5000 }),
        );

        const found = await run(store.findGrant("id", "g1"));

        equal(found?.userId, null);
        equal(found?.continueTokenHash, "rotated");
        equal(found?.lastContinuedAt, T0 + 5000);
      });

      it("of concurrent updateGrant calls with the same version exactly one wins", async () => {
        const store = await makeStore();

        await run(store.createGrant(grant("g1")));

        const results = await Promise.all(
          Array.from({ length: 8 }, (_, index) => run(store.updateGrant("g1", 0, { lastContinuedAt: T0 + index + 1 }))),
        );

        equal(results.filter(Boolean).length, 1);
        equal((await run(store.findGrant("id", "g1")))?.version, 1);
      });
    });

    describe("tokens", () => {
      it("finds a created token with its grant by valueHash and managementId", async () => {
        const store = await makeStore();

        await run(store.createGrant(grant("g1")));
        await run(store.createToken(token("t1", "g1")));
        await run(store.createToken(token("t2", "g1", { revokedAt: T0 + 1 })));

        equal(await run(store.findTokenWithGrant("valueHash", "value-t1")), {
          token: token("t1", "g1"),
          grant: grant("g1"),
        });

        equal(await run(store.findTokenWithGrant("managementId", "manage-t1")), {
          token: token("t1", "g1"),
          grant: grant("g1"),
        });

        // Revoked tokens are returned too: the server decides what they mean.
        equal(await run(store.findTokenWithGrant("valueHash", "value-t2")), {
          token: token("t2", "g1", { revokedAt: T0 + 1 }),
          grant: grant("g1"),
        });

        equal(await run(store.findTokenWithGrant("valueHash", "nope")), null);
        equal(await run(store.findTokenWithGrant("managementId", "nope")), null);
      });

      if (uniqueConstraints) {
        it("refuses a second token with the same valueHash or managementId", async () => {
          const store = await makeStore();

          await run(store.createGrant(grant("g1")));
          await run(store.createToken(token("t1", "g1")));

          await rejects(run(store.createToken(token("t2", "g1", { valueHash: "value-t1" }))));
          await rejects(run(store.createToken(token("t3", "g1", { managementId: "manage-t1" }))));
        });
      }

      it("revokeTokens by id revokes once and reports it", async () => {
        const store = await makeStore();

        await run(store.createGrant(grant("g1")));
        await run(store.createToken(token("t1", "g1")));

        equal(await run(store.revokeTokens("id", "t1", T0 + 10)), 1);
        equal(await run(store.revokeTokens("id", "t1", T0 + 20)), 0);
        equal(await run(store.revokeTokens("id", "missing", T0 + 20)), 0);
        equal((await run(store.findTokenWithGrant("valueHash", "value-t1")))?.token.revokedAt, T0 + 10);
      });

      it("revokeTokens by grantId revokes only that grant's tokens that are still active", async () => {
        const store = await makeStore();

        await run(store.createGrant(grant("g1")));
        await run(store.createGrant(grant("g2")));
        await run(store.createToken(token("t1", "g1")));
        await run(store.createToken(token("t2", "g1")));
        await run(store.createToken(token("t3", "g1", { revokedAt: T0 + 1 })));
        await run(store.createToken(token("t4", "g2")));

        equal(await run(store.revokeTokens("grantId", "g1", T0 + 10)), 2);
        equal((await run(store.findTokenWithGrant("valueHash", "value-t3")))?.token.revokedAt, T0 + 1);
        equal((await run(store.findTokenWithGrant("valueHash", "value-t4")))?.token.revokedAt, null);
      });

      it("of concurrent revokeTokens calls for the same token exactly one gets it", async () => {
        const store = await makeStore();

        await run(store.createGrant(grant("g1")));
        await run(store.createToken(token("t1", "g1")));

        const results = await Promise.all(
          Array.from({ length: 8 }, () => run(store.revokeTokens("id", "t1", T0 + 10))),
        );

        equal(
          results.reduce((sum, count) => sum + count, 0),
          1,
        );
      });
    });

    describe("extended records", () => {
      const first = { label: "first", access: [{ type: "incoming-payment" as const, actions: ["read" as const] }] };
      const requests = [first, { label: "second", access: grant("g").access }];

      // Only a store that sets `extendedRecords` has to keep the optional fields: for any other these cases do nothing.
      it("keeps finishMethod and tokenRequests of a grant, patched or not", async () => {
        const store = await makeStore();

        if (store.extendedRecords !== true) return;
        await run(store.createGrant(grant("g1", { finishMethod: "push", tokenRequests: requests })));

        equal(await run(store.findGrant("id", "g1")), grant("g1", { finishMethod: "push", tokenRequests: requests }));

        await run(store.updateGrant("g1", 0, { finishMethod: "redirect", tokenRequests: [first] }));

        const patched = await run(store.findGrant("id", "g1"));

        equal(patched?.finishMethod, "redirect");
        equal(patched?.tokenRequests, [first]);

        await run(store.updateGrant("g1", 1, { finishMethod: null, tokenRequests: null }));

        const cleared = await run(store.findGrant("id", "g1"));

        equal(cleared?.finishMethod ?? null, null);
        equal(cleared?.tokenRequests ?? null, null);
      });

      it("keeps the access and label of a token, next to a token without them", async () => {
        const store = await makeStore();

        if (store.extendedRecords !== true) return;
        await run(store.createGrant(grant("g1")));
        await run(store.createToken(token("t1", "g1", { access: first.access, label: "first" })));
        await run(store.createToken(token("t2", "g1")));

        const withAccess = await run(store.findTokenWithGrant("valueHash", "value-t1"));
        const without = await run(store.findTokenWithGrant("valueHash", "value-t2"));

        equal(withAccess?.token, token("t1", "g1", { access: first.access, label: "first" }));
        equal(without?.token.access ?? null, null);
        equal(without?.token.label ?? null, null);
      });
    });

    describe("nonces", () => {
      it("claims a free key once and refuses it until the claim expires", async () => {
        const store = await makeStore();

        equal(await run(store.claimNonce("k1", T0 + 1000, T0)), true);
        equal(await run(store.claimNonce("k1", T0 + 2000, T0 + 500)), false);
        equal(await run(store.claimNonce("k2", T0 + 1000, T0 + 500)), true);
        equal(await run(store.claimNonce("k1", T0 + 3000, T0 + 1000)), true);
        equal(await run(store.claimNonce("k1", T0 + 4000, T0 + 2000)), false);
      });

      if (uniqueConstraints) {
        it("of concurrent claims for a free key exactly one wins", async () => {
          const store = await makeStore();

          const results = await Promise.all(
            Array.from({ length: 8 }, () => run(store.claimNonce("k1", T0 + 1000, T0))),
          );

          equal(results.filter(Boolean).length, 1);
        });
      }
    });
  });
}
