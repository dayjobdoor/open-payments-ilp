/**
 * A store written before the optional record fields has no column for them and never sees them. The doubles of
 * `support.ts` keep whatever they are handed, so they could not tell a server that writes such a field anyway. The
 * Better Auth store is the other shape: it has the binding column but not the extended ones.
 */
import * as Effect from "effect/Effect";
import { describe, expect, it } from "vite-plus/test";
import { memoryGnapStore, type GnapStore } from "../../src/gnap/server/index";
import {
  browserFinish,
  browserStart,
  continueWith,
  createServerHarness,
  grantBody,
  idp,
  incoming,
  json,
  jsonBody,
  startGrant,
  withToken,
} from "./support";

const EXTENDED_GRANT_FIELDS = ["finishMethod", "tokenRequests"];
const EXTENDED_TOKEN_FIELDS = ["access", "label"];

/**
 * A store without the extended columns (and without the binding one unless `binding`): a write that names a column it
 * lacks is recorded, as an `UPDATE` of a missing column would fail.
 */
const strictStore = (binding: boolean): { readonly store: GnapStore; readonly refused: string[] } => {
  const inner = memoryGnapStore();
  const refused: string[] = [];
  const noGrantFields = binding ? EXTENDED_GRANT_FIELDS : [...EXTENDED_GRANT_FIELDS, "interactBinding"];

  const guard = (kind: string, record: object, fields: ReadonlyArray<string>) => {
    for (const field of fields) if (field in record) refused.push(`${kind}.${field}`);
  };

  const store: GnapStore = {
    ...(binding && { interactionBinding: true as const }),
    createGrant: (grant) => (guard("createGrant", grant, noGrantFields), inner.createGrant(grant)),
    findGrant: inner.findGrant,
    updateGrant: (id, version, patch) => (
      guard("updateGrant", patch, noGrantFields),
      inner.updateGrant(id, version, patch)
    ),
    createToken: (token) => (guard("createToken", token, EXTENDED_TOKEN_FIELDS), inner.createToken(token)),
    findTokenWithGrant: inner.findTokenWithGrant,
    revokeTokens: inner.revokeTokens,
    claimNonce: inner.claimNonce,
  };

  return { store, refused };
};

describe("a store without the extended record fields", () => {
  it.each([
    ["no optional capability", false],
    ["interactionBinding only, like the Better Auth store", true],
  ])(
    "is never handed one of them, with %s, through consent, continuation, rotation and cancellation",
    async (_name, binding) => {
      const { store, refused } = strictStore(binding);
      const h = await createServerHarness({ unvalidated: true, store });

      // Interactive: start, decide, finish, continue, then manage the token and cancel the grant.
      const pending = await startGrant(h);
      const { cookie } = await browserStart(h, pending);

      expect((await idp(h, pending, "accept")).status).toBe(202);

      const finish = await browserFinish(h, pending, cookie);
      const interactRef = new URL(finish.headers.get("location") ?? "").searchParams.get("interact_ref") ?? "";

      h.clock.advance(60);

      const continued = await continueWith(h, pending, { interact_ref: interactRef });
      const granted = await jsonBody<{ access_token: { value: string; manage: string } }>(continued);

      expect(continued.status).toBe(200);

      const rotated = await h.signedCall(
        granted.access_token.manage,
        withToken(json("POST"), granted.access_token.value),
      );

      expect(rotated.status).toBe(200);

      expect((await h.signedCall(pending.continueUri, withToken(json("DELETE"), pending.continueToken))).status).toBe(
        204,
      );

      // Not interactive: a grant and its token in one request.
      expect((await h.signedCall(h.baseUrl, json("POST", grantBody([incoming])))).status).toBe(200);
      expect(refused).toEqual([]);
    },
  );

  it("is a check that can fail: a write that names a column the store lacks is recorded", async () => {
    const { store, refused } = strictStore(false);

    const record = {
      id: "t1",
      grantId: "g1",
      valueHash: "v",
      managementId: "m",
      expiresAt: 1,
      revokedAt: null,
      createdAt: 0,
    };

    await Effect.runPromise(store.createToken({ ...record, label: null }));
    await Effect.runPromise(store.updateGrant("g1", 0, { interactBinding: null, state: "REVOKED" }));

    expect(refused).toEqual(["createToken.label", "updateGrant.interactBinding"]);
  });
});
