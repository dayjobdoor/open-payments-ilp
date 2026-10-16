/**
 * Which grant item answers a requested access item during introspection. The expectations are what Rafiki's
 * `compareRequestAndGrantAccessItems` (`auth/src/access/utils.ts`, pinned checkout) returns for the same pairs; the
 * pairs were run through it once and are recorded here.
 */
import * as Effect from "effect/Effect";
import { describe, expect, it } from "vite-plus/test";
import type { AccessItem } from "../../src/gnap/index";
import { WALLET, amount, createServerHarness, seedGrant, seedToken } from "./support";

const identifier = WALLET;

interface Pair {
  readonly name: string;
  readonly requested: AccessItem;
  readonly granted: AccessItem;
  readonly covered: boolean;
}

type Incoming = Extract<AccessItem, { type: "incoming-payment" }>;

type Outgoing = Extract<AccessItem, { type: "outgoing-payment" }>;

/** An incoming-payment item; `owner` is its `identifier` (the harness wallet unless told otherwise). */
const incomingOf = (actions: Incoming["actions"], owner: string | null = identifier): Incoming => ({
  type: "incoming-payment",
  actions,
  ...(owner !== null && { identifier: owner }),
});

const outgoingOf = (limits?: Outgoing["limits"]): Outgoing => ({
  type: "outgoing-payment",
  actions: ["create"],
  identifier,
  ...(limits !== undefined && { limits }),
});

const PAIRS: ReadonlyArray<Pair> = [
  { name: "same item", requested: incomingOf(["create"]), granted: incomingOf(["create", "read"]), covered: true },
  {
    name: "request names a wallet, grant has no identifier",
    requested: incomingOf(["create"]),
    granted: incomingOf(["create"], null),
    covered: true,
  },
  {
    name: "grant names a wallet, request does not",
    requested: incomingOf(["create"], null),
    granted: incomingOf(["create"]),
    covered: true,
  },
  {
    name: "identifiers differ",
    requested: incomingOf(["create"]),
    granted: incomingOf(["create"], `${WALLET}x`),
    covered: false,
  },
  { name: "read-all covers read", requested: incomingOf(["read"]), granted: incomingOf(["read-all"]), covered: true },
  { name: "list-all covers list", requested: incomingOf(["list"]), granted: incomingOf(["list-all"]), covered: true },
  {
    name: "read does not cover read-all",
    requested: incomingOf(["read-all"]),
    granted: incomingOf(["read"]),
    covered: false,
  },
  {
    name: "equal limits, in another key order",
    requested: outgoingOf({ debitAmount: { assetScale: 2, assetCode: "USD", value: "1000" } }),
    granted: outgoingOf({ debitAmount: amount }),
    covered: true,
  },
  {
    name: "different limits",
    requested: outgoingOf({ debitAmount: { ...amount, value: "1" } }),
    granted: outgoingOf({ debitAmount: amount }),
    covered: false,
  },
  {
    name: "limits requested, grant has none",
    requested: outgoingOf({ debitAmount: amount }),
    granted: outgoingOf(),
    covered: false,
  },
  {
    name: "no limits requested, grant has some",
    requested: outgoingOf(),
    granted: outgoingOf({ debitAmount: amount }),
    covered: true,
  },
  {
    name: "other type",
    requested: { type: "quote", actions: ["create"] },
    granted: incomingOf(["create"]),
    covered: false,
  },
];

describe("introspection matches requested access as Rafiki does", () => {
  it.each(PAIRS.map((pair) => [pair.name, pair] as const))("%s", async (_name, pair) => {
    const h = await createServerHarness();
    const { grant } = await seedGrant(h, { state: "FINALIZED", access: [pair.granted] });
    const { value } = await seedToken(h, grant);

    const answer = await Effect.runPromise(h.server.introspectToken(value, [pair.requested]));

    expect(answer).toMatchObject({ active: true, access: pair.covered ? [pair.granted] : [] });
  });

  it("reports the first covering grant item once per requested item, in request order", async () => {
    const h = await createServerHarness();
    const wide = incomingOf(["create", "read"]);
    const narrow = incomingOf(["create"]);
    const { grant } = await seedGrant(h, { state: "FINALIZED", access: [wide, narrow] });
    const { value } = await seedToken(h, grant);

    const answer = await Effect.runPromise(
      h.server.introspectToken(value, [
        { type: "incoming-payment", actions: ["create"], identifier },
        { type: "incoming-payment", actions: ["read"], identifier },
      ]),
    );

    expect(answer).toMatchObject({ access: [wide, wide] });
  });

  it("reports no access for an empty request", async () => {
    const h = await createServerHarness();
    const { grant } = await seedGrant(h, { state: "FINALIZED", access: [incomingOf(["create"])] });
    const { value } = await seedToken(h, grant);

    expect(await Effect.runPromise(h.server.introspectToken(value, []))).toMatchObject({ active: true, access: [] });
  });
});
