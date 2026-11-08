import type {
  AuthenticatedClient as UpstreamAuthenticatedClient,
  UnauthenticatedClient as UpstreamUnauthenticatedClient,
} from "@interledger/open-payments";
import { describe, expect, expectTypeOf, it } from "vite-plus/test";
import type { AuthenticatedClient as EffectAuthenticatedClient } from "../../src/open-payments/index";
import type { AuthenticatedClient, UnauthenticatedClient } from "../../src/plain/open-payments";

// Compile-time only (enforced by `tsc -p tsconfig.test.json`): the clients are structurally assignable to
// @interledger/open-payments' client types, so they can be passed where those types are expected. Error classes are
// not shared: `instanceof` against upstream's `OpenPaymentsRequestError` does not match (see the README).
export type Assignable = {
  authenticated: AuthenticatedClient extends UpstreamAuthenticatedClient ? true : false;
  unauthenticated: UnauthenticatedClient extends UpstreamUnauthenticatedClient ? true : false;
  // Control: the check can fail, the Effect client is not assignable.
  effectClientIsNot: EffectAuthenticatedClient extends UpstreamAuthenticatedClient ? false : true;
};

describe("upstream client compatibility", () => {
  it("is checked by the compiler", () => {
    expectTypeOf<AuthenticatedClient>().toExtend<UpstreamAuthenticatedClient>();
    expectTypeOf<UnauthenticatedClient>().toExtend<UpstreamUnauthenticatedClient>();
    expectTypeOf<EffectAuthenticatedClient>().not.toExtend<UpstreamAuthenticatedClient>();

    const compat: Assignable = {
      authenticated: true,
      unauthenticated: true,
      effectClientIsNot: true,
    };

    expect(compat).toEqual({ authenticated: true, unauthenticated: true, effectClientIsNot: true });
  });
});
