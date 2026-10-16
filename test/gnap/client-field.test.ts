import * as Result from "effect/Result";
import { describe, expect, it } from "vite-plus/test";
import {
  getGrantClientIdentity,
  GnapClientFieldError,
  parseClientField,
  toTokenInfoClient,
} from "../../src/gnap/index";

const JWK = {
  kid: "key-1",
  alg: "EdDSA",
  use: "sig",
  kty: "OKP",
  crv: "Ed25519",
  x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
} as const;

const WALLET = "https://wallet.example/op/t/w";

const failure = <A>(result: Result.Result<A, GnapClientFieldError>): GnapClientFieldError => {
  if (Result.isSuccess(result)) throw new Error("expected failure");

  return result.failure;
};

const success = <A>(result: Result.Result<A, GnapClientFieldError>): A => {
  if (Result.isFailure(result)) throw result.failure;

  return result.success;
};

describe("parseClientField", () => {
  it("accepts a wallet address string, a walletAddress object and a jwk object", () => {
    expect(success(parseClientField(WALLET))).toEqual({ client: WALLET });
    expect(success(parseClientField({ walletAddress: WALLET }))).toEqual({ client: WALLET });
    expect(success(parseClientField({ jwk: JWK }))).toEqual({ jwk: JWK });
  });

  it("keeps additional JWK members", () => {
    expect(success(parseClientField({ jwk: { ...JWK, ext: true } }))).toEqual({ jwk: { ...JWK, ext: true } });
  });

  it.each([
    [null, "client-missing"],
    [undefined, "client-missing"],
    ["", "client-missing"],
    [42, "client-invalid-type"],
    [true, "client-invalid-type"],
    [{}, "client-invalid-shape"],
    [{ walletAddress: 1 }, "client-invalid-shape"],
    [{ jwk: { ...JWK, crv: "P-256" } }, "client-invalid-shape"],
    [[], "client-invalid-shape"],
  ])("reports %j as %s", (input, reason) => {
    const error = failure(parseClientField(input));

    expect(error).toBeInstanceOf(GnapClientFieldError);
    expect(error).toMatchObject({ _tag: "GnapClientFieldError", reason, message: "Invalid client field" });
  });
});

describe("getGrantClientIdentity", () => {
  it("prefers a stored JWK (object or JSON string) over the wallet address", () => {
    expect(success(getGrantClientIdentity({ client: WALLET, jwk: JSON.stringify(JWK) }))).toEqual({ jwk: JWK });
    expect(success(getGrantClientIdentity({ client: WALLET, jwk: JWK }))).toEqual({ jwk: JWK });
  });

  it("falls back to the wallet address when the stored JWK is unusable", () => {
    expect(success(getGrantClientIdentity({ client: WALLET, jwk: "not json" }))).toEqual({ client: WALLET });
    expect(success(getGrantClientIdentity({ client: WALLET, jwk: JSON.stringify({ kid: "x" }) }))).toEqual({
      client: WALLET,
    });
  });

  it("fails when there is neither a client nor a usable JWK", () => {
    expect(failure(getGrantClientIdentity({ client: null, jwk: null }))).toMatchObject({
      reason: "client-missing-identity",
      message: "Grant must have either client or jwk",
    });
    expect(failure(getGrantClientIdentity({ jwk: "{" })).reason).toBe("client-missing-identity");
  });
});

describe("toTokenInfoClient", () => {
  it("maps an identity to the introspection `client` member", () => {
    expect(toTokenInfoClient({ client: WALLET })).toEqual({ walletAddress: WALLET });
    expect(toTokenInfoClient({ jwk: JWK })).toEqual({ jwk: JWK });
  });
});
