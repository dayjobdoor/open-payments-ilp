import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import * as schemas from "../open-payments/schemas";
import type { JWK } from "../open-payments/types";
import { GnapClientFieldError, type GnapClientFieldErrorReason } from "./errors";
import type { TokenInfoClient } from "./types";

/** Identity of a grant's client: a wallet address (`client`) or an inline key (`jwk`). */
export type ParsedClientField = { client: string; jwk?: never } | { client?: never; jwk: JWK };

const rawClient = Schema.Union([
  Schema.NonEmptyString,
  Schema.Struct({ walletAddress: Schema.String }),
  Schema.Struct({ jwk: schemas.jwk }),
]);

const decodeRawClient = Schema.decodeUnknownResult(rawClient);

const decodeJwk = Schema.decodeUnknownResult(schemas.jwk);

const isString = Schema.is(Schema.String);

const isObject = Schema.is(Schema.ObjectKeyword);

const fail = (reason: GnapClientFieldErrorReason): Result.Result<never, GnapClientFieldError> =>
  Result.fail(new GnapClientFieldError({ reason }));

function rawClientReason<Input>(input: Input): GnapClientFieldErrorReason {
  if (!input) return "client-missing";

  if (isObject(input)) return "client-invalid-shape";

  return "client-invalid-type";
}

/**
 * Parses the `client` field of a GNAP grant request: a wallet address string, `{ walletAddress }`, or `{ jwk }`.
 * Fails with {@link GnapClientFieldError} (`client-missing`, `client-invalid-type`, `client-invalid-shape`).
 *
 * @see https://openpayments.dev/apis/auth-server/operations/post-request/
 */
export function parseClientField<Input>(input: Input): Result.Result<ParsedClientField, GnapClientFieldError> {
  if (!input) return fail("client-missing");
  const parsed = decodeRawClient(input);

  if (Result.isFailure(parsed)) return fail(rawClientReason(input));
  const value = parsed.success;

  if (isString(value)) return Result.succeed({ client: value });

  if ("walletAddress" in value) return Result.succeed({ client: value.walletAddress });

  return Result.succeed({ jwk: value.jwk });
}

function parseStoredJwk(raw: string | JWK | null | undefined): JWK | null {
  if (!raw) return null;

  if (!isString(raw)) {
    const jwk = decodeJwk(raw);

    return Result.isSuccess(jwk) ? jwk.success : null;
  }

  try {
    const jwk = decodeJwk(JSON.parse(raw));

    return Result.isSuccess(jwk) ? jwk.success : null;
  } catch {
    return null;
  }
}

/**
 * Client identity of a persisted grant. An inline JWK (object or JSON string) wins over the wallet address.
 * Fails with {@link GnapClientFieldError} (`client-missing-identity`) when neither is present or the JWK is invalid and there is no wallet address.
 */
export function getGrantClientIdentity(grant: {
  readonly client?: string | null | undefined;
  readonly jwk?: string | JWK | null | undefined;
}): Result.Result<ParsedClientField, GnapClientFieldError> {
  const jwk = parseStoredJwk(grant.jwk);

  if (jwk) return Result.succeed({ jwk });

  if (grant.client) return Result.succeed({ client: grant.client });

  return fail("client-missing-identity");
}

/** The `client` member of a token introspection response for a client identity. */
export function toTokenInfoClient(identity: ParsedClientField): TokenInfoClient {
  return identity.jwk ? { jwk: identity.jwk } : { walletAddress: identity.client };
}
