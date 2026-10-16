import type { YieldableError } from "effect/Cause";
import * as Data from "effect/Data";

/** Why a GNAP request could not be understood. */
export type GnapClientFieldErrorReason =
  /** The `client` field is absent. */
  | "client-missing"
  /** The `client` field is neither a string nor an object. */
  | "client-invalid-type"
  /** The `client` field is an object that is neither `{ walletAddress }` nor `{ jwk }`. */
  | "client-invalid-shape"
  /** A stored grant has neither a client wallet address nor a JWK. */
  | "client-missing-identity";

interface GnapClientFieldErrorFields {
  readonly reason: GnapClientFieldErrorReason;
  readonly message: string;
}

// Explicit annotation: `isolatedDeclarations` forbids a call expression in an `extends` clause.
const Base: new (fields: GnapClientFieldErrorFields) => YieldableError & {
  readonly _tag: "GnapClientFieldError";
} & Readonly<GnapClientFieldErrorFields> = Data.TaggedError("GnapClientFieldError")<GnapClientFieldErrorFields>;

const MESSAGES = {
  "client-missing": "Invalid client field",
  "client-invalid-type": "Invalid client field",
  "client-invalid-shape": "Invalid client field",
  "client-missing-identity": "Grant must have either client or jwk",
} as const satisfies { readonly [Reason in GnapClientFieldErrorReason]: string };

/**
 * A GNAP request or stored grant that cannot be interpreted, discriminated by `reason`.
 * `message` is safe to show to the requesting client.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9635
 */
export class GnapClientFieldError extends Base {
  constructor(args: { readonly reason: GnapClientFieldErrorReason }) {
    super({ reason: args.reason, message: MESSAGES[args.reason] });
  }
}
