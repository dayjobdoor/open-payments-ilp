import type { YieldableError } from "effect/Cause";
import * as Data from "effect/Data";

/** Why an ILP/OER/STREAM codec call failed. */
export type IlpCodecErrorReason =
  /** Input ended before a complete value could be read. */
  | "truncated"
  /** A length prefix used more bytes than needed. */
  | "non-canonical"
  /** A number does not fit its OER type (e.g. uint64) or a length exceeds a protocol limit. */
  | "out-of-range"
  /** The packet type byte is not the one expected for this operation. */
  | "invalid-type"
  /** An ILP address violates RFC 15. */
  | "invalid-address"
  /** An expiry timestamp is not a valid `YYYYMMDDhhmmssfff` UTC time. */
  | "invalid-timestamp"
  /** Any other field-level violation (wrong fixed length, bad error code, bad UTF-8, ...). */
  | "invalid-field";

interface IlpCodecErrorFields {
  readonly reason: IlpCodecErrorReason;
  readonly message: string;
}

// Explicit annotation: `isolatedDeclarations` forbids a call expression in an `extends` clause.
const Base: new (fields: IlpCodecErrorFields) => YieldableError & {
  readonly _tag: "IlpCodecError";
} & Readonly<IlpCodecErrorFields> = Data.TaggedError("IlpCodecError")<IlpCodecErrorFields>;

/**
 * Failure of an OER/ILP/IL-DCP/STREAM-packet encoder or decoder.
 * `reason` discriminates the cause; `message` is human-readable.
 */
export class IlpCodecError extends Base {}

/** @internal Throws inside OER reader/writer callbacks; converted to a `Result` failure at the boundary. */
export function codecFail(reason: IlpCodecErrorReason, message: string): never {
  throw new IlpCodecError({ reason, message });
}
