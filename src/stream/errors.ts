import type { YieldableError } from "effect/Cause";
import * as Data from "effect/Data";

/** Why a STREAM crypto, credential, receipt or sender operation failed. */
export type StreamErrorReason =
  /** AES-256-GCM authentication failed, or the ciphertext is shorter than IV + tag. */
  | "decryption-failed"
  /** A shared secret, key or server secret has the wrong length. */
  | "invalid-key"
  /** The server's base ILP address is invalid or the generated destination address is not a valid ILP address. */
  | "invalid-address"
  /** A credential option (payment tag, receipt nonce/secret, asset scale) or a receipt total is out of range. */
  | "invalid-option"
  /** A receipt is not 58 bytes or has an unsupported version. */
  | "invalid-receipt"
  /** A receipt's HMAC does not match its secret: forged, corrupted or from another connection. */
  | "receipt-hmac-mismatch";

interface StreamErrorFields {
  readonly reason: StreamErrorReason;
  readonly message: string;
}

// Explicit annotation: `isolatedDeclarations` forbids a call expression in an `extends` clause.
const Base: new (fields: StreamErrorFields) => YieldableError & {
  readonly _tag: "StreamError";
} & Readonly<StreamErrorFields> = Data.TaggedError("StreamError")<StreamErrorFields>;

/** Failure of the STREAM crypto, credential, receipt or sender operations. `reason` discriminates the cause. */
export class StreamError extends Base {}
