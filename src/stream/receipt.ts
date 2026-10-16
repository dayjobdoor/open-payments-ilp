import * as Effect from "effect/Effect";
import type { Result } from "effect/Result";
import { codecFail, type IlpCodecError } from "../ilp/errors";
import { readOer } from "../ilp/oer";
import { constantTimeEqual } from "../internal/bytes";
import { StreamError } from "./errors";
import { hmac } from "./key-cache";

const RECEIPT_VERSION = 1;

const RECEIPT_LENGTH = 58;

/** Bytes covered by the HMAC: everything but the trailing 32-byte HMAC itself. */
const SIGNED_LENGTH = 26;

/** A decoded STREAM receipt (RFC 39). */
export interface StreamReceipt {
  /** Receipt format version; only `1` exists. */
  readonly version: number;
  /** 16-byte nonce the receiver issued with the credentials. */
  readonly nonce: Uint8Array;
  /** The stream the receipt covers (a single byte on the wire). */
  readonly streamId: number;
  /** Total amount the receiver has credited on the connection. */
  readonly totalReceived: bigint;
  /** The 32-byte HMAC-SHA256 over the preceding 26 bytes. */
  readonly hmac: Uint8Array;
}

/**
 * Parses a 58-byte STREAM receipt (RFC 39) without checking its HMAC; use {@link verifyStreamReceipt} to authenticate.
 * Fails with `IlpCodecError` (`invalid-field`) unless `bytes` is exactly 58 bytes long.
 */
export function decodeStreamReceipt(bytes: Uint8Array): Result<StreamReceipt, IlpCodecError> {
  return readOer(bytes, (reader) => {
    if (bytes.length !== RECEIPT_LENGTH) codecFail("invalid-field", `a receipt is ${RECEIPT_LENGTH} bytes`);

    return {
      version: reader.readUInt8(),
      nonce: reader.readOctets(16),
      streamId: reader.readUInt8(),
      totalReceived: reader.readUInt64(),
      hmac: reader.readOctets(32),
    };
  });
}

/**
 * Authenticates a STREAM receipt (RFC 39) against the receipt secret issued with the credentials and returns it decoded.
 * `secret` is either the 32-byte secret itself or, when secrets are per nonce, a function from the (still
 * unauthenticated) receipt to its secret. The HMAC is compared in constant time.
 *
 * Fails with `StreamError`: `invalid-receipt` when `receipt` is not 58 bytes or has a version other than 1,
 * `invalid-key` for an empty secret, `receipt-hmac-mismatch` when the HMAC does not match (forged or wrong secret).
 */
export function verifyStreamReceipt(
  receipt: Uint8Array,
  secret: Uint8Array | ((receipt: StreamReceipt) => Uint8Array),
): Effect.Effect<StreamReceipt, StreamError> {
  const decoded = decodeStreamReceipt(receipt);

  if (decoded._tag === "Failure") {
    return Effect.fail(new StreamError({ reason: "invalid-receipt", message: decoded.failure.message }));
  }

  if (decoded.success.version !== RECEIPT_VERSION) {
    return Effect.fail(
      new StreamError({ reason: "invalid-receipt", message: `unsupported receipt version ${decoded.success.version}` }),
    );
  }

  const key = secret instanceof Uint8Array ? secret : secret(decoded.success);

  if (key.length === 0) {
    return Effect.fail(new StreamError({ reason: "invalid-key", message: "receipt secret must not be empty" }));
  }

  return Effect.flatMap(
    Effect.promise(() => hmac(key, receipt.subarray(0, SIGNED_LENGTH))),
    (expected) =>
      constantTimeEqual(expected, decoded.success.hmac)
        ? Effect.succeed(decoded.success)
        : Effect.fail(new StreamError({ reason: "receipt-hmac-mismatch", message: "receipt HMAC does not match" })),
  );
}

/** @internal A receipt for stream 1 totalling `totalReceived` (a uint64), authenticated with `setup.secret`. */
export async function createStreamReceipt(
  setup: { readonly nonce: Uint8Array; readonly secret: Uint8Array },
  totalReceived: bigint,
): Promise<Uint8Array> {
  const receipt = new Uint8Array(RECEIPT_LENGTH);
  receipt[0] = RECEIPT_VERSION;
  receipt.set(setup.nonce, 1);
  receipt[17] = 1;
  new DataView(receipt.buffer).setBigUint64(18, totalReceived);
  receipt.set(await hmac(setup.secret, receipt.subarray(0, SIGNED_LENGTH)), SIGNED_LENGTH);

  return receipt;
}
