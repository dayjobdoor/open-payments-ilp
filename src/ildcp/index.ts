/**
 * Interledger Dynamic Configuration Protocol (IL-DCP): a node asks its upstream peer for its ILP address,
 * asset code and asset scale by sending a zero-amount Prepare to `peer.config`.
 *
 * @see https://interledger.org/developers/rfcs/ilp-over-http/
 * @see https://interledger.org/developers/rfcs/dynamic-configuration-protocol/
 * @module
 */
import * as Result from "effect/Result";
import { IlpErrorCode } from "../ilp/codes";
import { codecFail, IlpCodecError } from "../ilp/errors";
import { asciiBytes, asciiString, readOer, utf8String, writeOer } from "../ilp/oer";
import { isValidIlpAddress } from "../ilp/address";
import {
  deserializeFulfill,
  deserializePrepare,
  serializeFulfill,
  serializePrepare,
  type IlpReply,
} from "../ilp/packets";
import { constantTimeEqual, decodeBase64, utf8Encode } from "../internal/bytes";

/** The reserved destination address of IL-DCP requests. */
export const ILDCP_DESTINATION = "peer.config";

/** The configuration an upstream peer returns. */
export interface IldcpResponse {
  /** The ILP address assigned to the requesting node. */
  readonly clientAddress: string;
  /** Number of decimal places of the asset's unit (0–255). */
  readonly assetScale: number;
  /** Asset code, e.g. `USD`. */
  readonly assetCode: string;
}

/** A decoded IL-DCP request. */
export interface IldcpRequest {
  readonly expiresAt: Date;
  readonly data: Uint8Array;
}

// SHA-256 of 32 zero bytes: every IL-DCP request uses this condition and every response its all-zero preimage.
// Never handed out or mutated: serializers copy it into the packet.
const ILDCP_CONDITION = decodeBase64("Zmh6rfhivXdsj8GLjp+OIAiXFIVu4jOzkCpZHQ1fKSU=");

const FULFILLMENT_LENGTH = 32;

/**
 * Serializes an IL-DCP request (a zero-amount Prepare to `peer.config`).
 * `expiresAt` is explicit so the codec never reads the clock.
 * Fails with `IlpCodecError` when `expiresAt` is unrepresentable or `data` exceeds 32767 bytes.
 */
export function serializeIldcpRequest(request: {
  readonly expiresAt: Date;
  readonly data?: Uint8Array;
}): Result.Result<Uint8Array<ArrayBuffer>, IlpCodecError> {
  return serializePrepare({
    amount: 0n,
    expiresAt: request.expiresAt,
    executionCondition: ILDCP_CONDITION,
    destination: ILDCP_DESTINATION,
    data: request.data ?? new Uint8Array(0),
  });
}

/**
 * Parses an IL-DCP request. Fails with `IlpCodecError` when the packet is not a valid Prepare, is not addressed to
 * `peer.config`, or does not carry the IL-DCP condition. Expiry is not checked (see {@link serveIldcp}).
 */
export function deserializeIldcpRequest(bytes: Uint8Array): Result.Result<IldcpRequest, IlpCodecError> {
  return Result.flatMap(deserializePrepare(bytes), (prepare) => {
    if (prepare.destination !== ILDCP_DESTINATION) {
      return Result.fail(notIldcp("packet is not an IL-DCP request (destination is not peer.config)"));
    }

    if (!constantTimeEqual(prepare.executionCondition, ILDCP_CONDITION)) {
      return Result.fail(notIldcp("packet does not carry the IL-DCP execution condition"));
    }

    return Result.succeed({ expiresAt: prepare.expiresAt, data: prepare.data });
  });
}

/**
 * Serializes an IL-DCP response: a Fulfill with an all-zero fulfillment whose data is
 * `VarOctetString(address) | UInt8(scale) | VarOctetString(assetCode)`.
 * Fails with `IlpCodecError` for an invalid address or a scale outside 0–255.
 */
export function serializeIldcpResponse(response: IldcpResponse): Result.Result<Uint8Array<ArrayBuffer>, IlpCodecError> {
  return Result.flatMap(encodeResponseData(response), (data) =>
    serializeFulfill({ fulfillment: new Uint8Array(FULFILLMENT_LENGTH), data }),
  );
}

/**
 * Parses an IL-DCP response. Fails with `IlpCodecError` when the packet is not a Fulfill with the all-zero
 * fulfillment, or its data is truncated or carries an invalid address or asset code.
 */
export function deserializeIldcpResponse(bytes: Uint8Array): Result.Result<IldcpResponse, IlpCodecError> {
  return Result.flatMap(deserializeFulfill(bytes), (fulfill) => {
    if (fulfill.fulfillment.some((byte) => byte !== 0)) {
      return Result.fail(notIldcp("IL-DCP response does not contain the expected fulfillment"));
    }

    return readOer(fulfill.data, (reader) => {
      const clientAddress = asciiString(reader.readVarOctetString(), "clientAddress");

      if (!isValidIlpAddress(clientAddress)) codecFail("invalid-address", "clientAddress is not a valid ILP address");
      const assetScale = reader.readUInt8();
      const assetCode = utf8String(reader.readVarOctetString(), "assetCode");

      return { clientAddress, assetScale, assetCode };
    });
  });
}

/**
 * Answers an IL-DCP request. Never fails: an invalid, foreign or expired request yields an `F00` Reject
 * triggered by `serverAddress`, a valid one yields the Fulfill carrying `response`.
 *
 * `now` is explicit; the request is expired when `now` is later than its `expiresAt`.
 */
export function serveIldcp(options: {
  readonly requestPacket: Uint8Array;
  readonly serverAddress: string;
  readonly response: IldcpResponse;
  readonly now: Date;
}): IlpReply {
  const reject = (message: string): IlpReply => ({
    code: IlpErrorCode.F00_BAD_REQUEST,
    triggeredBy: options.serverAddress,
    message,
    data: new Uint8Array(0),
  });

  const request = deserializeIldcpRequest(options.requestPacket);

  if (Result.isFailure(request)) return reject(request.failure.message);

  if (options.now.getTime() > request.success.expiresAt.getTime()) return reject("IL-DCP request packet is expired.");
  const data = encodeResponseData(options.response);

  if (Result.isFailure(data)) return reject(data.failure.message);

  return { fulfillment: new Uint8Array(FULFILLMENT_LENGTH), data: data.success };
}

function encodeResponseData(response: IldcpResponse): Result.Result<Uint8Array<ArrayBuffer>, IlpCodecError> {
  return writeOer((out) => {
    if (!isValidIlpAddress(response.clientAddress)) {
      codecFail("invalid-address", "clientAddress is not a valid ILP address");
    }

    out.writeVarOctetString(asciiBytes(response.clientAddress, "clientAddress"));
    out.writeUInt8(response.assetScale);
    out.writeVarOctetString(utf8Encode(response.assetCode));
  });
}

function notIldcp(message: string): IlpCodecError {
  return new IlpCodecError({ reason: "invalid-field", message });
}
