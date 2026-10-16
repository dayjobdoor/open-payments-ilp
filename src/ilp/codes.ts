/** ILP packet type byte values (RFC 27). */
export const IlpPacketType = { Prepare: 12, Fulfill: 13, Reject: 14 } as const;

/**
 * ILP reject error codes (RFC 27): `F` final, `T` temporary, `R` relative.
 * @see https://interledger.org/developers/rfcs/interledger-protocol/#error-codes
 */
export const IlpErrorCode = {
  F00_BAD_REQUEST: "F00",
  F01_INVALID_PACKET: "F01",
  F02_UNREACHABLE: "F02",
  F03_INVALID_AMOUNT: "F03",
  F04_INSUFFICIENT_DESTINATION_AMOUNT: "F04",
  F05_WRONG_CONDITION: "F05",
  F06_UNEXPECTED_PAYMENT: "F06",
  F07_CANNOT_RECEIVE: "F07",
  F08_AMOUNT_TOO_LARGE: "F08",
  F99_APPLICATION_ERROR: "F99",
  T00_INTERNAL_ERROR: "T00",
  T01_PEER_UNREACHABLE: "T01",
  T02_PEER_BUSY: "T02",
  T03_CONNECTOR_BUSY: "T03",
  T04_INSUFFICIENT_LIQUIDITY: "T04",
  T05_RATE_LIMITED: "T05",
  T99_APPLICATION_ERROR: "T99",
  R00_TRANSFER_TIMED_OUT: "R00",
  R01_INSUFFICIENT_SOURCE_AMOUNT: "R01",
  R02_INSUFFICIENT_TIMEOUT: "R02",
  R99_APPLICATION_ERROR: "R99",
} as const;

/** Union of the standard reject code strings. */
export type IlpErrorCodeValue = (typeof IlpErrorCode)[keyof typeof IlpErrorCode];
