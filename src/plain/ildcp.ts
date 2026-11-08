import * as Effect from "effect/Effect";
import * as ildcp from "../ildcp";
import type { IldcpResponse } from "../ildcp";
import { sync, type Sync } from "../internal/plain";

/**
 * Exception flavour of `open-payments-ilp/ildcp`, shaped after `ilp-protocol-ildcp` (not a port): codecs return the
 * value and throw `IlpCodecError`.
 */

export { IlpCodecError, type IlpCodecErrorReason } from "../ilp/errors";
export { ILDCP_DESTINATION, serveIldcp, type IldcpRequest, type IldcpResponse } from "../ildcp";

/** Serializes an IL-DCP request; throws `IlpCodecError` for an unrepresentable `expiresAt` or oversized `data`. */
export const serializeIldcpRequest: Sync<typeof ildcp.serializeIldcpRequest> = sync(ildcp.serializeIldcpRequest);
/** Parses an IL-DCP request; throws `IlpCodecError` when it is not a valid IL-DCP Prepare. */
export const deserializeIldcpRequest: Sync<typeof ildcp.deserializeIldcpRequest> = sync(ildcp.deserializeIldcpRequest);
/** Serializes an IL-DCP response; throws `IlpCodecError` for an invalid address or scale. */
export const serializeIldcpResponse: Sync<typeof ildcp.serializeIldcpResponse> = sync(ildcp.serializeIldcpResponse);
/** Parses an IL-DCP response; throws `IlpCodecError` when it is not a valid IL-DCP Fulfill. */
export const deserializeIldcpResponse: Sync<typeof ildcp.deserializeIldcpResponse> = sync(
  ildcp.deserializeIldcpResponse,
);

/**
 * Asks the upstream connector for this node's ILP address and asset. `sendData` carries one serialized Prepare to the
 * connector and returns (or resolves with) the serialized reply; if it throws or rejects, so does `fetchIldcp`.
 *
 * Options: `clock` supplies "now" (default `new Date()`), `ttlMs` is how long the request stays valid, in
 * milliseconds (default 30000).
 *
 * Rejects with `IlpCodecError` when the reply is not an IL-DCP response. A connector Reject is such a case: the
 * error has reason `invalid-type` and its message names the Reject's `code` and `message`.
 */
export const fetchIldcp = (
  sendData: (prepare: Uint8Array<ArrayBuffer>) => Uint8Array | Promise<Uint8Array>,
  options: { readonly clock?: () => Date; readonly ttlMs?: number } = {},
): Promise<IldcpResponse> =>
  Effect.runPromise(ildcp.fetchIldcp((prepare) => Effect.promise(async () => sendData(prepare)), options));
