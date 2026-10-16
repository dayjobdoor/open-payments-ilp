/**
 * Adapter between caller-supplied `Uint8Array<ArrayBufferLike>` and WebCrypto's `Uint8Array<ArrayBuffer>`.
 * @internal Not exported from any public entry point.
 */

/** Returns `bytes` itself when it is `ArrayBuffer`-backed, otherwise a copy (e.g. `SharedArrayBuffer` views). */
export function owned(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  // SAFETY: the instanceof check proves the backing store is a plain ArrayBuffer.
  return bytes.buffer instanceof ArrayBuffer ? (bytes as Uint8Array<ArrayBuffer>) : new Uint8Array(bytes);
}
