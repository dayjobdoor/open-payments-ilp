import * as Effect from "effect/Effect";
import { sha256, toHex, utf8Encode } from "../internal/bytes";

/**
 * Extracts the token from an `Authorization: GNAP <token>` header value.
 * Returns `null` when the header is absent, uses another scheme, or carries an empty token.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9635#section-7.2
 */
export function extractGnapToken(authorization: string | undefined): string | null {
  // HTTP auth schemes are case-insensitive (RFC 9110 §11.1).
  return authorization?.match(/^GNAP +(\S+)\s*$/i)?.[1] ?? null;
}

/** Formats the `Authorization` header value for a GNAP access token. */
export function formatGnapAuthorization(token: string): string {
  return `GNAP ${token}`;
}

/**
 * SHA-256 of a token (continue or access token) as lower-case hex, for storing a verifier instead of the secret.
 */
export function hashToken(token: string): Effect.Effect<string> {
  return Effect.promise(async () => toHex(await sha256(utf8Encode(token))));
}
