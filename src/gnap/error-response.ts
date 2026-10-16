/**
 * Error codes of the Open Payments authorisation server (`error.code` in auth-server.yaml) and of
 * RFC 9635 §3.6 / §10.15.2 and RFC 9767 §5.9. Other strings are allowed on the wire.
 */
export type GnapErrorCode =
  | "invalid_request"
  | "invalid_client"
  | "invalid_interaction"
  | "invalid_flag"
  | "invalid_rotation"
  | "key_rotation_not_supported"
  | "invalid_continuation"
  | "too_fast"
  | "too_many_attempts"
  | "user_denied"
  | "request_denied"
  | "unknown_interaction"
  | "unknown_user"
  | "invalid_resource_server"
  | "invalid_access";

/** Error body of auth-server.yaml: `{ error: { code, description } }`. */
export interface GnapErrorResponse {
  readonly error: { readonly code: string; readonly description: string };
}

/**
 * Builds `{ error: { code, description } }`. Rafiki's auth server always sends a description, so it is required.
 *
 * @see https://openpayments.dev/apis/auth-server/
 */
export function gnapErrorBody(code: GnapErrorCode | (string & {}), description: string): GnapErrorResponse {
  return { error: { code, description } };
}
