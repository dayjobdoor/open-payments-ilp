import type { components as ASComponents } from "../open-payments/generated/auth-server";
import type {
  components as TIComponents,
  operations as TIOperations,
} from "../open-payments/generated/token-introspection";

/** `interact` of a grant request: how the client can start and finish an interaction. */
export type InteractRequest = ASComponents["schemas"]["interact-request"];

/** `interact` of a pending grant response: where to send the user, and the server's finish nonce. */
export type InteractResponse = ASComponents["schemas"]["interact-response"];

/** `continue` of a grant response: where and with which token to continue the grant. */
export type GrantContinue = ASComponents["schemas"]["continue"];

/** GNAP access token as issued by the Open Payments authorisation server. */
export type GrantAccessToken = ASComponents["schemas"]["access_token"] & { readonly label?: string };

/** Error response of the Open Payments authorisation server API. */
export type AuthServerError =
  | ASComponents["schemas"]["error-invalid-client"]
  | ASComponents["schemas"]["error-invalid-request"]
  | ASComponents["schemas"]["error-request-denied"]
  | ASComponents["schemas"]["error-too-fast"]
  | ASComponents["schemas"]["error-invalid-continuation"]
  | ASComponents["schemas"]["error-invalid-rotation"];

/** Body of `POST /` on the token introspection endpoint. */
export type TokenIntrospectionRequest = TIOperations["post-introspect"]["requestBody"]["content"]["application/json"];

/** Introspection result for an active token. */
export type TokenInfo = TIComponents["schemas"]["token-info"];

/** Body of the introspection response: `{ active: false }` or the token info. */
export type TokenIntrospectionResponse =
  TIOperations["post-introspect"]["responses"]["200"]["content"]["application/json"];

/** The `client` of an introspected token: a wallet address or an inline JWK. */
export type TokenInfoClient = TokenInfo["client"];
