import type * as Cause from "effect/Cause";
import type * as Effect from "effect/Effect";
import type { AccessItem, Subject } from "../index";
import type { ParsedClientField } from "../client-field";
import type { HttpSignatureError } from "../../http-signatures/errors";
import type { JWK } from "../../open-payments/types";
import type { GnapStore } from "./store";

/** `interact` of a grant request as the server understood it: `finish.method` may be `push` (RFC 9635 §2.5.2.2). */
export interface GnapInteractRequest {
  readonly start: ReadonlyArray<"redirect">;
  readonly finish?: {
    readonly method: "redirect" | "push";
    readonly uri: string;
    readonly nonce: string;
    readonly hash_method?: "sha-256" | "sha-384" | "sha-512";
  };
}

/** A grant request as the server understood it, handed to {@link GnapServerConfig.policy}. */
export interface GnapGrantRequest {
  /** The identity the client claims; its signature has been verified before the policy runs. */
  readonly client: ParsedClientField;
  /**
   * Requested `access_token.access` items (empty when only a subject is requested). For an `access_token` array
   * (RFC 9635 §2.1.2) the items of every requested token, without duplicates: one consent covers them all.
   */
  readonly access: ReadonlyArray<AccessItem>;
  readonly subject?: Subject;
  readonly interact?: GnapInteractRequest;
}

/** What the consent UI is told about a pending grant. */
export interface InteractionDetails {
  readonly grantId: string;
  /** Wallet address of the client (interactive grants never belong to JWK clients). */
  readonly client: string;
  readonly access: ReadonlyArray<AccessItem>;
  readonly subject?: Subject;
  /** `PENDING` until the owner decides, then `APPROVED` or `DENIED` (the vocabulary of id-provider.yaml). */
  readonly state: "PENDING" | "APPROVED" | "DENIED";
  /** Whether the client asked to be redirected back (`interact.finish`) once the owner decides. */
  readonly finish: boolean;
  /** ISO 8601. */
  readonly expiresAt: string;
}

/**
 * Query parameters Rafiki puts on the consent URL, for a `consentUrl` function. Rafiki takes `clientName` and
 * `clientUri` from the query of the start URL, which anybody holding the link can edit; here they come from the grant.
 */
export interface ConsentUrlParams {
  readonly interactId: string;
  readonly nonce: string;
  /**
   * Host name of the client's wallet address. Rafiki sends the wallet address document's `publicName` here (and
   * refuses clients whose wallet address has none). This server never fetches the wallet address document, only its
   * `jwks.json` to verify the signature, so the host is the name it can vouch for; a consent page that wants the
   * `publicName` reads it from `clientUri`.
   */
  readonly clientName: string;
  /** The client's wallet address. */
  readonly clientUri: string;
}

/**
 * What a tenant brings to the interaction: Rafiki v2's `idpConsentUrl` and `idpSecret` of a tenant. Both optional:
 * a tenant without `consentUrl` can only get grants that need no consent (`400 invalid tenant` otherwise); without
 * `idpSecret` its identity provider back channel is off.
 */
export interface TenantConfig {
  /** As {@link GnapServerConfig.interaction}'s `consentUrl`. */
  readonly consentUrl?: string | ((params: ConsentUrlParams) => string);
  /** As {@link GnapServerConfig.idpSecret}. */
  readonly idpSecret?: string;
}

/** Configuration of {@link createGnapServer}. All hooks are plain data or Effect-returning functions. */
export interface GnapServerConfig {
  /**
   * Public URL of the authorisation server: the `authServer` of the clients' wallet addresses, where grant requests
   * are POSTed. No trailing slash. Its path is the base path {@link GnapServer.route} serves under, and the string
   * every URL in the responses and every signature base is built from, whatever proxy sits in front.
   */
  readonly baseUrl: string;
  readonly store: GnapStore;
  /**
   * Rafiki v2 multi-tenancy: serve one authorisation server for several tenants, as Rafiki does. Clients POST the
   * grant request to `{baseUrl}/{tenantId}` (a tenant's wallet addresses name that URL as their `authServer`;
   * `POST {baseUrl}` is `404`), and the finish `hash` is computed over that URL. Everything after the grant request
   * (`/continue/…`, `/token/…`, `/interact/…`, `/grant/…`) is tenant-less, the tenant being the one stored in the
   * grant. Resolve `tenantId` to its identity provider settings, or to `null` when there is no such tenant (`404
   * Not Found`, after the client's signature was verified, as in Rafiki). The result replaces `interaction.consentUrl`
   * and `idpSecret`, which are not used then. A tenant named `introspect` is unreachable: the fixed `POST /introspect`
   * route wins. Omit for the single-tenant layout (`POST {baseUrl}`).
   */
  readonly tenants?: (tenantId: string) => Effect.Effect<TenantConfig | null>;
  /** Clock for expiry, `wait` and signature freshness. Default: `new Date()`. */
  readonly clock?: () => Date;
  /** Secret generator for continue/access tokens, nonces and references. Default: 256 random bits, base64url. */
  readonly generateToken?: () => string;
  /**
   * Public keys of a client identified by wallet address. Only keys whose `kid` equals the signature's `keyid`
   * are used.
   *
   * The default is `GET {walletAddress}/jwks.json` with {@link GnapServerConfig.fetch}, hardened against SSRF: it
   * refuses wallet addresses that are not `https`, carry credentials, or whose host is an IP literal, `localhost`
   * or `*.localhost`, `*.local`, `*.internal`, a single label, or has a trailing dot; it never follows redirects
   * and rejects responses over 64 KiB. DNS rebinding is NOT covered (Web Standards give no way to inspect the
   * resolved address): where clients must not reach private networks, resolve keys here yourself, with an egress
   * policy, a pinned allow-list or a cache.
   *
   * A key lookup that fails is answered `400 invalid_client` and never reaches {@link GnapServerConfig.onError}. To
   * log why, wrap this function: the default's {@link HttpSignatureError} carries the underlying error (timeout,
   * status, size, not a JWK set) as `cause`.
   */
  readonly resolveClientKeys?: (walletAddress: string) => Effect.Effect<ReadonlyArray<JWK>, HttpSignatureError>;
  /**
   * `fetch` used by the default key resolver and for the `finish.method: "push"` callback (a `POST` that never
   * follows redirects, times out after 5 seconds and is only made to public `https` URLs). Default: global `fetch`.
   */
  readonly fetch?: typeof globalThis.fetch;
  readonly policy?: {
    /**
     * Whether a grant needs the resource owner's consent. Default (Rafiki's): a subject is requested, or any
     * `outgoing-payment` item, or any item with the `list-all` action; plain `incoming-payment` and `quote` access
     * is granted immediately.
     */
    readonly requiresInteraction?: (request: GnapGrantRequest) => boolean;
  };
  /** Required to serve any grant that needs interaction. */
  readonly interaction?: {
    /**
     * Where `GET /interact/:id/:nonce` sends the user. A string gets Rafiki's query parameters (`interactId`,
     * `nonce`, `clientName`, `clientUri`); a function builds the URL itself. Required to serve interactive grants,
     * unless {@link GnapServerConfig.tenants} supplies it per tenant.
     */
    readonly consentUrl?: TenantConfig["consentUrl"];
    /** Lifetime of an interaction, from the grant request. Default 600 seconds. */
    readonly expiresInSeconds?: number;
    /**
     * Required for {@link GnapServer.decideInteraction} with an authenticated `userId` (and so for the Better Auth
     * consent endpoints): without it every such decision is refused (`403 request_denied`), and so is any answer other
     * than `true`. It must answer whether the user may decide on what the grant names, e.g. owns the wallet address of
     * every `outgoing-payment` item and of the requested `subject` (RFC 9635 §3.4). A grant may carry only a
     * `subject` (`details.access` is then empty), so check both. Being signed in proves nothing about that.
     */
    readonly authorize?: (args: {
      readonly userId: string;
      readonly details: InteractionDetails;
    }) => Effect.Effect<boolean>;
  };
  /**
   * Secret of the identity provider back channel (`x-idp-secret`, id-provider.yaml); use a long random value. Without
   * it (an empty string counts as none) `GET|POST /grant/:id/:nonce…` answers `404`; {@link GnapServer.decideInteraction}
   * serves consent that is authenticated some other way. Not used with {@link GnapServerConfig.tenants}, where every
   * tenant has its own.
   */
  readonly idpSecret?: string;
  /**
   * Enables `POST /introspect` for resource servers (token-introspection.yaml). `authorize` receives the untouched
   * request (verify its signature or bearer secret there) and answers `false` for a caller it does not recognise
   * (`400 invalid_resource_server`, RFC 9767 §3.5), `true` for one that may ask about any token, or `{ tenantId }` for
   * one that may only ask about tokens of that tenant: a token of another tenant is then `{ active: false }`, as an
   * unknown one is, so the answer reveals nothing about tokens beyond the caller's tenant. Off by default;
   * {@link GnapServer.introspectToken} is always available in process (and not scoped).
   */
  readonly introspection?: {
    readonly authorize: (request: Request) => Effect.Effect<boolean | { readonly tenantId: string }>;
  };
  /** Lifetime of issued access tokens. Default 600 seconds. */
  readonly accessTokenExpiresInSeconds?: number;
  /** Minimum seconds between continuation requests (`continue.wait`). Default and floor 5 (RFC 9635 §3.1). */
  readonly waitSeconds?: number;
  /**
   * Digest encoding of the finish `hash`. Default `base64`, padded, as Rafiki sends it; RFC 9635 and the Open
   * Payments docs specify unpadded `base64url`, which is the other choice.
   */
  readonly finishHashEncoding?: "base64" | "base64url";
  /**
   * Largest request body read, in bytes. Larger ones are answered with `413` before anything else happens (no key
   * fetch, no parsing); the body is read as a stream and abandoned once past the cap. Default 64 KiB.
   */
  readonly maxBodyBytes?: number;
  /**
   * Called with the cause of every unexpected failure that {@link GnapServer.route} (or a handler) answers with a
   * `500`: a store outage, a throwing callback, a bug. It never receives request data (the cause itself may embed
   * what the failing code put in it, such as SQL parameters), and the library logs nothing by default: the host
   * decides what to redact and where to log. A failure or defect inside the hook is swallowed and never changes the
   * client's response. It also receives a failed `finish.method: "push"` delivery (a `die` of an `Error` that names
   * the reason, without the client's URL); the owner's decision and the response to the browser are unaffected.
   */
  readonly onError?: (cause: Cause.Cause<never>) => Effect.Effect<void>;
}
