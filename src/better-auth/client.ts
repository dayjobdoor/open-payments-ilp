/**
 * Client plugin for the `open-payments-ilp/better-auth` GNAP plugin: actions for the consent page that decides on
 * a pending grant. Add it to `createAuthClient({ plugins: [gnapClient()] })`.
 *
 * @module
 */
import type { BetterAuthClientPlugin } from "better-auth/types";
import type { InteractionDetails } from "../gnap/server/index";
import { GNAP_ERROR_CODES } from "./schema";
import type { GnapPlugin } from "./index";

type Fetch = Parameters<NonNullable<BetterAuthClientPlugin["getActions"]>>[0];

/** The `{ data, error }` result of a Better Auth client call. */
export type GnapClientResult<T> =
  | { readonly data: T; readonly error: null }
  | {
      readonly data: null;
      readonly error: {
        readonly status: number;
        readonly statusText: string;
        readonly code?: string;
        readonly message?: string;
      };
    };

/** Where to send the user after a decision: the server's finish URL, which sends the browser back to the client. */
export interface GnapDecision {
  readonly redirect: string;
}

/** Actions added to the Better Auth client as `authClient.gnap.*`; `interactId` and `nonce` come from the consent URL. */
export interface GnapClientActions {
  readonly gnap: {
    /** Grant details for the consent page. Needs a signed-in user. */
    readonly getInteraction: (interactId: string, nonce: string) => Promise<GnapClientResult<InteractionDetails>>;
    /** The user consents. Navigate to `data.redirect` afterwards: the finish step sends the browser back to the client. */
    readonly acceptInteraction: (interactId: string, nonce: string) => Promise<GnapClientResult<GnapDecision>>;
    /** The user rejects. Navigate to `data.redirect` afterwards. */
    readonly rejectInteraction: (interactId: string, nonce: string) => Promise<GnapClientResult<GnapDecision>>;
  };
}

/** The client plugin returned by {@link gnapClient}. */
export interface GnapClientPlugin extends BetterAuthClientPlugin {
  readonly id: "gnap";
  readonly $InferServerPlugin: GnapPlugin;
  readonly pathMethods: Record<string, "POST" | "GET">;
  readonly getActions: ($fetch: Fetch) => GnapClientActions;
  readonly $ERROR_CODES: typeof GNAP_ERROR_CODES;
}

/** The route of one interaction; `params` fills `:id` and `:nonce`, and the fetch layer encodes them once. */
const INTERACTION = "/gnap/interaction/:id/:nonce";

/** Creates the client plugin of the GNAP plugin. */
export function gnapClient(): GnapClientPlugin {
  return {
    id: "gnap",
    // SAFETY: type-level link to the server plugin only; the value is never read at runtime.
    $InferServerPlugin: {} as GnapPlugin,
    pathMethods: {
      [INTERACTION]: "GET",
      [`${INTERACTION}/accept`]: "POST",
      [`${INTERACTION}/reject`]: "POST",
    },
    getActions: ($fetch) => ({
      gnap: {
        getInteraction: (interactId, nonce) =>
          $fetch<InteractionDetails>(INTERACTION, { method: "GET", params: { id: interactId, nonce } }),
        acceptInteraction: (interactId, nonce) =>
          $fetch<GnapDecision>(`${INTERACTION}/accept`, { method: "POST", params: { id: interactId, nonce } }),
        rejectInteraction: (interactId, nonce) =>
          $fetch<GnapDecision>(`${INTERACTION}/reject`, { method: "POST", params: { id: interactId, nonce } }),
      },
    }),
    $ERROR_CODES: GNAP_ERROR_CODES,
  };
}
