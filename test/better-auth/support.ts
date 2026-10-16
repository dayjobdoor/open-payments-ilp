// oxlint-disable anti-slop/no-unsafe-dictionary-type -- Tests send arbitrary request bodies and headers by design.
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import * as Effect from "effect/Effect";
import { gnap, type GnapOptions } from "../../src/better-auth/index";
import { gnapSchema } from "../../src/better-auth/schema";
import { signRequest, type SigningKey } from "../../src/http-signatures/index";
import { expectConformsToSpec } from "../gnap-server/openapi";
import {
  CONSENT_URL,
  IDP_SECRET,
  createClientKey,
  createClock,
  walletFetch,
  withHeaders,
} from "../gnap-server/support";

export const BASE_URL = "https://as.test";

/** Where the plugin mounts the grant endpoint. */
export const GNAP_PATH = "/api/auth/gnap";

const SECRET = "x".repeat(40);

const USER = { email: "owner@example.com", password: "correct horse battery", name: "Owner" };

export interface HarnessOptions extends Partial<GnapOptions> {
  readonly baseURL?: string;
  /** Extra `betterAuth` options (e.g. `rateLimit`). */
  readonly auth?: Record<string, unknown>;
  /** Leaves out the `interaction.authorize` hook that lets every signed-in user decide. */
  readonly withoutConsentHook?: boolean;
}

/** A Better Auth instance with the GNAP plugin on an in-memory database, plus a signed-in user. */
export const createHarness = async (options: HarnessOptions = {}) => {
  const { baseURL = BASE_URL, auth: authOptions = {}, withoutConsentHook = false, ...gnapOptions } = options;
  const clientKey = await createClientKey();
  const clock = createClock();

  // The memory adapter needs every model's table up front.
  const db: Record<string, unknown[]> = Object.fromEntries(
    ["user", "session", "account", "verification", ...Object.keys(gnapSchema)].map((model) => [model, []]),
  );

  const auth = betterAuth({
    database: memoryAdapter(db),
    baseURL,
    secret: SECRET,
    emailAndPassword: { enabled: true },
    // Off by default under test; the consent API relies on it against cross-site POSTs.
    advanced: { disableOriginCheck: false },
    ...authOptions,
    plugins: [
      gnap({
        // A multi-tenant server has no top-level secret: every tenant brings its own.
        ...(gnapOptions.tenants === undefined && { idpSecret: IDP_SECRET }),
        fetch: walletFetch([clientKey]),
        clock: clock.now,
        ...gnapOptions,
        interaction: {
          consentUrl: CONSENT_URL,
          ...(!withoutConsentHook && { authorize: () => Effect.succeed(true) }),
          ...gnapOptions.interaction,
        },
      }),
    ],
  });

  const signUp = await auth.api.signUpEmail({ body: USER, asResponse: true });

  const cookie = signUp.headers
    .getSetCookie()
    .map((line) => line.split(";")[0])
    .join("; ");

  const grantUrl = `${baseURL}${GNAP_PATH}`;

  /** Calls the Better Auth handler as the signed-in resource owner (same-origin, with the session cookie). */
  const asUser = (path: string, init: RequestInit = {}): Promise<Response> =>
    auth.handler(new Request(`${baseURL}/api/auth${path}`, withHeaders(init, { cookie, origin: baseURL })));

  /** Sends `request` to the handler; throws when a GNAP response is not what the OpenAPI documents allow. */
  const call = async (request: Request): Promise<Response> => {
    const response = await auth.handler(request.clone());

    await expectConformsToSpec(request, new URL(request.url).pathname.slice(GNAP_PATH.length), response.clone());

    return response;
  };

  /** Signs `init` with `key` (default: the harness client's) and sends it straight to the handler. */
  const signedCall = async (url: string, init: RequestInit, key: SigningKey = clientKey.signingKey) =>
    call(await Effect.runPromise(signRequest(new Request(url, init), key)));

  const userId = async (): Promise<string> => {
    const session = await auth.api.getSession({ headers: new Headers({ cookie }) });

    return session?.user.id ?? "";
  };

  return { auth, db, clock, clientKey, cookie, asUser, call, signedCall, userId, baseURL, grantUrl };
};

export type Harness = Awaited<ReturnType<typeof createHarness>>;
