import * as Cause from "effect/Cause";
import * as Effect from "effect/Effect";
import { buildFinishUrl, computeInteractionHash } from "../interaction";
import { constantTimeEqualText } from "../../internal/bytes";
import type { ConsentUrlParams, InteractionDetails } from "./config";
import { grantEndpoint, tenantConfig, updateGrant, type Core } from "./core";
import { fail, redirect, respond, type GnapRouteError, type ParamHandler } from "./http";
import { postFinish } from "./push";
import type { GrantRecord, GrantState } from "./store";

interface InteractionParams {
  readonly id: string;
  readonly nonce: string;
}

/** The interaction `interactId` + `nonce` name, whatever state its grant is in. */
const findInteraction = (
  core: Core,
  interactId: string,
  nonce: string,
  status = 404,
): Effect.Effect<GrantRecord, GnapRouteError> =>
  Effect.gen(function* () {
    const grant = yield* core.store.findGrant("interactId", interactId);

    if (
      grant === null ||
      grant.interactNonce === null ||
      grant.client === null ||
      !constantTimeEqualText(nonce, grant.interactNonce)
    ) {
      return yield* fail(status, "unknown_interaction", "unknown interaction");
    }

    return grant;
  });

const isExpired = (core: Core, grant: GrantRecord): boolean =>
  grant.interactExpiresAt !== null && core.now() > grant.interactExpiresAt;

/** What the owner decided (Rafiki's interaction state), whether or not `/finish` has recorded it on the grant yet. */
const decisionOf = (state: GrantState): InteractionDetails["state"] =>
  state === "ACCEPTED" || state === "APPROVED" || state === "FINALIZED"
    ? "APPROVED"
    : state === "DENIED" || state === "REJECTED"
      ? "DENIED"
      : "PENDING";

const detailsOf = (grant: GrantRecord): InteractionDetails => ({
  grantId: grant.id,
  client: grant.client ?? "",
  access: grant.access,
  ...(grant.subject !== null && { subject: grant.subject }),
  state: decisionOf(grant.state),
  finish: grant.finishUri !== null,
  expiresAt: new Date(grant.interactExpiresAt ?? grant.createdAt).toISOString(),
});

/** The client's finish URI with `result` (and `message`) appended. */
const finishWith = (finishUri: string, result: string, message?: string): string => {
  const url = new URL(finishUri);

  url.searchParams.set("result", result);

  if (message !== undefined) url.searchParams.set("message", message);

  return url.toString();
};

/** The `interact_ref` and the `hash` that proves the server, the payload of a finish redirect or push. */
const finishPayload = (core: Core, grant: GrantRecord) =>
  Effect.gen(function* () {
    const interactRef = grant.interactRef ?? "";

    const hash = yield* computeInteractionHash({
      clientNonce: grant.clientNonce ?? "",
      serverNonce: grant.interactNonce ?? "",
      interactRef,
      grantEndpoint: grantEndpoint(core, grant),
      encoding: core.config.finishHashEncoding ?? "base64",
      ...(grant.finishHashMethod !== null && { method: grant.finishHashMethod }),
    });

    return { interactRef, hash };
  });

/** The client's finish redirect for an approved interaction: `interact_ref` and the `hash` that proves the server. */
const approvedRedirect = (core: Core, grant: GrantRecord, finishUri: string): Effect.Effect<string> =>
  Effect.map(finishPayload(core, grant), (payload) => buildFinishUrl(finishUri, payload));

/**
 * `finish.method: "push"` (RFC 9635 §4.2.2): hands the client the finish payload in a `POST`. A delivery that fails
 * is reported to `onError` and nothing else: the owner's decision stands and the client can still poll its grant.
 */
const pushFinish = (core: Core, grant: GrantRecord, finishUri: string) =>
  Effect.gen(function* () {
    const { interactRef, hash } = yield* finishPayload(core, grant);
    const failure = yield* postFinish(core.config.fetch, finishUri, { hash, interact_ref: interactRef });

    if (failure !== null) {
      yield* Effect.suspend(
        () => core.config.onError?.(Cause.die(new Error(`finish push failed: ${failure}`))) ?? Effect.void,
      ).pipe(Effect.ignoreCause);
    }
  });

const cookieName = (interactId: string): string => `gnap-interaction-${interactId}`;

const cookieValue = (request: Request, name: string): string | undefined =>
  request.headers
    .get("cookie")
    ?.split(";")
    .map((pair) => pair.trim())
    .find((pair) => pair.startsWith(`${name}=`))
    ?.slice(name.length + 1);

/** `GET /interact/:id/:nonce`: where `interact.redirect` points; binds the browser and forwards to the consent page. */
const startInteraction = (core: Core, { id, nonce }: InteractionParams) =>
  Effect.gen(function* () {
    const grant = yield* findInteraction(core, id, nonce, 400);

    if (grant.state !== "PENDING" || isExpired(core, grant)) {
      if (grant.finishUri === null) return yield* fail(403, "invalid_interaction", "invalid interaction");

      return redirect(finishWith(grant.finishUri, "invalid_interaction", "invalid interaction"));
    }

    const consentUrl = (yield* tenantConfig(core, grant.tenantId))?.consentUrl;

    if (consentUrl === undefined) {
      if (grant.finishUri === null) return yield* fail(500, "request_denied", "internal server error");

      return redirect(finishWith(grant.finishUri, "request_denied", "internal server error"));
    }

    const clientUri = grant.client ?? "";

    const params: ConsentUrlParams = {
      interactId: id,
      nonce,
      clientName: URL.canParse(clientUri) ? new URL(clientUri).hostname : clientUri,
      clientUri,
    };

    const location =
      // oxlint-disable-next-line anti-slop/no-runtime-typeof -- `consentUrl` is a URL or a callback by contract.
      typeof consentUrl === "function"
        ? consentUrl(params)
        : (() => {
            const url = new URL(consentUrl);

            for (const [name, value] of Object.entries(params)) url.searchParams.set(name, value);

            return url.toString();
          })();

    // Rafiki's session cookie, with the nonce as its value: it ties the browser to this URL, but anyone who knows the
    // nonce can set it, so it is not a proof that this browser started the interaction.
    const cookie = [
      `${cookieName(id)}=${nonce}`,
      `Path=${core.basePath}/interact/${id}`,
      `Max-Age=${core.interactionExpiresInSeconds}`,
      "HttpOnly",
      "SameSite=Lax",
      ...(core.baseUrl.startsWith("https:") ? ["Secure"] : []),
    ].join("; ");

    return redirect(location, { "set-cookie": cookie });
  });

/**
 * Moves a decided grant on when the owner's browser reaches `/finish` (`ACCEPTED` to `APPROVED`, `DENIED` to
 * `REJECTED`); a grant that is past that point is left alone. Says whether this call made the move.
 */
const settle = (core: Core, grant: GrantRecord, from: "ACCEPTED" | "DENIED", to: "APPROVED" | "REJECTED") =>
  Effect.gen(function* () {
    const outcome = { moved: false };

    if (grant.state !== from) return false;

    yield* updateGrant(core, grant, (current) => {
      outcome.moved = current.state === from;

      return Effect.succeed(outcome.moved ? { state: to } : {});
    });

    return outcome.moved;
  });

/**
 * `GET /interact/:id/:nonce/finish`: sends the user back to the client (or answers `202` when the client polls or
 * is pushed the result, `finish.method: "push"`: the push is made once, by the visit that approved the grant).
 */
const finishInteraction = (core: Core, request: Request, { id, nonce }: InteractionParams) =>
  Effect.gen(function* () {
    const grant = yield* findInteraction(core, id, nonce);
    // Only a redirect client sends the browser back; a push client is told over the back channel.
    const finishUri = grant.finishMethod === "push" ? null : grant.finishUri;

    if (isExpired(core, grant)) {
      if (finishUri === null) return yield* fail(401, "invalid_interaction", "interaction expired");

      return redirect(finishWith(finishUri, "invalid_interaction", "interaction expired"));
    }

    const session = cookieValue(request, cookieName(id));

    if (session === undefined || !constantTimeEqualText(session, nonce)) {
      return yield* fail(401, "invalid_request", "invalid session");
    }

    if (grant.state === "REVOKED") {
      if (finishUri === null) return yield* fail(404, "unknown_interaction", "unknown interaction");

      return redirect(finishWith(finishUri, "unknown_interaction", "unknown interaction"));
    }

    const decision = decisionOf(grant.state);
    let approvedNow = false;

    if (decision === "APPROVED") approvedNow = yield* settle(core, grant, "ACCEPTED", "APPROVED");
    else if (decision === "DENIED") yield* settle(core, grant, "DENIED", "REJECTED");

    if (finishUri !== null) {
      if (decision === "APPROVED") return redirect(yield* approvedRedirect(core, grant, finishUri));

      return redirect(finishWith(finishUri, decision === "DENIED" ? "grant_rejected" : "grant_invalid"));
    }

    if (decision === "PENDING") return yield* fail(401, "invalid_interaction", "interaction is not active");

    if (approvedNow && grant.finishUri !== null) yield* pushFinish(core, grant, grant.finishUri);

    return new Response(null, { status: 202 });
  });

/**
 * The identity provider's back channel is authenticated by the `x-idp-secret` of the grant's tenant; a tenant
 * without a secret (or none configured) has no back channel and the interaction is `404`.
 */
const requireIdpSecret = (
  core: Core,
  request: Request,
  grant: GrantRecord,
  code: "invalid_request" | "invalid_interaction",
) =>
  Effect.gen(function* () {
    const secret = (yield* tenantConfig(core, grant.tenantId))?.idpSecret;

    // An empty secret is no secret: `x-idp-secret:` (empty) must not authenticate anybody.
    if (secret === undefined || secret === "") return yield* fail(404, "unknown_interaction", "unknown interaction");
    const presented = request.headers.get("x-idp-secret");

    if (presented === null || !constantTimeEqualText(presented, secret)) {
      return yield* fail(401, code, "invalid x-idp-secret");
    }
  });

/** What the consent UI shows for `interactId` + `nonce`. Fails `404 unknown_interaction` when there is none. */
export const getInteraction = (
  core: Core,
  args: { readonly interactId: string; readonly nonce: string },
): Effect.Effect<InteractionDetails, GnapRouteError> =>
  Effect.gen(function* () {
    const grant = yield* findInteraction(core, args.interactId, args.nonce);

    if (grant.state === "REVOKED") return yield* fail(404, "unknown_interaction", "unknown interaction");

    return detailsOf(grant);
  });

/** Records a decision on an interaction already looked up (one store read less than {@link decideInteraction}). */
const decide = (
  core: Core,
  grant: GrantRecord,
  args: { readonly choice: string; readonly userId?: string },
): Effect.Effect<{ readonly redirect: string }, GnapRouteError> =>
  Effect.gen(function* () {
    if (grant.state === "REJECTED" || grant.state === "REVOKED") {
      return yield* fail(401, "user_denied", "user denied interaction");
    }

    if (grant.state !== "PENDING" || isExpired(core, grant)) {
      return yield* fail(400, "invalid_interaction", "invalid interaction");
    }

    if (args.choice !== "accept" && args.choice !== "reject") {
      return yield* fail(400, "invalid_request", "invalid interaction choice");
    }

    const authorize = core.config.interaction?.authorize;

    // A signed-in user owns nothing the grant names (a wallet, a subject) until the hook says so: no hook, no decision.
    if (args.userId !== undefined) {
      if (authorize === undefined || (yield* authorize({ userId: args.userId, details: detailsOf(grant) })) !== true) {
        return yield* fail(403, "request_denied", "the user may not decide on this interaction");
      }
    }

    yield* updateGrant(core, grant, (current) =>
      current.state === "PENDING"
        ? Effect.succeed({
            state: args.choice === "accept" ? ("ACCEPTED" as const) : ("DENIED" as const),
            userId: args.userId ?? null,
          })
        : fail(400, "invalid_interaction", "invalid interaction"),
    );

    return { redirect: `${core.baseUrl}/interact/${grant.interactId ?? ""}/${grant.interactNonce ?? ""}/finish` };
  });

/**
 * Records the resource owner's decision, as `POST /grant/:id/:nonce/:choice` does for the identity provider. With a
 * `userId` (an authenticated consent page) `interaction.authorize` is asked first and the user is stored. Returns
 * the URL of `/finish`: like Rafiki, the grant only becomes `APPROVED` (or `REJECTED`) when the owner's browser
 * arrives there, and from there it is sent back to the client.
 */
export const decideInteraction = (
  core: Core,
  args: {
    readonly interactId: string;
    readonly nonce: string;
    readonly choice: string;
    readonly userId?: string;
  },
): Effect.Effect<{ readonly redirect: string }, GnapRouteError> =>
  Effect.flatMap(findInteraction(core, args.interactId, args.nonce), (grant) =>
    decide(core, grant, { choice: args.choice, ...(args.userId !== undefined && { userId: args.userId }) }),
  );

const idpGetGrant = (core: Core, request: Request, { id, nonce }: InteractionParams) =>
  Effect.gen(function* () {
    const grant = yield* findInteraction(core, id, nonce);

    if (grant.state === "REVOKED") return yield* fail(404, "unknown_interaction", "unknown interaction");
    yield* requireIdpSecret(core, request, grant, "invalid_request");
    const { grantId, access, subject, state } = detailsOf(grant);

    return Response.json({ grantId, access, ...(subject !== undefined && { subject }), state });
  });

const idpDecide = (
  core: Core,
  request: Request,
  { id, nonce, choice }: InteractionParams & { readonly choice: string },
) =>
  Effect.gen(function* () {
    const grant = yield* findInteraction(core, id, nonce);

    yield* requireIdpSecret(core, request, grant, "invalid_interaction");
    yield* decide(core, grant, { choice });

    return new Response(null, { status: 202 });
  });

export interface InteractionHandlers {
  readonly startInteraction: ParamHandler<InteractionParams>;
  readonly finishInteraction: ParamHandler<InteractionParams>;
  readonly idpGetGrant: ParamHandler<InteractionParams>;
  readonly idpDecide: ParamHandler<InteractionParams & { readonly choice: string }>;
}

/** Handlers of the front channel (`/interact/…`) and the identity provider's back channel (`/grant/…`). */
export const interactionHandlers = (core: Core): InteractionHandlers => ({
  startInteraction: (_request, params) => respond(core, startInteraction(core, params)),
  finishInteraction: (request, params) => respond(core, finishInteraction(core, request, params)),
  idpGetGrant: (request, params) => respond(core, idpGetGrant(core, request, params)),
  idpDecide: (request, params) => respond(core, idpDecide(core, request, params)),
});
