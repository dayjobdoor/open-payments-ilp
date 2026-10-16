// oxlint-disable anti-slop/no-unknown-returns -- The reference client's responses are validated by the client itself; the flows only compare them.
/**
 * Wire compatibility: the reference `@interledger/open-payments` client (which validates every response against the
 * Open Payments OpenAPI documents and signs requests its own way) drives an authorisation server over real HTTP.
 * Shared by the core and by the Better Auth adapter, which both must pass it unchanged.
 */
import { createPrivateKey } from "node:crypto";
import { createAuthenticatedClient, isFinalizedGrantWithAccessToken, isPendingGrant } from "@interledger/open-payments";
import * as Effect from "effect/Effect";
import { afterAll, beforeAll, describe, expect, it } from "vite-plus/test";
import { computeInteractionHash, type AccessItem } from "../../src/gnap/index";
import { FINISH_URI, KEY_ID, WALLET, type ClientKey } from "./support";

/** What the flows need from the server under test. */
export interface ReferenceTarget {
  /** The grant endpoint, e.g. `http://127.0.0.1:1234/gnap`. */
  readonly authServer: string;
  /** Where grant requests are POSTed when that is not `authServer` (multi-tenant: `authServer/{tenantId}`). */
  readonly grantUrl?: string;
  readonly clientKey: ClientKey;
  readonly idpSecret: string;
  readonly advanceClock: (seconds: number) => void;
  readonly introspect: (token: string, access?: ReadonlyArray<AccessItem>) => Promise<unknown>;
  readonly close: () => Promise<void>;
}

type Reference = Awaited<ReturnType<typeof createAuthenticatedClient>>;

const outgoing = {
  type: "outgoing-payment" as const,
  actions: ["create" as const, "read" as const],
  identifier: WALLET,
  limits: { debitAmount: { value: "1000", assetCode: "USD", assetScale: 2 } },
};

/** Registers the reference client flows under `describe(name)`; `start` boots the server and returns its handles. */
export function describeReferenceClient(name: string, start: () => Promise<ReferenceTarget>): void {
  describe(`reference client: ${name}`, () => {
    let target: ReferenceTarget;
    let reference: Reference;

    beforeAll(async () => {
      target = await start();
      const pkcs8 = await crypto.subtle.exportKey("pkcs8", target.clientKey.signingKey.privateKey);

      reference = await createAuthenticatedClient({
        walletAddressUrl: WALLET,
        keyId: KEY_ID,
        privateKey: createPrivateKey({ key: Buffer.from(pkcs8), format: "der", type: "pkcs8" }),
        useHttp: true,
        logLevel: "silent",
      });
    });

    afterAll(async () => {
      await target.close();
    });

    const idp = (path: string, init: RequestInit = {}) =>
      globalThis.fetch(`${target.authServer}/grant/${path}`, {
        ...init,
        headers: { "x-idp-secret": target.idpSecret },
      });

    /** The user's browser: follows `interact.redirect`, consents through the back channel, comes back to finish. */
    const browser = async (redirect: string, choice: "accept" | "reject") => {
      const start = await globalThis.fetch(redirect, { redirect: "manual" });
      const consent = new URL(start.headers.get("location") ?? "");
      const cookie = (start.headers.get("set-cookie") ?? "").split(";")[0] ?? "";
      const [interactId = "", nonce = ""] = new URL(redirect).pathname.split("/").slice(-2);

      expect(start.status).toBe(302);
      expect(consent.searchParams.get("interactId")).toBe(interactId);

      const details = await idp(`${interactId}/${nonce}`);

      expect(await details.json()).toMatchObject({ state: "PENDING" });
      expect((await idp(`${interactId}/${nonce}/${choice}`, { method: "POST" })).status).toBe(202);

      const finish = await globalThis.fetch(`${target.authServer}/interact/${interactId}/${nonce}/finish`, {
        redirect: "manual",
        headers: { cookie },
      });

      return { finish, nonce, location: new URL(finish.headers.get("location") ?? "about:blank") };
    };

    /** Where grant requests go: the tenant URL on a multi-tenant server, else the base URL. */
    const grantUrl = (): string => target.grantUrl ?? target.authServer;

    const interactive = () =>
      reference.grant.request(
        { url: grantUrl() },
        {
          access_token: { access: [outgoing] },
          interact: { start: ["redirect"], finish: { method: "redirect", uri: FINISH_URI, nonce: "ref-nonce" } },
        },
      );

    it("receives an incoming-payment grant at once and cancels it", async () => {
      const grant = await reference.grant.request(
        { url: grantUrl() },
        { access_token: { access: [{ type: "incoming-payment", actions: ["create", "read"] }] } },
      );

      if (!isFinalizedGrantWithAccessToken(grant)) throw new Error("expected an access token");

      expect(await target.introspect(grant.access_token.value)).toMatchObject({
        active: true,
        client: { walletAddress: WALLET },
      });

      await reference.grant.cancel({ url: grant.continue.uri, accessToken: grant.continue.access_token.value });
      expect(await target.introspect(grant.access_token.value)).toEqual({ active: false });
    });

    it("completes the interactive flow: consent, hash, continue, rotate, revoke", async () => {
      const pending = await interactive();

      if (!isPendingGrant(pending)) throw new Error("expected a pending grant");

      const { finish, location } = await browser(pending.interact.redirect, "accept");
      const interactRef = location.searchParams.get("interact_ref") ?? "";

      expect(finish.status).toBe(302);

      // Rafiki's hash: SHA-256 over `clientNonce \n serverNonce \n interactRef \n grantEndpoint`, padded base64.
      expect(location.searchParams.get("hash")).toBe(
        await Effect.runPromise(
          computeInteractionHash({
            clientNonce: "ref-nonce",
            serverNonce: pending.interact.finish,
            interactRef,
            grantEndpoint: grantUrl(),
            encoding: "base64",
          }),
        ),
      );

      target.advanceClock(6);

      const grant = await reference.grant.continue(
        { url: pending.continue.uri, accessToken: pending.continue.access_token.value },
        { interact_ref: interactRef },
      );

      if (!isFinalizedGrantWithAccessToken(grant)) throw new Error("expected an access token");
      const token = grant.access_token;

      // Like Rafiki: only the items the resource server asks about are reported.
      expect(await target.introspect(token.value, [outgoing])).toMatchObject({ active: true, access: [outgoing] });
      expect(await target.introspect(token.value)).toMatchObject({ active: true, access: [] });

      const rotated = await reference.token.rotate({ url: token.manage, accessToken: token.value });

      expect(await target.introspect(token.value)).toEqual({ active: false });

      await reference.token.revoke({ url: rotated.access_token.manage, accessToken: rotated.access_token.value });
      expect(await target.introspect(rotated.access_token.value)).toEqual({ active: false });
    });

    it("completes a polling flow (no finish): the client waits, then collects the token", async () => {
      const pending = await reference.grant.request(
        { url: grantUrl() },
        { access_token: { access: [outgoing] }, interact: { start: ["redirect"] } },
      );

      if (!isPendingGrant(pending)) throw new Error("expected a pending grant");

      target.advanceClock(6);

      const waiting = await reference.grant.continue({
        url: pending.continue.uri,
        accessToken: pending.continue.access_token.value,
      });

      expect(isFinalizedGrantWithAccessToken(waiting)).toBe(false);

      await browser(pending.interact.redirect, "accept");
      target.advanceClock(6);

      const grant = await reference.grant.continue({
        url: pending.continue.uri,
        accessToken: pending.continue.access_token.value,
      });

      expect(isFinalizedGrantWithAccessToken(grant)).toBe(true);
    });

    it("is refused with the GNAP error body when the owner rejects", async () => {
      const pending = await interactive();

      if (!isPendingGrant(pending)) throw new Error("expected a pending grant");

      const { location } = await browser(pending.interact.redirect, "reject");

      expect(location.searchParams.get("result")).toBe("grant_rejected");

      target.advanceClock(6);

      await expect(
        reference.grant.continue(
          { url: pending.continue.uri, accessToken: pending.continue.access_token.value },
          { interact_ref: "x" },
        ),
      ).rejects.toMatchObject({ status: 404, code: "invalid_continuation" });
    });

    it("cancels a pending grant", async () => {
      const pending = await interactive();

      if (!isPendingGrant(pending)) throw new Error("expected a pending grant");

      await reference.grant.cancel({ url: pending.continue.uri, accessToken: pending.continue.access_token.value });

      await expect(
        reference.grant.continue(
          { url: pending.continue.uri, accessToken: pending.continue.access_token.value },
          { interact_ref: "x" },
        ),
      ).rejects.toMatchObject({ status: 401, code: "invalid_continuation" });
    });
  });
}
