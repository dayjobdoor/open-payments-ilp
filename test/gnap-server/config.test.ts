// oxlint-disable anti-slop/no-unknown-parameters, anti-slop/no-unsafe-dictionary-type, anti-slop/no-known-value-widening -- Tests send arbitrary request bodies and misconfigurations by design.
/** A server is created with a usable configuration or not at all: an option cannot quietly switch a protection off. */
import * as Effect from "effect/Effect";
import { describe, expect, it } from "vite-plus/test";
import { createGnapServer, memoryGnapStore, type GnapServerConfig } from "../../src/gnap/server/index";
import { BASE_URL, createServerHarness, errorOf, grantBody, incoming, json } from "./support";

const create = (config: Partial<GnapServerConfig> = {}) =>
  createGnapServer({ baseUrl: BASE_URL, store: memoryGnapStore(), ...config });

describe("a configuration that cannot be applied", () => {
  it.each([
    ["maxBodyBytes", { maxBodyBytes: Number.NaN }],
    ["maxBodyBytes", { maxBodyBytes: Number.POSITIVE_INFINITY }],
    ["maxBodyBytes", { maxBodyBytes: -1 }],
    ["waitSeconds", { waitSeconds: Number.NaN }],
    ["waitSeconds", { waitSeconds: Number.POSITIVE_INFINITY }],
    ["waitSeconds", { waitSeconds: -1 }],
    ["accessTokenExpiresInSeconds", { accessTokenExpiresInSeconds: Number.NaN }],
    ["accessTokenExpiresInSeconds", { accessTokenExpiresInSeconds: Number.POSITIVE_INFINITY }],
    ["accessTokenExpiresInSeconds", { accessTokenExpiresInSeconds: 0 }],
    ["accessTokenExpiresInSeconds", { accessTokenExpiresInSeconds: -60 }],
    ["interaction.expiresInSeconds", { interaction: { expiresInSeconds: Number.NaN } }],
    ["interaction.expiresInSeconds", { interaction: { expiresInSeconds: Number.POSITIVE_INFINITY } }],
    ["interaction.expiresInSeconds", { interaction: { expiresInSeconds: 0 } }],
    ["finishHashEncoding", { finishHashEncoding: "hex" as "base64" }],
    ["baseUrl", { baseUrl: "" }],
    ["baseUrl", { baseUrl: "/gnap" }],
    ["baseUrl", { baseUrl: "as.test/gnap" }],
    ["baseUrl", { baseUrl: "ftp://as.test/gnap" }],
    ["baseUrl", { baseUrl: "https://as.test/gnap?tenant=1" }],
    ["baseUrl", { baseUrl: "https://as.test/gnap?" }],
    ["baseUrl", { baseUrl: "https://as.test/gnap#top" }],
    ["baseUrl", { baseUrl: "https://user:secret@as.test/gnap" }],
  ] satisfies ReadonlyArray<readonly [string, Partial<GnapServerConfig>]>)(
    "stops createGnapServer with a RangeError that names %s",
    (option, config) => {
      expect(() => create(config)).toThrow(RangeError);
      expect(() => create(config)).toThrow(`GnapServerConfig.${option} must be`);
    },
  );

  it("accepts the edges of the ranges, a trailing slash and plain http", () => {
    expect(() =>
      create({
        baseUrl: "http://localhost:3000/gnap/",
        maxBodyBytes: 0,
        waitSeconds: 0,
        accessTokenExpiresInSeconds: 1,
        interaction: { expiresInSeconds: 1 },
        finishHashEncoding: "base64url",
      }),
    ).not.toThrow();
  });

  it("applies a body cap of 0 instead of reading the body", async () => {
    const h = await createServerHarness({ maxBodyBytes: 0, unvalidated: true });

    const response = await h.signedCall(h.baseUrl, json("POST", grantBody([incoming])));

    expect(await errorOf(response)).toMatchObject({ status: 413, code: "invalid_request" });
  });

  it("answers 500 and tells onError when the clock returns an Invalid Date, instead of letting nothing expire", async () => {
    const causes: unknown[] = [];

    const h = await createServerHarness({
      clock: () => new Date(Number.NaN),
      onError: (cause) => Effect.sync(() => void causes.push(cause)),
      unvalidated: true,
    });

    const response = await h.signedCall(h.baseUrl, json("POST", grantBody([incoming])));

    expect(await errorOf(response)).toMatchObject({ status: 500, code: "request_denied" });
    expect(causes).toHaveLength(1);
  });
});
