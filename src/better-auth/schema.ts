import type { BetterAuthPlugin } from "better-auth/types";

/**
 * The three tables the plugin adds to the Better Auth schema (run the Better Auth migration after adding it):
 * `gnapGrant`, with the interaction inline, `gnapAccessToken` and `gnapNonce` (replay guard for signature nonces; delete rows past `expiresAt` whenever convenient). Timestamps are `date` columns; the store
 * converts them to the epoch milliseconds of `GnapStore`.
 *
 * Indexes the server relies on: `gnapGrant.continueId` and `gnapGrant.interactId` (unique, the latter nullable),
 * `gnapAccessToken.valueHash` and `gnapAccessToken.managementId` (unique), `gnapAccessToken.grantId`, `gnapNonce.key` (unique).
 */
export const gnapSchema: NonNullable<BetterAuthPlugin["schema"]> = {
  gnapGrant: {
    fields: {
      version: { type: "number", required: true },
      state: { type: "string", required: true, index: true },
      tenantId: { type: "string", required: false },
      client: { type: "string", required: false },
      jwk: { type: "json", required: false },
      access: { type: "json", required: true },
      subject: { type: "json", required: false },
      interactId: { type: "string", required: false, unique: true },
      interactNonce: { type: "string", required: false },
      interactRef: { type: "string", required: false },
      interactExpiresAt: { type: "date", required: false },
      finishUri: { type: "string", required: false },
      clientNonce: { type: "string", required: false },
      finishHashMethod: { type: "string", required: false },
      label: { type: "string", required: false },
      userId: {
        type: "string",
        required: false,
        index: true,
        references: { model: "user", field: "id", onDelete: "set null" },
      },
      continueId: { type: "string", required: true, unique: true },
      continueTokenHash: { type: "string", required: true },
      lastContinuedAt: { type: "date", required: true },
      createdAt: { type: "date", required: true },
      updatedAt: { type: "date", required: true },
    },
  },
  gnapAccessToken: {
    fields: {
      grantId: {
        type: "string",
        required: true,
        index: true,
        references: { model: "gnapGrant", field: "id", onDelete: "cascade" },
      },
      valueHash: { type: "string", required: true, unique: true },
      managementId: { type: "string", required: true, unique: true },
      expiresAt: { type: "date", required: true },
      revokedAt: { type: "date", required: false },
      createdAt: { type: "date", required: true },
    },
  },
  gnapNonce: {
    fields: {
      key: { type: "string", required: true, unique: true },
      expiresAt: { type: "date", required: true },
    },
  },
};

/** Error codes of the consent API (the GNAP endpoints answer with GNAP error bodies instead). */
export const GNAP_ERROR_CODES = {
  UNKNOWN_INTERACTION: { code: "unknown_interaction", message: "unknown interaction" },
  INVALID_INTERACTION: { code: "invalid_interaction", message: "invalid interaction" },
  USER_DENIED: { code: "user_denied", message: "user denied interaction" },
  REQUEST_DENIED: { code: "request_denied", message: "the user may not decide on this interaction" },
} as const;
