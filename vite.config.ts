import { defineConfig } from "vite-plus";

const entries = [
  "ilp",
  "ildcp",
  "stream",
  "http-signatures",
  "open-payments",
  "gnap",
  "webhooks",
  "better-auth",
  "hono",
] as const;

// Peer dependencies (effect, better-auth, hono) stay external by default.
export default defineConfig({
  pack: {
    entry: {
      ...Object.fromEntries(entries.map((name) => [`${name}/index`, `src/${name}/index.ts`])),
      "gnap/server/index": "src/gnap/server/index.ts",
      "gnap/server/testing/index": "src/gnap/server/testing/index.ts",
      "better-auth/client": "src/better-auth/client.ts",
    },
    format: "esm",
    platform: "neutral",
    target: "es2023",
    dts: true,
    sourcemap: true,
    clean: true,
    publint: true,
    attw: { profile: "esm-only", level: "error" },
  },
  test: {
    include: ["test/**/*.test.ts"],
    // Generous and explicit: CI and shared machines are slow, and the first gnap-server test compiles the OpenAPI documents.
    testTimeout: 60_000,
    hookTimeout: 60_000,
    allowOnly: false,
  },
});
