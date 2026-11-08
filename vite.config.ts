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
      "plain/ilp": "src/plain/ilp.ts",
      "plain/ildcp": "src/plain/ildcp.ts",
      "plain/http-signatures": "src/plain/http-signatures.ts",
      "plain/open-payments": "src/plain/open-payments.ts",
      "plain/stream": "src/plain/stream.ts",
      "plain/webhooks": "src/plain/webhooks.ts",
      "plain/gnap": "src/plain/gnap.ts",
      "plain/gnap/server": "src/plain/gnap-server.ts",
      "plain/gnap/server/testing": "src/plain/gnap-server-testing.ts",
      "plain/better-auth": "src/plain/better-auth.ts",
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
