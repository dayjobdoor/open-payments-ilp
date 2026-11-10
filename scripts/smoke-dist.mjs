// Smoke test of the built package (run `vp pack` first; plain Node ESM, no dependencies):
//   node scripts/smoke-dist.mjs
//
// 1. Installs dist + package.json next to a symlink to `effect` only and imports every `exports` entry in a fresh
//    Node process: entries without optional peers must load and expose their named exports; `/better-auth`, `/hono`
//    and `/plain/better-auth` must fail with nothing but a clean "Cannot find package" for their own peer. Then one
//    real call per plain entry runs against the packed code, so a wrapper wired to the wrong function fails here.
// 2. With the peers present, imports `/better-auth`, `/hono` and `/plain/better-auth` for real (they must load and
//    expose their named exports), then type-checks a consumer file against the built declarations (the
//    `declare module "hono"` augmentation must survive declaration bundling, and one typed call per plain entry must
//    resolve to a plain value, not a Result, an Effect or `never`). Any tsc error line outside the peers' own
//    declarations fails.
import { execFileSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, parse } from "node:path";
import { fileURLToPath } from "node:url";

const packageDir = join(dirname(fileURLToPath(import.meta.url)), "..");

const manifest = JSON.parse(readFileSync(join(packageDir, "package.json"), "utf8"));

if (!existsSync(join(packageDir, "dist"))) throw new Error("dist/ is missing: run `vp pack` in the package first");

/** Names each entry must export; `peer` marks the entries that need an optional peer dependency to load. */
const expected = {
  "./ilp": { names: ["serializePrepare", "deserializePrepare"] },
  "./ildcp": { names: ["serveIldcp"] },
  "./stream": { names: ["buildStreamPrepare", "createStreamReply"] },
  "./http-signatures": { names: ["signRequest", "verifyRequest", "generateEd25519KeyPair"] },
  "./open-payments": { names: ["addAmounts", "createUnauthenticatedClient"] },
  "./gnap": { names: ["computeInteractionHash", "verifyInteractionHash"] },
  "./gnap/server": { names: ["createGnapServer", "memoryGnapStore"] },
  "./gnap/server/testing": { names: ["storeContract"] },
  "./webhooks": { names: ["signWebhook", "verifyWebhookSignature"] },
  "./better-auth/client": { names: ["gnapClient"] },
  "./better-auth": { names: ["gnap", "betterAuthGnapStore"], peer: "better-auth" },
  "./hono": { names: ["gnapAuthMiddleware", "getGnapAuth"], peer: "hono" },
  "./plain/ilp": { names: ["serializeIlpPrepare", "deserializeIlpPrepare", "postPrepare"] },
  "./plain/ildcp": { names: ["fetchIldcp", "serveIldcp"] },
  "./plain/http-signatures": { names: ["signRequest", "verifyRequest", "importPrivateKey"] },
  "./plain/open-payments": {
    names: ["createAuthenticatedClient", "createUnauthenticatedClient", "addAmounts"],
  },
  "./plain/stream": {
    names: ["buildStreamPrepare", "createStreamReply", "generateStreamCredentials"],
  },
  "./plain/webhooks": { names: ["signWebhook", "verifyWebhookSignature"] },
  "./plain/gnap": { names: ["computeInteractionHash", "verifyInteractionHash", "hashToken"] },
  "./plain/gnap/server": { names: ["createGnapServer", "memoryGnapStore", "fetchClientKeys"] },
  "./plain/gnap/server/testing": { names: ["storeContract"] },
  "./plain/better-auth": { names: ["gnap", "betterAuthGnapStore"], peer: "better-auth" },
};

const entries = Object.keys(manifest.exports).filter((key) => key !== "./package.json");

const untracked = entries.filter((key) => !(key in expected));

if (untracked.length > 0) throw new Error(`add the new exports entries to smoke-dist.mjs: ${untracked.join(", ")}`);

/** Directory of a dependency installed in this workspace: the nearest `node_modules/<name>` above the package. */
function installed(name) {
  for (let dir = packageDir; dir !== parse(dir).root; dir = dirname(dir)) {
    if (existsSync(join(dir, "node_modules", name, "package.json")))
      return realpathSync(join(dir, "node_modules", name));
  }

  throw new Error(`${name} is not installed: run \`bun install\``);
}

const root = mkdtempSync(join(tmpdir(), "open-payments-ilp-smoke-"));

const failures = [];

/** A project with the built package and the given dependencies (symlinks) in its node_modules. */
function project(name, dependencies) {
  const dir = join(root, name);
  const modules = join(dir, "node_modules");

  mkdirSync(join(modules, "open-payments-ilp"), { recursive: true });
  cpSync(join(packageDir, "dist"), join(modules, "open-payments-ilp", "dist"), { recursive: true });
  cpSync(join(packageDir, "package.json"), join(modules, "open-payments-ilp", "package.json"));
  writeFileSync(join(dir, "package.json"), JSON.stringify({ type: "module" }));

  for (const dependency of dependencies) symlinkSync(installed(dependency), join(modules, dependency), "dir");

  return dir;
}

try {
  // 1. Runtime: only `effect` is installed, so hono and better-auth are absent.
  const bare = project("bare", ["effect"]);

  const probe = `
    const result = {};
    for (const entry of ${JSON.stringify(entries)}) {
      try {
        const module = await import("open-payments-ilp" + entry.slice(1));
        result[entry] = { names: Object.keys(module) };
      } catch (error) {
        result[entry] = { code: error.code, message: String(error.message).split("\\n")[0] };
      }
    }
    console.log(JSON.stringify(result));
  `;

  const imported = JSON.parse(
    execFileSync(process.execPath, ["--input-type=module", "-e", probe], { cwd: bare, encoding: "utf8" }),
  );

  for (const entry of entries) {
    const { names, peer } = expected[entry];
    const got = imported[entry];

    if (peer === undefined) {
      const missing = got.names === undefined ? names : names.filter((name) => !got.names.includes(name));

      if (missing.length > 0) failures.push(`${entry}: ${got.message ?? `missing exports ${missing.join(", ")}`}`);
      else console.log(`ok   ${entry}: loads with effect only (${got.names.length} exports)`);
    } else if (
      got.code === "ERR_MODULE_NOT_FOUND" &&
      new RegExp(`Cannot find package '${peer}(/|')`).test(got.message)
    ) {
      console.log(`ok   ${entry}: without ${peer} fails cleanly (${got.message})`);
    } else {
      failures.push(`${entry}: expected "Cannot find package '${peer}'" without ${peer}, got ${JSON.stringify(got)}`);
    }
  }

  // Runtime: a real call per plain entry, so a wrapper that is wired to the wrong function fails after packing.
  const calls = `
    const check = (condition, message) => {
      if (!condition) throw new Error(message);
    };
    const thrown = (run) => {
      try {
        run();
      } catch (error) {
        return error;
      }
    };
    const same = (a, b) => JSON.stringify(a, (_, v) => (typeof v === "bigint" ? String(v) : v)) === JSON.stringify(b, (_, v) => (typeof v === "bigint" ? String(v) : v));

    const ilp = await import("open-payments-ilp/plain/ilp");
    const wire = ilp.serializePrepare({
      amount: 1n,
      expiresAt: new Date("2030-01-01T00:00:00Z"),
      executionCondition: new Uint8Array(32),
      destination: "g.alice",
      data: new Uint8Array(0),
    });
    check(wire instanceof Uint8Array, "plain/ilp serializePrepare returns bytes");
    check(ilp.deserializePrepare(wire).destination === "g.alice", "plain/ilp deserializePrepare returns the Prepare");
    check(thrown(() => ilp.deserializePrepare(new Uint8Array(2)))?._tag === "IlpCodecError", "plain/ilp throws IlpCodecError");
    check(ilp.isReject(ilp.deserializeReply(ilp.serializeReject({ code: "F99", triggeredBy: "g.a", message: "", data: new Uint8Array(0) }))), "plain/ilp reply");

    const ildcp = await import("open-payments-ilp/plain/ildcp");
    const response = { clientAddress: "g.hub.alice", assetScale: 2, assetCode: "USD" };
    const now = new Date("2030-01-01T00:00:00Z");
    const fetched = await ildcp.fetchIldcp(
      (prepare) => ilp.serializeReply(ildcp.serveIldcp({ requestPacket: prepare, serverAddress: "g.hub", response, now })),
      { clock: () => now },
    );
    check(same(fetched, response), "plain/ildcp fetchIldcp returns the response");

    const signatures = await import("open-payments-ilp/plain/http-signatures");
    const { privateKey, publicJwk } = await signatures.generateEd25519KeyPair();
    const signed = await signatures.signRequest(
      new Request("https://rs.test/x", { method: "POST", headers: { "content-type": "application/json", authorization: "GNAP t" }, body: "{}" }),
      { keyId: "k1", privateKey },
    );
    const verified = await signatures.verifyRequest(signed, {
      requiredComponents: ["@method", "@target-uri", "authorization"],
      resolveKey: async (keyId) => (keyId === "k1" ? publicJwk : null),
    });
    check(verified.keyId === "k1", "plain/http-signatures signs and verifies");
    check(signatures.parseDictionary("a=1")[0][0] === "a", "plain/http-signatures parseDictionary returns the entries");
    check(typeof signatures.serializeItem({ value: { type: "integer", value: 1 }, params: [] }) === "string", "plain/http-signatures serializeItem returns a string");
    check((await signatures.importPrivateKey(privateKey)) === privateKey, "plain/http-signatures importPrivateKey");
    check((await signatures.importPrivateKey(await crypto.subtle.exportKey("jwk", privateKey))).type === "private", "plain/http-signatures importPrivateKey(jwk)");

    const payments = await import("open-payments-ilp/plain/open-payments");
    const amount = { value: "5", assetCode: "USD", assetScale: 2 };
    check(payments.parseAmountValue("12") === 12n, "plain/open-payments parseAmountValue returns the bigint");
    check(payments.compareAmounts(amount, amount) === 0, "plain/open-payments compareAmounts returns the number");
    check(payments.addAmounts(amount, amount).value === "10", "plain/open-payments addAmounts returns the amount");
    check(thrown(() => payments.parseAmountValue("x"))?._tag === "OpenPaymentsError", "plain/open-payments throws OpenPaymentsError");
    check(typeof (await payments.createUnauthenticatedClient()).walletAddress.get === "function", "plain/open-payments client");

    const stream = await import("open-payments-ilp/plain/stream");
    const keys = await stream.deriveStreamKeys(new Uint8Array(32).fill(1));
    const sealed = await stream.encryptStreamData(keys.encryptionKey, new Uint8Array([1, 2, 3]));
    check(same([...(await stream.decryptStreamData(keys.encryptionKey, sealed))], [1, 2, 3]), "plain/stream encrypts and decrypts");
    check((await stream.generateStreamFulfillment(keys.fulfillmentKey, sealed)).length === 32, "plain/stream generateStreamFulfillment");
    check(thrown(() => stream.decodeStreamReceipt(new Uint8Array(3)))?._tag === "IlpCodecError", "plain/stream throws IlpCodecError");

    const webhooks = await import("open-payments-ilp/plain/webhooks");
    check(webhooks.canonicalizeJson({ b: 1, a: 2 }) === '{"a":2,"b":1}', "plain/webhooks canonicalizeJson returns the string");
    const header = await webhooks.signWebhook({ a: 1 }, { secret: "s" });
    check((await webhooks.isValidWebhookSignature({ a: 1 }, header, { secret: "s" })) === true, "plain/webhooks signs and verifies");
    check((await webhooks.isValidWebhookSignature({ a: 2 }, header, { secret: "s" })) === false, "plain/webhooks isValidWebhookSignature resolves false");

    const gnap = await import("open-payments-ilp/plain/gnap");
    check(typeof (await gnap.hashToken("token")) === "string", "plain/gnap hashToken resolves a string");

    const gnapServer = await import("open-payments-ilp/plain/gnap/server");
    const store = gnapServer.memoryGnapStore();
    check((await store.claimNonce("k", 2000, 1000)) === true, "plain/gnap/server store is a Promise port");
    const server = gnapServer.createGnapServer({ baseUrl: "https://as.test/gnap", store, idpSecret: "s" });
    check((await server.introspectToken("unknown")).active === false, "plain/gnap/server introspectToken");
    check(typeof (await import("open-payments-ilp/plain/gnap/server/testing")).storeContract === "function", "plain/gnap/server/testing");

    console.log("ok");
  `;

  try {
    execFileSync(process.execPath, ["--input-type=module", "-e", calls], {
      cwd: bare,
      encoding: "utf8",
      stdio: "pipe",
    });
    console.log("ok   plain entries: a real call per entry returns plain values");
  } catch (error) {
    failures.push(
      `plain entry calls: ${String(error.stderr ?? error.message)
        .split("\n")
        .slice(0, 8)
        .join("\n")}`,
    );
  }

  // 2. With the optional peers present: the entries that need them load from the packed code and expose their names.
  const typed = project("typed", ["effect", "hono", "better-auth"]);
  const peerEntries = entries.filter((entry) => expected[entry].peer !== undefined);

  const peerProbe = `
    const result = {};
    for (const entry of ${JSON.stringify(peerEntries)}) {
      try {
        result[entry] = { names: Object.keys(await import("open-payments-ilp" + entry.slice(1))) };
      } catch (error) {
        result[entry] = { message: String(error.stack ?? error.message).split("\\n").slice(0, 3).join(" | ") };
      }
    }
    console.log(JSON.stringify(result));
  `;

  const withPeers = JSON.parse(
    execFileSync(process.execPath, ["--input-type=module", "-e", peerProbe], { cwd: typed, encoding: "utf8" }),
  );

  for (const entry of peerEntries) {
    const { names, peer } = expected[entry];
    const got = withPeers[entry];
    const missing = got.names === undefined ? names : names.filter((name) => !got.names.includes(name));

    if (missing.length > 0)
      failures.push(`${entry}: with ${peer} installed, ${got.message ?? `missing exports ${missing.join(", ")}`}`);
    else console.log(`ok   ${entry}: loads with ${peer} installed (${got.names.length} exports)`);
  }

  // 3. Types: a consumer with the optional peers present, against the built declarations.
  writeFileSync(
    join(typed, "consumer.ts"),
    [
      'import { Hono } from "hono";',
      'import { gnapAuthMiddleware, type GnapAuthRefreshErrorHook } from "open-payments-ilp/hono";',
      ...entries.map((entry, index) => `import * as entry${index} from "open-payments-ilp${entry.slice(1)}";`),
      'import * as plainGnap from "open-payments-ilp/plain/gnap";',
      'import * as plainGnapServer from "open-payments-ilp/plain/gnap/server";',
      'import * as plainHttpSignatures from "open-payments-ilp/plain/http-signatures";',
      'import * as plainIldcp from "open-payments-ilp/plain/ildcp";',
      'import * as plainIlp from "open-payments-ilp/plain/ilp";',
      'import * as plainOpenPayments from "open-payments-ilp/plain/open-payments";',
      'import * as plainStream from "open-payments-ilp/plain/stream";',
      'import * as plainWebhooks from "open-payments-ilp/plain/webhooks";',
      "",
      `export const entries = [${entries.map((_, index) => `entry${index}`).join(", ")}];`,
      "",
      "// One typed call per plain entry: a wrapper that returns a Result, an Effect or `never` fails to compile here.",
      "type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;",
      "const expectType = <_ extends true>(): void => {};",
      "expectType<Equal<ReturnType<typeof plainIlp.serializePrepare>, Uint8Array<ArrayBuffer>>>();",
      "expectType<Equal<ReturnType<typeof plainIlp.deserializePrepare>, plainIlp.IlpPrepare>>();",
      "expectType<Equal<ReturnType<typeof plainIldcp.fetchIldcp>, Promise<plainIldcp.IldcpResponse>>>();",
      "expectType<Equal<ReturnType<typeof plainIldcp.deserializeIldcpResponse>, plainIldcp.IldcpResponse>>();",
      "expectType<Equal<ReturnType<typeof plainHttpSignatures.createSignatureBase>, string>>();",
      "expectType<Equal<ReturnType<typeof plainHttpSignatures.serializeItem>, string>>();",
      "expectType<Equal<ReturnType<typeof plainHttpSignatures.parseDictionary>, plainHttpSignatures.SfDictionary>>();",
      "expectType<Equal<ReturnType<typeof plainHttpSignatures.signRequest>, Promise<Request>>>();",
      "expectType<Equal<ReturnType<typeof plainOpenPayments.parseAmountValue>, bigint>>();",
      "expectType<Equal<ReturnType<typeof plainOpenPayments.compareAmounts>, -1 | 0 | 1>>();",
      "expectType<Equal<ReturnType<typeof plainOpenPayments.addAmounts>, plainOpenPayments.Amount>>();",
      "expectType<Equal<ReturnType<typeof plainOpenPayments.createUnauthenticatedClient>, Promise<plainOpenPayments.UnauthenticatedClient>>>();",
      'expectType<Equal<ReturnType<plainOpenPayments.AuthenticatedClient["quote"]["get"]>, Promise<plainOpenPayments.Quote>>>();',
      "expectType<Equal<ReturnType<typeof plainStream.deriveStreamKeys>, Promise<plainStream.StreamKeys>>>();",
      "expectType<Equal<ReturnType<typeof plainStream.decodeStreamReceipt>, plainStream.StreamReceipt>>();",
      "expectType<Equal<ReturnType<typeof plainWebhooks.canonicalizeJson>, string>>();",
      "expectType<Equal<ReturnType<typeof plainWebhooks.signWebhook>, Promise<string>>>();",
      "expectType<Equal<ReturnType<typeof plainGnap.hashToken>, Promise<string>>>();",
      "expectType<Equal<ReturnType<typeof plainGnapServer.memoryGnapStore>, plainGnapServer.GnapStore>>();",
      'expectType<Equal<ReturnType<plainGnapServer.GnapStore["claimNonce"]>, Promise<boolean>>>();',
      'expectType<Equal<ReturnType<ReturnType<typeof plainGnapServer.createGnapServer>["route"]>, Promise<Response>>>();',
      "",
      "const hook: GnapAuthRefreshErrorHook = (error) => {",
      "  console.warn(error.status, error.code);",
      "};",
      "",
      "const app = new Hono();",
      "",
      'app.use("*", async (c, next) => {',
      '  c.set("gnapAuthRefreshErrorHook", hook);',
      "  // @ts-expect-error the augmentation types the hook: a number is refused",
      '  c.set("gnapAuthRefreshErrorHook", 1);',
      "  await next();",
      "});",
      "",
      'app.use("*", gnapAuthMiddleware());',
      "",
    ].join("\n"),
  );

  writeFileSync(
    join(typed, "tsconfig.json"),
    JSON.stringify({
      compilerOptions: {
        target: "ES2023",
        lib: ["ES2023", "DOM", "DOM.Iterable"],
        module: "NodeNext",
        moduleResolution: "NodeNext",
        types: [],
        strict: true,
        noEmit: true,
        skipLibCheck: false,
      },
      files: ["consumer.ts"],
    }),
  );

  try {
    execFileSync(process.execPath, [join(installed("typescript"), "bin", "tsc"), "-p", "tsconfig.json"], {
      cwd: typed,
      encoding: "utf8",
      stdio: "pipe",
    });
    console.log("ok   consumer type-checks against dist (hono augmentation, plain calls, every entry)");
  } catch (error) {
    // Only errors inside the declarations of the peers themselves are tolerated (they need Node and DOM types the
    // consumer does not load). Any other output line (consumer.ts, our dist, a tsconfig or tsc failure) fails.
    const isPeerDeclarationError = (line) =>
      /^\S*node_modules\/(?!open-payments-ilp\/)\S*\(\d+,\d+\): error TS\d+/.test(line);
    const unexpected = String(error.stdout ?? "")
      .concat(error.stdout === undefined || error.stdout === "" ? `${error.message}\n${error.stderr ?? ""}` : "")
      .split("\n")
      .filter((line) => line.trim() !== "" && !/^\s/.test(line) && !isPeerDeclarationError(line));

    if (unexpected.length > 0) failures.push(`consumer type check:\n${unexpected.join("\n")}`);
    else console.log("ok   consumer type-checks against dist (hono augmentation, plain calls, every entry)");
  }
} finally {
  rmSync(root, { recursive: true, force: true });
}

if (failures.length > 0) {
  console.error(`\n${failures.length} smoke failure(s):\n${failures.map((failure) => `- ${failure}`).join("\n")}`);
  process.exit(1);
}

console.log("\nsmoke-dist: all good");
