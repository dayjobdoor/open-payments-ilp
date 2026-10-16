/**
 * In-process fake of the three Open Payments servers. Success responses are the examples published in the
 * OpenAPI documents (openapi/), so the fixtures cannot drift from the spec the types are generated from.
 * Requests that need authorisation must carry a valid RFC 9421 signature (verified with the package's own
 * `verifyRequest`) and a GNAP Authorization header, mirroring what a real resource/auth server enforces.
 */
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import * as Effect from "effect/Effect";
import { HttpSignatureError, verifyRequest } from "../../src/http-signatures/index";
import type { JsonValue } from "../../src/webhooks/index";

interface OpenApiOperation {
  responses?: Record<
    string,
    { content?: { "application/json"?: { examples?: Record<string, { value: JsonValue }>; example?: JsonValue } } }
  >;
}

interface OpenApiDocument {
  paths: Record<string, Record<string, OpenApiOperation>>;
}

const requireFromUpstream = createRequire(createRequire(import.meta.url).resolve("@interledger/open-payments"));

// SAFETY: @interledger/openapi is untyped from here; this is the surface used (createOpenAPI dereferences the spec).
const { createOpenAPI } = requireFromUpstream("@interledger/openapi") as {
  createOpenAPI: (path: string) => Promise<OpenApiDocument>;
};

const specPath = (name: string): string => resolve(import.meta.dirname, "../../openapi", `${name}.yaml`);

/** Which spec answers under which path prefix of the fake origin. */
const MOUNTS = [
  { prefix: "/alice", spec: "wallet-address-server" },
  { prefix: "/rs", spec: "resource-server" },
  { prefix: "/as", spec: "auth-server" },
] as const;

export interface RecordedRequest {
  readonly method: string;
  readonly url: string;
  readonly headers: Headers;
  readonly body: string;
  /** Key id of the verified signature, when the request was signed. */
  readonly signedBy: string | undefined;
}

export interface FakeServer {
  /** Handles a request in-process (use as the client's `fetch`). */
  readonly handle: (request: Request) => Promise<Response>;
  readonly requests: RecordedRequest[];
  /** Queues a replacement response for the next request to `METHOD path-template` (e.g. `POST /rs/incoming-payments`). */
  readonly respondOnce: (route: string, response: Response) => void;
  /** The example value the fake serves for `METHOD path-template`. */
  readonly example: (route: string) => JsonValue | undefined;
}

interface Route {
  readonly method: string;
  readonly template: string;
  readonly pattern: RegExp;
  readonly status: number;
  readonly body: JsonValue | undefined;
  readonly needsAuth: boolean;
}

function firstExample(operation: OpenApiOperation): { status: number; body: JsonValue | undefined } | undefined {
  const success = Object.keys(operation.responses ?? {})
    .filter((status) => status.startsWith("2"))
    .sort();

  const status = success[0];

  if (status === undefined) return undefined;
  const json = operation.responses?.[status]?.content?.["application/json"];
  const body = json?.example ?? (json?.examples ? Object.values(json.examples)[0]?.value : undefined);

  return { status: Number(status), body };
}

async function loadRoutes(): Promise<Route[]> {
  const routes: Route[] = [];

  for (const { prefix, spec } of MOUNTS) {
    const document = await createOpenAPI(specPath(spec));

    for (const [template, item] of Object.entries(document.paths)) {
      for (const [method, operation] of Object.entries(item)) {
        const example = firstExample(operation);

        if (!example || !["get", "post", "delete"].includes(method)) continue;
        const full = template === "/" ? prefix : `${prefix}${template}`;

        routes.push({
          method: method.toUpperCase(),
          template: full,
          pattern: new RegExp(`^${full.replace(/\{[^}]+\}/g, "[^/]+")}$`),
          status: example.status,
          body: example.body,
          needsAuth: spec !== "wallet-address-server",
        });
      }
    }
  }

  return routes;
}

/** The specs are dereferenced once per process: a fresh fake server per test is then cheap. */
let routesLoading: Promise<Route[]> | undefined;

const json = (status: number, body: JsonValue | undefined): Response =>
  body === undefined
    ? new Response(null, { status })
    : new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

const problem = (status: number, code: string, description: string): Response =>
  json(status, { error: { code, description } });

/**
 * @param keys public JWKs by `kid`, used to verify request signatures.
 */
export async function createFakeServer(keys: Readonly<Record<string, JsonWebKey>>): Promise<FakeServer> {
  const routes = await (routesLoading ??= loadRoutes());
  const requests: RecordedRequest[] = [];
  const overrides = new Map<string, Response[]>();

  const handle = async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    const pathname = url.pathname.replace(/\/$/, "") || "/";
    const route = routes.find((candidate) => candidate.method === request.method && candidate.pattern.test(pathname));
    const body = await request.clone().text();
    const needsSignature = request.method === "POST" || request.headers.has("authorization");
    let signedBy: string | undefined;

    if (route?.needsAuth && needsSignature) {
      const verified = await Effect.runPromise(
        verifyRequest(request.clone(), {
          resolveKey: (keyId) => {
            const key = keys[keyId];

            return key
              ? Effect.succeed(key)
              : Effect.fail(new HttpSignatureError({ reason: "unknown-key", message: keyId }));
          },
        }).pipe(Effect.result),
      );

      if (verified._tag === "Failure") {
        requests.push({ method: request.method, url: request.url, headers: request.headers, body, signedBy });

        return problem(401, "invalid_client", `bad signature: ${verified.failure.message}`);
      }

      signedBy = verified.success.keyId;
    }

    requests.push({ method: request.method, url: request.url, headers: request.headers, body, signedBy });

    if (pathname === "/alice/jwks.json" && request.method === "GET") {
      return json(200, {
        keys: Object.entries(keys).map(([kid, jwk]) => ({
          kid,
          alg: "EdDSA",
          use: "sig",
          kty: jwk.kty ?? "OKP",
          crv: jwk.crv ?? "Ed25519",
          x: jwk.x ?? "",
        })),
      });
    }

    if (pathname === "/alice/did.json" && request.method === "GET") {
      return json(200, { "@context": ["https://www.w3.org/ns/did/v1"], id: "did:web:127.0.0.1:alice" });
    }

    if (!route) return problem(404, "not_found", `no route for ${request.method} ${pathname}`);
    const override = overrides.get(`${route.method} ${route.template}`)?.shift();

    if (override) return override;

    return json(route.status, route.body);
  };

  return {
    handle,
    requests,
    respondOnce: (route, response) => void overrides.set(route, [...(overrides.get(route) ?? []), response]),
    example: (route) => routes.find((candidate) => `${candidate.method} ${candidate.template}` === route)?.body,
  };
}

/** Serves `handle` on 127.0.0.1 (random port) for clients that cannot take an injected `fetch`. */
export async function listen(handle: (request: Request) => Promise<Response>): Promise<{
  readonly origin: string;
  readonly close: () => Promise<void>;
}> {
  const server: Server = createServer((incoming, outgoing) => {
    const chunks: Buffer[] = [];

    incoming.on("data", (chunk: Buffer) => chunks.push(chunk));
    incoming.on("end", () => {
      const headers = new Headers();

      for (const [name, value] of Object.entries(incoming.headers)) {
        if (value !== undefined) headers.set(name, Array.isArray(value) ? value.join(", ") : value);
      }

      const hasBody = incoming.method !== "GET" && incoming.method !== "HEAD" && chunks.length > 0;

      const request = new Request(`http://${incoming.headers.host}${incoming.url}`, {
        method: incoming.method ?? "GET",
        headers,
        ...(hasBody && { body: Buffer.concat(chunks) }),
      });

      void handle(request).then(async (response) => {
        outgoing.writeHead(response.status, Object.fromEntries(response.headers));
        outgoing.end(Buffer.from(await response.arrayBuffer()));
      });
    });
  });

  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  // SAFETY: the server listens on a TCP port, so `address()` is an AddressInfo.
  const { port } = server.address() as AddressInfo;

  return {
    origin: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((done) => server.close(() => done())),
  };
}
