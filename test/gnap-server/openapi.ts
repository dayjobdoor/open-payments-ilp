// oxlint-disable anti-slop/no-unsafe-dictionary-type -- Models the untyped @interledger/openapi document.
/**
 * Response validation against the published OpenAPI documents (openapi/): auth-server.yaml,
 * id-provider.yaml and token-introspection.yaml, with the validators of `@interledger/openapi` (the ones the
 * reference client and Rafiki use).
 */
import { createRequire } from "node:module";
import { resolve } from "node:path";

type Validator = (response: { status: number; body: unknown }) => true;

interface OpenApiDocument {
  paths: Record<string, Record<string, unknown>>;
  createResponseValidator: (options: { path: string; method: string }) => Validator;
}

const requireFromUpstream = createRequire(createRequire(import.meta.url).resolve("@interledger/open-payments"));

// SAFETY: @interledger/openapi is untyped from here; this is the surface used.
const { createOpenAPI } = requireFromUpstream("@interledger/openapi") as {
  createOpenAPI: (path: string) => Promise<OpenApiDocument>;
};

const specPath = (name: string): string => resolve(import.meta.dirname, "../../openapi", `${name}.yaml`);

const SPECS = ["auth-server", "id-provider", "token-introspection"] as const;

interface Operation {
  readonly method: string;
  readonly template: string;
  readonly pattern: RegExp;
  readonly validate: Validator;
}

const operations = (async (): Promise<Operation[]> => {
  const found: Operation[] = [];

  for (const name of SPECS) {
    const document = await createOpenAPI(specPath(name));

    for (const [template, item] of Object.entries(document.paths)) {
      for (const method of Object.keys(item).filter((key) => ["get", "post", "delete"].includes(key))) {
        // token-introspection.yaml documents `POST /` on its own server; the single-mount server answers `/introspect`.
        const mounted = name === "token-introspection" ? "/introspect" : template;

        found.push({
          method: method.toUpperCase(),
          template,
          pattern: new RegExp(`^${mounted.replace(/\{[^}]+\}/g, "[^/]+")}/?$`),
          validate: document.createResponseValidator({ path: template, method }),
        });
      }
    }
  }

  return found;
})();

/**
 * Throws when `response` (to `request`, whose path is `relativePath` below the server's base path) violates the
 * OpenAPI operation it answers. Requests no operation describes are not validated.
 */
export const expectConformsToSpec = async (
  request: Request,
  relativePath: string,
  response: Response,
): Promise<void> => {
  // `POST /` is documented twice (grant request, introspection); the path decides.
  const operation = (await operations).find(
    (candidate) => candidate.method === request.method && candidate.pattern.test(relativePath || "/"),
  );

  if (operation === undefined) return;
  const text = await response.text();
  const json = response.headers.get("content-type")?.includes("json") === true;

  try {
    operation.validate({ status: response.status, body: json ? JSON.parse(text) : text === "" ? null : text });
  } catch (error) {
    throw new Error(
      `${request.method} ${relativePath} -> ${response.status} violates ${operation.template}: ${JSON.stringify(error)} ${text}`,
    );
  }
};
