import * as Cause from "effect/Cause";
import type { YieldableError } from "effect/Cause";
import * as Data from "effect/Data";
import * as Effect from "effect/Effect";
import * as Result from "effect/Result";
import { gnapErrorBody, type GnapErrorCode } from "../error-response";
import { utf8Decode } from "../../internal/bytes";
import { announcesMoreThan, readCapped } from "../../internal/http";
import type { Core } from "./core";

interface GnapRouteErrorFields {
  readonly status: number;
  readonly code: GnapErrorCode;
  readonly description: string;
}

// Explicit annotation: `isolatedDeclarations` forbids a call expression in an `extends` clause.
const Base: new (fields: GnapRouteErrorFields) => YieldableError & {
  readonly _tag: "GnapRouteError";
} & Readonly<GnapRouteErrorFields> = Data.TaggedError("GnapRouteError")<GnapRouteErrorFields>;

/** A failure the server answers as `{ error: { code, description } }` with `status`, as Rafiki's auth server does. */
export class GnapRouteError extends Base {}

export const fail = (status: number, code: GnapErrorCode, description: string): Effect.Effect<never, GnapRouteError> =>
  Effect.fail(new GnapRouteError({ status, code, description }));

const errorResponse = ({ status, code, description }: GnapRouteErrorFields): Response =>
  Response.json(gnapErrorBody(code, description), { status });

/** Tells `config.onError` (whose own failure never reaches the client). */
const report = (core: Core, cause: Cause.Cause<never>): Effect.Effect<void> =>
  Effect.suspend(() => core.config.onError?.(cause) ?? Effect.void).pipe(Effect.ignoreCause);

/**
 * Turns a handler's failures into responses: route errors as themselves, anything unexpected as `500`. Every `500`,
 * the server's own as well as a defect, is told to `config.onError` first.
 */
export const respond = (core: Core, program: Effect.Effect<Response, GnapRouteError>): Effect.Effect<Response> =>
  program.pipe(
    Effect.catch((error) =>
      (error.status >= 500 ? report(core, Cause.die(error)) : Effect.void).pipe(Effect.as(errorResponse(error))),
    ),
    Effect.catchCauseIf(Cause.hasDies, (cause) =>
      report(core, cause).pipe(
        Effect.as(errorResponse({ status: 500, code: "request_denied", description: "internal server error" })),
      ),
    ),
    // RFC 9635 §3 requires `no-store` on grant responses; every response of this server carries it, which is stricter.
    Effect.tap((response) => Effect.sync(() => response.headers.set("cache-control", "no-store"))),
  );

export const noContent = (): Response => new Response(null, { status: 204 });

export const redirect = (location: string, headers: Record<string, string> = {}): Response =>
  new Response(null, { status: 302, headers: { location, ...headers } });

/** The request body, or `413 invalid_request` when it is longer than `maxBytes`. */
export const readBody = (
  request: Pick<Request, "headers" | "body">,
  maxBytes: number,
): Effect.Effect<Uint8Array<ArrayBuffer>, GnapRouteError> =>
  Effect.gen(function* () {
    const bytes = announcesMoreThan(request.headers, maxBytes)
      ? null
      : yield* Effect.tryPromise({
          try: (signal) => readCapped(request.body, maxBytes, signal),
          // A body that cannot be read (the client went away mid-request) is the client's failure, not a crash.
          catch: () =>
            new GnapRouteError({ status: 400, code: "invalid_request", description: "request body could not be read" }),
        });

    if (bytes === null) return yield* fail(413, "invalid_request", "request body too large");

    // RFC 9635 §2: a request body is JSON; empty bodies (poll, rotate, DELETE) carry no media type.
    const mediaType = request.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase();

    if (bytes.byteLength > 0 && mediaType !== "application/json") {
      return yield* fail(400, "invalid_request", "content-type must be application/json");
    }

    return bytes;
  });

/** The text of `bytes`, or `400 invalid_request` when they are not UTF-8. */
export const utf8Text = (bytes: Uint8Array): Effect.Effect<string, GnapRouteError> =>
  Effect.try({
    try: () => utf8Decode(bytes),
    catch: () => new GnapRouteError({ status: 400, code: "invalid_request", description: "invalid request" }),
  });

/** Decodes JSON `bytes` with `decode` or fails with `400 invalid_request`. */
export const decodeJson = <A>(
  decode: (input: string) => Result.Result<A, unknown>,
  bytes: Uint8Array,
): Effect.Effect<A, GnapRouteError> =>
  Effect.flatMap(utf8Text(bytes), (text) => {
    const result = decode(text);

    return Result.isSuccess(result) ? Effect.succeed(result.success) : fail(400, "invalid_request", "invalid request");
  });

/** A handler of a route without parameters. Never fails: errors are responses. */
export type RequestHandler = (request: Request) => Effect.Effect<Response>;

/** A handler of a route with path parameters `P`. */
export type ParamHandler<P> = (request: Request, params: P) => Effect.Effect<Response>;
