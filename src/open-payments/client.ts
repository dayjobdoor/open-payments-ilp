import * as Effect from "effect/Effect";
import * as Result from "effect/Result";
import * as Schema from "effect/Schema";
import { encodeBase64Url, utf8Encode } from "../internal/bytes";
import { bufferResponse } from "../internal/http";
import type { HttpSignatureError } from "../http-signatures/index";
import { signHeaders } from "../http-signatures/sign";
import {
  checkCompletedIncomingPayment,
  checkCreatedIncomingPayment,
  checkIncomingPayment,
  checkOutgoingPayment,
} from "./invariants";
import { OpenPaymentsError } from "./errors";
import { attemptLimit, isTransientStatus, mayRepeat, retryDelayMs, type RetryOptions } from "./retry";
import * as schemas from "./schemas";
import type {
  AccessToken,
  CreateIncomingPaymentArgs,
  CreateOutgoingPaymentArgs,
  CreateQuoteArgs,
  DIDDocument,
  Grant,
  GrantContinuation,
  GrantContinuationRequest,
  GrantRequest,
  IncomingPayment,
  IncomingPaymentPaginationResult,
  IncomingPaymentWithPaymentMethods,
  JWK,
  JWKS,
  OutgoingPayment,
  OutgoingPaymentGrantSpentAmounts,
  OutgoingPaymentPaginationResult,
  OutgoingPaymentWithSpentAmounts,
  PaginationArgs,
  PendingGrant,
  PublicIncomingPayment,
  Quote,
  WalletAddress,
} from "./types";

/** A resource addressed by its full URL, requested without credentials. */
export interface UnauthenticatedResourceRequestArgs {
  /** Full URL of the resource, e.g. `https://openpayments.dev/incoming-payments/08394f02-…`. */
  readonly url: string;
  /**
   * Repeat this request if it fails transiently, although it is a `POST`: overrides `retry.retryNonIdempotent`.
   * Only meaningful with `ClientOptions.retry`, and only for requests whose first attempt may have been processed.
   */
  readonly retryNonIdempotent?: boolean | undefined;
}

/** A resource requested with a GNAP access token. */
export interface ResourceRequestArgs extends UnauthenticatedResourceRequestArgs {
  /** Access token value obtained from a grant. */
  readonly accessToken: string;
}

/** Grant continuation / token management URL plus the token authorising it. */
export interface GrantOrTokenRequestArgs extends ResourceRequestArgs {}

/** A collection of a wallet address' resources. `url` is the resource server base URL. */
export interface CollectionRequestArgs extends ResourceRequestArgs {
  /** Wallet address URL whose resources are listed. */
  readonly walletAddress: string;
}

/** Options shared by both client flavours. */
export interface ClientOptions {
  /** `fetch` implementation. Defaults to the global `fetch`. */
  readonly fetch?: typeof globalThis.fetch;
  /** Rewrite every request URL to `http:` (development only). */
  readonly useHttp?: boolean;
  /** Abort a request after this many milliseconds. Defaults to 5000, like the reference client. */
  readonly requestTimeoutMs?: number;
  /** Fail a request whose response body is longer than this many bytes (announced or streamed). Defaults to 1 MiB. */
  readonly maxResponseBytes?: number;
  /** Time source for the `created` parameter of request signatures. Defaults to `new Date()`. */
  readonly clock?: () => Date;
  /**
   * Validate every response body against the Open Payments schemas (default `true`). When `false` the body is
   * returned as received; the payment invariants (asset matches, amounts) are still checked, as in the reference client.
   */
  readonly validateResponses?: boolean;
  /**
   * Opt-in retries with exponential backoff and jitter; see {@link RetryOptions} for the exact matrix. Default: none,
   * a failed request fails at once. Each attempt is signed anew.
   */
  readonly retry?: RetryOptions;
}

/** Options of {@link createAuthenticatedClient}. */
export interface AuthenticatedClientOptions extends ClientOptions {
  /** The wallet address that identifies this client in grant requests. */
  readonly walletAddressUrl: string;
  /** Identifier of the key, as published in the wallet address' JWKS. */
  readonly keyId: string;
  /**
   * Ed25519 private key used to sign requests; import it with `importEd25519PrivateKeyPem` or
   * `importEd25519PrivateJwk` from `open-payments-ilp/http-signatures`.
   */
  readonly privateKey: CryptoKey;
}

/** Request timeout when `requestTimeoutMs` is not given: the reference client's default. */
const DEFAULT_REQUEST_TIMEOUT_MS = 5000;

/** Response size limit when `maxResponseBytes` is not given: far above a page of 100 payments. */
const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;

type Decoder<T> = ReturnType<typeof Schema.decodeUnknownEffect<Schema.Codec<T>>>;

// Built once: compiling a schema's parser is several times the cost of running it.
const decode = {
  walletAddress: Schema.decodeUnknownEffect(schemas.walletAddress),
  jwks: Schema.decodeUnknownEffect(schemas.jwks),
  didDocument: Schema.decodeUnknownEffect(schemas.didDocument),
  publicIncomingPayment: Schema.decodeUnknownEffect(schemas.publicIncomingPayment),
  incomingPayment: Schema.decodeUnknownEffect(schemas.incomingPayment),
  incomingPaymentWithMethods: Schema.decodeUnknownEffect(schemas.incomingPaymentWithMethods),
  incomingPaymentPage: Schema.decodeUnknownEffect(schemas.incomingPaymentPage),
  outgoingPayment: Schema.decodeUnknownEffect(schemas.outgoingPayment),
  outgoingPaymentWithSpentAmounts: Schema.decodeUnknownEffect(schemas.outgoingPaymentWithSpentAmounts),
  outgoingPaymentPage: Schema.decodeUnknownEffect(schemas.outgoingPaymentPage),
  outgoingPaymentGrantSpentAmounts: Schema.decodeUnknownEffect(schemas.outgoingPaymentGrantSpentAmounts),
  quote: Schema.decodeUnknownEffect(schemas.quote),
  grantResponse: Schema.decodeUnknownEffect(Schema.Union([schemas.pendingGrant, schemas.grant])),
  grant: Schema.decodeUnknownEffect(schemas.grant),
  accessTokenResponse: Schema.decodeUnknownEffect(schemas.accessTokenResponse),
} as const;

type Result_<A> = Effect.Effect<A, OpenPaymentsError>;

/** Wallet address routes. */
export interface WalletAddressRoutes {
  /** `GET {url}` */
  readonly get: (args: UnauthenticatedResourceRequestArgs) => Result_<WalletAddress>;
  /** `GET {url}/jwks.json` */
  readonly getKeys: (args: UnauthenticatedResourceRequestArgs) => Result_<JWKS>;
  /** `GET {url}/did.json` */
  readonly getDIDDocument: (args: UnauthenticatedResourceRequestArgs) => Result_<DIDDocument>;
}

/** Incoming payment routes of the unauthenticated client. */
export interface UnauthenticatedIncomingPaymentRoutes {
  /** `GET {url}` without credentials: the public view. */
  readonly get: (args: UnauthenticatedResourceRequestArgs) => Result_<PublicIncomingPayment>;
}

/** Incoming payment routes of the authenticated client. */
export interface IncomingPaymentRoutes {
  /** `GET {url}` */
  readonly get: (args: ResourceRequestArgs) => Result_<IncomingPaymentWithPaymentMethods>;
  /** `GET {url}` without credentials: the public view. */
  readonly getPublic: (args: UnauthenticatedResourceRequestArgs) => Result_<PublicIncomingPayment>;
  /** `POST {url}/incoming-payments` */
  readonly create: (
    args: ResourceRequestArgs,
    createArgs: CreateIncomingPaymentArgs,
  ) => Result_<IncomingPaymentWithPaymentMethods>;
  /** `POST {url}/complete` */
  readonly complete: (args: ResourceRequestArgs) => Result_<IncomingPayment>;
  /** `GET {url}/incoming-payments?wallet-address=…` */
  readonly list: (args: CollectionRequestArgs, pagination?: PaginationArgs) => Result_<IncomingPaymentPaginationResult>;
}

/** Outgoing payment routes. */
export interface OutgoingPaymentRoutes {
  /** `GET {url}` */
  readonly get: (args: ResourceRequestArgs) => Result_<OutgoingPayment>;
  /** `GET {url}/outgoing-payments?wallet-address=…` */
  readonly list: (args: CollectionRequestArgs, pagination?: PaginationArgs) => Result_<OutgoingPaymentPaginationResult>;
  /** `POST {url}/outgoing-payments` */
  readonly create: (
    args: ResourceRequestArgs,
    createArgs: CreateOutgoingPaymentArgs,
  ) => Result_<OutgoingPaymentWithSpentAmounts>;
  /** `GET {url}/outgoing-payment-grant` */
  readonly getGrantSpentAmounts: (args: ResourceRequestArgs) => Result_<OutgoingPaymentGrantSpentAmounts>;
}

/** Quote routes. */
export interface QuoteRoutes {
  /** `GET {url}` */
  readonly get: (args: ResourceRequestArgs) => Result_<Quote>;
  /** `POST {url}/quotes` */
  readonly create: (args: ResourceRequestArgs, createArgs: CreateQuoteArgs) => Result_<Quote>;
}

/** Grant routes. */
export interface GrantRoutes {
  /**
   * `POST {url}`. `url` is the authorisation server root. The grant request's `client` is this client's wallet
   * address unless `clientOverride` supplies a JWK.
   */
  readonly request: (
    args: UnauthenticatedResourceRequestArgs,
    grantRequest: Omit<GrantRequest, "client">,
    clientOverride?: { readonly jwk: JWK },
  ) => Result_<PendingGrant | Grant>;
  /** `POST {url}` with the continue access token. */
  readonly continue: (
    args: GrantOrTokenRequestArgs,
    continuation?: GrantContinuationRequest,
  ) => Result_<Grant | GrantContinuation>;
  /** `DELETE {url}` with the continue access token. */
  readonly cancel: (args: GrantOrTokenRequestArgs) => Result_<void>;
}

/** Token routes. */
export interface TokenRoutes {
  /** `POST {url}` (the token's `manage` URL). */
  readonly rotate: (args: GrantOrTokenRequestArgs) => Result_<AccessToken>;
  /** `DELETE {url}` (the token's `manage` URL). */
  readonly revoke: (args: GrantOrTokenRequestArgs) => Result_<void>;
}

/** Client that can only read public fields. */
export interface UnauthenticatedClient {
  readonly walletAddress: WalletAddressRoutes;
  readonly incomingPayment: UnauthenticatedIncomingPaymentRoutes;
}

/** Client exposing every Open Payments API; requests needing authorisation are signed. */
export interface AuthenticatedClient {
  readonly walletAddress: WalletAddressRoutes;
  readonly incomingPayment: IncomingPaymentRoutes;
  readonly outgoingPayment: OutgoingPaymentRoutes;
  readonly grant: GrantRoutes;
  readonly token: TokenRoutes;
  readonly quote: QuoteRoutes;
}

interface Transport {
  readonly options: ClientOptions;
  readonly key: { readonly keyId: string; readonly privateKey: CryptoKey } | undefined;
}

interface Call {
  readonly method: "GET" | "POST" | "DELETE";
  readonly url: string;
  readonly accessToken?: string | undefined;
  readonly body?: object | undefined;
  readonly query?: Readonly<Record<string, string | number | undefined>> | undefined;
  readonly retryNonIdempotent?: boolean | undefined;
}

const transportError = (call: Call, cause: Error): OpenPaymentsError =>
  new OpenPaymentsError({
    reason: "transport",
    message: `Error making Open Payments ${call.method} request`,
    description: cause.message,
    cause,
  });

const signingError = (call: Call, cause: HttpSignatureError): OpenPaymentsError =>
  new OpenPaymentsError({
    reason: "signing",
    message: `Error signing Open Payments ${call.method} request`,
    description: cause.message,
    cause,
  });

const errorBody = Schema.Struct({
  error: Schema.Struct({
    code: Schema.optionalKey(Schema.String),
    description: Schema.optionalKey(Schema.String),
    details: Schema.optionalKey(Schema.Record(Schema.String, Schema.Json)),
  }),
});

const decodeErrorBody = Schema.decodeUnknownResult(Schema.fromJsonString(errorBody));

const decodeJsonObject = Schema.decodeUnknownResult(Schema.fromJsonString(Schema.Record(Schema.String, Schema.Json)));

/**
 * Builds the `http` error from a non-2xx response with the reference client's rules: `error.code`, `error.details`
 * and a non-empty `error.description` of an Open Payments error body; otherwise the JSON object body re-serialised,
 * the raw text, or, when the body is empty, the status line.
 */
const httpError = (call: Call, response: Response, text: string, url: string): OpenPaymentsError => {
  const body = decodeErrorBody(text);
  const detail = Result.isSuccess(body) ? body.success.error : undefined;
  const object = decodeJsonObject(text);
  const status = `${response.status} ${response.statusText}`.trim();

  const description =
    detail?.description ||
    (Result.isSuccess(object)
      ? JSON.stringify(object.success)
      : text || `Request failed with status code ${status}: ${call.method} ${url}`);

  return new OpenPaymentsError({
    reason: "http",
    message: `Error making Open Payments ${call.method} request`,
    status: response.status,
    description,
    ...(detail?.code !== undefined && { code: detail.code }),
    ...(detail?.details !== undefined && { details: detail.details }),
  });
};

const requestUrl = (transport: Transport, call: Call): string => {
  const url = new URL(call.url);

  if (transport.options.useHttp) url.protocol = "http:";

  for (const [name, value] of Object.entries(call.query ?? {})) {
    if (value) url.searchParams.set(name, String(value));
  }

  return url.href;
};

const toError = (cause: unknown): Error => (cause instanceof Error ? cause : new Error(String(cause)));

/** One failed attempt: the error plus what the retry loop needs to judge it. */
interface AttemptFailure {
  readonly error: OpenPaymentsError;
  /** Whether the failure is transient by default (before `retryOn` and the method rule). */
  readonly transient: boolean;
  /** The `Retry-After` header of the failed response. */
  readonly retryAfter: string | null;
}

const permanent = (error: OpenPaymentsError): AttemptFailure => ({ error, transient: false, retryAfter: null });

/** Thrown inside an attempt when the body exceeds `maxResponseBytes`: repeating cannot help. */
class ResponseTooLarge extends Error {}

/** One request/response exchange; a fresh signature, timeout and `fetch` every time it runs. */
const attempt = (transport: Transport, call: Call): Effect.Effect<Response, AttemptFailure> =>
  Effect.gen(function* () {
    const url = yield* Effect.try({
      try: () => requestUrl(transport, call),
      catch: (cause) => permanent(transportError(call, toError(cause))),
    });

    const headers = new Headers({ Accept: "application/json" });
    const body = call.body === undefined ? undefined : JSON.stringify(call.body);

    if (call.accessToken) headers.set("Authorization", `GNAP ${call.accessToken}`);

    if (body !== undefined) headers.set("Content-Type", "application/json");

    // Mirrors the reference client: POSTs and anything carrying an Authorization header are signed.
    if (transport.key && (call.method === "POST" || call.accessToken)) {
      yield* signHeaders(
        { method: call.method, url, headers },
        body === undefined ? undefined : utf8Encode(body),
        transport.key,
        {
          tag: "gnap",
          created: (transport.options.clock ?? (() => new Date()))(),
          // With retries a signature is never reusable: a fresh nonce makes every attempt's unique.
          ...(transport.options.retry && { nonce: encodeBase64Url(crypto.getRandomValues(new Uint8Array(16))) }),
        },
      ).pipe(Effect.mapError((cause) => permanent(signingError(call, cause))));
    }

    const timeoutMs = transport.options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    const maxBytes = transport.options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
    const fetchImpl = transport.options.fetch ?? globalThis.fetch;

    const response = yield* Effect.tryPromise({
      try: async (signal) => {
        const timeoutSignal = AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]);

        const received = await fetchImpl(url, {
          method: call.method,
          headers,
          ...(body !== undefined && { body }),
          signal: timeoutSignal,
        });

        // The body is read under the same timeout: a peer that stalls mid-body is cut off like one that never answers.
        const buffered = await bufferResponse(received, maxBytes, timeoutSignal);

        if (buffered === null) throw new ResponseTooLarge(`Response body is longer than ${maxBytes} bytes`);

        return buffered;
      },
      catch: (cause): AttemptFailure => ({
        error: transportError(call, toError(cause)),
        transient: !(cause instanceof ResponseTooLarge),
        retryAfter: null,
      }),
    });

    if (response.ok) return response;

    const text = yield* Effect.tryPromise({
      try: () => response.text(),
      catch: (): AttemptFailure => ({
        error: transportError(call, new Error("Could not read the error response body")),
        transient: true,
        retryAfter: null,
      }),
    });

    return yield* Effect.fail<AttemptFailure>({
      error: httpError(call, response, text, url),
      transient: isTransientStatus(response.status),
      retryAfter: response.headers.get("retry-after"),
    });
  });

/** The error of the last attempt, marked with the number of attempts made. */
const withAttempts = (error: OpenPaymentsError, attempts: number): OpenPaymentsError =>
  new OpenPaymentsError({
    reason: error.reason,
    message: error.message,
    attempts,
    ...(error.status !== undefined && { status: error.status }),
    ...(error.code !== undefined && { code: error.code }),
    ...(error.description !== undefined && { description: error.description }),
    ...(error.details !== undefined && { details: error.details }),
    ...(error.validationErrors !== undefined && { validationErrors: error.validationErrors }),
    ...(error.cause !== undefined && { cause: error.cause }),
  });

const pause = ({ sleep }: RetryOptions, ms: number): Effect.Effect<void> =>
  sleep === undefined
    ? Effect.sleep(ms)
    : Effect.suspend(() => {
        const slept = sleep(ms);

        return slept instanceof Promise ? Effect.promise(() => slept) : slept;
      });

/** Runs `attempt` under the retry policy of the client, if it has one. */
const execute = (transport: Transport, call: Call): Effect.Effect<Response, OpenPaymentsError> => {
  const retry = transport.options.retry;

  if (retry === undefined) return Effect.mapError(attempt(transport, call), ({ error }) => error);

  const limit = attemptLimit(retry);
  const repeatable = mayRepeat(call.method, call.retryNonIdempotent ?? retry.retryNonIdempotent ?? false);

  return Effect.gen(function* () {
    for (let made = 1; ; made++) {
      const outcome = yield* Effect.result(attempt(transport, call));

      if (Result.isSuccess(outcome)) return outcome.success;
      const { error, transient, retryAfter } = outcome.failure;

      if (made >= limit || !repeatable || !(retry.retryOn ? retry.retryOn(error) : transient)) {
        return yield* Effect.fail(withAttempts(error, made));
      }

      const now = (transport.options.clock ?? (() => new Date()))().getTime();

      yield* pause(retry, retryDelayMs(retry, made, error.status, retryAfter, now));
    }
  });
};

const decodeFailure = (status: number, message: string): OpenPaymentsError =>
  new OpenPaymentsError({
    reason: "validation",
    message: "Could not validate OpenAPI response",
    status,
    description: "Could not validate OpenAPI response",
    validationErrors: [message],
  });

/**
 * Runs a call, checks the JSON body against `decode` and returns the body as received, so members the schema does
 * not know survive (the reference client does not strip them either).
 */
const requestJson = <T>(transport: Transport, call: Call, decode: Decoder<T>): Result_<T> =>
  Effect.gen(function* () {
    const response = yield* execute(transport, call);

    const json = yield* Effect.tryPromise({
      try: () => response.json(),
      catch: () => decodeFailure(response.status, "Response body is not valid JSON"),
    });

    if (transport.options.validateResponses !== false) {
      yield* decode(json).pipe(Effect.mapError((error) => decodeFailure(response.status, error.message)));
    }

    // SAFETY: `decode` accepted `json`, so it has the shape of `T`; the schemas add no transformation.
    return json as T;
  });

/** Runs a call whose success response has no body (`204`). */
const requestVoid = (transport: Transport, call: Call): Result_<void> =>
  Effect.asVoid(
    Effect.flatMap(execute(transport, call), (response) =>
      Effect.promise(async () => {
        await response.body?.cancel();
      }),
    ),
  );

/**
 * Runs a payment invariant on a decoded body. With `validateResponses: false` the body may lack members the
 * invariant reads: that is a validation error like any other, not a crash.
 */
const check = <T>(invariant: () => Result.Result<T, OpenPaymentsError>): Result_<T> =>
  Effect.try({
    try: invariant,
    catch: () =>
      new OpenPaymentsError({
        reason: "validation",
        message: "Could not validate OpenAPI response",
        description: "Response body lacks members the payment checks read",
        validationErrors: ["Response body lacks members the payment checks read"],
      }),
  }).pipe(Effect.flatMap(Effect.fromResult));

function walletAddressRoutes(transport: Transport): WalletAddressRoutes {
  return {
    get: ({ url }) => requestJson(transport, { method: "GET", url }, decode.walletAddress),
    getKeys: ({ url }) => requestJson(transport, { method: "GET", url: `${url}/jwks.json` }, decode.jwks),
    getDIDDocument: ({ url }) => requestJson(transport, { method: "GET", url: `${url}/did.json` }, decode.didDocument),
  };
}

function publicIncomingPayment(
  transport: Transport,
  { url }: UnauthenticatedResourceRequestArgs,
): Result_<PublicIncomingPayment> {
  return requestJson(transport, { method: "GET", url }, decode.publicIncomingPayment);
}

function pageQuery(walletAddress: string, pagination: PaginationArgs | undefined) {
  return { ...pagination, "wallet-address": walletAddress };
}

function incomingPaymentRoutes(transport: Transport): IncomingPaymentRoutes {
  return {
    get: ({ url, accessToken }) => {
      const call: Call = { method: "GET", url, accessToken };

      return requestJson(transport, call, decode.incomingPaymentWithMethods).pipe(
        Effect.flatMap((payment) => check(() => checkIncomingPayment(payment))),
      );
    },
    getPublic: (args) => publicIncomingPayment(transport, args),
    create: ({ url, accessToken, retryNonIdempotent }, createArgs) => {
      const call: Call = {
        method: "POST",
        url: `${url}/incoming-payments`,
        accessToken,
        body: createArgs,
        retryNonIdempotent,
      };

      return requestJson(transport, call, decode.incomingPaymentWithMethods).pipe(
        Effect.flatMap((payment) => check(() => checkCreatedIncomingPayment(payment))),
      );
    },
    complete: ({ url, accessToken, retryNonIdempotent }) => {
      const call: Call = { method: "POST", url: `${url}/complete`, accessToken, retryNonIdempotent };

      return requestJson(transport, call, decode.incomingPayment).pipe(
        Effect.flatMap((payment) => check(() => checkCompletedIncomingPayment(payment))),
      );
    },
    list: ({ url, accessToken, walletAddress }, pagination) => {
      const call: Call = {
        method: "GET",
        url: `${url}/incoming-payments`,
        accessToken,
        query: pageQuery(walletAddress, pagination),
      };

      return requestJson(transport, call, decode.incomingPaymentPage).pipe(
        Effect.flatMap((page) => check(() => Result.all(page.result.map(checkIncomingPayment))).pipe(Effect.as(page))),
      );
    },
  };
}

function outgoingPaymentRoutes(transport: Transport): OutgoingPaymentRoutes {
  return {
    get: ({ url, accessToken }) => {
      const call: Call = { method: "GET", url, accessToken };

      return requestJson(transport, call, decode.outgoingPayment).pipe(
        Effect.flatMap((payment) => check(() => checkOutgoingPayment(payment))),
      );
    },
    list: ({ url, accessToken, walletAddress }, pagination) => {
      const call: Call = {
        method: "GET",
        url: `${url}/outgoing-payments`,
        accessToken,
        query: pageQuery(walletAddress, pagination),
      };

      return requestJson(transport, call, decode.outgoingPaymentPage).pipe(
        Effect.flatMap((page) => check(() => Result.all(page.result.map(checkOutgoingPayment))).pipe(Effect.as(page))),
      );
    },
    create: ({ url, accessToken, retryNonIdempotent }, createArgs) => {
      const call: Call = {
        method: "POST",
        url: `${url}/outgoing-payments`,
        accessToken,
        body: createArgs,
        retryNonIdempotent,
      };

      return requestJson(transport, call, decode.outgoingPaymentWithSpentAmounts).pipe(
        Effect.flatMap((payment) => check(() => checkOutgoingPayment(payment))),
      );
    },
    getGrantSpentAmounts: ({ url, accessToken }) =>
      requestJson(
        transport,
        { method: "GET", url: `${url}/outgoing-payment-grant`, accessToken },
        decode.outgoingPaymentGrantSpentAmounts,
      ),
  };
}

function quoteRoutes(transport: Transport): QuoteRoutes {
  return {
    get: ({ url, accessToken }) => requestJson(transport, { method: "GET", url, accessToken }, decode.quote),
    create: ({ url, accessToken, retryNonIdempotent }, createArgs) =>
      requestJson(
        transport,
        { method: "POST", url: `${url}/quotes`, accessToken, body: createArgs, retryNonIdempotent },
        decode.quote,
      ),
  };
}

const invalidGrantRequest = (description: string): OpenPaymentsError =>
  new OpenPaymentsError({ reason: "invalid-request", message: "Invalid Grant Request", description });

function grantRoutes(transport: Transport, client: string): GrantRoutes {
  return {
    request: ({ url, retryNonIdempotent }, grantRequest, clientOverride) => {
      if (!grantRequest.access_token && !grantRequest.subject) {
        return Effect.fail(
          invalidGrantRequest('Grant request must include at least one of "access_token" or "subject".'),
        );
      }

      const outgoing = grantRequest.access_token?.access.find((item) => item.type === "outgoing-payment");

      if (outgoing?.limits && "debitAmount" in outgoing.limits && "receiveAmount" in outgoing.limits) {
        return Effect.fail(invalidGrantRequest('Only one of "debitAmount" or "receiveAmount" may be specified.'));
      }

      return requestJson(
        transport,
        {
          method: "POST",
          url,
          body: { ...grantRequest, client: clientOverride ?? client },
          retryNonIdempotent,
        },
        decode.grantResponse,
      );
    },
    continue: ({ url, accessToken, retryNonIdempotent }, continuation) =>
      requestJson(
        transport,
        { method: "POST", url, accessToken, body: continuation, retryNonIdempotent },
        decode.grant,
      ),
    cancel: ({ url, accessToken }) => requestVoid(transport, { method: "DELETE", url, accessToken }),
  };
}

function tokenRoutes(transport: Transport): TokenRoutes {
  return {
    rotate: ({ url, accessToken, retryNonIdempotent }) =>
      requestJson(transport, { method: "POST", url, accessToken, retryNonIdempotent }, decode.accessTokenResponse),
    revoke: ({ url, accessToken }) => requestVoid(transport, { method: "DELETE", url, accessToken }),
  };
}

/**
 * Creates a client that can only fetch public data (wallet address, keys, DID document, public incoming payment).
 * Nothing is signed. Every route returns an `Effect` failing with {@link OpenPaymentsError}
 * (`http`, `validation` or `transport`); no I/O happens until the effect runs, and nothing is retried unless
 * `options.retry` is set (see {@link RetryOptions}).
 *
 * @see https://openpayments.dev/apis/wallet-address-server/
 */
export function createUnauthenticatedClient(options: ClientOptions = {}): UnauthenticatedClient {
  const transport: Transport = { options, key: undefined };

  return {
    walletAddress: walletAddressRoutes(transport),
    incomingPayment: { get: (args) => publicIncomingPayment(transport, args) },
  };
}

/**
 * Creates a client exposing every Open Payments API. `POST` requests and requests carrying a token are
 * signed with `signRequest` (RFC 9421, Ed25519). Every route returns an `Effect` failing with
 * {@link OpenPaymentsError} (`http`, `validation`, `transport`, `signing`, `invalid-request`, `invalid-amount`);
 * no I/O happens until the effect runs, and nothing is retried unless `options.retry` is set (see
 * {@link RetryOptions}; a `POST` needs `retryNonIdempotent`). Responses are returned as received (unknown members
 * included) after validation.
 *
 * @see https://openpayments.dev/apis/
 */
export function createAuthenticatedClient(options: AuthenticatedClientOptions): AuthenticatedClient {
  const transport: Transport = { options, key: { keyId: options.keyId, privateKey: options.privateKey } };

  return {
    walletAddress: walletAddressRoutes(transport),
    incomingPayment: incomingPaymentRoutes(transport),
    outgoingPayment: outgoingPaymentRoutes(transport),
    grant: grantRoutes(transport, options.walletAddressUrl),
    token: tokenRoutes(transport),
    quote: quoteRoutes(transport),
  };
}
