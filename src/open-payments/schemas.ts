/**
 * Effect schemas for the responses the client validates. Each schema's decoded type is checked
 * against the corresponding alias in ./types.ts at its use site in client.ts.
 * @internal Not exported from the public entry point.
 */
import * as Schema from "effect/Schema";
import type {
  AccessItem,
  Subject,
  AccessToken,
  Amount,
  DIDDocument,
  Grant,
  IlpPaymentMethod,
  IncomingPayment,
  IncomingPaymentPaginationResult,
  IncomingPaymentWithPaymentMethods,
  JWK,
  JWKS,
  OutgoingPayment,
  OutgoingPaymentGrantSpentAmounts,
  OutgoingPaymentPaginationResult,
  OutgoingPaymentWithSpentAmounts,
  PendingGrant,
  PublicIncomingPayment,
  Quote,
  WalletAddress,
} from "./types";

const mutableArray = <S extends Schema.Constraint>(item: S): Schema.mutable<Schema.$Array<S>> =>
  Schema.mutable(Schema.Array(item));

const amountValue = Schema.String.check(Schema.isPattern(/^\d+$/));

export const amount: Schema.Codec<Amount> = Schema.Struct({
  value: amountValue,
  assetCode: Schema.String,
  assetScale: Schema.Int,
});

const metadata = Schema.Record(Schema.String, Schema.Unknown);

/** Open Payments JWKs may carry additional members, which are kept. */
export const jwk: Schema.Codec<JWK> = Schema.StructWithRest(
  Schema.Struct({
    kid: Schema.String,
    alg: Schema.Literal("EdDSA"),
    use: Schema.optionalKey(Schema.Literal("sig")),
    kty: Schema.Literal("OKP"),
    crv: Schema.Literal("Ed25519"),
    x: Schema.String.check(Schema.isPattern(/^[A-Za-z0-9_-]+$/)),
  }),
  [Schema.Record(Schema.String, Schema.Unknown)],
);

/** The wallet address document allows additional properties, which are kept. */
export const walletAddress: Schema.Codec<WalletAddress> = Schema.StructWithRest(
  Schema.Struct({
    id: Schema.String,
    publicName: Schema.optionalKey(Schema.String),
    assetCode: Schema.String,
    assetScale: Schema.Int,
    authServer: Schema.String,
    resourceServer: Schema.String,
  }),
  [Schema.Record(Schema.String, Schema.Unknown)],
);

export const jwks: Schema.Codec<JWKS> = Schema.Struct({ keys: mutableArray(jwk) });

export const didDocument: Schema.Codec<DIDDocument> = Schema.Record(Schema.String, Schema.Unknown);

const incomingPaymentFields = {
  id: Schema.String,
  walletAddress: Schema.String,
  completed: Schema.Boolean,
  incomingAmount: Schema.optionalKey(amount),
  receivedAmount: amount,
  expiresAt: Schema.optionalKey(Schema.String),
  metadata: Schema.optionalKey(metadata),
  createdAt: Schema.String,
};

export const incomingPayment: Schema.Codec<IncomingPayment> = Schema.Struct(incomingPaymentFields);

export const ilpPaymentMethod: Schema.Codec<IlpPaymentMethod> = Schema.Struct({
  type: Schema.Literal("ilp"),
  ilpAddress: Schema.String,
  sharedSecret: Schema.String,
});

export const incomingPaymentWithMethods: Schema.Codec<IncomingPaymentWithPaymentMethods> = Schema.Struct({
  ...incomingPaymentFields,
  methods: mutableArray(ilpPaymentMethod),
});

export const publicIncomingPayment: Schema.Codec<PublicIncomingPayment> = Schema.Struct({
  receivedAmount: Schema.optionalKey(amount),
  authServer: Schema.String,
});

const outgoingPaymentFields = {
  id: Schema.String,
  walletAddress: Schema.String,
  quoteId: Schema.optionalKey(Schema.String),
  failed: Schema.Boolean,
  receiver: Schema.String,
  receiveAmount: amount,
  debitAmount: amount,
  sentAmount: amount,
  metadata: Schema.optionalKey(metadata),
  createdAt: Schema.String,
};

export const outgoingPayment: Schema.Codec<OutgoingPayment> = Schema.Struct(outgoingPaymentFields);

export const outgoingPaymentWithSpentAmounts: Schema.Codec<OutgoingPaymentWithSpentAmounts> = Schema.Struct({
  ...outgoingPaymentFields,
  grantSpentDebitAmount: Schema.optionalKey(amount),
  grantSpentReceiveAmount: Schema.optionalKey(amount),
});

export const outgoingPaymentGrantSpentAmounts: Schema.Codec<OutgoingPaymentGrantSpentAmounts> = Schema.Struct({
  spentReceiveAmount: Schema.NullOr(amount),
  spentDebitAmount: Schema.NullOr(amount),
});

export const quote: Schema.Codec<Quote> = Schema.Struct({
  id: Schema.String,
  walletAddress: Schema.String,
  receiver: Schema.String,
  receiveAmount: amount,
  debitAmount: amount,
  method: Schema.Literal("ilp"),
  expiresAt: Schema.optionalKey(Schema.String),
  createdAt: Schema.String,
});

const pageInfo = Schema.Struct({
  startCursor: Schema.optionalKey(Schema.String),
  endCursor: Schema.optionalKey(Schema.String),
  hasNextPage: Schema.Boolean,
  hasPreviousPage: Schema.Boolean,
});

export const incomingPaymentPage: Schema.Codec<IncomingPaymentPaginationResult> = Schema.Struct({
  pagination: pageInfo,
  result: mutableArray(incomingPayment),
});

export const outgoingPaymentPage: Schema.Codec<OutgoingPaymentPaginationResult> = Schema.Struct({
  pagination: pageInfo,
  result: mutableArray(outgoingPayment),
});

export const subject: Schema.Codec<Subject> = Schema.Struct({
  sub_ids: mutableArray(Schema.Struct({ id: Schema.String, format: Schema.Literal("uri") })),
});

/** One `access` entry of a grant request or access token. Decode with `onExcessProperty: "error"` to reject unknown members. */
export const accessItem: Schema.Codec<AccessItem> = Schema.Union([
  Schema.Struct({
    type: Schema.Literal("incoming-payment"),
    actions: mutableArray(Schema.Literals(["create", "complete", "read", "read-all", "list", "list-all"])),
    identifier: Schema.optionalKey(Schema.String),
  }),
  Schema.Struct({
    type: Schema.Literal("outgoing-payment"),
    actions: mutableArray(Schema.Literals(["create", "read", "read-all", "list", "list-all"])),
    identifier: Schema.String,
    limits: Schema.optionalKey(
      Schema.Union([
        Schema.Struct({
          receiver: Schema.optionalKey(Schema.String),
          interval: Schema.optionalKey(Schema.String),
          debitAmount: amount,
        }),
        Schema.Struct({
          receiver: Schema.optionalKey(Schema.String),
          interval: Schema.optionalKey(Schema.String),
          receiveAmount: amount,
        }),
        Schema.Struct({ receiver: Schema.optionalKey(Schema.String), interval: Schema.optionalKey(Schema.String) }),
      ]),
    ),
  }),
  Schema.Struct({
    type: Schema.Literal("quote"),
    actions: mutableArray(Schema.Literals(["create", "read", "read-all"])),
  }),
]);

export const accessToken: Schema.Codec<AccessToken["access_token"]> = Schema.Struct({
  value: Schema.String,
  manage: Schema.String,
  expires_in: Schema.optionalKey(Schema.Number),
  access: mutableArray(accessItem),
});

const continuation = Schema.Struct({
  access_token: Schema.Struct({ value: Schema.String }),
  uri: Schema.String,
  wait: Schema.optionalKey(Schema.Number),
});

export const accessTokenResponse: Schema.Codec<AccessToken> = Schema.Struct({ access_token: accessToken });

export const pendingGrant: Schema.Codec<PendingGrant> = Schema.Struct({
  interact: Schema.Struct({ redirect: Schema.String, finish: Schema.String }),
  continue: continuation,
});

/** Also matches continuation-only responses: `access_token` and `subject` are optional. */
export const grant: Schema.Codec<Grant> = Schema.Struct({
  access_token: Schema.optionalKey(accessToken),
  continue: continuation,
  subject: Schema.optionalKey(subject),
});
