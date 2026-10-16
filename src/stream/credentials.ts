import * as Effect from "effect/Effect";
import * as Result from "effect/Result";
import { ILP_ADDRESS_MAX_LENGTH, isValidIlpAddress } from "../ilp/address";
import { codecFail } from "../ilp/errors";
import { asciiBytes, asciiString, readOer, utf8String, writeOer } from "../ilp/oer";
import { decodeBase64Url, encodeBase64Url, utf8Encode } from "../internal/bytes";
import { decrypt, encrypt, keysForSecret, STREAM_ENCRYPTION_OVERHEAD, type StreamKeys } from "./crypto";
import { StreamError } from "./errors";
import { hmac, latin1, memo } from "./key-cache";

const SERVER_SECRET_LENGTH = 32;

const RECEIPT_NONCE_LENGTH = 16;

const RECEIPT_SECRET_LENGTH = 32;

const TOKEN_LABEL = utf8Encode("ilp_stream_connection_token");

const SHARED_SECRET_LABEL = utf8Encode("ilp_stream_shared_secret");

const FLAG_PAYMENT_TAG = 1;

const FLAG_RECEIPTS = 2;

const FLAG_ASSET_DETAILS = 4;

/** The receiving server's identity: a long-lived secret and the ILP address it is reachable under. */
export interface StreamServerConfig {
  /** 32 random bytes. Every connection token and shared secret is derived from it. */
  readonly serverSecret: Uint8Array;
  /** Base ILP address of the server; credentials are issued as `<serverAddress>.<token>`. */
  readonly serverAddress: string;
}

/** Optional data bound into a connection token (RFC 39 receipts, RFC 29 asset details, payment tag). */
export interface StreamCredentialOptions {
  /** ASCII tag identifying the payment; returned with every accepted packet. */
  readonly paymentTag?: string;
  /** Receipt nonce (16 bytes) and secret (32 bytes); enables STREAM receipts. */
  readonly receipt?: { readonly nonce: Uint8Array; readonly secret: Uint8Array };
  /** Asset the server credits; sent back to senders in a `ConnectionAssetDetails` frame. */
  readonly asset?: { readonly code: string; readonly scale: number };
}

/** An SPSP-style credential pair. */
export interface StreamCredentials {
  /** Destination ILP address: `<serverAddress>.<base64url(token)>`. */
  readonly ilpAddress: string;
  /** 32-byte shared secret to give the sender out of band. */
  readonly sharedSecret: Uint8Array;
}

/** @internal What a connection token carries, after decryption. */
export interface StreamConnectionDetails {
  readonly paymentTag?: string;
  readonly receipt?: { readonly nonce: Uint8Array; readonly secret: Uint8Array };
  readonly asset?: { readonly code: string; readonly scale: number };
}

/** @internal What the server secret yields, shared by every connection of every server address using it. */
export interface SecretKeys {
  readonly sharedSecretKeyGen: Uint8Array;
  readonly connectionTokenKeyGen: Uint8Array;
  /** Authenticated connections by token, so repeat packets skip the token decryption and key derivation. */
  readonly connections: Map<string, Promise<Connection | undefined>>;
}

/** @internal An authenticated connection token with everything derived from it. */
export interface Connection {
  readonly details: StreamConnectionDetails;
  readonly keys: StreamKeys;
}

const SECRET_CAPACITY = 16;

const CONNECTION_CAPACITY = 256;

const secrets = new Map<string, Promise<SecretKeys>>();

/** @internal The first problem with `config`, if any. */
export function checkServerConfig(config: StreamServerConfig): StreamError | undefined {
  if (config.serverSecret.length !== SERVER_SECRET_LENGTH) {
    return new StreamError({ reason: "invalid-key", message: "server secret must be 32 bytes" });
  }

  if (!isValidIlpAddress(config.serverAddress)) {
    return new StreamError({ reason: "invalid-address", message: "invalid server base ILP address" });
  }

  return undefined;
}

/** @internal The two key generators of a (validated) 32-byte server secret, derived once per distinct secret. */
export function secretKeys(serverSecret: Uint8Array): Promise<SecretKeys> {
  return memo(
    secrets,
    latin1(serverSecret),
    async () => {
      const [connectionTokenKeyGen, sharedSecretKeyGen] = await Promise.all([
        hmac(serverSecret, TOKEN_LABEL),
        hmac(serverSecret, SHARED_SECRET_LABEL),
      ]);

      return { sharedSecretKeyGen, connectionTokenKeyGen, connections: new Map() };
    },
    SECRET_CAPACITY,
  );
}

/** @internal The shared secret of a connection: `HMAC-SHA256(sharedSecretKeyGen, token)`. */
export function sharedSecretFromToken(keys: SecretKeys, token: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return hmac(keys.sharedSecretKeyGen, token);
}

/**
 * @internal The connection behind the address segment `segment`, or `undefined` when it is not a token this server
 * issued (malformed, or it does not authenticate). Only authenticated tokens are cached, so a flood of garbage
 * cannot evict real connections.
 */
export function openConnection(keys: SecretKeys, segment: string): Promise<Connection | undefined> {
  return memo(
    keys.connections,
    segment,
    async () => {
      const token = decodeToken(segment);
      const details = token && (await openConnectionToken(keys, token));

      if (!token || !details) return undefined;

      return { details, keys: await keysForSecret(await sharedSecretFromToken(keys, token)) };
    },
    CONNECTION_CAPACITY,
  );
}

function decodeToken(segment: string): Uint8Array | undefined {
  try {
    return decodeBase64Url(segment);
  } catch {
    return undefined;
  }
}

/** Decrypts and parses a connection token. `undefined` when it does not authenticate or is malformed. */
async function openConnectionToken(keys: SecretKeys, token: Uint8Array): Promise<StreamConnectionDetails | undefined> {
  if (token.length < STREAM_ENCRYPTION_OVERHEAD) return undefined;
  let decrypted: Uint8Array;

  try {
    decrypted = await decrypt(keys.connectionTokenKeyGen, token);
  } catch {
    return undefined;
  }

  const details = readOer(decrypted, (reader): StreamConnectionDetails => {
    const flags = reader.readUInt8();
    const paymentTag = flags & FLAG_PAYMENT_TAG ? asciiString(reader.readVarOctetString(), "paymentTag") : undefined;

    const receipt =
      flags & FLAG_RECEIPTS
        ? { nonce: reader.readOctets(RECEIPT_NONCE_LENGTH), secret: reader.readOctets(RECEIPT_SECRET_LENGTH) }
        : undefined;

    const asset =
      flags & FLAG_ASSET_DETAILS
        ? { code: utf8String(reader.readVarOctetString(), "asset code"), scale: reader.readUInt8() }
        : undefined;

    return {
      ...(paymentTag !== undefined && { paymentTag }),
      ...(receipt && { receipt }),
      ...(asset && { asset }),
    };
  });

  return Result.isSuccess(details) ? details.success : undefined;
}

/**
 * Issues SPSP-style credentials for a new connection, byte-compatible with
 * `@interledger/stream-receiver`'s `StreamServer.generateCredentials`:
 * a random-IV AES-256-GCM connection token (keyed from the server secret) is appended to the server address,
 * and the shared secret is `HMAC-SHA256(HMAC-SHA256(serverSecret, "ilp_stream_shared_secret"), token)`.
 * Nothing is stored: {@link createStreamReply} re-derives everything from the token.
 *
 * Fails with `StreamError`: `invalid-key` for a server secret that is not 32 bytes, `invalid-address` for an invalid
 * server address or a resulting address over 1023 characters, `invalid-option` for malformed options.
 */
export function generateStreamCredentials(
  config: StreamServerConfig,
  options: StreamCredentialOptions = {},
): Effect.Effect<StreamCredentials, StreamError> {
  const invalid = checkServerConfig(config);

  if (invalid) return Effect.fail(invalid);

  const plaintext = writeOer((out) => {
    const { paymentTag, receipt, asset } = options;

    if (receipt && receipt.nonce.length !== RECEIPT_NONCE_LENGTH) {
      codecFail("invalid-field", "receipt nonce must be 16 bytes");
    }

    if (receipt && receipt.secret.length !== RECEIPT_SECRET_LENGTH) {
      codecFail("invalid-field", "receipt secret must be 32 bytes");
    }

    // An empty tag means no tag, as in stream-receiver.
    out.writeUInt8(
      (paymentTag ? FLAG_PAYMENT_TAG : 0) | (receipt ? FLAG_RECEIPTS : 0) | (asset ? FLAG_ASSET_DETAILS : 0),
    );

    if (paymentTag) out.writeVarOctetString(asciiBytes(paymentTag, "paymentTag"));

    if (receipt) {
      out.writeOctets(receipt.nonce);
      out.writeOctets(receipt.secret);
    }

    if (asset) {
      out.writeVarOctetString(utf8Encode(asset.code));
      out.writeUInt8(asset.scale);
    }
  });

  if (Result.isFailure(plaintext)) {
    return Effect.fail(new StreamError({ reason: "invalid-option", message: plaintext.failure.message }));
  }

  // Unpadded base64url of the IV + tag + plaintext token; every character is a valid address character.
  const tokenLength = Math.ceil(((STREAM_ENCRYPTION_OVERHEAD + plaintext.success.length) * 4) / 3);

  if (config.serverAddress.length + 1 + tokenLength > ILP_ADDRESS_MAX_LENGTH) {
    return Effect.fail(
      new StreamError({ reason: "invalid-address", message: "too much data to encode within an ILP address" }),
    );
  }

  return Effect.promise(async () => {
    const keys = await secretKeys(config.serverSecret);
    const token = await encrypt(keys.connectionTokenKeyGen, plaintext.success);

    return {
      ilpAddress: `${config.serverAddress}.${encodeBase64Url(token)}`,
      sharedSecret: await sharedSecretFromToken(keys, token),
    };
  });
}
