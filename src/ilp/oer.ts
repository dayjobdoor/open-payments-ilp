import * as Result from "effect/Result";
import { codecFail, IlpCodecError } from "./errors";

const MAX_UINT64 = (1n << 64n) - 1n;

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

const MASK_32 = 0xffff_ffffn;

const TWO_32 = 0x1_0000_0000;

const TIMESTAMP_LENGTH = 17;

/** Length prefixes above 4 bytes would address more than 4 GiB; no ILP packet gets near that. */
const MAX_LENGTH_PREFIX_BYTES = 4;

const MAX_LENGTH = 0xffff_ffff;

/** Decodes ASCII bytes; any byte >= 0x80 is a codec failure. */
export function asciiString(bytes: Uint8Array, what: string): string {
  let out = "";

  for (const byte of bytes) {
    if (byte > 0x7f) codecFail("invalid-field", `${what} contains a non-ASCII byte`);
    out += String.fromCharCode(byte);
  }

  return out;
}

/** Encodes an ASCII string; any code unit >= 0x80 is a codec failure. */
export function asciiBytes(text: string, what: string): Uint8Array {
  const out = new Uint8Array(text.length);

  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);

    if (code > 0x7f) codecFail("invalid-field", `${what} contains a non-ASCII character`);
    out[i] = code;
  }

  return out;
}

const strictUtf8 = new TextDecoder("utf-8", { fatal: true });

/** Decodes UTF-8 bytes; malformed input is a codec failure rather than a `TypeError`. */
export function utf8String(bytes: Uint8Array, what: string): string {
  try {
    return strictUtf8.decode(bytes);
  } catch {
    return codecFail("invalid-field", `${what} is not valid UTF-8`);
  }
}

/**
 * Cursor over an OER-encoded buffer (RFC 30 subset used by ILP and STREAM).
 * Every `read*` method throws {@link IlpCodecError}; wrap use in {@link readOer} to get a `Result`.
 * Returned byte arrays are copies, never views of the input.
 */
export class OerReader {
  readonly #bytes: Uint8Array;
  #offset = 0;

  constructor(bytes: Uint8Array) {
    // A plain Uint8Array so `slice` copies instead of aliasing (Buffer#slice is a view).
    this.#bytes =
      bytes.constructor === Uint8Array ? bytes : new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.length);
  }

  /** Bytes consumed so far. */
  get offset(): number {
    return this.#offset;
  }

  /** Bytes not yet consumed. */
  get remaining(): number {
    return this.#bytes.length - this.#offset;
  }

  /** Reads exactly `length` raw octets (fixed-length OCTET STRING). */
  readOctets(length: number): Uint8Array {
    const start = this.#take(length);

    return this.#bytes.slice(start, start + length);
  }

  /** Reads a fixed `UInt8`. */
  readUInt8(): number {
    return this.#bytes[this.#take(1)] ?? 0;
  }

  /** Reads a fixed big-endian `UInt32`. */
  readUInt32(): number {
    return this.#number(this.#take(4), 4);
  }

  /** Reads a fixed big-endian `UInt64`. */
  readUInt64(): bigint {
    return this.#bigint(this.#take(8), 8);
  }

  /** Reads an OER length determinant. Rejects non-canonical (over-long) forms. */
  readLengthPrefix(): number {
    const first = this.readUInt8();

    if (first < 0x80) return first;
    const prefixBytes = first & 0x7f;

    if (prefixBytes === 0) codecFail("non-canonical", "length prefix of 0 bytes");

    if (prefixBytes > MAX_LENGTH_PREFIX_BYTES) {
      codecFail("out-of-range", `length prefix of ${prefixBytes} bytes is unsupported`);
    }

    const length = this.#number(this.#take(prefixBytes), prefixBytes);
    const minimum = prefixBytes === 1 ? 0x80 : 2 ** ((prefixBytes - 1) * 8);

    if (length < minimum) codecFail("non-canonical", `length ${length} encoded in ${prefixBytes} bytes`);

    return length;
  }

  /** Reads a `VarOctetString`: length prefix then that many octets. */
  readVarOctetString(): Uint8Array {
    return this.readOctets(this.readLengthPrefix());
  }

  /** Reads a `VarOctetString` and returns a reader over its contents, without copying them. */
  readNested(): OerReader {
    const length = this.readLengthPrefix();
    const start = this.#take(length);

    return new OerReader(this.#bytes.subarray(start, start + length));
  }

  /** Reads a `VarUInt` of 1–8 bytes (value ≤ 2^64-1). Leading zero bytes are tolerated, as ilp-packet does. */
  readVarUInt(): bigint {
    const length = this.readLengthPrefix();

    if (length === 0) codecFail("invalid-field", "VarUInt of length 0");

    if (length > 8) codecFail("out-of-range", `VarUInt of ${length} bytes exceeds uint64`);

    return this.#bigint(this.#take(length), length);
  }

  /** Like {@link readVarUInt} but a value wider than 8 bytes saturates to 2^64-1 (STREAM `receiveMax`/`sendMax`). */
  readVarUIntSaturating(): bigint {
    const length = this.readLengthPrefix();

    if (length === 0) codecFail("invalid-field", "VarUInt of length 0");
    const start = this.#take(length);

    return length > 8 ? MAX_UINT64 : this.#bigint(start, length);
  }

  /** Reads the 17-character ILP timestamp `YYYYMMDDhhmmssfff` (UTC) used by Prepare `expiresAt`. */
  readTimestamp(): Date {
    const start = this.#take(TIMESTAMP_LENGTH);
    const bytes = this.#bytes;

    for (let i = start; i < start + TIMESTAMP_LENGTH; i++) {
      const byte = bytes[i] ?? 0;

      if (byte < 0x30 || byte > 0x39) codecFail("invalid-timestamp", "timestamp is not YYYYMMDDhhmmssfff");
    }

    const field = (from: number, to: number): number => {
      let value = 0;

      for (let i = start + from; i < start + to; i++) value = value * 10 + ((bytes[i] ?? 0) - 0x30);

      return value;
    };

    const year = field(0, 4);
    const month = field(4, 6);
    const day = field(6, 8);
    const hour = field(8, 10);
    const minute = field(10, 12);
    const second = field(12, 14);
    const millisecond = field(14, 17);

    // Explicit ranges reject calendar overflow (month 13, Feb 30, hour 24, second 60 ...) that Date would roll over.
    if (month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) {
      codecFail("invalid-timestamp", "timestamp is not a valid UTC time");
    }

    if (day < 1 || day > daysInMonth(year, month)) {
      codecFail("invalid-timestamp", "timestamp is not a valid UTC time");
    }

    if (year >= 100) return new Date(Date.UTC(year, month - 1, day, hour, minute, second, millisecond));

    // Date.UTC would map years 0–99 to 1900–1999; setUTCFullYear keeps them literal.
    const date = new Date(0);
    date.setUTCFullYear(year, month - 1, day);
    date.setUTCHours(hour, minute, second, millisecond);

    return date;
  }

  /** Claims `length` bytes and returns where they start. */
  #take(length: number): number {
    const start = this.#offset;

    if (length > this.#bytes.length - start) {
      codecFail("truncated", `expected ${length} bytes but only ${this.#bytes.length - start} remain`);
    }

    this.#offset = start + length;

    return start;
  }

  /** Big-endian value of up to 6 bytes, exact as a double. */
  #number(start: number, length: number): number {
    let value = 0;

    for (let i = start; i < start + length; i++) value = value * 256 + (this.#bytes[i] ?? 0);

    return value;
  }

  /** Big-endian value of up to 8 bytes; one `BigInt` allocation on the common (≤ 6 byte) path. */
  #bigint(start: number, length: number): bigint {
    if (length <= 6) return BigInt(this.#number(start, length));
    const split = start + length - 4;

    return (BigInt(this.#number(start, length - 4)) << 32n) | BigInt(this.#number(split, 4));
  }
}

/** Builder for OER-encoded buffers. Every `write*` method throws {@link IlpCodecError}; wrap in {@link writeOer}. */
export class OerWriter {
  #buffer = new Uint8Array(128);
  #length = 0;

  /** Appends raw octets (fixed-length OCTET STRING). */
  writeOctets(bytes: Uint8Array): void {
    this.#reserve(bytes.length);
    this.#buffer.set(bytes, this.#length);
    this.#length += bytes.length;
  }

  /** Writes a fixed `UInt8` (0–255). */
  writeUInt8(value: number): void {
    if (!Number.isInteger(value) || value < 0 || value > 0xff) codecFail("out-of-range", `${value} is not a uint8`);
    this.#reserve(1);
    this.#buffer[this.#length++] = value;
  }

  /** Writes a fixed big-endian `UInt32`. */
  writeUInt32(value: number): void {
    if (!Number.isInteger(value) || value < 0 || value > MAX_LENGTH) {
      codecFail("out-of-range", `${value} is not a uint32`);
    }

    this.#reserve(4);
    this.#putUInt32(value);
  }

  /** Writes a fixed big-endian `UInt64` (0 ≤ value ≤ 2^64-1). */
  writeUInt64(value: bigint): void {
    this.#reserve(8);
    this.#putUInt64(checkUInt64(value));
  }

  /** Writes an OER length determinant in its canonical (shortest) form. */
  writeLengthPrefix(length: number): void {
    if (!Number.isInteger(length) || length < 0 || length > MAX_LENGTH) {
      codecFail("out-of-range", `length ${length} is not encodable`);
    }

    this.#reserve(5);
    this.#putLength(length);
  }

  /** Writes a `VarOctetString`. */
  writeVarOctetString(bytes: Uint8Array): void {
    this.writeLengthPrefix(bytes.length);
    this.writeOctets(bytes);
  }

  /**
   * Writes a `VarOctetString` whose contents `write` appends to this same writer,
   * so nested structures need no intermediate buffer.
   */
  writeNested(write: (writer: OerWriter) => void): void {
    const lengthAt = this.#length;
    this.#reserve(1);
    this.#length += 1;
    write(this);
    const size = this.#length - lengthAt - 1;

    if (size < 0x80) {
      this.#buffer[lengthAt] = size;

      return;
    }

    if (size > MAX_LENGTH) codecFail("out-of-range", `length ${size} is not encodable`);
    const extra = lengthWidth(size) - 1;
    this.#reserve(extra);
    this.#buffer.copyWithin(lengthAt + 1 + extra, lengthAt + 1, lengthAt + 1 + size);
    const end = this.#length + extra;
    this.#length = lengthAt;
    this.#putLength(size);
    this.#length = end;
  }

  /** Writes a `VarUInt` in its minimal byte width (0 → one `0x00` byte). */
  writeVarUInt(value: bigint): void {
    const [high, low] = split(checkUInt64(value));
    const width = high > 0 ? 4 + byteWidth(high) : byteWidth(low);
    this.#reserve(width + 1);
    this.#buffer[this.#length++] = width;

    for (let shift = (width - 1) * 8; shift >= 0; shift -= 8) {
      // Bytes above bit 31 come from `high`, the rest from `low`.
      this.#buffer[this.#length++] = shift >= 32 ? (high >>> (shift - 32)) & 0xff : (low >>> shift) & 0xff;
    }
  }

  /** Writes the 17-character ILP timestamp `YYYYMMDDhhmmssfff` (UTC). */
  writeTimestamp(date: Date): void {
    const year = date.getUTCFullYear();

    if (Number.isNaN(year)) codecFail("invalid-timestamp", "expiresAt is an invalid Date");

    if (year < 0 || year > 9999) codecFail("out-of-range", `year ${year} is outside 0000–9999`);
    this.#reserve(TIMESTAMP_LENGTH);
    this.#putDigits(year, 4);
    this.#putDigits(date.getUTCMonth() + 1, 2);
    this.#putDigits(date.getUTCDate(), 2);
    this.#putDigits(date.getUTCHours(), 2);
    this.#putDigits(date.getUTCMinutes(), 2);
    this.#putDigits(date.getUTCSeconds(), 2);
    this.#putDigits(date.getUTCMilliseconds(), 3);
  }

  /** The concatenation of everything written so far. */
  toBytes(): Uint8Array<ArrayBuffer> {
    return this.#buffer.slice(0, this.#length);
  }

  #reserve(extra: number): void {
    const needed = this.#length + extra;

    if (needed <= this.#buffer.length) return;
    const grown = new Uint8Array(Math.max(needed, this.#buffer.length * 2));
    grown.set(this.#buffer.subarray(0, this.#length));
    this.#buffer = grown;
  }

  #putUInt32(value: number): void {
    const buffer = this.#buffer;
    const at = this.#length;
    buffer[at] = value >>> 24;
    buffer[at + 1] = (value >>> 16) & 0xff;
    buffer[at + 2] = (value >>> 8) & 0xff;
    buffer[at + 3] = value & 0xff;
    this.#length = at + 4;
  }

  #putUInt64(value: bigint): void {
    const [high, low] = split(value);
    this.#putUInt32(high);
    this.#putUInt32(low);
  }

  /** Writes the canonical length determinant; the caller reserved 5 bytes. */
  #putLength(length: number): void {
    if (length < 0x80) {
      this.#buffer[this.#length++] = length;

      return;
    }

    const bytes = lengthWidth(length) - 1;
    this.#buffer[this.#length++] = 0x80 | bytes;

    for (let shift = (bytes - 1) * 8; shift >= 0; shift -= 8) this.#buffer[this.#length++] = (length >>> shift) & 0xff;
  }

  #putDigits(value: number, width: number): void {
    let rest = value;

    for (let i = this.#length + width - 1; i >= this.#length; i--) {
      this.#buffer[i] = 0x30 + (rest % 10);
      rest = Math.floor(rest / 10);
    }

    this.#length += width;
  }
}

/**
 * Runs `read` against `bytes`, returning its value or the {@link IlpCodecError} it threw.
 * Other exceptions are defects and propagate.
 */
export function readOer<A>(bytes: Uint8Array, read: (reader: OerReader) => A): Result.Result<A, IlpCodecError> {
  return Result.try({
    try: () => read(new OerReader(bytes)),
    catch: (error) => {
      if (error instanceof IlpCodecError) return error;
      throw error;
    },
  });
}

/** Runs `write` against a fresh {@link OerWriter}, returning the bytes or the {@link IlpCodecError} it threw. */
export function writeOer(write: (writer: OerWriter) => void): Result.Result<Uint8Array<ArrayBuffer>, IlpCodecError> {
  return Result.try({
    try: () => {
      const writer = new OerWriter();
      write(writer);

      return writer.toBytes();
    },
    catch: (error) => {
      if (error instanceof IlpCodecError) return error;
      throw error;
    },
  });
}

function checkUInt64(value: bigint): bigint {
  if (value < 0n || value > MAX_UINT64) {
    codecFail("out-of-range", `${String(value)} is not a uint64`);
  }

  return value;
}

/** High and low 32 bits of a uint64; values below 2^53 avoid `BigInt` arithmetic. */
function split(value: bigint): readonly [high: number, low: number] {
  if (value <= MAX_SAFE) {
    const number = Number(value);

    return [Math.floor(number / TWO_32), number >>> 0];
  }

  return [Number(value >> 32n), Number(value & MASK_32)];
}

/** Bytes needed for `value` (a uint32), at least one. */
function byteWidth(value: number): number {
  return value < 0x100 ? 1 : value < 0x1_0000 ? 2 : value < 0x100_0000 ? 3 : 4;
}

/** Total bytes of the canonical length determinant for `length`. */
function lengthWidth(length: number): number {
  return length < 0x80 ? 1 : 1 + byteWidth(length);
}

/** Days in `month` (1–12) of the proleptic Gregorian `year`. */
function daysInMonth(year: number, month: number): number {
  if (month === 2) return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28;

  // 31 days in odd months up to July and even months from August.
  return 30 + ((month + (month >> 3)) & 1);
}
