import * as Result from "effect/Result";
import { decodeBase64, encodeBase64 } from "../internal/bytes";
import { HttpSignatureError } from "./errors";

/** A bare item of RFC 8941 (§3.3). Dates and display strings (RFC 9651) are not supported. */
export type SfBareItem =
  | { readonly type: "integer" | "decimal"; readonly value: number }
  | { readonly type: "string" | "token"; readonly value: string }
  | { readonly type: "binary"; readonly value: Uint8Array }
  | { readonly type: "boolean"; readonly value: boolean };

/** Ordered parameters (§3.1.2). Keys are unique. */
export type SfParams = ReadonlyArray<readonly [string, SfBareItem]>;

/** An item with parameters (§3.3). */
export interface SfItem {
  readonly value: SfBareItem;
  readonly params: SfParams;
}

/** An inner list with parameters (§3.1.1). */
export interface SfInnerList {
  readonly items: ReadonlyArray<SfItem>;
  readonly params: SfParams;
}

/** A dictionary (§3.2) as ordered, unique-keyed entries. */
export type SfDictionary = ReadonlyArray<readonly [string, SfItem | SfInnerList]>;

/** Internal control-flow signal; always converted to an `HttpSignatureError` at the public boundary. */
class SfSyntaxError extends Error {}

const DIGIT = /[0-9]/;

const ALPHA = /[A-Za-z]/;

const KEY_START = /[a-z*]/;

const KEY_CHAR = /[a-z0-9_\-.*]/;

const TOKEN_CHAR = /[A-Za-z0-9!#$%&'*+\-.^_`|~:/]/;

const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;

function fail(message: string): never {
  throw new SfSyntaxError(message);
}

class Parser {
  private pos = 0;

  constructor(private readonly input: string) {}

  private peek(): string {
    return this.input.charAt(this.pos);
  }

  private get done(): boolean {
    return this.pos >= this.input.length;
  }

  private skipSp(): void {
    while (this.peek() === " ") this.pos++;
  }

  private skipOws(): void {
    while (this.peek() === " " || this.peek() === "\t") this.pos++;
  }

  dictionary(): SfDictionary {
    const entries: Array<readonly [string, SfItem | SfInnerList]> = [];
    const seen = new Set<string>();
    this.skipSp();

    while (!this.done) {
      const key = this.key();

      if (seen.has(key)) fail(`duplicate dictionary key "${key}"`);
      seen.add(key);
      let member: SfItem | SfInnerList;

      if (this.peek() === "=") {
        this.pos++;
        member = this.itemOrInnerList();
      } else {
        member = { value: { type: "boolean", value: true }, params: this.params() };
      }

      entries.push([key, member]);
      this.skipOws();

      if (this.done) break;

      if (this.peek() !== ",") fail("expected ',' between dictionary members");
      this.pos++;
      this.skipOws();

      if (this.done) fail("trailing comma");
    }

    return entries;
  }

  finish(): void {
    this.skipSp();

    if (!this.done) fail("unexpected trailing characters");
  }

  itemOrInnerList(): SfItem | SfInnerList {
    return this.peek() === "(" ? this.innerList() : this.item();
  }

  private innerList(): SfInnerList {
    this.pos++;
    const items: SfItem[] = [];

    for (;;) {
      this.skipSp();

      if (this.done) fail("unterminated inner list");

      if (this.peek() === ")") {
        this.pos++;

        return { items, params: this.params() };
      }

      items.push(this.item());

      if (this.peek() !== " " && this.peek() !== ")") fail("expected ' ' or ')' in inner list");
    }
  }

  private item(): SfItem {
    return { value: this.bareItem(), params: this.params() };
  }

  private params(): SfParams {
    const params: Array<readonly [string, SfBareItem]> = [];
    const seen = new Set<string>();

    while (this.peek() === ";") {
      this.pos++;
      this.skipSp();
      const key = this.key();

      if (seen.has(key)) fail(`duplicate parameter "${key}"`);
      seen.add(key);
      let value: SfBareItem = { type: "boolean", value: true };

      if (this.peek() === "=") {
        this.pos++;
        value = this.bareItem();
      }

      params.push([key, value]);
    }

    return params;
  }

  private key(): string {
    if (!KEY_START.test(this.peek())) fail("invalid key");
    const start = this.pos;

    while (!this.done && KEY_CHAR.test(this.peek())) this.pos++;

    return this.input.slice(start, this.pos);
  }

  private bareItem(): SfBareItem {
    const c = this.peek();

    if (c === "-" || DIGIT.test(c)) return this.number();

    if (c === '"') return { type: "string", value: this.string() };

    if (c === ":") return { type: "binary", value: this.binary() };

    if (c === "?") return { type: "boolean", value: this.boolean() };

    if (c === "*" || ALPHA.test(c)) return { type: "token", value: this.token() };

    return fail("unsupported bare item");
  }

  private number(): SfBareItem {
    const negative = this.peek() === "-";

    if (negative) this.pos++;

    if (!DIGIT.test(this.peek())) fail("number needs a digit");
    const start = this.pos;
    let decimal = false;

    while (!this.done) {
      const c = this.peek();

      if (DIGIT.test(c)) this.pos++;
      else if (!decimal && c === ".") {
        if (this.pos - start > 12) fail("decimal integer part too long");
        decimal = true;
        this.pos++;
      } else break;

      if (!decimal && this.pos - start > 15) fail("integer too long");

      if (decimal && this.pos - start > 16) fail("decimal too long");
    }

    const text = this.input.slice(start, this.pos);

    if (decimal && (text.endsWith(".") || text.length - text.indexOf(".") - 1 > 3)) fail("invalid decimal");
    const magnitude = Number(text);

    return { type: decimal ? "decimal" : "integer", value: negative ? -magnitude : magnitude };
  }

  private string(): string {
    this.pos++;
    let out = "";

    for (;;) {
      if (this.done) fail("unterminated string");
      const c = this.peek();
      this.pos++;

      if (c === "\\") {
        const next = this.peek();

        if (next !== '"' && next !== "\\") fail("invalid string escape");
        out += next;
        this.pos++;
      } else if (c === '"') {
        return out;
      } else {
        const code = c.charCodeAt(0);

        if (code < 0x20 || code > 0x7e) fail("invalid string character");
        out += c;
      }
    }
  }

  private token(): string {
    const start = this.pos;
    this.pos++;

    while (!this.done && TOKEN_CHAR.test(this.peek())) this.pos++;

    return this.input.slice(start, this.pos);
  }

  /** Only the canonical padded encoding is accepted: re-encoding must reproduce the input. */
  private binary(): Uint8Array {
    this.pos++;
    const end = this.input.indexOf(":", this.pos);

    if (end < 0) fail("unterminated byte sequence");
    const text = this.input.slice(this.pos, end);
    this.pos = end + 1;

    if (!BASE64.test(text) || text.length % 4 !== 0) fail("invalid base64");
    const bytes = decodeBase64(text);

    if (encodeBase64(bytes) !== text) fail("non-canonical base64");

    return bytes;
  }

  private boolean(): boolean {
    this.pos++;
    const c = this.peek();

    if (c !== "0" && c !== "1") fail("invalid boolean");
    this.pos++;

    return c === "1";
  }
}

function attempt<A>(what: string, run: () => A): Result.Result<A, HttpSignatureError> {
  try {
    return Result.succeed(run());
  } catch (error) {
    if (error instanceof SfSyntaxError) {
      return Result.fail(new HttpSignatureError({ reason: "malformed", message: `${what}: ${error.message}` }));
    }

    throw error;
  }
}

/**
 * Strict RFC 8941 dictionary parser. Rejects duplicate dictionary keys and duplicate parameters (RFC 8941 would
 * let the last win), trailing commas, non-canonical base64, and any trailing garbage.
 *
 * Fails with `HttpSignatureError` (`malformed`).
 *
 * @see https://www.rfc-editor.org/rfc/rfc8941#section-4.2.2
 */
export const parseDictionary: (input: string) => Result.Result<SfDictionary, HttpSignatureError> = (input) =>
  attempt("Invalid structured field dictionary", () => {
    const parser = new Parser(input);
    const dictionary = parser.dictionary();
    parser.finish();

    return dictionary;
  });

function serializeString(value: string): string {
  let out = '"';

  for (const c of value) {
    const code = c.charCodeAt(0);

    if (c.length !== 1 || code < 0x20 || code > 0x7e) fail("string is not printable ASCII");
    out += c === '"' || c === "\\" ? `\\${c}` : c;
  }

  return `${out}"`;
}

function serializeBare(item: SfBareItem): string {
  switch (item.type) {
    case "integer":
      if (!Number.isSafeInteger(item.value) || Math.abs(item.value) > 999_999_999_999_999) fail("integer out of range");

      return String(item.value);
    case "decimal": {
      const text = item.value.toFixed(3).replace(/0+$/, "");

      if (Math.abs(item.value) >= 1e12) fail("decimal out of range");

      return text.endsWith(".") ? `${text}0` : text;
    }

    case "string":
      return serializeString(item.value);
    case "token":
      if (!/^[A-Za-z*][A-Za-z0-9!#$%&'*+\-.^_`|~:/]*$/.test(item.value)) fail("invalid token");

      return item.value;
    case "binary":
      return `:${encodeBase64(item.value)}:`;
    case "boolean":
      return item.value ? "?1" : "?0";
  }
}

function serializeParams(params: SfParams): string {
  let out = "";

  for (const [key, value] of params) {
    if (!/^[a-z*][a-z0-9_\-.*]*$/.test(key)) fail(`invalid parameter key "${key}"`);
    out += value.type === "boolean" && value.value ? `;${key}` : `;${key}=${serializeBare(value)}`;
  }

  return out;
}

function serializeItemUnchecked(item: SfItem): string {
  return `${serializeBare(item.value)}${serializeParams(item.params)}`;
}

/**
 * RFC 8941 item serialization.
 *
 * Fails with `HttpSignatureError` (`malformed`) when a value cannot be represented (e.g. non-ASCII string).
 *
 * @see https://www.rfc-editor.org/rfc/rfc8941#section-4.1.3
 */
export const serializeItem: (item: SfItem) => Result.Result<string, HttpSignatureError> = (item) =>
  attempt("Cannot serialize item", () => serializeItemUnchecked(item));

/**
 * RFC 8941 inner list serialization, e.g. `("@method" "@target-uri");created=1`.
 *
 * Fails with `HttpSignatureError` (`malformed`) when a value cannot be represented.
 *
 * @see https://www.rfc-editor.org/rfc/rfc8941#section-4.1.1.1
 */
export const serializeInnerList: (list: SfInnerList) => Result.Result<string, HttpSignatureError> = (list) =>
  attempt(
    "Cannot serialize inner list",
    () => `(${list.items.map(serializeItemUnchecked).join(" ")})${serializeParams(list.params)}`,
  );
