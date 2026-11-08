import { canonicalize } from "json-canonicalize";
import * as Result from "effect/Result";
import { describe, expect, it } from "vite-plus/test";
import { canonicalizeJson, type JsonValue } from "../../src/webhooks/index";
import { prng } from "../support/prng";

const canon = (value: JsonValue): string => {
  const result = canonicalizeJson(value);

  if (Result.isFailure(result)) throw result.failure;

  return result.success;
};

const failureReason = (value: JsonValue): string | undefined => {
  const result = canonicalizeJson(value);

  return Result.isFailure(result) ? result.failure.reason : undefined;
};

const double = (hex: string): number =>
  new DataView(new BigUint64Array([BigInt(`0x${hex}`)]).buffer).getFloat64(0, true);

describe("RFC 8785 Appendix B number serialisation", () => {
  it.each([
    ["0000000000000000", "0"],
    ["8000000000000000", "0"],
    ["0000000000000001", "5e-324"],
    ["8000000000000001", "-5e-324"],
    ["7fefffffffffffff", "1.7976931348623157e+308"],
    ["ffefffffffffffff", "-1.7976931348623157e+308"],
    ["4340000000000000", "9007199254740992"],
    ["c340000000000000", "-9007199254740992"],
    ["4430000000000000", "295147905179352830000"],
    ["44b52d02c7e14af5", "9.999999999999997e+22"],
    ["44b52d02c7e14af6", "1e+23"],
    ["44b52d02c7e14af7", "1.0000000000000001e+23"],
    ["444b1ae4d6e2ef4e", "999999999999999700000"],
    ["444b1ae4d6e2ef4f", "999999999999999900000"],
    ["444b1ae4d6e2ef50", "1e+21"],
    ["3eb0c6f7a0b5ed8c", "9.999999999999997e-7"],
    ["3eb0c6f7a0b5ed8d", "0.000001"],
    ["41b3de4355555553", "333333333.3333332"],
    ["41b3de4355555555", "333333333.3333333"],
    ["41b3de4355555557", "333333333.33333343"],
    ["becbf647612f3696", "-0.0000033333333333333333"],
    ["43143ff3c1cb0959", "1424953923781206.2"],
  ])("%s serialises as %s", (bits, text) => {
    expect(canon(double(bits))).toBe(text);
  });

  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])("rejects %s", (value) => {
    const result = canonicalizeJson(value);

    expect(Result.isFailure(result) && result.failure).toMatchObject({
      _tag: "WebhookError",
      reason: "unsupported-value",
    });
  });
});

describe("RFC 8785 §3.2.3 property sorting", () => {
  it("orders keys by UTF-16 code units and escapes only what JSON requires", () => {
    const input: JsonValue = {
      "\u20ac": "Euro Sign",
      "\r": "Carriage Return",
      "\ufb33": "Hebrew Letter Dalet With Dagesh",
      "1": "One",
      "\ud83d\ude00": "Emoji: Grinning Face",
      "\u0080": "Control",
      "\u00f6": "Latin Small Letter O With Diaeresis",
    };

    expect(canon(input)).toBe(
      '{"\\r":"Carriage Return","1":"One","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis",' +
        '"\u20ac":"Euro Sign","\ud83d\ude00":"Emoji: Grinning Face","\ufb33":"Hebrew Letter Dalet With Dagesh"}',
    );
  });

  it("escapes control characters, quotes and backslashes in lower-case hex", () => {
    expect(canon('\u0000\u001f\b\t\n\f\r"\\/\u007f')).toBe('"\\u0000\\u001f\\b\\t\\n\\f\\r\\"\\\\/\u007f"');
  });
});

describe("structure", () => {
  it("drops undefined members and nulls undefined array elements like json-canonicalize", () => {
    // SAFETY: untyped input as it arrives from JavaScript callers.
    const input = { b: undefined, a: [1, undefined, { z: undefined, y: 2 }] } as never;

    expect(canon(input)).toBe('{"a":[1,null,{"y":2}]}');
    expect(canon(input)).toBe(canonicalize(input));
  });

  it("rejects cycles but not repeated references", () => {
    const shared = { x: 1 };
    const cyclic: { [key: string]: JsonValue } = {};

    cyclic["self"] = cyclic;

    expect(canon([shared, shared])).toBe('[{"x":1},{"x":1}]');
    expect(failureReason(cyclic)).toBe("unsupported-value");
  });

  it("rejects a cycle through an array as well", () => {
    const cyclic: JsonValue[] = [1];

    cyclic.push(cyclic);

    expect(failureReason(cyclic)).toBe("unsupported-value");
    expect(failureReason({ list: cyclic })).toBe("unsupported-value");
  });

  it("rejects values JSON cannot carry", () => {
    // SAFETY: deliberately outside JsonValue.
    const bigint = 10n as never;
    // SAFETY: deliberately outside JsonValue.
    const withFunction = { f: () => 1 } as never;

    expect(failureReason(bigint)).toBe("unsupported-value");
    expect(failureReason(withFunction)).toBe("unsupported-value");
  });

  it("serialises nesting of any depth without overflowing the stack", () => {
    const depth = 100_000;
    let deepArray: JsonValue = [];
    let deepObject: JsonValue = {};

    for (let level = 1; level < depth; level++) {
      deepArray = [deepArray];
      deepObject = { a: deepObject };
    }

    expect(canon(deepArray)).toBe(`${"[".repeat(depth)}${"]".repeat(depth)}`);
    expect(canon(deepObject)).toBe(`${'{"a":'.repeat(depth - 1)}{}${"}".repeat(depth - 1)}`);
  });

  it("still detects a cycle at great depth", () => {
    const root: { [key: string]: JsonValue } = {};
    let tip = root;

    for (let level = 0; level < 10_000; level++) {
      const child: { [key: string]: JsonValue } = {};

      tip["child"] = child;
      tip = child;
    }

    tip["root"] = root;

    expect(failureReason(root)).toBe("unsupported-value");
  });

  it("fails on a toJSON member that JSON.stringify cannot serialise", () => {
    // SAFETY: deliberately outside JsonValue.
    const returnsNothing = { toJSON: () => undefined } as never;
    // SAFETY: deliberately outside JsonValue.
    const throws = { toJSON: () => 10n } as never;

    expect(failureReason(returnsNothing)).toBe("unsupported-value");
    expect(failureReason(throws)).toBe("unsupported-value");
  });
});

function randomJson(next: () => number, depth: number): JsonValue {
  const kinds = depth > 3 ? 5 : 7;
  const kind = next() % kinds;

  if (kind === 0) return null;

  if (kind === 1) return next() % 2 === 0;

  if (kind === 2) return (next() % 2_000_001) - 1_000_000;

  if (kind === 3) return (next() / 4294967296) * 10 ** ((next() % 60) - 30);

  if (kind === 4) return randomString(next);

  if (kind === 5) return Array.from({ length: next() % 5 }, () => randomJson(next, depth + 1));

  const object: { [key: string]: JsonValue } = {};

  for (let index = next() % 6; index > 0; index--) object[randomString(next)] = randomJson(next, depth + 1);

  return object;
}

const ALPHABET = ["a", "Z", "0", "é", "€", "😀", "\u0000", "\n", '"', "\\", "/", "\u2028", "\ufb33", " "];

function randomString(next: () => number): string {
  return Array.from({ length: next() % 6 }, () => ALPHABET[next() % ALPHABET.length]).join("");
}

/**
 * What json-canonicalize hands to `JSON.stringify`, which keeps members in insertion order: an object with a non-null
 * `toJSON` member (a method, or a value that `JSON.stringify` ignores as one) and a `Date`. Not JSON values, so cast.
 */
function randomToJsonLeaf(next: () => number): JsonValue {
  const kind = next() % 8;
  const payload = randomJson(next, 2);

  switch (kind) {
    // SAFETY: deliberately outside JsonValue (all cases below).
    case 0:
      return { b: 1, toJSON: payload, a: 2 } as never;
    case 1:
      return { z: randomString(next), toJSON: [0, 1], a: payload } as never;
    case 2:
      return { b: payload, toJSON: () => payload, a: [3, { y: 1, x: 2 }] } as never;
    case 3:
      return new Date(next() * 1000) as never;
    case 4:
      return new Date(Number.NaN) as never;
    case 5:
      return [1, new Date(next() * 1000), { toJSON: "text", k: 1 }] as never;
    // `toJSON: null` is not a toJSON member: the object is sorted like any other.
    case 6:
      return { b: payload, toJSON: null, a: 1 } as never;
    default:
      return { toJSON: 0, nested: { b: 1, a: payload } } as never;
  }
}

function randomToJsonDocument(next: () => number): JsonValue {
  const leaves = Array.from({ length: 1 + (next() % 3) }, () => randomToJsonLeaf(next));

  if (next() % 2 === 0) return leaves;

  const object: { [key: string]: JsonValue } = {};

  for (const leaf of leaves) object[randomString(next)] = leaf;

  // A fresh leaf, not a shared one: json-canonicalize reports a repeated reference as a cycle when one member path is a prefix of the other's (`$.` and `$.a`).
  return { ...object, "~": randomJson(next, 2), a: randomToJsonLeaf(next) };
}

describe("differential against json-canonicalize", () => {
  it("agrees on 2000 deterministic random documents", () => {
    const next = prng(0x8785);

    for (let index = 0; index < 2000; index++) {
      const value = randomJson(next, 0);

      expect(canon(value)).toBe(canonicalize(value));
    }
  });

  it("agrees on 2000 documents with toJSON members and Dates, which json-canonicalize serialises with JSON.stringify", () => {
    const next = prng(0x7501);
    let withToJsonMember = 0;
    let withDate = 0;

    for (let index = 0; index < 2000; index++) {
      const value = randomToJsonDocument(next);
      const expected = canonicalize(value);

      expect(canon(value)).toBe(expected);

      if (expected.includes('"toJSON":')) withToJsonMember++;

      if (/"\d{4}-\d\d-\d\dT[\d:.]+Z"/.test(expected)) withDate++;
    }

    // Guards against a generator that never produces the cases it exists for.
    expect(withToJsonMember).toBeGreaterThan(500);
    expect(withDate).toBeGreaterThan(200);
  });

  it("serialises an object with a toJSON member in insertion order, as Rafiki signs it", () => {
    // SAFETY: deliberately outside JsonValue.
    const metadata = { toJSON: 1, b: 1, a: 2 } as never;
    const event = { id: "e", type: "incoming_payment.created", data: { metadata } };

    expect(canon({ toJSON: 1, b: 1, a: 2 } as never)).toBe('{"toJSON":1,"b":1,"a":2}');
    expect(canon(event)).toBe(
      '{"data":{"metadata":{"toJSON":1,"b":1,"a":2}},"id":"e","type":"incoming_payment.created"}',
    );
    expect(canon(event)).toBe(canonicalize(event));
  });

  it("serialises a Date as its ISO string and a toJSON method by its result", () => {
    // SAFETY: deliberately outside JsonValue.
    const date = new Date(Date.UTC(2024, 0, 2, 3, 4, 5, 6)) as never;
    // SAFETY: deliberately outside JsonValue.
    const method = { toJSON: () => ({ b: 1, a: 2 }) } as never;

    expect(canon(date)).toBe('"2024-01-02T03:04:05.006Z"');
    expect(canon({ at: date })).toBe('{"at":"2024-01-02T03:04:05.006Z"}');
    expect(canon(method)).toBe('{"b":1,"a":2}');
    expect(canon([date, method])).toBe(canonicalize([date, method]));
  });

  it("agrees on the Rafiki event shape", () => {
    const event = {
      id: "6f1a9e2e-1111-4c2a-9f4e-0123456789ab",
      type: "incoming_payment.completed",
      data: { receivedAmount: { value: "100", assetCode: "USD", assetScale: 2 }, completed: true, metadata: null },
    };

    expect(canon(event)).toBe(canonicalize(event));
  });
});
