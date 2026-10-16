const ILP_ADDRESS_PATTERN = /^(?:g|private|example|peer|self|test[1-3]?|local)(?:\.[A-Za-z0-9_~-]+)+$/;

/** @internal Longest valid ILP address (RFC 15). */
export const ILP_ADDRESS_MAX_LENGTH = 1023;

/**
 * Whether `value` is a valid ILP address per RFC 15: an allocation scheme
 * (`g`, `private`, `example`, `peer`, `self`, `test`, `test1`–`test3`, `local`) followed by
 * one or more `.`-separated segments of `[A-Za-z0-9_~-]`, at most 1023 characters.
 *
 * @see https://interledger.org/developers/rfcs/ilp-addresses/
 */
export function isValidIlpAddress(value: string): boolean {
  return value.length <= ILP_ADDRESS_MAX_LENGTH && ILP_ADDRESS_PATTERN.test(value);
}
