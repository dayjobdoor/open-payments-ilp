import { describe, expect, it } from "vite-plus/test";
import { isLoopbackHost } from "../../src/internal/url";

/** `URL.hostname` of `href`, as callers pass it (IPv6 literals keep their brackets). */
const hostnameOf = (href: string): string => new URL(href).hostname;

describe("isLoopbackHost", () => {
  it.each(["localhost", "127.0.0.1", "[::1]"])("is true for %s", (hostname) => {
    expect(isLoopbackHost(hostname)).toBe(true);
  });

  it.each([
    ["http://localhost:3000/", true],
    ["http://127.0.0.1/", true],
    ["http://[::1]:8080/path", true],
    ["http://LOCALHOST/", true],
    // The WHATWG URL parser rewrites these spellings to the canonical names before the check sees them.
    ["http://127.1/", true],
    ["http://0x7f.0.0.1/", true],
    ["http://2130706433/", true],
    ["http://[0:0:0:0:0:0:0:1]/", true],
    ["http://[::ffff:127.0.0.1]/", false],
    ["http://127.0.0.2/", false],
  ])("treats the hostname of %s, as URL normalises it, as loopback: %s", (href, expected) => {
    expect(isLoopbackHost(hostnameOf(href))).toBe(expected);
  });

  it.each([
    "example.com",
    "localhost.example.com",
    "foo.localhost",
    "127.0.0.2",
    "127.0.0.1.example.com",
    "0.0.0.0",
    "::1",
    "[::ffff:127.0.0.1]",
    "[::ffff:7f00:1]",
    "[::2]",
    "",
    " localhost",
    "localhost ",
    "localhost.",
    "LOCALHOST",
  ])("is false for %j", (hostname) => {
    expect(isLoopbackHost(hostname)).toBe(false);
  });

  it("matches the WHATWG hostname exactly: an unbracketed IPv6 literal is not what URL.hostname returns", () => {
    expect(hostnameOf("http://[::1]/")).toBe("[::1]");
    expect(isLoopbackHost("::1")).toBe(false);
  });
});
