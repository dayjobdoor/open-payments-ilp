/**
 * URL helpers shared by `gnap/server` and `hono`. Web Standards only.
 * @internal Not exported from any public entry point.
 */

const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Whether a WHATWG `URL.hostname` is one of the three canonical loopback names `localhost`, `127.0.0.1` and `[::1]`
 * (IPv6 literals keep their brackets). Other loopback spellings (`127.0.0.2`, `foo.localhost`, `[::ffff:7f00:1]`)
 * are not matched.
 */
export const isLoopbackHost = (hostname: string): boolean => LOOPBACK_HOSTS.has(hostname);
