/**
 * URL helpers shared by every subpath. Web Standards only.
 * @internal Not exported from any public entry point.
 */

const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** Whether a WHATWG `URL.hostname` is the user's own machine (IPv6 literals keep their brackets). */
export const isLoopbackHost = (hostname: string): boolean => LOOPBACK_HOSTS.has(hostname);
