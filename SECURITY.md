# Security policy

## Supported versions

Only the latest `alpha` release (see `npm view open-payments-ilp dist-tags`). Fixes ship as a new prerelease.

## Reporting a vulnerability

Report privately through [GitHub private vulnerability reporting](https://github.com/dayjobdoor/open-payments-ilp/security/advisories/new). Do not open a public issue or PR. Include the subpath (`open-payments-ilp/<subpath>`), version and a reproduction. Expect an acknowledgement within a week.

In scope: HTTP message signature verification, GNAP grant, token and interaction handling (including the Better Auth plugin), the Hono GNAP client and its session cookies, the Open Payments client (URL handling, redirects, response limits), webhook signature checks, ILP/STREAM codec parsing of untrusted packets, and the `/plain/*` entry points, which wrap the same code.

Known limitation: with the `x-idp-secret` identity provider back channel the GNAP server never sees the consenting browser, so an attacker who opens `interact.redirect` first and gets the owner to approve through the identity provider can still finish in their own browser. The identity provider has to bind its consent to the browser that arrived from `/interact` (the browser binding of `interactionBinding` covers the `/finish` step and consent made with a `userId`).
