# Security policy

## Supported versions

Only the latest `alpha` release (see `npm view open-payments-ilp dist-tags`). Fixes ship as a new prerelease.

## Reporting a vulnerability

Report privately through [GitHub private vulnerability reporting](https://github.com/dayjobdoor/open-payments-ilp/security/advisories/new). Do not open a public issue or PR. Include the subpath (`open-payments-ilp/<subpath>`), version and a reproduction. Expect an acknowledgement within a week.

In scope: HTTP message signature verification, GNAP grant, token and interaction handling (including the Better Auth plugin), webhook signature checks, ILP/STREAM codec parsing of untrusted packets.
