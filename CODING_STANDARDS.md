# Coding standards

Read during review, not while implementing. Mechanical rules are not here: formatting, lint, and `SAFETY:` comments on type assertions are enforced by `mise run check`. This file holds judgement calls.

## Compatibility and docs

- A behaviour change that a client, a store or a consumer can observe updates `CHANGELOG.md` and a row of [docs/compatibility.md](docs/compatibility.md) in the same change. A stricter-than-the-counterpart behaviour is a "deviation" row with its opt-out, if there is one.
- Every concrete claim in a README section or a doc comment (a name, a default, a status code, an error `reason`, "never", "always", "only") is checked against the code it describes. A claim you cannot check is removed or marked unverified.
- A new option or public export appears in its README subpath section, and in `/plain/*` when its Effect counterpart has one.

## Ports and plain entries

- A change to a port (`GnapStore`) is additive: an optional field behind a capability flag, a new case in `storeContract` that runs only for stores that set the flag, and the flag copied by `src/internal/plain-gnap.ts` in both directions.
- `src/plain/*` has no logic of its own. A function that exists only there belongs in the Effect module first. Every export of a plain entry returns a value or a `Promise`, never an `Effect` or a `Result` (`test/plain/no-effect-leak.test.ts` fails otherwise).

## Untrusted input and security

- Anything read from the network or a request is bounded in size, count and time before it is parsed. A numeric option is validated finite and in range; an invalid one fails closed instead of switching a check off.
- Secrets and digests compare in constant time. A new outbound URL passes the same scheme, credential and host checks as the existing ones (`isPublicHttpsUrl`, the client's URL policy).
- A decision, token or session is tied to what the user saw or the browser that started it, not only to an identifier that can be copied. A write that can lose an optimistic-lock race re-checks the fields it was computed from.

## Errors

- Each module fails with its own tagged error and a kebab-case `reason`; a new reason is documented where the module's other reasons are. An unexpected failure is a defect, not a typed failure.

## Tests

- Behaviour first: assert the observable result and the error `reason`, not that something threw. No test without an assertion; no `try`/`catch` without a failure path.
- Deterministic: inject the clock, seed randomness, no wall-clock sleeps beyond a few milliseconds.
- A security fix has a test that fails without it. A type-level check has a control that can fail.

## Comments

- A comment states a constraint, a unit, a trust boundary or a reason, not what the code does or how it changed. It is checked against the code (see Compatibility and docs).
