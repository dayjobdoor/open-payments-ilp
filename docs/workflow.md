# Workflow

How changes get into `main` and onto npm. History is managed with [jj](https://jj-vcs.github.io/jj/) colocated with git (`.jj/` and `.git/` both exist). Use jj commands; avoid `git commit`, `git add`, `git checkout`, `git reset` and `git stash` (they confuse jj's state; park work with `jj new`).

## jj

- The working copy `@` is always one commit; edits update it, no `git add`. `◆` is immutable (pushed), `○` is mutable. Bookmarks (git branches) do not move on their own.
- git hooks do not run for jj commits: checks live in CI, and locally you run `mise run check` yourself before pushing.
- Commit messages: `feat:` `fix:` `test:` `docs:` `chore:`. A commit without a description cannot be pushed.

```sh
jj st                              # changes in @
jj commit -m "feat: ..." <paths>   # describe + start a new @ (paths limit what is committed)
jj split -m "fix: ..." <paths>     # cut <paths> out of @
jj undo                            # undo the last operation; `jj op log` lists them all
```

- Push straight to `main`, no pull requests, no long-lived branches:

  ```sh
  jj git fetch && jj rebase -d main@origin
  mise run check
  jj bookmark set main -r @-
  jj git push --bookmark main --dry-run && jj git push --bookmark main
  ```

- Never rewrite commits that are already pushed (`◆`).
- The global git ignore on a machine may exclude files such as `bun.lock` or `*.sql`. Ignored new files do not show in `jj st` and are not committed. This repo re-includes `bun.lock` with `!bun.lock` in `.gitignore`; check `jj st` after adding a file, and use `jj file track --include-ignored <path>` for an ignored one.

## Accounts, SSH and gh

The repository belongs to one GitHub account; the machine may hold several. Keep each account's key and identity local to this clone.

- Commit identity: the account's `users.noreply.github.com` address (GitHub Settings → Emails). For jj, a scoped config in `~/.config/jj/config.toml` (`[[--scope]]` with `--when.repositories = ["<parent directory>"]`, then `[--scope.user]` with `name` and `email`), or `jj config set --repo user.email ...`. Check with `jj log -r @ -T 'author.email()'` before pushing. An author already committed is rewritten with `jj metaedit --update-author -r <rev>` (unpushed commits only).
- Push identity (git side): `git config core.sshCommand "ssh -i ~/.ssh/<key> -o IdentitiesOnly=yes -o IdentityAgent=none"` in this clone, so the agent's other keys are not offered first. A push that says `Permission ... denied to <other account>` used the wrong key. Verify a key with `ssh -F /dev/null -i ~/.ssh/<key> -o IdentitiesOnly=yes -T git@github.com` (it prints the account name).
- `gh` is logged in as whichever accounts `gh auth status` lists. Read-only calls on this public repository work without a login (`gh api repos/<owner>/<repo>/...`); anything that writes needs the owning account's token, so prefer `git`/`jj` over the API for writes.
- Useful read-only checks: `gh run list -R <owner>/<repo>`, `gh run view <id> --log-failed`, `gh api repos/<owner>/<repo>/environments/npm-publish --jq .protection_rules` (must list `required_reviewers`).

## Releasing

Releases are keyless: `.github/workflows/publish.yml` runs on every push to `main`, publishes only when npm does not yet have the `package.json` version, and authenticates with npm trusted publishing (OIDC, no token).

1. Bump `version` in `package.json` and add a `## <version> (date)` heading to `CHANGELOG.md`. The dist-tag follows the version: `x.y.z-alpha.N` → `alpha`, `-beta.N` → `beta`, another prerelease id → `next`, a plain version → `latest`.
2. `mise run check`, commit, push to `main`.
3. The `plan` and `verify` jobs run; the `publish` job waits for the maintainer's approval in the `npm-publish` GitHub environment (required reviewers). After approval it publishes with provenance, pushes the tag `v<version>` and creates a GitHub Release from that version's CHANGELOG section (a prerelease for any non-`latest` dist-tag).
4. Check: `npm view open-payments-ilp dist-tags versions --json`; `npm view open-payments-ilp@<version> dist.attestations`.

The first publish of a name, `npm trust`, `npm deprecate`, `npm owner`, `npm access` and token management need the maintainer's interactive 2FA login; they are never run from CI or by an agent. Trust configuration expires if no publish succeeds within two days. `latest` cannot be removed from a package; it moves when the first stable version ships.

Branch rules: a ruleset on `main` blocks force-push and deletion and requires the `check` CI job (the repository admin bypasses it, so direct pushes keep working); `v*` tags cannot be moved or deleted. Dependabot (`.github/dependabot.yml`) opens weekly PRs for Actions and bun dependencies; merge them after CI passes.
