# Development process

## Commit conventions

Commits follow [Conventional Commits](https://www.conventionalcommits.org/): `type(scope)?: subject`
with the standard types (`feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`, `ci`, `build`).

The subject stays **imperative and describes what was done**: "fix: bound session reads by a deadline",
not "fixed timeouts". A mixed change takes its most significant type (`fix` over `refactor` over
`test`) rather than splitting hairs.

**Never add an AI co-author or attribution trailer.**

## The `api` scope

The engine is embedded downstream at the `ekvm-engine` library's public API, pinned by git rev, so a change to
that surface is committed with the `api` scope:

- `Sandbox`, `Limits`, `RunResult`
- `VmmError`, including its variants *and* the `kind()` bucket mapping
- the `ekvm-channel` wire protocol
- the daemon's `ekvm-protocol` wire types

Use `feat(api):` or `fix(api):`, with `!` appended when the change is incompatible. The point is
legibility: a downstream pin bump should be auditable from the log alone, without reading diffs.
Internal-only changes do not use the scope.

Adding a `VmmError` variant is additive rather than breaking, because the enum is `#[non_exhaustive]`
and `kind()`'s match is wildcard-free, so the compiler forces the new variant into a deliberate bucket.

## Backwards compatibility

- Keep public struct fields private, with a builder.
- Annotate public enums `#[non_exhaustive]`.
- Use `#[serde(default)]` for optional wire fields.
- After the first tag, verify with
  `cargo semver-checks check-release --baseline-rev v0.1.0`.

## Pull requests are human-owned

A **coding agent** (Claude, Gemini, Codex, as opposed to this project's own `ekvm` binary) never
opens, approves, or merges a pull request. Asking another human to accept work, and reviewing it, are
human steps. That part is not configurable: an agent that can approve its own change has removed the
only review the change was going to get.

**Whether an agent commits and pushes is the operator's call.** Nothing in the project forbids it, so
it comes down to how the person running the agent wants to work. When an agent does commit:

- One logical change per commit, so the log stays bisectable.
- [Conventional Commits](#commit-conventions), with the [`api` scope](#the-api-scope) where it applies.
- **Never an AI co-author or attribution trailer.**
- Branch first if the checkout is on the default branch. A commit is cheap to amend; a push to `main`
  is the one that is awkward to undo.

Release tags remain a human step. See [RELEASES.md](../RELEASES.md).

## Documentation conventions

Doc files are flat in `docs/` and named `<topic>-<subtopic>.md`, so a nested chapter carries its
parent's prefix (`cli-install.md`, `contributing-testing.md`). The hierarchy lives in `SUMMARY.md`
rather than in directories, which keeps every cross-link a bare `./sibling.md` and keeps a chapter's
published URL stable when its place in the reading order changes.

What the [prose-drift lint](./contributing-ci.md#the-host-safe-gate) enforces: backticked repo
paths, relative Markdown links, the `#section` anchor on those links, and any `cargo … -p` package
name must all resolve. What it does not: whether the prose around a working pointer is still true.

On voice, the rule is to claim nothing the project cannot back. Describe mechanisms, which a diff can
falsify. Where a test backs a statement, make the test the grammatical subject. An absolute is fine
when the sentence names its enforcer (`#![forbid(unsafe_code)]`, a wildcard-free `match`); it is not
fine when the enforcer is "the implementation being correct". Prose uses colons, commas, or parentheses
rather than em-dashes.
