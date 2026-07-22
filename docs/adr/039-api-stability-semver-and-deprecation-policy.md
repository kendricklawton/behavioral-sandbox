# 039. API stability: a semver and deprecation policy, written now, in force at `v0.1.0` *(2026-07-22)*

**Context.** The engine is embedded downstream at the `vmm` library's public API and the `channel`
wire protocol, pinned by git rev. That pinned surface is named precisely in `AGENTS.md`: `Sandbox`,
`Limits`, `RunResult`, `VmmError` (its variants *and* the `kind()` -> `ErrorKind` bucketing), and the
`channel` wire protocol. The **mechanism** for signalling change already exists and is good: every
change to that surface carries an `api:` commit marker (with `!` for an incompatibility), so a pin
bump is auditable from the git log alone; the JSON surfaces carry a versioned `schema` field
(decision 028); the wire API negotiates a version and makes skew a typed error (decision 030). What
does **not** exist is the **promise**: a team evaluating the engine for a product cannot read "what
will you not break, and how will you tell me before you do." That policy was scheduled post-tag (it
lived inside the Phase 21 wire-spec box). But the policy *text* costs nothing to write now and is
exactly what an adopter reads before betting on the API; only its *enforcement* (a released version
number to bump, a curated changelog, the Rust support window) needs the tag.

**Decision.** Write the semver and deprecation policy now. It takes effect at `v0.1.0`; before then,
the existing markers are the only signal and everything is disposable (decision 035). The policy:

- **Post-`v0.1.0`, the crate version is semver over the pinned surface.**
  - **MAJOR:** an incompatible change to `Sandbox` / `Limits` / `RunResult` / `VmmError` (a removed
    or renamed variant, or a changed `kind()` bucket) / the `channel` wire protocol. Raising a
    `Limits` default is breaking (it is load-bearing, per `embedding.md`), so it is MAJOR.
  - **MINOR:** an additive change. A new method, a new `VmmError` variant (the enum is
    `#[non_exhaustive]`, so adding one is compatible), a new optional field, a new capability behind
    a default that preserves old behavior.
  - **PATCH:** a behavior-preserving fix.
- **Pre-`v0.1.0`, there is no version to bump.** The `api:` / `!` markers and the `schema` field are
  the signal; downstream pins by git rev (`embedding.md`). This is unchanged.
- **Deprecation window.** An item slated for removal is marked `#[deprecated]` in one MINOR, keeps
  working for at least one further MINOR, and is removed no earlier than the next MAJOR. The JSON and
  wire `schema` versions move by their own rule (additive within a version; a rename or removal bumps
  the integer, decisions 028 and 030), independent of the crate's semver.
- **The Rust support window stays deferred to `v0.1.0`** (decision 037): before the tag, supported
  Rust is current stable, pinned; the last-three-stable window is revisited at the tag. Unchanged
  here.
- **Enforcement and the changelog begin at the tag.** `RELEASES.md` already carries the release
  mechanics and the "no `CHANGELOG.md` until `v0.1.0`" stance; curated release notes start there.

**Alternatives considered.**
- **Leave the whole thing to Phase 21, post-tag.** Rejected. The wire-spec freeze and the
  cross-language conformance suite genuinely belong post-tag, but the *written policy* is what an
  evaluator reads *before* adopting, and withholding it until after the tag is a self-inflicted "no
  stated stability promise" gap. Writing it now, in force later, costs nothing and closes that gap;
  the Phase 21 box is reworded from "write a semver policy" to "apply and enforce this one across the
  SDKs and the wire spec."
- **Start enforcing semver now (tag `v0.0.x` with promises).** Rejected. Pre-rename and pre-`v0.1.0`,
  every tag is a disposable checkpoint (decision 035, `RELEASES.md`), and the public identifiers still
  churn once at the rename (the working name is not final). A stability promise made before the name
  is final is a promise you will break; the policy correctly waits for the tag to bind.

**Consequences and notes.**
- **No new code.** The signalling machinery (`api:` / `!` markers, the `schema` field, the wire
  version handshake) already exists; this decision writes down what they mean and when the promise
  binds. Its reader-facing home is `docs/stability.md`.
- **One place to read the promise.** Before this, an embedder had to infer the contract from
  `AGENTS.md`'s commit convention plus `embedding.md`'s pin note plus `RELEASES.md`; now the semver
  and deprecation rules are stated as policy, cited from all three.

**As shipped.** This decision and `docs/stability.md` state the policy; `RELEASES.md` carries the
release mechanics; the Phase 21 wire-spec box is reworded to apply this policy rather than to invent
one. No code change: the markers and schema versioning it formalizes are already in the tree.
