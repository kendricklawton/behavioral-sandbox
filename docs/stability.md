# Stability & releases

If you are embedding the engine, this is the page that tells you **what will not break under you, and
how you will be told before it does**. The short version: before the first tagged release the API
moves by git rev and the commit log is the signal; from `v0.1.0` on, the pinned surface moves by
semver with a deprecation window.

## The pinned surface

The engine is embedded downstream at the `vmm` library's public API and the `channel` wire protocol.
The surface that carries a stability promise is exactly:

- `Sandbox`, `Limits`, `RunResult`
- `VmmError`, including its variants **and** the `kind()` -> `ErrorKind` bucket mapping
- the `channel` wire protocol

A change to any of these carries an `api:` marker in its commit (with `!` for an incompatible change),
so a downstream pin bump is auditable from the git log alone. See
[Using the engine API](./embedding.md) for the shape of that surface and why its defaults are
load-bearing.

## Before `v0.1.0`: pin by git rev

There is no released version yet, so there is no version number to bump. Downstream pins this crate by
git rev, and the signals of change are the `api:` / `!` commit markers, the versioned `schema` field
on the JSON surfaces
([decision 028](./adr/028-agent-doctor-shares-one-host-check-implementation-the.md)), and the wire
protocol's version handshake
([decision 030](./adr/030-the-wire-api-is-versioned-newline-json-in-a-shared.md)). Every pre-`v0.1.0`
tag is a disposable checkpoint with no stability promise
([decision 035](./adr/035-distribution-is-a-checksummed-tarball-an-installer.md)).

## From `v0.1.0`: semver over the pinned surface

The full policy is
[decision 039](./adr/039-api-stability-semver-and-deprecation-policy.md); the rules an embedder needs:

- **MAJOR** is an incompatible change to the pinned surface: a removed or renamed `VmmError` variant,
  a changed `kind()` bucket, an incompatible `channel` change, or raising a `Limits` default (defaults
  are load-bearing, so raising one is breaking).
- **MINOR** is additive: a new method, a new `VmmError` variant (the enum is `#[non_exhaustive]`, so
  adding one is compatible), a new optional field, a new capability that preserves old behavior.
- **PATCH** is a behavior-preserving fix.
- **Deprecation:** an item slated for removal is marked `#[deprecated]` in one MINOR, keeps working
  for at least one further MINOR, and is removed no earlier than the next MAJOR. The JSON and wire
  `schema` versions move on their own rule (additive within a version; a rename or removal bumps the
  integer), independent of the crate's semver.

## Rust version

Supported Rust is **current stable, pinned exactly**, with no back-support before `v0.1.0`; a
Wasmtime-style last-three-stable window is revisited at the tag. The reasoning and the operating
checklist are [decision 037](./adr/037-rust-version-tracks-current-stable-no-back-support-yet.md) and
the Rust-version section of
[`RELEASES.md`](https://github.com/k-henry-org/agent/blob/main/RELEASES.md).

## Releases and the changelog

The finish line is `v0.1.0`, cut only once every planned phase is green. There is no `CHANGELOG.md`
before then: in the pre-release line the decision records and the git log are the change record, and
curated release notes begin at the tag. Tags are a human git step. The full release model is
[`RELEASES.md`](https://github.com/k-henry-org/agent/blob/main/RELEASES.md).
