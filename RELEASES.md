# Releases

**No releases yet.** The first tagged release will be `v0.1.0`.

## The finish line: `v0.1.0`

`v0.1.0` is the first real release: an engine that **boots a microVM, runs code, enforces and
records what it did, self-hostable and documented**. It is cut only once every planned phase is
green, so the tag means the whole story works end to end, not a subset.

- **The vNext tracks do not gate `v0.1.0`.** The polyglot SDKs (extending the engine outward, to
  more callers) and the Wasmtime sibling (extending it sideways, to a second isolation boundary)
  land *after* the tag. Both presuppose the frozen wire API; neither pulls tenancy/billing/
  scheduling into scope, and the Wasmtime sibling never dilutes the core properties (it ships as a
  separate artifact with a weaker, clearly-labelled guarantee).
- **Everything until then is a pre-release `v0.0.x`.** Checkpoint tags start at `v0.0.1`, the
  first packaged checkpoint (`cargo xtask dist` + a draft GitHub release, decision 035); later
  milestones bump the `0.0.x` patch as they land. These are checkpoints, not releases: no
  stability promise, and they ship under the working name, so they are disposable by design
  (no package managers, no promotion, decision 035). (The Cargo manifests carry `0.1.0` as their
  in-development working number, distinct from these git tags; every crate is `publish = false`,
  so nothing reaches crates.io before the `v0.1.0` release.)
- **Tags are a human git step.** The coding agent's job ends at the working tree; the user cuts
  every tag (see [`AGENTS.md`](https://github.com/k-henry-org/agent/blob/main/AGENTS.md)).

## Why there's no changelog yet

**No `CHANGELOG.md` until `v0.1.0`.** In the pre-release line the record of what changed and why is
deliberately not a curated changelog, which would only churn every `v0.0.x`. Instead:

- [The decision records](docs/adr/README.md), one dated, numbered ADR per hard-to-reverse choice,
  so the reasoning outlives the diff.
- The git log, one imperative subject per logical change; changes to the pinned public API carry a
  leading `api:` marker so downstream pin bumps are auditable from the log alone.
- [`ROADMAP.md`](ROADMAP.md), while it exists, the staged plan whose checkboxes track the remaining
  work toward the tag.

Curated release notes start accumulating in this file with `v0.1.0`.

## Rust version support

**Policy: the supported Rust is current stable, pinned exactly, with no back-support before `v0.1.0`.**
The reasoning, and the Wasmtime-style last-three-stable window deferred to `v0.1.0`, are in
[decision 037](docs/adr/037-rust-version-tracks-current-stable-no-back-support-yet.md); this section is
the operating checklist.

- **Two files, kept in step:** `rust-toolchain.toml` pins the build and lint toolchain;
  `[workspace.package].rust-version` in the root `Cargo.toml` mirrors it and is the stated downstream
  floor. They move together, never apart, so there is no untested floor below the pin.
- **The eBPF crate (`crates/probes`) is nightly by construction** and outside this entirely.

**Bumping Rust (one deliberate move, never incidental drift):**

1. Pick the new stable.
2. Set `channel` in `rust-toolchain.toml` and `rust-version` in the root `Cargo.toml` to it, together.
3. Run the gate green: `cargo xtask ci`.
4. Note the bump in the release notes.

