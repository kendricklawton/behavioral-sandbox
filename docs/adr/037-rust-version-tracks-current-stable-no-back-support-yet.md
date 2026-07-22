# 037. Rust version tracks current stable, pinned; a support window waits for v0.1.0 *(2026-07-22)*

**Context.** The engine is embedded downstream at the `vmm` library's public API, pinned by git rev, so
the Rust it requires is a legibility question for embedders, not just an internal detail. Two facts
shape the answer before `v0.1.0`. First, the workspace already pins an **exact** stable toolchain in
`rust-toolchain.toml` (currently `1.97.0`) so a local build and CI run the identical compiler and
clippy, killing the "a lint passes locally but a newer CI stable rejects it" drift. Second, there is no
released version and no external embedder yet: nobody is pinned to an older toolchain that a bump would
break. A wider "support the last N stable releases" window (as a mature library like Wasmtime commits
to) buys embedder reach that does not exist yet, at the cost of a floor-below-pin split and a dedicated
CI lane to keep that floor honest.

**Decision.** Before `v0.1.0`, the supported Rust **is current stable, pinned exactly**.
`rust-toolchain.toml` pins the build and lint toolchain; `[workspace.package].rust-version` in
`Cargo.toml` is kept **in step** with it and is the stated downstream floor. There is deliberately **no
back-support window**: bumping Rust is a single, deliberate move of both the pin and `rust-version`
together, never incidental drift, and never a promise to compile on an older release. The eBPF crate
(`crates/probes`) is nightly by construction and sits outside this entirely.

A support window (a Wasmtime-style "last three stable", its floor tested by its own CI lane and
decoupled from the build pin) is **revisited at `v0.1.0`**, when the SDKs and external embedders that
make a window worth its maintenance actually exist. Recorded here so the deferral is a decision, not a
silent gap.

**Alternatives considered.**
- **Support the last three stable releases now (Wasmtime's window).** Wasmtime and Cranelift support the
  current stable and the two before it, tested by a dedicated floor CI lane, and bump the floor by
  editing one `rust-version` field. Rejected *for now*: it is a mature-library policy (Wasmtime is 1.0+
  and widely embedded), and this engine is pre-`v0.1.0` with no external embedder to serve. Adopting it
  would decouple `rust-version` from the pin (a floor below the build toolchain), add a CI lane, and
  commit the project to policing every future dependency and feature bump against that floor:
  maintenance with no current beneficiary. It is the natural policy to adopt *at* `v0.1.0`, per the
  revisit above.
- **Float `channel = "stable"` rather than pinning.** Rejected: that is exactly the drift the pin exists
  to kill (a stale local stable passing a lint a newer CI stable rejects).
- **A low, embed-friendly floor (say 1.85), decoupled from the pin.** Measured as buildable today, but
  rejected: it claims support that is not tested, and for a security engine a low floor can block taking
  the latest *patched* dependency when that dependency bumps its own MSRV.

**Consequences and notes.**
- **One number, two files, moved together.** A Rust bump edits `rust-toolchain.toml` and `Cargo.toml`'s
  `rust-version` in the same change, so they never diverge and there is no untested floor to defend.
- **Embedders read one number.** `rust-version` says which stable to build with; there is no window to
  reason about before `v0.1.0`.
- **The revisit is real work, not a wish.** Adopting a support window at `v0.1.0` (the floor CI lane, the
  decoupled `rust-version`, the policy rewrite) is its own future box, scheduled when the embedder story
  lands, not assumed done here.

**As shipped.** The policy is already the code: `rust-toolchain.toml` pins `1.97.0`, `Cargo.toml`'s
`rust-version` is `1.97` in step, and both carry a comment stating the no-back-support stance and citing
this decision. `RELEASES.md` carries the reader-facing summary and the "bump both together" checklist.
