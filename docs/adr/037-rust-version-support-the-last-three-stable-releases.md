# 037. Rust version support: the last three stable releases, one floor tested in CI *(2026-07-22)*

**Context.** The engine is embedded downstream at the `vmm` library's public API, pinned by git rev,
so the minimum Rust version it compiles on (the MSRV) is a contract, not an implementation detail: it
decides which toolchains a hoster can build the engine on. Until now the only number was
`[workspace.package].rust-version`, set to whatever stable happened to be current, which both
over-claimed (the code only needs the `is_none_or` floor, stabilized in 1.82) and was never tested, so
it was a marketed number, not a measured one, exactly what the core properties (guardrail #6) forbid.
This repo is deliberately shaped after Wasmtime (docs layout, the sibling in `ROADMAP.md`), and Wasmtime
already answers this question with a disciplined, well-worn policy, so the cost is in adopting it, not
inventing one.

**Decision.** Support the **last three stable Rust releases** (the current stable and the two before
it), the same window Wasmtime and Cranelift commit to. Concretely:

- **One number, one place.** `[workspace.package].rust-version` in the root `Cargo.toml` is the floor,
  inherited by every host crate. It is the single source of truth; this document states the *policy*,
  never a copy of the number (which would drift).
- **The floor is tested, not asserted.** A dedicated CI lane builds the host gate on the pinned floor
  toolchain with `--locked`, so a dependency bump or a stray newer-than-floor API is caught, not
  discovered downstream. Default CI keeps running on current stable. A floor we do not test is not a
  floor (guardrail #6).
- **The eBPF crate is exempt, by construction.** `crates/probes` builds for `bpfel-unknown-none` under
  its own **nightly** toolchain (`build-std`, its own `rust-toolchain.toml`), so it has no stable MSRV
  and never will; the three-stable window covers the host crates only. This is the one place the engine
  departs from Wasmtime's model, and it is inherent to eBPF, not a choice.
- **Bumping the floor is a one-field edit, recorded.** Raise `rust-version` when a dependency or a
  language feature the engine wants requires it; note the bump in the release notes. Pre-`v0.1.0` this
  is free (breaking changes are allowed); from `v0.1.0` on, an MSRV raise is a minor-version event.

**Alternatives considered.**
- **A wide floor (6-12 months, or a pinned old rustc).** Rejected: this is a security engine, so being
  able to take the latest *patched* `ed25519-dalek` / `aya` / `zeroize` matters more than an old
  toolchain, and a wide window blocks a security patch that bumps its own MSRV. Wasmtime explicitly
  declines a wider window as unjustified maintenance, and this engine's audience (KVM, host kernel
  >= 5.15 per decision 032, x86_64 Linux, build-from-rev) runs modern toolchains.
- **Latest stable only (no window).** Rejected: too tight for a library others build from a rev; a
  hoster one release behind should still compile. Three releases (~4 months) is the mainstream default.
- **A low, embed-friendly floor like 1.85.** Measured and buildable today, but rejected for the same
  security-agility reason, and because claiming it would demand policing every future dependency bump to
  stay under it, maintenance the audience does not need.

**Consequences and notes.**
- **The declared floor may lag the code's true minimum.** That is fine and intended: `rust-version` is a
  *supported* floor (tested, last-of-three), not the lowest rustc the code happens to compile on.
- **Downstream legibility.** A change that raises the floor is visible in one `Cargo.toml` line and the
  release notes, so an embedder bumping their pin can see it coming, the same auditability the `api:`
  commit marker gives the wire surface.
- **How to stay on top of it** lives in `RELEASES.md` (the "Rust version support" section): the
  per-release checklist (bump the floor to current-stable-minus-two, run the floor lane, note it).

**As shipped.** Policy adopted here; the mechanics it prescribes (setting `rust-version` to the tested
floor and adding the floor CI lane to `.github/workflows/ci.yml` and `cargo xtask`) are the
implementing follow-up, tracked as its own roadmap box so the first-unchecked-box loop schedules it,
never a bare-prose deferral.
