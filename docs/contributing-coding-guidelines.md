# Coding guidelines

For the most part this project follows common Rust conventions, though there are a few additional
things to be aware of. The workflow and gate mechanics are in [Contributing](./contributing.md); this
page is about the code itself.

## `rustfmt`

All code is formatted according to rustfmt, checked by the host-safe gate. That includes the two
**detached** workspaces, `crates/probes` and `fuzz`, which are excluded from the root one and so are
reached by their own gate step rather than by `--all`. Format locally with:

```console
cargo fmt --all
```

at the root of the repository. `cargo xtask check` runs the same check in about four seconds, along
with the prose-drift lint and Clippy, which is the intended inner loop.

## Compiler warnings and lints

The gate promotes all compiler warnings to errors, so `main` never has warnings for the pinned
compiler. One exception is real and visible: the eBPF object build in `crates/probes` emits a
`linker_messages` warning about the nightly's LLVM shared library and does **not** deny warnings,
because that build runs through `rustup run … cargo build` for `bpfel-unknown-none` rather than
through the workspace's `-D warnings` step. Clippy does gate that crate; the compiler warning is
what survives. Unlike a project that floats on `stable`, this one **pins the toolchain exactly** in
`rust-toolchain.toml`, so a warning that appears locally appears in CI too and vice versa. That is the
whole reason for the pin: a lint that passes on a stale local stable and fails on a newer CI stable is
a class of surprise this project chose to design out.

During local development warnings are just warnings, and a build or test run still succeeds. This is
useful mid-refactor. By the time a change lands, the gate requires them resolved.

## Clippy

The gate runs Clippy with `-D warnings` across the workspace **and across the two detached
workspaces**. On top of the default set, this project **opts additional lints into `deny`** through
`[workspace.lints.clippy]` in the root `Cargo.toml`:

```toml
[workspace.lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
todo = "deny"
unimplemented = "deny"
unreachable = "deny"
```

That list is not stylistic. Design rule 5 says a hostile guest, a failed probe, or a broken channel
should surface as a typed error rather than a panic, hang, or leak, and these lints are what makes the
compiler enforce the "no panic" half instead of leaving it to habit. A function that cannot proceed
returns a typed error; it does not `unwrap`.

Two consequences worth knowing before you fight the lints:

- **Integration-test crates that use `panic!` as an assertion helper opt out per file** with
  `#![allow(clippy::panic)]`, because Clippy has no allow-in-tests knob for the explicit-panic macros
  the way it does for `unwrap`/`expect`. Free helper functions in a test binary (anything not a
  `#[test]` fn) are the case that needs this.
- **Prefer an explicit `panic!` with a message over `expect`** in those helpers, so the failure names
  what went wrong. `if let Err(e) = … { panic!("create the mount point {}: {e}", …) }` reads better in
  a test log than a bare `expect`.

Run Clippy locally exactly as the gate does:

```console
cargo clippy --workspace --all-targets -- -D warnings
```

Contributors are welcome to propose new lints. Enabling one for the workspace means fixing it
everywhere in the same change.

`crates/probes` and `fuzz` cannot write `[lints] workspace = true`, because cargo inherits lints for
*members* and both are excluded. The gate reads the deny list above out of the root manifest and
passes it to them on the command line, so there is one policy rather than a second copy to keep in
step. Until 2026-08-02 there was no policy on them at all: both were outside rustfmt, Clippy, and
`cargo deny`, and `crates/probes`, the one crate allowed `unsafe`, had accumulated 18 findings that
nothing would have reported.

## Minimum supported `rustc` version (MSRV)

Supported Rust is **current stable**, pinned exactly in `rust-toolchain.toml` and mirrored at minor
granularity in the workspace `rust-version`. There is no back-support window for older toolchains yet;
the policy is recorded in [RELEASES.md](../RELEASES.md).

Bumping Rust means editing `rust-toolchain.toml` and `Cargo.toml` together, then verifying
`cargo xtask ci`. Note that the pin insulates the repository from a local `rustup update`: your default
stable moving forward does not change what the gate compiles with, so nothing breaks until someone
bumps the pin deliberately.

The eBPF crate (`crates/probes`) is **nightly by construction**, because `bpfel-unknown-none` has no
prebuilt `core` and needs `-Z build-std`. It pins an exact dated nightly in its own
`crates/probes/rust-toolchain.toml` for the same reason the workspace pins a stable, and `bpf-linker`
links against that nightly's LLVM, so the two move together. A gate test
(`ebpf_toolchain_pins_are_single_sourced`) fails if any copy of either pin drifts from its single
source.

## Dependencies

This project is **dependency-light by design**, and the threshold for adding one is higher than
default. Before adding a dependency, consider whether the needed slice is small enough to write. The
`ekvm-channel` crate is dependency-free on purpose; `ekvm-probes-common` has zero dependencies so the two sides
of the eBPF boundary cannot drift.

`cargo deny` runs in the host-safe gate and checks licenses, advisories, and duplicate versions. Every
out-of-band input (the guest kernel, the Alpine base rootfs, `apk-tools`, the Firecracker release) is
**sha256-pinned**. The guest package closure installed on top of that base is the exception: it floats
within the pinned Alpine branch and is held by a recorded lockfile plus a weekly rebuild, not a hash.
`cargo xtask vendor` mirrors every input locally for offline builds, closure included. Pins that
appear in more than one file are held together by gate tests rather than vigilance, which is what
caught a Firecracker pin that had drifted below its own support floor.

Non-Rust SDKs live in separate companion repositories, so Python, Node, and Go build tooling never
enters this workspace.

## Crate organization

Crates live flat under `crates/<name>`, and the **package name is usually the directory name**. The
CLI is the deliberate exception: `crates/cli` declares `name = "ekvm"`, because a package's default
binary inherits the package name and nobody wants to type `cli run`. `xtask` sits at the root, outside
the shipped set.

Two boundaries decide where new code belongs:

- **The host path stays `unsafe`-free**, so anything that must touch raw pointers belongs behind the
  eBPF boundary in `crates/probes`, not in the driver.
- **Types crossing the eBPF boundary live in `ekvm-probes-common`**, single-sourced as `#[repr(C)]`
  plain-old-data with no dependencies, so the kernel side and the loader side cannot disagree about a
  layout.

`ekvm-engine` is the library downstream embedders pin, so its public surface is the API that carries the `api`
commit scope. Keep new public items out of it unless an embedder needs them.

## Use of `unsafe`

**The host path forbids it outright.** Every crate in the workspace carries
`#![forbid(unsafe_code)]` except `crates/probes`. This is not an aspiration policed by review; it is
a compiler error, and it is the enforcer named wherever the docs claim the host path is unsafe-free.

The rule is stated as "every crate except one" rather than as a list of crate names on purpose:
`every_crate_forbids_unsafe_except_the_bpf_one` derives the set from the tree and fails if any crate
drops the attribute *or* if `probes` quietly gains it, so a new crate has to be decided about rather
than defaulting into an unchecked gap. Both pages that state this rule previously named five of the
six crates that carried it, while claiming a universal that three crates did not satisfy.

`crates/probes` is the sole exception, and structurally so. It builds for the BPF target, where
reading a map value means dereferencing a raw pointer the verifier has already bounded. Its module
documentation states this in one place rather than at every call site, which is the convention: state
the threat-model framing once, on the item that owns it.

The rule for new code is therefore simple, and simpler than most projects can manage: if a design
needs `unsafe` on the host path, the design is wrong for this repository. Reach for the safe wrapper
instead. `ekvm-probes-loader` joins a network namespace through nix's *safe* `setns` specifically to keep
its `forbid` attribute intact, and that trade (a dependency instead of an `unsafe` block) is the one
this project prefers every time.

Inside `crates/probes`, each `unsafe` block gets a preceding comment explaining why it is sound, in
terms a reader can verify from the surrounding function alone.
