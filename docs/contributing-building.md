# Building

One Rust workspace, **stable** toolchain, Linux-only. The minimum supported Rust version
(`rust-version` in `[workspace.package]`) tracks current stable: the project carries no
back-compatibility burden this early, so building expects a recent stable toolchain (`rustup update`
if `cargo` complains the installed version is older than the manifest's `rust-version`). The eBPF
programs (`crates/probes`) are the exception: excluded from the workspace, built for
`bpfel-unknown-none` under their own pinned nightly (`-Z build-std=core`, since rustup ships no
prebuilt `core` for the BPF target) and linked by `bpf-linker`.

## Prerequisites

The **host** requirements (KVM, Firecracker, `e2fsprogs`, `iproute2`) are the engine's own, and
[Installation](./cli-install.md#preparing-the-host) walks a bare machine through them. Building adds
two more:

- **Rust, stable** ([`rustup`](https://www.rust-lang.org/tools/install)). The pinned version lives in
  `rust-toolchain.toml`, so `rustup` selects it for you inside the repo.
- **For the eBPF probes** (optional until you want the observability half): **`bpf-linker`** plus a
  **nightly** toolchain with **`rust-src`**, since `-Z build-std=core` needs the standard library
  source:

  ```console
  cargo install bpf-linker
  rustup toolchain install nightly --component rust-src
  ```

`cargo xtask setup` reports what a given host is still missing, build toolchain and runtime
dependencies alike.

## Getting a source tree ready

```console
git clone https://github.com/k-henry-org/agent && cd agent
cargo xtask setup            # verify KVM, BTF, firecracker, bpf-linker, caps: reports what's missing
cargo build                  # the workspace: driver, loader, CLI, guest agent
```

The repo ships **no binary images**, so the guest artifacts are fetched or built into `artifacts/`
(gitignored):

```console
cargo xtask fetch-artifacts  # the pinned guest kernel (vmlinux) + boot rootfs (sha256-verified)
cargo xtask build-rootfs     # the agent rootfs: Alpine + python3 + the static guest agent
                             # (reproducible; --verify asserts two builds are byte-identical)
cargo xtask build-probes     # the eBPF object (skips with a note when bpf-linker/nightly are absent)
```

To build without reaching either upstream, populate a mirror first: see
[Vendoring for offline builds](./cli-install.md#vendoring-for-offline-builds).

## While you work, the fast loop

```console
cargo xtask check
```

fmt · the prose-drift lint · clippy `-D warnings`, and **no tests**. That last part is the point:
measured on this workspace after a source edit, the test step is ~16s of a ~17s `ci` run and every
other step rounds to nothing once warm, so not running tests is the only thing that buys a faster
loop (~4s). So `check` tells you the code formats, lints, and compiles; it cannot tell you it works.
Steps it shares with `ci` use identical flags and environment, so the two share one build cache and
alternating between them doesn't trigger a rebuild. Run the gate before you push.

## Before you push, the local gate

```console
cargo install bpf-linker cargo-deny    # one-time
cargo xtask ci
```

`cargo xtask ci` is the **host-safe gate** and runs everywhere, no KVM or caps needed:
fmt · the prose-drift lint · clippy `-D warnings` · build · unit tests · docs · `cargo deny` ·
the eBPF object build (which asserts the object keeps its `.BTF` section, so a probe that won't
compile or that drops its BTF fails fast here). The prose-drift lint keeps checkable claims in
prose honest: every `decision NNN` citation must exist as an ADR under `docs/adr/`, every backticked repo
path in a Rust comment must point at something in the tree, and every relative Markdown link must
resolve; a rename or renumber fails the gate instead of silently orphaning the references.

## The privileged gate

Booting a microVM and loading/attaching eBPF need `/dev/kvm` and elevated caps, so the
**integration tests** (VM boot, exec, tap networking, probe attach) are `#[ignore]`d and run as
real root:

```console
sudo -E env CARGO_TARGET_DIR="$PWD/target-privileged" cargo xtask ci-privileged
```

on a machine that has them, your dev box, or a bare-metal/nested-virt CI runner (a stock cloud
VM usually can't nest KVM). **Never gate the everyday loop on a privileged runner.**

The `CARGO_TARGET_DIR` override matters: `sudo cargo …` builds as **root**, so without it this run
leaves root-owned artifacts in `./target` that then block your normal (non-root) `cargo build`.
Sending them to a throwaway `target-privileged/` (git-ignored, `rm -rf` it anytime) keeps the
`./target` your user builds into clean. `-E` preserves your `PATH` and `rustup` so `cargo` resolves
under `sudo`. **`ci-privileged` refuses to run as root without the override**, rather than warning
after the fact: the redirect has to be on the outer `cargo` (the one that builds `xtask` itself) to
keep `./target` clean at all, so it can only ever come from your invocation.

## The book

This documentation is an [mdBook](https://rust-lang.github.io/mdBook/):

```console
mdbook serve docs
```

Building it is optional, the pages are plain Markdown and readable in place.
