# Building

One Rust workspace, **stable** toolchain, Linux-only. The minimum supported Rust version
(`rust-version` in `[workspace.package]`) tracks current stable: the project carries no
back-compatibility burden this early, so building expects a recent stable toolchain (`rustup update`
if `cargo` complains the installed version is older than the manifest's `rust-version`). The eBPF
programs (`crates/probes`) are the exception: excluded from the workspace, built for
`bpfel-unknown-none` under their own pinned nightly (`-Z build-std=core`, since rustup ships no
prebuilt `core` for the BPF target) and linked by `bpf-linker`. Host prerequisites are covered in [Installation](./cli-install.md);
`cargo xtask setup` reports what's missing.

```console
cargo build                  # the workspace: driver, loader, CLI, guest agent
cargo xtask build-probes     # the eBPF object (skips with a note when bpf-linker/nightly are absent)
cargo xtask fetch-artifacts  # the pinned guest kernel + boot rootfs (sha256-verified)
cargo xtask build-rootfs     # the agent rootfs (reproducible; --check asserts byte-identical)
```

## Before you push, the local gate

```console
cargo install bpf-linker cargo-deny    # one-time
cargo xtask ci
```

`cargo xtask ci` is the **host-safe gate** and runs everywhere, no KVM or caps needed:
fmt · the prose-drift lint · clippy `-D warnings` · build · unit tests · docs · `cargo deny` ·
the eBPF object build (which asserts the object keeps its `.BTF` section, so a probe that won't
compile or that drops its BTF fails fast here). The prose-drift lint keeps checkable claims in
prose honest: every `decision NNN` citation must exist in the decision log, every backticked repo
path in a Rust comment must point at something in the tree, and every relative Markdown link must
resolve; a rename or renumber fails the gate instead of silently orphaning the references.

## The privileged gate

Booting a microVM and loading/attaching eBPF need `/dev/kvm` and elevated caps, so the
**integration tests** (VM boot, exec, tap networking, probe attach) are `#[ignore]`d and run under

```console
cargo xtask ci-privileged
```

on a machine that has them, your dev box, or a bare-metal/nested-virt CI runner (a stock cloud
VM usually can't nest KVM). **Never gate the everyday loop on a privileged runner.**

## The book

This documentation is an [mdBook](https://rust-lang.github.io/mdBook/):

```console
mdbook serve docs
```

Building it is optional, the pages are plain Markdown and readable in place.
