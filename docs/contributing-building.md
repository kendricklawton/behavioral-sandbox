# Building

The engine is Linux-only and needs `/dev/kvm` to run anything, though the host-safe gate builds and
tests without it. For host preparation from a bare machine (KVM access, Firecracker, the host tools)
see [Installation](./cli-install.md#preparing-the-host); this page is the developer's side.

## Prerequisites

- **Rust (stable)**, pinned exactly in `rust-toolchain.toml`. The version policy and the reason for
  pinning rather than floating are in
  [Coding guidelines](./contributing-coding-guidelines.md#minimum-supported-rustc-version-msrv).

- **The musl target**, required for the static in-guest agent:

  ```console
  rustup target add x86_64-unknown-linux-musl
  ```

- **`cargo-deny`**, run by the host-safe gate:

  ```console
  cargo install cargo-deny
  ```

- **The eBPF toolchain** (optional, only for the probes). Both pieces are **pinned**, and this is
  deliberate: unlike `aya`, which is a Cargo dependency held by `Cargo.lock`, these are installed out
  of band, so an unpinned install takes whatever shipped that morning and a compiler change can break
  the build with no commit from anyone. `bpf-linker` links against the pinned nightly's LLVM, so the
  two move together.

  ```console
  cargo install bpf-linker --locked --version 0.10.3
  rustup toolchain install nightly-2026-07-20 --profile minimal --component rust-src
  ```

  The nightly is pinned in `crates/probes/rust-toolchain.toml` and `bpf-linker` in `xtask`. A gate
  test (`ebpf_toolchain_pins_are_single_sourced`) compares every copy of both against those single
  sources, and another asserts this page hands out the pinned version rather than an unpinned
  `cargo install`.

## Setup commands

```console
git clone https://github.com/packsixfour/ekvm && cd ekvm
cargo xtask setup            # verify KVM, BTF, Firecracker, bpf-linker, caps
cargo xtask fetch-artifacts  # download the sha-pinned guest kernel and boot rootfs
cargo xtask build-rootfs     # build the reproducible guest rootfs (Alpine + python3 + static agent)
cargo xtask build-probes     # build the eBPF object (target: bpfel-unknown-none)
```

`cargo xtask setup` renders the same host checks as `ekvm doctor`, plus the build-toolchain rows, so
it is the one command to run first on a new machine.

## Vendoring for offline builds

Every out-of-band input is sha256-pinned except the guest's Alpine package closure, which floats
within the pinned branch and is recorded in `xtask/rootfs-packages.lock` rather than hashed (see
[Supply chain & provenance](./security-threat-model.md) for why). `cargo xtask vendor` mirrors all of
them locally, pinning the closure as it goes, so a self-hoster can build with no network. See
[Installation](./cli-install.md) for the operator-facing side of the same mirror.
