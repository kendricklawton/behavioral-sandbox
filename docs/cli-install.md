# Installation

The engine is **Linux-only** (it needs KVM). There is no packaged release yet — you build from
source, and `cargo xtask setup` tells you what your host is missing at every step.

## Prerequisites

- **A Linux host with `/dev/kvm`** and your user in the `kvm` group (or root). A reasonably
  recent kernel with **BTF** (`/sys/kernel/btf/vmlinux`) is required for CO-RE eBPF — most modern
  distros ship it.
- **Rust, stable** ([`rustup`](https://www.rust-lang.org/tools/install)) for the host/driver.
- **`firecracker`** + its **jailer** binary (pinned version — `cargo xtask setup` probes it), on
  `PATH` or named via `AGENT_FIRECRACKER`.
- **`e2fsprogs` + `coreutils`** (`mke2fs`, `e2fsck`, `debugfs`, `truncate`): the driver builds the
  rootfs and the bulk-input/output block devices, and reads outputs back, all **rootless** (no
  loopback, no `sudo`). A missing tool is a clear typed error.
- **`iproute2`** (`ip`): the driver creates and deletes the per-VM **tap** device backing the
  guest's virtio-net. Creating a tap needs `CAP_NET_ADMIN`.
- **`curl`**: `cargo xtask fetch-artifacts` and `cargo xtask build-rootfs` download the pinned
  guest kernel and Alpine packages (sha256-verified).
- **For the eBPF probes** (optional until you want the observability demos): **`bpf-linker`**
  plus a **nightly** toolchain with **`rust-src`** for `-Z build-std`
  (`cargo install bpf-linker`; `rustup toolchain install nightly --component rust-src`). The
  probes crate is excluded from the workspace and pins its own nightly, so the host/driver stays
  on stable.

### Capabilities

Two parts touch the kernel and need more than a plain user:

- Creating **tap** devices (networked sandboxes): `CAP_NET_ADMIN`.
- Loading/attaching **eBPF**: `CAP_BPF` + `CAP_PERFMON` — not full root. Grant a binary just those
  two with `setcap cap_bpf,cap_perfmon+ep <binary>`.
- The **jailer** (the default confinement for `agent run`) needs **real root**; on a dev box
  without it, `--unjailed` is the explicit opt-out (the guest still sits behind KVM).

## Setup

```console
git clone https://github.com/kendricklawton/agent && cd agent
cargo xtask setup            # verify KVM, BTF, firecracker, bpf-linker, caps — reports what's missing
cargo build
```

## Build the guest artifacts

The repo ships no binary images — `xtask` fetches or builds them into `artifacts/` (gitignored):

```console
cargo xtask fetch-artifacts    # the pinned guest kernel (vmlinux) + boot rootfs, sha256-verified
cargo xtask build-rootfs       # the agent rootfs: Alpine + python3 + the static guest agent
                               # (reproducible: two builds are byte-identical)
cargo xtask build-probes       # the eBPF object, for the observability demos (needs bpf-linker + nightly)
```

You're ready — head to [Using the agent CLI](./cli.md) to run something.
