# Installation

The engine is **Linux-only** (it needs KVM). There is no packaged release yet — you build from
source, and `cargo xtask setup` tells you what your host is missing at every step.

## Self-host in one command

Once you have the [prerequisites](#prerequisites), the whole stand-up is a single command:

```console
cargo xtask self-host           # obtain the pinned kernel + rootfs, build the guest image + eBPF
                                # object, install `agent`/`agentd`, then boot one sandbox to prove it
```

It installs the `agent` and `agentd` binaries into `~/.local/bin` (override with `--prefix DIR`) and,
on a host with `/dev/kvm`, boots a throwaway sandbox and runs a command as an end-to-end check. On a
host without KVM it does everything except the boot and prints the exact command to run the proof on a
KVM box. `--no-run` skips the boot proof (build + install only).

To build **offline** — no Firecracker S3 bucket, no Alpine CDN — point it at a vendored mirror first
(see [Vendoring for offline builds](#vendoring-for-offline-builds)):

```console
cargo xtask vendor                                  # snapshot every pinned input into ./vendor
AGENT_VENDOR_DIR=./vendor cargo xtask self-host     # build the whole engine from the mirror
```

## Supported platforms

The engine runs untrusted code, so its platform floor is part of its security posture, not just a
compatibility note: the parts the isolation-and-audit thesis rests on are **hard requirements**, the
rest **degrade with a stated consequence**. `agent doctor` reports exactly where your host sits and
exits non-zero if a hard requirement is missing.

**Hard requirements** (off these, the host is not supported — [decision 036](./contributing-architecture.md)):

| | Requirement | Why |
|---|---|---|
| **OS** | Linux | KVM is the isolation boundary |
| **Architecture** | `x86_64` or `aarch64` | Firecracker's two; the only targets the engine builds |
| **Host kernel** | **≥ 5.15** (a security-maintained LTS) | untrusted code on an unpatched kernel is a threat-model hole — KVM CVEs land here |
| **Virtualization** | `/dev/kvm` present and writable | there is no software isolation fallback |
| **Firecracker + jailer** | present on `PATH` | no VMM to launch (the jailer's absence degrades to `--unjailed`) |

**Tested-against / pinned versions:** Firecracker **v1.9** (a different version boots with a warning;
API bodies may not match). The **guest kernel** baked into the rootfs is pinned to a
Firecracker-supported version — Firecracker periodically retires old guest kernels, so a fresh build
tracks their supported set.

**Degradations** (the run still works, minus the named capability):

- No **BTF** / `CAP_BPF`+`CAP_PERFMON` → `--trace`/`--watch` report a coverage gap; **`--allow`
  egress enforcement refuses** rather than running unenforced.
- **cgroup v2** controllers not delegated → jailed VMs run without CPU/memory caps (a fail-open DoS
  mitigation, not the isolation boundary — [decision 013](./contributing-architecture.md)).
- No real root / no jailer → the jailed default fails; `--unjailed` still runs behind KVM.
- `ip` / `e2fsprogs` missing → only `--net` or bulk-I/O runs fail; others are unaffected.

## Prerequisites

- **A Linux host with `/dev/kvm`** (kernel ≥ 5.15, see [Supported platforms](#supported-platforms))
  and your user in the `kvm` group (or root). Kernel **BTF** (`/sys/kernel/btf/vmlinux`) is required
  for CO-RE eBPF — most modern distros ship it.
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

## Vendoring for offline builds

A build otherwise fetches four sha-pinned inputs from two upstreams: the guest kernel + boot rootfs
from Firecracker's CI S3 bucket, and the Alpine minirootfs + the guest package (`.apk`) closure from
the Alpine CDN. `cargo xtask vendor` snapshots **all** of them into a local mirror so a fresh host
builds without either upstream staying alive:

```console
cargo xtask vendor                    # download every pinned input into ./vendor, sha-verified,
                                      # and write vendor/vendor-manifest.txt (one sha256 per file)
cargo xtask vendor --dir /srv/mirror  # populate a mirror elsewhere
cargo xtask vendor --verify           # re-check an existing mirror against its manifest (offline)
```

Then set `AGENT_VENDOR_DIR` to the mirror and every build path resolves from it — no network:

```console
AGENT_VENDOR_DIR=./vendor cargo xtask self-host      # the whole stand-up, offline
AGENT_VENDOR_DIR=./vendor cargo xtask build-rootfs    # just the guest image, offline
```

The mirror is **not** committed (it holds downloaded images, like `artifacts/`); it is a self-hoster's
offline convenience, produced once. The `.apk` closure is pinned at vendor time (Alpine branch repos
delete old package revisions, so there is no stable per-package URL to pin in source), which makes an
offline build **more** reproducible than the live-CDN one — it installs from the frozen cache the
manifest hashes. See [decision 037](./contributing-architecture.md) for the full rationale.
