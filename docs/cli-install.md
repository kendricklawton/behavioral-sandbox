# Installation

The engine is **Linux-only** (it needs KVM). Two paths: build from source (`self-host`, below), or
install a packaged release (tarball / `install.sh` / container, decision 035). Pre-rename releases
are disposable `v0.0.x` checkpoints with no stability promise; `cargo xtask setup` (or
`agent doctor` once installed) tells you what your host is missing at every step.

## Preparing the host

Every install path below assumes a host that can already boot a microVM. On a fresh machine that
means four things, in this order.

Commands are given for **Ubuntu/Debian** and **Arch**, the two distros this engine is continuously
tested on (Ubuntu 24.04 in CI, Arch by hand during development, see
[Verified on](#supported-platforms)). Any other distro follows the same four steps with its own
package manager. The two differ in ways that actually bite, so read your own column rather than
assuming; [Distro differences](#distro-differences-that-bite) collects them.

### 1. Check that the box qualifies

```console
uname -m                      # must print x86_64
uname -r                      # must be 5.15 or newer
ls -l /dev/kvm                # must exist
ls /sys/kernel/btf/vmlinux    # needed for the eBPF half; most distro kernels ship it
```

If `/dev/kvm` is missing, stop here: there is no software isolation fallback, so nothing below will
help. The usual cause is a **cloud VM without nested virtualization**: a stock EC2, DigitalOcean, or
Hetzner cloud instance cannot boot a microVM. You need bare metal (an AWS `.metal` instance, a
dedicated server, your own machine) or a provider that exposes nested virt (GCP, some Azure SKUs).
On a laptop or desktop, check that virtualization is enabled in the firmware.

### 2. Install the host tools

Ubuntu / Debian:

```console
sudo apt update
sudo apt install -y iproute2 e2fsprogs curl ca-certificates
sudo apt install -y build-essential git        # only if you will build from source
```

Arch:

```console
sudo pacman -Syu
sudo pacman -S --needed iproute2 e2fsprogs curl ca-certificates
sudo pacman -S --needed base-devel git         # only if you will build from source
```

Most are already present on a normal install. [Prerequisites](#prerequisites) says what each one is
for and which are optional.

### 3. Get access to `/dev/kvm`

This is where the two distros differ, so check what your host actually ships before doing anything:

```console
ls -l /dev/kvm
```

- **`crw-rw---- root kvm`** (Ubuntu/Debian): mode `0660`, so a plain user cannot open it until they
  join the `kvm` group. Do step 3.
- **`crw-rw-rw- root kvm`** (Arch): mode `0666` from systemd's shipped udev rule
  (`/usr/lib/udev/rules.d/50-udev-default.rules`), so anyone can already open it. Skip to step 4.

To join the group:

```console
sudo usermod -aG kvm "$USER"
```

Membership is picked up at login, so **log out and back in** (or run `newgrp kvm` in the current
shell), then confirm it took:

```console
id -nG | tr ' ' '\n' | grep -x kvm   # prints kvm once the group is in effect
```

### 4. Install Firecracker and its jailer

The engine drives Firecracker, it does not bundle it (the container image is the one exception), so
both binaries have to be on `PATH`. v1.9 is the pinned version; a different one boots with a warning
because its API bodies may not match.

```console
VER=v1.9.1
ARCH=x86_64
curl -fsSL -o /tmp/fc.tgz \
  "https://github.com/firecracker-microvm/firecracker/releases/download/${VER}/firecracker-${VER}-${ARCH}.tgz"
tar -xzf /tmp/fc.tgz -C /tmp
sudo install -m0755 "/tmp/release-${VER}-${ARCH}/firecracker-${VER}-${ARCH}" /usr/local/bin/firecracker
sudo install -m0755 "/tmp/release-${VER}-${ARCH}/jailer-${VER}-${ARCH}"      /usr/local/bin/jailer
firecracker --version
```

Verifying that download against a pinned hash is tracked work, not yet done
([decision 040](./adr/040-supply-chain-provenance-pinning-and-release-signing.md)).

On Arch, `firecracker` is also in the AUR, but the release binaries above are what CI and the
pinned-version check are exercised against, so prefer them.

Now pick an install path below. Whichever you pick, running `agent doctor` afterwards is how you
confirm these four steps actually took.

### Distro differences that bite

Neither distro is more supported than the other; they bracket the tool-version spectrum, which is
why both are tested (Arch rolling-newest against Ubuntu LTS-oldest, and each has caught issues the
other could not).

| | Ubuntu | Arch |
|---|---|---|
| Host kernel | 24.04 ships 6.8; **22.04 ships exactly 5.15**, the supported floor | rolling, comfortably above the floor |
| `/dev/kvm` | `0660 root:kvm`, so you must join the group | `0666`, usually usable already |
| `/tmp` | varies by release, check it | tmpfs **`nodev` by default**, so the jailed default fails until you set `AGENT_SCRATCH_DIR` |
| `e2fsprogs` | 24.04 ships **1.47.0**, below the 1.47.1 floor where `mke2fs` honours `SOURCE_DATE_EPOCH`, so `cargo xtask build-rootfs --verify` fails (normal builds are fine) | current, above the floor |
| AppArmor | **enabled by default**, and can deny the jailer in ways that look like an engine bug | not installed by default |
| Build toolchain | `build-essential` | `base-devel` |

Test the `/tmp` question rather than trusting the table, since it depends on your own mount setup:

```console
findmnt -no OPTIONS -T /tmp | tr , '\n' | grep nodev   # prints nodev if you are affected
```

If it prints `nodev`, point the engine at a scratch dir that is not, once, in `~/.agent.toml`:

```toml
scratch_dir = "/home/you/agent-scratch"
```

`agent doctor` flags every one of these against your actual host, so treat it as the authority and
this table as orientation.

## Install from a release package

Every release ships one tarball per platform plus `SHA256SUMS`, assembled by `cargo xtask dist`:
the `agent` binary, the guest kernel, the agent rootfs, and the eBPF object, with a per-file
`MANIFEST.sha256` inside. `install.sh` verifies both layers before touching anything, then installs
the binary to `~/.local/bin`, the artifacts to `~/.local/share/agent`, and writes a starter
`~/.agent.toml` (kernel/rootfs paths) if you don't have one:

```console
curl -fsSL https://raw.githubusercontent.com/k-henry-org/agent/main/install.sh | sh
```

Offline, or straight from a package you built or downloaded by hand:

```console
cargo xtask dist                                            # assemble dist/agent-<ver>-x86_64-linux.tar.gz
AGENT_DIST_TARBALL=dist/agent-<ver>-x86_64-linux.tar.gz sh install.sh
```

Knobs (env): `AGENT_INSTALL_PREFIX` (binary dir), `AGENT_DATA_DIR` (artifact dir), `AGENT_VERSION`
(a specific release), `AGENT_NO_TOML=1` (skip the config write). Firecracker v1.9 stays a host
prerequisite (the engine drives it, it doesn't bundle it). eBPF observability needs no configuration:
the engine finds the installed `probes` object under the data dir on its own, so
`AGENT_PROBES_OBJECT` is only needed if you relocated the install with `AGENT_DATA_DIR`.

## Your first run

`agent doctor` is the tool that explains the host: every row it flags names its own fix, and when the
host is ready it prints the exact run command **for this host**. Run it first.

The one thing worth knowing before you do: a run is **jailed by default**, and the jailer needs real
root (it creates device nodes in the chroot). So on a normal user account the first command is either

```console
sudo -E agent run -- echo hello       # jailed, the supported posture
agent run --unjailed -- echo hello    # no root: still behind KVM, but the VMM runs unconfined
```

There is deliberately no silent fallback between the two: dropping the jail is something you ask for,
never something the engine does quietly for you. If a run fails on a host-readiness cause, the error
points you back at `agent doctor`.

## Run it as a container

The image bundles the pinned Firecracker (the one bundling exception: an image is a closed,
rebuilt filesystem) but never the KVM boundary, which is always the host's:

```console
cargo xtask dist
docker build -f Containerfile --build-arg DIST=dist/agent-<ver>-x86_64-linux -t agent:<ver> .
docker run --rm agent:<ver>                                          # doctor: what this host can do
docker run --rm --device /dev/kvm agent:<ver> run --unjailed -- echo hi
```

The jailed default and eBPF observation need more of the host (real root, CAP_BPF/CAP_PERFMON,
cgroup delegation); a hardened deployment runs those on the host or grants them explicitly, a
hoster call the image documents rather than makes (see the `Containerfile` header).

## Self-host in one command

Once you have the [prerequisites](#prerequisites), the whole stand-up is a single command:

```console
cargo xtask self-host           # obtain the pinned kernel + rootfs, build the guest image + eBPF
                                # object, install `agent`, then boot one sandbox to prove it
```

It installs the `agent` binary into `~/.local/bin` (override with `--prefix DIR`) and,
on a host with `/dev/kvm`, boots a throwaway sandbox and runs a command as an end-to-end check. On a
host without KVM it does everything except the boot and prints the exact command to run the proof on a
KVM box. `--no-run` skips the boot proof (build + install only).

To build **offline**, no Firecracker S3 bucket, no Alpine CDN, point it at a vendored mirror first
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

**Hard requirements** (off these, the host is not supported, [decision 032](./adr/032-supported-platforms-two-architectures-a-security.md)):

| | Requirement | Why |
|---|---|---|
| **OS** | Linux | KVM is the isolation boundary |
| **Architecture** | `x86_64` | the one architecture with tested artifacts and a privileged CI lane; aarch64 support returns only with hardware to test it on (decision 032 as narrowed) |
| **Host kernel** | **≥ 5.15** (a security-maintained LTS) | untrusted code on an unpatched kernel is a threat-model hole, KVM CVEs land here |
| **Virtualization** | `/dev/kvm` present and writable | there is no software isolation fallback |
| **Firecracker + jailer** | present on `PATH` | no VMM to launch (the jailer's absence degrades to `--unjailed`) |

**Tested-against / pinned versions:** Firecracker **v1.9** (a different version boots with a warning;
API bodies may not match). The **guest kernel** baked into the rootfs is pinned to a
Firecracker-supported version, Firecracker periodically retires old guest kernels, so a fresh build
tracks their supported set.

**Verified on** (measured, not marketed, this is the honest test surface as of pre-1.0):

- **Host-safe gate** (build, unit tests, lints, docs, the eBPF object build) runs in CI on **Ubuntu
  24.04** `x86_64` on every change.
- **The privileged path** (microVM boot, the jailer, the eBPF probes, the end-to-end integration
  suite) runs in CI on a GitHub-hosted **Ubuntu 24.04** runner (`x86_64`, nested KVM) and by hand
  on **Arch Linux** (rolling) during development, both with **Firecracker v1.9**. Those two are the
  continuously-tested distros, and they bracket the tool-version spectrum (rolling-newest against
  LTS-oldest; Ubuntu's e2fsprogs and IPv6 defaults each caught a real issue Arch could not). Other
  distros are supported per the checks above but not continuously exercised; `agent doctor` names
  exactly what a given host is missing.
- **`aarch64` is not supported at this time**: it was never privileged-tested (no arm64 KVM
  hardware or CI lane, and no pinned arm boot artifacts), so the claim was dropped rather than
  carried untested. A contribution that brings tested arm artifacts plus a privileged CI lane
  reopens it.
- One distro-specific gotcha already surfaced: on hosts that mount `/tmp` as tmpfs `nodev` (the
  systemd default on Arch, and some Ubuntu setups), the jailed default fails because the jailer's
  chroot `/dev/kvm` there is inert, point `AGENT_SCRATCH_DIR` at a non-`nodev` path. `agent doctor`
  flags this, and reports your own host's arch, kernel, and Firecracker version. See
  [Distro differences](#distro-differences-that-bite) for how to test it and the rest of the
  per-distro list.
- On distros that enable **AppArmor** by default (Ubuntu and Debian), a confinement profile can deny
  the jailer or Firecracker in ways that look like an engine bug. If a jailed boot fails for a reason
  none of the checks above explain, read `dmesg | grep -i apparmor` before chasing it further.

**Degradations** (the run still works, minus the named capability):

- No **BTF** / `CAP_BPF`+`CAP_PERFMON` → `--trace`/`--watch` report a coverage gap; **`--allow`
  egress enforcement refuses** rather than running unenforced.
- **cgroup v2** controllers not delegated → jailed VMs run without CPU/memory caps (a fail-open DoS
  mitigation, not the isolation boundary, [decision 010](./adr/010-per-run-resource-policy-one-limits-struct-of.md)).
- No real root / no jailer → the jailed default fails; `--unjailed` still runs behind KVM.
- **Scratch dir on a `nodev` mount** (the default `/tmp` on modern systemd hosts) → the jailer's chroot
  `/dev/kvm` is inert, so the jailed default fails to open KVM; set `AGENT_SCRATCH_DIR` to a
  non-`nodev` path (e.g. under `$HOME`), or use `--unjailed`. `agent doctor` flags this.
- `ip` / `e2fsprogs` missing → only `--net` or bulk-I/O runs fail; others are unaffected.

## Prerequisites

What the **engine** needs at runtime: what each dependency is for, and which are optional. For the
commands that install them on a fresh box, see [Preparing the host](#preparing-the-host); for what
**building from source** additionally needs (the Rust toolchain, `bpf-linker`), see
[Building](./contributing-building.md#prerequisites).

- **A Linux host with `/dev/kvm`** (kernel ≥ 5.15, see [Supported platforms](#supported-platforms))
  and your user in the `kvm` group (or root). Kernel **BTF** (`/sys/kernel/btf/vmlinux`) is required
  for CO-RE eBPF, most modern distros ship it.
- **`firecracker`** + its **jailer** binary (pinned version, `cargo xtask setup` probes it), on
  `PATH` or named via `AGENT_FIRECRACKER`.
- **`e2fsprogs` + `coreutils`** (`mke2fs`, `e2fsck`, `debugfs`, `truncate`): the driver builds the
  rootfs and the bulk-input/output block devices, and reads outputs back, all **rootless** (no
  loopback, no `sudo`). A missing tool is a clear typed error. The **reproducible** rootfs build
  (`cargo xtask build-rootfs --verify`) additionally needs e2fsprogs **>= 1.47.1**, where `mke2fs`
  starts honouring `SOURCE_DATE_EPOCH` (older versions stamp wall-clock times; Ubuntu 24.04's
  1.47.0 is below the floor, `cargo xtask setup` probes it).
- **`iproute2`** (`ip`): the driver creates and deletes the per-VM **tap** device backing the
  guest's virtio-net. Creating a tap needs `CAP_NET_ADMIN`.
- **`curl`**: `cargo xtask fetch-artifacts` and `cargo xtask build-rootfs` download the pinned
  guest kernel and Alpine packages (sha256-verified).

### Capabilities

How much of the engine you get depends on what the process is allowed to do, and this is the part
that most often surprises a first-time operator. Nothing here degrades silently: a capability you
lack either names itself in `agent doctor` or produces a typed refusal.

| What you want | What it needs | Without it |
|---|---|---|
| Run code, VMM unconfined | membership in the `kvm` group | this *is* the fallback: `--unjailed` |
| **Jailed run** (the default, the supported posture) | **real root**, so `sudo`, plus a scratch dir that is not on a `nodev` mount | the boot fails; ask for `--unjailed` explicitly |
| `--net`, a guest NIC | `CAP_NET_ADMIN`, to create the per-VM tap | only networked runs fail; the rest are unaffected |
| `--trace` / `--record` / `--watch` | `CAP_BPF` + `CAP_PERFMON` + kernel BTF | the run still happens and reports its coverage gap |
| `--allow` egress **enforcement** | the same eBPF capabilities | **refused**, rather than running unenforced |

Root covers every row. To keep the eBPF half off root, grant the binary just those two capabilities:

```console
sudo setcap cap_bpf,cap_perfmon+ep "$(command -v agent)"
```

The jailer's requirement cannot be narrowed the same way: it needs **real root** (euid 0) because it
builds a chroot with device nodes in it and then drops privileges itself, so no capability subset
substitutes. A jailed run therefore looks like this, with `-E` to keep your environment and an
explicit scratch dir if `/tmp` is `nodev`:

```console
mkdir -p ~/agent-scratch
sudo -E env AGENT_SCRATCH_DIR="$HOME/agent-scratch" "$(command -v agent)" run -- echo hello
```

## Compiling from source

[Self-host in one command](#self-host-in-one-command) is the short path: it obtains the guest
artifacts, builds the eBPF object, installs the binary, and proves the result by booting a sandbox.

To drive the individual steps instead, or to work on the engine itself, consult
[Building](./contributing-building.md), which owns the build toolchain (the Rust version policy, the
probes crate's pinned nightly and `bpf-linker`), the artifact commands, and the two test gates.

Once you have a binary, head to [Using the agent CLI](./cli.md) to run something.

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

Then set `AGENT_VENDOR_DIR` to the mirror and every build path resolves from it, no network:

```console
AGENT_VENDOR_DIR=./vendor cargo xtask self-host      # the whole stand-up, offline
AGENT_VENDOR_DIR=./vendor cargo xtask build-rootfs    # just the guest image, offline
```

The mirror is **not** committed (it holds downloaded images, like `artifacts/`); it is a self-hoster's
offline convenience, produced once. The `.apk` closure is pinned at vendor time (Alpine branch repos
delete old package revisions, so there is no stable per-package URL to pin in source), which makes an
offline build **more** reproducible than the live-CDN one, it installs from the frozen cache the
manifest hashes. See [decision 033](./adr/033-single-command-self-host-a-vendored-offline-mirror-of.md) for the full rationale.
