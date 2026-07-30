# Installation

The engine is **Linux-only** (it needs KVM). Two paths: build from source (`self-host`, below), or
install a packaged release (tarball / `install.sh` / container). Pre-rename releases
are disposable `v0.0.x` checkpoints with no stability promise; `cargo xtask setup` (or
`ekvm doctor` once installed) tells you what your host is missing at every step.

## Preparing the host

Every install path below assumes a host that can already boot a microVM. On a fresh machine that
means four things, in this order.

Commands are given for **Ubuntu/Debian** and **Arch**, the two distros this engine is continuously
tested on (Ubuntu 24.04 in CI, Arch by hand during development, see
[Verified on](#supported-platforms)). Any other distro follows the same four steps with its own
package manager; [Distro differences](#distro-differences-that-bite) collects where the two
diverge.

### 1. Check that the box qualifies

```console
uname -m                      # must print x86_64
uname -r                      # informational only: `ekvm doctor` probes for cgroup.kill itself
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
  join the `kvm` group, below.
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
both binaries have to be on `PATH`. Two versions matter, and both track upstream's own patch
window: the **pinned** release (currently **v1.16.1**) is what CI tests and the sha256 below
verifies, and the **floor** (currently **v1.15**) is the oldest series the Firecracker team still
patches, with the driver adapting its API requests to any release in between. Below the floor, a
boot continues with a warning but is neither tested here nor patched upstream, which is the wrong
footing for running untrusted code.

This range **moves with upstream, not with our release cadence**: when a series ages out of their
table the floor rises, which a weekly CI job checks so it cannot drift unnoticed.

```console
VER=v1.16.1
ARCH=x86_64
curl -fsSL -o /tmp/fc.tgz \
  "https://github.com/firecracker-microvm/firecracker/releases/download/${VER}/firecracker-${VER}-${ARCH}.tgz"
tar -xzf /tmp/fc.tgz -C /tmp
sudo install -m0755 "/tmp/release-${VER}-${ARCH}/firecracker-${VER}-${ARCH}" /usr/local/bin/firecracker
sudo install -m0755 "/tmp/release-${VER}-${ARCH}/jailer-${VER}-${ARCH}"      /usr/local/bin/jailer
firecracker --version
```

Both `install.sh` and `ekvm doctor` check a Firecracker binary found on `PATH` against the
pinned v1.16 release sha256 and warn on a mismatch (advisory: your Firecracker is your call, but
the pinned build is what CI exercises).

On Arch, `firecracker` is also in the AUR, but the release binaries above are what CI and the
pinned-version check are exercised against, so prefer them.

Now pick an install path below, and run `ekvm doctor` afterwards to confirm these four steps
took.

### Distro differences that bite

Neither distro is more supported than the other; they bracket the tool-version spectrum, which is
why both are tested (Arch rolling-newest against Ubuntu LTS-oldest, and each has caught issues the
other could not).

| | Ubuntu | Arch |
|---|---|---|
| Host kernel | 24.04 ships 6.8; **22.04 ships exactly 5.15**, the fallback floor | rolling, comfortably above the floor |
| `/dev/kvm` | `0660 root:kvm`, so you must join the group | `0666`, usually usable already |
| `/tmp` | varies by release, check it | tmpfs **`nodev` by default** (hardened baselines add `noexec`), so the jailed default needs a `scratch_dir` off both (the guided install sets one; see below) |
| `e2fsprogs` | 24.04 ships **1.47.0**, below the 1.47.1 floor where `mke2fs` honours `SOURCE_DATE_EPOCH`, so `cargo xtask build-rootfs --verify` fails (normal builds are fine) | current, above the floor |
| AppArmor | **enabled by default**, and can deny the jailer in ways that look like an engine bug | not installed by default |
| Build toolchain | `build-essential` | `base-devel` |

### Red Hat (RHEL 9, RHEL 10): a target, not yet verified

> **Nothing on this host family has been run yet.** RHEL 9 and 10 are intended targets; no boot,
> gate, or probe attach has been exercised on either. What follows is what the mechanism implies,
> not a report. Treat every row as a hypothesis until the privileged gate runs there.

| | RHEL 9 | RHEL 10 |
|---|---|---|
| Host kernel | `5.14.0-*.el9`, **below the 5.15 fallback floor**, so it qualifies via the probed `cgroup.kill` (present since 5.14) rather than by version | `6.12.0-*.el10`, above the fallback floor either way |
| cgroup | v2 unified by default | v2 unified by default |
| Kernel BTF | ships `/sys/kernel/btf/vmlinux`, so the eBPF half's CO-RE requirement is met | as RHEL 9 |
| **SELinux** | **enforcing by default, and the largest unknown.** The jailer chroots, `mknod`s `/dev/kvm`, bind-mounts, and drops uid: each is something targeted policy has opinions about. Expect denials before expecting success | as RHEL 9 |
| Secure Boot | with lockdown active, some BPF operations can be restricted; unverified here | as RHEL 9 |
| Containers | `podman`, not `docker`, for the [container recipe](#run-it-as-a-container) | as RHEL 9 |

RHEL 8 (`4.18.0-*.el8`, cgroup v1 hybrid by default) is **not** a target.

For CI without a subscription, **CentOS Stream 9**, **Rocky 9**, and **AlmaLinux 9** are
kernel-compatible with RHEL 9. The privileged gate still needs `/dev/kvm` and real root, so it
needs bare metal or nested virt on any of them.

Test the `/tmp` question rather than trusting the table, since it depends on your own mount setup:

```console
findmnt -no OPTIONS -T /tmp | tr , '\n' | grep -E 'nodev|noexec'   # prints the flags that affect you
```

If it prints `nodev` or `noexec`, point the engine at a scratch dir carrying neither, once, in
`~/.ekvm.toml`.
Keep the path **short**: a jailed boot nests this dir name twice inside its API socket path, which the
kernel caps at ~108 bytes (`ekvm doctor` and the boot error flag an over-long one), so a
short dir like `~/.ekvm` beats a long one:

```toml
scratch_dir = "/home/you/.ekvm"
```

The packaged `install.sh` and `cargo xtask self-host` **write this line for you** (as `~/.ekvm`) when
they detect a `nodev` or `noexec` `/tmp`, so a guided install already boots jailed; the manual form
above is for a from-source run, or a config you wrote yourself.

`ekvm doctor` flags every one of these against your actual host, so treat it as the authority and
this table as orientation.

## Install from a release package

> **No release has been published yet.** Version `0.0.0`, no tag, no artifacts: the URLs in this
> section do not resolve today. It describes the intended install path so it can be reviewed and
> tested before the first tag; until then, build from source (above). See
> [Status](./introduction.md#status).

Each release is intended to ship a release package tarball per platform plus `SHA256SUMS` and its
detached ed25519 signature `SHA256SUMS.sig`, assembled by `cargo xtask dist`:
the `ekvm` binary, the guest kernel, the guest rootfs, and the eBPF object, with a per-file `MANIFEST.sha256` inside. Two first-class installation methods are supported:

### Option A: the installer script (`curl | sh`)

```console
curl -fsSL https://get.ekvm.dev | sh
```

### Option B: verify and extract by hand

For air-gapped hosts, manual inspection, or offline testing, download and verify the release package:

```console
# Download release tarball, checksum manifest, and its detached signature
curl -LO https://github.com/packsixfour/ekvm/releases/latest/download/ekvm-0.1.0-x86_64-linux.tar.gz
curl -LO https://github.com/packsixfour/ekvm/releases/latest/download/SHA256SUMS
curl -LO https://github.com/packsixfour/ekvm/releases/latest/download/SHA256SUMS.sig

# Verify the manifest's signature against the release key pinned in the repo.
# Obtain release-key.pem out of band, never from the release assets: from a clone of the
# repo (it sits at the root), or the raw file on GitHub over a channel you already trust.
openssl pkeyutl -verify -pubin -inkey release-key.pem -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig

# Then verify integrity against the now-trusted SHA256SUMS
grep "ekvm-0.1.0-x86_64-linux.tar.gz$" SHA256SUMS | sha256sum -c -

# Extract and install (running install.sh inside the package installs with zero network calls)
tar -xzf ekvm-0.1.0-x86_64-linux.tar.gz
cd ekvm-0.1.0-x86_64-linux
sh ./install.sh
```

The installer knobs for this layer: `EKVM_RELEASE_PUBKEY` (an SPKI PEM path or the PEM text
itself) overrides the key pinned inside `install.sh`, and is the stronger anchor when supplied
out of band; `EKVM_INSECURE_SKIP_SIGNATURE=1` skips the signature check (needed only for
releases predating the signing scheme; the sha256 and manifest checks still run).

Or for a package assembled locally from source:

```console
cargo xtask dist                                            # assemble dist/ekvm-<ver>-x86_64-linux.tar.gz
EKVM_DIST_TARBALL=dist/ekvm-<ver>-x86_64-linux.tar.gz sh install.sh
```

Knobs (env): `EKVM_INSTALL_PREFIX` (binary dir), `EKVM_DATA_DIR` (artifact dir), `EKVM_VERSION`
(a specific release), `EKVM_NO_TOML=1` (skip the config write). Firecracker v1.16 stays a host
prerequisite (the engine drives it, it doesn't bundle it). eBPF observability needs no configuration:
the engine finds the installed `probes` object under the data dir on its own, so
`EKVM_PROBES_OBJECT` is only needed if you relocated the install with `EKVM_DATA_DIR`.

## Your first run

`ekvm doctor` is the tool that explains the host: every row it flags names its own fix, and when the
host is ready it prints the exact run command **for this host**. Run it first.

The one thing worth knowing before you do: a run is **jailed by default**, and the jailer needs real
root (it creates device nodes in the chroot). So on a normal user account the first command is either

```console
ekvm run --unjailed -- echo hello                 # no root needed: still behind KVM, but the VMM runs unconfined
sudo -E env "PATH=$PATH" ekvm run -- echo hello   # jailed, the supported posture
```

The `env "PATH=$PATH"` is not decoration: sudoers `secure_path` (on by default on Ubuntu and most
distros) overrides PATH even under `-E`, which hides both a `~/.local/bin` install of `ekvm` and the
firecracker/jailer binaries the engine resolves at spawn time.

There is deliberately no silent fallback between the two: dropping the jail is something you ask for,
never something the engine does quietly for you. If a run fails on a host-readiness cause, the error
points you back at `ekvm doctor`.

## Run it as a container

The image bundles the pinned Firecracker (the one bundling exception: an image is a closed,
rebuilt filesystem) but never the KVM boundary, which is always the host's:

```console
cargo xtask dist
docker build -f Containerfile --build-arg DIST=dist/ekvm-<ver>-x86_64-linux -t ekvm:<ver> .
docker run --rm ekvm:<ver>                                            # doctor: what this host can do
docker run --rm --device /dev/kvm ekvm:<ver> run --unjailed -- echo hi
```

The jailed default and eBPF observation need more of the host (real root, CAP_BPF/CAP_PERFMON,
cgroup delegation); a hardened deployment runs those on the host or grants them explicitly, a
hoster call the image documents rather than makes (see the `Containerfile` header).

## Self-host in one command

From a clone of the repo with a Rust toolchain installed (see
[Building](./contributing-building.md)), plus the
[prerequisites](#prerequisites), the whole stand-up is a single command:

```console
cargo xtask self-host           # obtain the pinned kernel + rootfs, build the guest image + eBPF
                                # object, install `ekvm`, then boot one sandbox to prove it
```

It installs the `ekvm` binary into `~/.local/bin` (override with `--prefix DIR`) and,
on a host with `/dev/kvm`, boots a throwaway sandbox and runs a command as an end-to-end check. On a
host without KVM it does everything except the boot and prints the exact command to run the proof on a
KVM box. `--no-run` skips the boot proof (build + install only). Like `install.sh`, it writes a starter
`~/.ekvm.toml` (absolute kernel/rootfs paths, and a `scratch_dir` off `nodev`/`noexec` when your
`/tmp` carries either flag) unless one already exists; `EKVM_NO_TOML=1` skips it.

To build **offline**, no Firecracker S3 bucket, no Alpine CDN, point it at a vendored mirror first
(see [Vendoring for offline builds](#vendoring-for-offline-builds)):

```console
cargo xtask vendor                                  # snapshot every pinned input into ./vendor
EKVM_VENDOR_DIR=./vendor cargo xtask self-host     # build the whole engine from the mirror
```

## Supported platforms

The engine runs untrusted code, so its platform floor is part of its security posture, not just a
compatibility note: the parts the isolation-and-audit thesis rests on are **hard requirements**, the
rest **degrade with a stated consequence**. `ekvm doctor` reports exactly where your host sits and
exits non-zero if a hard requirement is missing.

**Hard requirements** (off these, the host is not supported):

| | Requirement | Why |
|---|---|---|
| **OS** | Linux | KVM is the isolation boundary |
| **Architecture** | `x86_64` | the one architecture with tested artifacts and a privileged CI lane; aarch64 support returns only with hardware to test it on. |
| **Host kernel** | `cgroup.kill` present; **≥ 5.15** only where there is no cgroup v2 to probe | `cgroup.kill` is the crash-safe teardown primitive the engine needs, so the engine asks for it directly instead of inferring it from a version. Neither signal establishes that the kernel is *patched*: that is the operator's |
| **Virtualization** | `/dev/kvm` present and writable | there is no software isolation fallback |
| **Firecracker + jailer** | present on `PATH` | no VMM to launch (the jailer's absence degrades to `--unjailed`) |

**Supported / tested versions:** Firecracker per
[step 4 above](#4-install-firecracker-and-its-jailer) (v1.15 through v1.16, v1.16 tested in CI).
The **guest kernel** baked into the rootfs is pinned to a Firecracker-supported version;
Firecracker periodically retires old guest kernels, so a fresh build tracks their supported set.

**Verified on** (the test surface as of pre-1.0):

- **Host-safe gate** (build, unit tests, lints, docs, the eBPF object build) runs in CI on **Ubuntu
  24.04** `x86_64` on every change.
- **The privileged path** (microVM boot, the jailer, the eBPF probes, the end-to-end integration
  suite) runs in CI on a GitHub-hosted **Ubuntu 24.04** runner (`x86_64`, nested KVM) and by hand
  on **Arch Linux** (rolling) during development, both with **Firecracker v1.16**. Other distros
  are supported per the checks above but not continuously exercised; `ekvm doctor` names exactly
  what a given host is missing.
- **`aarch64` is not supported at this time**: it was never privileged-tested (no arm64 KVM
  hardware or CI lane, and no pinned arm boot artifacts), so the claim was dropped rather than
  carried untested. A contribution that brings tested arm artifacts plus a privileged CI lane
  reopens it.
- One distro-specific gotcha already surfaced: a `nodev` (or `noexec`) `/tmp` makes a raw jailed
  run fail; [Distro differences](#distro-differences-that-bite) owns the test and the fix.
- On distros that enable **AppArmor** by default (Ubuntu and Debian), a confinement profile can deny
  the jailer or Firecracker in ways that look like an engine bug. If a jailed boot fails for a reason
  none of the checks above explain, read `dmesg | grep -i apparmor` before chasing it further.

**Degradations** (the run still works, minus the named capability):

- No **BTF** / `CAP_BPF`+`CAP_PERFMON` → `--trace`/`--watch` report a coverage gap; **`--allow`
  egress enforcement refuses** rather than running unenforced.
- **cgroup v2** controllers not delegated → jailed VMs run without CPU/memory caps (a fail-open DoS
  mitigation, not the isolation boundary).
- No real root / no jailer → the jailed default fails; `--unjailed` still runs behind KVM.
- **Scratch dir on a `nodev` or `noexec` mount** → the jailed default can't open KVM or exec its
  chrooted VMM copy ([Distro differences](#distro-differences-that-bite) has the fix); `--unjailed`
  still runs.
- `ip` / `e2fsprogs` missing → only `--net` or bulk-I/O runs fail; others are unaffected.

## Troubleshooting

| Symptom / `ekvm doctor` check | Root cause | Fix |
|---|---|---|
| **`/dev/kvm` missing or permission denied** | No virtualization exposed (stock cloud VMs lack nested virt), or the user is not in the `kvm` group. | Check nested virtualization on cloud VMs. Add user to `kvm` group:<br>`sudo usermod -aG kvm $USER && newgrp kvm` |
| **`ScratchDirNodev` (jailed boot fails at KVM open)** | `/tmp` is mounted with the `nodev` mount option, making the jailer's chrooted `/dev/kvm` inert. | Set scratch dir to a non-`nodev` filesystem:<br>`export EKVM_SCRATCH_DIR=/var/tmp`<br>or set `scratch_dir = "/var/tmp"` in `.ekvm.toml`. |
| **`ScratchDirNoexec` (jailed boot fails at the VMM exec)** | `/tmp` is mounted with the `noexec` mount option, so the firecracker copy in the jailer's chroot cannot be exec'd. | Same fix: a scratch dir off `noexec`, e.g. `EKVM_SCRATCH_DIR=/var/tmp`. |
| **`cgroup v2 cpu+memory delegated` Warn** | cgroup v2 `cpu` and `memory` controllers are not delegated to unprivileged users space by systemd. | Run under `sudo` or enable delegation in systemd:<br>`systemctl edit user@$UID.service`<br>and add `[Service]` -> `Delegate=yes`. |
| **`unix socket path is too long (> 108 bytes)`** | Kernel `sockaddr_un.sun_path` limit (~108 bytes) exceeded by a deep scratch path under jailing. | Use a short scratch directory path:<br>`export EKVM_SCRATCH_DIR=/var/tmp` |
| **`CAP_BPF` / `CAP_PERFMON` Warn or Refusal** | Running without root or missing eBPF capabilities to load tracepoints and `tc` filters. | Grant binary capabilities without root:<br>`sudo setcap cap_bpf,cap_perfmon+ep $(command -v ekvm)`<br>or run with `sudo -E`. |
| **`Kernel BTF` missing** | Host Linux kernel was compiled without `CONFIG_DEBUG_INFO_BTF=y`. | Install a standard distro kernel that includes `/sys/kernel/btf/vmlinux` (Ubuntu >= 22.04, Arch, Fedora). |

## Prerequisites

What the **engine** needs at runtime: what each dependency is for, and which are optional. For the
commands that install them on a fresh box, see [Preparing the host](#preparing-the-host); for what
**building from source** additionally needs (the Rust toolchain, `bpf-linker`), see
[Building](./contributing-building.md).

- **A Linux host with `/dev/kvm`** (a kernel with `cgroup.kill`, see [Supported platforms](#supported-platforms))
  and your user in the `kvm` group (or root). Kernel **BTF** (`/sys/kernel/btf/vmlinux`) is required
  for CO-RE eBPF, most modern distros ship it.
- **`firecracker`** + its **jailer** binary (pinned version, `cargo xtask setup` probes it), on
  `PATH` or named via `EKVM_FIRECRACKER`.
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
lack either names itself in `ekvm doctor` or produces a typed refusal.

| What you want | What it needs | Without it |
|---|---|---|
| Run code, VMM unconfined | membership in the `kvm` group | this *is* the fallback: `--unjailed` |
| **Jailed run** (the default, the supported posture) | **real root**, so `sudo`, plus a scratch dir that is not on a `nodev` or `noexec` mount | the boot fails; ask for `--unjailed` explicitly |
| `--net`, a guest NIC | `CAP_NET_ADMIN`, to create the per-VM tap | only networked runs fail; the rest are unaffected |
| `--trace` / `--record` / `--watch` | `CAP_BPF` + `CAP_PERFMON` + kernel BTF | the run still happens and reports its coverage gap |
| `--allow` egress **enforcement** | the same eBPF capabilities | **refused**, rather than running unenforced |

Root covers every row. To keep the eBPF half off root, grant the binary just those two capabilities:

```console
sudo setcap cap_bpf,cap_perfmon+ep "$(command -v ekvm)"
```

The jailer's requirement cannot be narrowed the same way: it needs **real root** (euid 0) because it
builds a chroot with device nodes in it and then drops privileges itself, so no capability subset
substitutes. A jailed run therefore looks like this, with `-E` to keep your environment and an
explicit scratch dir if `/tmp` is `nodev` or `noexec`:

```console
mkdir -p ~/.ekvm
sudo -E env EKVM_SCRATCH_DIR="$HOME/.ekvm" "$(command -v ekvm)" run -- echo hello
```

(The short dir name is deliberate: the ~108-byte socket-path cap under
[Distro differences](#distro-differences-that-bite).)

## Compiling from source

[Self-host in one command](#self-host-in-one-command) is the short path.

To drive the individual steps instead, or to work on the engine itself, consult
[Building](./contributing-building.md), which owns the build toolchain (the Rust version policy, the
probes crate's pinned nightly and `bpf-linker`), the artifact commands, and the two test gates.

Once you have a binary, head to [Using the eKVM CLI](./cli.md) to run something.

## Vendoring for offline builds

A build otherwise fetches from two upstreams: three sha-pinned inputs (the guest kernel + boot rootfs
from Firecracker's CI S3 bucket, the Alpine minirootfs from the Alpine CDN), plus the guest package
(`.apk`) closure, which floats within the pinned Alpine branch and is recorded rather than hash-pinned
(see [Supply chain & provenance](./security-threat-model.md)). `cargo xtask vendor` snapshots **all**
of them into a local mirror, pinning the closure in the process, so a fresh host builds without either
upstream staying alive:

```console
cargo xtask vendor                    # download every pinned input into ./vendor, sha-verified,
                                      # and write vendor/vendor-manifest.txt (one sha256 per file)
cargo xtask vendor --dir /srv/mirror  # populate a mirror elsewhere
cargo xtask vendor --verify           # re-check an existing mirror against its manifest (offline)
```

Then set `EKVM_VENDOR_DIR` to the mirror and every build path resolves from it, no network:

```console
EKVM_VENDOR_DIR=./vendor cargo xtask self-host      # the whole stand-up, offline
EKVM_VENDOR_DIR=./vendor cargo xtask build-rootfs    # just the guest image, offline
```

The mirror is **not** committed (it holds downloaded images, like `artifacts/`); it is a self-hoster's
offline convenience, produced once. The `.apk` closure is pinned at vendor time (Alpine branch repos
delete old package revisions, so there is no stable per-package URL to pin in source), which makes an
offline build **more** reproducible than the live-CDN one, it installs from the frozen cache the
manifest hashes.

## Uninstall

The engine's whole footprint is four paths, so removal is four commands, no tool needed:

```console
rm ~/.local/bin/ekvm            # the binary (or your EKVM_INSTALL_PREFIX)
rm -rf ~/.local/share/ekvm      # kernel, rootfs, probes object (or your EKVM_DATA_DIR)
rm ~/.ekvm.toml                 # the starter config, if the install wrote one
rm -rf ~/.ekvm                  # the jail-usable scratch dir, if the install set one up
```

Nothing else outlives the runs: per-VM scratch under `scratch_dir` is reclaimed at teardown, and a
crashed run's residue is reclaimed by the next run's own-euid sweep, so there is nothing to hunt
for. Firecracker and the jailer were installed by you (step 4), so removing them, and leaving the
`kvm` group, are your calls, not the engine's.
