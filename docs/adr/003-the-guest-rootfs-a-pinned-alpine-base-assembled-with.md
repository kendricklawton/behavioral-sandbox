# 003. The guest rootfs: a pinned Alpine base, assembled with the agent baked in *(2026-07-12)*

**Decision.** The guest rootfs is **built, not fetched**: `cargo xtask build-rootfs` extracts a
**sha256-pinned Alpine minirootfs** (a real musl + busybox userland), bakes the static guest agent
in at `/usr/local/bin/agent-guest`, installs a minimal init, and assembles an ext4 image
(`artifacts/rootfs-agent.ext4`) with **`mke2fs -d`**, populating the filesystem from a staging dir
with **no root and no loopback mount**. A *distinct* output from the pinned Ubuntu boot rootfs Phase
1 used, so the `ci-privileged` hash-guard and the Phase-1 `login:` boot test are untouched. Two
hard-to-reverse pieces ride along:

- **Init model: busybox `init` is PID 1**, with a custom `/etc/inittab` (replacing Alpine's OpenRC)
  that mounts `devtmpfs`/`proc`/`sysfs` in `sysinit` and `respawn`s the agent on vsock port 1024
  (`AGENT_VSOCK_PORT`) attached to `ttyS0`. The agent is deliberately **not** PID 1: it has no
  orphan-reaping loop (a killed command's grandchildren reparent to PID 1, busybox reaps them; the
  `forbid(unsafe_code)` agent would leak zombies), and a PID-1 crash panics the kernel, which must
  never be the fate of the respawnable exec surface.
- **Readiness contract: the agent emits the sentinel, post-`bind`.** The agent prints
  `GUEST_READY_MARKER` (`agent_channel`) to stdout, the serial console, *after* its vsock listener
  is bound, and `Vm::boot` returns only once it scans that line. So "userspace ready" means "the
  agent is accepting," eliminating the connect-before-listen race. (Emitting it from init before
  spawning the agent would reintroduce that race.)

**Alternatives considered.**
- **Scratch + a static busybox.** Most minimal and educational, but no `/etc` skeleton, no musl
  loader, no package manager, and the next boxes (P3.2 Python, P3.9 Node) want a real libc
  userland; static CPython on scratch is genuinely painful. Rejected as the base; the scratch approach
  survives in P3.9's static Go/Rust ELF, which runs on this same image.
- **`docker export` of an image.** Needs the Docker daemon at build time and is less reproducible
  than a pinned tarball + scripted assembly. Rejected.
- **Overwrite `rootfs.ext4` / flip `BootConfig::default().rootfs` to Alpine.** Tempting ("`exec`
  just works"), but it breaks the `ci-privileged` sha256 guard (pins the Ubuntu hash) and the
  Phase-1 `login:` test in the same change. Kept **additive**: distinct filename, the test points at
  it explicitly. Retiring Ubuntu is a deliberate later change.

**Why.** Alpine is a pinned, ~5 MB, musl userland that boots with busybox and scales to Python/Node
via `apk`, the pragmatic base for the *runtime-agnostic* rootfs the Phase-3 goal calls for.
`mke2fs -d` keeps the whole build rootless and one-command, matching the "no `sudo cargo` roulette"
discipline. The agent as a baked-in, busybox-supervised child (never PID 1, never the containment
boundary) preserves core property 2. This closes decision 002's P2.2 ↔ P3.1 coupling and its
`vhost-vsock` prerequisite: the pinned Firecracker CI kernel (`vmlinux-6.1.102`) carries the guest
vsock transport + `CONFIG_DEVTMPFS_MOUNT`, proven by the in-VM `exec("echo hi") → hi, exit 0`
round trip.

**Consequences and notes.**
- **P3.1's reproducibility bar was "pinned inputs + a fixed UUID + one scripted command," not
  byte-identical.** ~~A content-manifest hash + any `SOURCE_DATE_EPOCH`/`hash_seed` byte-for-byte
  polish is **P3.6**.~~ **Resolved in P3.6 (decision 007):** `SOURCE_DATE_EPOCH` + a fixed htree hash
  seed + dropping apk's wall-clock install log make two builds byte-identical, verified by a gate; a
  committed lockfile records the resolved package closure.
- **The agent now depends on the `vsock` crate** (guest-agent-only; the host still reaches
  Firecracker's vsock over a plain `UnixStream`). Its tree is MIT/Apache and it doesn't breach the
  agent's own `forbid(unsafe_code)`.
- **The Alpine version + sha256 are pinned in `xtask`.** A bump means re-pinning the hash (the URL
  is replaceable, the hash is the contract, the decision-001 discipline).
- **A default-rootfs flip (Alpine replaces Ubuntu as the boot default) is a separate future change**,
  touching the default marker, the `ci-privileged` guard, and the Phase-1 boot test together.
