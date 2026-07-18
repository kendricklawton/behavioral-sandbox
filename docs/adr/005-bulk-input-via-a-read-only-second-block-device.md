# 005. Bulk input via a read-only second block device *(2026-07-12)*

**Decision.** When `BootConfig.input_dir` is set, the driver builds a **read-only** ext4 from that
host directory (rootless `mke2fs -d` into the per-VM scratch dir) and attaches it as a second block
device (`/dev/vdb`, `is_read_only: true`); the agent rootfs mounts it read-only at `/input` via a
best-effort `sysinit` line, so a command reads bulk input as `/input/...`. This is the
whole-working-dir / large-file path, the vsock channel's `PutFile` carries only small `≤1 MiB`
per-frame files. **No guest-agent change**: `/input` is a mounted dir the command references; the
agent's per-exec `/tmp` `RunDir` is untouched.

**Alternatives considered.**
- **A read-write "working dir" block device** (the device *is* the writable cwd; outputs land there).
  Rejected: that's P3.5 (pull artifacts back) done early, and it detonates P3.5's hardest problem now,
  `teardown` hard-kills Firecracker, so the guest never cleanly unmounts, and reading that ext4
  back host-side would be a dirty, un-replayed filesystem. It would also force the agent's `RunDir`
  into a sometimes-`/input`-sometimes-`/tmp` mode, breaking the per-exec isolation `RunDir` exists for
  and front-running Phase-7 stateful sessions. Read-only keeps the input **provably immutable**
  (`O_RDONLY`, the same primitive the P3.3 overlay guarantee rests on) and the writable working dir
  stays the P3.3 overlay `/tmp`.
- **A prebuilt image path** instead of a host directory. Deferred: a directory is the ergonomic match
  to "inject a working dir," and an `input_image` escape hatch is trivial to add later.

**Why.** Injecting a directory the driver turns into a block device is the standard bulk host→guest
path; it carries what a 1 MiB frame provably can't, at near-disk speed, with no channel round trips.
`is_read_only: true` is load-bearing: it makes the input immutable and sidesteps the dirty-ext4
read-back hazard. Symlinks in the input are copied verbatim by `mke2fs -d`, so a link resolves inside
the *guest's* filesystem, never the host's, no traversal escape.

**Consequences and notes.**
- **A new runtime tool dependency on the driver host** (`mke2fs` + `truncate`): previously the driver
  spawned only `firecracker`. A missing tool is a typed `VmmError::Artifact`, and `xtask setup`
  checks for `mke2fs`.
- **Boot-latency cost:** building the image (`truncate` + `mke2fs -d`) is on the boot path, bounded,
  but it belongs behind the pre-warmed-pool pre-build once Phase 5 lands.
- **`/dev/vdb` naming was order-dependent.** ~~Fine for a single input device; if P3.5 adds a third
  (writable output) drive, prefer mounting by filesystem label/UUID.~~ **Resolved in P3.5:** the
  guest now mounts both data devices by filesystem **label** (`agent-input`/`agent-output`, stamped
  with `mke2fs -L`, resolved with `findfs`), so the `/dev/vdX` letter, which shifts when output is
  present but input isn't, no longer matters. The input image gained an `agent-input` label and the
  `sysinit` line became `/sbin/mount-drives`.
- **The image is sized generously** from the input's byte total + a `-N` inode count (many tiny files
  exhaust inodes, not bytes); an input past a 2 GiB ceiling is a typed error, not a giant image.
