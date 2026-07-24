# 005. Bulk input via a read-only second block device *(2026-07-12)*

**Context.** A command in the sandbox often needs a whole working directory or large files as input,
more than the host↔guest vsock channel is meant to carry: `PutFile` frames small `≤1 MiB` files, one
per frame, with a round trip each. Bulk host→guest data wants a different path, at near-disk speed and
with no channel chatter. Two forces shape that path. First, the input must be provably immutable: a
command must not be able to mutate what it was given, and reading a guest-written filesystem back
host-side is a hazard, since teardown hard-kills Firecracker and the guest never cleanly unmounts, so
that ext4 comes back dirty and un-replayed. Second, the writable working dir must stay the overlay
`/tmp` that per-exec isolation rests on, so injected input can't quietly become a sometimes-writable
cwd and break the isolation `RunDir` exists for.

**Decision.** When `BootConfig.input_dir` is set, the driver builds a **read-only** ext4 from that
host directory (rootless `mke2fs -d` into the per-VM scratch dir) and attaches it as a second block
device (`/dev/vdb`, `is_read_only: true`); the guest rootfs mounts it read-only at `/input` via a
best-effort `sysinit` line, so a command reads bulk input as `/input/...`. This is the
whole-working-dir / large-file path, the vsock channel's `PutFile` carries only small `≤1 MiB`
per-frame files. **No guest-agent change**: `/input` is a mounted dir the command references; the
agent's per-exec `/tmp` `RunDir` is untouched.

**Alternatives considered.**
- **A read-write "working dir" block device** (the device *is* the writable cwd; outputs land there).
  Rejected: that's the pull-artifacts-back capability done early, and it detonates that work's hardest
  problem now, `teardown` hard-kills Firecracker, so the guest never cleanly unmounts, and reading that
  ext4 back host-side would be a dirty, un-replayed filesystem. It would also force the agent's
  `RunDir` into a sometimes-`/input`-sometimes-`/tmp` mode, breaking the per-exec isolation `RunDir`
  exists for and front-running the later stateful-sessions work. Read-only keeps the input **provably
  immutable** (`O_RDONLY`, the same primitive the overlay guarantee rests on) and the writable working
  dir stays the overlay `/tmp`.
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
  but it belongs behind the pre-warmed-pool pre-build once the pool lands.
- **`/dev/vdb` naming was order-dependent.** ~~Fine for a single input device; if a later change adds a
  third (writable output) drive, prefer mounting by filesystem label/UUID.~~ **Resolved when the
  writable output drive landed:** the guest now mounts both data devices by filesystem **label**
  (`kee-input`/`kee-output`, stamped with `mke2fs -L`, resolved with `findfs`), so the `/dev/vdX`
  letter, which shifts when output is present but input isn't, no longer matters. The input image
  gained an `kee-input` label and the `sysinit` line became `/sbin/mount-drives`.
- **The image is sized generously** from the input's byte total + a `-N` inode count (many tiny files
  exhaust inodes, not bytes); an input past a 2 GiB ceiling is a typed error, not a giant image.
