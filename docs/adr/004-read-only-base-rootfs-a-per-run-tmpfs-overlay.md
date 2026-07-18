# 004. Read-only base rootfs + a per-run tmpfs overlay *(2026-07-12)*

**Decision.** When `BootConfig.read_only_root` is set, the driver attaches the base rootfs
**read-only and shared** (no per-VM copy, Firecracker opens it `O_RDONLY`, so the guest can't mutate
it), and the guest stacks a **per-run tmpfs overlay** over it so `/` is writable but ephemeral. A
baked `/sbin/overlay-init` (PID 1, via `init=/sbin/overlay-init` the driver appends) mounts a
size-capped tmpfs, builds `overlayfs` with the RO base as lowerdir and the tmpfs as upper+work,
`pivot_root`s into it, and `exec`s the real init. **Read-only base and overlay are one concept, not
two knobs**: a RO `/` without the overlay would break the agent's `/tmp` working dir (`EROFS`), so
the single flag implies both.

**Alternatives considered.**
- **A second writable block device as the overlay upper.** Rejected for P3.3: heavier (a per-VM image
  to create/format on the host) and it consumes the exact mechanism P3.4/P3.5 own (injecting a per-run
  working dir via a second block device). tmpfs keeps P3.3 to the overlay approach and is sharing-optimal,
  the base is shared read-only (page-cache-deduped across VMs) and the overlay costs only the RAM a
  run actually writes, vs. today's full ~50 MB copy per boot.
- **An initramfs that sets up the overlay before pivoting** ("initramfs vs rootfs"). Rejected:
  `BootSource` has no `initrd_path`, so it means a second CPIO artifact to build, pin, and hash-guard
  for zero benefit when a baked `/sbin/overlay-init` reuses the single ext4 we already assemble.
  Documenting the choice suffices.
- **`switch_root` instead of `pivot_root`.** Rejected: `switch_root` expects to *free* the old root,
  but ours is the RO base still in use as the overlay lowerdir. `pivot_root` keeps it mounted, shadowed
  at `/rom`.

**Why.** Runs are disposable, so an ephemeral RAM overlay is the natural writable layer, and sharing
one read-only base is the memory-sharing win Phase 5 is measured against. The tmpfs cap is **half of guest
RAM** (`mem_mib / 2`), passed on the kernel command line as `overlay_size=<N>M`, the kernel routes
`key=value` cmdline tokens into PID 1's environment, so `overlay-init` reads `$overlay_size` without
mounting `/proc` first. A guest has **no swap**, so a tmpfs sized near RAM would drive the OOM-killer
rather than bound a runaway write. `/overlay` is **baked into the image** because the root is read-only
when `overlay-init` runs, you can't `mkdir` a mountpoint on a read-only `/`.

**Consequences and notes.**
- **Additive, not a flip.** `read_only_root` defaults `false` and is **not** an `AGENT_*` env key, it's
  set in code where the agent image is chosen as a bundle (the test's `agent_rootfs_config`), so the
  multi-env footprint doesn't grow. The stock (Ubuntu) config still copies + boots read-write. Making
  the agent rootfs the read-only default is still the separate flip this file's decision 003 reserved.
- **Snapshot/restore (Phase 5):** the tmpfs upper lives in guest RAM, so it is captured by a memory
  snapshot, and a restore requires the same read-only base present at the same host path.
- **A read-only rootfs must ship `/sbin/overlay-init` + a `/overlay` mountpoint** (both baked by
  `build-rootfs`); pointing `read_only_root` at an image without them is a bounded boot failure (typed
  `VmmError`, `panic=1` → Firecracker exits → console tail), not a hang.
