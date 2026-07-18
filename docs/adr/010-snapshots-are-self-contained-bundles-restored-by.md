# 010. Snapshots are self-contained bundles restored by staging the disk *(2026-07-12)*

**Decision.** A microVM snapshot is a **self-contained bundle** in one directory: the vCPU/device
**state** file, the full guest **memory** file, and a **point-in-time copy of the root disk**.
- **Take it paused, copy the disk in the paused window.** `RunningVm::snapshot` does `PATCH /vm
  {Paused}` (freeze vCPUs) then `PUT /snapshot/create {Full}`, and copies the root disk *while paused*
  so the on-disk bytes agree with the frozen memory image, then `PATCH /vm {Resumed}`. A create
  failure still falls through to the resume, so a failed snapshot never leaves the guest frozen (the
  no-hang discipline).
- **Restore stages the disk at the recorded path, then unlinks it.** Firecracker opens each drive's
  backing file **during `PUT /snapshot/load`**, at the path baked into the snapshot, *before* any
  `PATCH /drives` can repoint it (learned by trying the rebase-after-load path and watching the load
  fail on the source's since-reclaimed scratch path). So `Vm::restore` copies the bundle's private disk
  to that recorded path, loads with `resume_vm:true`, then **unlinks** the staged file once the VMM
  holds the fd. The restored clone gets its own disk **inode** (the open fd keeps it alive for the VM's
  lifetime), shares no writable backing with its source, and leaves nothing outside its own scratch
  dir. Staging refuses to overwrite an existing file, so a still-live source's disk is never clobbered.
- **The API client gained `patch`** (Firecracker uses `PATCH` for in-place changes to a configured VM)
  and typed bodies for `/vm`, `/snapshot/create`, `/snapshot/load`, with the closed-set discriminants
  (`Paused`/`Resumed`, `Full`, `File`) modelled as enums, the same wire-discriminant discipline as
  `Action` (decision 001).

**Alternatives considered.**
- **Rebase the drive after load (`PATCH /drives`).** Rejected because it doesn't work: Firecracker
  opens the backing file at load, so the recorded path must be valid *then*; a post-load patch is too
  late. Staging-then-unlink is the workaround that keeps the bundle portable.
- **Reference a read-only shared base instead of copying the disk.** The right long-term shape for
  memory-sharing (many clones over one base), but it needs the source booted `read_only_root`, which needs the
  agent rootfs, which needs vsock to reach its readiness marker, and a vsock/NIC snapshot can't yet
  recreate its host endpoints on restore. So the read-write, private-copy path is the P5.1/P5.2 scope;
  read-only-base pre-warmed snapshots are P5.3/P5.4.

**Why.** A self-contained bundle can be moved or kept after the source VM is gone, which is what makes
"snapshot then restore N clones" (P5.4) and a pre-warmed pool (P5.6) tractable. The staging trick is the
minimal correct way to honour Firecracker's load-time drive-open contract without a shared mutable
backing file.

**Consequences and notes.**
- **Restore is dramatically faster than cold boot:** dev box, ~1.57 s cold vs **~8.9 ms** restore
  (≈177×). This is the fast-start reason the phase exists; the tracked p50/p99 benchmark is P5.7.
- **Snapshotting is scoped to a root-disk-only, read-write boot.** A VM with vsock, a NIC, or an output
  device is a typed error today (its host endpoints can't be recreated on restore yet, P5.4/P5.5), and
  a read-only shared base is deferred (P5.3/P5.4). The guard is structural (the root backing must live
  inside the VM's scratch dir), so it can't silently produce an unrestorable bundle.
- **The restored VM has no exec channel yet.** vsock-over-snapshot (so a restored pre-warmed VM can run code)
  is P5.8; today restore exposes liveness + teardown, and `boot_latency()` on a restored VM holds the
  restore latency.
- **Bundle size is state + ~guest-RAM memory + a full root-disk copy.** Copying the whole disk per
  snapshot is the honest cost of a portable, read-write bundle; diff snapshots and base-sharing (memory-sharing
  over the pre-warmed pool) are the P5.3/P5.4/P5.7 optimizations.

**Pre-warmed snapshots + concurrent clones (P5.3/P5.4, 2026-07-12).** Extended to snapshot a
`read_only_root` VM carrying the vsock exec channel, and to restore many exec-ready clones from it:
- **The read-only base is referenced, not copied.** A `read_only_root` boot's disk is the shared
  pinned base at a persistent path, so the bundle records it in place (no per-VM copy) and restore
  opens it read-only; N clones share one base (page-cache-deduped memory-sharing) while each gets its own
  in-RAM overlay from its own restored memory image. The structural test is which side of the scratch
  dir the disk lives on. A read-write boot keeps the copy-and-stage path.
- **Concurrent clones needed a per-clone vsock socket, solved without the jailer.** A first probe
  confirmed empirically that clones restored concurrently **collide** on the socket path baked into the
  snapshot (`Address in use`), because Firecracker re-binds the vsock listener at the recorded path on
  load. Fix: bind vsock at a **relative** name (`v.sock`) and run each VMM with its scratch dir as
  **cwd**, so the recorded relative path resolves per-clone. This is lighter than the Phase-6 jailer's
  per-VM mount namespace and doesn't block the pre-warmed pool on it. Consequence: every *file* path handed
  to Firecracker must now be **absolute** (its cwd is no longer the driver's), a small resolve-to-
  absolute pass on kernel/rootfs/bundle paths; the vsock path is the one deliberate exception.
- **Restore waits for exec-readiness.** A just-resumed guest agent needs a moment before its vsock
  listener is reachable again, so restore polls a connect until it succeeds (bounded by the deadline)
  before returning, its analogue of boot's userspace-marker wait. Restore of a pre-warmed agent VM measured
  ~8 ms vs ~300 ms cold boot, then the clone runs code.
- **Still deferred:** a snapshot with an **input or output device** is a typed error (per-clone
  images a restore can't yet recreate). A **NIC** is no longer deferred: decision 011 restores
  networked clones with a fresh identity. `ci-privileged` now runs the VM tests serially (they boot
  real microVMs and some assert on host-global leak state).
- **Jailed restore stages the bundle into the chroot** *(2026-07-14, P7.0e)*: with `BootConfig.jail`
  set, the clone spawns under the jailer and this decision's staging happens chroot-relative, the
  state file copied in, the memory file and a shared base disk **bind-mounted read-only** (clones
  keep sharing one page cache), a private disk copy staged at the baked-in path resolved inside the
  chroot and unstaged once the VMM holds the fd. **Snapshotting a jailed VM is refused**, deliberately,
  not just deferred: its disk lives at a chroot-relative path inside a torn-down-with-the-VM chroot,
  so a bundle would record an unrestorable backing, and the clone story doesn't need it. Snapshot an
  *unjailed* pre-warmed source (it runs only the embedder's warm-up), restore **jailed** clones from it:
  the untrusted code runs confined, and the confined pre-warmed `Pool` falls out of the same approach.
