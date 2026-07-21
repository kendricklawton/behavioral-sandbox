# 009. Snapshots are self-contained bundles restored by staging the disk *(2026-07-12)*

**Context.** The engine's fast-start story rests on snapshots: boot one microVM, snapshot it, then
restore many clones (and keep a pre-warmed pool warm) instead of cold-booting each. Restore is
dramatically cheaper than a cold boot, which is the whole reason snapshots exist. Two forces shape how a
snapshot is built. First, a snapshot must outlive its source: a bundle that can be moved or kept after
the source VM is gone is what makes "snapshot then restore N clones" and a pre-warmed pool tractable.
Second, Firecracker opens each drive's backing file during `PUT /snapshot/load`, at the path baked into
the snapshot, *before* any `PATCH /drives` can repoint it, so the recorded path must be valid at load
time. Staging the disk at that recorded path is the minimal correct way to honour that load-time
contract without a shared mutable backing file.

**Decision.** A microVM snapshot is a **self-contained bundle** in one directory: the vCPU/device
**state** file, the full guest **memory** file, and a **point-in-time copy of the root disk**.
- **Take it paused, copy the disk in the paused window.** `RunningVm::snapshot` does `PATCH /vm
  {Paused}` (freeze vCPUs) then `PUT /snapshot/create {Full}`, and copies the root disk *while paused*
  so the on-disk bytes agree with the frozen memory image, then `PATCH /vm {Resumed}`. A create
  failure still falls through to the resume, so a failed snapshot never leaves the guest frozen (the
  no-hang discipline).
- **Restore stages the disk at the recorded path, then unlinks it.** Firecracker opens each drive's
  backing file **during `PUT /snapshot/load`**, at the path baked into the snapshot, *before* any
  `PATCH /drives` can repoint it (the rebase-after-load path fails on the source's since-reclaimed
  scratch path). So `Vm::restore` copies the bundle's private disk
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
  recreate its host endpoints on restore. So the read-write, private-copy path lands first;
  read-only-base pre-warmed snapshots come later.

**Consequences and notes.**
- **Restore is dramatically faster than cold boot:** dev box, ~1.57 s cold vs **~8.9 ms** restore
  (≈177×). This is the fast-start reason the capability exists; the tracked p50/p99 benchmark lands later.
- **Snapshotting is scoped to a root-disk-only, read-write boot.** A VM with vsock, a NIC, or an output
  device is a typed error today (its host endpoints can't be recreated on restore yet), and
  a read-only shared base is deferred. The guard is structural (the root backing must live
  inside the VM's scratch dir), so it can't silently produce an unrestorable bundle.
- **The restored VM has no exec channel yet.** vsock-over-snapshot (so a restored pre-warmed VM can run code)
  comes later; today restore exposes liveness + teardown, and `boot_latency()` on a restored VM holds the
  restore latency.
- **Bundle size is state + ~guest-RAM memory + a full root-disk copy.** Copying the whole disk per
  snapshot is the honest cost of a portable, read-write bundle; diff snapshots and base-sharing (memory-sharing
  over the pre-warmed pool) are later optimizations.

**Pre-warmed snapshots + concurrent clones (2026-07-12).** Extended to snapshot a
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
  **cwd**, so the recorded relative path resolves per-clone. This is lighter than the jailer's
  per-VM mount namespace and doesn't block the pre-warmed pool on it. Consequence: every *file* path handed
  to Firecracker must now be **absolute** (its cwd is no longer the driver's), a small resolve-to-
  absolute pass on kernel/rootfs/bundle paths; the vsock path is the one deliberate exception.
- **Restore waits for exec-readiness.** A just-resumed guest agent needs a moment before its vsock
  listener is reachable again, so restore polls a connect until it succeeds (bounded by the deadline)
  before returning, its analogue of boot's userspace-marker wait. Restore of a pre-warmed agent VM measured
  ~8 ms vs ~300 ms cold boot, then the clone runs code.
- **Still deferred:** a snapshot with an **input or output device** is a typed error (per-clone
  images a restore can't yet recreate). A **NIC** is no longer deferred: a networked clone restores
  into a fresh per-VM netns and reuses the snapshot's baked-in identity, isolated by its namespace
  (decision 014, superseding the earlier fresh-identity re-addressing).
  `ci-privileged` now runs the VM tests serially (they boot
  real microVMs and some assert on host-global leak state).
- **Restore identity: entropy and clocks** *(folded from the retired restore-identity record,
  2026-07-21)*. **Entropy: rely on VMGenID, and prove it.** Both halves are already in the pinned
  stack: Firecracker v1.9 ships the VMGenID device and bumps the generation on snapshot restore, and
  the pinned guest kernel's `vmgenid` driver reseeds the kernel CRNG on a generation bump.
  `restored_clones_do_not_share_entropy_or_freeze_the_clock` proves it end to end: two clones
  restored from one snapshot draw from `getrandom` immediately after restore, the dangerous window
  before any interrupt-entropy reseed, and the draws differ. No engine mechanism was added because
  none is needed; if a future kernel/VMM pin loses either half, that test fails and the gap is
  visible, not silent. **Clocks: document the staleness; don't fix it up.** kvm-clock keeps the
  monotonic clock sane across restore, but the guest's wall clock lags by the snapshot's age; the
  engine does not reach into the guest to set the time (a fix-up belongs to the workload, and the
  audit log timestamps host-side). A documented limitation the pre-warmed-pool docs carry: code that
  trusts guest wall-clock time (TLS validity windows, token expiry) can misbehave in a clone until
  it resyncs.
- **Jailed restore stages the bundle into the chroot** *(2026-07-14)*: with `BootConfig.jail`
  set, the clone spawns under the jailer and this decision's staging happens chroot-relative, the
  state file copied in, the memory file and a shared base disk **bind-mounted read-only** (clones
  keep sharing one page cache), a private disk copy staged at the baked-in path resolved inside the
  chroot and unstaged once the VMM holds the fd. **Snapshotting a jailed VM is refused**, deliberately,
  not just deferred: its disk lives at a chroot-relative path inside a torn-down-with-the-VM chroot,
  so a bundle would record an unrestorable backing, and the clone story doesn't need it. Snapshot an
  *unjailed* pre-warmed source (it runs only the embedder's warm-up), restore **jailed** clones from it:
  the untrusted code runs confined, and the confined pre-warmed `Pool` falls out of the same approach.
