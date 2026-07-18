# 011. Restore identity: the agent re-addresses the clone; VMGenID reseeds it *(2026-07-12)*

**Problem.** Restore hands every clone a byte-identical copy of one guest memory image, so anything
that must be unique per VM but was frozen into that image is now shared: the guest's **network
identity** (IP/MAC/routes), its **RNG state**, and its **clocks**. Network identity is the
load-bearing one here because Phase 4 addresses the guest via the kernel `ip=` parameter (decision
009), which runs exactly once, before userspace, at the *source's* boot; it cannot re-fire on
restore, so a clone wakes still holding the snapshot's baked-in address on a link it no longer
matches.

**Decision (network): keep `ip=` for cold boot; the guest agent applies a fresh identity on restore.**
- **Cold boot is unchanged.** `ip=` stays the cold-boot fast path: zero overhead, no rootfs change,
  and nothing about restore makes it worse at that job.
- **On restore of a networked snapshot**, the driver recreates the snapshot's recorded tap (see the
  v1.9 constraint below), assigns its host end a **fresh /30** from the same allocator cold boot uses,
  and then the **guest agent replaces the baked-in `eth0` address** with the new one, one
  `sh -c "ip addr flush … && ip addr add <fresh>/30 …"` over the vsock exec channel, after the
  exec-readiness poll. This is the runtime counterpart of boot-time `ip=`: same address shape, same
  **empty-gateway invariant** (`ip addr add` installs only the connected /30 route, so deny-by-default
  (decision 008) holds for clones exactly as for cold boots, proven by the off-subnet check in
  `restored_networked_clone_gets_a_fresh_identity`).
- **Core-property check:** this puts network *configuration* in the guest agent, acceptable because the agent
  is exec/IO convenience (core property 2) and enforcement never moves in-guest: policy stays host-side (the
  route shape today, eBPF at the tap from Phase 11). A guest that tampers with its own address gains
  nothing: the host end of the /30 and the tap it enforces on are outside its reach.
- **MAC is deliberately not changed.** The clone keeps the snapshot's MAC; each clone sits on its own
  point-to-point tap (a separate L2 segment), so MAC uniqueness across taps is irrelevant, and on
  v1.9 only one networked clone can be live at a time anyway.
- A **networked snapshot without vsock is refused** (typed): there would be no channel to re-address
  its clone, which would otherwise wake permanently mis-addressed.

**The v1.9 constraint (probed, not assumed).** `PUT /snapshot/load` on the pinned Firecracker v1.9
rejects `network_overrides` ("unknown field", probed against the real binary), so the snapshot's
recorded `host_dev_name` is fixed: restore must present a tap with **exactly that name**. Consequence at
the time: **only one networked clone can be live at a time** on v1.9. ***(Resolved: decision 017 (P7.0c)
gives each clone its own network namespace, so all recreate the same baked-in tap name without colliding,
concurrent networked clones now run, and `Tap::create_named` + the in-guest re-addressing below are
deleted.)*** Concurrent networked clones needed either a Firecracker with `network_overrides` (a
deliberate version bump) or per-VM network namespaces (the Phase-6 jailer), deferred to whichever lands
first, the netns route landed. Non-networked pre-warmed clones keep their unbounded concurrency (P5.4).

**Decision (entropy): rely on VMGenID, and prove it.** Both halves are already in the pinned stack:
Firecracker v1.9 ships the VMGenID device and bumps the generation on snapshot restore, and the
pinned 6.1.102 guest kernel carries the `vmgenid` driver (present in 5.18+), which reseeds the kernel
CRNG on a generation bump. `restored_clones_do_not_share_entropy_or_freeze_the_clock` proves it end
to end: two clones restored from one snapshot draw 16 bytes from `getrandom` immediately after
restore, the dangerous window, before any natural interrupt-entropy reseed, and the draws differ.
No engine mechanism was added because none is needed; if a future kernel/VMM pin loses either half,
that test fails and the gap is visible, not silent.

**Decision (clocks): document the staleness; don't fix it up.** kvm-clock keeps the monotonic clock
sane across restore, but the guest's **wall clock lags by the snapshot's age** (measured: a clone
restored ~9 s after its snapshot reports a wall clock ~9 s behind the host). The engine does not
reach into the guest to set the time: a fix-up belongs to the workload or a later phase's explicit
mechanism (and the audit log timestamps host-side, so the audit trail never depends on guest
clocks). Recorded as a documented limitation the pre-warmed-pool docs must carry: code that trusts guest
wall-clock time (TLS validity windows, token expiry) can misbehave in a clone until it resyncs.

**Alternatives considered (network).**
- **MMDS (Firecracker's metadata service) + in-guest fetch.** Cloud-init-style: bake a fetch-and-apply
  step into the rootfs, host writes per-clone metadata. Rejected: a second in-guest config surface and
  a rootfs change, to deliver exactly what the existing exec channel already delivers with one
  command; MMDS earns its keep only when clones need richer metadata than an address.
- **A tiny DHCP server per tap.** Rejected: a persistent host-side daemon per VM (or a shared one
  with per-tap scoping) is a heavy, stateful addition for a two-address /30 whose contents the driver
  already knows; and the guest would need a DHCP client re-trigger on restore anyway, the same
  "poke the guest after resume" shape as the agent path, plus a daemon.
- **Reuse the source's /30 for the clone.** Rejected: only ever works for a single sequential clone,
  couples the clone's identity to the source's lifetime, and silently breaks the moment two clones
  overlap; a fresh /30 keeps the isolation story uniform with cold boots.

**Consequences and notes.**
- `Snapshot` records the tap name; `Tap::create_named` reserves a fixed name with a fresh /30
  (`ip addr add` remains the /30's atomic reservation, as in decision 009).
- The **guest `ip` tool is now load-bearing for restore** (busybox `ip` in the agent rootfs); a future
  rootfs slimming that drops it would break networked restore; the typed error from the identity
  step names the guest's stderr, so the failure is legible.
- **Decision 009 addendum:** boot-time `ip=` is cold-boot-only by nature; restore identity is this
  decision's runtime path. If that runtime path ever proves cleaner for cold boot too, unify then,
  with evidence, not speculatively.
