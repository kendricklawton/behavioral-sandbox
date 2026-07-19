# 009. The per-VM tap: shelled out to `ip`, deleted on every teardown path *(2026-07-12)*

**Context.** The driver's teardown model is "everything reclaimable lives in `workdir`": tear the
scratch dir down and the VM's resources go with it. A per-VM host **tap** breaks that assumption. It
is the first per-VM resource that lives **outside** the scratch dir, so `remove_dir_all(workdir)`
cannot reclaim it (decision 008's note flagged exactly this). That makes explicit teardown
load-bearing rather than incidental: a handle has to be threaded through the lifecycle and deleted on
every path, or a boot that fails after tap-create leaks an interface. Two further forces shape the
mechanism. The driver's style is dependency-light shell-outs to host tools (`mke2fs`/`truncate`/
`e2fsck`/`debugfs`), which keeps it `unsafe`-free and its dependency tree small. And uniqueness has to
hold across concurrent driver processes without a check-then-create race, the same constraint
`create_workdir` already answers.

**Decision.** With `BootConfig.enable_network`, the driver gives the guest a virtio-net `eth0` backed
by a per-VM host **tap**. Mechanism:
- **Create by shelling out to `ip` (iproute2)**, not a netlink crate, the same convention the driver
  already uses for `mke2fs`/`truncate`/`e2fsck`/`debugfs`. Creating a tap needs `CAP_NET_ADMIN`, so
  this is a privileged operation (like `/dev/kvm`); the integration test skips without the capability.
- **Host-global unique name via create-and-retry.** The name is `fc<hex>` (≤14 bytes, within the
  15-byte `IFNAMSIZ` limit), seeded from a PID-mixed counter. Uniqueness across concurrent driver
  processes rests on `ip tuntap add` failing on an already-taken name as the **atomic reservation**
  (detected by asking netlink whether the interface now exists, since `ip tuntap` fails with `EBUSY`,
  not the RTNETLINK `EEXIST`, on a collision), the same
  fail-if-exists-then-retry pattern as `create_workdir`, never a `/sys/class/net` scan (which would
  race between check and create).
- **A locally-administered unicast MAC** (`02:00:xx:xx:xx:xx`) derived from the per-VM index: first
  octet sets the LAA bit and clears the multicast bit, so every VM gets a distinct, valid NIC address.
- **Attach** via `PUT /network-interfaces/eth0` (`host_dev_name` + `guest_mac`), a sixth API body
  struct mirroring the vsock block.
- **Delete on every teardown path.** A tap lives **outside** the per-VM scratch dir, so
  `remove_dir_all(workdir)` cannot reclaim it. The `Tap` handle is threaded through `Spawned` and
  `RunningVm` (like `vsock_uds`/`output`) and deleted (`ip link del`) in all three reclamation paths,
  `RunningVm::drop`, `Spawned::drop`, and `Spawned::abort`, so a boot that fails *after* tap-create
  still cleans up. Deletion is best-effort (`tracing::warn!` on failure, never a panic, the host path
  is `#![forbid(unsafe_code)]`/no-panic).

**Alternatives considered.**
- **`rtnetlink` (a netlink crate) instead of shelling `ip`.** Rejected: it pulls an async dependency
  tree through `cargo deny` for no benefit; the driver's whole style is dependency-light shell-outs to
  host tools, and `ip` is already a documented `ci-privileged` requirement.
- **Encode VM identity in the tap name.** Rejected: `IFNAMSIZ` is 15 bytes and a PID+sequence blows
  the budget. The name is just a claimed host-global token; per-VM identity is the MAC (and, later, the
  subnet/CID the allocator will derive from the same index).
- **A `Drop` on `Tap`.** Rejected: `Spawned`/`RunningVm` already own the guaranteed-teardown `Drop`s;
  a second `Drop` would risk double-delete noise. One owner, explicit delete in the three paths.

**Consequences and notes.**
- **The allocator yields name + MAC + a point-to-point /30** (`subnet_for`): from
  `10.200.0.0/16`, host = block+1, guest = block+2, with the /30 index folding the PID bits down so
  concurrent processes don't collide at `NET_SEQ=0`. Guest addressing is the kernel `ip=` param
  (`CONFIG_IP_PNP`, present in the pinned kernel), so it needs no rootfs change; the host end is
  assigned in `Tap::create` and cascades away on `ip link del`. Still open on the same index: the
  guest **CID** (still the hardcoded `DEFAULT_GUEST_CID = 3`).
- **The /30 is atomically unique per VM.** The PID-fold only makes a same-`NET_SEQ` collision
  *unlikely*, and folding 64 bits to a 14-bit index means two distinct tap names can still map to one
  /30. So `Tap::create` makes the **host-address assignment the reservation**: `ip addr add` fails when
  another VM already holds that /30 (checked with `host_addr_exists`, netlink-truthy, not a string
  match), and the loop reclaims the tap and retries with a fresh token (the same fail-if-taken pattern
  as the name). Two concurrent sandboxes therefore never share a subnet, which is what keeps one VM off
  another's tap (proven by `two_vms_cannot_reach_each_others_tap`).
- **Per-VM network-namespace isolation is deferred, by design.** ***(Resolved: decision 017 moved the
  tap into a per-VM netns; the unique-/30 allocator below is retired, every VM now reuses one
  fixed /30, isolated by its namespace.)*** The isolation bar is met at L3: with no
  default route a guest can only address its own /30, so it can't even name another VM's tap, and the
  unique-/30 reservation removes the one way subnets could overlap. Putting each tap in its own netns
  (and running the VMM inside it) is stronger defence-in-depth but couples to running the VMM under the
  **jailer**; it's recorded here as the jailer's work, not built alongside the tap.
- **Deny-by-default holds by construction:** the guest is addressed on the /30 and can reach
  the host end, but the `ip=` gateway field is **empty**, so the kernel installs only the connected
  route, **no default route**, and the driver installs no masquerade or `ip_forward`. So the guest
  reaches the host and nothing else, until eBPF-enforced egress policy (decision 008) opens anything.
- **A hard-killed driver can still orphan a tap** (no `Drop`-of-temp-dir safety net, unlike the
  scratch dir), the same class of gap as a SIGKILL leaking a VM, and the reason the leak test scans
  for orphaned `fc*` interfaces. The durable owner is the jailer/cgroup model.
- **Kernel `ip=` addressing is cold-boot-only by nature** (learned once snapshot-restore landed): it
  runs exactly once, before userspace, so it cannot re-address a snapshot-restored clone. That is not a
  defect in this decision, it is the boundary of what boot-time config can do; restore identity is
  decision 011's runtime path (the guest agent applies a fresh address over vsock). `ip=` stays the
  zero-overhead cold-boot mechanism; if the runtime path ever proves cleaner for cold boot too, unify
  then, with evidence.
