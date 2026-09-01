# A run, start to finish

Boot, exec, teardown, and the pre-warmed pool. The teardown section is the subtle part of the codebase and the part most worth reading carefully.

## Booting a sandbox

`Vm::boot` is the entry point. `Sandbox::open` is a thin wrapper over it. The sequence, in order:

**1. Refuse-first preflight.** The checks run before anything is touched, each returning a typed
error that names its own fix:

- `refuse_uncappable_boot`, for a `require_limits` boot that cannot be capped, because caps live on the
  jailed VMM's cgroup and an unjailed run is definitionally uncapped.
- `refuse_unusable_scratch`, for a jailed boot whose scratch dir sits on a `nodev` or `noexec` mount,
  since the jailer's chroot needs a working `/dev/kvm` node and an executable `firecracker` copy there.
- `refuse_unsupported_vcpus`, for a count the pinned VMM will reject.
- `refuse_offlink_gateway`, for a networked boot whose configured gateway is off the guest's own `/30`
  link: the guest cannot ARP it, so the kernel would refuse the default route and the sandbox would
  come up sealed, reading as "the gateway option does not work" rather than as the typo it is.

The pattern is worth internalizing, because it recurs: **find out early and say so**, rather than
spawning a VMM and letting a raw Firecracker error surface deep in boot. Each of these exists because
the deep-in-boot version of the failure was confusing enough to be mistaken for an engine bug.

**2. The KVM check**, done here rather than inside `launch`, so the launch and boot-failure machinery
stays unit-testable on hosts without KVM (a fake `firecracker` needs no VM).

**3. One deadline for the whole boot.** `boot_deadline` is computed once and shared by host-side
staging and the API boot, so a slow rootfs copy cannot run unbounded before the boot's own timeout
even starts.

**4. `Spawned::launch`** does the host-side staging, all of it under that deadline:

- `create_workdir` (in `spawn/workdir.rs`) mints `<scratch>/bsx-<pid>-<seq>` **fail-if-exists at mode 0700**, advancing the
  sequence on collision. Both properties matter: the scratch base is world-writable and the name is
  predictable, so a pre-existing directory must never be adopted. The name is also deliberately
  *short*, because the jailer nests it **twice** inside the API socket path, which must fit
  `sockaddr_un.sun_path` at roughly 108 bytes.
- The workdir is immediately wrapped in a `WorkdirGuard`, whose `Drop` removes it on every exit from
  the staging window, an error return or an unwinding panic alike. It is disarmed only once a tap may
  exist, from which point the netns-aware reclaim helpers own cleanup instead.
- The rootfs is either **shared** (a `read_only_root` boot hands Firecracker the pinned base `O_RDONLY`
  and the guest's writable layer comes from its tmpfs overlay) or **copied** per VM. The copy is the
  heaviest host-side step, so the deadline is checked before it and re-checked by each later step.
- Bulk `input_dir` and `output_dir` become ext4 images in the workdir, attached as extra block devices.
- Networking, when asked for, is a per-VM netns holding a tap.
- A jailed boot spawns the jailer (not `firecracker` directly) and stages resources into its chroot;
  an unjailed boot spawns `firecracker` itself.

**5. `run_boot`** drives the Firecracker API socket through the boot sequence and waits for the guest's
readiness marker on the console. That marker is configurable, because it is a property of the rootfs
image rather than of the engine.

**6. The probes attach after boot**, not before: the sandbox has to exist before anything can be
bound to it.

## Executing a command

Exec rides `crates/channel` over vsock. The protocol is deliberately dull: a 5-byte header (a tag plus
a little-endian `u32` length) and then a payload, with **the length checked against `MAX_PAYLOAD`
(1 MiB) before anything is allocated**. That ordering is the whole defense against a hostile guest
declaring a 4 GiB frame.

`bsx-channel` is nearly dependency-free (`zeroize`, giving the post-send secret wipe a volatile store,
is the one dependency; its `Cargo.toml` states why), and is shared verbatim by the driver and the
in-guest agent, so a wire-format change reaches both sides in the same commit.

Inside the guest, `guest-agent` runs one command per connection and streams stdout, stderr, and the
exit status back as frames. It is built static against musl and baked into the rootfs. It is
**exec and I/O convenience, not a security boundary**: a guest that compromises it has compromised
something the threat model already assumes is hostile.

Three bounds apply to every exec, and each exists because a hostile guest can otherwise grow host cost
without limit:

- A **wall-clock budget**, so a command that never exits becomes a typed timeout.
- An **aggregate output cap** (16 MiB by default). Each frame is already bounded by `MAX_PAYLOAD`, but
  a guest can send unboundedly *many* frames, so the total is capped too. Per-frame overhead is charged
  toward the cap as well, so even empty frames spend it; `exec_output_cap_is_enforced` pins the cap and
  `output_cap_counts_file_path_bytes_not_just_data` pins the overhead accounting.
- A **vsock connect and handshake deadline**, so a dead or stalled guest is a typed error rather than a
  host hang. Liveness is the transport's job.

## Teardown, and the paths you do not call

This is the subtle part of the codebase, and the part most worth reading carefully. Design rule 5 says
a hostile or crashing guest should surface as a typed error rather than a panic, hang, or leak, and
most of the machinery here exists to hold up the "leak" half under conditions where ordinary `Drop` is
not enough.

There are four layers, each covering a failure the previous one cannot:

**`Drop` on `RunningVm`** handles the ordinary path, including an early `?` return or an unwinding
panic. It reclaims the VMM, the workdir, and the out-of-workdir residue (the tap, the jailer's cgroup)
that the workdir removal would otherwise miss.

**The sentinel** covers losing the whole driver process, where no destructor runs at all: Ctrl-C,
SIGKILL, an OOM kill. It is a small POSIX `sh` process holding the read end of a pipe. The kernel
closes the write end when the driver dies **on any exit path**, so `read` returning EOF *is* the death
notification: no polling, no signal handlers, no timers. It runs `trap ''` first, so a SIGINT racing
the new process group cannot kill the sentinel before it does its job, and everything after the `read`
is best-effort and idempotent, so on a clean teardown it finds the directories already gone and falls
through instantly. Teardown waits a bounded time for a disarmed sentinel and then hard-kills it,
because the driver must never hang waiting on its own cleanup helper.

**`cgroup.kill`** is what makes the kill itself atomic and complete: one write takes down the entire
VMM process tree without enumerating pids, which is why it is also the capability
[`bsx doctor` probes for](./cli-commands.md#bsx-doctor) rather than inferring from a kernel version.

**The orphan sweep** (`sweep.rs`, public as `sweep_orphans`) is the backstop for residue that outlived
everything above, from a driver killed in a way that defeated even the sentinel. It scans the scratch
base for `bsx-<pid>-<seq>` directories whose owning pid is gone, detaches any mounts underneath (a
leaked bind mount would otherwise make removal fail with `EBUSY` and silently poison later mountinfo
scans), and reclaims them.

Two smaller guards follow the same shape: `StagedDisk` for the restore path's out-of-workdir disk copy,
and `ensure_private_staging_dir`, which refuses to adopt a staging directory that is not owned by us at
mode 0700, because a snapshot bakes in a predictable path that a local attacker could pre-create.

The confinement suite (`crates/engine/tests/confinement.rs`) is where these are exercised:
`driver_death_cannot_leak_a_vm`, `a_jailed_vmm_killed_mid_boot_leaves_no_mounts_behind`,
`sweep_reclaims_a_crashed_drivers_netns_and_scratch_dir`.

## Snapshots and the pool

`snapshot.rs` creates and restores Firecracker snapshots; `pool.rs` keeps pre-warmed clones so an
`open` can be served by a restore rather than a cold boot. A restore runs the **same** preflight guards
as a boot, which is why `refuse_unusable_scratch` is called from both.

Three snapshots are refused outright rather than half-supported, each because the bundle would
record something unrestorable. [The VMM and its jail](./architecture-firecracker.md) has them with
the API-level reasoning.
