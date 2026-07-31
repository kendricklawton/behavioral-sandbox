# The VMM and its jail

The isolation half: how the driver talks to Firecracker, what the guest ends up holding, and what
confines the VMM process itself. The observation half is [The eBPF half](./architecture-ebpf.md);
this is the side that makes the boundary hardware.

## Talking to Firecracker

Firecracker takes its configuration as HTTP/1.1 over a unix socket, one request per resource, and
`crates/vmm/src/firecracker.rs` hand-rolls the sliver of HTTP that needs rather than pulling in an
HTTP crate and an async runtime. That keeps the dependency graph of the crate an embedder pins
small, which [decision 7](./architecture-decisions.md#7-synchronous-engine-no-async-runtime) argues
is a security property rather than a preference.

Three pieces of framing are load-bearing, and a naive client hangs on each:

- **One fresh connection per request.** Keep-alive means "read to EOF" never returns, so every
  request sends `Connection: close` and the response is framed by `Content-Length`.
- **Success is `204 No Content`.** An empty body is the normal answer; a fault is `4xx` carrying
  `{"fault_message": "..."}`, which becomes the text of the typed error.
- **Every call is bounded.** Ordinary calls answer instantly and get a 5 second socket timeout,
  which only ever bounds a wedged VMM. `/snapshot/create` and `/snapshot/load` withhold their reply
  until Firecracker has moved the whole guest memory file, so they get a wall scaled by guest size
  instead.

Two bounds exist specifically because the VMM is the thing the jail assumes may be compromised. A
response body is refused past 1 MiB **before** anything is allocated, and the reader is clamped
before any line is read, since `read_line` grows without limit on a stream that never sends a
newline. And `DeadlineReader` re-arms the socket timeout to the *remaining* budget before each read
rather than trusting `SO_RCVTIMEO`, which every arriving byte resets: a peer dripping one byte just
inside the timeout would otherwise hold a call open indefinitely. The test
`a_drip_feeding_peer_trips_the_whole_response_deadline` feeds a byte every 20 ms forever against a
200 ms deadline and requires the call to fail.

## The boot conversation

`run_boot` in `spawn.rs` waits for the API socket to *accept* a connection (not merely exist, since
the file appears before `listen`), then issues these in order. Each is preceded by a deadline check,
because although the client caps each call individually, their sum also has to fit the boot's one
wall.

| # | Request | Sent when |
|---|---|---|
| 1 | `PUT /boot-source` | always: the kernel and its command line |
| 2 | `PUT /drives/rootfs` | always: read-only iff the boot is `read_only_root` |
| 3 | `PUT /drives/input` | only with `input_dir`, always read-only |
| 4 | `PUT /drives/output` | only with `output_dir`, read-write |
| 5 | `PUT /machine-config` | always: vCPU count and memory |
| 6 | `PUT /vsock` | only when a guest CID is set |
| 7 | `PUT /network-interfaces/eth0` | only when a tap exists |
| 8 | `PUT /actions` (`InstanceStart`) | always |

Boot latency is measured from step 8 to the guest's readiness marker, not from the top, so the
number reports the guest's boot rather than the driver's staging.

A **restore issues none of this**. The guest's devices, vCPUs, and memory are recreated from the
snapshot, so `Vm::restore` spawns a bare VMM and makes exactly one call, `PUT /snapshot/load`.

## What the guest ends up with

| Device | How it arrives |
|---|---|
| `/dev/vda` | the root drive; Firecracker adds `root=/dev/vda` to the command line itself |
| `/dev/vdb` | the bulk input image, opened `O_RDONLY` by Firecracker, which is what makes it immutable |
| the output drive | mounted **by label** (`ekvm-output`), since a boot may attach input, output, both, or neither, so the letter is not stable |
| `eth0` | one virtio-net backed by a host tap the driver creates first, inside a per-VM netns |
| vsock | one device on guest CID 3, the exec channel's transport |
| `ttyS0` | not an API call: `console=ttyS0` on the command line, and Firecracker wires it to its own stdout, which the driver captures |

There is no balloon device.

Every drive carries a derived rate limiter: 256 MiB/s sustained bandwidth with a 1 GiB one-time
burst, and no IOPS bound. The burst is sized past any rootfs the engine ships, so a cold boot's
rootfs read runs unthrottled by construction and only sustained thrashing is shaped. It is an
internal default rather than a `Limits` knob, so surfacing it later would be an additive change.
Unlike the cgroup caps, it **rides a restore**, because a clone reopens the drive from snapshot
state that carries the limiter.

## Not sending fields an older Firecracker would reject

Firecracker rejects unknown fields outright, so a request body written against the newest release
fails every call on an older one. The rule the code is written against: **gate any field newer than
the support floor on a `_SINCE` constant, so adding a field cannot silently raise the floor.**

The engine supports v1.15 through v1.16 and tests v1.16. The floor tracks upstream's own support
window rather than a number of convenience, because it exists to reject *unpatched* VMMs rather than
old ones; the reasoning and the procedure for moving it are in
[Firecracker version policy](./contributing-firecracker-policy.md).

`clock_realtime` on `PUT /snapshot/load` is the worked example. It exists from v1.16 and advances a
restored guest's clock by the time elapsed since the snapshot, which for a pre-warmed pool is the
common case rather than the exception. Sending it unconditionally broke restore on every older
release. It is now set from the probed version and **omitted** when the probe is unavailable or
unparseable, because the omitted body is the one every supported release accepts: guessing wrong
that way costs a clone whose clock did not advance, and guessing wrong the other way fails the
restore outright. `the_clock_fixup_is_gated_above_the_floor_not_at_it` asserts the gate sits
strictly above the floor, so if a future bump ever makes them meet, that assertion is the reminder
that the conditional has become dead code.

## The jailer

KVM contains the guest. The jailer contains the **VMM process**, so a Firecracker bug or a guest
that broke out into the VMM still lands in a chroot, under a dropped uid, in its own mount and
network namespaces, in a cgroup, behind Firecracker's own seccomp filters.

The jailer is a separate upstream binary. Given the VMM to exec and an id, it builds a chroot,
`mknod`s the device nodes the VMM needs (`/dev/kvm`, `/dev/net/tun`), places the process in a
cgroup, chroots, drops to uid/gid 10000, and execs Firecracker with its API socket at the
chroot-relative `/run/firecracker.socket`. The driver never creates the device nodes itself, which
is why the jailer needs real root: `mknod` of a device node is `EPERM` in a non-initial user
namespace even holding `CAP_MKNOD`.

**Everything the VMM opens must live inside the chroot and be named by its chroot-relative path**,
which is the single fact that shapes the rest of the jailed path. Three ways in, chosen by what the
resource is:

- **Copy**, for the kernel and a read-write rootfs. This is the honest cost of the jail on a
  read-write boot: those files live outside the chroot and hardlinking across the tmpfs boundary
  would `EXDEV`.
- **Read-only bind mount**, for the shared base image on a `read_only_root` boot, so every jailed VM
  shares one inode and its page cache. Two steps, since a bind mount is read-write regardless of
  `-o ro` on the first call and only the `remount,ro,bind` actually drops write access. It works
  only when the scratch dir sits under a *shared* host mount, because nothing else propagates into
  the jailer's `MS_SLAVE` namespace; otherwise it falls back to a copy. Memory sharing is
  best-effort, the isolation is not, and the copy confines identically.
- **Built in place**, for the bulk input and output images, since those builders are rootless
  `mke2fs` runs that take a target directory.

Each bind mount is recorded and unmounted before the scratch dir is removed, or the mount point
`EBUSY`s and leaks the chroot.

The cgroup is the jailer's to create, and the driver passes `--cgroup-version 2` explicitly because
the jailer defaults to v1 and would not find the hierarchy. Caps are memory (the budget plus a
128 MiB VMM overhead), CPU (a quota against a 100 ms period), and `pids.max` at 1024. That last one
is defense in depth for a narrow case rather than fork-bomb protection: a guest fork bomb lives in
the *guest's* kernel and never reaches the host, and Firecracker itself holds only an API thread, a
VMM thread, and one per vCPU, so 1024 is enormous headroom. Two flags are deliberately absent:
no `--daemonize`, so the guest's serial console still reaches the host, and no `--no-seccomp`.

Two things the driver does differently once chrooted are worth knowing before reading `spawn.rs`.
Staging happens **after** the API socket answers, since the chroot does not exist until the jailer
builds it. And the workdir name is deliberately short, because the jailer embeds it **twice** in the
API socket path, which must fit `sockaddr_un.sun_path` at 108 bytes; `check_sun_path` refuses up
front and names `EKVM_SCRATCH_DIR` as the fix, because the alternative is a `bind()` failing deep
inside Firecracker and surfacing as a boot timeout that says nothing.

## Snapshot and restore

Snapshotting pauses, writes, copies, and resumes, in that order:

1. `PATCH /vm` to `Paused`, freezing the vCPUs so the memory image is a consistent point in time.
2. `PUT /snapshot/create`, writing the device state and the full guest memory.
3. Copy the root disk **inside the paused window**, so it stays in step with that memory.
4. `PATCH /vm` to `Resumed`. A failed create still falls through to this, so the guest is never
   left frozen.
5. If the VM has vsock, poll the agent until it answers before handing the VM back.

A torn bundle is swept by a guard that runs on an error return or an unwinding panic alike.

Three snapshots are refused rather than half-supported, each because the bundle would record
something unrestorable: an **already-restored** VM (its live disk is an anonymous inode with no host
path), a **jailed** VM (its disk path is chroot-relative), and a VM holding **bulk input or output**
devices. The intended shape follows from the second: snapshot an unjailed pre-warmed source, restore
*jailed* clones from it, and the untrusted code runs in the clones.

Restore's constraint is that no Firecracker release offers a drive-path override on load, so the VMM
reopens the disk at the path baked into the snapshot. An unjailed restore of a read-write snapshot
is therefore single-flight; a jailed restore re-roots that path per chroot, and a `read_only_root`
snapshot shares one base, so either escapes it. The staging directory a restore uses is adopted only
when it is already private at mode 0700 and owned by us, because a blind `create_dir_all` would
adopt an attacker-planted world-writable directory and let a local user swap the staged disk before
the load opens it.

Snapshots also carry the producing host's CPUID features, so restoring on a different CPU model can
fault the guest with an illegal instruction. Cross-host restore needs matching CPU models or a
matching CPU template.
