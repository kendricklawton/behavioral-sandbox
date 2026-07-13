# 005: The boot you only pay once (snapshots, guest memory, and what restore must fix up)

> Phase 5 of the sandbox engine. Phases 1 to 4 built a microVM that boots, runs code, owns a disk,
> and gets a controlled network. Phase 5 makes it **start in milliseconds**: pause a warm VM, write
> what it *is* to disk, and restore any number of exec-ready clones from that one frozen image,
> paying the cold boot exactly once.

```rust
let snap = vm.snapshot(&dir)?;                 // pause, write state + memory, resume
let clone = Vm::restore(&snap, &config)?;      // a fresh VMM resumes the frozen guest in ~10 ms
let mut pool = Pool::new(snap, config, 4)?;    // or keep clones pre-restored and exec-ready
let vm = pool.take()?;                         // ~1 ms pop + health probe, then exec immediately
```

A running VM feels like a machine, but to the host it is just **state**: vCPU registers KVM holds,
device-model state the VMM holds, guest RAM in a host memory mapping, and a disk backing file.
Snapshotting is serializing that state; restoring is handing it to a brand-new VMM and resuming.
The lesson of the phase is in the last step: a byte-identical copy of a machine is *too* identical,
and three kinds of state (network identity, entropy, clocks) must be fixed up, worked around, or
honestly documented before clones are safe to hand out.

## What a snapshot actually is

`RunningVm::snapshot` produces a **self-contained bundle** in one directory (ARCHITECTURE decision
010): a **state** file (vCPU registers and device state), a **memory** file (all of guest RAM), and
the root **disk**. The take sequence is `PATCH /vm {Paused}` (freeze the vCPUs), `PUT
/snapshot/create {Full}` (write state + memory), copy the disk, `PATCH /vm {Resumed}`.

Two details carry the correctness:

- **The disk is copied inside the paused window.** Memory and disk are one coherent machine state:
  the guest's page cache, in-flight writes, and filesystem all assume the disk matches the frozen
  RAM. Copy the disk while the guest still runs and the bundle holds a disk from *after* its
  memory, a subtle corruption you only meet later. Pause, copy, resume: the copy is of a quiesced
  disk that agrees with the frozen memory image.
- **A failed create still resumes the guest.** The pause and the create are separate calls, so the
  driver guarantees the `Resumed` patch runs even when the create errors: a failed snapshot is a
  typed error, never a guest left frozen (the no-hang discipline on the host path).

A "warm" snapshot is the same mechanism pointed at a more valuable moment: boot the agent rootfs,
run `python3 -c "import json, os, sys"` once so the interpreter and its imports are resident in
guest RAM, *then* snapshot. The bundle now holds a machine where Python has already started; every
clone inherits that work for free.

## Guest memory: the file is the VM

The memory file is the interesting artifact. It is all of guest RAM (256 MiB at today's default),
and on restore Firecracker does not read it into fresh memory: it **maps** it copy-on-write
(`MAP_PRIVATE`). That one mmap flag is most of the phase's economics:

- **Pages fault in lazily.** A restored clone doesn't touch 256 MiB up front; it faults pages in
  from the file as the guest touches them. That is why restore is ~10 ms and not "read 256 MiB".
- **Clones share pages through the host page cache.** Ten clones mapping one memory file read the
  same cached pages; the Python interpreter warmed into the image exists **once** in host RAM no
  matter how many clones run it.
- **Writes are private.** The first write to a mapped page copies it (copy-on-write) into anonymous
  memory owned by that clone. A clone's true memory cost is its **dirty pages**, not its RAM size.

The disk side tells the same density story. A warm snapshot is taken from a `read_only_root` boot,
so the bundle doesn't copy the disk at all: it records the shared pinned base **in place**, and
every clone opens it read-only with its own in-RAM overlay on top. Contrast the honest baseline
this repo started from: booting a full private rootfs copy per sandbox (≈300 MB for Phase 1's
Ubuntu image, 132 MiB for today's agent image), which on a tmpfs `/tmp` is that much host RAM per
sandbox. A warm clone copies nothing: one shared base, one shared memory file, per-clone cost =
copy-on-write dirty pages.

## The disk contract restore must honor

One Firecracker behavior shaped the whole restore design, and it was learned by watching a restore
fail, not by reading docs: **Firecracker opens each drive's backing file during `PUT
/snapshot/load`, at the exact path recorded in the snapshot**, before any `PATCH /drives` could
repoint it. The recorded path must be valid at load time, and for a read-write bundle that path is
the *source's* scratch dir, which may be long gone.

The fix is a small piece of Unix craft: **stage, load, unlink**. Restore copies the bundle's
private disk to the recorded path (refusing to overwrite, so a still-live source is never
clobbered), loads with `resume_vm: true`, and once the VMM holds the open fd, **unlinks** the
staged file. The clone's disk becomes an anonymous inode: alive as long as the fd is (this is just
Unix unlink semantics), owned by exactly one VM, sharing no writable backing with anything, and
leaving nothing on disk to clean up. Read-only warm bundles skip all of this and reference the
shared base directly.

The same load-time-rebinding theme hit the exec channel. The snapshot records the vsock Unix-socket
path, and Firecracker re-binds a listener **at that recorded path** on load, so concurrent clones
of one snapshot collided on it (`Address in use`, probed empirically). The fix: record a
**relative** socket path (`v.sock`) and run each VMM with its own scratch dir as **cwd**, so the
recorded path resolves per-clone. Cheaper than a mount namespace, available before the Phase 6
jailer, and with one consequence worth remembering: once the VMM's cwd moved, every *file* path
handed to Firecracker had to become absolute. The relative socket is the one deliberate exception.

## The state you must fix up on restore

Here is the phase's core lesson. Restore hands every clone a byte-identical copy of one machine,
and three kinds of state were frozen into that image that must **not** be identical across clones
(ARCHITECTURE decision 011):

**Network identity.** Phase 4 addresses the guest with the kernel `ip=` parameter, which runs
exactly once, before userspace, at the *source's* boot. It cannot re-fire on restore, so a clone
wakes still holding the snapshot's baked-in address on a link it no longer matches. The fix keeps
each mechanism where it is strongest: `ip=` stays the zero-overhead cold-boot path, and on restore
the **guest agent applies the clone's fresh identity at runtime**: the driver allocates a fresh /30
(same allocator as cold boot), recreates the tap, and sends one command over the exec channel
(`ip addr flush dev eth0 && ip addr add <fresh>/30 dev eth0`). The empty-gateway invariant carries
over: the clone gets its connected /30 route and **no default route**, so deny-by-default (decision
008) holds for clones exactly as for cold boots. Configuration rides the agent; enforcement stays
host-side, which is the spine's division of labor.

One probed constraint bounds this: the pinned Firecracker v1.9 rejects `network_overrides` on load
("unknown field", against the real binary), so the snapshot's recorded tap **name** is fixed and
restore must recreate exactly it. Only **one networked clone can be live at a time** on this pin;
the sanctioned paths out are a Firecracker bump or the Phase 6 jailer's per-VM network namespace.
Non-networked clones have no such limit.

**Entropy.** This is the quietly dangerous one. Every clone wakes with the CRNG state that was
frozen at snapshot time: identical entropy pools, so, naively, identical "random" bytes. Two clones
generating a TLS key, a session token, or a nonce would generate the *same* one. The fix is already
in the pinned stack, and the engine's job was to **prove** it rather than add mechanism:
Firecracker v1.9 ships the **VMGenID** device and bumps its generation on restore, and the pinned
6.1.102 guest kernel's `vmgenid` driver reseeds the kernel CRNG when the generation changes. The
test restores two clones from one snapshot and has each draw random bytes *immediately*, in the
dangerous window before any natural reseed: the draws differ. If a future kernel or VMM pin loses
either half of that contract, the test fails visibly instead of the property rotting silently.

**Clocks.** kvm-clock keeps the guest's **monotonic** clock sane across restore (timers and
timeouts behave). The **wall clock** is another matter: it lags by exactly the snapshot's age
(measured: a clone restored ~9 s after its snapshot reports a wall clock ~9 s behind). The engine
deliberately does not reach into the guest to fix it: a time fix-up belongs to the workload or a
later explicit mechanism, and the flight recorder timestamps host-side, so the audit trail never
depends on a guest clock. The documented consequence: guest code that trusts wall-clock time (TLS
certificate validity, token expiry) can misbehave in a clone until it resyncs.

There is a fourth fix-up hiding in plain sight: **readiness itself**. A cold boot signals userspace
via the console marker; a restored guest prints nothing (it was already booted). Restore's
analogue is a bounded poll: connect to the agent's re-bound vsock listener until it answers, and
only then return the clone. The same "nothing listening yet" condition got a name in the error
taxonomy, `VmmError::GuestUnavailable`, typed as transient/retryable, which is exactly what a pool
needs to tell "try the next clone" from "infrastructure is broken".

## The warm pool

With restore this cheap, the last step is keeping clones **pre-restored**: `Pool` holds N
exec-ready clones of one warm snapshot. `take()` pops ready stock and health-probes the candidate
(a fast connect to its agent); a clone that died while pooled is a typed `GuestUnavailable` from
the probe, so it is discarded and the next is tried, and a dry pool restores inline rather than
failing a take a fresh clone could serve. `refill()` is explicit: the caller pays restore time back
at a moment of its choosing (between requests), never on the hot path. The pool is **synchronous by
design**: the engine has no async runtime and no background threads on the host path, and a
self-refilling, concurrency-managed pool is the daemon's job (Phase 16), not the library's.

## Measured, not marketed

`cargo xtask bench-warm` times all three start paths end to end, from "start a sandbox" to "a
Python one-liner's output is back on the host", n=100 per path, nearest-rank percentiles (dev box):

| start path                          | p50    | p99    |
|-------------------------------------|--------|--------|
| cold boot + exec (per-VM disk copy) | 689 ms | 943 ms |
| warm-snapshot restore + exec        | 105 ms | 172 ms |
| warm-pool take + exec               | 45 ms  | 90 ms  |

The raw restore (load + resume, before the exec) is ~10 ms; most of the remaining warm-path time
is Python itself running inside the guest, not the engine. And the footprint baseline falls with
the latency one: no per-sandbox disk copy, one page-cache-shared base and memory file, dirty pages
as the marginal cost.

## Try it

```console
# the numbers above, on your box (needs /dev/kvm + the built agent rootfs):
cargo xtask bench-warm

# the proofs (snapshot coherence, staging, concurrent clones, identity/entropy/clock fix-ups,
# the pool's discard-and-replace), serially, in the privileged gate:
cargo xtask ci-privileged

# without ambient caps, a user+net namespace grants what the tests need:
unshare -Urn --map-root-user sh -c 'ip link set lo up; cargo test -p agent-vmm --test boot -- --ignored --test-threads=1'
```

The demo is the bench plus eight privileged tests, from `snapshots_a_running_microvm` through
`warm_restore_returns_output_in_far_under_cold_boot` (restore a warm Python snapshot, run code,
output back in far under a cold boot: the phase's promise, asserted).

Phase 5 leaves the engine able to start a sandbox in tens of milliseconds instead of most of a
second, from one warm image, with the copied-machine hazards either fixed (network identity),
proven handled by the platform (entropy), or documented (wall clock). Next: the VMM itself gets
confined, jailer, cgroups, and seccomp, the other half of the isolation story, and the mechanism
that finally makes teardown survive even a dead host process.
