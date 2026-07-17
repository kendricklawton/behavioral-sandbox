# Host-side observability & enforcement

The engine has two halves. [Using the engine API](./embedding.md) documents the Firecracker
driver: the hardware-isolation boundary that *contains* untrusted code. This document is the
other half: the host-side eBPF that
*observes and enforces* what that code does, from outside the guest where it can't be reached (core
property 2). Phase 8 establishes the foundation the later phases build on: build, load, attach, and
read one program end to end (syscalls P9, tap network P10/P11, cgroup P12, fused into the audit
log P13).

The worked example is a counter: `count_execve` attaches to the `sys_enter_execve` tracepoint and
tallies how many `execve`s the host does, into two maps. It is deliberately small; the point is the
path, not the payload.

## The two crates

- **`crates/probes`** (`#![no_std]`, `#![no_main]`) holds the in-kernel programs. It builds for
  `bpfel-unknown-none`, not the host triple, so it is *excluded* from the workspace and pins its own
  nightly toolchain (`-Z build-std=core`, since rustup ships no prebuilt `core` for the BPF target).
  `bpf-linker` links the LLVM bitcode rustc emits into a BPF ELF. `unsafe` lives here (raw map-pointer
  derefs); the host/driver path stays `#![forbid(unsafe_code)]`.
- **`crates/probes-loader`** is the userspace side, built with **aya** (pure-Rust, no libbpf/C
  toolchain), synchronous (no async runtime, matching the driver). Its public shape is a typed handle
  (`ExecveCounter::{load, count, counts_by_pid}`) returning a typed `ProbeError` — the eBPF analogue
  of the driver's `VmmError`. It reads the compiled object from a **path** (`cargo xtask build-probes`
  output, or `AGENT_PROBES_OBJECT`), never `include_bytes!`/`build.rs`, so the host workspace stays on
  stable and `cargo xtask ci` runs everywhere (decision 020).

## eBPF program types

An eBPF program is attached to a *hook*, and its type is the hook's shape: what context it gets and
what it may do. Phase 8 uses a **tracepoint** (`#[tracepoint]`), a stable kernel-defined event with a
stable argument format — here `syscalls/sys_enter_execve`. Its context is read-only; it returns 0.
The later phases use other types: **tc/`classifier`** and **XDP** on a VM's tap (P10/P11), where the
context is a packet the program may inspect and drop; and **cgroup** hooks for per-sandbox accounting
(P12). Same load/attach/map machinery, different hook.

## Maps

Maps are the shared memory between the kernel program and userspace. Two here:

- **`PerCpuArray<u64>`** (`EXECVE_COUNT`), one slot. **Per-CPU** means each CPU has its own copy of
  the slot, so the program increments with a plain `+= 1` and no cross-CPU atomic (contention-free);
  the loader reads all per-CPU copies and **sums** them. This is the idiomatic pattern for a hot
  counter.
- **`HashMap<u32, u64>`** (`EXECVE_BY_PID`), per-PID counts, bounded at 4096 entries (maps are sized
  at load). A full map drops new keys; the per-CPU total stays authoritative.

Maps are **BTF-defined** (see below), so their key/value types are described in the object's BTF and
aya validates them at load.

## The verifier

Before the kernel runs a BPF program it *verifies* it: every path must be safe and terminate. Two
of its rules the counter hits on purpose:

- **Bounded loops.** Walking the fixed 16-byte `comm` buffer to its NUL terminator is a loop whose
  bound is a compile-time constant, so the verifier can prove it terminates even with a data-dependent
  `break`. An *unbounded* `while` would be rejected. (Older kernels rejected all loops; bounded loops
  have been allowed since 5.3.)
- **Map access patterns.** A map lookup returns a pointer that may be null (key absent). The verifier
  **forbids dereferencing it without a null-check first**. `get_ptr_mut` returns an `Option`, so the
  `if let Some(slot) = ...` *is* the mandatory check; the deref happens only inside the `Some` arm,
  and we `insert` only on the miss (lookup-or-init).

The verifier runs **at load**, in the kernel, so a rejection needs a real load to surface — which is
why the verifier proof is a privileged test passing, not a host-gate check.

## CO-RE / BTF

**BTF** (BPF Type Format) is the kernel's compact description of its own types, exposed at
`/sys/kernel/btf/vmlinux`. **CO-RE** (Compile Once, Run Everywhere) uses it so one compiled object
runs across kernels whose structs are laid out differently: the object records *what field of what
type* it wants, and aya **relocates** those accesses against the running kernel's BTF at load. No
per-kernel recompile.

Two non-obvious build facts (a regression here ships a non-portable object, so `build-probes` asserts
the `.BTF` section is present):

- The object carries BTF only because the profile keeps **`debug = true`** (bpf-linker derives BTF
  from debug info) *and* the target passes **`bpf-linker --btf`** (off by default), via a
  `[target.bpfel-unknown-none]` link-arg.
- The counter reads no kernel struct fields yet, so it needs no *field-offset* relocations. Those
  arrive in Phase 9 (reading kernel structs). Here BTF is the map typing plus the load-time relocation
  path — the portability mechanism the later phases build on.

## Lifetime: no pinned residue

The aya `Ebpf` owns the program, its maps, and the live attachment. Dropping the loader (`Drop`)
detaches the program and frees the maps. Nothing is **pinned** into `/sys/fs/bpf`, so a crashed loader
leaves no kernel residue — the eBPF analogue of the driver's no-leak teardown (which reclaims taps,
netns, cgroups, and scratch dirs). Pinning stays opt-in, added only where a program must outlive its
loader (not on this path). This discipline matters more in P10/P11, where a leaked `tc` filter would
dangle on a torn-down sandbox's tap.

## Capabilities and the support probe

Loading and attaching the probes needs **`CAP_BPF`** (load programs/maps, read maps) and
**`CAP_PERFMON`** (attach a tracepoint via `perf_event_open`) — the two that split out of
`CAP_SYS_ADMIN` in Linux 5.8. **Not full root:** grant a loader binary just those with
`setcap cap_bpf,cap_perfmon+ep <binary>`. `check_support` names *those two* as the standard
requirement; an exotic host with only `CAP_BPF` and a permissive `kernel.perf_event_paranoid` may
attach anyway, but the pre-flight is a conservative advisory, not a sysctl-probing oracle. The
capability *bit logic* (which bits, correct masking) is unit-tested on the host gate; the end-to-end
"loads unprivileged with just the two caps" is verified by the `setcap` run above, not by CI (whose
privileged tests run as root, whose mask has every bit).

`check_support()` is the dependency guard (the eBPF analogue of the driver's Firecracker-version
probe): before a load it checks kernel BTF and the two capabilities and, if either is missing, returns
a **legible typed error naming the requirement** (`ProbeError::Unsupported`) rather than letting the
load fail with a cryptic verifier reject or `EPERM`. A host that can't run the probes says so plainly.

## Network observation on the tap (Phase 10)

`count_execve` sees only the *host's* syscalls, but a microVM's **network** is different: every packet
the guest sends or receives crosses its **tap** device on the host, so a program on the tap sees the
guest's own traffic directly. `TapMonitor` attaches two `tc`/clsact classifiers — `tap_ingress` and
`tap_egress`, the two hooks clsact adds to a device — and each parses the frame's IPv4 5-tuple and adds
the packet to that flow's per-direction byte/packet counters in the `FLOWS` map. `tc` (not XDP) because
clsact gives *both* directions uniformly on any device, and because Phase 11 enforcement (drop a denied
flow) lives at the same hook; P10 is observe-only (both hooks return `TC_ACT_OK`). The flow record
(`FlowKey` → `FlowCounts`) is single-sourced in `crates/probes-common` and read back as raw bytes, so
the loader stays `#![forbid(unsafe_code)]` (decision 023). A sandbox's tap lives in its own network
namespace (decision 017), so `TapMonitor::attach_in_netns` enters that netns (via `setns` behind nix's
safe wrapper, decision 024) to bind the monitor to one sandbox's `fc0`, and `totals()` sums the flows
into a per-VM rollup. Dropping the monitor frees its userspace handles; the sandbox's netns teardown
reclaims the `tc` filter, so attach-on-open and detach-on-close leave no host residue. `cargo xtask
watch-sandbox` boots a real networked sandbox and prints the per-VM flows its guest actually generated
— Phase 10's live view.

## Egress enforcement in the kernel (Phase 11)

Phase 10 observes; Phase 11 turns the same tap hook into **control**. The ingress classifier (a frame
the guest *sends*) now also consults a per-sandbox allow-list — the `POLICY` map of `PolicyRule`s
(destination CIDR + optional port/proto), single-sourced in `crates/probes-common` next to the flow
record. When the `ENFORCE` toggle is on, a guest-sent IPv4 packet whose destination matches no active
rule returns `TC_ACT_SHOT` (dropped at the tap, never leaves the host); a match returns `TC_ACT_OK`.
The per-rule test (`rule_matches`, a masked-CIDR + wildcard-port/proto compare) is shared by the kernel
scan and a host-unit-tested `egress_allowed`, so the verdict can't drift. The program scans the fixed
`MAX_POLICY_RULES` array in a **bounded loop** (the verifier's compile-time cap), and the mask is built
so the shift operand is always `< 32` (an out-of-range shift is a verifier reject).

Two deliberate carve-outs keep deny-by-default from being deny-*everything*: **ARP** is always allowed
(the guest must resolve its on-link gateway `10.200.0.1` before it can reach any endpoint), and the
**egress hook** (a reply arriving *to* the guest) always accepts, since egress policy governs what the
guest sends and replies to allowed traffic must return. Enforcement is **opt-in and per VM**: each
`TapMonitor` owns its own maps, and a monitor that never sets a policy stays observe-only (both hooks
accept, exactly the Phase 10 behavior).

The userspace schema is `EgressPolicy` — an allow-list built from friendly `Ipv4Addr` CIDRs and ports,
lowered to the `PolicyRule`s the map holds. Its **deny-by-default** is the safe default: the empty
policy (`EgressPolicy::deny_all()`, the `Default`) allows nothing, so a sandbox launched with no explicit
allowance reaches nothing — the eBPF, host-observed complement to the driver's no-route-to-the-world
deny-by-default (decision 008). `TapMonitor::set_egress_policy` applies a policy to an already-attached
monitor; `TapMonitor::enforce_in_netns` applies it **at launch**, arming the maps *before* the tc
programs go live on the tap so there is no window where the tap is up but un-policed (the first guest
packet is already policed). Rules go in as raw bytes (`PolicyRule::to_bytes`, so the loader needs no
`unsafe` `aya::Pod` binding); `clear_egress_policy` disarms.

Every dropped packet is **recorded** before the drop: the classifier counts it against its destination
in a `DENIALS` map, which `TapMonitor::denials()` reads back — the audit trail of which endpoints a
sandbox was blocked from (P11.5), which Phase 13 folds into the per-run record. The whole mechanism (map,
schema, deny-by-default, ingress-hook enforcement, ARP carve-out) is decision 025; `net_enforce.rs`
(ignored/privileged) proves a guest reaches an allow-listed endpoint and is blocked from everything else
(P11.7); and `cargo xtask enforce-sandbox` is the live exit-gate demo. Folding attach-and-enforce into
`Sandbox::open` at launch is Phase 13's convergence.

## Resource accounting from the cgroup (Phase 12)

Where Phases 10/11 watch the tap, Phase 12 meters the **cgroup**: how much host CPU, memory, and IO a
sandbox's VMM consumes running the guest. The CPU axis is the eBPF part — `account_sched_switch`
attaches to the `sched/sched_switch` tracepoint and, on every context switch, charges the on-CPU
nanoseconds the outgoing task just ran to that task's cgroup id in the `CPU_NS` map. It works because at
that tracepoint the scheduler has not yet swapped `current` (it still points at the task leaving the
CPU), so `bpf_get_current_cgroup_id()` is exactly the cgroup whose CPU slice just ended. A per-CPU
`LAST_SWITCH` cursor is always restamped so intervals stay exact. One consequence to know: a slice
**posts at switch-out**, so a still-running task's current slice is pending — a pegged vCPU can hold a
whole busy window un-posted until the guest idles and the thread blocks. Read after the run quiesces for
run-scoped totals; a mid-run read is a floor.

**One program, many sandboxes.** `sched_switch` is a *global* tracepoint, so the probe is attached
**once** and meters a *set* of cgroups (`METER_TARGETS`), not one program per sandbox — a
program-per-sandbox would run every attached program on every context switch (O(sandboxes) per switch).
`ResourceMeter::add_target(id)` registers a sandbox's cgroup, `remove_target` unregisters it, and the hot
path stays a single hash lookup no matter how many sandboxes are metered; `CPU_NS` holds only the
registered cgroups. `ResourceMeter::cpu_time(id)` reads the total back, and `cargo xtask bench-meter`
measures the honest per-context-switch cost (no meter vs attached-not-metering-us vs
attached-metering-us). That is the "bounded, sane under many concurrent sandboxes" property, measured.

**Correlated to the sandbox, all three axes.** The `id` is exactly what `cgroup_id_of_pid(vmm_pid)`
resolves, so the CPU track lines up with the Firecracker per-VM cgroup; `cgroup_dir_of_pid(vmm_pid)` gives
the dir for the other two axes. Memory and IO don't need a probe — cgroup v2 already maintains them per
cgroup, so `CgroupStats::read` reads `memory.peak`/`memory.current`, `io.stat` (rbytes/wbytes summed), and
`cpu.stat`'s `usage_usec` (an independent cross-check on the eBPF CPU total) straight from the cgroup dir,
best-effort (every field an `Option`, so a missing controller or older kernel is a `None`, never an error
— accounting fails open, decision 013). `ResourceMeter::summary_for_pid(vmm_pid)` rolls all three into a
`ResourceSummary` for one sandbox. That is the "cgroup-bpf **or** cgroup + tracepoints" the phase allows:
eBPF where per-event timing earns its keep (CPU), the kernel's own counters where they already exist
(memory, IO). The whole mechanism is decision 026; `resource_meter.rs` (ignored/privileged) proves a
CPU-heavy run reports more CPU than an idle one attributed to the sandbox (P12.5); `cargo xtask
meter-sandbox` is the live exit-gate demo. The engine *measures*; the hoster *bills*.

## The fused audit record (Phase 13)

Phases 9–12 each drive one probe standalone; Phase 13 binds all three to a launched sandbox and fuses
their output into one per-run **audit record**, host-observed from outside the guest. It lives in
`probes-loader` (not `agent-vmm`, decisions 024/026/028), bridged to the driver only by plain values:

- **Two shared probes + a per-VM tap.** The `sched_switch` meter and the `sys_enter_*` tracepoints are
  global, so each is loaded **once** for the host — `SharedMeter` and `SharedTracer` — and every sandbox
  registers its cgroup as a *target* on both (bounded overhead, decision 028). The tap monitor is per-VM.
- **One post-boot attach.** `SandboxProbes::attach(vmm_pid, netns, tap, egress, &tracer, &meter)` runs
  once after `Sandbox::open`: it resolves the VMM's cgroup, registers it on the shared tracer + meter, and
  attaches the tap in the sandbox's netns (enforcing an egress policy if given). Every axis is fail-open —
  a missing cap/BTF/object degrades to a recorded `AxisGap`, never a blocked run.
- **Finalize + detach on close.** `SandboxProbes::collect(timing)` reads the three probes into a
  `RunRecord` **and** unregisters this run's cgroup from the shared sets, while the sandbox is still alive.
  Dropping without collecting detaches only (the abandoned path). Timing enters as plain `Duration`s the
  caller lifts from `Sandbox::boot_latency` + `RunResult::metrics.wall`.
- **The record.** `RunRecord` fuses network flows + per-VM totals + egress denials (tap), CPU + memory/IO
  (`ResourceSummary`), and the VMM's bounded host-syscall footprint, with `coverage` gaps for whatever was
  unavailable. Its core is network + resources + denials — the signals host eBPF observes strongly.
- **Deterministic JSON.** `RunRecord::to_json` is a hand-rolled, compact, byte-stable serializer (fixed
  key order, arrays pre-sorted, integer-nanosecond durations) — the machine-readable audit surface the
  language SDKs parse and Phase 14 pretty-prints. Pinned by a golden test.

The privileged `audit_record.rs` proves it end to end: a guest that touches the network + reads a file
yields a record whose flows show the network **exactly**, while the in-guest file read correctly never
appears in the host-syscall axis (below). `SandboxProbes::collect` is finalize-on-close; the live view +
`agent run --trace` are Phase 14.

## The hardware-isolation consequence (the honest limit)

`count_execve` counts the **host's** `execve`s, not the guest's. A microVM runs its own kernel, so
untrusted code's syscalls are serviced *in-guest* and never trap to a host tracepoint. This is the
price of core property 1 (isolation is hardware): host-side syscall visibility is inherently coarse
for a microVM. The strong cross-boundary signals are **network** (the tap, P10/P11) and **resources**
(the cgroup, P12), which the host observes directly. We say this plainly rather than promise in-guest
syscall introspection the boundary can't deliver.

## Try it

```console
cargo xtask build-probes                       # builds the object (with BTF); asserts .BTF present
cargo build -p agent-probes-loader --example count_execve
sudo setcap cap_bpf,cap_perfmon+ep target/debug/examples/count_execve
target/debug/examples/count_execve             # unprivileged, with just the two caps
```

Or the privileged test, which spawns processes and asserts the counter moved and that a load+drop
leaves no pinned residue:

```console
cargo test -p agent-probes-loader --test counter --no-run
sudo <the-printed-binary> --ignored --test-threads=1
```

The per-phase exit-gate demos each boot a real sandbox and show one probe end to end (all need
`/dev/kvm` + the agent rootfs + the built object, run as root or with the named caps):

```console
cargo xtask trace-sandbox      # P9:  the sandbox's host syscall footprint, by cgroup
cargo xtask watch-sandbox      # P10: the guest's per-VM network flows on its tap
cargo xtask enforce-sandbox    # P11: deny-by-default egress, allow-listed, enforced at the tap
cargo xtask meter-sandbox      # P12: per-sandbox CPU (eBPF) + memory/IO (cgroup v2)
cargo xtask bench-meter        # P12.4: the metering overhead, measured (no KVM needed)
```

## Beyond the counter: a per-event syscall trace (Phase 9, in progress)

Phase 8's counter proves the load→attach→read→drop path with the smallest possible payload. Phase 9
turns that into a real **stream of per-event records** (this section is extended as the phase
completes; here is the shape so far):

- **A ring buffer, not a counter (P9.1).** Three tracepoint programs (`trace_execve` / `trace_openat`
  / `trace_connect`, on the matching `sys_enter_*` hooks) push a whole `SyscallEvent` — pid, tid,
  cgroup id, `comm`, and the opened path or connected sockaddr — into one `BPF_MAP_TYPE_RINGBUF`. The
  ring buffer is the modern (5.8+) replacement for the per-CPU perf array: a single ordered MPSC queue
  the loader drains with one consumer (`SyscallTracer::drain`). Reading the syscall's pointer argument
  (a user `char *` path, a `sockaddr *`) uses `bpf_probe_read_user_*`.
- **A shared, single-sourced record.** `SyscallEvent` lives in one dependency-free `#![no_std]` crate
  (`crates/probes-common`) that both the kernel writer and the userspace reader depend on, so the
  `#[repr(C)]` layout can't drift between them — the reader parses it field by field, no `unsafe`.
- **Filter to one sandbox (P9.2).** A two-slot `FILTER` array (target tgid, target cgroup id; `0` =
  don't filter that axis) is consulted *in the program*, so a non-matching event is dropped before it
  ever reaches the ring buffer. `SyscallTracer::watch_pid` / `watch_cgroup` set it;
  the default watches the whole host. See `docs/contributing-architecture.md` decision 021.
- **Or a *set* of sandboxes, for one shared tracer (P13.5).** A `TRACE_TARGETS` cgroup set + a
  `TRACE_SET` mode toggle (the `METER_TARGETS`/`METER_ALL` pattern) let **one** attached tracer serve
  every concurrent sandbox — each registers its cgroup with `SyscallTracer::add_target`, and only those
  cgroups' events are emitted. A tracer-per-sandbox would instead run *N* copies of each `sys_enter_*`
  on every syscall (O(sandboxes)); the set keeps it one hash lookup. Off by default, so the single-target
  path above is unchanged. Decision 028.
- **A live trace, attributed to a sandbox (P9.3/P9.4).** `SyscallTracer::stream` loops the drain,
  decoding each event with `SyscallEvent::describe` (a path, or an `a.b.c.d:port` sockaddr) and handing
  it to a callback as it arrives, until a caller predicate stops it. `cgroup_id_of_pid` closes the loop
  with the Firecracker track: it resolves a VMM pid to its cgroup id (the inode of the cgroup dir,
  which equals `bpf_get_current_cgroup_id`), so `watch_cgroup(cgroup_id_of_pid(vmm_pid)?)` scopes the
  trace to exactly one sandbox. The bridge is plain values, so `probes-loader` never depends on `vmm`.

The honest limit is unchanged (isolation is hardware): these are the **host's** syscalls — a
Firecracker worker's `execve`/`openat`/`connect` — never the guest's, which are serviced in-guest and
never trap here.

```console
cargo build -p agent-probes-loader --example trace_syscalls
sudo setcap cap_bpf,cap_perfmon+ep target/debug/examples/trace_syscalls
target/debug/examples/trace_syscalls           # a filtered trace, then an unfiltered one
```
