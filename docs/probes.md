# Host-side observability & enforcement

The engine has two halves. [The VMM and its jail](./architecture-firecracker.md) documents the Firecracker
driver: the hardware-isolation boundary that *contains* untrusted code. This document is the
other half: the host-side eBPF that
*observes and enforces* what that code does, from the host side of the KVM boundary: the programs
are loaded by a host process and attached to host-kernel hooks, outside the guest's address space and
outside any namespace it can enter (design rule 2). It starts with the foundation, build, load, attach, and read one program end to
end, then builds out each axis: the syscall trace, network observation and egress enforcement on
the tap, resource accounting from the cgroup, and the fused per-run audit record.

The worked example is a counter: `count_execve` attaches to the `sys_enter_execve` tracepoint and
tallies how many `execve`s the host does, into two maps. It is deliberately small; the point is the
path, not the payload.

## The three crates

- **`crates/probes`** (`#![no_std]`, `#![no_main]`) holds the in-kernel programs. It builds for
  `bpfel-unknown-none`, not the host triple, so it is *excluded* from the workspace and pins its own
  nightly toolchain (`-Z build-std=core`, since rustup ships no prebuilt `core` for the BPF target).
  `bpf-linker` links the LLVM bitcode rustc emits into a BPF ELF. `unsafe` lives here (raw map-pointer
  derefs); the host/driver path stays `#![forbid(unsafe_code)]`.
- **`crates/probes-common`** is the dependency-free `#![no_std]` crate both sides compile: the
  `#[repr(C)]` records that cross the kernel/user boundary (`SyscallEvent`, the flow and policy
  types) and the rule-matchers shared by the kernel scan and the host tests. Single-sourcing the
  layout is what the later sections lean on.
- **`crates/probes-loader`** is the userspace side, built with **aya** (pure-Rust, no libbpf/C
  toolchain), synchronous (no async runtime, matching the driver). Its public shape is a typed handle
  (`ExecveCounter::{load, count, counts_by_pid}`) returning a typed `ProbeError`, the eBPF analogue
  of the driver's `VmmError`. It reads the compiled object from a **path** (`cargo xtask build-probes`
  output, or `BSX_PROBES_OBJECT`), never `include_bytes!`/`build.rs`, so the host workspace stays on
  stable and `cargo xtask ci` runs everywhere.

## eBPF program types

An eBPF program is attached to a *hook*, and its type is the hook's shape: what context it gets and
what it may do. The counter uses a **tracepoint** (`#[tracepoint]`), a stable kernel-defined event
with a stable argument format, here `syscalls/sys_enter_execve`. Its context is read-only; it
returns 0. The later sections use other types: **tc/`classifier`** on a VM's tap, where the
context is a packet the program may inspect and drop; and the global scheduler tracepoint that
powers per-sandbox accounting. Same load/attach/map machinery, different hook.

## Maps

Maps are the shared memory between the kernel program and userspace. Two here:

- **`PerCpuArray<u64>`** (`EXECVE_COUNT`), one slot. **Per-CPU** means each CPU has its own copy of
  the slot, so the program increments with a plain `+= 1` and no cross-CPU atomic (contention-free);
  the loader reads all per-CPU copies and **sums** them. This is the idiomatic pattern for a hot
  counter.
- **`HashMap<u32, u64>`** (`EXECVE_BY_PID`), per-PID counts, bounded at 4096 entries (maps are sized
  at load). A full map drops new keys; the per-CPU total stays authoritative.

Maps are **BTF-defined** (see below), so their key/value types are described in the object's BTF.

## The verifier

Before the kernel runs a BPF program it *verifies* it: every path must be safe and terminate. Two
of its rules the counter hits on purpose:

- **Bounded loops.** Walking the fixed 16-byte `comm` buffer to its NUL terminator is a loop whose
  bound is a compile-time constant, so the verifier can prove it terminates even with a data-dependent
  `break`. An *unbounded* `while` would be rejected.
- **Map access patterns.** A map lookup returns a pointer that may be null (key absent). The verifier
  **forbids dereferencing it without a null-check first**. `get_ptr_mut` returns an `Option`, so the
  `if let Some(slot) = ...` *is* the mandatory check; the deref happens only inside the `Some` arm,
  and we `insert` only on the miss (lookup-or-init).

The verifier runs **at load**, in the kernel, so a rejection needs a real load to surface, which is
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
  come with the per-event syscall trace (below), which reads kernel structs. Here BTF is the map
  typing plus the load-time relocation path, the portability mechanism the later sections build on.

## Lifetime: no pinned residue

The aya `Ebpf` owns the program, its maps, and the live attachment. Dropping the loader (`Drop`)
detaches the program and frees the maps. Nothing is **pinned** into `/sys/fs/bpf`, so a crashed loader
leaves no kernel residue, the eBPF analogue of the driver's no-leak teardown (which reclaims taps,
netns, cgroups, and scratch dirs). Pinning stays opt-in, added only where a program must outlive its
loader (not on this path). This discipline matters more on the tap, where a leaked `tc` filter would
dangle on a torn-down sandbox's tap.

## Capabilities and the support probe

Loading and attaching the tracepoint probes needs **`CAP_BPF`** (load programs/maps, read maps) and
**`CAP_PERFMON`** (attach a tracepoint via `perf_event_open`), the two that split out of
`CAP_SYS_ADMIN` in Linux 5.8. **Not full root** for that path: grant a loader binary just those with
`setcap cap_bpf,cap_perfmon+ep <binary>`. The tap axes need more: creating the clsact qdisc takes
`CAP_NET_ADMIN`, and entering another sandbox's netns (`attach_in_netns`/`enforce_in_netns`) calls
`setns`, which takes `CAP_SYS_ADMIN` or root, so the two-cap grant covers the counter and the
tracer, not a full sandbox attach. `check_support` names *the two load-path caps* as the standard
requirement; an exotic host with only `CAP_BPF` and a permissive `kernel.perf_event_paranoid` may
attach anyway, but the pre-flight is a conservative advisory, not a sysctl-probing oracle. The
capability *bit logic* (which bits, correct masking) is unit-tested on the host gate; the end-to-end
"loads unprivileged with just the two caps" is verified by the `setcap` run above, not by CI (whose
privileged tests run as root, whose mask has every bit).

`check_support()` is the dependency guard (the eBPF analogue of the driver's Firecracker-version
probe): before a load it checks kernel BTF and the two capabilities and, if either is missing, returns
a **legible typed error naming the requirement** (`ProbeError::Unsupported`) rather than letting the
load fail with a cryptic verifier reject or `EPERM`. A host that can't run the probes says so plainly.

## Network observation on the tap

`count_execve` sees only the *host's* syscalls, but a microVM's **network** is different: every packet
the guest sends or receives crosses its **tap** device on the host, so a program on the tap sees the
guest's own traffic directly. `TapMonitor` attaches two `tc`/clsact classifiers, `tap_ingress` and
`tap_egress`, the two hooks clsact adds to a device, and each parses the frame's 5-tuple, IPv4 into the
`FLOWS` map or IPv6 into a parallel `FLOWS6` (dual-stack: parallel `FlowKey`/`FlowKey6` types
and maps, so the v4 path is byte-for-byte unchanged), adding the packet to that flow's per-direction
byte/packet counters.

`tc` (not XDP) because
clsact gives *both* directions uniformly on any device, and because egress enforcement (dropping a
denied flow, the next section) lives at the same hook; observation alone is exactly that, observe-only
(both hooks return `TC_ACT_OK`). The flow record
(`FlowKey`/`FlowKey6` → `FlowCounts`) is single-sourced in `crates/probes-common` and read back as raw bytes, so
the loader stays `#![forbid(unsafe_code)]`.

A sandbox's tap lives in its own network namespace, so `TapMonitor::attach_in_netns` enters that netns (via `setns` behind nix's
safe wrapper) to bind the monitor to one sandbox's `fc0`, and `totals()` sums the flows
into a per-VM rollup. Dropping the monitor frees its userspace handles; the sandbox's netns teardown
reclaims the `tc` filter, so attach-on-open and detach-on-close leave no host residue.

## Egress enforcement in the kernel

Observation watches; enforcement turns the same tap hook into **control**. The ingress classifier (a frame
the guest *sends*) now also consults a per-sandbox allow-list, the `POLICY`/`POLICY6` maps of
`PolicyRule`/`PolicyRule6`s (destination CIDR + optional port/proto), single-sourced in
`crates/probes-common` next to the flow record. When the `ENFORCE` toggle is on, a guest-sent packet
(v4 or v6) whose destination matches no active rule returns `TC_ACT_SHOT` (dropped at the tap, never
leaves the host); a match returns `TC_ACT_OK`. The per-rule test (`rule_matches`/`rule_matches6`, a
masked-CIDR + wildcard-port/proto compare, byte-wise for v6 since eBPF has no `u128`) is one function,
called by the kernel scan and by the host-unit-tested `egress_allowed`/`egress_allowed6` alike. The scan
around it is mirrored by hand; for v4, `crates/probes-loader/tests/differential.rs` hands the loaded
classifier a synthetic frame and asserts its verdict is the one `egress_allowed` gives for the same
destination, and `observe_only_passes_every_frame_enforcement_would_drop` is the control that keeps that
comparison from passing on a classifier that drops everything. The
program scans the fixed `MAX_POLICY_RULES` array in a **bounded loop** (the verifier's compile-time
cap), and the v4 mask is built so the shift operand is always `< 32` (an out-of-range shift is a
verifier reject).

Two deliberate carve-outs keep deny-by-default from being deny-*everything*. **ARP** (v4) is always
allowed, and ICMPv6 whose **destination is an on-link scope** (`fe80::/10`, `ff02::/16`, and the
guest's own link; the `icmp6_dst_on_link` gate tests scope, not message type) passes so neighbor
discovery works: the guest must resolve its on-link host end before it can reach any endpoint, and ND
aimed at a routable address gets no carve-out. The link arm is that one `/64`, not `fc00::/7`: a
unique-local address is routable *within a site* (RFC 4193), so sparing the whole range would leave a
guest an unpoliced ICMPv6 path (Echo carries payload) to whatever an operator-furnished uplink can
reach, which `a_ula_outside_the_guests_own_link_is_policed_not_spared` pins shut. And the **egress hook** (a reply arriving *to* the guest) always accepts,
since egress policy governs what the guest sends and replies to allowed traffic must return. Enforcement is
**opt-in and per VM**: each `TapMonitor` owns its own maps, and a monitor that never sets a policy stays
observe-only (both hooks accept, exactly the observe-only behavior above).

The userspace schema is `EgressPolicy`, an allow-list built from friendly `Ipv4Addr`/`Ipv6Addr` CIDRs
(`Ipv4Cidr`/`Ipv6Cidr`) and ports, lowered to the `PolicyRule`/`PolicyRule6`s the maps hold. Its **deny-by-default** is the safe default: the empty
policy (`EgressPolicy::deny_all()`, the `Default`) allows nothing, so a sandbox launched with no explicit
allowance reaches nothing, the eBPF, host-observed complement to the driver's own deny-by-default
(no route out of the guest unless one is configured, and no uplink built for it either). `TapMonitor::set_egress_policy` applies a policy to an already-attached
monitor; `TapMonitor::enforce_in_netns` applies it **at launch**: it populates the policy maps and only then
attaches the classifiers, so the programs go live against maps that already hold the run's rules. Rules go in as raw bytes (`PolicyRule::to_bytes`, so the loader needs no
`unsafe` `aya::Pod` binding); `clear_egress_policy` disarms.

Every dropped packet is **recorded** before the drop: the classifier counts it against its destination
in a `DENIALS`/`DENIALS6` map, which `TapMonitor::denials()`/`denials6()` reads back, the audit trail of which endpoints a
sandbox was blocked from, folded into the per-run record (below). Both the flow table and the denial
map are fixed-size (4096 entries), and saturation is **counted, never silent**: a full map bumps a
per-CPU drop counter (`TapMonitor::dropped_flows()`/`dropped_denials()`), the record's network
section carries the counts and a `truncated` flag, and the run gets a coverage gap, so a guest that
churns source ports to fill the table cannot quietly evict its real traffic from its own record
(the `EVENT_DROPS` honest-loss discipline, applied to the network axis). Enforcement never depends
on the maps: a denied packet is dropped at the tap whether or not its audit row fit. The egress filter mechanism (map,
schema, deny-by-default, ingress-hook enforcement, ARP carve-out) is pinned by `net_enforce.rs`
(ignored/privileged): a guest reaches an allow-listed endpoint and is blocked from everything
else. Folding attach-and-enforce into the launch
path is the fused record's convergence (below).

## Resource accounting from the cgroup

Where the tap sections watch the network, this axis meters the **cgroup**: how much host CPU, memory, and IO a
sandbox's VMM consumes running the guest. The CPU axis is the eBPF part, `account_sched_switch`
attaches to the `sched/sched_switch` tracepoint and, on every context switch, charges the on-CPU
nanoseconds the outgoing task just ran to that task's cgroup id in the `CPU_NS` map. It works because at
that tracepoint the scheduler has not yet swapped `current` (it still points at the task leaving the
CPU), so `bpf_get_current_cgroup_id()` is exactly the cgroup whose CPU slice just ended. A per-CPU
`LAST_SWITCH` cursor is always restamped so intervals stay exact. One consequence to know: a slice
**posts at switch-out**, so a still-running task's current slice is pending, a pegged vCPU can hold a
whole busy window un-posted until the guest idles and the thread blocks. Read after the run quiesces for
run-scoped totals; a mid-run read is a floor.

**One program, many sandboxes.** `sched_switch` is a *global* tracepoint, so the probe is attached
**once** and meters a *set* of cgroups (`METER_TARGETS`), not one program per sandbox, a
program-per-sandbox would run every attached program on every context switch (O(sandboxes) per switch).
`ResourceMeter::add_target(id)` registers a sandbox's cgroup, `remove_target` unregisters it, and the hot
path stays a single hash lookup no matter how many sandboxes are metered; `CPU_NS` holds only the
registered cgroups. `ResourceMeter::cpu_time(id)` reads the total back, and `cargo xtask bench-meter`
measures the honest per-context-switch cost (no meter vs attached-not-metering-us vs
attached-metering-us). That is the "bounded, sane under many concurrent sandboxes" property, measured.

**Correlated to the sandbox, all three axes.** The `id` is exactly what `cgroup_id_of_pid(vmm_pid)`
resolves, so the CPU track lines up with the Firecracker per-VM cgroup; `cgroup_dir_of_pid(vmm_pid)` gives
the dir for the other two axes. Memory and IO don't need a probe, cgroup v2 already maintains them per
cgroup, so `CgroupStats::read` reads `memory.peak`/`memory.current`, `io.stat` (rbytes/wbytes summed), and
`cpu.stat`'s `usage_usec` (an independent cross-check on the eBPF CPU total) straight from the cgroup dir,
best-effort (every field an `Option`, so a missing controller or older kernel is a `None`, never an error,
accounting fails open). `ResourceMeter::summary_for_pid(vmm_pid)` rolls all three into a
`ResourceSummary` for one sandbox. The split is deliberate, "cgroup-bpf **or** cgroup + tracepoints":
eBPF where per-event timing earns its keep (CPU), the kernel's own counters where they already exist
(memory, IO). `resource_meter.rs` (ignored/privileged) runs a CPU-heavy sandbox and an idle one and asserts the
first is attributed more CPU than the second. The engine *measures*; the hoster *bills*.

## The fused audit record

The sections above each drive one probe standalone; the fused record binds all three to a launched
sandbox and fuses their output into one per-run **audit record**, host-observed from outside the
guest. The attach bundle lives in `bsx-probes-loader` (not `bsx-engine`), bridged to the driver
only by plain values; the record itself (its types, JSON, and signing/verification) lives in
`bsx-record`, aya-free so a consumer verifies it off-host:

- **Two shared probes + a per-VM tap.** The `sched_switch` meter and the `sys_enter_*` tracepoints are
  global, so each is loaded **once** for the host, as `SharedMeter` and `SharedTracer` (the share-one-
  program wrappers over the meter above and the per-event syscall tracer introduced below), and every
  sandbox registers its cgroup as a *target* on both (bounded overhead). The tap monitor is per-VM.
- **One post-boot attach.** `SandboxProbes::attach(params, &tracer, &meter)` runs once after
  `Sandbox::open`, its per-run inputs carried in an `AttachParams` (built from the VMM pid; the
  optional NIC, egress policy, and gateway are fields, with the netns and tap names paired in one
  `Nic` value so half a NIC is unrepresentable): it resolves the VMM's cgroup, registers it on the
  shared tracer + meter, and attaches the tap in the sandbox's netns (enforcing an egress policy if
  given; the gateway rides into the record's egress posture). Every axis is fail-open,
  a missing cap/BTF/object degrades to a recorded `AxisGap`, never a blocked run.
- **Finalize + detach on close.** `SandboxProbes::collect(subject, timing)` reads the three probes into
  a `RunRecord` (the `RecordSubject` is the identity stamped first into its JSON; the CLI wrapper
  supplies it) **and** unregisters this run's cgroup from the shared sets, while the sandbox is still
  alive. Dropping without collecting detaches only (the abandoned path). Timing enters as plain
  `Duration`s the caller lifts from `Sandbox::boot_latency` + `RunResult::metrics.wall`.
- **The record.** `RunRecord` fuses network flows + per-VM totals + egress denials (tap), CPU + memory/IO
  (`ResourceSummary`), and the VMM's bounded host-syscall footprint, with `coverage` gaps for whatever was
  unavailable. Its core is network + resources + denials, the signals host eBPF observes strongly.
- **Deterministic JSON.** `RunRecord::to_json` is a hand-rolled, compact, byte-stable serializer (fixed
  key order, arrays pre-sorted, integer-nanosecond durations), the machine-readable audit surface a
  client parses and the CLI's `--trace` pretty-prints today. Pinned by a golden test.

The privileged `audit_record.rs` exercises this end to end: it boots a guest that touches the network
and reads a file, then asserts the record's flows carry that network activity and that the
host-syscall axis is *bound* to the sandbox (no coverage gap). It deliberately asserts nothing about
the in-guest file read: that is an axis the host is architecturally blind to, the hardware-isolation
consequence described at the end of this chapter. `SandboxProbes::collect` is finalize-on-close; between attach
and collect, `SandboxProbes::snapshot` gives a watcher a live reading
(`LiveSnapshot`: the tap now, the meter now, a *clone* of the syscall fold-so-far, so the fold the
record finalizes from is left in place), what the
CLI's `--watch` live view redraws from. The CLI face of all of this
(`bsx run --net --trace --record run.json --watch`) is documented in [Observing a run](./cli-observe.md).

## The hardware-isolation consequence (the honest limit)

`count_execve` counts the **host's** `execve`s, not the guest's. A microVM runs its own kernel, so
untrusted code's syscalls are serviced by that in-guest kernel; what reaches a host tracepoint is the
VMM process's own host-side work. This is the
price of design rule 1 (isolation is hardware): host-side syscall visibility is inherently coarse
for a microVM. The strong cross-boundary signals are **network** (the tap) and **resources**
(the cgroup), which the host observes directly. We say this plainly rather than promise in-guest
syscall introspection the boundary can't deliver.

## Try it

```console
cargo xtask build-probes                       # builds the object (with BTF); asserts .BTF present
cargo build -p bsx-probes-loader --example count_execve
sudo setcap cap_bpf,cap_perfmon+ep target/debug/examples/count_execve
target/debug/examples/count_execve             # unprivileged, with just the two caps
```

Or the privileged test, which spawns processes and asserts the counter moved and that a load+drop
leaves no pinned residue:

```console
cargo test -p bsx-probes-loader --test counter --no-run
sudo <the-printed-binary> --ignored --test-threads=1
```

The network axis has its own example. Point it at any interface carrying traffic, a sandbox's `fc0`
from inside its netns or an ordinary device in the current one, and it prints the per-flow
byte/packet counters the section above describes. It needs `CAP_NET_ADMIN` on top of the two load
caps, per the qdisc requirement above, so this one is shown under `sudo`:

```console
cargo build -p bsx-probes-loader --example monitor_tap
sudo target/debug/examples/monitor_tap <interface>
```

The metering overhead has its own bench, which needs no KVM:

```console
cargo xtask bench-meter
```

## Beyond the counter: the per-event syscall trace

The counter exercises the load→attach→read→drop path with the smallest possible payload; the tracer
turns that into a real **stream of per-event records**:

- **A ring buffer, not a counter.** Three tracepoint programs (`trace_execve` / `trace_openat`
  / `trace_connect`, on the matching `sys_enter_*` hooks) push a whole `SyscallEvent`, pid, tid,
  cgroup id, `comm`, and the opened path or connected sockaddr, into one `BPF_MAP_TYPE_RINGBUF`. The
  ring buffer is the modern (5.8+) replacement for the per-CPU perf array: a single ordered MPSC queue
  the loader drains with one consumer (`SyscallTracer::drain`). Reading the syscall's pointer argument
  (a user `char *` path, a `sockaddr *`) uses `bpf_probe_read_user_*`.
- **A shared, single-sourced record.** `SyscallEvent` lives in one dependency-free `#![no_std]` crate
  (`crates/probes-common`) that both the kernel writer and the userspace reader depend on, so the
  `#[repr(C)]` layout can't drift between them, the reader parses it field by field, no `unsafe`.
- **Filter to one sandbox.** A two-slot `FILTER` array (target tgid, target cgroup id; `0` =
  don't filter that axis) is consulted *in the program*, so a non-matching event is dropped before it
  ever reaches the ring buffer. `SyscallTracer::watch_pid` / `watch_cgroup` set it;
  the default watches the whole host.
- **Or a *set* of sandboxes, for one shared tracer.** A `TRACE_TARGETS` cgroup set + a
  `TRACE_SET` mode toggle (the `METER_TARGETS`/`METER_ALL` pattern) let **one** attached tracer serve
  every concurrent sandbox, each registers its cgroup with `SyscallTracer::add_target`, and only those
  cgroups' events are emitted. A tracer-per-sandbox would instead run *N* copies of each `sys_enter_*`
  on every syscall (O(sandboxes)); the set keeps it one hash lookup. Off by default, so the single-target
  path above is unchanged.
- **A live trace, attributed to a sandbox.** `SyscallTracer::stream` loops the drain,
  decoding each event with `SyscallEvent::describe` (a path, or an `a.b.c.d:port` / `[v6]:port` sockaddr) and handing
  it to a callback as it arrives, until a caller predicate stops it. `cgroup_id_of_pid` closes the loop
  with the Firecracker track: it resolves a VMM pid to its cgroup id (the inode of the cgroup dir,
  which equals `bpf_get_current_cgroup_id`), so `watch_cgroup(cgroup_id_of_pid(vmm_pid)?)` scopes the
  trace to exactly one sandbox. The bridge is plain values, so `bsx-probes-loader` never depends on
  `bsx-engine`.

The honest limit from
[the hardware-isolation consequence](#the-hardware-isolation-consequence-the-honest-limit)
holds here unchanged: these are the **host's** syscalls, never the guest's.

```console
cargo build -p bsx-probes-loader --example trace_syscalls
sudo setcap cap_bpf,cap_perfmon+ep target/debug/examples/trace_syscalls
target/debug/examples/trace_syscalls           # whole-host, 5s; args: [seconds] [pid-to-filter]
```
