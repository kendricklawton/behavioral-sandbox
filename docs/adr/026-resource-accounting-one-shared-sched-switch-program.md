# 026. Resource accounting: one shared `sched_switch` program metering a cgroup set, CPU from eBPF, memory/IO from cgroup v2 *(2026-07-16)*

**Problem.** Phase 12 meters what a sandbox *costs*, host CPU, memory, IO, as the metering primitive
the hoster bills on (the engine measures; billing is the hoster's, guardrail 4/3). A microVM services
its own syscalls in-guest, so the strong host-side signal is the **cgroup** the VMM runs in (decision
014/P6.7): its host CPU (running the vCPUs), its charged memory, its IO. This decision fixes *how* that
is measured and *how it scales* to many concurrent sandboxes.

**Decision.** **CPU rides one shared eBPF `sched_switch` program metering a *set* of cgroups; memory and
IO ride the kernel's native cgroup v2 counters.**
- **CPU: a `sched/sched_switch` tracepoint, one program, attached once.** On every context switch it
  charges the on-CPU nanoseconds the outgoing task just ran to that task's cgroup id in the `CPU_NS`
  hash map. It is correct because at that tracepoint the scheduler has not yet swapped `current` (it
  still points at the task leaving the CPU), so `bpf_get_current_cgroup_id()` is exactly the cgroup
  whose slice ended; a per-CPU `LAST_SWITCH` cursor is always restamped so intervals stay exact across
  the metered/not-metered branch.
- **A target *set* (`METER_TARGETS`), not a program-per-sandbox.** `sched_switch` is a *global*
  tracepoint: attaching one program per sandbox would run **every** attached program on **every**
  context switch (O(sandboxes) per switch). Instead one program consults a `cgroup_id -> 1` set the
  loader writes; the hot path is a single hash lookup, and `CPU_NS` only ever holds the registered
  cgroups. Adding a sandbox is one map insert, not one more attached program, so accounting stays
  bounded and sane under many concurrent sandboxes (P12.4, measured by `bench-meter`). A `METER_ALL`
  toggle is the whole-host escape hatch for a snapshot or a test, not the per-sandbox path.
- **Memory/IO: the kernel's own cgroup v2 counters, not a probe.** `memory.peak`/`memory.current`,
  `io.stat` (rbytes/wbytes), and `cpu.stat`'s `usage_usec` (an independent cross-check on the eBPF CPU
  total) are maintained by the kernel per cgroup; `CgroupStats::read` reads them from the cgroup dir,
  best-effort (every field an `Option`, a missing controller/older kernel is `None`, never an error,
  accounting fails open, decision 013). This is the "cgroup-bpf **or** cgroup + tracepoints" the phase
  allows: eBPF where per-event timing earns its keep (CPU), the kernel's counters where they already
  exist (memory, IO).
- **Correlated by the FC per-VM cgroup (P12.2).** `cgroup_id_of_pid(vmm_pid)` resolves the id for the
  CPU meter and `cgroup_dir_of_pid(vmm_pid)` the dir for `CgroupStats`, so a sandbox's VMM pid (the
  Firecracker track's `vmm_pid`) scopes all three axes to that one sandbox's cgroup.
  `ResourceMeter::summary_for_pid` rolls them into a `ResourceSummary` (P12.3).

**Alternatives considered.**
- **Read only cgroup v2 files, no eBPF.** Rejected as the CPU story: `cpu.stat` gives a coarse total,
  but the phase is "resource accounting **via cgroup-bpf**", and the scheduler tracepoint gives precise,
  event-driven, per-cgroup CPU attribution that generalizes to per-task/percentile views later.
  `cpu.stat`'s `usage_usec` is kept as a cross-check, not the source.
- **A program attached per sandbox (mirroring `TapMonitor`'s per-tap attach).** Rejected: a tap only
  sees its own sandbox's packets, but `sched_switch` is global, so per-sandbox programs are O(N) per
  switch. One shared program + a target set is the scalable shape.
- **Track memory via BPF (page-fault/rss hooks).** Rejected: memory is a gauge the kernel already keeps
  per cgroup (`memory.peak` is the meaningful high-water mark); a BPF reimplementation would be noisier
  and slower than reading the counter.

**Consequences and notes.**
- **Not the pinned public API.** The surface is on `probes-loader` (`ResourceMeter`, `CgroupStats`,
  `ResourceSummary`, `cgroup_dir_of_pid`), not `vmm`'s `Sandbox`, so this is **not** an `api:` change.
  Folding the `ResourceSummary` into the persisted per-run audit record (fused with the network denials
  and the syscall trace) is Phase 13's convergence, kept out of `agent-vmm` so the driver stays
  independent of the eBPF loader (they bridge only by plain values).
- **Best-effort accuracy.** The `CPU_NS` accumulate is per-CPU-serialized by the scheduler hook but not
  atomic across CPUs, so a heavily-parallel cgroup can undercount by a hair, fine for a metering
  signal (the same posture as the flow counters, decision 023).
- P12.5 (`resource_meter.rs`, ignored/privileged) proves a CPU-heavy run reports far more CPU than an
  idle one, attributed to the sandbox's cgroup; `cargo xtask meter-sandbox` is the live exit-gate demo.
