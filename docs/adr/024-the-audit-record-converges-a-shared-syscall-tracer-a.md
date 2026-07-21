# 024. The audit record converges: a shared syscall tracer, a single post-boot attach, and deterministic JSON *(2026-07-17)*

**Context.** The audit record is the engine's deliverable: a host-observed account of what a run did,
and its format is a contract the language SDKs parse. Closing it well answers four standing
requirements at once, the probes detach and the record finalizes when a sandbox closes, the surface is
structured JSON, the per-run overhead stays bounded even under concurrency, and the whole path is
proven end to end.

Those requirements collide with an earlier shape. A per-VM `SyscallTracer`, reconciled against the
tap/meter's "attach after boot" via the original `ArmedProbes::arm()` → `bind()`, attaches *N* copies
of each `sys_enter_*` tracepoint and runs all of them on **every** matching host syscall, the
O(sandboxes)-per-event shape decision 023 already rejected for `sched_switch`. Two forces pull against
each other: per-VM attach exists to catch the boot window before the guest is up, while a shared probe
exists to keep the per-event cost and the ring-buffer volume bounded. The record's core (network +
resources + denials) does not depend on the boot window, so the design resolves toward bounded
overhead.

**Decision.** Three shape choices define the closed record; the first retires the two-phase attach.

**The syscall tracer is shared, not per-VM.** The tracer now takes the *same* treatment as the meter: a
`TRACE_TARGETS` cgroup **set** + a `TRACE_SET` mode toggle in the kernel program (the exact
`METER_TARGETS`/`METER_ALL` pattern), one shared `SyscallTracer` loaded once for the host, and every
sandbox registers its cgroup as a target. One shared drain routes each event to that cgroup's private
`SyscallFold`, so concurrent sandboxes stay independent (a sandbox reads only its own footprint;
unregistering one leaves the others untouched) and both the per-event cost and the ring-buffer volume
stay bounded (a single hash lookup, only target cgroups emitted). The CPU meter was already shared this
way, so **both** host-wide probes are now loaded once (`SharedTracer` + `SharedMeter`) and only the
per-VM tap is owned by the bundle.

**The two-phase arm/bind collapses to a single post-boot `SandboxProbes::attach`.** Because nothing
per-VM has to pre-attach anymore, the arm/bind sequence becomes one post-boot attach, simpler, and
still "on `Sandbox::open`" (the caller's arm-free sequence). `TRACE_SET` defaults off, so the
single-target `watch_pid`/`watch_cgroup` path (its tests, benches, demos) is byte-for-byte unchanged;
set mode is opt-in and used only by `SharedTracer`.

**Detach + finalize on close.** `collect(timing)` is the close-time finalize: it reads the three probes
into the record **and** unregisters this run's cgroup from the shared tracer + meter, all while the
sandbox is still alive (the cgroup dir + map fds must be live). `Drop` is the abandoned-path safety
net, detach only, no record, and is a no-op after `collect`. So a bundle always leaves the shared sets
clean whether it is finalized or dropped.

**Deterministic JSON.** `RunRecord::to_json` is hand-rolled, dependency-free, and compact, the same
reasoning as the hand-framed wire (decision 002): the audit-log format is a contract the language SDKs
parse, so the exact bytes are pinned here (a golden test), not left to a derive's field order. It is
byte-stable (fixed key order; every array already sorted by its builder), float-free (durations are
integer nanoseconds), and renders addresses/protocols/syscalls by name. A later phase pretty-prints it
for people and exports it; this is the machine surface underneath.

**Not the pinned public API.** All of this is on `probes-loader`; `agent-vmm`'s `Sandbox`/`RunResult`
are untouched, **not** an `api:` change. The privileged end-to-end test drives the real launch sequence
(load shared probes → boot → `attach` → run → `collect` → JSON) and asserts the guest's network touch
shows up *exactly*, while its in-guest file read correctly does **not** appear in the host-syscall axis
(the isolation working, not a gap).

Five refinements, all made while the format was still unpublished, are part of this decision's shape:

- **Denials aggregate by destination.** The kernel keys `DENIALS` by the dropped packet's full
  5-tuple, so retries from different guest source ports arrive as separate entries; sorting them by
  destination alone was not a total order (byte-stability broke on ties, and the JSON showed
  duplicate-looking rows). `NetSection::from_tap` now sums per `(dst, port, proto)`, one row per
  blocked endpoint, totally ordered, matching the JSON surface.
- **Loss is counted, never silent.** A full ring buffer drops events by design; the kernel now counts
  those drops (`EVENT_DROPS`), and the bundle snapshots the counter at attach and reports a nonzero
  delta at collect as a coverage gap. The buffer is drained at `SharedTracer::load` (clearing the
  unfiltered load-window baseline), at every registration, and on demand (`poll`) for long-lived hosts.
- **Every axis records its gap.** A poisoned meter/tracer lock, a failed resource read, or a failed
  tap-map read each produce a specific `AxisGap`, a record showing zero CPU or an empty footprint
  means the sandbox was quiet, never that a read silently failed. A failed flow/denial read keeps the
  rest of the network section and names exactly what was lost.
- **Truncation is exact.** `overflow_events` (né `distinct_dropped`, renamed before anything parsed
  it) counts every event past the notable cap, so `total - overflow_events` is the exactly-attributed
  share; the kept set is documented as first-by-arrival. JSON durations clamp to u64 nanoseconds, a
  documented ceiling consumers can parse with ordinary 64-bit integers.
- **Filter modes can't half-apply.** The `watch_*` setters switch the tracer back to single-filter
  mode just as `add_target` switches it to set mode, so the active model always matches the last
  setter used; folds are created fresh at registration (a recycled cgroup id can't inherit a dead
  run's events).

**Consequences.** The one cost of retiring the two-phase attach: `host_syscalls` now covers from
**registration (just after boot) onward**, not the pre-boot boot window. That window is the
VMM/jailer's own host setup, not guest-attributable behaviour, and the record's core (network +
resources + denials) is unaffected, a deliberate trade of exact-boot-window capture for bounded
overhead. Every other axis fails loud rather than silent: a poisoned lock, a failed read, or a full
ring buffer each surface as a named gap in the record (the refinements above), so an empty footprint or
zero CPU always means a quiet sandbox, never a dropped read.

**Relationship to prior decisions.** This **supersedes the original two-phase arm/bind attach**: with
nothing per-VM left to pre-attach, its `arm()` → `bind()` reconciliation is gone. It extends the
shared-probe treatment the CPU meter already used, closing the O(sandboxes)-per-event shape decision
023 rejected for `sched_switch`. And the hand-rolled JSON follows the hand-framed wire of decision 002,
an SDK-parsed contract whose exact bytes are pinned, not derived.
