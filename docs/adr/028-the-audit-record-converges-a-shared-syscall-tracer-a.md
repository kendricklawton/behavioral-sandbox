# 028. The audit record converges: a shared syscall tracer, a single post-boot attach, and deterministic JSON *(2026-07-17)*

Phase 13 closes the audit log: detach + finalize on close (P13.3), a structured JSON surface (P13.4),
a bound on the overhead under concurrency (P13.5), and the end-to-end proof (P13.6). Three shape
choices are worth pinning; the first **supersedes the two-phase arm/bind of decision 027**.

**The syscall tracer is shared, not per-VM (P13.5), this retires the two-phase attach.** Decision 027
kept a per-VM `SyscallTracer` and reconciled "attach before boot" (to catch the boot window) with the
tap/meter's "attach after boot" via `ArmedProbes::arm()` → `bind()`. But a tracer per sandbox attaches
*N* copies of each `sys_enter_*` tracepoint and runs all of them on **every** matching host syscall,
the O(sandboxes)-per-event shape decision 026 already rejected for `sched_switch`. So the tracer now
takes the *same* treatment as the meter: a `TRACE_TARGETS` cgroup **set** + a `TRACE_SET` mode toggle
in the kernel program (the exact `METER_TARGETS`/`METER_ALL` pattern), one shared `SyscallTracer`
loaded once for the host, and every sandbox registers its cgroup as a target. One shared drain routes
each event to that cgroup's private `SyscallFold`, so concurrent sandboxes stay independent (a sandbox
reads only its own footprint; unregistering one leaves the others untouched) and both the per-event
cost and the ring-buffer volume stay bounded (a single hash lookup, only target cgroups emitted). The
CPU meter was already shared this way, so **both** host-wide probes are now loaded once
(`SharedTracer` + `SharedMeter`) and only the per-VM tap is owned by the bundle.

Because nothing per-VM has to pre-attach anymore, the two-phase `arm`/`bind` **collapses to a single
post-boot `SandboxProbes::attach`**, simpler, and still "on `Sandbox::open`" (the caller's
arm-free sequence). The one consequence: `host_syscalls` now covers from **registration (just after
boot) onward**, not the pre-boot boot window. That window is the VMM/jailer's own host setup, not
guest-attributable behaviour, and the record's core (network + resources + denials) is unaffected, a
deliberate trade of exact-boot-window capture for bounded overhead. `TRACE_SET` defaults off, so the
single-target `watch_pid`/`watch_cgroup` path (Phase 9 tests, benches, demos) is byte-for-byte
unchanged; set mode is opt-in and used only by `SharedTracer`.

**Detach + finalize on close (P13.3).** `collect(timing)` is the close-time finalize: it reads the
three probes into the record **and** unregisters this run's cgroup from the shared tracer + meter, all
while the sandbox is still alive (the cgroup dir + map fds must be live). `Drop` is the abandoned-path
safety net, detach only, no record, and is a no-op after `collect`. So a bundle always leaves the
shared sets clean whether it is finalized or dropped.

**Deterministic JSON (P13.4).** `RunRecord::to_json` is hand-rolled, dependency-free, and compact, the
same reasoning as the hand-framed wire (decision 002): the audit-log format is a contract the language
SDKs parse, so the exact bytes are pinned here (a golden test), not left to a derive's field order.
It is byte-stable (fixed key order; every array already sorted by its builder), float-free (durations
are integer nanoseconds), and renders addresses/protocols/syscalls by name. Phase 14 pretty-prints it
for people and exports it; this is the machine surface underneath.

**Not the pinned public API.** All of this is on `probes-loader`; `agent-vmm`'s `Sandbox`/`RunResult`
are untouched, **not** an `api:` change. The privileged end-to-end test drives the real launch sequence
(load shared probes → boot → `attach` → run → `collect` → JSON) and asserts the guest's network touch
shows up *exactly*, while its in-guest file read correctly does **not** appear in the host-syscall axis
(the isolation working, not a gap).

**Hardening pass (same day, pre-ship).** A review of the fresh implementation tightened five things
while the format was still unpublished; they are part of this decision's shape:

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
