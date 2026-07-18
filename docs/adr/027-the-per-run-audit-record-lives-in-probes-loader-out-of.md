# 027. The per-run audit record lives in `probes-loader`, out of `agent-vmm`; a two-phase arm/bind attach reconciles tracer-before-boot with on-open *(2026-07-17)*

Phase 13 fuses the three host-side probes into one **per-run audit record** and attaches them to a
sandbox at launch. Two questions had to be settled: *where* the record and the attach machinery live,
and *how* "attach on `Sandbox::open`" is realized given the probes' conflicting timing.

**Where.** The record type (`RunRecord`) and its aggregation live in **`probes-loader`** (new modules
`record.rs` + `observer.rs`), **not** in `agent-vmm`. Decisions 024 and 026 already bind this: the
driver must gain no dependency on the eBPF loader, and the two tracks bridge only by plain values. So
`agent-vmm` is untouched; the bundle takes the plain values `Sandbox` already exposes (`vmm_pid()` →
its cgroup for the syscall tracer and the CPU meter, `netns()` + `tap_name()` for the network monitor)
and never a `Sandbox`. The composition, a short launch sequence around `open`, is the *caller's*
(the CLI/daemon later), never the driver's. `record.rs` is pure (no aya, no vmm), so its whole
aggregation is unit-tested on the host gate with synthetic inputs.

**How (two phases).** A single post-`open` constructor can't attach all three: the syscall tracer must
attach *before* boot (the jailer creates the sandbox's cgroup *during* boot, so its id isn't knowable
up front, the tracer watches host-wide, then scopes to the cgroup and filters the buffered boot window
post-hoc, the Phase-9 pattern), while the tap monitor and meter need the netns/cgroup to already exist,
so they bind *after* boot. Hence `ArmedProbes::arm()` (pre-boot) → `ArmedProbes::bind(...)` (post-boot)
→ `SandboxProbes::collect(timing)`. "On `Sandbox::open`" is that three-call sequence around `open`, not
a constructor inside `vmm`.

**The record.** Its **core is network + resources + denials**, the signals host eBPF observes strongly
across the hardware boundary. `host_syscalls` is explicitly the **VMM's host footprint**, not in-guest
syscalls. It is bounded two ways (repetition collapses into a hit count; the distinct set caps at
`MAX_NOTABLE = 64`, flagging truncation) and every collection is deterministically sorted, so a record
built from the same observations is byte-stable (the property the Phase-14 JSON output relies on).

**The meter is shared, not per-VM.** A fresh `ResourceMeter` per sandbox would re-instantiate the
global `sched_switch` program per VM, the O(N)-per-context-switch shape decision 026 rejects. So the
bundle registers its cgroup as a *target* on a caller-owned `SharedMeter` and unregisters on drop; the
tracer and tap are legitimately per-VM and owned by the bundle. (A shared syscall-tracer fan-out is the
clean P13.5 follow-up, deliberately not built here.)

**Consequences and notes.**
- **Not the pinned public API.** All new surface is on `probes-loader`; `vmm`'s `Sandbox`/`RunResult`
  are untouched, **not** an `api:` change. Timing enters `collect` as plain `Duration`s the caller
  lifts from `Sandbox::boot_latency` + `RunResult::metrics.wall`, so the record never depends on `vmm`.
- **Fail-open.** Each axis degrades independently to a recorded `AxisGap`; a host missing caps/BTF/the
  object still runs the sandbox and yields a thinner, honestly-annotated record (the decision-013 posture).
- **Deferred.** Detach/finalize-on-close beyond the drop `remove_target` (P13.3), the deterministic JSON
  *output* surface (P13.4), the overhead bound (P13.5), the privileged end-to-end proof (P13.6), and the
  CLI `agent run --trace` (Phase 14) all build on this record without reshaping it.
