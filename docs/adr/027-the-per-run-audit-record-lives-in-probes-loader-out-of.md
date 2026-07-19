# 027. The per-run audit record lives in `probes-loader`, out of `agent-vmm`; a two-phase arm/bind attach reconciles tracer-before-boot with on-open *(2026-07-17)*

**Context.** The engine fuses its three host-side probes (the syscall tracer, the tap monitor, the CPU
meter) into one **per-run audit record** and attaches them to a sandbox at launch. Two design questions
fall out of that, and both are shaped by standing constraints rather than by discovery. The first is
*where* the record type and the attach machinery live. Decisions 024 and 026 already draw the line: the
driver gains no dependency on the eBPF loader, and the two tracks bridge only by plain values, so the
record cannot sit inside `agent-vmm`. The second is *how* "attach on `Sandbox::open`" can be realized at
all, because the probes have conflicting timing. The syscall tracer must attach *before* boot: the jailer
creates the sandbox's cgroup *during* boot, so its id isn't knowable up front, and the tracer therefore
watches host-wide, then scopes to the cgroup and filters the buffered boot window post-hoc (the pattern
established when the tracer first landed). The tap monitor and the meter, by contrast, need the netns and
cgroup to already exist, so they can only bind *after* boot. A single post-`open` constructor cannot
satisfy both.

**Decision.** The record type (`RunRecord`) and its aggregation live in **`probes-loader`** (new modules
`record.rs` + `observer.rs`), **not** in `agent-vmm`. `agent-vmm` is untouched; the bundle takes the plain
values `Sandbox` already exposes (`vmm_pid()` → its cgroup for the syscall tracer and the CPU meter,
`netns()` + `tap_name()` for the network monitor) and never a `Sandbox`. The composition, a short launch
sequence around `open`, is the *caller's* (the CLI/daemon later), never the driver's. `record.rs` is pure
(no aya, no vmm), so its whole aggregation is unit-tested on the host gate with synthetic inputs.

The attach is two phases: `ArmedProbes::arm()` (pre-boot) → `ArmedProbes::bind(...)` (post-boot) →
`SandboxProbes::collect(timing)`. "On `Sandbox::open`" is that three-call sequence around `open`, not a
constructor inside `vmm`.

The record's **core is network + resources + denials**, the signals host eBPF observes strongly across the
hardware boundary. `host_syscalls` is explicitly the **VMM's host footprint**, not in-guest syscalls. It is
bounded two ways (repetition collapses into a hit count; the distinct set caps at `MAX_NOTABLE = 64`,
flagging truncation) and every collection is deterministically sorted, so a record built from the same
observations is byte-stable (the property the deterministic JSON output relies on).

The meter is **shared, not per-VM.** A fresh `ResourceMeter` per sandbox would re-instantiate the global
`sched_switch` program per VM, the O(N)-per-context-switch shape decision 026 rejects. So the bundle
registers its cgroup as a *target* on a caller-owned `SharedMeter` and unregisters on drop; the tracer and
tap are legitimately per-VM and owned by the bundle. (A shared syscall-tracer fan-out is a clean follow-up,
deliberately not built here.)

**Consequences and notes.**
- **Not the pinned public API.** All new surface is on `probes-loader`; `vmm`'s `Sandbox`/`RunResult`
  are untouched, **not** an `api:` change. Timing enters `collect` as plain `Duration`s the caller
  lifts from `Sandbox::boot_latency` + `RunResult::metrics.wall`, so the record never depends on `vmm`.
- **Fail-open.** Each axis degrades independently to a recorded `AxisGap`; a host missing caps/BTF/the
  object still runs the sandbox and yields a thinner, honestly-annotated record (the decision-013 posture).
- **Deferred.** Detach/finalize-on-close beyond the drop `remove_target`, the deterministic JSON
  *output* surface, the overhead bound, the privileged end-to-end proof, and the CLI `agent run --trace`
  all build on this record without reshaping it.
