# 010. Per-run resource policy: one `Limits` struct of quantities, enforced at the host cgroup, failing open *(2026-07-14)*

**Context.** The engine caps each run at the host cgroup: every VMM gets a cgroup with
`cpu.max`/`memory.max` and a boot deadline. The controls, though, are scattered: [`Limits`]
`{ vcpus, mem_mib, wall }` rides the boot path while a fixed `DEFAULT_EXEC_TIMEOUT` and
`MAX_EXEC_OUTPUT` sit buried in exec. The API commits to surfacing per-sandbox limits as **one options
struct**, so before that wiring lands the *shape* that struct commits to has to be fixed. Three forces
pull on the shape: a resource budget is a set of quantities, but network egress is a capability, not a
number; one public struct is simpler to pin and read than two parallel ones; and on a host missing the
cgroup controllers the choice is whether to refuse to boot or run uncapped. Getting the shape right now
makes the follow-on work wiring, not design.

**Decision.** The per-run resource policy is the one already-public, API-pinned, `#[non_exhaustive]`
struct [`Limits`], carrying **resource quantities**, never mechanism. Its knobs:
- **`vcpus: NonZeroU8`** sets the guest's vCPU count *and* the host cgroup `cpu.max` (exactly `vcpus` cores:
  `vcpus × 100000` per 100000us period). One number caps both what the guest sees and what the VMM may
  burn.
- **`mem_mib: NonZeroU32`** sets guest RAM *and* `memory.max = (mem_mib + 128 MiB)` (the measured host-side VMM
  overhead above guest RAM), so the guest is never handed RAM its own cgroup would then OOM.
- **`wall: Duration`** is the run's wall-clock budget: it sets the boot-to-userspace deadline *and* the
  exec wall-clock budget (the internal `DEFAULT_EXEC_TIMEOUT` becomes settable), so one `wall` means the
  whole run, not just boot.
- the **exec output cap** (the fixed `MAX_EXEC_OUTPUT`, surfaced on the wire as `OutputCap { limit }`) is
  the fourth knob.

Two things it deliberately is **not**:
- **Not network policy.** The "net policy" is a *capability* (deny-by-default egress, decision 008), not
  a numeric budget: it stays a separate boolean / eBPF-enforced concern and does not become a `Limits`
  field. Quantities here, capabilities there.
- **Not per-exec.** The policy binds at the **host VMM cgroup** (per-VM, created by the jailer), the
  single choke point that caps the whole guest + VMM together. The guest-side per-exec cgroup is a
  *reaping* mechanism (`cgroup.kill`), not a second policy surface: it sets no limits.

**Alternatives considered.**
- **A separate `ResourcePolicy` type distinct from `Limits`.** Rejected: `Limits` already *is* the
  per-run budget the public API pins and embedders read; a parallel type would split one concept in two and
  force a second public API surface. Grow the one struct.
- **Fold network egress into the same struct.** Rejected: a quantity struct that also carries a
  capability flag invites "set `mem_mib` and `net` in one call" ergonomics that blur the deny-by-default
  line; egress is enforced in a different layer (eBPF), on a different schedule (when networking lands).
- **Fail closed on missing delegation.** Rejected as the *default* (a self-hoster on a bare container
  could then never boot), kept as the future opt-in below for embedders who would rather refuse than run
  uncapped.

**Consequences.** The follow-on work is wiring, not design: add the exec-wall and output-cap knobs to
`Limits`, thread them to the existing `DEFAULT_EXEC_TIMEOUT` / `MAX_EXEC_OUTPUT` sites, and keep today's
timeout semantics (cooperative `ExecTimeout`, `ExecUnresponsive` as the liveness backstop). No new type,
no new enforcement point.

Degradation is **fail-open, and recorded.** The cgroup caps need the v2 `cpu`+`memory` controllers
delegated to the root; where they aren't (a bare container), the driver logs a warning and boots
**without** limits rather than refusing. This is the one place the engine fails *open*, and it is
deliberate: resource caps are DoS / fairness mitigation, not the isolation boundary. The isolation
boundary (KVM, and the jailer's chroot + uid-drop + seccomp) **never** degrades: a jail that can't be
built is a hard error, never a quiet half-confinement (the `Vm::boot` refusal of jail + vsock/NIC/
overlay/bulk-I/O, verified host-safe). A strict embedder wanting "no limits ⇒ no boot" is a future
`require_limits`-style toggle, deferred here, not built.

Defaults are a **load-bearing floor.** `Limits::default()` (1 vCPU, 256 MiB, 30 s) is conservative on
purpose: an embedder pinning this crate relies on a default run staying small. **Raising** a default (or
the fixed output cap) hands every default run more resource and is a breaking, `api:`-marked change;
**lowering** one, or adding a field (the struct is `#[non_exhaustive]`), is safe.

**Done** *(2026-07-15)*: `wall` extended to the exec budget (`with_limits` folds it into both the boot
deadline and each exec's budget; `BootConfig` keeps a `boot_timeout`/`exec_wall` split beneath the
public API), `output_cap` added as the fourth knob, defaults unchanged (30 s / 16 MiB), the whole
timeout ladder (socket idle, guest kill, host backstop) derived from the configured value.
`require_limits` was **not** built: no embedder has asked to fail closed yet, so its note stands.

**`pids.max` added as host-side defense in depth** *(2026-07-16)*: the per-VM cgroup now also sets
`pids.max` (a fixed 1024, gated on the `pids` controller being delegated, warning + skipping if not,
fail-open *per controller*, so a host with cpu/memory but not pids keeps those caps). It is **not** a
`Limits` knob and does not touch the public API: a guest fork-bomb is already bounded by `memory.max`
and lives in the guest's own kernel, so this only caps the narrow case of a hypervisor-level exploit
forking *host* processes. The arg builder was made pure (`cgroup_args_for`) so the per-controller
fail-open is host-gate unit-tested; the remaining IO-bandwidth leg is deferred.
