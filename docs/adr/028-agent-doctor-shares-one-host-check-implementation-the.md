# 028. `agent doctor` shares one host-check implementation; the JSON surfaces are versioned before anyone parses them *(2026-07-17)*

**Context.** The engine's isolation rests on the host, so whether a given host can run a sandbox at all
is a property an operator has to know *before* the first run, not discover mid-flight. That pulls in two
directions. A readiness check wants to live close to the runtime prerequisites it inspects (KVM, jailer,
real-root, firecracker, iproute2/e2fsprogs, cgroup delegation, kernel version, boot artifacts), yet the
dev-box check (`cargo xtask setup`) and the operator's check must not drift into two divergent verdicts
about the same host. And some prerequisites are load-bearing for isolation while others only degrade
convenience, so the check has to distinguish a refusal from a warning rather than treat every missing
input alike. In parallel, the two machine-readable surfaces the engine emits, the `--json` run result
and the audit record, are about to become a contract that external consumers parse; a contract that gains
a stable meaning only once something depends on it is far cheaper to shape now than to migrate later.

**Decision.** The host readiness check ships as an engine subcommand, `agent doctor`, so an operator on
a fresh host reads what will work, degrade, or refuse before the first sandbox. The **one implementation**
lives in `agent-vmm::doctor` (a structured `Vec<Check>` with an `Ok`/`Warn`/`Fail` status plus the
degradation matrix), where the engine-runtime prerequisites are its domain; both `agent doctor` and
`cargo xtask setup` render it, so the dev-box check and the operator's can't drift. The status split
mirrors the engine's own error discipline: the isolation boundary (`/dev/kvm`) and the boot artifacts are
**hard** (`Fail` gives a non-zero exit, so `agent doctor && agent run …` gates), while the jailer,
resource caps, and networking/bulk-I/O tools **fail open** (`Warn` with a named consequence). The
eBPF-capability row (`CAP_BPF`/`CAP_PERFMON` + BTF) stays in the probe loader, out of `agent-vmm`
(decisions 021/023); each entry point appends it. `xtask setup` keeps its dev-only rows (bpf-linker,
nightly, readelf) local, since an operator running the shipped engine doesn't need them.

Both machine JSON surfaces carry a leading integer `schema` field: the `--json` run result
(`RUN_RESULT_SCHEMA`) and the audit record (`AUDIT_SCHEMA_VERSION`), each starting at `1` and
**versioned independently**, two contracts, two versions. The compatibility policy is: within a version,
changes are *additive only* (a new field a consumer can ignore); renaming or removing a field, or changing
a value's meaning, **bumps** the integer. This lands before anything external parses the bytes, so the
wire API and the SDK freeze harden a stable contract rather than a moving one.

**Consequences.** The single `agent-vmm::doctor` source means one place to keep correct, and any new
prerequisite must declare itself hard or fail-open, forcing the isolation-vs-convenience call to be made
explicitly rather than by omission. The fail-open rows are the residual risk: a host missing the jailer,
resource caps, or networking tools still runs, degraded, and the operator carries the consequence named in
the `Warn`. Independent schema counters cost a second version to reason about, but they buy each surface
its own evolution rate. The audit record's previously-open field questions were already settled by
decision 024's hardening pass (`overflow_events` semantics, the u64-nanosecond ceiling), so v1 is a
considered shape, not a placeholder.
