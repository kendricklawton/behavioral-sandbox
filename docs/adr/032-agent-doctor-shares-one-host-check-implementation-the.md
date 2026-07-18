# 032. `agent doctor` shares one host-check implementation; the JSON surfaces are versioned before anyone parses them *(2026-07-17)*

**Doctor.** The host readiness check ships as an engine subcommand, `agent doctor`, so an operator on
a fresh host reads what will work, degrade, or refuse *before* the first sandbox. The **one
implementation** lives in `agent-vmm::doctor` (structured `Vec<Check>` with an `Ok`/`Warn`/`Fail`
status + the degradation matrix), where the engine-runtime prerequisites (KVM, jailer, real-root,
firecracker, iproute2/e2fsprogs, cgroup delegation, kernel version, boot artifacts) are its domain;
both `agent doctor` and `cargo xtask setup` render it, so the dev-box check and the operator's can't
drift. The status split mirrors the engine's own error discipline: the isolation boundary (`/dev/kvm`)
and the boot artifacts are **hard** (`Fail` → non-zero exit, so `agent doctor && agent run …` gates),
while the jailer, resource caps, and networking/bulk-I/O tools **fail open** (`Warn` with a named
consequence). The eBPF-capability row (`CAP_BPF`/`CAP_PERFMON` + BTF) stays in the probe loader, out of
`agent-vmm` (decisions 024/026); each entry point appends it. `xtask setup` keeps its dev-only rows
(bpf-linker, nightly, readelf) local, an operator running the shipped engine doesn't need them.

**Versioned JSON.** Both machine JSON surfaces carry a leading integer `schema` field: the `--json`
run result (`RUN_RESULT_SCHEMA`) and the audit record (`AUDIT_SCHEMA_VERSION`), each starting at `1`
and **versioned independently**, two contracts, two versions. The **compatibility policy**: within a
version, changes are *additive only* (a new field a consumer can ignore); renaming/removing a field or
changing a value's meaning **bumps** the integer. This lands *before* anything external parses the
bytes (the wire API and the SDK freeze harden a stable contract, not a moving one). The audit record's
previously-open field questions were already settled by decision 028's hardening pass
(`overflow_events` semantics, the u64-nanosecond ceiling), so v1 is a considered shape, not a
placeholder.
