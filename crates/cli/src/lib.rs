//! Shared library for the crate's two binaries — the `agent` CLI (`src/main.rs`) and the `agentd`
//! daemon (`src/agentd/`). Both are thin hosts of the same `agent-vmm` public API, and both compose
//! the driver track with the host-side eBPF track the same way; that composition — the
//! [`audit`] module's [`Observability`](audit::Observability)/[`RunProbes`](audit::RunProbes) — lives
//! here so it is single-sourced, not `#[path]`-duplicated between the two bins.
#![forbid(unsafe_code)]

pub mod audit;
