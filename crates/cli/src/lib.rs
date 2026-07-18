//! Shared library for the crate's two binaries, the `agent` CLI (`src/main.rs`) and the `agentd`
//! daemon (`src/agentd/`). Both are thin hosts of the same `agent-vmm` public API, and both compose
//! the driver track with the host-side eBPF track the same way; that composition, the
//! [`audit`] module's [`Observability`](audit::Observability)/[`RunProbes`](audit::RunProbes), lives
//! here so it is single-sourced, not `#[path]`-duplicated between the two bins.
#![forbid(unsafe_code)]

pub mod audit;

/// Firecracker v1.9 caps a microVM at 32 vCPUs (decision 001), so both the CLI (`--vcpus`) and the
/// daemon (`open`) refuse anything above it at their edge rather than surfacing a late Firecracker
/// API error mid-boot. Single-sourced here so the two entry points can't drift on the cap.
pub const MAX_VCPUS: u8 = 32;
