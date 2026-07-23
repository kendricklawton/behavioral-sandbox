//! Shared library for the single `agent` binary: the CLI (`src/main.rs`, `run`/`shell`/…) and the
//! `agent serve` daemon (`src/serve.rs`) are both thin hosts of the same `agent-vmm` public API, and
//! both compose the driver track with the host-side eBPF track the same way; that composition, the
//! [`audit`] module's [`Observability`](audit::Observability)/[`RunProbes`](audit::RunProbes), lives
//! here so it is single-sourced, not duplicated between the CLI path and the daemon's session path.
#![forbid(unsafe_code)]

pub mod audit;
pub mod policy;

/// Firecracker v1.9 caps a microVM at 32 vCPUs (ADR 001), so both the CLI (`--vcpus`) and the
/// daemon (`open`) refuse anything above it at their edge rather than surfacing a late Firecracker
/// API error mid-boot. Single-sourced here so the two entry points can't drift on the cap.
pub const MAX_VCPUS: u8 = 32;
