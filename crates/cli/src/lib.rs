//! Shared library for the `ekvm` binary: the CLI (`src/main.rs`, `run`/`shell`/…) and the
//! `ekvm serve` daemon (`src/serve.rs`) are both thin hosts of the same `ekvm` public API, and
//! both compose the driver track with the host-side eBPF track the same way; that composition, the
//! [`audit`] module's [`Observability`](audit::Observability)/[`RunProbes`](audit::RunProbes), lives
//! here so it is single-sourced, not duplicated between the CLI path and the daemon's session path.
#![forbid(unsafe_code)]

pub mod audit;
pub mod config;
pub mod policy;

/// The pinned Firecracker's vCPU ceiling and the predicate for the rest of its domain (`[1, 32]`,
/// and 1 or an even number), re-exported from the engine rather than restated. Both the CLI
/// (`--vcpus`) and the daemon (`open`) refuse an out-of-domain count at their own edge rather than
/// surfacing a late API error mid-boot, and taking the rule from `ekvm` is what keeps the three
/// checks from drifting apart the way a copied constant does.
pub use ekvm::{vcpus_supported, MAX_VCPUS};
