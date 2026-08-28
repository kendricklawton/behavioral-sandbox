//! The signed per-run **audit record**: its types, deterministic JSON, summary projection, and
//! ed25519 signing and verification.
//!
//! The *consumer's* half of the audit story: `bsx-probes-loader` attaches the probes and reads their
//! maps, and what it assembles is a [`RunRecord`].
//!
//! - **Verifiable off-host.** Everything about the record lives here, with no aya and no nix, so an
//!   auditor's machine or a CI job with no eBPF, KVM, or root can parse and verify one.
//!   `record_crate_is_aya_free` holds that in the gate.
//! - **Network + resources + denials are the core**, the signals host-side eBPF observes strongly
//!   across the hardware boundary. [`RunRecord::host_syscalls`] is the **VMM's host footprint**,
//!   explicitly not the guest's syscalls, which a microVM services in-guest.
//! - **Deterministic.** Every collection is sorted, so a record built from the same observations is
//!   byte-stable regardless of map-iteration order, which is what the JSON output rests on. Past
//!   [`MAX_NOTABLE`] distinct syscall events, *which* of them the bounded sample kept follows the
//!   order the ring buffer delivered them in; every count stays exact.

#![forbid(unsafe_code)]

pub use bsx_probes_common::{
    COMM_CAP, DETAIL_CAP, FlowCounts, FlowKey, FlowKey6, PolicyRule, PolicyRule6, Protocol,
    Syscall, SyscallEvent,
};

/// Which local uids this host trusts to have authored a file it reads, shared by the signing-key
/// gate here and the user-config gate in `crates/cli/src/trust.rs`.
mod ids;
/// Deterministic JSON of the record: the machine-readable audit surface, byte-stable and
/// dependency-free. Pure, so it is golden-tested host-safe.
mod json;
/// The per-run audit record: the fused, deterministically-ordered view of what one run did. Pure, so
/// its whole aggregation is unit-tested host-safe.
mod record;
/// Record integrity: an `ed25519` detached signature over the canonical record bytes, so alteration
/// after the producing host is detectable. The key is host-side; the guest never sees it.
mod signing;
/// The plain measurement values the record embeds: network totals and the resource summary.
mod stats;
/// The model-legible projection of the record, the compact third face for an agent's observe-then-act
/// loop. A pure view, golden-tested host-safe.
mod summary;
/// Synthetic wire-struct inputs shared by the modules' unit tests, so a field added to one of those
/// structs is answered once rather than in copies that drift.
#[cfg(test)]
mod testutil;

pub use ids::HostIds;
pub use json::AUDIT_SCHEMA_VERSION;
pub use record::{
    AxisGap, DenialRecord, DenialRecord6, EgressPosture, EnforcementMode, FlowRecord, FlowRecord6,
    MAX_NOTABLE, NetSection, NotableSyscall, RecordSubject, RunRecord, SyscallCounts, SyscallFold,
    SyscallFootprint, Timing,
};
pub use signing::{
    ChainError, HostKey, KeyError, MAX_ENVELOPE_BYTES, SIGNED_RECORD_SCHEMA_VERSION, TrustedKey,
    VerifiedEntry, VerifyError, data_dir, default_key_path, record_hash, verify, verify_chain,
    verify_entry,
};
pub use stats::{CgroupStats, NetStats, ResourceSummary};
pub use summary::SUMMARY_SCHEMA_VERSION;
