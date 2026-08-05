//! The signed per-run **audit record**: its types, deterministic JSON, summary projection, and
//! ed25519 signing/verification.
//!
//! This crate is the *consumer's* half of the audit story. `ekvm-probes-loader` attaches the eBPF
//! probes and reads their maps; what it assembles is a [`RunRecord`], and everything about that
//! record (its shape, its byte-stable JSON, the signature envelope, verification and the session
//! hash-chain) lives here so a record can be parsed and verified **off-host**: an auditor's
//! machine, a CI job, any consumer with no eBPF, no KVM, and no root. No aya, no nix, enforced by
//! `record_crate_is_aya_free` in the gate.
//!
//! The record's **core is network + resources + denials**, the signals host-side eBPF observes
//! strongly across the hardware boundary. [`RunRecord::host_syscalls`] is the **VMM's host
//! footprint**, explicitly *not* the guest's syscalls (a microVM services those in-guest). Every
//! collection is deterministically sorted, so a record built from the same observations is
//! byte-stable regardless of map-iteration order, the property the JSON output relies on.

#![forbid(unsafe_code)]

pub use ekvm_probes_common::{
    COMM_CAP, DETAIL_CAP, FlowCounts, FlowKey, FlowKey6, PolicyRule, PolicyRule6, Protocol,
    Syscall, SyscallEvent,
};

/// Deterministic JSON of the record: the machine-readable audit surface, byte-stable and
/// dependency-free (`RunRecord::to_json`). Pure, unit-tested host-safe against a golden.
mod json;
/// The per-run audit record: the fused, deterministically-ordered view of what one run did,
/// aggregated from the three probes. Pure, so its whole aggregation is unit-tested host-safe.
mod record;
/// Record integrity: an `ed25519` detached signature over the canonical record bytes, so alteration
/// after the producing host is detectable. Host-side key; the guest never sees it.
mod signing;
/// The plain measurement values the record embeds: network totals and the resource summary.
mod stats;
/// The model-legible projection of the record (`RunRecord::to_summary_json`): the compact, third face
/// for an agent's observe→act loop. A pure view of the record, golden-tested host-safe.
mod summary;

pub use json::AUDIT_SCHEMA_VERSION;
pub use record::{
    AxisGap, DenialRecord, DenialRecord6, EgressPosture, FlowRecord, FlowRecord6, MAX_NOTABLE,
    NetSection, NotableSyscall, RecordSubject, RunRecord, SyscallCounts, SyscallFold,
    SyscallFootprint, Timing,
};
pub use signing::{
    ChainError, HostKey, KeyError, MAX_ENVELOPE_BYTES, SIGNED_RECORD_SCHEMA_VERSION, TrustedKey,
    VerifyError, data_dir, default_key_path, record_hash, verify, verify_chain,
};
pub use stats::{CgroupStats, NetStats, ResourceSummary};
pub use summary::SUMMARY_SCHEMA_VERSION;
