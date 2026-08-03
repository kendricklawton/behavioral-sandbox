//! Record durability: a signed envelope written by an earlier build must keep verifying, and
//! today's canonicalization must keep reproducing the bytes that were signed.
//!
//! The signed-record surface is the one contract whose breakage reaches *backwards*: a change to
//! the canonical JSON or the envelope shape does not break a build, it silently invalidates every
//! record already sitting in an operator's `records_dir`. So the contract is pinned by an
//! **artifact**, not by code alone: `tests/fixtures/run-record.envelope.json` is a frozen envelope
//! (signed 2026-08-03 by a throwaway test key), and these tests hold today's code to it. A change
//! that fails them is a schema break and needs `SIGNED_RECORD_SCHEMA_VERSION` /
//! `AUDIT_SCHEMA_VERSION` bumped with a deliberate migration story, then a regenerated fixture
//! (`regenerate_fixture` below).

use std::time::Duration;

use ekvm_record::{
    record_hash, verify, AxisGap, FlowCounts, FlowKey, HostKey, NetSection, NetStats,
    RecordSubject, ResourceSummary, RunRecord, SyscallEvent, SyscallFootprint, Timing, TrustedKey,
};

/// The frozen envelope. Regenerate only on a deliberate schema bump (`regenerate_fixture`).
const ENVELOPE: &str = include_str!("fixtures/run-record.envelope.json");
/// The public half of the throwaway fixture key ([`fixture_key`]); not a secret, the seed is in
/// this file. What matters is that `verify` accepts the frozen envelope under it.
const PUBKEY_HEX: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
/// `record_hash` of the frozen canonical record bytes, the value a session chain would carry.
const CANONICAL_HASH: &str = "1bb0652cb600621048687ca966b5fdfb0f6779a179228fe09bc075cca9d1bd48";

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// The throwaway signing key the fixture was generated with. A fixed seed, so the fixture is
/// reproducible; it signs nothing but this test's record.
fn fixture_key() -> HostKey {
    HostKey::from_seed([7u8; 32])
}

/// A synthetic `SyscallEvent` from public fields, the same shape `json.rs`'s golden tests use.
fn ev(syscall: u32, cgroup: u64, detail: &[u8], comm: &str) -> SyscallEvent {
    let mut d = [0u8; ekvm_record::DETAIL_CAP];
    let n = detail.len().min(d.len());
    d[..n].copy_from_slice(&detail[..n]);
    let mut c = [0u8; ekvm_record::COMM_CAP];
    let m = comm.len().min(c.len());
    c[..m].copy_from_slice(&comm.as_bytes()[..m]);
    SyscallEvent {
        cgroup_id: cgroup,
        pid: 7,
        tid: 7,
        syscall,
        detail_len: n as u32,
        comm: c,
        detail: d,
    }
}

/// The fixture's record, rebuilt from fixed parts through the public API. Every axis is populated,
/// so a canonicalization change anywhere in the record shows up as a byte difference.
fn fixture_record() -> RunRecord {
    let counts = FlowCounts {
        ingress_packets: 2,
        ingress_bytes: 120,
        egress_packets: 3,
        egress_bytes: 200,
    };
    let flows = vec![
        (
            FlowKey::new(
                u32::from_be_bytes([10, 200, 0, 2]),
                u32::from_be_bytes([1, 1, 1, 1]),
                40000,
                53,
                IPPROTO_UDP,
            ),
            counts,
        ),
        (
            FlowKey::new(
                u32::from_be_bytes([10, 200, 0, 2]),
                u32::from_be_bytes([8, 8, 8, 8]),
                40001,
                443,
                IPPROTO_TCP,
            ),
            counts,
        ),
    ];
    let mut totals = NetStats::default();
    totals.ingress_packets = 4;
    totals.ingress_bytes = 240;
    totals.egress_packets = 6;
    totals.egress_bytes = 400;
    let denials = vec![(
        FlowKey::new(0, u32::from_be_bytes([9, 9, 9, 9]), 0, 443, IPPROTO_TCP),
        4,
    )];

    let mut resources = ResourceSummary::default();
    resources.cpu_time = Duration::from_nanos(5_000);
    resources.cgroup.cpu_usage_usec = Some(6);
    resources.cgroup.memory_current = Some(1024);
    resources.cgroup.memory_peak = Some(4096);
    resources.cgroup.io_wbytes = Some(512);

    let host_syscalls = SyscallFootprint::from_events(
        0x42,
        &[
            ev(0, 0x42, b"/bin/sh", "sh"),
            ev(1, 0x42, b"/etc/hosts", "sh"),
            ev(1, 0x42, b"/etc/hosts", "sh"),
        ],
    );

    RunRecord::from_parts(
        RecordSubject::new("ekvm-4242-0".into(), 1_700_000_000_000_000_000),
        Some(NetSection::from_tap(flows, totals, denials, 0, 0)),
        resources,
        host_syscalls,
        Timing {
            boot: Duration::from_millis(120),
            exec_wall: Duration::from_millis(42),
        },
        vec![AxisGap::Cpu("meter lock poisoned".into())],
    )
}

#[test]
fn a_frozen_envelope_still_verifies() {
    let trusted = TrustedKey::from_hex(PUBKEY_HEX).expect("fixture pubkey");
    let canonical = verify(ENVELOPE.trim_end(), &[trusted])
        .expect("the frozen envelope must verify under the fixture key");
    assert_eq!(
        record_hash(&canonical),
        CANONICAL_HASH,
        "the canonical bytes inside the frozen envelope changed"
    );
}

#[test]
fn todays_canonicalization_reproduces_the_frozen_bytes() {
    let trusted = TrustedKey::from_hex(PUBKEY_HEX).expect("fixture pubkey");
    let canonical = verify(ENVELOPE.trim_end(), &[trusted]).expect("frozen envelope");
    assert_eq!(
        fixture_record().to_json(),
        canonical,
        "to_json no longer reproduces the bytes an earlier build signed; this invalidates \
         records already on disk and needs a schema bump plus a regenerated fixture"
    );
}

/// Regenerates the fixture after a *deliberate* schema bump. `cargo test -p ekvm-record --test
/// durability -- --ignored --nocapture`, then paste the printed envelope into the fixture file and
/// the printed constants above.
#[test]
#[ignore = "writes nothing; prints a fresh fixture for a deliberate schema bump"]
fn regenerate_fixture() {
    let key = fixture_key();
    let envelope = key.sign_record(&fixture_record());
    let canonical = fixture_record().to_json();
    println!("--- fixtures/run-record.envelope.json ---");
    println!("{envelope}");
    println!("--- PUBKEY_HEX ---");
    println!("{}", key.key_id());
    println!("--- CANONICAL_HASH ---");
    println!("{}", record_hash(&canonical));
}
