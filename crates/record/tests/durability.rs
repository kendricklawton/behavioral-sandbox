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

// The fixture readers below sit outside the `#[test]` bodies where the no-panic lints are relaxed,
// and a fixture this suite cannot read is a failed test either way.
#![allow(clippy::expect_used)]

use std::time::Duration;

use bsx_record::{
    AUDIT_SCHEMA_VERSION, AxisGap, FlowCounts, FlowKey, HostKey, MAX_ENVELOPE_BYTES, NetSection,
    NetStats, RecordSubject, ResourceSummary, RunRecord, SIGNED_RECORD_SCHEMA_VERSION,
    SUMMARY_SCHEMA_VERSION, SyscallEvent, SyscallFootprint, Timing, TrustedKey, record_hash,
    verify, verify_chain,
};

/// The frozen envelope. Regenerate only on a deliberate schema bump (`regenerate_fixture`).
const ENVELOPE: &str = include_str!("fixtures/run-record.envelope.json");
/// The frozen **chain**: two envelopes, one per line, the shape a daemon session writes. Frozen
/// separately from [`ENVELOPE`] because a chained record signs `prev + "\n" + canonical`, and nothing
/// about the single-record fixture covers that framing, so a change to it would reach
/// backwards through every session record on disk with the single-record pin still green.
const CHAIN: &str = include_str!("fixtures/run-record.chain.jsonl");
/// The fixture set's metadata: the record-side schema numbers, and the key id and canonical hash
/// the envelopes above verify under. Beside the fixtures rather than in this file, so a verifier in
/// another language reads the whole set without reading Rust.
const META: &str = include_str!("fixtures/meta.json");

/// One string out of [`META`], by its key under `fixture`. Optional rather than panicking, since a
/// helper here sits outside the `#[test]` bodies where the no-panic lints are relaxed.
fn meta_fixture_str(key: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(META).ok()?;
    Some(v["fixture"][key].as_str()?.to_string())
}

/// The public half of the throwaway fixture key ([`fixture_key`]); not a secret, the seed is in
/// this file. What matters is that `verify` accepts the frozen envelope under it.
fn pubkey_hex() -> String {
    meta_fixture_str("key_id").expect("meta.json names `fixture.key_id`")
}

/// `record_hash` of the frozen canonical record bytes, the value a session chain would carry.
fn canonical_hash() -> String {
    meta_fixture_str("canonical_hash").expect("meta.json names `fixture.canonical_hash`")
}

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// The throwaway signing key the fixture was generated with. A fixed seed, so the fixture is
/// reproducible; it signs nothing but this test's record.
fn fixture_key() -> HostKey {
    HostKey::from_seed([7u8; 32])
}

/// A synthetic `SyscallEvent` from public fields, deliberately a second copy of `src/testutil.rs`'s
/// builder: an integration test compiles as a foreign crate and cannot see `pub(crate)`, and building the
/// fixture through the **public** API is what makes this suite evidence that an outside consumer can
/// reconstruct the
/// signed bytes.
fn ev(syscall: u32, cgroup: u64, detail: &[u8], comm: &str) -> SyscallEvent {
    let mut d = [0u8; bsx_record::DETAIL_CAP];
    let n = detail.len().min(d.len());
    d[..n].copy_from_slice(&detail[..n]);
    let mut c = [0u8; bsx_record::COMM_CAP];
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

/// The deliberate copy above must stay byte-for-byte the shared builder, or this suite proves an
/// outside consumer can rebuild *something else*. Held here rather than by deleting the copy,
/// because building the fixture inline is what makes the suite evidence about the public API.
#[test]
fn the_public_api_fixture_matches_the_shared_builder() {
    let mine = ev(59, 0x42, b"/bin/sh", "sh");
    let shared = bsx_test_support::syscall_event(59, 0x42, b"/bin/sh", "sh");
    assert_eq!(mine.cgroup_id, shared.cgroup_id);
    assert_eq!((mine.pid, mine.tid), (shared.pid, shared.tid));
    assert_eq!(mine.syscall, shared.syscall);
    assert_eq!(mine.detail_len, shared.detail_len);
    assert_eq!(mine.comm, shared.comm);
    assert_eq!(mine.detail, shared.detail);
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
        // A frozen input: this string sits inside the signed bytes, so the fixture verifies only
        // for this exact value. It is deliberately not today's sandbox-id prefix. The artifact
        // stands for a record an earlier build wrote, and `sandbox_id` is an opaque string, so a
        // prefix change is not a schema change and must not regenerate the fixture.
        RecordSubject::new("ekvm-4242-0".into(), 1_700_000_000_000_000_000),
        Some(NetSection::from_tap(flows, totals, denials, 0, 0)),
        resources,
        host_syscalls,
        Timing::new(Duration::from_millis(120), Duration::from_millis(42)),
        vec![AxisGap::Cpu("meter lock poisoned".into())],
    )
}

/// The chain's second record: the fixture record with a different exec time, so the two canonical
/// strings differ and the link between them commits to something rather than to itself.
fn fixture_record_two() -> RunRecord {
    let mut record = fixture_record();
    record.timing = Timing::new(Duration::from_millis(7), Duration::from_millis(9));
    record
}

#[test]
fn a_frozen_chain_still_verifies() {
    let trusted = TrustedKey::from_hex(&pubkey_hex()).expect("fixture pubkey");
    let entries: Vec<&str> = CHAIN
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(entries.len(), 2, "the frozen chain is two records");
    let records = verify_chain(&entries, &[trusted]).expect(
        "the frozen chain must still verify: the `prev + \\n + canonical` framing is signed, so a \
         change to it invalidates every session record already on disk",
    );
    assert_eq!(records[0], fixture_record().to_json());
    assert_eq!(records[1], fixture_record_two().to_json());
    assert_eq!(
        record_hash(&records[0]),
        canonical_hash(),
        "the anchor is the same record the single-envelope fixture carries"
    );
}

#[test]
fn a_frozen_envelope_still_verifies() {
    let trusted = TrustedKey::from_hex(&pubkey_hex()).expect("fixture pubkey");
    let canonical = verify(ENVELOPE.trim_end(), &[trusted])
        .expect("the frozen envelope must verify under the fixture key");
    assert_eq!(
        record_hash(&canonical),
        canonical_hash(),
        "the canonical bytes inside the frozen envelope changed"
    );
}

#[test]
fn todays_canonicalization_reproduces_the_frozen_bytes() {
    let trusted = TrustedKey::from_hex(&pubkey_hex()).expect("fixture pubkey");
    let canonical = verify(ENVELOPE.trim_end(), &[trusted]).expect("frozen envelope");
    assert_eq!(
        fixture_record().to_json(),
        canonical,
        "to_json no longer reproduces the bytes an earlier build signed; this invalidates \
         records already on disk and needs a schema bump plus a regenerated fixture"
    );
}

/// Every number `meta.json` publishes, against the code it describes. The file is what an off-host
/// verifier in another language sizes its buffers and gates its schemas by, so a value it states
/// that this crate does not hold would be wrong everywhere except here.
#[test]
fn the_published_fixture_metadata_matches_the_code_it_describes() {
    let m: serde_json::Value = serde_json::from_str(META).expect("meta.json is JSON");
    assert_eq!(
        m["signed_record_schema_version"],
        serde_json::json!(SIGNED_RECORD_SCHEMA_VERSION)
    );
    assert_eq!(
        m["audit_schema_version"],
        serde_json::json!(AUDIT_SCHEMA_VERSION)
    );
    assert_eq!(
        m["summary_schema_version"],
        serde_json::json!(SUMMARY_SCHEMA_VERSION)
    );
    assert_eq!(
        m["max_envelope_bytes"],
        serde_json::json!(MAX_ENVELOPE_BYTES)
    );
    // The two file names are the rest of the set an outside verifier needs to find.
    assert_eq!(
        m["fixture"]["envelope"],
        serde_json::json!("run-record.envelope.json")
    );
    assert_eq!(
        m["fixture"]["chain"],
        serde_json::json!("run-record.chain.jsonl")
    );
    // `key_id` and `canonical_hash` are already load-bearing: every verify test above reads them
    // from here, so a wrong value fails those rather than needing its own assertion.
}

/// Regenerates the fixture after a *deliberate* schema bump, printing a fresh envelope and the two
/// `meta.json` values to paste in:
///
/// ```console
/// BSX_REGENERATE_FIXTURE=1 cargo test -p bsx-record --test durability regenerate -- --nocapture
/// ```
///
/// Gated on the variable rather than `#[ignore]`, because in this repo `#[ignore]` means "needs KVM
/// or root" and `ci-privileged` runs **every** ignored test: an ignored helper runs there, in the
/// suite that is release evidence. Inert everywhere until asked for.
#[test]
fn regenerate_fixture() {
    if std::env::var_os("BSX_REGENERATE_FIXTURE").is_none() {
        return;
    }
    let key = fixture_key();
    let envelope = key.sign_record(&fixture_record());
    let canonical = fixture_record().to_json();
    println!("--- fixtures/run-record.envelope.json ---");
    println!("{envelope}");
    let r1 = fixture_record().to_json();
    let r2 = fixture_record_two().to_json();
    println!("--- fixtures/run-record.chain.jsonl ---");
    println!("{}", key.sign_canonical_chained(&r1, None));
    println!(
        "{}",
        key.sign_canonical_chained(&r2, Some(&record_hash(&r1)))
    );
    println!("--- fixtures/meta.json: fixture.key_id ---");
    println!("{}", key.key_id());
    println!("--- fixtures/meta.json: fixture.canonical_hash ---");
    println!("{}", record_hash(&canonical));
}
