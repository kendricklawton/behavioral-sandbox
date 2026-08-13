#![allow(clippy::unwrap_used, clippy::expect_used)]

use bsx_record::{
    AxisGap, FlowCounts, FlowKey, HostKey, NetSection, NetStats, RecordSubject, RunRecord,
    SyscallEvent, SyscallFootprint, Timing, record_hash, verify, verify_chain,
};
use criterion::{Criterion, black_box, criterion_group, criterion_main};

const IPPROTO_TCP: u8 = 6;

/// A synthetic `SyscallEvent` with the cgroup and comm a bench never varies, from the shared
/// builder so the bytes timed here are the bytes the tests assert on.
fn ev(syscall: u32, detail: &[u8]) -> SyscallEvent {
    bsx_test_support::syscall_event(syscall, 0x42, detail, "sh")
}

/// A **populated** record: 64 flows and a full notable set, so `to_json` is timed on what the engine
/// actually serializes. An empty record measures the cheapest path through both renderers and
/// reports a number that does not describe either (design rule 6).
fn sample_record() -> RunRecord {
    let counts = FlowCounts {
        ingress_packets: 2,
        ingress_bytes: 120,
        egress_packets: 3,
        egress_bytes: 200,
    };
    let flows: Vec<_> = (0..64u16)
        .map(|i| {
            (
                FlowKey::new(
                    u32::from_be_bytes([10, 200, 0, 2]),
                    u32::from_be_bytes([8, 8, (i >> 8) as u8, i as u8]),
                    40000 + i,
                    443,
                    IPPROTO_TCP,
                ),
                counts,
            )
        })
        .collect();
    let denials: Vec<_> = (0..8u16)
        .map(|i| {
            (
                FlowKey::new(
                    0,
                    u32::from_be_bytes([9, 9, 0, i as u8]),
                    0,
                    443,
                    IPPROTO_TCP,
                ),
                4,
            )
        })
        .collect();
    let events: Vec<SyscallEvent> = (0..64u32)
        .map(|i| ev(1, format!("/usr/lib/some/path/number-{i:03}.so").as_bytes()))
        .collect();
    RunRecord::from_parts(
        RecordSubject::new("sb-bench-12345".to_string(), 1_700_000_000_000_000_000),
        Some(NetSection::from_tap(
            flows,
            NetStats::default(),
            denials,
            0,
            0,
        )),
        Default::default(),
        SyscallFootprint::from_events(0x42, &events),
        Timing::new(
            std::time::Duration::from_millis(120),
            std::time::Duration::from_millis(15),
        ),
        vec![AxisGap::Cpu("meter lock poisoned".into())],
    )
}

fn bench_record_formatting(c: &mut Criterion) {
    let record = sample_record();

    c.bench_function("to_json", |b| b.iter(|| black_box(record.to_json())));

    c.bench_function("to_summary_json", |b| {
        b.iter(|| black_box(record.to_summary_json()))
    });
}

fn bench_record_signing_and_verification(c: &mut Criterion) {
    let host_key = HostKey::from_seed([7u8; 32]);
    let trusted_key = host_key.verifying_key();
    let record_json = sample_record().to_json();

    c.bench_function("record_signing", |b| {
        b.iter(|| black_box(host_key.sign_canonical(black_box(&record_json))))
    });

    let signed_envelope = host_key.sign_canonical(&record_json);

    c.bench_function("record_verification", |b| {
        b.iter(|| {
            black_box(
                verify(
                    black_box(&signed_envelope),
                    black_box(std::slice::from_ref(&trusted_key)),
                )
                .expect("valid signature"),
            )
        })
    });
}

fn bench_record_chaining(c: &mut Criterion) {
    let host_key = HostKey::from_seed([7u8; 32]);
    let trusted_key = host_key.verifying_key();

    // Three *distinct* records, each link committing to the one before it. Signing the same record
    // three times makes every hash equal, so the chain would verify whatever the links said.
    let records: Vec<String> = (0..3)
        .map(|i| {
            let mut r = sample_record();
            r.timing = Timing::new(
                std::time::Duration::from_millis(100 + i),
                std::time::Duration::from_millis(i),
            );
            r.to_json()
        })
        .collect();
    let e0 = host_key.sign_canonical_chained(&records[0], None);
    let e1 = host_key.sign_canonical_chained(&records[1], Some(&record_hash(&records[0])));
    let e2 = host_key.sign_canonical_chained(&records[2], Some(&record_hash(&records[1])));

    let chain = [e0, e1, e2];
    let chain_refs: Vec<&str> = chain.iter().map(|s| s.as_str()).collect();

    c.bench_function("verify_chain_3_records", |b| {
        b.iter(|| {
            black_box(
                verify_chain(
                    black_box(&chain_refs),
                    black_box(std::slice::from_ref(&trusted_key)),
                )
                .expect("valid chain"),
            )
        })
    });
}

criterion_group!(
    benches,
    bench_record_formatting,
    bench_record_signing_and_verification,
    bench_record_chaining
);
criterion_main!(benches);
