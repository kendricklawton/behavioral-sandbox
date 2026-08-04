#![allow(clippy::unwrap_used, clippy::expect_used)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ekvm_record::{record_hash, verify, verify_chain, HostKey, RecordSubject, RunRecord, Timing};

fn sample_record() -> RunRecord {
    let subject = RecordSubject::new("sb-bench-12345".to_string(), 1_700_000_000_000_000_000);
    let timing = Timing {
        boot: std::time::Duration::from_millis(120),
        exec_wall: std::time::Duration::from_millis(15),
    };
    RunRecord::from_parts(
        subject,
        None,
        Default::default(),
        Default::default(),
        timing,
        vec![],
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
    let record_json = sample_record().to_json();

    let e0 = host_key.sign_canonical_chained(&record_json, None);
    let h0 = record_hash(&record_json);
    let e1 = host_key.sign_canonical_chained(&record_json, Some(&h0));
    let h1 = record_hash(&record_json);
    let e2 = host_key.sign_canonical_chained(&record_json, Some(&h1));

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
