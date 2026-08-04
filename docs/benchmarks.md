# Benchmarks

**No benchmark numbers are published at present.** This page documents the methodology and how to
run the suite yourself; the result tables were withdrawn on 2026-07-29 and will return once they can
be defended.

Why they were withdrawn: the published figures were measured on the development laptop under a
"quiet host" claim that nothing verified, and the guards that would have caught an invalid run (a
control column that re-measures the opening condition at the end, and a recorded 1-minute load
average) were added *afterwards*. The numbers may well have been roughly right; the problem is that
nobody can tell. Publishing a number nobody can defend is worse than publishing none, so they are
parked until a re-run on a host whose quiet state is verified.

The suite lives in [`xtask`](https://github.com/ekvm-rs/ekvm/tree/main/xtask) and runs via
`cargo xtask bench-all`. Run it on your own host; that result is about your host, which is the only
thing a benchmark ever tells you.

## Methodology

- **Nearest-rank percentiles**: `min / p50 / p90 / p99 / max` without interpolation.
- **Tail metrics**: Percentile ranks requiring higher sample counts than executed return `—` instead of relabeling `max` (e.g. `p99` requires `n ≥ 100`).
- **Baseline comparison**: Warm starts are measured against cold boots, eBPF overhead against unattached baselines, and shared memory footprint (PSS) against un-deduplicated RSS.
- **Failure is loud, not filtered**: a boot or exec that errors mid-bench aborts its whole section
  with the error rather than being dropped from the sample, so a reported percentile never averages
  over silent retries (`bench-density` is the one deliberate early stop, and it names its reason).
- **Reproduce.** One command runs the whole suite as a single report:

  ```console
  cargo xtask bench-all              # the full suite; skips sections whose host prereq is missing
  cargo xtask bench-warm --runs 100  # or a single bench at a sharper n for publication-grade tails
  ```

  The KVM benches need `/dev/kvm` + the built ekvm rootfs; the eBPF benches need
  `CAP_BPF`+`CAP_PERFMON` + `cargo xtask build-probes` (not KVM). `bench-all` records the host it ran
  on and skips any section it can't run, with the reason, so a report says exactly what it measured.

The withdrawn figures were taken on the development host, with the guest at 256 MiB and 1 vCPU on a
132 MiB rootfs. When numbers return, they return with the machine and date they were taken on.

### The reference host

Local measurements and the privileged suite run on a laptop, not a server: Linux 7.0.11, Intel
i5-10310U (8 vCPUs at 1.70 GHz), 15 GiB RAM, Arch Linux, Firecracker v1.16.1, `x86_64`. It is also the
host these numbers describe. The engine is exercised on one other kernel, the Ubuntu 24.04 runner
the privileged suite uses nightly, which is why the portability claim in
[Host-side observability & enforcement](./probes.md) is described as a mechanism rather than a
broadly tested property.

CI runs the host-safe gate on Ubuntu 24.04 `x86_64` on every change, and the privileged suite nightly
on a GitHub-hosted Ubuntu 24.04 `x86_64` runner with nested KVM. Nested KVM makes timing
unrepresentative, so benchmarks are never gated there.

## What the suite measures

Each section below exists and runs today; only the published result tables are withdrawn.

| Bench | Question |
|---|---|
| `bench-boot` | Cold boot latency, and the cost of the per-VM rootfs copy |
| `bench-warm` | Snapshot restore and pool take, against cold boot |
| `bench-density` | Memory sharing across concurrent clones: RSS against PSS |
| `bench-footprint` | Per-sandbox host cost under each rootfs/overlay choice |
| `bench-trace` | Added nanoseconds per `openat` from the syscall tracer, in three conditions |
| `bench-meter` | Added nanoseconds per context switch from the CPU meter |
| `bench-scale` | Whether per-event cost changes with the number of watched sandboxes |
| `bench-sign` | Record signing and verification cost |

The KVM benches need `/dev/kvm` and the built ekvm rootfs; the eBPF benches need
`CAP_BPF`+`CAP_PERFMON` and `cargo xtask build-probes`, but not KVM.

## How the suite guards against measuring nothing

Two checks, both added after a run was silently invalidated by a busy host:

- **A control column.** Each sweep re-measures its opening condition at the end. If that control has
  moved more than 15%, the host drifted during the run and the verdict is reported as INCONCLUSIVE
  rather than as a result. A growth check alone would not catch this, because it is one-sided.
- **A recorded load average.** A host under *uniform* load holds perfectly still at the wrong number,
  which no internal control can detect. `bench-all` and `bench-scale` record the 1-minute load
  average so a reader can judge the conditions.

`bench-all` also records the host it ran on and skips any section whose prerequisite is missing,
naming the reason, so a report states what it actually measured.

