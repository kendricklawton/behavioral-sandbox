# Benchmarks

**One result is published: [cold boot latency](#cold-boot-latency-exec-01-2026-08-16), measured on
2026-08-16.** Every other result table was withdrawn on 2026-07-29 and stays withdrawn. This page
documents the methodology and how to run the suite yourself.

Why the rest were withdrawn: the published figures were measured on the development laptop under a
"quiet host" claim that nothing verified, and the guards that would have caught an invalid run (a
control column that re-measures the opening condition at the end, and a recorded 1-minute load
average) were added *afterwards*. The numbers may well have been roughly right; the problem is that
nobody can tell. Publishing a number nobody can defend is worse than publishing none, so they are
parked until a re-run on a host whose quiet state is verified.

Why cold boot returned ahead of them: two reporting defects sat between the rest of the suite and a
defensible table, and neither reached `bench-boot`. Both are now closed in the code. `bench-all`
records the scratch directory and the mount holding it (`scratch_line` in `xtask/src/bench.rs`,
through the driver's own mountinfo parser), where the boot run below had to record it by hand. And
`bench-meter` measures its unattached baseline twice and reports any delta inside that spread as
below its noise floor rather than as a number. The remaining tables return when the suite re-runs on
the measurement host, which is also what first exercises the meter's control on a host with the eBPF
capabilities it needs.

The suite lives in [`xtask`](https://github.com/kendricklawton/behavioral-sandbox/tree/main/xtask)
and runs via `cargo xtask bench-all`. Run it on your own host; that result is about your host, which
is the only thing a benchmark ever tells you.

## Methodology

- **Nearest-rank percentiles**: `min / p50 / p90 / p99 / max` without interpolation.
- **Tail metrics**: Percentile ranks requiring higher sample counts than executed return `—` instead of relabeling `max` (e.g. `p99` requires `n ≥ 100`).
- **Baseline comparison**: Warm starts are measured against cold boots, eBPF overhead against unattached baselines, and shared memory footprint (PSS) against un-deduplicated RSS.
- **Failure is loud, not filtered**: a boot or exec that errors mid-bench aborts its whole section
  with the error rather than being dropped from the sample, so a reported percentile never averages
  over silent retries (`bench-density` is the one deliberate early stop, and it names its reason).
- **Reproduce.** Two commands run the benchmarking suites:

  ```console
  cargo bench -p bsx-record         # Criterion micro-benchmarks: record signing, verification, hash-chaining, JSON
  cargo xtask bench-all              # the full system suite; skips sections whose host prereq is missing
  cargo xtask bench-warm --runs 100  # or a single bench at a sharper n for publication-grade tails
  ```

  The KVM benches need `/dev/kvm` + the built BSX rootfs; the eBPF benches need
  `CAP_BPF`+`CAP_PERFMON` + `cargo xtask build-probes` (not KVM). `bench-all` records the host it ran
  on, including the mount holding its scratch directory, and skips any section it can't run, with
  the reason, so a report says exactly what it measured.

The withdrawn figures were taken on the development host, with the guest at 256 MiB and 1 vCPU on a
132 MiB rootfs. When numbers return, they return with the machine and date they were taken on.

### The reference host

Published numbers are measured on **exec-01**, a bare-metal server described in full beside the
result it produced. The laptop below is where the code is written and the privileged suite runs
locally; it is not a measurement host, and no figure on this page comes from it.

Intel i5-10310U (8 vCPUs at 1.70 GHz), 15 GiB RAM, Arch Linux (rolling, kernel 7.1.5 as of
2026-08-05), Firecracker v1.16.1, `x86_64`. Arch is rolling, so a number states the kernel it was
measured on rather than inheriting the one named here.

That makes three kernels the engine has run on: this laptop, the Ubuntu 24.04 runner the privileged
suite uses nightly, and exec-01. Three is why the portability claim in
[Host-side observability & enforcement](./probes.md) is described as a mechanism rather than a
broadly tested property.

CI runs the host-safe gate on Ubuntu 24.04 `x86_64` on every change, and the privileged suite nightly
on GitHub-hosted Ubuntu 24.04 `x86_64` runners with nested KVM, one lane per supported Firecracker
series. Nested KVM makes timing unrepresentative, so benchmarks are never gated there.

## Cold boot latency (exec-01, 2026-08-16)

`bench-boot` reports three series per rootfs path. **Wall** is `Vm::boot` end to end. **Guest boot**
is `boot_latency()`, from Firecracker's `InstanceStart` to the guest's userspace marker. **Host
staging** is the per-boot difference between the two, subtracted sample by sample rather than
percentile by percentile, so a staging percentile is a real boot's staging and not the gap between
two unrelated boots.

### The measurement host

| | |
|---|---|
| Machine | exec-01, bare metal, Intel Xeon E-2176G at 3.70 GHz, 12 CPUs, 62 GiB RAM |
| Kernel | Linux 7.0.0-28-generic (Ubuntu 24.04), `x86_64` |
| Firecracker | v1.16.1 |
| Guest | 1 vCPU, 256 MiB, 132 MiB rootfs, `vmlinux-6.1.102` |
| Guest rootfs sha256 | `212ba229dc0a6949de0a9449c8c62bb3b19b8fca5c480c3a99c6019f97ebac16`, two builds byte-identical |
| Build profile | release |
| Scratch filesystem | root filesystem, no separate `/tmp` mount; 436 GB, 5% used |
| 1-minute load average | 0.02 at the start of the run |
| `bsx doctor` | 20 ok, 2 degraded (SMT enabled, `gather_data_sampling` exposed) |
| Commit | `dc6315b` |

`cargo xtask ci-privileged` ran green on this host immediately before the measurement.

### Boot, by rootfs path (n=100 per series)

Read-only shared base, the posture the CLI and daemon apply:

| | min | p50 | p90 | p99 | max |
|---|---|---|---|---|---|
| wall | 94 | **100** | 105 | 120 | 123 |
| guest boot | 85 | **91** | 95 | 109 | 109 |
| host staging | 6 | **9** | 12 | 16 | 16 |

Read-write per-VM copy, which `BootConfig::default()` still uses:

| | min | p50 | p90 | p99 | max |
|---|---|---|---|---|---|
| wall | 146 | **149** | 153 | 168 | 169 |
| guest boot | 82 | **83** | 87 | 103 | 103 |
| host staging | 64 | **66** | 70 | 72 | 77 |

Duplicating the 132 MiB base costs 49 ms of wall: 57 ms more host staging, less the 8 ms of guest
boot that the overlay init spends and the copy path does not.

### What `quiet` in the boot arguments costs

A second arm ran the same binary and the same guest image with one token removed from
`DEFAULT_BOOT_ARGS`, n=100 per series:

| | min | p50 | p90 | p99 | max |
|---|---|---|---|---|---|
| wall, shared base | 296 | **304** | 313 | 324 | 349 |
| guest boot, shared base | 288 | **294** | 304 | 313 | 335 |
| host staging, shared base | 6 | **9** | 12 | 14 | 14 |
| wall, per-VM copy | 345 | **352** | 357 | 366 | 395 |
| guest boot, per-VM copy | 280 | **286** | 291 | 301 | 328 |
| host staging, per-VM copy | 64 | **66** | 70 | 72 | 72 |

p50 difference, with `quiet` against without:

| | shared base | per-VM copy |
|---|---|---|
| wall | −204 | −203 |
| guest boot | **−203** | **−203** |
| host staging | **0** | **0** |

`quiet` sets the console loglevel to 4, which keeps informational printk off the serial console. It
has no host-side mechanism, and host staging does not move on either path: 9 ms on the shared base
and 66 ms on the copy, identical across both arms. The guest-boot difference is −203 ms on the two
paths independently.

This arm also reproduces the withdrawn 2026-08-12 figures on this same host to the millisecond (304
and 352 ms wall, n=30 there against n=100 here). Two things that closes: the 2026-08-12 run did not
record its build profile, and a release build reproduces it exactly; and the guest package closure
moved between the two dates (`python3` 3.14.5-r0 to 3.14.7-r1, plus `expat` entering) without moving
boot.

### Through the CLI (n=20)

`bsx run --demo-boot`, which reports `boot_latency()` only, through the CLI's jailed default and the
shared read-only base:

| | min | p50 | p90 | p99 | max |
|---|---|---|---|---|---|
| boot to userspace | 87 | **88** | 91 | — | 109 |

`p99` is `—` because n=20 admits no sample at that rank. Against the 91 ms guest-boot p50 on the same
base, the jailer costs nothing measurable on this clock: its setup is host-side and lands in staging,
which `boot_latency()` does not span.

### Reproducing this

The commit is `dc6315b`. `xtask/rootfs-packages.lock` was re-pinned on the measurement host to the
closure recorded above, which does not change the image: the lockfile is compared against the
resolved closure after a build and is never an input to it, so the binaries and the guest image at
`dc6315b` are the ones measured. The second arm is `dc6315b` with the token `quiet` deleted from
`DEFAULT_BOOT_ARGS` in `crates/engine/src/vm.rs` and nothing else changed.

```console
cargo run --release --quiet --package xtask -- bench-boot --runs 100
```

## What the suite measures

Each section below exists and runs today. `bench-boot`'s tables are published above; the rest are
withdrawn.

| Bench | Question |
|---|---|
| `bench-boot` | Cold boot latency, split into guest boot vs host staging, and the cost of the per-VM rootfs copy |
| `bench-warm` | Snapshot restore and pool take, against cold boot |
| `bench-density` | Memory sharing across concurrent clones: RSS against PSS |
| `bench-footprint` | Per-sandbox host cost under each rootfs/overlay choice |
| `bench-trace` | Added nanoseconds per `openat` from the syscall tracer, in three conditions |
| `bench-meter` | Added nanoseconds per context switch from the CPU meter |
| `bench-scale` | Whether per-event cost changes with the number of watched sandboxes |
| `bench-sign` | Record signing and verification cost |

The KVM benches need `/dev/kvm` and the built BSX rootfs; the eBPF benches need
`CAP_BPF`+`CAP_PERFMON` and `cargo xtask build-probes`, but not KVM.

## How the suite guards against measuring nothing

Two checks, both added after a run was silently invalidated by a busy host:

- **A control column.** Each sweep re-measures its opening condition at the end. If that control has
  moved more than 15%, the host drifted during the run and the verdict is reported as INCONCLUSIVE
  rather than as a result. A growth check alone would not catch this, because it is one-sided.
- **A recorded load average.** A host under *uniform* load holds perfectly still at the wrong number,
  which no internal control can detect. `bench-all` and `bench-scale` record the 1-minute load
  average so a reader can judge the conditions.

`bench-all` also records the host it ran on, the mount holding its scratch directory included (a
tmpfs scratch charges the rootfs copy to host RAM, which moves the boot and footprint numbers), and
skips any section whose prerequisite is missing, naming the reason, so a report states what it
actually measured.

