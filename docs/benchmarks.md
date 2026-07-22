# Benchmarks

*Measured, not marketed.* Every performance claim this engine makes is backed by a benchmark you can
re-run, reported with percentiles, against an honest baseline. This page is the results report; the
numbers below come from the benchmark suite in [`xtask`](https://github.com/k-henry-org/agent/tree/main/xtask), re-run with `cargo xtask bench-all`.

## Methodology

- **Percentiles, never averages.** Latencies and per-event costs are reported as
  `min / p50 / p90 / p99 / max`, nearest-rank (no interpolation). An average hides the tail a caller
  actually feels; a percentile does not.
- **Honest tails.** A percentile whose rank lands on the last sample has no observation above it, so
  it is just `max` relabeled. Those print `—`: a `p99` needs `n ≥ 100` to mean anything, and a short
  run is not allowed to dress its slowest sample up as a tail.
- **Against a baseline.** Each number is stated against the honest thing it improves on: a warm start
  against a **cold boot**, a probe's cost against **no probe attached**, a clone's true footprint
  against the **naive Rss** that double-counts shared pages.
- **Only-if-it-worked.** A timed run that did not produce its expected result is an error, never a
  fast sample: a bench that timed failures would be lying.
- **Reproduce.** One command runs the whole suite as a single report:

  ```console
  cargo xtask bench-all              # the full suite; skips sections whose host prereq is missing
  cargo xtask bench-warm --runs 100  # or a single bench at a sharper n for publication-grade tails
  ```

  The KVM benches need `/dev/kvm` + the built agent rootfs; the eBPF benches need
  `CAP_BPF`+`CAP_PERFMON` + `cargo xtask build-probes` (not KVM). `bench-all` records the host it ran
  on and skips any section it can't run, with the reason, so a report says exactly what it measured.

The numbers on this page were measured on: **Linux 7.0.11, Intel i5-10310U (8 vCPUs @ 1.70 GHz),
15 GiB RAM**, agent rootfs 132 MiB, guest 256 MiB / 1 vCPU. Your hardware will differ; re-run the
suite to get numbers for your host.

## Start latency: cold boot vs snapshot restore vs pool take

`cargo xtask bench-warm --runs 100`. The **cold boot** is the honest baseline (a fresh microVM on a
private read-write copy of the rootfs, disk copy and all). The **snapshot restore** brings up a clone
from one prewarmed snapshot; the **pool take** pops a prefilled clone (its restore paid off the clock,
between requests). Each path is split into its isolated **start** (begin a sandbox → an exec-ready VM)
and its **time-to-first-result** (start + a Python one-liner's output back on the host).

Start latency (ms, n=100):

| path              | min | p50 | p90 | p99 | max |
|-------------------|----:|----:|----:|----:|----:|
| cold boot         | 317 | 380 | 476 | 627 | 755 |
| snapshot restore  |  31 |  41 |  50 |  59 |  64 |
| pool take         |   0 |   0 |   5 |   9 |  27 |

Time-to-first-result (ms, n=100):

| path               | min | p50 | p90 | p99 | max |
|--------------------|----:|----:|----:|----:|----:|
| cold boot + exec   | 359 | 431 | 534 | 714 | 838 |
| restore + exec     |  74 | 102 | 123 | 168 | 210 |
| pool take + exec   |  42 |  66 | 238 | 537 | 765 |

**Result:** a snapshot restore starts ~9× faster than a cold boot (p50 41 ms vs 380 ms), and a pool
take is effectively instant (p50 0 ms). Restore is the tighter path end-to-end (p99 168 ms vs the pool
path's 537 ms) because the pool's first exec races the off-clock refill for CPU; when tail latency
matters more than steady-state throughput, restore-per-request is the steadier choice.

### Bottleneck found and fixed

The decomposition above is what makes a bottleneck legible: the three start paths, isolated. It showed
the driver's **readiness waits**, the loops that poll for the API socket, the userspace marker, and
(on restore) the guest agent, sleeping on a fixed 20 ms / 10 ms interval between checks. A fixed
interval adds up to a whole interval (about half of it on average) of pure *quantization* to every
start: readiness has already happened, but the poll won't notice until its next tick. On a ~40 ms
restore that is a large slice; on the boot tail it is needless jitter.

The fix replaces the fixed sleep with an adaptive back-off (start at 1 ms, double to a 5 ms cap), so
readiness is caught within about a millisecond when it comes quickly, while a long cold boot still
polls cheaply. Measured back-to-back on the same quiet host (start latency, ms):

| path              | before p50 | after p50 | before max | after max |
|-------------------|-----------:|----------:|-----------:|----------:|
| snapshot restore  |         40 |    **22** |         56 |    **32** |
| cold boot         |        417 |       430 |        515 |   **458** |

Restore start dropped ~45% (40 → 22 ms) and its worst case tightened (56 → 32 ms); restore-plus-exec
fell from 103 to 79 ms, and the pool-take tail from a 148 ms worst case to 67 ms. Cold boot is
unchanged at the median, it is dominated by the guest's own kernel-and-init time, where the poll is a
small fraction, but its tail tightened too. The lesson the numbers taught: on the paths the snapshot
machinery makes fast, a coarse *host-side poll* had become a meaningful fraction of the whole start.

## Memory-sharing density: how many concurrent microVMs before it degrades

`cargo xtask bench-density --count 32`. Restores clones one at a time from a single prewarmed snapshot,
keeps **every clone alive**, and samples the summed **Rss** (naive, counts the shared base in full for
every VM) against the summed **Pss** (proportional set size, shared pages divided across their
sharers, the true host footprint). The Rss/Pss gap *is* the memory-sharing benefit, made a number. It
stops at the target, a restore failure, or a memory floor (`max(1 GiB, 5% of RAM)`, so it never swaps
the host).

| clones | Rss sum (MiB) | Pss sum (MiB) |
|-------:|--------------:|--------------:|
|      1 |            31 |            31 |
|      2 |            62 |            32 |
|      4 |           123 |            35 |
|      8 |           249 |            40 |
|     16 |           505 |            51 |
|     32 |           755 |            68 |

**Result:** at 32 concurrent clones the naive Rss reads 755 MiB, but only **68 MiB** is actually
resident, **11× denser** than if nothing were shared. The marginal cost of one more clone is ~1 MiB
of Pss (its copy-on-write dirty pages); the read-only base disk and the 256 MiB snapshot memory file
stay page-cache-deduped across the whole fleet, not copied per VM.

**Scope: the engine measures, the hoster schedules.** This curve is a sizing input, not a scheduler.
How far you overcommit RAM or CPU, how you pin across NUMA nodes, and which run lands on which host
are the hoster's placement policy, not engine work (the engine-not-platform line, decision 038 and the
[threat model](./threat-model.md#assumptions-and-residual-risk)). The engine hands you the per-clone
footprint so you can set those ratios; it does not set them for you.

## Per-sandbox footprint: the effect of the overlay/rootfs choice

`cargo xtask bench-footprint --count 4`. Brings up a cohort of identical sandboxes on each disk
strategy and reports the per-VM VMM `Pss` plus the whole-host `MemAvailable` drop per sandbox. A per-VM
read-write copy lives in tmpfs *outside* the VMM's address space, so its Pss alone undercounts it,
whole-host is the honest meter here (and the bench proves it: identical 46 MiB Pss for both cold paths,
wildly different whole-host cost).

| strategy                         | VMM Pss / VM | whole-host / sandbox |
|----------------------------------|-------------:|---------------------:|
| cold boot, per-VM RW copy (baseline) |     46 MiB |              262 MiB |
| cold boot, shared RO base            |     46 MiB |               47 MiB |
| snapshot restore                     |      9 MiB |               ~0 MiB |

**Result:** the rootfs choice moves per-sandbox host cost from ~262 MiB (a private RW copy of the whole
132 MiB image, plus its touched guest RAM) to ~47 MiB (the base shared once for the fleet, writes in a
guest tmpfs overlay) to ~0 MiB (a restore shares even the memory file copy-on-write, paying only for the
pages the guest dirties). Guest RAM dominates the rest; shrink the base and you mainly buy sharing, not
boot time (see `cargo xtask bench-boot`).

One caveat, which the harness itself demonstrates: the whole-host number attributes the *first touch*
of shared files, so a page-cache-warm base shrinks the shared-base row. The numbers above are from a
standalone run on a settled host; `bench-all`'s footprint section runs after other benches have already
cached the base and reports a lower shared-base cost for exactly that reason, the shared cost is paid
once per host, and whichever cohort touches the base first pays it.

## eBPF probe overhead

The host-side probes add a bounded per-event cost, measured against a **no-probe baseline** on the same
micro-workload. These benches need `CAP_BPF`+`CAP_PERFMON` and the built probe object (not KVM), so run
them on an eBPF-capable host:

```console
cargo xtask bench-trace --runs 100   # added ns per openat: no probe vs filtered-out vs event-written
cargo xtask bench-meter --runs 100   # added ns per context switch: no meter vs not-metering-us vs metering-us
cargo xtask bench-scale --runs 100   # per-event cost vs watched-sandbox count (1 → 512): stays flat
```

What each measures, and the claim it backs:

- **`bench-trace`**, the syscall tracer's added cost per `openat`, in three conditions: no probe
  (baseline), attached-but-filtered-out (the cost every *other* process on the box pays for the probe
  being live, an in-kernel filter check that drops the event), and attached-and-capturing (the cost
  the *one sandbox you watch* pays, a full event written to the ring buffer). A microVM's own syscalls
  never trap here; they stay in-guest, so this bounds the cost on the VMM's host footprint, not on
  guest code.
- **`bench-meter`**, the resource meter's added cost per context switch, in the same
  baseline / not-metering-us / metering-us shape on a ping-pong workload.
- **`bench-scale`**, the *under-load* dimension: sweeps the watched-target-set size from 1 to 512 and
  shows the per-event cost stays **flat**. One shared program is attached to the global tracepoint, so
  each event is a single O(1) hash lookup no matter how many sandboxes are watched, total probe
  overhead scales with the **event rate**, not with the number of concurrent sandboxes.

Run these on your host and record the deltas; the design guarantee is that both per-event costs are
bounded and independent of the sandbox count.

## Record signing overhead

Signing the finalized record (decision 034) is one `ed25519` sign over the already-canonical bytes,
run once at record finalization, **off the boot/exec path**. This bench is host-only (no KVM, no
eBPF), so it always runs:

```console
cargo xtask bench-sign --runs 1000        # per-record ed25519 sign/verify + the sha256 chain hash
```

Measured on the reference host below (a `--release` build over a 760-byte canonical record), per
operation, in **nanoseconds**:

| operation             | min | p50 | p90 | p99 | max |
|-----------------------|-----|-----|-----|-----|-----|
| sign (unchained)      | 47449 | 52130 | 83113 | 132529 | 306601 |
| sign (chained)        | 47870 | 51897 | 77383 | 112041 | 336789 |
| verify                | 79750 | 88749 | 129967 | 181759 | 410207 |
| record_hash (sha256)  | 7073 | 7754 | 11789 | 22940 | 443027 |

The takeaway is the order of magnitude: a sign is **~50 microseconds** (p50), verify ~90, the chain
hash ~8, all far under a millisecond and dwarfed by a run's boot (hundreds of ms) and exec. Chaining a
record (the session hash-chain) costs the same as an unchained sign. Signing therefore adds no
measurable latency to a run. (Run in `--release`: `ed25519` is 10-40x slower in an unoptimized build,
so a `cargo xtask` debug build reports numbers that aren't representative; the workspace also
opt-levels the `dalek`/`sha2` crates in the dev profile so tests aren't slowed.)
