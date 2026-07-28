# Benchmarks

Performance measurements are backed by reproducible benchmarks reported as nearest-rank percentiles against baseline execution. The numbers below are produced by the benchmark suite in [`xtask`](https://github.com/packsixfour/ekvm/tree/main/xtask) via `cargo xtask bench-all`.

## Methodology

- **Nearest-rank percentiles**: `min / p50 / p90 / p99 / max` without interpolation.
- **Tail metrics**: Percentile ranks requiring higher sample counts than executed return `—` instead of relabeling `max` (e.g. `p99` requires `n ≥ 100`).
- **Baseline comparison**: Warm starts are measured against cold boots, eBPF overhead against unattached baselines, and shared memory footprint (PSS) against un-deduplicated RSS.
- **Success gating**: Benchmark runs that fail or error out are excluded from latency calculations.
- **Reproduce.** One command runs the whole suite as a single report:

  ```console
  cargo xtask bench-all              # the full suite; skips sections whose host prereq is missing
  cargo xtask bench-warm --runs 100  # or a single bench at a sharper n for publication-grade tails
  ```

  The KVM benches need `/dev/kvm` + the built ekvm rootfs; the eBPF benches need
  `CAP_BPF`+`CAP_PERFMON` + `cargo xtask build-probes` (not KVM). `bench-all` records the host it ran
  on and skips any section it can't run, with the reason, so a report says exactly what it measured.

The numbers on this page were measured on: **Linux 7.0.11, Intel i5-10310U (8 vCPUs @ 1.70 GHz),
15 GiB RAM**, Firecracker v1.16.1, ekvm rootfs 132 MiB, guest 256 MiB / 1 vCPU.

## Start latency: cold boot vs snapshot restore vs pool take

`cargo xtask bench-warm --runs 100`. The **cold boot** is the baseline (a fresh microVM on a
private read-write copy of the rootfs, disk copy and all). The **snapshot restore** brings up a clone
from one prewarmed snapshot; the **pool take** pops a prefilled clone (its restore paid off the clock,
between requests). Each path is split into its isolated **start** (begin a sandbox → an exec-ready VM)
and its **time-to-first-result** (start + a Python one-liner's output back on the host).

Start latency (ms, n=100):

| path              | min | p50 | p90 | p99 | max |
|-------------------|----:|----:|----:|----:|----:|
| cold boot         | 382 | 452 | 512 | 572 | 624 |
| snapshot restore  |  18 |  49 |  58 |  92 | 104 |
| pool take         |   1 |   6 |   7 |   8 |   9 |

Time-to-first-result (ms, n=100):

| path               | min | p50 | p90 | p99 | max |
|--------------------|----:|----:|----:|----:|----:|
| cold boot + exec   | 431 | 512 | 581 | 662 | 679 |
| restore + exec     |  65 | 159 | 188 | 246 | 258 |
| pool take + exec   |  44 | 112 | 138 | 154 | 160 |

**Result:** a snapshot restore starts ~9× faster than a cold boot (p50 49 ms vs 452 ms), and a pool
take is single-digit milliseconds (p50 6 ms, max 9 ms: the pop plus its health probe). End-to-end
the pool path is now both the fastest and the tightest (p50 112 ms, p99 154 ms, vs restore's
159/246): the long pool tail the previous recorded run showed (p99 537 ms, the first exec racing
the off-clock refill) did not reproduce on this stack.

### Bottleneck found and fixed

The decomposition above is what makes a bottleneck legible: the three start paths, isolated. It showed
the driver's **readiness waits**, the loops that poll for the API socket, the userspace marker, and
(on restore) the guest agent, sleeping on a fixed 20 ms / 10 ms interval between checks. A fixed
interval adds up to a whole interval (about half of it on average) of pure *quantization* to every
start. On a ~40 ms
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
(That experiment was recorded on the Firecracker v1.9 stack; the v1.16 tables above supersede its
absolute numbers, the lesson stands.)

## Memory-sharing density: how many concurrent microVMs before it degrades

`cargo xtask bench-density --count 16`. Restores clones one at a time from a single prewarmed snapshot,
keeps **every clone alive**, and samples the summed **Rss** (naive, counts the shared base in full for
every VM) against the summed **Pss** (proportional set size, shared pages divided across their
sharers, the true host footprint). The Rss/Pss gap *is* the memory-sharing benefit, made a number. It
stops at the target, a restore failure, or a memory floor (`max(1 GiB, 5% of RAM)`, so it never swaps
the host). Raise `--count` for a longer curve; the marginal-cost number is what sizing needs.

| clones | Rss sum (MiB) | Pss sum (MiB) |
|-------:|--------------:|--------------:|
|      1 |            40 |            40 |
|      2 |            81 |            46 |
|      4 |           163 |            57 |
|      8 |           327 |            80 |
|     16 |           621 |           103 |

**Result:** at 16 concurrent clones the naive Rss reads 621 MiB, but only **103 MiB** is actually
resident, **6× denser** than if nothing were shared. The marginal cost of one more clone is ~4.2 MiB
of Pss (its copy-on-write dirty pages); the read-only base disk and the 256 MiB snapshot memory file
stay page-cache-deduped across the whole fleet, not copied per VM.

**Scope: the engine measures, the hoster schedules.** This curve is a sizing input, not a scheduler.
How far you overcommit RAM or CPU, how you pin across NUMA nodes, and which run lands on which host
are the hoster's placement policy, not engine work (the engine-not-platform line and the
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
once per host, and whichever cohort touches the base first pays it. (This table is the one on this
page still measured on the v1.9 stack: a valid whole-host sample needs a freshly settled host, run
`bench-footprint` first after a reboot or an idle stretch, and a post-bench attempt on the v1.16
stack disqualified itself with a negative row, cache reclaim from the earlier benches outpacing the
cohort's own cost.)

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

Measured on the reference host (n=100 bursts per condition):

Added cost per `openat` (`bench-trace`, ns/openat):

| condition                | min  | p50  | p90  | p99  | max  |
|--------------------------|-----:|-----:|-----:|-----:|-----:|
| baseline (no probes)     | 1395 | 1667 | 4474 | 5210 | 5351 |
| unwatched (filtered out) | 1665 | 1804 | 2057 | 2377 | 2622 |
| watched (event written)  | 1969 | 2163 | 2570 | 3631 | 4744 |

At p50, a live-but-filtered probe adds **~137 ns** per openat (what every unwatched process pays for
the probe existing) and full capture adds **~496 ns** (what the one watched sandbox pays), with all
100,000 watched events captured, none dropped.

Scaling (`bench-scale`, watched-set size 1 → 512): tracer p50 2136 → 2126 ns/openat, meter p50
3743 → 3823 ns/switch. Both flat, as designed: one shared program, one O(1) lookup per event, so
probe overhead scales with the event rate, not the concurrent-sandbox count.

The meter's absolute three-condition table is deliberately not recorded yet: on the reference host
its baseline condition, measured first, ran ~3× slower than the attached conditions (scheduler
placement and frequency ramp-up dominate the ping-pong workload's early samples), which would print
a nonsense negative overhead. Until the harness interleaves its conditions, the honest published
numbers for the meter are the flat scale sweep above, which bounds its per-switch cost with the
workload included.

## Record signing overhead

Signing the finalized record. is one `ed25519` sign over the already-canonical bytes,
run once at record finalization, **off the boot/exec path**. This bench is host-only (no KVM, no
eBPF), so it always runs:

```console
cargo xtask bench-sign --runs 1000        # per-record ed25519 sign/verify + the sha256 chain hash
```

Measured on the reference host (n=1000, over a 760-byte canonical record), per operation, in
**nanoseconds**:

| operation             | min | p50 | p90 | p99 | max |
|-----------------------|-----|-----|-----|-----|-----|
| sign (unchained)      | 90525 | 104514 | 126662 | 217478 | 362834 |
| sign (chained)        | 91189 | 104372 | 126470 | 202486 | 328051 |
| verify                | 105828 | 123156 | 153265 | 281192 | 423491 |
| record_hash (sha256)  | 10936 | 12732 | 16653 | 39824 | 91871 |

The takeaway is the order of magnitude: a sign is **~105 microseconds** (p50), verify ~125, the chain
hash ~13, all far under a millisecond and dwarfed by a run's boot (hundreds of ms) and exec. Chaining
a record (the session hash-chain) costs the same as an unchained sign. Signing therefore adds no
measurable latency to a run. (The workspace opt-levels the `dalek`/`sha2` crates even in the dev
profile, so the `cargo xtask` harness measures optimized crypto; absolute values still swing with the
host's CPU frequency state, the order of magnitude is the claim.)
