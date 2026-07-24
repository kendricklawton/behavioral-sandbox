# Testing

Four layers, cheapest first, the split exists so the everyday loop never waits on privileges:

1. **Unit / pure:** driver config assembly, protocol framing, policy-map encoding, error
   mapping, no VM, no root. Run by `cargo xtask ci`.
2. **eBPF object build** (`cargo xtask build-probes`, part of the `ci` gate): the probes compile
   for `bpfel-unknown-none` via `bpf-linker` **with BTF**; a compile error or a dropped `.BTF`
   section fails the CI gate. (The kernel *verifier* runs at load, so a verifier reject surfaces
   in the privileged probe tests, not here.)
3. **Privileged integration** (`cargo xtask ci-privileged`): boot a real microVM → `exec` → tap
   networking → attach probes → assert the observed record shows exactly what the workload did.
   Needs KVM + caps. Each test prints *why* it skipped when the host can't run it.
4. **Benchmarks:** cold boot, snapshot restore, pre-warmed-pool `exec` latency, memory-sharing,
   and probe overhead, reported with percentiles (p50/p99), tracked over time:

   ```console
   cargo xtask bench-boot     # boot-to-userspace latency, shared-base vs per-VM copy
   cargo xtask bench-warm     # cold boot vs snapshot restore vs pool take: start + time-to-first-result
   cargo xtask bench-density  # memory-sharing: summed Rss vs Pss as concurrent clones stack up
   cargo xtask bench-footprint # per-sandbox footprint + the overlay/rootfs choice's effect
   cargo xtask bench-trace    # per-syscall tracing overhead (no probes / filtered out / recording)
   cargo xtask bench-meter    # per-context-switch resource-metering overhead
   cargo xtask bench-scale    # probe overhead under load: per-event cost vs watched-sandbox count
   cargo xtask bench-all      # the whole suite as one reproducible report (skips missing-prereq sections)
   ```

   The recorded numbers and full methodology live in the [Benchmarks](./benchmarks.md) report.

A fifth layer, **fuzzing**, guards the places attacker-controlled bytes meet the host path (the
host↔guest channel decoders, the daemon's client wire, the signed-record envelope, and the
eBPF-boundary parsers): a deterministic property test per surface runs in the `ci` gate above, and a
seeded `cargo fuzz` harness does deep nightly runs. See [Fuzzing](./contributing-fuzzing.md).

## Negative-space tests

The bugs that survive a memory-safe language and a happy-path suite share one signature: they live
in what must *not* happen. New code that matches one of these three shapes carries the matching
test, host-safe wherever the property allows:

1. **Reads from an untrusted peer → an adversarial-liveness test.** Slow-drip (one byte per
   interval, inside any per-read timeout), never-terminate, flood, and half-close each get a
   bounded, typed outcome, never a pinned thread or an unbounded buffer. A bare `SO_RCVTIMEO` is
   re-armed by every byte, so bound the whole message/request with one absolute deadline.
   Template: the metrics slow-drip test in `crates/cli/src/metrics.rs` (and its
   `read_request_head` deadline loop); the session, exec-collect, and Firecracker-client readers
   carry the same pattern.
2. **Stages-then-publishes, or tears down, a resource → a fault-injection test.** Cleanup lives in
   an RAII `Drop` guard (disarmed on publish/handoff), not a per-error-path `remove` a panic can
   skip, and a `catch_unwind` test proves the guard fires on unwind and spares the published
   artifact. Template: the `StagingFile` unwind test in `crates/probes-loader/src/signing.rs`;
   the same shape guards the daemon's temp socket, the boot staging workdir, and the snapshot
   bundle. (`Drop` cannot run on SIGKILL; the startup sweeps own that half.)
3. **Documents an invariant → a test that asserts it.** "Counters only go up", "bounded at N",
   "truncation is flagged": assert the property itself, not just the absence of a panic, and
   guard against a vacuous pass (a floor on the sample count, a baseline that can't read as
   zero-equals-zero). Template: the counter-monotonicity and histogram-monotonicity tests in
   `crates/cli/src/metrics.rs` and the required-keys freeze in `crates/probes-loader/src/json.rs`.

The per-phase exit-gate demos (a real sandbox, one probe end to end) are listed under *Try it* in
[Host-side observability & enforcement](./probes.md#try-it).

## On a real KVM box: the full manual pass

A bare-metal or nested-virt host with `/dev/kvm`, real root, and the eBPF caps runs every layer. This
is the order to exercise the whole engine end to end; each step links to its detail.

1. **Check the host.** `cargo xtask setup` (build-time) and `kee doctor` (runtime) report exactly
   what is missing; `doctor` exits non-zero on a missing hard requirement.
   ([Supported platforms](./cli-install.md#supported-platforms).)
2. **Stand it up.** `cargo xtask self-host` does the whole build: the guest kernel + rootfs + eBPF
   object, installs the `kee` binary, and boots one proof sandbox.
   ([Self-host in one command](./cli-install.md#self-host-in-one-command).)
3. **Run one sandbox, confined.** With real root you exercise the jailed default (not `--unjailed`):
   `kee run -- python3 -c 'print(2 ** 100)'`. Add `--net` / `--trace` / `--record` / `--watch` to
   see the host-observed record. ([Using the eke CLI](./cli.md).)
4. **The privileged integration suite.** `cargo xtask ci-privileged` boots real microVMs, execs, runs
   tap networking, attaches probes, and asserts the observed record: the half the host-safe gate
   cannot reach. It self-checks its prerequisites and prints the fix if an artifact is missing, and
   it *refuses* to run without real root (run it under `sudo`), BTF, or the built eBPF object:
   the capability-gated tests skip themselves on a short host, and a skipped test is a pass to
   cargo, so running anyway would print a hollow green.
5. **The live demos.** One probe end to end each: `trace-sandbox`, `watch-sandbox`, `enforce-sandbox`,
   `meter-sandbox`. ([Host-side observability, *Try it*](./probes.md#try-it).)
6. **The daemon.** `kee serve --socket ./kee.sock`, then drive it with the reference client or `socat`.
   ([Using the `kee serve` daemon](./daemon.md).)
7. **The embedding API.** The reference integration
   [`crates/probes-loader/examples/reference_integration.rs`](../crates/probes-loader/examples/reference_integration.rs)
   composes the whole lifecycle (open, attach, exec, collect, close) in one small program.
   ([Using the engine API](./embedding.md).)
8. **The numbers.** `cargo xtask bench-all` for the measured percentiles. ([Benchmarks](./benchmarks.md).)
