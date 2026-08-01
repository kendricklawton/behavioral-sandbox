# Testing

## The four layers

1. **Unit tests.** Driver config assembly, protocol framing, error mappings, and the pure parsers
   behind host detection. Run by [`cargo xtask ci`](./contributing-ci.md#the-host-safe-gate).
2. **eBPF build verification.** The probes compile for `bpfel-unknown-none` with `.BTF` debug sections
   enabled, which is what CO-RE needs at load time.
3. **Privileged integration.** End-to-end microVM boot, exec, TAP network filtering, snapshot and
   restore, and audit probe checks. Run by
   [`sudo -E ./ci-privileged.sh`](./contributing-ci.md#the-privileged-gate).
4. **Benchmarks.** Latency, density, and overhead, reported as percentiles with the host and date. See
   [Benchmarks](./benchmarks.md) for the methodology and why the result tables are currently withdrawn.

   ```console
   cargo xtask bench-boot     # cold boot vs the per-VM copy
   cargo xtask bench-warm     # snapshot restore vs the pre-warmed pool
   cargo xtask bench-density  # memory sharing: RSS vs PSS under load
   cargo xtask bench-trace    # syscall trace overhead
   cargo xtask bench-all      # the whole suite
   ```

## Two habits that matter more than the layers

**A test must be shown to fail.** Write the assertion, then temporarily break the behavior it covers
and watch it fail, then revert. A test that has never failed is not yet evidence. This is not
theoretical here: a readback test once passed for 120 seconds on a timeout while proving nothing, and
the assertion that unmasked it (refuse a `Timeout`, bound the elapsed time) found both a test
regression and a real engine defect.

**Beware the test that passes on the wrong subject.** A commit titled "stop two tests from passing on
something other than their subject" exists in this history. When selecting a row or a record field by
substring, prefer an exact or prefix match: `label.starts_with("host kernel")` rather than
`label.contains("kernel")`, which would also match "guest kernel present".

Tests whose meaning changes under `sudo` must say so with an explicit `ekvm_test_support::have_real_root()`
guard, because the privileged gate runs the whole suite as root.

## Coverage

`cargo xtask fuzz-coverage <target>` measures one libFuzzer target against its corpus, which says
nothing about the rest of the engine. For the **workspace's** coverage by its test suite:

```console
sudo -E env "PATH=$PATH" CARGO_TARGET_DIR="$PWD/target-privileged" cargo xtask coverage
```

It runs the whole suite once with `--include-ignored`, so the figure is the union of the host-safe and
privileged gates rather than either half. That is the only way to answer "which code do the privileged
tests never reach", and it is why the run needs the same host as the privileged gate: it shares that
gate's preflight, so a coverage run cannot quietly measure a suite whose privileged half self-skipped.
`--host-only` gives a fast partial number and says so.

Two opt-in installs, each refused up front with the one-line fix rather than failing at the merge step:
`cargo install cargo-llvm-cov --locked`, and `rustup component add llvm-tools-preview` (deliberately
not in `rust-toolchain.toml`, which would push the download onto every dev and CI job for a command
almost none of them run).

**Nothing gates on the number,** and no figure is published. A coverage threshold that blocks merges
gets satisfied with tests written for the number; the per-file uncovered regions in the HTML report are
the point. Two categories read low for structural reasons rather than missing tests: the guest agent's
`main.rs` loop runs inside the guest where no host profile is collected, and the `--watch` TUI's render
loop has no test vehicle.
