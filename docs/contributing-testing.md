# Testing

Four layers, cheapest first — the split exists so the everyday loop never waits on privileges:

1. **Unit / pure:** driver config assembly, protocol framing, policy-map encoding, error
   mapping — no VM, no root. Run by `cargo xtask ci`.
2. **eBPF object build** (`cargo xtask build-probes`, part of the `ci` gate): the probes compile
   for `bpfel-unknown-none` via `bpf-linker` **with BTF**; a compile error or a dropped `.BTF`
   section fails the CI gate. (The kernel *verifier* runs at load, so a verifier reject surfaces
   in the privileged probe tests, not here.)
3. **Privileged integration** (`cargo xtask ci-privileged`): boot a real microVM → `exec` → tap
   networking → attach probes → assert the observed record shows exactly what the workload did.
   Needs KVM + caps. Each test prints *why* it skipped when the host can't run it.
4. **Benchmarks:** cold boot, snapshot restore, pre-warmed-pool `exec` latency, memory-sharing,
   and probe overhead — reported with percentiles (p50/p99), tracked over time:

   ```console
   cargo xtask bench-boot     # boot-to-userspace latency, shared-base vs per-VM copy
   cargo xtask bench-warm     # time-to-first-result: cold boot vs snapshot restore vs pool take
   cargo xtask bench-trace    # per-syscall tracing overhead (no probes / filtered out / recording)
   cargo xtask bench-meter    # per-context-switch resource-metering overhead
   ```

The per-phase exit-gate demos (a real sandbox, one probe end to end) are listed under *Try it* in
[Host-side observability & enforcement](./probes.md#try-it).
