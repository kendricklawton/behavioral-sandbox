# CI gates

Three commands, in increasing cost. The first two run anywhere; the third needs real hardware.

## The fast inner loop

```console
cargo xtask check
```

Format, the prose-drift lint, and Clippy with `-D warnings`. Skips tests, so it returns in a few
seconds. This is the loop to run while editing.

## The host-safe gate

```console
cargo xtask ci
```

Runs everywhere, with no root and no KVM: rustfmt, the prose-drift lint, Clippy `-D warnings`, build,
unit tests, doc build, `cargo deny`, and the eBPF object build. This is what CI runs on every change,
and a change is not ready until it passes.

The prose-drift lint is worth knowing about: it checks that backticked repo paths and relative
Markdown links in the docs actually resolve. It does **not** check anchors, wording, or numbers, so a
cross-page `#anchor` link is on the author to verify.

## The privileged gate

```console
sudo -E ./ci-privileged.sh
```

Runs the microVM boot, exec, TAP networking, snapshot/restore, and eBPF probe-attach integration
tests. Needs `/dev/kvm` and **real root**, so it wants a dev box or a bare-metal/nested-virt runner; a
stock cloud VM cannot nest KVM.

The wrapper exists because a `sudo` run otherwise stacks three environment concerns by hand:

- A throwaway `CARGO_TARGET_DIR`. The gate *refuses* to run as root without it, because a root build
  into `./target` leaves root-owned artifacts that block every later non-root `cargo`.
- An `EKVM_SCRATCH_DIR` off `nodev` and `noexec` mounts, pre-checked, since the jailer's chroot needs
  working device nodes and an executable `firecracker` copy there.
- rustup's `cargo` back on `PATH`, which `sudo` strips.

The gate **refuses outright** without root, BTF, or the eBPF object, rather than letting the
capability-gated tests skip themselves into a hollow green. A skipped test is a pass to cargo, which
makes silent skipping worse than failing.

Never gate the everyday loop on a privileged runner.

## Other workflows

- `firecracker-pin.yml` runs weekly and watches upstream's support table, per
  [Firecracker version policy](./contributing-firecracker-policy.md).
- `fuzz-smoke.yml` and `fuzz.yml` are the two fuzzing tiers, per
  [Fuzzing](./contributing-fuzzing.md).
- `ci-privileged-hosted.yml` runs the privileged gate nightly on a hosted runner under nested KVM.
  Correctness only: nested KVM makes timing unrepresentative, so benchmarks are never gated there.
- `docs.yml` publishes the book, and is manual-only until the first release.
