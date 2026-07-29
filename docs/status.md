# Status and verification record

<!-- ANCHOR: banner -->
> **Pre-release, unreleased, unaudited.** Version `0.0.0`, no tag, no published artifact. One
> maintainer; nothing here has been reviewed by anyone outside the project. Nothing in this book is
> a promise: it describes how the engine is built and what has been measured, with the date and
> machine. Anything can change without notice; if you build on this, pin a git rev. See
> [Status and verification record](./status.md).
<!-- ANCHOR_END: banner -->

This page is the single place a date, a host, or a measurement appears. Every other chapter refers
here rather than restating it, so the record has one thing to keep current instead of many.

## What a passing test is worth

<!-- ANCHOR: test-scope -->
A passing test shows that the case it constructs behaved as described, on the host that ran it, at
the revision it ran against. It does not show that the property holds for cases the test does not
construct. Throughout this book, a named test is a pointer to a scenario you can read and re-run,
not a proof of a general property.
<!-- ANCHOR_END: test-scope -->

Two consequences worth stating plainly:

- **Evidence expires.** A gate that passed in July is evidence about July's revision on July's host.
  Nothing here is settled until it is re-run against whatever revision is eventually tagged.
- **A test is only as good as its assertions.** Commit `c4a05e2` in this repo exists because two
  tests were passing on something other than their subject. Where a chapter cites a test, the useful
  move is to read the test.

## Verified on

<!-- ANCHOR: verified-on -->
**Development host** (where the privileged suite and all local measurements are run): Linux
7.0.11, Intel i5-10310U (8 vCPUs at 1.70 GHz), 15 GiB RAM, Arch Linux. This is a laptop, not a
server, and it is the *only* kernel the engine has been exercised on.

**CI**: the host-safe gate (`cargo xtask ci`) runs on Ubuntu 24.04 `x86_64` on every change. The
privileged suite (`cargo xtask ci-privileged`: microVM boot, the jailer, eBPF attach, the
integration tests) runs nightly on a GitHub-hosted Ubuntu 24.04 `x86_64` runner with nested KVM.

**Firecracker**: v1.16.1 pinned. `x86_64` only.
<!-- ANCHOR_END: verified-on -->

## Last full verification: 2026-07-29

Both gates green, three consecutive clean privileged runs, on the development host above.

**Test coverage**: 81.95% of lines, 81.98% of regions, 78.86% of functions, over the shipped crates
(`xtask` and `test-support` excluded, since neither ships). Measured by `cargo xtask coverage`, which
runs the whole suite once with `--include-ignored`, so the figure is the union of both gates rather
than either half.

Scope of that number, since a percentage invites over-reading:

- One kernel, one machine, one revision.
- It measures which lines *executed*, not whether anything asserted they behaved correctly.
- Nothing gates on it. A coverage threshold that blocks merges gets satisfied by tests written for
  the number; the per-file uncovered regions are the point.

Files where coverage is low, and why:

| File | Lines | Reason |
|---|---|---|
| `crates/guest-agent/src/main.rs` | 24% | Measurement artifact. This loop runs *inside the guest*, where no host profile is collected. Its logic lives in `lib.rs` (85%). |
| `crates/cli/src/watch.rs` | 31% | The `--watch` TUI render loop. The timeline logic beneath it is unit-tested; interactive rendering has no test vehicle. |
| `crates/cli/src/session.rs` | 42% | The daemon's per-message dispatch arms, mostly error-reply formatting. |
| `crates/cli/src/serve.rs` | 48% | As above. |
| `crates/probes-loader/src/observer.rs` | 46% | The live-stream half of the loader. The projections it feeds are at 94-97%. |

## What has not been done

Stated because their absence is the honest counterweight to everything else in this book:

- **No external security review or audit.** The threat model is the author's own reasoning about the
  author's own code. See [Threat model](./threat-model.md).
- **One kernel.** The CO-RE/BTF portability described in [Host-side observability &
  enforcement](./probes.md) is a property of the mechanism, not a tested claim: the probes have been
  loaded on exactly one kernel version.
- **No Red Hat host has been run.** RHEL 9 and 10 are intended targets and `ekvm doctor` now probes
  for `cgroup.kill` rather than a version number so RHEL 9's `5.14` can qualify, but nothing has
  booted, gated, or attached a probe there. SELinux in particular is unexercised. See
  [Red Hat](./cli-install.md#red-hat-rhel-9-rhel-10-a-target-not-yet-verified).
- **No published benchmark numbers.** See [Benchmarks](./benchmarks.md) for why they were withdrawn
  and what has to happen before they return.
- **No fuzzing at scale.** Ten libFuzzer targets exist and run nightly, but not continuously
  (no OSS-Fuzz or equivalent), and two targets have thin corpora.
- **No outside users.** Nobody has installed or run this who did not build it.
- **No release, so no support policy in force.** [RELEASES.md](../RELEASES.md) describes what is
  planned, not what is currently offered.
- **`x86_64` only.** aarch64 needs hardware and a privileged CI lane before anything about it could
  be claimed.

## Reproducing any of this

```console
cargo xtask ci                 # host-safe gate: fmt, lints, unit tests, docs, deny, eBPF build
sudo -E ./ci-privileged.sh     # privileged suite: needs /dev/kvm, real root, BTF
```

Coverage, which runs the whole suite instrumented and needs the same host as the privileged gate:

```console
sudo -E ./ci-privileged.sh && \
  sudo -E env "PATH=$PATH" CARGO_TARGET_DIR="$PWD/target-privileged" cargo xtask coverage
```

`ekvm doctor` reports whether your own host can run any of it.
