# Using the `bsx` CLI

In addition to the [embedding API](./embedding.md), which lets you use the engine as a library, the
project provides a `bsx` CLI to run untrusted code in a hardware-isolated microVM from the command
line. It is the engine's **reference embedder**: the whole sandbox lifecycle, open (confined by
default), exec with inputs, collect artifacts, close, in one command.

In short, you can run a command inside a microVM like so:

```console
bsx run -- python3 -c 'print(2 + 2)'
```

Or, to prove the boundary without running anything of your own, boot a microVM to userspace and read
its console:

```console
bsx run --demo-boot
```

The defaults point at the guest rootfs (built by `cargo xtask build-rootfs` or `self-host`), which
carries `python3`, `node`, and the in-guest exec agent. From a source checkout without installing,
the same commands are `cargo run -p bsx -- run …`.

`bsx run` is **jailed by default**: the VMM runs under Firecracker's jailer (chroot, uid/gid drop,
its own namespaces, a cgroup), with Firecracker's own built-in seccomp filters left on top because
the driver never passes `--no-seccomp`. That needs real root and the `jailer` binary. On a dev box
without them, `--unjailed` is the explicit, greppable opt-out, and the guest still sits behind the KVM
hardware boundary; only the VMM process itself runs unconfined.

For more information be sure to check out [how to install the CLI](./cli-install.md), [the commands
and options](./cli-commands.md), [observing what a run did](./cli-observe.md), and [how to configure
the engine](./cli-config.md).

## Every engine capability, and where it lives

Every library capability is reachable through a few orthogonal verbs, or named below as deliberately
out of scope.

| Engine capability | CLI surface |
|-------------------|-------------|
| Boot + one exec | [`bsx run -- <cmd>`](./cli-commands.md#bsx-run) |
| Stateful session | [`bsx shell`](./cli-commands.md#bsx-shell) |
| Confinement (jail) | jailed by default; `--unjailed` opts out |
| Resource limits (`Limits`) | `--vcpus`, `--mem`, `--wall`, `--output-cap` |
| Load-bearing limits (`require_limits`) | `--require-limits`: refuse, rather than boot uncapped, when a cgroup cap can't apply |
| Per-exec inputs | `--env`, `--put`, piped stdin |
| Artifact retrieval | `--get` (deny-by-default) |
| Networking (NIC) | `--net` |
| A route out (`GuestEgress`) | `--gateway`, `--resolver` (the hoster furnishes the uplink; [decision 9](./architecture-decisions.md#9-egress-is-enabled-by-the-engine-constructed-by-the-hoster)) |
| Egress policy (`EgressPolicy`) | [`--allow IP[/CIDR][:PORT][/PROTO]`](./cli-observe.md#enforcing-egress-with---allow) |
| Host-observed audit record | [`--trace`, `--record`, `--record-summary`, `--watch`](./cli-observe.md) |
| Verify a signed record | [`bsx verify <record>`](./cli-commands.md#bsx-verify) |
| Structured run result | `--json` |
| Host readiness | [`bsx doctor`](./cli-commands.md#bsx-doctor) |
| Crashed-run residue (`sweep_orphans`) | no flag: run automatically before every boot subcommand, reclaiming this euid's dead-pid scratch dirs and netns |
| Config layering | [flags > env (`BSX_*`) > project `.bsx.toml` > `~/.bsx.toml` > defaults](./cli-config.md) |

## Deliberately not in the CLI

Daemon-scoped, embedding-API, or platform, by design. Their absence is intent, not omission.
"The CLI" here means the one-shot commands (`run`, `shell`, `doctor`, `verify`): a process that
boots one VM, does its work, and exits. The daemon is the **same `bsx` binary** started as
`bsx serve`, so a daemon-scoped feature is one subcommand away, not a separate install; what
differs is the operational shape — a long-lived process with its own flags, policy, and wire API.

- **Snapshots and the pre-warmed pool.** A pre-warmed pool is a long-lived-process concern, so it
  lives in the [`bsx serve` daemon](./daemon.md) (`--prewarm`), not a one-shot CLI.
- **The wire API.** The programmatic driver surface is
  [the daemon's](./daemon-protocol.md), not a subcommand.
- **A storage-shape knob.** The CLI and the daemon boot their VMs on the **shared read-only root**
  (`BootConfig::read_only_root`: the agent image served `O_RDONLY`, `/` made writable by a per-run
  tmpfs overlay capped at half the guest's RAM), set in the one posture fold `run`, `shell`, and
  `serve` share. A one-shot `bsx run` gains no cross-VM sharing from it, but it skips duplicating
  the base image per boot (48 ms of a 352 ms p50 cold boot, exec-01, 2026-08-12). There is no flag
  to change the shape: the field stays an embedder's decision on `BootConfig`, and the overlay
  needs the agent image's overlay init, so a `rootfs` override pointing at a foreign image fails at
  boot rather than booting unshared.
- **Bulk block-device I/O** (`BootConfig::input_dir`/`output_dir`, whole directories or large files as
  ext4 devices) and **out-of-band control** (`KillHandle`, force-killing a blocked exec from another
  thread) are *embedding-API* capabilities. The CLI's file path is per-frame `--put`/`--get` (small,
  bounded files); a caller needing bulk transfer or async cancellation drives the library directly. A
  one-shot CLI cancels by process signal (Ctrl-C, and the sandbox's `Drop` tears the VM down).
- **Platform features.** These are the *hoster's* layer, above the engine: a recorded non-goal
  (design rule 4), which is what makes proposing one a design error rather than a missing feature.
  What that covers is listed in [Where the engine ends](./embedding-scope.md).

Running one probe at a time, standalone, is
[Host-side observability & enforcement](./probes.md), under *Try it*.
