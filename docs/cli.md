# Using the eKVM CLI

In addition to the [embedding API](./embedding.md), which lets you use the engine as a library, the
project provides an `ekvm` CLI to run untrusted code in a hardware-isolated microVM from the command
line. It is the engine's **reference embedder**: the whole sandbox lifecycle, open (confined by
default), exec with inputs, collect artifacts, close, in one command.

In short, you can run a command inside a microVM like so:

```console
ekvm run -- python3 -c 'print(2 + 2)'
```

Or, to prove the boundary without running anything of your own, boot a microVM to userspace and read
its console:

```console
ekvm run --demo-boot
```

The defaults point at the guest rootfs (built by `cargo xtask build-rootfs` or `self-host`), which
carries `python3`, `node`, and the in-guest exec agent. From a source checkout without installing,
the same commands are `cargo run -p ekvm -- run …`.

`ekvm run` is **jailed by default**: the VMM runs under Firecracker's jailer (chroot, uid/gid drop,
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
| Boot + one exec | [`ekvm run -- <cmd>`](./cli-commands.md#ekvm-run) |
| Stateful session | [`ekvm shell`](./cli-commands.md#ekvm-shell) |
| Confinement (jail) | jailed by default; `--unjailed` opts out |
| Resource limits (`Limits`) | `--vcpus`, `--mem`, `--wall`, `--output-cap` |
| Load-bearing limits (`require_limits`) | `--require-limits`: refuse, rather than boot uncapped, when a cgroup cap can't apply |
| Per-exec inputs | `--env`, `--put`, piped stdin |
| Artifact retrieval | `--get` (deny-by-default) |
| Networking (NIC) | `--net` |
| A route out (`GuestEgress`) | `--gateway`, `--resolver` (the hoster furnishes the uplink; [decision 9](./architecture-decisions.md#9-egress-is-enabled-by-the-engine-constructed-by-the-hoster)) |
| Egress policy (`EgressPolicy`) | [`--allow IP[/CIDR][:PORT][/PROTO]`](./cli-observe.md#enforcing-egress-with---allow) |
| Host-observed audit record | [`--trace`, `--record`, `--record-summary`, `--watch`](./cli-observe.md) |
| Verify a signed record | [`ekvm verify <record>`](./cli-commands.md#ekvm-verify) |
| Structured run result | `--json` |
| Host readiness | [`ekvm doctor`](./cli-commands.md#ekvm-doctor) |
| Crashed-run residue (`sweep_orphans`) | no flag: run automatically before every boot subcommand, reclaiming this euid's dead-pid scratch dirs and netns |
| Config layering | [flags > env (`EKVM_*`) > `.ekvm.toml` > defaults](./cli-config.md) |

## Deliberately not in the CLI

Daemon-scoped, embedding-API, or platform, by design. Their absence is intent, not omission.

- **Snapshots and the pre-warmed pool.** A pre-warmed pool is a long-lived-process concern, so it
  lives in the [`ekvm serve` daemon](./daemon.md) (`--prewarm`), not a one-shot CLI.
- **The wire API.** The programmatic driver surface is
  [the daemon's](./daemon-protocol.md), not a subcommand.
- **The shared read-only root** (`BootConfig::read_only_root`, one base image served `O_RDONLY` to
  many VMs with a per-run tmpfs overlay). A one-shot CLI boots one VM, so the sharing has nothing to
  share with; it pays off across concurrent sandboxes, which is an embedder's arrangement. Nothing
  the CLI or the daemon runs sets it, so each `ekvm run` gets its own read-write copy of the base.
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
