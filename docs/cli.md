# Using the `ekvm` CLI

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
seccomp, its own namespaces, a cgroup), which needs real root and the `jailer` binary. On a dev box
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
| Per-exec inputs | `--env`, `--put`, piped stdin |
| Artifact retrieval | `--get` (deny-by-default) |
| Networking (NIC) | `--net` |
| Egress policy (`EgressPolicy`) | [`--allow IP[/CIDR][:PORT][/PROTO]`](./cli-observe.md#enforcing-egress-with---allow) |
| Host-observed audit record | [`--trace`, `--record`, `--record-summary`, `--watch`](./cli-observe.md) |
| Verify a signed record | [`ekvm verify <record>`](./cli-commands.md#ekvm-verify) |
| Structured run result | `--json` |
| Host readiness | [`ekvm doctor`](./cli-commands.md#ekvm-doctor) |
| Config layering | [flags > env (`EKVM_*`) > `.ekvm.toml` > defaults](./cli-config.md) |

## Deliberately not in the CLI

Daemon-scoped, embedding-API, or platform, by design. Their absence is intent, not omission.

- **Snapshots and the pre-warmed pool.** A pre-warmed pool is a long-lived-process concern, so it
  lives in the [`ekvm serve` daemon](./daemon.md) (`--prewarm`), not a one-shot CLI.
- **The wire API.** The programmatic driver surface is
  [the daemon's](./daemon.md#the-wire-protocol-versioned-json-schema-1), not a subcommand.
- **Bulk block-device I/O** (`BootConfig::input_dir`/`output_dir`, whole directories or large files as
  ext4 devices) and **out-of-band control** (`KillHandle`, force-killing a blocked exec from another
  thread) are *embedding-API* capabilities. The CLI's file path is per-frame `--put`/`--get` (small,
  bounded files); a caller needing bulk transfer or async cancellation drives the library directly. A
  one-shot CLI cancels by process signal (Ctrl-C, and the sandbox's `Drop` tears the VM down).
- **Tenancy, auth, billing, fleet scheduling, a dashboard, image and registry management.** These are
  the *hoster's* platform, above the engine; they never land in this repo.

The per-axis eBPF demos (one probe at a time) live in
[Host-side observability & enforcement](./probes.md), under *Try it*.
