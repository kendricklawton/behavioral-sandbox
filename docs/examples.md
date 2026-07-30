# Examples

Worked, end-to-end walkthroughs. Where [Using the eKVM CLI](./cli.md) is the reference (every flag,
the config layering), these are task-shaped: pick the task you want to perform and follow it through,
output and all.

- **[Run untrusted code](./examples-run-code.md)**, a script with stdin, a structured result, and
  files in and out.
- **[Observe a run from the host](./examples-observe.md)**, the fused surface: one run, all three
  probes, one audit record.
- **[Contain an agent](./examples-contain-an-agent.md)**, deny-by-default egress and a record that
  shows what the guest *claimed* against what the host *saw*.
- **[Analyze an untrusted binary](./examples-analyze-a-binary.md)**, run an unknown static ELF and
  watch it from outside.
- **[Run a CI job from a fork](./examples-ci-job.md)**, untrusted pull-request scripts with no NIC at
  all.

## Before you start

Every example assumes the prerequisites are installed ([Installation](./cli-install.md)) and the guest
rootfs is built:

```console
cargo xtask build-rootfs
```

The examples that observe a run also need the probe object:

```console
cargo xtask build-probes
```

`ekvm run` is **jailed by default**, which needs real root. The examples below use `--unjailed` where
the point is the workflow rather than the confinement, since that runs on a dev box without `sudo`;
the guest still sits behind the KVM boundary either way. Where the example is *about* what the host
observes or enforces, the jailed form is shown instead.

Two of these ship as runnable files in [`docs/examples/`](./examples/), so you can run them rather
than retype them.
