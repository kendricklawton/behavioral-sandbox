# Observing a run from the host

Running the code is half the point; the other half is seeing what it did, from *outside* the guest
where the code can't forge or disable the record. This is the host-side eBPF track. Each view below
is a real demo that boots a sandbox, attaches one probe, drives a workload, and prints what it saw.

The mechanics (program types, maps, the verifier, capabilities) are in [Host-side observability &
enforcement](./probes.md); this page is the workflow. All of these need `/dev/kvm`, the agent
rootfs, the built probe object (`cargo xtask build-probes`), and the eBPF capabilities
(`CAP_BPF`+`CAP_PERFMON`, plus `CAP_NET_ADMIN` for the network ones) — run as root or grant the
named caps.

> The unified `agent run --trace` that prints one fused per-run audit log is the next track on the
> [roadmap](https://github.com/kendricklawton/agent/blob/main/ROADMAP.md); today each axis is its own
> demo, shown here.

## Its syscalls

The sandbox's **host** syscall footprint (the VMM's execve/openat/connect), attributed in-kernel to
that one sandbox's cgroup. A microVM's *guest* syscalls stay in-guest by design, so this is the
host-visible footprint, not the guest's internals:

```console
cargo xtask trace-sandbox
```

## Its network

Every packet the guest sends or receives crosses its tap device on the host, so a program on the
tap sees the guest's own traffic. This boots a networked sandbox and prints the per-VM flows it
generated:

```console
cargo xtask watch-sandbox
```

## Its network, denied by default

Same tap hook, now enforcing: a deny-by-default egress policy that allows exactly one endpoint. The
allowed traffic passes; everything else is dropped at the tap (never leaving the host) and recorded
as a denial:

```console
cargo xtask enforce-sandbox
```

## Its resource use

Per-sandbox CPU (from an eBPF `sched_switch` probe) plus memory and I/O (from the guest's cgroup):
an idle guest charges near-zero host CPU while a CPU-heavy one charges most of a core, alongside the
per-run resource summary.

```console
cargo xtask meter-sandbox
```

## Putting it together

A typical loop is: run the workload with `agent run` (see [Running untrusted
code](./examples-untrusted-code.md)), and observe it with the views above. The engine *measures*
and *records*; what a hoster does with that (bill it, alert on it, store it) is the hoster's, by
design. Once the audit-log track lands, these separate views become one structured record emitted
per run.
