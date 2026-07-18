# Observing a run from the host

Running the code is half the point; the other half is seeing what it did, from *outside* the guest
where the code can't forge or disable the record. This is the host-side eBPF track. Each view below
is a real demo that boots a sandbox, attaches one probe, drives a workload, and prints what it saw.

The mechanics (program types, maps, the verifier, capabilities) are in [Host-side observability &
enforcement](./probes.md); this page is the workflow. All of these need `/dev/kvm`, the agent
rootfs, the built probe object (`cargo xtask build-probes`), and the eBPF capabilities
(`CAP_BPF`+`CAP_PERFMON`, plus `CAP_NET_ADMIN` for the network ones), run as root or grant the
named caps.

## The whole run, fused

The CLI carries the fused surface: one run, all three probes bound to it, one audit record out.
Watch it live, read the trail after, keep the machine record:

```console
agent run --unjailed --net --watch --trace --record run.json -- \
    python3 -c "import socket; open('/etc/hostname').read(); \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'hi', ('10.200.0.1', 9999))"
```

- `--watch` is the live view (a full-screen terminal UI on stderr): the guest's flows and denials
  as they happen, its resources, the VMM's host-syscall footprint, and a timeline. `q` closes the
  view; the run continues.
- `--trace` prints the human-readable audit trail on stdout after the run.
- `--record run.json` writes the deterministic JSON record, the machine surface downstream tools
  parse (byte-stable; see [Using the agent CLI](./cli.md)).

All of it is fail-open: without the eBPF capabilities the run still works and the record says
exactly which axes are missing and why. The per-axis demos below are the same probes driven one at
a time, useful when you want to study a single mechanism.

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

A typical loop is: run the workload with `agent run --trace` (or `--watch` to see it live, and
`--record` to keep the JSON), then drill into a single axis with the demos above when something
looks interesting. The engine *measures* and *records*; what a hoster does with that (bill it,
alert on it, store it) is the hoster's, by design.
