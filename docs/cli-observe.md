# Observing a run

`--trace`, `--record`, `--record-summary`, and `--watch` bind the host-side eBPF probes to the sandbox
at launch and fuse what they saw into one per-run audit record, observed from the host side of the KVM
boundary: the probes are loaded by a host process and attached to host-kernel hooks.

```console
# Watch it live, read the trail after, keep the machine record and the model-legible summary:
ekvm run --unjailed --net --watch --trace --record run.json --record-summary run.sum.json -- python3 -c '…'
```

## Four faces, one record

- **`--watch`**, the live view, drawn on stderr (stdout stays the run's result): the guest's network
  flows and egress denials as they happen, its CPU/memory/IO, the VMM's host-syscall footprint, and a
  running timeline. `q` or `Esc` closes the view and the run continues. When the command finishes the
  view stays up (so a fast run doesn't flash away) until you close it.

- **`--trace`**, the human-readable trail on stdout after the run: timing, per-flow traffic, denials,
  resources, notable host syscalls, and a `gap` line for any axis that couldn't bind.

- **`--record FILE`**, the machine surface: the record as one line of deterministic, byte-stable JSON
  (integer nanoseconds, no floats; addresses and protocols by name). This is the format downstream
  SDKs parse. The pretty trail makes no stability promise.

- **`--record-summary FILE`**, the **model-legible** face: a compact projection of the same record for
  an agent's observe-then-act loop. What it *reached* (distinct destinations, flows collapsed to their
  endpoint), what egress was *denied*, its resource envelope, and any coverage gap, with the forensic
  detail (per-flow counters, per-syscall `comm` and hit counts) dropped. A *view* of the record, not
  new observation: compact, deterministic, and byte-stable, so an agent gets a small, stable summary to
  feed into its next turn.

Check a `--record` file with [`ekvm verify`](./cli-commands.md#ekvm-verify).

## Schema versioning

Each machine JSON surface carries a leading integer **`schema`** field, and the `--json` run result,
the `--record` audit record, and the `--record-summary` projection version **independently**. The
`--json` result and the summary are at `1`; a `--record` file's outer object is the signing envelope
at `2`, wrapping a record that is itself `1`, so read the `schema` at the level you are parsing. The compatibility policy: **within a version, changes are additive only**, a new field
a consumer can ignore; **renaming or removing a field, or changing a value's meaning, bumps the
version.**

## What the probes need, and what happens without them

The probes need kernel BTF, `CAP_BPF` and `CAP_PERFMON` (plus `CAP_NET_ADMIN` for the tap), and the
built object (`cargo xtask build-probes`).

Observation is **fail-open**: on a host without them the run still works, and the record's coverage
section says exactly which axes are missing and why. A thinner record annotates itself rather than
presenting itself as complete.

The syscall axis is the **VMM's host footprint**. A microVM services the guest's syscalls in its own
kernel, so their absence from a host tracepoint is the isolation working, not a blind spot; the guest's
*network* is observed exactly, at the tap.

## Enforcing egress with `--allow`

`--net` alone is observe-only: the guest reaches nothing past the host end of its /30 (the driver's
deny-by-default routing), and the tap records what crosses it. To *permit* specific egress, list each
destination with a repeatable `--allow`, which requires `--net`:

```console
# Allow DNS to one resolver and HTTPS to a subnet; everything else is dropped at the tap and recorded.
ekvm run --unjailed --net \
    --allow 1.1.1.1:53/udp --allow 10.0.0.0/8:443/tcp --record run.json -- ...
```

Each `--allow` is `IP[/CIDR][:PORT][/PROTO]`; a bare `IP` is a single-host `/32`, any port, any
protocol. The allowances build a deny-by-default egress policy: the policy maps are populated first and
the classifiers are attached to the tap only afterwards, so the programs go live against maps that
already hold the run's rules. Every allowance is explicit on the command line, and what the policy
dropped lands in the record's `denials`.

Enforcement is a security control, so unlike observation it does **not** fail open: `--allow` on a host
that can't load the probes (or can't get `CAP_NET_ADMIN` to police the tap) is a typed refusal, never a
run that quietly ignores the policy. `--allow` without `--net` is refused at the command line.

A host can withdraw guest networking entirely with
[`allow_net`](./cli-config.md#setting-allow_net).

The per-axis eBPF demos (one probe at a time) live in
[Host-side observability & enforcement](./probes.md), under *Try it*.
