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
  SDKs will parse. The pretty trail makes no stability promise.

- **`--record-summary FILE`**, the **model-legible** face: a compact projection of the same record for
  an agent's observe-then-act loop. What it *reached* (distinct destinations, flows collapsed to their
  endpoint), what egress was *denied*, its resource envelope, and any coverage gap, with the forensic
  detail (per-flow counters, per-syscall `comm` and hit counts) dropped. A *view* of the record, not
  new observation: compact, deterministic, and byte-stable, so an agent gets a small, stable summary to
  feed into its next turn.

Check a `--record` file with [`ekvm verify`](./cli-commands.md#ekvm-verify).

**The record says what was permitted, not only what was refused.** The network section's `posture`
carries the rules the classifier actually holds (read back from the kernel after attach, so it
reports what is in force rather than what was requested), whether enforcement was armed, and the
configured gateway. Without it a run with no traffic and no denials looks the same whether the
sandbox reached nothing or was allowed everything and stayed quiet. The summary projects the same
three as `allowed`, `routed`, and `enforcing`, since `reached` and `denied` are both backward-looking
and an agent planning its next turn needs to know what it may retry.

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

`--net` alone is observe-only: the tap records what crosses it, but no policy is armed. It is also
sealed unless you add [`--gateway`](#giving-the-guest-a-route-to-be-policed-on), so the guest reaches
nothing past the host end of its /30. To bound what may cross that tap, list each destination with a
repeatable `--allow`, which requires `--net`:

```console
# Allow one port on the host end; everything else is dropped at the tap and recorded.
ekvm run --net \
    --allow 10.200.0.1:9000/udp --record run.json -- ...
```

**What `--allow` does, and what it does not.** It populates the policy maps and attaches the
classifiers to the tap, so it decides which flows may cross. It does not create a path, and neither
does `--gateway`: the per-VM network namespace holds exactly two interfaces, `lo` and the tap, so
until something furnishes it the only address the guest can reach is the host end of its /30, no
matter what an allowance names. Where an uplink exists, `--allow` is what bounds what leaves through
it. Which half of that is whose is
[decision 9](./architecture-decisions.md#9-egress-is-enabled-by-the-engine-constructed-by-the-hoster):
the engine names a gateway and enforces at the tap, the hoster builds the uplink and allocates the
addresses it needs.

## Giving the guest a route to be policed on

Without `--gateway` the guest installs its connected /30 and nothing else, so a destination beyond
that is refused by the guest's own routing with `ENETUNREACH` before a packet is emitted. That is
the shipped default, and it means an off-link attempt never reaches the tap, so **nothing about it
appears in the record**.

```console
# A route, a resolver, and allowances for both things a fetch touches: the resolver, and the
# index itself. Each is named by address, because the tap policy matches addresses, not names.
ekvm run --net --gateway 10.200.0.1 --resolver 10.200.0.53 \
    --allow 10.200.0.53:53/udp \
    --allow 10.0.0.0/8:443/tcp \
    --record run.json -- pip install --index-url https://pypi.internal/simple somepkg
```

Note what that example does *not* do: reach a public index. A hostname behind a CDN resolves to
addresses that rotate, so it cannot be allow-listed here at all, and widening the rule until it
happens to match defeats the point. Fetching by name belongs in a proxy the hoster runs, which is
the same line [decision 9](./architecture-decisions.md#9-egress-is-enabled-by-the-engine-constructed-by-the-hoster)
draws for the uplink.

`--gateway` fills the field the kernel `ip=` parameter otherwise leaves empty. It names a path
rather than building one: the engine adds no veth, bridge, forwarding, or NAT, so on a host whose
per-VM netns nothing has furnished the reachable set is unchanged. What changes is that the guest
can now *emit* those packets, so the classifier judges them and a refusal lands in `denials`. The
observable set widens even where the reachable set does not.

`--resolver` rides the same parameter's DNS field; the guest image links `/etc/resolv.conf` to the
kernel's record of it. Reaching that resolver still needs an allowance like any other destination,
and the engine runs no resolver of its own. Both are host constants, so they are normally set once
in [configuration](./cli-config.md) rather than on every command line. IPv4 only: `--allow` parses
v4 addresses, so a v6 route would be one no policy you can write here could bound.

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
