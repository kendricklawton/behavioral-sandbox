# Using the `agent` CLI

`agent` is the reference embedder of the engine: the whole sandbox lifecycle — open (confined by
default), exec with inputs, collect artifacts, close — in one command. If you haven't set up the
host and built the guest artifacts yet, do [Installation](./cli-install.md) first.

## Quick start

```console
# Prove the boundary: boot a microVM to userspace and read its console.
cargo run -p agent-cli -- run --demo-boot

# Run code inside one. The agent rootfs (built by `cargo xtask build-rootfs`) carries
# python3 and the in-guest exec agent:
export AGENT_ROOTFS=artifacts/rootfs-agent.ext4
export AGENT_MARKER=AGENT-GUEST-READY
cargo run -p agent-cli -- run -- python3 -c 'print(2 + 2)'
```

`agent run` is **jailed by default** — the VMM runs under Firecracker's jailer (chroot, uid/gid
drop, seccomp, its own namespaces, a cgroup), which needs real root and the `jailer` binary. On a
dev box without them, `--unjailed` is the explicit, greppable opt-out: the guest still sits behind
the KVM hardware boundary, only the VMM process itself runs unconfined.

## `agent run`

One sandbox, one command, everything as flags:

```console
agent run [FLAGS] -- <cmd> [args…]
```

| Flag | What it does |
|------|--------------|
| `--demo-boot` | Just boot a microVM and read its console — no command. |
| `--unjailed` | Run the VMM without the jailer (see above). Default is confined. |
| `--env KEY=VALUE` | Set an environment variable on the guest command (repeatable). Values are treated as secrets: the engine never logs them. |
| `--put FILE` | Inject a host file into the run's working directory (repeatable; guest name = basename). |
| `--get PATH` | Fetch a file from the run's working directory afterwards (repeatable; written under the current directory at the same relative path). Deny-by-default: only what you asked for is written. |
| `--vcpus N` | Guest vCPUs (default 1). A whole number in 1..=32; zero or over-cap is a typed error, never a silent clamp (Firecracker v1.9 caps a microVM at 32). |
| `--mem MIB` | Guest memory in MiB (default 256). A whole number of at least 1; zero is a typed error. |
| `--wall SECONDS` | Wall-clock budget (default 30, minimum 1): the boot deadline and the command's runtime budget alike. |
| `--output-cap BYTES` | Cap on captured stdout+stderr+artifacts (default 16 MiB). |
| `--json` | Emit the structured run result as one JSON object on stdout (exit code, streams, artifacts, metrics, and the effective `limits`) instead of relaying the raw streams. |
| `--net` | Boot with a NIC (a per-VM tap the host-side probes observe). Deny-by-default is unchanged: with no egress allowance the guest reaches nothing beyond the host end of its /30. |
| `--allow IP[/CIDR][:PORT][/PROTO]` | Allow one egress destination past the deny-by-default tap (repeatable) — e.g. `1.1.1.1`, `10.0.0.0/8`, `1.1.1.1:443/tcp`. Requires `--net`; builds the run's egress policy, armed before the tap goes live. A host that can't enforce (missing eBPF caps) is a typed refusal, never a silent unenforced run. |
| `--trace` | Attach the host-side probes and print the run's **audit trail** (human-readable) on stdout after the run. Conflicts with `--json` (machine consumers use `--record`). |
| `--record FILE` | Attach the probes and write the run's deterministic **audit record** (one line of byte-stable JSON) to `FILE` for later inspection. |
| `--record-summary FILE` | Attach the probes and write the run's **model-legible summary** to `FILE`: a compact projection of the audit record (what it reached, what egress was denied, its resource envelope, any coverage gap) shaped for an agent's observe→act loop. |
| `--watch` | Watch the run **live**: a full-screen view on stderr (flows and denials, resources, the VMM's host syscalls, a timeline). Needs stderr on a terminal; `q` closes the view, the run continues (after the command finishes, the view stays up until closed). |
| `--log FILTER` | Log filter for stderr (overrides `AGENT_LOG`), e.g. `info`, `debug`. |

Piped stdin is forwarded to the guest command. Bulk data belongs on the block-device paths
instead (`input_dir`/`output_dir` in the [engine API](./embedding.md)) — the exec request is a
single bounded frame.

### Streams and exit codes

Logs go to **stderr**; the run's output (raw relay, or the `--json` result object) goes to
**stdout** — so `agent run … 2>/dev/null` stays pipe-clean and `--json | jq` just works. The
guest command's exit code becomes `agent run`'s own (a crash *inside* the sandbox is a result,
not an error — death by signal comes back as `128 + signal`); exit code **2** is reserved for an
operational failure of the engine itself (no KVM, a missing artifact, a boot timeout, a broken
channel).

```console
$ echo 'hi' | agent run --json -- python3 -c 'import sys; print(sys.stdin.read().upper())' 2>/dev/null
{"schema":1,"exit_code":0,"stdout":"HI\n", …, "metrics":{…},"limits":{…}}
```

## `agent shell`

One sandbox held open as an interactive, stateful session: one `sh -c` exec per input line, every
line sharing the guest's working directory and (via the boot overlay) the wider filesystem — so a
file written on line 1, or a package installed on line 2, is there on line 3. Shell *process*
state (`cd`, variables) does not persist: each line is its own exec. The prompt and diagnostics go
to stderr, command output to stdout, so a piped script of lines stays clean. `--unjailed`, `--vcpus`,
and `--mem` work the same as on `run`.

## `agent doctor`

Check this host's readiness *before* the first sandbox: `agent doctor` prints one line per
prerequisite — KVM, the jailer + real-root, `firecracker` v1.9, iproute2/e2fsprogs, cgroup
delegation, the kernel version, the boot artifacts, and the eBPF capabilities — each marked `ok`,
`warn` (a fail-open degradation, with the consequence named), or `FAIL` (a hard miss: no boot
without it). It exits non-zero when a hard prerequisite is missing, so `agent doctor && agent run …`
gates cleanly. A footer restates the fails-open-vs-hard split. (`cargo xtask setup` renders the same
checks for a dev box, plus the build-toolchain rows.)

## Configuration

Configuration layers **flags > environment (`AGENT_*`) > file (`.agent.toml`) > defaults** — one
value, four sources, highest wins. The **file** layer is the nearest `.agent.toml` walking up from
the current directory (the `.gitignore` convention), so a project pins its engine config beside its
code; its keys mirror the environment names 1:1 (minus the `AGENT_` prefix, lowercased), and an
unknown key is a typed error, never a silent no-op.

| Variable | `.agent.toml` key | What it points at | Default |
|----------|-------------------|-------------------|---------|
| `AGENT_FIRECRACKER` | `firecracker` | the `firecracker` binary | `firecracker` (PATH) |
| `AGENT_KERNEL` | `kernel` | the guest kernel image | `artifacts/vmlinux` |
| `AGENT_ROOTFS` | `rootfs` | the guest rootfs image | `artifacts/rootfs.ext4` |
| `AGENT_MARKER` | `marker` | the console line that means "userspace is up" (`AGENT-GUEST-READY` for the agent rootfs) | the boot image's login prompt |
| `AGENT_SCRATCH_DIR` | `scratch_dir` | base dir for per-VM scratch (rootfs copies, chroots, sockets). `/tmp` is often tmpfs (host RAM) — point at real disk on small hosts | `/tmp` |
| `AGENT_LOG` | `log` | the stderr log filter (`tracing` syntax) | `warn` |
| `AGENT_PROBES_OBJECT` | — | the built eBPF object (for the probe demos) | the `cargo xtask build-probes` output path |

```toml
# .agent.toml — pinned beside a project's code
kernel = "/srv/agent/vmlinux"
rootfs = "/srv/agent/rootfs-agent.ext4"
marker = "AGENT-GUEST-READY"
log = "info"
```

## Watching a run from the host

`agent run` carries the engine's convergence on flags: `--trace`, `--record`, and `--watch` bind
the host-side eBPF probes to the sandbox at launch and fuse what they saw into one per-run audit
record — observed from *outside* the guest, where the code can't forge or disable it.

```console
# Watch it live, read the trail after, keep the machine record + the agent-legible summary:
agent run --unjailed --net --watch --trace --record run.json --record-summary run.sum.json -- python3 -c '…'
```

Four faces, one record:

- **`--watch`** — the live view, drawn on stderr (stdout stays the run's result): the guest's
  network flows and egress denials as they happen, its CPU/memory/IO, the VMM's host-syscall
  footprint, and a running timeline. `q`/`Esc` closes the view; the run continues. When the
  command finishes the view stays up (so a fast run doesn't flash away) until you close it.
- **`--trace`** — the human-readable trail on stdout after the run: timing, per-flow traffic,
  denials, resources, notable host syscalls, and a `gap` line for any axis that couldn't bind.
- **`--record FILE`** — the machine surface: the record as one line of deterministic, byte-stable
  JSON (integer nanoseconds, no floats; addresses and protocols by name). This is the format
  downstream SDKs parse; the pretty trail makes no stability promise.
- **`--record-summary FILE`** — the **model-legible** face: a compact projection of the same record
  for an agent's observe→act loop — what it *reached* (distinct destinations, flows collapsed to
  their endpoint), what egress was *denied*, its resource envelope, and any coverage gap, with the
  forensic detail (per-flow counters, per-syscall `comm`/hits) dropped. A *view* of the record, not
  new observation: measurably compact (well under half the full record on a busy run), deterministic,
  and byte-stable, so an agent gets a small, stable summary to feed back into its next turn.

Each machine JSON surface carries a leading integer **`schema`** field — the `--json` run result, the
`--record` audit record, and the `--record-summary` projection version **independently**, each
starting at `1`. The compatibility policy:
**within a version, changes are additive only** — a new field a consumer can ignore; **renaming or
removing a field, or changing a value's meaning, bumps the version.** A parser keys on `schema` to
know which shape it is reading. This is versioned *before* anything external parses it, so the wire
API and the language SDKs harden a stable contract, not a moving one.

The probes need kernel BTF, `CAP_BPF`+`CAP_PERFMON` (+ `CAP_NET_ADMIN` for the tap), and the built
object (`cargo xtask build-probes`). Everything is **fail-open**: on a host without them the run
still works and the record's coverage section says exactly which axes are missing and why. The
syscall axis is the **VMM's host footprint** — a microVM services the guest's syscalls in-guest,
so their absence there is the isolation working, not a blind spot (the guest's *network* is
observed exactly, at the tap).

### Enforcing egress with `--allow`

`--net` alone is observe-only: the guest reaches nothing past the host end of its /30 (the driver's
deny-by-default routing), and the tap records what crosses it. To *permit* specific egress, list each
destination with a repeatable `--allow` (which requires `--net`):

```console
# Allow DNS to one resolver and HTTPS to a subnet; everything else is dropped at the tap and recorded.
agent run --unjailed --net \
    --allow 1.1.1.1:53/udp --allow 10.0.0.0/8:443/tcp --record run.json -- ...
```

Each `--allow` is `IP[/CIDR][:PORT][/PROTO]` (a bare `IP` is a single-host `/32`, any port, any
protocol). The allowances build a deny-by-default egress policy that is **armed before the tap goes
live**, so there is no window in which the guest's first packet slips past unpoliced. Every allowance
is explicit on the command line, and what the policy dropped lands in the record's `denials`.

Enforcement is a security control, so it does **not** fail open: `--allow` on a host that can't load
the probes (or can't get `CAP_NET_ADMIN` to police the tap) is a typed refusal, never a run that
quietly ignores the policy. `--allow` without `--net` is refused at the command line.

## Every engine capability, and where it lives

The CLI is the engine's **reference embedder**: every library capability is reachable here through a
few orthogonal verbs, or named below as deliberately out of scope. The map:

| Engine capability | CLI surface |
|-------------------|-------------|
| Boot + one exec | `agent run -- <cmd>` |
| Stateful session | `agent shell` |
| Confinement (jail) | jailed by default; `--unjailed` opts out |
| Resource limits (`Limits`) | `--vcpus`, `--mem`, `--wall`, `--output-cap` |
| Per-exec inputs | `--env`, `--put`, piped stdin |
| Artifact retrieval | `--get` (deny-by-default) |
| Networking (NIC) | `--net` |
| Egress policy (`EgressPolicy`) | `--allow IP[/CIDR][:PORT][/PROTO]` |
| Host-observed audit record | `--trace` (human), `--record FILE` (JSON), `--record-summary FILE` (model-legible), `--watch` (live) |
| Structured run result | `--json` |
| Host readiness | `agent doctor` |
| Config layering | flags > env (`AGENT_*`) > `.agent.toml` > defaults |

**Deliberately not in the CLI — daemon-scoped, embedding-API, or platform, by design** (their absence
is intent, not omission):

- **Snapshots + the pre-warmed pool** — a pre-warmed pool is a long-lived-process concern; it lives
  in the [`agentd` daemon](./daemon.md) (`--prewarm`), not a one-shot CLI.
- **The wire API** — the programmatic driver surface is the
  [daemon's](./daemon.md#the-wire-protocol-versioned-json-schema-1), not a subcommand.
- **Bulk block-device I/O** (`BootConfig::input_dir`/`output_dir` — whole directories / large files
  as ext4 devices) and **out-of-band control** (`KillHandle` — force-kill a blocked exec from another
  thread) are *embedding-API* capabilities. The CLI's file path is per-frame `--put`/`--get` (small,
  bounded files); a caller needing bulk transfer or async cancellation drives the library directly.
  A one-shot CLI cancels by process signal (Ctrl-C → the sandbox's `Drop` tears the VM down).
- **Tenancy, auth, billing, fleet scheduling, a dashboard, image/registry management** — these are
  the *hoster's* platform, above the engine (guardrail 4); they never land in this repo.

The per-axis eBPF demos (one probe at a time) live in
[Host-side observability & enforcement](./probes.md), under *Try it*.
