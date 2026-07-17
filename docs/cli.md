# Using the agent CLI

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
| `--wall SECONDS` | Wall-clock budget (default 30, minimum 1): the boot deadline and the command's runtime budget alike. |
| `--output-cap BYTES` | Cap on captured stdout+stderr+artifacts (default 16 MiB). |
| `--json` | Emit the structured run result as one JSON object on stdout instead of relaying the raw streams. |
| `--net` | Boot with a NIC (a per-VM tap the host-side probes observe). Deny-by-default is unchanged: with no egress allowance the guest reaches nothing beyond the host end of its /30. |
| `--trace` | Attach the host-side probes and print the run's **audit trail** (human-readable) on stdout after the run. Conflicts with `--json` (machine consumers use `--record`). |
| `--record FILE` | Attach the probes and write the run's deterministic **audit record** (one line of byte-stable JSON) to `FILE` for later inspection. |
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
{"exit_code":0,"stdout":"HI\n", …, "metrics":{…}}
```

## `agent shell`

One sandbox held open as an interactive, stateful session: one `sh -c` exec per input line, every
line sharing the guest's working directory and (via the boot overlay) the wider filesystem — so a
file written on line 1, or a package installed on line 2, is there on line 3. Shell *process*
state (`cd`, variables) does not persist: each line is its own exec. The prompt and diagnostics go
to stderr, command output to stdout, so a piped script of lines stays clean. `--unjailed` works
the same as on `run`.

## Configuration

Configuration layers **flags > environment (`AGENT_*`) > defaults** (a `.agent.toml` file layer is
planned). The environment keys:

| Variable | What it points at | Default |
|----------|-------------------|---------|
| `AGENT_FIRECRACKER` | the `firecracker` binary | `firecracker` (PATH) |
| `AGENT_KERNEL` | the guest kernel image | `artifacts/vmlinux` |
| `AGENT_ROOTFS` | the guest rootfs image | `artifacts/rootfs.ext4` |
| `AGENT_MARKER` | the console line that means "userspace is up" (`AGENT-GUEST-READY` for the agent rootfs) | the boot image's login prompt |
| `AGENT_SCRATCH_DIR` | base dir for per-VM scratch (rootfs copies, chroots, sockets). `/tmp` is often tmpfs (host RAM) — point at real disk on small hosts | `/tmp` |
| `AGENT_LOG` | the stderr log filter (`tracing` syntax) | `warn` |
| `AGENT_PROBES_OBJECT` | the built eBPF object (for the probe demos) | the `cargo xtask build-probes` output path |

## Watching a run from the host

`agent run` carries the engine's convergence on flags: `--trace`, `--record`, and `--watch` bind
the host-side eBPF probes to the sandbox at launch and fuse what they saw into one per-run audit
record — observed from *outside* the guest, where the code can't forge or disable it.

```console
# Watch it live, read the trail after, keep the machine record:
agent run --unjailed --net --watch --trace --record run.json -- python3 -c '…'
```

Three surfaces, one record:

- **`--watch`** — the live view, drawn on stderr (stdout stays the run's result): the guest's
  network flows and egress denials as they happen, its CPU/memory/IO, the VMM's host-syscall
  footprint, and a running timeline. `q`/`Esc` closes the view; the run continues. When the
  command finishes the view stays up (so a fast run doesn't flash away) until you close it.
- **`--trace`** — the human-readable trail on stdout after the run: timing, per-flow traffic,
  denials, resources, notable host syscalls, and a `gap` line for any axis that couldn't bind.
- **`--record FILE`** — the machine surface: the record as one line of deterministic, byte-stable
  JSON (integer nanoseconds, no floats; addresses and protocols by name). This is the format
  downstream SDKs parse; the pretty trail makes no stability promise.

The probes need kernel BTF, `CAP_BPF`+`CAP_PERFMON` (+ `CAP_NET_ADMIN` for the tap), and the built
object (`cargo xtask build-probes`). Everything is **fail-open**: on a host without them the run
still works and the record's coverage section says exactly which axes are missing and why. The
syscall axis is the **VMM's host footprint** — a microVM services the guest's syscalls in-guest,
so their absence there is the isolation working, not a blind spot (the guest's *network* is
observed exactly, at the tap).

The per-axis eBPF demos (one probe at a time) live in
[Host-side observability & enforcement](./probes.md), under *Try it*.
