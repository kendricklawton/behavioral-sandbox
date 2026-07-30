# Commands and options

{{#include ./status.md:banner}}

The four verbs: [`ekvm run`](#ekvm-run) for one sandbox and one command, [`ekvm shell`](#ekvm-shell)
for a stateful session, [`ekvm doctor`](#ekvm-doctor) to check a host before the first sandbox, and
[`ekvm verify`](#ekvm-verify) to check a signed audit record. The daemon,
[`ekvm serve`](./daemon.md), has its own chapter.

## `ekvm run`

One sandbox, one command, everything as flags:

```console
ekvm run [FLAGS] -- <cmd> [args…]
```

| Flag | What it does |
|------|--------------|
| `--demo-boot` | Just boot a microVM and read its console, no command. |
| `--unjailed` | Run the VMM without the jailer. Default is confined. |
| `--require-limits` | Refuse the boot if the cpu/memory cgroup caps can't be applied, instead of the default warn-and-boot-uncapped. Makes the resource envelope load-bearing; needs the jailer (so not with `--unjailed`) and delegated cgroup v2 controllers. Also [`require_limits`](./cli-config.md#setting-require_limits). |
| `--env KEY=VALUE` | Set an environment variable on the guest command (repeatable). Values are treated as secrets: the code paths that log or render a run omit them. |
| `--put FILE` | Inject a host file into the run's working directory (repeatable; guest name = basename). |
| `--get PATH` | Fetch a file from the run's working directory afterwards (repeatable; written under the current directory at the same relative path). Deny-by-default: only what you asked for is written. |
| `--vcpus N` | Guest vCPUs (default 1). Firecracker's `vcpu_count` domain: **1 or an even number, up to 32**. Zero, an odd count above 1, or an over-cap value is a typed error at parse, never a silent clamp. |
| `--mem MIB` | Guest memory in MiB (default 256). A whole number of at least 1; zero is a typed error. |
| `--wall SECONDS` | Wall-clock budget (default 30, minimum 1): the boot deadline and the command's runtime budget alike. |
| `--output-cap BYTES` | Cap on captured stdout+stderr+artifacts (default 16 MiB). |
| `--json` | Emit the structured run result as one JSON object on stdout (exit code, streams, artifacts, metrics, and the effective `limits`) instead of relaying the raw streams. |
| `--net` | Boot with a NIC (a per-VM tap the host-side probes observe). Deny-by-default is unchanged: with no egress allowance the guest reaches nothing beyond the host end of its /30. |
| `--allow IP[/CIDR][:PORT][/PROTO]` | Allow one egress destination past the deny-by-default tap (repeatable), e.g. `1.1.1.1`, `10.0.0.0/8`, `1.1.1.1:443/tcp`. Requires `--net`; semantics in [Enforcing egress](./cli-observe.md#enforcing-egress-with---allow). |
| `--trace` | Attach the host-side probes and print the run's **audit trail** (human-readable) on stdout after the run. Conflicts with `--json` (machine consumers use `--record`). |
| `--record FILE` | Attach the probes and write the run's deterministic **audit record** to `FILE`, signed with the host key in a schema-2 envelope, so alteration is detectable; check it with [`ekvm verify`](#ekvm-verify). |
| `--record-summary FILE` | Attach the probes and write the run's **model-legible summary** to `FILE`: a compact projection of the audit record shaped for an agent's observe-then-act loop. |
| `--watch` | Watch the run **live**: a full-screen view on stderr. Needs stderr on a terminal; `q` closes the view and the run continues. |
| `--log FILTER` | Log filter for stderr (overrides [`log`](./cli-config.md#setting-log)), e.g. `info`, `debug`. |

Piped stdin is forwarded to the guest command. Bulk data belongs on the block-device paths instead
(`input_dir`/`output_dir` in the [engine API](./embedding.md)), since the exec request is a single
bounded frame.

The four observability flags are covered in [Observing a run](./cli-observe.md).

### Streams and exit codes

Logs go to **stderr**; the run's output (raw relay, or the `--json` result object) goes to **stdout**,
so `ekvm run … 2>/dev/null` stays pipe-clean and `--json | jq` just works.

The guest command's exit code becomes `ekvm run`'s own: a crash *inside* the sandbox is a result, not
an error, and death by signal comes back as `128 + signal`. Exit code **2** is reserved for an
operational failure of the engine itself (no KVM, a missing artifact, a boot timeout, a broken
channel).

```console
$ echo 'hi' | ekvm run --json -- python3 -c 'import sys; print(sys.stdin.read().upper())' 2>/dev/null
{"schema":1,"exit_code":0,"stdout":"HI\n", …, "metrics":{…},"limits":{…}}
```

## `ekvm shell`

One sandbox held open as an interactive, stateful session: one `sh -c` exec per input line, every line
sharing the guest's working directory and (via the boot overlay) the wider filesystem, so a file
written on line 1, or a package installed on line 2, is there on line 3.

Shell *process* state (`cd`, variables) does not persist: each line is its own exec. The prompt and
diagnostics go to stderr and command output to stdout, so a piped script of lines stays clean.
`--unjailed`, `--vcpus`, and `--mem` work the same as on [`run`](#ekvm-run).

`ekvm shell` cannot record, so a host that sets
[`require_record`](./cli-config.md#setting-require_record) refuses it.

## `ekvm doctor`

Check this host's readiness *before* the first sandbox. `ekvm doctor` prints one line per
prerequisite: KVM, the jailer and real root, `firecracker` plus its pinned sha256, iproute2 and
e2fsprogs, cgroup delegation, the kernel's `cgroup.kill` capability, the boot artifacts, the eBPF
capabilities, the mandatory-access-control posture, and the host-hardening advisories (SMT, KSM, CPU
vulnerability mitigations, which matter for a multi-tenant host).

Each row is marked one of three ways:

- **`ok`**, the prerequisite is satisfied.
- **`warn`**, a fail-open degradation or an advisory, with the consequence named on the row.
- **`FAIL`**, a hard miss: no boot without it.

It exits non-zero when a hard prerequisite is missing, so `ekvm doctor && ekvm run …` gates cleanly. A
footer tallies the rows.

```console
ekvm doctor              # the report
ekvm doctor --explain    # plus the full fails-open-vs-hard-error matrix
ekvm doctor --json       # machine-readable (schema 1), for a host report you can send on
```

`--explain` keeps the matrix off the default report so the rows stay scannable; each non-`ok` row
already names its own fix. `cargo xtask setup` renders the same checks for a dev box, plus the
build-toolchain rows.

Every check is a **capability probe**, never a distro or version test: `cgroup.kill` rather than a
kernel version, `/sys/kernel/security/lsm` rather than a distro name. The rationale is
[design decision 8](./design.md).

## `ekvm verify`

`ekvm run --record` and the daemon's `trace` reply sign the finalized record with a **host key** the
guest never sees (an `ed25519` detached signature over the canonical record bytes), so a consumer can
detect any alteration made *after* the producing host. The record file is a schema-2 envelope,
`{schema, key_id, signature, record}`, with the record carried inside as a string.

`ekvm verify <record>` re-reads the canonical bytes and checks the signature, exiting non-zero on any
mismatch. The input is treated as untrusted (that is the point of verifying) and is bounded: a file
over 16 MiB is rejected as "not a signed record" without being read in, since a real envelope is
kilobytes.

```console
ekvm verify run.json                      # trusts this host's own signing key
ekvm verify --key <64-hex> run.json       # trust a public key handed over out of band (repeatable)
```

The trust root is the host signing key. This detects post-hoc alteration; it does **not** prove a
*compromised* producing host didn't sign a lie. Key custody and rotation are the hoster's: the key
path resolves from [`signing_key`](./cli-config.md#setting-signing_key), generated on first use, and a
record's `key_id` names the key that signed it.

**Key rotation.** `ekvm verify` trusts a *set* of keys, so rotating the host key doesn't invalidate
records already signed. Keep the retired public keys (their `key_id`s) listed in
[`trusted_keys`](./cli-config.md#setting-trusted_keys), and `ekvm verify` trusts that set together
with the current signing key and any `--key` given, so old and new records both verify.

**Session hash-chain.** A one-shot `ekvm run --record` writes a single, unchained record. Within a
**session** (the [daemon](./daemon.md)'s `trace` verb), each record additionally commits to the
previous one's hash (a `prev` field), so the *sequence* is tamper-evident as a whole: a client that
collects the records can detect a reordered, inserted, or deleted one, not just a single-record edit
(via the library `verify_chain`). Truncating the tail of a chain is not detectable without an external
anchor, which is the append-only limitation.
