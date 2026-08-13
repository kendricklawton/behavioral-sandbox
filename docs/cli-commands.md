# Commands and options

The four verbs: [`bsx run`](#bsx-run) for one sandbox and one command, [`bsx shell`](#bsx-shell)
for a stateful session, [`bsx doctor`](#bsx-doctor) to check a host before the first sandbox, and
[`bsx verify`](#bsx-verify) to check a signed audit record. The daemon,
[`bsx serve`](./daemon.md), has its own chapter.

## `bsx run`

One sandbox, one command, everything as flags:

```console
bsx run [FLAGS] -- <cmd> [args…]
```

| Flag | What it does |
|------|--------------|
| `--demo-boot` | Just boot a microVM and read its console, no command. |
| `--unjailed` | Run the VMM without the jailer. Default is confined. |
| `--require-limits` | Refuse the boot if the cpu/memory cgroup caps can't be applied, instead of the default warn-and-boot-uncapped. Makes the resource envelope load-bearing; needs the jailer (so not with `--unjailed`) and delegated cgroup v2 controllers. Also [`require_limits`](./cli-config.md#setting-require_limits). |
| `--jail-uid UID` | The uid the jailer drops the VMM to (default 10000). An operator setting rather than a caller's, since sandboxes sharing an id can signal each other's VMMs. Zero is refused by name. Also [`jail_uid`](./cli-config.md#setting-jail_uid-and-jail_gid) / `BSX_JAIL_UID`. |
| `--jail-gid GID` | The gid the jailer drops the VMM to (default 10000), on the same terms as `--jail-uid`. |
| `--env KEY=VALUE` | Set an environment variable on the guest command (repeatable). Values are treated as secrets: the code paths that log or render a run omit them. |
| `--put FILE` | Inject a host file into the run's working directory (repeatable; guest name = basename). |
| `--get PATH` | Fetch a file from the run's working directory afterwards (repeatable; written under the current directory at the same relative path). Deny-by-default: only what you asked for is written. |
| `--vcpus N` | Guest vCPUs (default 1). Firecracker's `vcpu_count` domain: **1 or an even number, up to 32**. Zero, an odd count above 1, or an over-cap value is a typed error at parse, never a silent clamp. |
| `--mem MIB` | Guest memory in MiB (default 256). A whole number of at least 1; zero is a typed error. |
| `--wall SECONDS` | Wall-clock budget (default 30, minimum 1): the boot deadline and the command's runtime budget alike. |
| `--output-cap BYTES` | Cap on captured stdout+stderr+artifacts (default 16 MiB). |
| `--json` | Emit the structured run result as one JSON object on stdout (exit code, streams, artifacts, metrics, and the effective `limits`) instead of relaying the raw streams. |
| `--net` | Boot with a NIC (a per-VM tap the host-side probes observe). Deny-by-default is unchanged: with no egress allowance the guest reaches nothing beyond the host ends of its own [dual-stack link](./architecture-host.md#networking). |
| `--allow IP[/CIDR][:PORT][/PROTO]` | Bound what may cross the deny-by-default tap (repeatable), e.g. `10.200.0.1:9000/udp`, `10.0.0.0/8:443/tcp`. Constrains traffic rather than creating a path: without an operator-provided uplink the reachable set is the host end of the /30. Requires `--net`; semantics in [Enforcing egress](./cli-observe.md#enforcing-egress-with---allow). |
| `--gateway IP` | Give the guest a default route via this address, which must be the host end of its /30 (the only other address on the link). An off-link value is refused up front, since the guest could not ARP it and would come up sealed. Names a path rather than creating one: the engine builds no uplink, so where nothing has furnished the netns the reachable set is unchanged. What it changes is that the attempt now crosses the tap, so `--allow` can bound it and the record can show it. Requires `--net`; see [decision 9](./architecture-decisions.md#9-egress-is-enabled-by-the-engine-constructed-by-the-hoster). |
| `--resolver IP` | Tell the guest to resolve names at this address. Reaching it needs an allowance like any other destination, and the engine runs no resolver. Requires `--gateway`. |
| `--trace` | Attach the host-side probes and print the run's **audit trail** (human-readable) on stdout after the run. Conflicts with `--json` (machine consumers use `--record`). |
| `--record FILE` | Attach the probes and write the run's deterministic **audit record** to `FILE`, signed with the host key in a schema-2 envelope, so alteration is detectable; check it with [`bsx verify`](#bsx-verify). |
| `--record-summary FILE` | Attach the probes and write the run's **model-legible summary** to `FILE`: a compact projection of the audit record shaped for an agent's observe-then-act loop. |
| `--watch` | Watch the run **live**: a full-screen view on stderr. Needs stderr on a terminal; `q` closes the view and the run continues. |
| `--log FILTER` | Log filter for stderr (overrides [`log`](./cli-config.md#setting-log)), e.g. `info`, `debug`. |

Piped stdin is forwarded to the guest command. Bulk data belongs on the block-device paths instead
(`input_dir`/`output_dir` in the [engine API](./embedding.md)), since the exec request is a single
bounded frame.

The four observability flags are covered in [Observing a run](./cli-observe.md).

### Streams and exit codes

Logs go to **stderr**; the run's output (raw relay, or the `--json` result object) goes to **stdout**,
so `bsx run … 2>/dev/null` stays pipe-clean and `--json | jq` just works.

The guest command's exit code becomes `bsx run`'s own: a crash *inside* the sandbox is a result, not
an error, and death by signal comes back as `128 + signal`. Exit code **2** is reserved for an
operational failure of the engine itself (no KVM, a missing artifact, a boot timeout, a broken
channel).

```console
$ echo 'hi' | bsx run --json -- python3 -c 'import sys; print(sys.stdin.read().upper())' 2>/dev/null
{"schema":1,"exit_code":0,"stdout":"HI\n", …, "metrics":{…},"limits":{…}}
```

## `bsx shell`

One sandbox held open as an interactive, stateful session: one `sh -c` exec per input line, every line
sharing the guest's working directory and (via the boot overlay) the wider filesystem, so a file
written on line 1, or a package installed on line 2, is there on line 3.

Shell *process* state (`cd`, variables) does not persist: each line is its own exec. The prompt and
diagnostics go to stderr and command output to stdout, so a piped script of lines stays clean.
`--unjailed`, `--vcpus`, `--mem`, `--require-limits`, and `--jail-uid` / `--jail-gid` work the same
as on [`run`](#bsx-run).

`bsx shell` cannot record, so a host that sets
[`require_record`](./cli-config.md#setting-require_record) refuses it.

## `bsx doctor`

Check this host's readiness *before* the first sandbox. `bsx doctor` prints one line per
prerequisite: the architecture (`x86_64`), KVM, the jailer and real root, `firecracker` plus its
pinned sha256, iproute2 and e2fsprogs, a scratch dir that is not `nodev`/`noexec`, cgroup
delegation, the kernel's `cgroup.kill` capability, the boot artifacts, the eBPF
capabilities, the mandatory-access-control posture, and the host-hardening advisories (SMT, KSM, CPU
vulnerability mitigations, which matter for a multi-tenant host).

Each row is marked one of three ways:

- **`ok`**, the prerequisite is satisfied.
- **`warn`**, a fail-open degradation or an advisory, with the consequence named on the row.
- **`FAIL`**, a hard miss: no boot without it.

It exits non-zero when a hard prerequisite is missing, so `bsx doctor && bsx run …` gates cleanly. A
footer tallies the rows.

```console
bsx doctor              # the report
bsx doctor --explain    # plus the full fails-open-vs-hard-error matrix
bsx doctor --json       # machine-readable (schema 1), for a host report you can send on
```

`--explain` keeps the matrix off the default report so the rows stay scannable; each non-`ok` row
already names its own fix. `cargo xtask setup` renders the same checks for a dev box, plus the
build-toolchain rows.

The checks are **capability probes first, never distro tests**: `cgroup.kill` rather than a kernel
version, `/sys/kernel/security/lsm` rather than a distro name. A version compare survives in
exactly two places, as fallback and as pin: the kernel row falls back to a `>= 5.15` floor only
where there is no cgroup v2 hierarchy to probe, and the Firecracker row checks the supported
release range. The rationale is
[design decision 8](./architecture-decisions.md#8-portability-is-a-capability-question-not-a-distro-question).

## `bsx verify`

`bsx run --record` and the daemon's `trace` reply sign the finalized record with a **host key**
that never crosses into the guest (the key loads in the host process; only the detached `ed25519`
signature over the canonical record bytes reaches the file), so a consumer can
detect any alteration made *after* the producing host. The record file is a schema-2 envelope,
`{schema, key_id, signature, record}`, with the record carried inside as a string.

`bsx verify <record>` re-reads the canonical bytes and checks the signature, exiting non-zero on any
mismatch. The input is treated as untrusted (that is the point of verifying) and is bounded: a single
envelope is bounded at 16 MiB, and a record file (which may hold a session chain of multiple envelopes)
is bounded at 256 MiB, rejected up front if exceeded.

The file's shape picks the check. One line is a single envelope. Several lines, one envelope per
line in order (the shape a daemon client saves its `trace` replies in), verify as a **session
chain**: signatures plus each record's commitment to its predecessor's hash, so a reordered,
inserted, or dropped record fails even though every envelope alone carries a valid signature.
`a_chain_file_verifies_and_a_reordered_or_tampered_one_fails` pins both directions.

A chain is verified **from its anchor**: the first line must be the session's unchained first
record. That is what makes a dropped *head* detectable, and it is also why a mid-session slice (a
rotated log, the last N replies kept) cannot be checked as a chain, only envelope by envelope, which
keeps each record's authenticity and loses the ordering property. Dropping the *tail* stays
undetectable either way without an external anchor.

```console
bsx verify run.json                      # trusts this host's own signing key
bsx verify --key <64-hex> run.json       # trust a public key handed over out of band (repeatable)
bsx verify session.jsonl                 # several lines: the session chain, order and all
```

The trust root is the host signing key. This detects post-hoc alteration; it does **not** prove a
*compromised* producing host didn't sign a lie. Key custody and rotation are the hoster's: the key
path resolves from [`signing_key`](./cli-config.md#setting-signing_key), generated on first use, and a
record's `key_id` names the key that signed it.

**Key rotation.** `bsx verify` trusts a *set* of keys, so rotating the host key doesn't invalidate
records already signed. Keep the retired public keys (their `key_id`s) listed in
[`trusted_keys`](./cli-config.md#setting-trusted_keys), and `bsx verify` trusts that set together
with the current signing key and any `--key` given, so old and new records both verify.

**Session hash-chain.** A one-shot `bsx run --record` writes a single, unchained record. Within a
**session** (the [daemon](./daemon.md)'s `trace` verb), each record additionally commits to the
previous one's hash (a `prev` field), so the *sequence* is tamper-evident as a whole: a client that
saves the records one per line can hand the file to `bsx verify` (or call the library's
`verify_chain`) and detect a reordered, inserted, or deleted one, not just a single-record edit.
Truncating the tail of a chain is not detectable without an external
anchor, which is the append-only limitation.
