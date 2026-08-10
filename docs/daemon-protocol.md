# The daemon wire protocol

Newline-delimited JSON: the client sends one request object per line, the daemon answers with
response lines. **Every message carries a leading `schema` field**; a peer that sends a different
number gets a fatal, session-ending error before its body is trusted.

Line-delimited JSON (not the length-prefixed binary framing of the host↔guest channel), and not gRPC,
because the peer is a **local, trusted-ish client**: the daemon is synchronous with no async runtime
(a recorded decision with its own re-open conditions, see
[the design notes](./architecture-decisions.md#7-synchronous-engine-no-async-runtime)),
and hand-debuggability (`socat`, `nc`) plus "any language with a JSON library and a unix socket can
drive it" matter more than a compact wire. Every decode is bounded and typed, so a
malformed or oversize line is a reported error or a drop rather than a parse the daemon acts on.

One connection is one sandbox **session**: the VM *is* the session, so repeated verbs share one
working directory, and closing the connection tears the sandbox down.

The shared wire contract lives in the `bsx-protocol` crate (serde-only, no `bsx`), so the
daemon, the [reference client](./daemon.md#the-reference-client), and anything else written
against it all speak exactly the same shapes.

## Requests

| Request | Meaning |
|---|---|
| `{"schema":1,"op":"open","vcpus":2,"mem_mib":512,"wall_secs":60,"output_cap":16777216}` | Boot the session's sandbox (all knobs optional; omitted keeps the conservative default). **First message.** A knobbed `open` is never served from the pool. |
| `{"schema":1,"op":"open","net":true,"allow":["1.1.1.1:443/tcp"]}` | The same, with a NIC and an egress allow-list armed on its tap. `allow` requires `net`; both default to no NIC. `net` without `allow` is **deny-all**, not observe-only: a wire client never gets an unpoliced tap. The daemon refuses the session outright if the tap could not be policed. Whether a route out exists is the daemon's posture, not the client's ([decision 9](./architecture-decisions.md#9-egress-is-enabled-by-the-engine-constructed-by-the-hoster)). Never served from the pool. |
| `{"schema":1,"op":"exec","argv":["echo","hi"],"stdin":"text\n","env":[["K","V"]]}` | Run a command, feeding `stdin` (UTF-8 text). Optional `env` pairs set the spawned command's environment only; the values are secrets by contract, rendered as key-plus-count by the wire type's redacting `Debug`. |
| `{"schema":1,"op":"put","path":"in.txt","content":"data\n"}` | Write a UTF-8 file into the working directory, for a later `exec`/`get`. |
| `{"schema":1,"op":"get","path":"out.txt"}` | Read a working-directory file back. A missing file is `present:false`, not an error. |
| `{"schema":1,"op":"snapshot"}` | Snapshot the session VM into a daemon-host bundle. Three postures are typed refusals, deliberately (not gaps): a **jailed** session (its disk lives at a chroot-relative path torn down with the VM, so a bundle would record an unrestorable backing), an **already-restored** VM (which is what every pooled clone is), and a VM carrying an input/output block device. Snapshot an unjailed, cold-booted source and restore jailed clones. |
| `{"schema":1,"op":"trace"}` | Return the host-observed audit record (`RunRecord`) so far, as a JSON object. Sampled **live** (repeatable mid-session): its coverage reflects attach time, and an absent axis may be a transient read, not a finalized gap (unlike the CLI's `--record`). |
| `{"schema":1,"op":"trace_summary"}` | Return the **model-legible summary** so far, the compact projection the CLI's `--record-summary` writes (what it reached, what egress was denied, its resource envelope, any coverage gap), sampled live like `trace`. The face an agent reads between turns. |
| `{"schema":1,"op":"cancel"}` | Abandon an **in-flight** request and end the session, answered `cancelled`. The one verb legal while another request is outstanding: it exists because a client blocked on a long `exec` has no other way to reach the daemon. **It ends the session, it does not abort one command**: the engine cancels a running exec by killing the sandbox, so session state dies with it (snapshot first if it matters). Hanging up lands in the same place: the daemon polls the connection during an in-flight request and treats EOF like a `cancel`, killing the sandbox within one poll tick. What `cancel` adds is the acknowledgement. |
| `{"schema":1,"op":"close"}` | End the session and tear the sandbox down (a hung-up connection does the same). |

`put`/`get` carry **UTF-8 text**; bulk or binary I/O is the block-device path
(`BootConfig::input_dir`/`output_dir`), not this per-message line.

## Responses

| Response | Meaning |
|---|---|
| `{"schema":1,"reply":"opened","boot_ms":118,"pooled":false}` | The sandbox booted; `pooled` says whether it came from the pre-warmed pool. |
| `{"schema":1,"reply":"result","exit_code":0,"stdout":"hi\n","stderr":"","exec_wall_ms":7}` | A command finished (`stdout`/`stderr` lossy UTF-8, like `bsx run --json`; a non-zero `exit_code` is a *result*, not an error). |
| `{"schema":1,"reply":"put","path":"in.txt"}` | A `put` landed. |
| `{"schema":1,"reply":"got","path":"out.txt","content":"data\n","present":true,"lossy":false}` | A `get`'s contents (`present:false` + empty `content` when the file is absent). `content` is lossy UTF-8; `lossy:true` flags that the file's bytes were not valid UTF-8, so replacement characters stand in and the original bytes are not recoverable from this reply. Absent (an omitted field) reads as `false`. |
| `{"schema":1,"reply":"snapshotted","dir":"/tmp/bsx-snapshots-…/snap-0"}` | A snapshot bundle was written to that **daemon-host** directory. |
| `{"schema":1,"reply":"trace","record":{…}}` | The audit record as a **signed envelope**: `{schema, key_id, signature, record}`, where `record` is the canonical record JSON carried as a string. Verify it with `bsx verify` or the trusted public key. Within a session, successive `trace` replies are **hash-chained**: each after the first carries a `prev` field (the SHA-256 of the previous record; the first is the unchained anchor), so the sequence is tamper-evident, not just each record alone. Verification refuses a `prev` that is not those 64 hex characters rather than reading it: the fixed shape is what tells the signed `prev + "\n" + record` message where one half ends. Save the replies one per line and `bsx verify` checks the whole chain, order and all; the library form is `verify_chain` in `bsx-record`. |
| `{"schema":1,"reply":"trace_summary","summary":{…}}` | The record summary as its own JSON object (with its own leading `schema`, the *summary* version). |
| `{"schema":1,"reply":"cancelled"}` | The in-flight request was abandoned and the sandbox torn down, acknowledging `cancel`. Always the connection's last message; whatever the cancelled request had produced is discarded. |
| `{"schema":1,"reply":"closed"}` | The session ended cleanly. |
| `{"schema":1,"reply":"error","message":"…","fatal":false,"kind":"guest"}` | The request could not be served. `fatal:true` means the session is gone (reconnect); `fatal:false` is a per-request fault (a command that couldn't spawn, a schema-valid but malformed line) the session survives. A wrong `schema` is `fatal:true`. `kind` says **whose fault** it is, so a client branches on a value instead of parsing `message`: see below. |
| `{"schema":1,"reply":"at_capacity","retry_after_ms":1000}` | The daemon is **at capacity** (the `--max-sessions` count or an aggregate resource ceiling is full) and refused the `open` before booting anything. A distinct backpressure signal (not an `error`) a dispatcher fails over on; `retry_after_ms` is a backoff hint. Always session-ending. |

## Error kinds

`fatal` answers "is this session over?"; `kind` answers "whose fault, and what should I do?". They
are independent: a guest fault is non-fatal but retrying the same command changes nothing, while a
failed boot is fatal yet nothing about the caller's request was wrong.

| `kind` | Meaning | What a client should do |
|---|---|---|
| `infra` | The host couldn't stand the sandbox up, or a bounded wait expired. | Retry, or try another host. |
| `transport` | A framing/IO fault on an established exec channel, or a guest silent past its deadline. | Retire the sandbox; don't blame the command. |
| `guest` | The run is at fault: couldn't spawn, outran its budget, flooded output. | Fix the command; an identical retry fails identically. |
| `protocol` | The client's own message: wrong `schema`, undecodable, oversize, or out of order. | Fix the client. |
| `refused` | Understood and declined: an operator-chosen posture (an `open` past an operator ceiling, a withdrawn NIC, snapshotting a jailed session) or a capability this session lacks (no probes attached). | Don't retry as-is. |

`infra` / `transport` / `guest` are the wire form of the engine's own pinned error taxonomy
(`bsx_engine::ErrorKind`), so a wire client and a Rust embedder classify the same failure the same
way.

**Treat an unrecognized `kind` as `infra`.** The set may grow; an unrecognized value means
"unclassified", and assuming the host rather than the caller is the conservative read. An absent
`kind` (an omitted field) reads the same way.

**One rejected `open` knob can come back two ways, both `protocol`.** A value the field's type cannot
hold is refused while the line is being decoded and carries the decoder's own wording (`vcpus: 300`
does not fit the byte `vcpus` is carried in); a value the type holds but this host will not serve is
refused afterwards, by the daemon, and names the rule it broke (`vcpus: 7`, since a count must be 1
or even). Both are `protocol` and both name the field, so a client that reports `message` and fixes
the request needs no special case. Both are also **fatal**, because `open` is the first message and a
session that never opened has nothing to continue; reconnect to retry. Do not parse either text.

## Compatibility rules (what a client must do)

The engine's own client is written in Rust with serde, but nothing here depends on that: a client in
any language faces these questions independently, so the answers are the protocol's, not the
implementation's. Three rules, in decreasing order of how often you will hit them.

**1. Ignore fields you do not recognize.** Messages may grow fields within a `schema`, so a decoder
must not reject an object because it carries something extra. This is how the wire evolves without a
version bump: a new optional field is invisible to clients that do not parse it and meaningful to ones that do. A
client that rejects unknown fields (a strict struct decoder, a `deny_unknown_fields`-style setting)
will break when a daemon adds optional fields. Note the direction: **omitted** optional fields keep the
documented default, so absence and unfamiliarity are both safe.

**2. Reject a `reply` you do not recognize, loudly.** Unlike fields, an unrecognized *reply kind* is
a hard error and must be surfaced, not skipped. This is deliberate, and it is the opposite of
rule 1: the protocol is strict request/response, so a reply you cannot interpret means you have lost
track of what the daemon is answering. Skipping it would silently desynchronize the session and
misattribute every later reply to the wrong request. Growing the reply set is therefore a
`schema` bump, not an additive change, and a bump is
rejected up front by both sides.

**3. Degrade on an unrecognized enumerated *value*.** Where a field carries a value from a named set
rather than free text, the set may grow, and an unfamiliar value must map to a documented
conservative default rather than failing. `kind` is the case that exists today: treat anything you
do not recognize (or an absent `kind`) as `infra`. Values are not replies; they carry no framing, so
degrading loses information rather than synchronization.

The short version: **fields grow, values grow, replies do not.** A `schema` mismatch is always
fatal and always reported before a body is trusted, so a client built against a future revision
fails immediately instead of half-understanding a session.

## Line size bounds

The two directions carry **different** bounds, and a client implements both.

| Direction | Bound | What it bounds |
|---|---|---|
| Request (client to daemon) | 4 MiB | A line an untrusted peer sent. The daemon refuses a longer one before decoding it, drains to the next newline so the session resyncs, and answers `protocol`. |
| Reply (daemon to client) | 33 MiB | The daemon's own output, under the session's `output_cap`. One number for both directions is what makes a run's own `stdout` undeliverable, so the reply bound is the larger. |

The reply bound is not `output_cap` and cannot be derived from it: JSON escaping expands what the
guest printed, six bytes for a C0 control byte and three for a byte that is not valid UTF-8, so
33 MiB carries the default 16 MiB cap's worth of ordinary text but not a cap's worth of either.
Output that expands past the bound comes back as a `guest` error naming the number, never as a
silently truncated `result` and never as a dropped connection, so a client surfaces it like any other
flooded-output fault.

## Protocol examples

A whole session, driven by hand (an `open` with no fields takes the defaults):

```console
$ printf '%s\n' \
    '{"schema":1,"op":"open"}' \
    '{"schema":1,"op":"exec","argv":["echo","hi"]}' \
    '{"schema":1,"op":"close"}' \
  | socat - UNIX-CONNECT:./bsx.sock
{"schema":1,"reply":"opened","boot_ms":118,"pooled":false}
{"schema":1,"reply":"result","exit_code":0,"stdout":"hi\n","stderr":"","exec_wall_ms":7}
{"schema":1,"reply":"closed"}
```

### Inject, run, extract (`put` → `exec` → `get`)

The round trip a caller uses to collect what a run *produced*, not just what it printed:

**Request 1 (`put` the input):**
```json
{"schema":1,"op":"put","path":"app.py","content":"with open('out.txt', 'w') as f:\n    f.write('generated in the guest\\n')\n"}
```
**Response 1:**
```json
{"schema":1,"reply":"put","path":"app.py"}
```

**Request 2 (`exec` it):**
```json
{"schema":1,"op":"exec","argv":["python3","app.py"],"stdin":""}
```
**Response 2:**
```json
{"schema":1,"reply":"result","exit_code":0,"stdout":"","stderr":"","exec_wall_ms":8}
```

**Request 3 (`get` the file the run wrote):**
```json
{"schema":1,"op":"get","path":"out.txt"}
```
**Response 3:**
```json
{"schema":1,"reply":"got","path":"out.txt","content":"generated in the guest\n","present":true,"lossy":false}
```

### Live audit inspection (`trace_summary`)

**Request:**
```json
{"schema":1,"op":"trace_summary"}
```
**Response:**
```json
{
  "schema": 1,
  "reply": "trace_summary",
  "summary": {
    "schema": 1,
    "timing": {"boot_ns": 128000000, "exec_ns": 14000000},
    "network": null,
    "host_syscalls": {"execve": 3, "openat": 41, "connect": 0, "notable": [], "truncated": false},
    "resources": {
      "cpu_ns": 16000000,
      "mem_peak_bytes": 28432000,
      "io_read_bytes": 1310720,
      "io_write_bytes": 0
    },
    "gaps": []
  }
}
```
