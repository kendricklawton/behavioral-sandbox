# Conformance for a wire client

One wire, more than one decoder: the Rust reference client (`bsx-client`) and whatever an
operator writes against [the protocol](./daemon-protocol.md). Each reimplements the same JSON
shapes without sharing code, so "the client works" needs one meaning rather than one per
implementation. This page is that meaning: the scenarios a client is expected to handle, what
each one is checking, and the reply that says it did.

It is a checklist, not a harness. Nothing here runs the scenarios for you, and passing them says
the cases below behaved as described against the daemon you ran, on the day you ran it.

## Running them

Every scenario drives a real `bsx serve` over its unix socket. Two groups, because they need
different hosts:

- **Pre-boot scenarios** (1, 8, 9, 10, 11, 12) are answered before any VM exists, so they run on a
  host with no `/dev/kvm` and no guest rootfs. Put these in a client's everyday CI: they
  cover the framing, the schema gate, and the fault taxonomy, which is where a hand-written decoder
  actually breaks.
- **Booting scenarios** (2 through 7) need `/dev/kvm` plus the guest artifacts, the same
  prerequisites as [the privileged gate](./cli-install.md#preparing-the-host).

A daemon for the pre-boot group needs no artifacts at all:

```console
bsx serve --socket ./bsx.sock --max-vcpus 2 --max-sessions 1
```

## The scenarios

### 1. A session opens, and every line carries its schema

Send `{"schema":1,"op":"open"}`. Expect one `opened` reply carrying `boot_ms` and `pooled`.

Checks the minimum a client must do: stamp `schema` on what it sends, read one newline-delimited
JSON object per reply, and take the documented defaults when `open` names no knobs. A client that
omits `schema` gets a `protocol` error naming the missing field, which is worth asserting too.

### 2. Exec returns a result, and a non-zero exit is not an error

`{"schema":1,"op":"exec","argv":["sh","-c","echo out; echo err >&2; exit 3"]}` answers with
`result` carrying `exit_code: 3`, `stdout`, `stderr`, and `exec_wall_ms`.

The distinction that trips client authors: a non-zero `exit_code` is a *result*, not a failure. A
client that raises on it cannot report what the guest actually did. Failures arrive as `error`.

### 3. Files round-trip, and a missing file is not an error

`put` a file, `exec` something that reads it and writes another, `get` that one back. Then `get` a
path that does not exist and expect `present: false` with empty `content` and no error.

### 4. A non-UTF-8 file is flagged, not silently substituted

Write bytes that are not valid UTF-8 in the guest (`printf '\377\376' > bin.dat`), then `get` it.
The reply carries `lossy: true`: the content is a lossy rendering and the original bytes are not
recoverable from this line. A clean text file answers `lossy: false`.

A client must surface that flag. Bulk or binary transfer is the engine's block-device path, not this
wire. `a_binary_get_is_flagged_lossy_and_a_text_get_is_not` covers the daemon's half.

### 5. Trace and summary are live and repeatable

`trace` answers with a signed envelope; `trace_summary` answers with the compact projection. Both
are non-destructive: ask twice mid-session and the session continues either way.

A client should treat the `record` and `summary` objects as opaque JSON, since they carry their own
schema versions distinct from the wire's. Re-serializing the envelope must not disturb the canonical
record bytes inside it, or the signature stops verifying.

### 6. Cancel ends an in-flight exec and gets an acknowledgement

Start a long `exec`, then send `{"schema":1,"op":"cancel"}` on the same connection. Expect
`cancelled`, and treat it as the connection's last message.

Two properties worth separate assertions: `cancel` is the only verb legal while a request is
outstanding, and it ends the *session* rather than one command (the sandbox is torn down). A client
that expects a `result` for the cancelled exec will hang. `cancel` is also acknowledged when the
exec has outrun the daemon's idle timeout, which
`a_cancel_after_the_idle_deadline_still_gets_its_ack` covers.

### 7. Hanging up mid-exec is a clean end, with no reply

Drop the connection during a long `exec`. The daemon tears the sandbox down within one poll
interval, and sends nothing, because there is nobody to read it. A client's teardown path must not
wait for a reply it will never get.

### 8. An operator ceiling is `refused`, a malformed value is `protocol`

Against a daemon started with `--max-vcpus 2`, `{"schema":1,"op":"open","vcpus":16}` answers with a
fatal `error` whose `kind` is `refused`: a well-formed ask this host declines, so retrying it
unchanged will not help. `{"schema":1,"op":"open","vcpus":0}` answers `protocol`: a value the VMM
could never boot, so the client's own message is what needs fixing.

Branching on `kind` rather than the message text is the whole point of the taxonomy, and this pair
is what proves a client branches correctly. `an_operator_ceiling_refusal_is_kind_refused_on_the_wire`
covers the daemon's half.

### 9. An unknown field is ignored

Send an `open` carrying a field this schema does not define. It must decode and behave as if the
field were absent. This is compatibility rule 1 and the most common way a strict decoder breaks on a
routine daemon upgrade.

### 10. An unknown `reply` is a hard error

Feed the client a line like `{"schema":1,"reply":"streamed","chunk":"x"}` (a fixture, not something
a current daemon sends). It must surface an error rather than skip the line: an uninterpretable
reply means the client has lost track of what is being answered, and continuing would misattribute
every later reply. This is rule 2, the deliberate opposite of rule 9.

### 11. An unknown or absent `kind` degrades

An `error` whose `kind` is a value this client predates, and an `error` with no `kind` at all, must
both decode, and both read as `infra` (conservative: assume the host, not the caller). A `kind` that
is not even a string must degrade the same way rather than failing the whole reply, since losing the
daemon's `message` over an advisory field is the failure this rule exists to prevent.

### 12. A wrong `schema` is fatal, and reported before the body

`{"schema":2,"op":"close"}` is rejected on the version, not on the body, and the same holds for a
body this version has never seen. A client built against a future revision fails immediately instead
of half-understanding a session.

## Also worth covering

Not scenarios every client needs, but each is a real edge a client will eventually meet:

- **Backpressure.** A daemon at `--max-sessions` answers a new connection with `at_capacity` and a
  `retry_after_ms` hint. It is always session-ending, and distinct from `error` so a dispatcher can
  branch on "full, try another host" without matching strings. The hint is a hint: the daemon cannot
  know when a slot frees.
- **Oversize lines.** A line past the 4 MiB cap is refused; the daemon resynchronizes to the next
  line boundary rather than emitting a cascade for one oversize message. A client should apply the
  same bound to what it sends rather than discovering the cap by hitting it.
- **Blank lines.** A stray newline is not a message and is skipped, so a client's framing must not
  treat one as a decode failure.
- **Snapshotting a jailed session** is a typed refusal, not a crash: the session's disk lives in the
  jailer's chroot.

## What conformance does not cover

Latency, throughput, and boot time are not conformance. They belong to
[Benchmarks](./benchmarks.md), measured on a named host with a date, and a client that satisfies
every scenario here can still be slow.
