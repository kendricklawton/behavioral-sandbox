# Examples

{{#include ./status.md:banner}}

Worked, end-to-end walkthroughs of using the engine. Where [Using the eKVM CLI](./cli.md) is the reference (every flag, the config layering), these are task-shaped walkthroughs: pick the task you want to perform and follow it through, output and all.

All examples assume you have installed the prerequisites ([Installation](./cli-install.md)) and built the eKVM rootfs (`cargo xtask build-rootfs`). For host-side eBPF examples, make sure to build the probes object (`cargo xtask build-probes`).

---

## 1. Run untrusted code

Run a script or binary inside a microVM, feed it input, and receive a structured result. `ekvm run` is jailed by default (requires root); examples below use `--unjailed` for development environments.

### A script, with stdin
Logs go to stderr, so `2>/dev/null` leaves only the program's own output:

```console
$ echo 'hello' | ekvm run --unjailed -- python3 -c 'import sys; print(sys.stdin.read().upper())' 2>/dev/null
HELLO
```

### A structured result
`--json` replaces the raw relay with one JSON object on stdout: the exit code, streams, artifacts, and host-measured metrics. A crash *inside* the guest comes back as a result (`exit_code`), not an engine error:

```console
$ ekvm run --unjailed --json -- python3 -c 'print(2 + 2)' 2>/dev/null | jq .exit_code
0
```

### Files in, files out
Inject host files into the run's working directory with `--put`, and fetch results with `--get`. `--get` is deny-by-default: only paths you explicitly name are returned.

```console
$ echo 'a,b,c' > input.csv
$ ekvm run --unjailed --put input.csv --get output.txt -- \
    python3 -c 'open("output.txt","w").write(open("input.csv").read().count(",").__str__())'
$ cat output.txt
2
```

---

## 2. Observe a run from the host

The other half of a run is its record, observed from the host side of the KVM boundary.

### The whole run, fused
The CLI carries the fused surface: one run, all three host eBPF probes bound to it, one audit record out:

```console
ekvm run --net --watch --trace --record run.json -- \
    python3 -c "import socket; open('/etc/hostname').read(); \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'hi', ('10.200.0.1', 9999))"
```

- `--watch` presents a live terminal view of flows, denials, and resource usage.
- `--trace` prints the human-readable audit trail on stdout.
- `--record run.json` writes the signed, deterministic JSON record.

Each axis also has a standalone live demo; see
[Host-side observability & enforcement](./probes.md).

---

## 3. Contain an agent, and prove what it did

Untrusted AI agents or dynamic scripts may invoke tools or phone home. `ekvm` enforces deny-by-default egress at the virtual TAP interface and produces an out-of-guest audit record of what traffic the host permitted and what it dropped.

### An agent that phones home
Consider an agent attempting two UDP network calls: one to a search index (`10.200.0.1:9000`), one to an exfiltration webhook (`10.200.0.1:9100`).

```console
ekvm run --net \
    --allow 10.200.0.1:9000/udp \
    --record record.json \
    --record-summary summary.json \
    -- python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"search", ("10.200.0.1", 9000))
s.sendto(b"exfil", ("10.200.0.1", 9100))
print("both calls sent")
'
```

### What the record shows
Even though the guest transcript reports both calls as sent, `summary.json` carries what the host
observed at the tap:

```json
{
  "network": {
    "reached": ["10.200.0.1:9000/udp"],
    "denied":  ["10.200.0.1:9100/udp"]
  }
}
```

`ekvm verify record.json` checks the host signature; [`ekvm verify`](./cli-commands.md#ekvm-verify) states exactly what that does and does not prove.

---

## 4. Analyze an untrusted binary

Run an unknown static Linux ELF in a microVM and observe it from the host (`analyze-me` is any
static binary you want to watch):

```console
$ ekvm run --unjailed --net --trace \
    --put analyze-me -- /bin/sh -c 'chmod +x analyze-me && ./analyze-me'
```

Network activity at the TAP interface provides external visibility into binary behavior. Host-side tracepoints observe VMM host syscalls; guest-kernel syscalls are handled inside the VM (see [Threat model](./threat-model.md)). The audit trail shows flow attempts and enforcement results:

Illustrative output (the timings are from one run on the development host, not a benchmark; see
[Benchmarks](./benchmarks.md)):

```text
── audit record ─────────────────────────────────────────────
 timing     boot 126 ms · exec 38 ms
 network    reached  —
            denied   203.0.113.9:443/tcp        ← phone-home blocked at TAP
```

---

## 5. Run a CI job from a fork

Execute untrusted CI pull request scripts safely:

```console
$ ekvm run \
    --put project.tar --put ci-job.sh --get report.txt \
    --record-summary ci.json -- /bin/sh ci-job.sh
```

With no `--net` flag the sandbox has no NIC at all, and `ci.json` records `"network": null`: the record's proof of it.
