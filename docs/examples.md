# Examples

Worked, end-to-end walkthroughs of using the engine. Where [Using the eKVM CLI](./cli.md) is the reference (every flag, the config layering), these are task-shaped walkthroughs: pick the task you want to perform and follow it through, output and all.

All examples assume you have installed the prerequisites ([Installation](./cli-install.md)) and built the eKVM rootfs (`cargo xtask build-rootfs`). For host-side eBPF examples, make sure to build the probes object (`cargo xtask build-probes`).

---

## 1. Running Untrusted Code

Run a script or a binary you don't trust inside a microVM, feed it input, and read a structured result back. Every command here is `ekvm run`, jailed by default; add `--unjailed` on a dev box without real root and the `jailer` binary.

### A script, with stdin
The guest command reads stdin like any process; logs go to stderr, so `2>/dev/null` leaves only the program's own output:

```console
$ echo 'hello' | ekvm run -- python3 -c 'import sys; print(sys.stdin.read().upper())' 2>/dev/null
HELLO
```

### A structured result
`--json` replaces the raw relay with one JSON object on stdout: the exit code, streams, artifacts, and host-measured metrics. A crash *inside* the guest comes back as a result (`exit_code`), not an engine error:

```console
$ ekvm run --json -- python3 -c 'print(2 + 2)' 2>/dev/null | jq .exit_code
0
```

### Files in, files out
Inject host files into the run's working directory with `--put`, and fetch results with `--get`. `--get` is deny-by-default: only paths you explicitly name are returned.

```console
$ echo 'a,b,c' > input.csv
$ ekvm run --put input.csv --get output.txt -- \
    python3 -c 'open("output.txt","w").write(open("input.csv").read().count(",").__str__())'
$ cat output.txt
2
```

---

## 2. Observing a Run from the Host

Running code is half the point; the other half is observing what it did from *outside* the guest, where untrusted code cannot forge or disable the record.

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

### Per-axis observation commands
- **Host Syscalls**: `cargo xtask trace-sandbox` (attributes VMM host syscalls to the sandbox cgroup).
- **Network Flows**: `cargo xtask watch-sandbox` (monitors TAP packets).
- **Egress Enforcement**: `cargo xtask enforce-sandbox` (drops unauthorized TAP packets).
- **Resource Metering**: `cargo xtask meter-sandbox` (meters CPU/memory/IO via `sched_switch` & cgroup v2).

---

## 3. Containing an Agent and Proving What It Did

Untrusted AI agents or dynamic scripts may invoke tools or phone home. `ekvm` enforces deny-by-default egress at the virtual TAP interface and produces an out-of-guest audit record that proves what traffic was permitted and what was dropped.

### Scripted Tool Loop
Consider an agent attempting two UDP network calls—one to a search index (`10.200.0.1:9000`), and one to an exfiltration webhook (`10.200.0.1:9100`).

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

### Verified Out-of-Guest Observation
Even though the guest transcript reports both calls as sent, `summary.json` proves ground truth:

```json
{
  "network": {
    "reached": ["10.200.0.1:9000/udp"],
    "denied":  ["10.200.0.1:9100/udp"]
  }
}
```

`ekvm verify record.json` verifies the host signature, confirming the guest did not alter the record.

---

## 4. Analyzing an Untrusted Binary

Run an unknown static Linux ELF binary in a microVM and observe its system calls and network behavior from the host:

```console
$ ekvm run --net --trace \
    --put analyze-me -- /bin/sh -c 'chmod +x analyze-me && ./analyze-me'
```

The human-readable audit trail outlines all `openat`, `execve`, and `connect` attempts made by the binary:

```text
── audit record ─────────────────────────────────────────────
 timing     boot 126 ms · exec 38 ms
 syscalls   execve  /bin/sh, ./analyze-me
            openat  /etc/hostname, …
            connect 203.0.113.9:443
 network    reached  —
            denied   203.0.113.9:443/tcp        ← phone-home blocked at TAP
```

---

## 5. Running a CI Job from a Fork

Execute untrusted CI pull request scripts safely:

```console
$ ekvm run \
    --put project.tar --put ci-job.sh --get report.txt \
    --record-summary ci.json -- /bin/sh ci-job.sh
```

With no `--net` flag, the sandbox has no virtual NIC allocated. `ci.json` records `"network": null`, providing verifiable proof that the execution had no path off the host to exfiltrate secrets or fetch unverified dependencies.
