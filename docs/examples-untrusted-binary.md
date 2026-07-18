# Analyzing an untrusted binary

You have a statically-linked Linux binary and no source: a sample under analysis, a vendor blob, a
build artifact from a fork. Run it in a microVM and let the **host** tell you what it did, every
`execve`, `openat`, and `connect` it made, observed from outside the guest where the binary can't
hide them. This is the malware-sandbox use case, minus the trust.

Point the CLI at the agent rootfs (once), and add `--unjailed` on a dev box without real root:

```console
export AGENT_ROOTFS=artifacts/rootfs-agent.ext4
export AGENT_MARKER=AGENT-GUEST-READY
```

## A stand-in for the unknown binary

We don't ship a binary (the engine runs *any* static ELF; see [Running untrusted
code](./examples-untrusted-code.md)). Build a small, deliberately nosy one to stand in, it reads a
host file and tries to phone home:

```console
$ cat > analyze-me.c <<'EOF'
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
int main(void) {
    FILE *f = fopen("/etc/hostname", "r");           /* an openat the host will see */
    if (f) { char b[64] = {0}; if (fgets(b, sizeof b, f)) printf("read hostname: %s", b); fclose(f); }
    int s = socket(AF_INET, SOCK_STREAM, 0);          /* a connect the host will see */
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(443);
    inet_pton(AF_INET, "203.0.113.9", &a.sin_addr);
    printf(connect(s, (struct sockaddr *)&a, sizeof a) == 0 ? "phoned home\n" : "connect blocked\n");
    return 0;
}
EOF
$ cc -static -O2 -o analyze-me analyze-me.c      # or: musl-gcc -static -O2 -o analyze-me analyze-me.c
```

## Run it, watched from the host

Inject the binary with `--put`, run it, and attach the host probes with `--trace` (the human-readable
audit trail) and `--net` (so its network attempts cross the deny-by-default tap and are recorded).
The binary is opaque; the record is not:

```console
$ cargo run -q -p agent-cli -- run --unjailed --net --trace \
    --put analyze-me -- /bin/sh -c 'chmod +x analyze-me && ./analyze-me'
read hostname: localhost
connect blocked

── audit record ─────────────────────────────────────────────
 timing     boot 126 ms · exec 38 ms
 syscalls   execve  /bin/sh, ./analyze-me
            openat  /etc/hostname, /lib/ld-musl-x86_64.so.1, …
            connect 203.0.113.9:443
 network    reached  —
            denied   203.0.113.9:443/tcp        ← the phone-home, dropped at the tap
 resources  cpu 7 ms · mem peak 3.1 MiB
```

The binary's own output (`connect blocked`) and the host's record agree, but you did not have to
take the binary's word for it: the `connect` to `203.0.113.9` is there whether or not the program
admits to it, and deny-by-default meant it never left the host. The exact numbers vary per host; the
shape is the point.

## From observed to enforced, and machine-readable

- **Allow-list what it may reach.** Add `--allow 203.0.113.9:443/tcp` (with `--net`) and that one
  destination moves from `denied` to `reached`; everything else stays blocked. Egress is
  deny-by-default and every allowance is recorded, see [Observing a run from the
  host](./examples-observe-a-run.md).
- **Capture the record.** Swap `--trace` for `--record analysis.json` (the full deterministic JSON)
  or `--record-summary analysis.json` (the compact, model-legible projection) to file the finding
  instead of printing it. `--watch` draws the same record live.
- **Diff two samples.** Because the record is deterministic and byte-stable, two runs of the same
  binary produce the same record, so a change in the record is a change in behavior.

The full syscall / network / resource machinery behind this trail is [Host-side observability &
enforcement](./probes.md).
