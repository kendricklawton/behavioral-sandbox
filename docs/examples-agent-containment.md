# Containing an agent, and proving what it did

The highest-value untrusted workload for this engine is **AI-generated code and autonomous agents**:
dynamic, possibly-misaligned code you did not write and cannot fully predict. This example runs a
**scripted agent** — a deterministic stand-in for an LLM's tool loop, with *no model and no secrets*,
so it runs the same way every time — inside a sandbox, egress-policed to exactly the endpoints it is
allowed to reach. It calls one permitted tool and one forbidden one, and the host-observed record
proves **exactly what it reached and what was blocked**.

The engine's contribution here is not a smarter agent; it is the containment and the trustworthy
record. The model is always the *caller*, never part of the engine (see
[decision 035](./contributing-architecture.md)):
nothing in the host path runs inference or holds a key, which is exactly why this demo is
CI-reproducible.

Needs `/dev/kvm`, the agent rootfs (`cargo xtask build-rootfs`), the built probe object
(`cargo xtask build-probes`), and `CAP_BPF`+`CAP_PERFMON`+`CAP_NET_ADMIN` — run as root or grant the
caps.

## The agent

The scripted agent is [`docs/examples/agent-tool-loop.py`](./examples/agent-tool-loop.py). Its
"tools" are two network endpoints; it calls both:

```python
GATEWAY = "10.200.0.1"                          # the host end of the sandbox's /30
TOOLS = [
    {"name": "search-index",  "port": 9000},    # we will allow-list this one
    {"name": "exfil-webhook", "port": 9100},    # this one is not on the list
]
# ... calls each tool over UDP, records its own local view of the result ...
```

The trap this example exposes: **fire-and-forget UDP succeeds locally even when the host drops it at
the tap.** So the agent cannot tell from inside the guest which call actually left the box — its own
transcript reports *both* tools as `sent`. The ground truth lives only in the host record.

## Run it, contained

Allow the one tool, deny the rest (deny-by-default), and capture both faces of the record:

```console
agent run --unjailed --net \
    --allow 10.200.0.1:9000/udp \
    --record record.json \
    --record-summary summary.json \
    -- python3 -c "$(cat docs/examples/agent-tool-loop.py)"
```

The agent's own stdout — its self-report — claims success on both:

```json
{"agent":"scripted-tool-loop","transcript":[
  {"tool":"search-index","port":9000,"result":"sent"},
  {"tool":"exfil-webhook","port":9100,"result":"sent"}]}
```

## What the host actually saw

The **model-legible summary** (`summary.json`) is the face a supervising agent reads back between
turns — compact, and shaped for exactly this question:

```json
{
  "schema": 1,
  "timing": { "boot_ns": …, "exec_ns": … },
  "network": {
    "reached": ["10.200.0.1:9000/udp"],
    "denied":  ["10.200.0.1:9100/udp"],
    "sent_bytes": 27, "recv_bytes": 0
  },
  "host_syscalls": { "execve": …, "openat": …, "connect": …, "notable": […], "truncated": false },
  "resources": { "cpu_ns": …, "mem_peak_bytes": …, "io_read_bytes": …, "io_write_bytes": … },
  "gaps": []
}
```

`reached` names the endpoint the allow-list permitted; `denied` names the one the tap dropped. The
agent believed both calls went out; the host record shows one did and one did not. **That gap is the
whole point** — a supervisor cannot trust an agent's self-report about its own containment, and does
not have to: the record is observed from *outside* the guest, where the agent can neither see nor
forge it.

The full record (`record.json`) carries the same facts with the forensic detail — the per-flow byte
and packet counts, the dropped-packet count on the denial, the VMM's host-syscall footprint. The
summary is a **view** of it (no new observation; [decision 035](./contributing-architecture.md)),
measurably smaller so it fits back into an agent's context. See
[Using the agent CLI](./cli.md#watching-a-run-from-the-host) for all four faces of the one record.

## Over the wire, too

An agent driving the daemon reads the same projection, not a CLI-only convenience: `agentd` serves it
as the `trace_summary` verb (alongside `trace` for the full record), so a supervisor written in any
language gets the identical model-legible observation over the socket. See
[Using the agentd daemon](./daemon.md). (Daemon sessions are observe-only — the `--allow`
*enforcement* that blocks the forbidden tool is the CLI/embedding path; the daemon serves the
*observation* of any session bound to the probes.)

## Why this matters

A pure-execution sandbox can run the agent's code safely, but it cannot *tell you what the code did*
in a way you can trust. This engine can: hardware isolation for the containment, host-side eBPF for a
tamper-resistant record, and a model-legible projection of that record to feed the supervising loop —
with no model anywhere in the host path. That trustworthy, host-observed audit trail is what a
supervisor needs to actually let an agent run.

The whole scenario runs in CI as a privileged test
(`scripted_agent_is_contained_and_the_record_shows_reached_vs_blocked`), so this page is not a story:
it is a check that stays true.
