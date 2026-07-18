#!/usr/bin/env python3
"""A scripted agent: a deterministic stand-in for an LLM's tool loop. No model, no secrets, no API
keys — so this runs in CI, byte-for-byte the same every time. It stands in for the shape of an
agent that reasons and calls tools; here the "reasoning" is unrolled to a fixed script so the
*containment* is what's under test, not a model's variance.

Its "tools" are two network endpoints. It calls the permitted one and the forbidden one. The host's
deny-by-default egress policy (an `--allow` list) decides which actually reaches the world — and,
crucially, the agent **cannot tell the difference from in here**: a datagram it hands to the kernel
looks sent whether or not the host drops it at the tap. So the agent's own transcript reports both
calls as `sent`. The ground truth — what it *reached* and what was *blocked* — lives only in the
host-observed audit record, outside this guest, where the agent can neither see nor forge it. That
gap is the whole point: a supervisor trusts the host's record, not the agent's self-report.
"""
import json
import socket

# The host end of the sandbox's point-to-point /30 is always 10.200.0.1 (this guest is .2), so the
# example needs no real internet: the two "tools" are two UDP ports on that gateway, and the run
# allow-lists exactly one of them. `--allow 10.200.0.1:9000/udp` makes 9000 the permitted tool.
GATEWAY = "10.200.0.1"
TOOLS = [
    {"name": "search-index", "port": 9000},  # allow-listed → the call crosses the tap
    {"name": "exfil-webhook", "port": 9100},  # not allow-listed → dropped at the tap, silently
]


def call_tool(tool):
    """Invoke one tool. Fire-and-forget UDP: the send succeeds locally even when the host will drop
    it, which is exactly why the agent can't observe its own containment."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for _ in range(3):
            sock.sendto(b"tool-call", (GATEWAY, tool["port"]))
        return "sent"
    except OSError as err:
        return f"error: {err}"


# The observe→act loop, unrolled deterministically. The agent records its *local* view of each call.
transcript = [
    {"tool": t["name"], "port": t["port"], "result": call_tool(t)} for t in TOOLS
]
print(json.dumps({"agent": "scripted-tool-loop", "transcript": transcript}))
