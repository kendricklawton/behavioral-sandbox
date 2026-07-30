# Analyze an untrusted binary

Run an unknown static Linux ELF in a microVM and watch it from the host. `analyze-me` is any static
binary you want to observe:

```console
$ ekvm run --unjailed --net --trace \
    --put analyze-me -- /bin/sh -c 'chmod +x analyze-me && ./analyze-me'
```

Network activity at the tap gives external visibility into what the binary reaches for. The audit
trail shows flow attempts and enforcement results:

```text
── audit record ─────────────────────────────────────────────
 timing     boot 126 ms · exec 38 ms
 network    reached  —
            denied   203.0.113.9:443/tcp        ← phone-home blocked at TAP
```

Those timings are from one run on the development host and are illustrative, not a benchmark. See
[Benchmarks](./benchmarks.md).

## What this does and does not show you

**The network is observed exactly**, at the tap, because every packet the guest sends crosses a device
the host owns.

**The syscalls are not the guest's.** The host-syscall axis records the *VMM's* footprint. A microVM
services the guest's own syscalls in its own kernel, so they never reach a host tracepoint. That
absence is the isolation working rather than a blind spot, and it is why this technique tells you
about a binary's external behavior rather than giving you an in-guest strace. The reasoning is in the
[threat model](./security-threat-model.md).

If you need in-guest syscall detail, that is a guest-side tool run inside the sandbox, which is a
different trust posture: whatever it reports is the guest's account, not the host's.
