# Observe a run from the host

The other half of a run is its record, observed from the host side of the KVM boundary.

## The whole run, fused

One run, all three host-side eBPF probes bound to it, one audit record out:

```console
ekvm run --net --watch --trace --record run.json -- \
    python3 -c "import socket; open('/etc/hostname').read(); \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'hi', ('10.200.0.1', 9999))"
```

- **`--watch`** presents a live terminal view of flows, denials, and resource usage.
- **`--trace`** prints the human-readable audit trail on stdout after the run.
- **`--record run.json`** writes the signed, deterministic JSON record.

The four faces of the record, and what each is for, are in
[Observing a run](./cli-observe.md#four-faces-one-record).

## Reading a thinner record

On a host without eBPF capability the run still works, and the record's coverage section names the
axes that could not bind. That is deliberate: a thinner record annotates itself rather than presenting
itself as complete. If you are unsure what your host can do, `ekvm doctor` says so before you boot
anything.

Each axis also has a standalone live demo, one probe at a time, in
[Host-side observability & enforcement](./probes.md).
