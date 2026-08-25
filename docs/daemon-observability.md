# Observability for the hoster

The daemon exposes its own numbers; dashboards, alerting, and retention are the hoster's, above the
engine.

## Structured logs

Operational logs are structured `tracing` events on **stderr**, human-readable text by default,
or one JSON object per line with `--log-json` (or `BSX_LOG_FORMAT=json`) for a log shipper. The
events and their fields (`vmm_pid`, `boot_ms`, `pooled`, …) are identical in both encodings; the flag
changes only the framing. The filter is `--log` / `BSX_LOG` (default `info`, the per-session
open/close lines are the daemon's operational trace).

```console
bsx serve --socket ./bsx.sock --log-json --log info 2>> /var/log/bsx.jsonl
```

## Metrics (Prometheus)

`--metrics ADDR` serves the Prometheus text-exposition format at `GET /metrics`:

```console
bsx serve --socket ./bsx.sock --metrics 127.0.0.1:9920
curl -s http://127.0.0.1:9920/metrics
```

The endpoint is **off by default**, and it serves plain HTTP with **no auth** (the same posture as
the unix socket: access control is the hoster's), bind it to loopback or a private scrape network,
never a public interface. If the requested address can't be bound, the daemon **refuses to start**
(an operational surface you asked for must not silently be absent). Durations follow the Prometheus
convention of base units: **seconds**, never milliseconds.

| Metric | Type | Meaning |
|---|---|---|
| `bsx_build_info{version=…}` | gauge | Build metadata (value always 1). |
| `bsx_sessions_opened_total{pooled=…}` | counter | Sessions opened, pre-warmed pool vs cold boot. |
| `bsx_session_open_failures_total` | counter | `open`s that never produced a sandbox. |
| `bsx_open_refusals_total{reason=…}` | counter | `at_capacity` refusals, by which ceiling refused: `sessions` (`--max-sessions`) vs `resources` (`--max-committed-*`). A flat zero here plus flat opens means saturation, not calm. |
| `bsx_sessions_active` | gauge | Sessions currently open (one live microVM each). |
| `bsx_sentinel_degraded` | gauge | Active sessions whose VM-lifetime sentinel could not be armed (fallback to Drop-only cleanup). |
| `bsx_sweep_reclaimed_total{resource=…}` | counter | Orphaned VM resources reclaimed by sweeps (`resource="dirs"` or `"netns"`). |
| `bsx_requests_total{verb=…}` | counter | Requests served after `open`, by wire verb. |
| `bsx_request_errors_total{kind=…}` | counter | Errored requests, by the same fault kind the client was told: `guest` (the run), `refused` (the daemon declined: an operator ceiling, or a capability this session lacks), `transport`/`infra` (the sandbox is gone). A rising `refused` is this host's posture or capabilities, not a misbehaving command. |
| `bsx_protocol_errors_total` | counter | Wire lines that failed to decode (malformed, oversize, wrong schema). |
| `bsx_boot_seconds` | histogram | Boot-to-serving latency (warm pops and cold boots alike). |
| `bsx_guest_command_seconds` | histogram | Host-observed wall time of guest commands. |
| `bsx_pool_ready` | gauge | Warm clones ready in the pool, **absent** (not zero) without a pool. |
| `bsx_committed_mem_mib` / `_committed_vcpus` | gauge | Guest memory (MiB) / vCPUs committed across live sessions and pre-warmed pool clones: the RAM actually spoken for. |
| `bsx_capacity_mem_mib` / `_capacity_vcpus` | gauge | The aggregate ceilings (`--max-committed-mem-mib` / `--max-committed-vcpus`; `0` = unlimited). Scrape committed-vs-capacity to route on real headroom. |

A minimal scrape config:

```yaml
scrape_configs:
  - job_name: bsx
    static_configs:
      - targets: ["127.0.0.1:9920"]
```
