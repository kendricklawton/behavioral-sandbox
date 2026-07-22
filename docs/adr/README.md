# Architecture decision records

Each hard-to-reverse choice in the engine is one numbered **ADR**: the decision, the
alternatives considered, and the why, so the reasoning outlives the diff. Entries are
append-only; reversing one is a new ADR, not an edit. Keyed by its own number and date (never a
phase), so each stands on its own as the roadmap evolves. The overview and repo layout live in
[the architecture chapter](../contributing-architecture.md).

- [001. Drive Firecracker via its HTTP API over a unix socket](./001-drive-firecracker-via-its-http-api-over-a-unix-socket.md) *(2026-07-10)*
- [002. Host↔guest channel: vsock + a tiny guest agent](./002-host-guest-channel-vsock-a-tiny-guest-agent.md) *(2026-07-10)*
- [003. The guest rootfs: a pinned Alpine base, assembled with the agent baked in](./003-the-guest-rootfs-a-pinned-alpine-base-assembled-with.md) *(2026-07-12)*
- [004. Read-only base rootfs + a per-run tmpfs overlay](./004-read-only-base-rootfs-a-per-run-tmpfs-overlay.md) *(2026-07-12)*
- [005. Bulk input via a read-only second block device](./005-bulk-input-via-a-read-only-second-block-device.md) *(2026-07-12)*
- [006. Bulk output via a read-after-death writable block device](./006-bulk-output-via-a-read-after-death-writable-block.md) *(2026-07-12)*
- [007. A byte-for-byte reproducible rootfs build](./007-a-byte-for-byte-reproducible-rootfs-build.md) *(2026-07-12)*
- [008. Guest networking is deny-by-default: a tap with no route to the world](./008-guest-networking-is-deny-by-default-a-tap-with-no.md) *(2026-07-12)*
- [009. Snapshots are self-contained bundles restored by staging the disk](./009-snapshots-are-self-contained-bundles-restored-by.md) *(2026-07-12)*
- [010. Per-run resource policy: one `Limits` struct of quantities, enforced at the host cgroup, failing open](./010-per-run-resource-policy-one-limits-struct-of.md) *(2026-07-14)*
- [011. Cgroup-owned VM lifetime: a sentinel that outlives the driver, and a file-based kill handle](./011-cgroup-owned-vm-lifetime-a-sentinel-that-outlives-the.md) *(2026-07-14)*
- [012. Jailed execution is the convergence target; the Sandbox surface jails by default](./012-jailed-execution-is-the-convergence-target-the-sandbox.md) *(2026-07-14)*
- [013. The engine/hoster security line: the engine's tools can't be weaponized; deploying them is the hoster's](./013-the-engine-hoster-security-line-the-engine-s-tools-can.md) *(2026-07-14)*
- [014. Per-VM network namespace: the tap lives in the VM's netns, not the host's](./014-per-vm-network-namespace-the-tap-lives-in-the-vm-s.md) *(2026-07-14; supersedes the earlier tap and restore-identity netns notes)*
- [015. Per-exec inputs (files + env) ride the exec channel under a pinned secret-hygiene contract](./015-per-exec-inputs-files-env-ride-the-exec-channel-under.md) *(2026-07-14)*
- [016. The VM is the session: one persistent in-guest working directory per agent process](./016-the-vm-is-the-session-one-persistent-in-guest-working.md) *(2026-07-15)*
- [017. The eBPF loader: aya, an object loaded from a path, and links that drop with the loader](./017-the-ebpf-loader-aya-an-object-loaded-from-a-path-and.md) *(2026-07-15)*
- [018. Syscall observability: a ring buffer of per-event records, a shared POD type, and an in-kernel filter](./018-syscall-observability-a-ring-buffer-of-per-event.md) *(2026-07-15)*
- [019. Multi-tenant safety is airtight per-run isolation, proven by the containment suite](./019-multi-tenant-safety-is-airtight-per-run-isolation.md) *(2026-07-15)*
- [020. Network observation: `tc`/clsact on the tap, a per-flow 5-tuple map, observe-only](./020-network-observation-tc-clsact-on-the-tap-a-per-flow-5.md) *(2026-07-16)*
- [021. Bind the tap monitor to a sandbox by entering its network namespace](./021-bind-the-tap-monitor-to-a-sandbox-by-entering-its.md) *(2026-07-16)*
- [022. Egress policy: a per-VM allow-list in an eBPF map, deny-by-default, enforced at the tap](./022-egress-policy-a-per-vm-allow-list-in-an-ebpf-map-deny.md) *(2026-07-16)*
- [023. Resource accounting: one shared `sched_switch` program metering a cgroup set, CPU from eBPF, memory/IO from cgroup v2](./023-resource-accounting-one-shared-sched-switch-program.md) *(2026-07-16)*
- [024. The audit record converges: a shared syscall tracer, a single post-boot attach, and deterministic JSON](./024-the-audit-record-converges-a-shared-syscall-tracer-a.md) *(2026-07-17)*
- [025. The observability face: the CLI carries the audit surface on flags, the live view draws on stderr](./025-the-observability-face-the-cli-carries-the-audit.md) *(2026-07-17)*
- [026. `--allow` projects the egress policy: enforcement is a typed refusal, never a degradation](./026-allow-projects-the-egress-policy-enforcement-is-a.md) *(2026-07-17)*
- [027. The `.agent.toml` config file layer: nearest-up-from-cwd, env-mirrored keys, typos are errors](./027-the-agent-toml-config-file-layer-nearest-up-from-cwd.md) *(2026-07-17)*
- [028. `agent doctor` shares one host-check implementation; the JSON surfaces are versioned before anyone parses them](./028-agent-doctor-shares-one-host-check-implementation-the.md) *(2026-07-17)*
- [029. The whole security boundary: what's trusted, what the adversary is, and what's assumed sound](./029-the-whole-security-boundary-what-s-trusted-what-the.md) *(2026-07-17)*
- [030. The wire API is versioned newline-JSON in a shared `agent-protocol` crate, not gRPC](./030-the-wire-api-is-versioned-newline-json-in-a-shared.md) *(2026-07-17)*
- [031. The AI-scope boundary: the model is always the caller, never an engine component](./031-the-ai-scope-boundary-the-model-is-always-the-caller.md) *(2026-07-17)*
- [032. Supported platforms: two architectures, a security-maintained host-kernel floor, and pinned upstream versions](./032-supported-platforms-two-architectures-a-security.md) *(2026-07-17)*
- [033. Single-command self-host + a vendored offline mirror of every pinned input](./033-single-command-self-host-a-vendored-offline-mirror-of.md) *(2026-07-17)*
- [034. The integrity model: a host-signed record, and the boundary a signature does not cross](./034-the-integrity-model-a-host-signed-record-and-the.md) *(2026-07-21)*
- [035. Distribution: a checksummed tarball, an installer script, and a container image; nothing that freezes the working name](./035-distribution-is-a-checksummed-tarball-an-installer.md) *(2026-07-21)*
- [036. AGENTS.md is the canonical operating manual, the dotfile is retired](./036-agents-md-is-the-canonical-operating-manual.md) *(2026-07-21)*
