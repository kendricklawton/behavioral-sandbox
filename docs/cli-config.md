# Configuration of `ekvm`

Configuration layers **flags > environment (`EKVM_*`) > file (`.ekvm.toml`) > defaults**. The file
layer is the nearest `.ekvm.toml` walking up from the current directory (the `.gitignore` convention),
so a project pins its engine config beside its code.

The file uses the [toml] format. Its keys mirror the environment names 1:1, minus the `EKVM_` prefix
and lowercased, and an **unknown key is a typed error, never a silent no-op**.

All settings are **optional**. If a setting is not specified, the **default** value is used. *Thus, if
you don't know what value to use, don't specify it.* The defaults might be tuned in the future.

Example config:

```toml
# .ekvm.toml: pinned beside a project's code
kernel = "/srv/ekvm/vmlinux"
rootfs = "/srv/ekvm/rootfs-guest.ext4"
marker = "GUEST-READY"
log = "info"
```

[toml]: https://toml.io/
[operator policy]: #operator-policy

---

## Setting `firecracker`

- **env**: `EKVM_FIRECRACKER`
- **type**: string (path or command name)
- **default**: `firecracker` (resolved on `PATH`)

The Firecracker binary the engine drives. The engine does not bundle it, so an upstream security patch
never waits on a release of this engine. v1.15 through v1.16 are supported and v1.16.1 is the pinned,
tested, hash-verified release; [`ekvm doctor`](./cli-commands.md#ekvm-doctor) reports both the version
and whether the binary's sha256 matches the pin.

[`firecracker`]: #setting-firecracker

## Setting `kernel`

- **env**: `EKVM_KERNEL`
- **type**: string (path)
- **default**: `artifacts/vmlinux`

The guest kernel image to boot. Fetch one with `cargo xtask fetch-artifacts`, or point this at your
own. A missing kernel is a hard failure, not a degradation: there is nothing to boot.

[`kernel`]: #setting-kernel

## Setting `rootfs`

- **env**: `EKVM_ROOTFS`
- **type**: string (path)
- **default**: `artifacts/rootfs-guest.ext4`

The guest root filesystem image. `cargo xtask build-rootfs` builds one reproducibly, with the static
`guest-agent` baked in; the default image carries `python3` and `node`. A read-only base is shared
across sandboxes, with a writable overlay per run, so nothing a run changes outlives it unless
explicitly collected.

[`rootfs`]: #setting-rootfs

## Setting `marker`

- **env**: `EKVM_MARKER`
- **type**: string
- **default**: `GUEST-READY`

The console line that means "userspace is up", which ends the boot wait. The default is the guest
rootfs image's own ready sentinel. A foreign rootfs needs its own marker, for example its `login:`
prompt.

[`marker`]: #setting-marker

## Setting `scratch_dir`

- **env**: `EKVM_SCRATCH_DIR`
- **type**: string (path)
- **default**: `/tmp`, or `/var/tmp` when `/tmp` is unusable (see below)

Base directory for per-VM scratch: rootfs copies, the jailer's chroot, and API sockets.

Two things to know. First, `/tmp` is often tmpfs, which is host RAM, so point this at real disk on a
small host. Second, a **jailed** boot builds its chroot here, which means it needs a filesystem
mounted neither `nodev` (which makes the chroot's `/dev/kvm` node inert) nor `noexec` (which refuses
the exec of the chrooted `firecracker` copy). systemd mounts `/tmp` `nodev` by default and hardened
baselines add `noexec`, so the engine falls back to `/var/tmp` when it detects either, the guided
install pins a usable path for you, and a jailed boot on a bad mount is refused with a typed error
naming the flag rather than failing deep in boot.

Keep the path **short**: the jailer nests the per-VM directory name twice inside the API socket path,
which the kernel caps at roughly 108 bytes.

[`scratch_dir`]: #setting-scratch_dir

## Setting `log`

- **env**: `EKVM_LOG`
- **type**: string (`tracing` filter syntax)
- **default**: `warn`

The stderr log filter, for example `info` or `debug`. Logs go to stderr and only there (the one
`tracing` subscriber is initialized with a stderr writer), so
`ekvm run … 2>/dev/null` stays pipe-clean. The `--log` flag overrides this per run.

[`log`]: #setting-log

## Setting `require_limits`

- **env**: `EKVM_REQUIRE_LIMITS`
- **type**: boolean
- **default**: `false`

Fail closed when the cpu/memory cgroup caps can't be applied, instead of the default warn-and-boot-
uncapped. This makes the resource envelope load-bearing, which is the inverse of the default fail-open
posture (caps are a denial-of-service mitigation, not the isolation boundary).

Needs the jailer, so it is incompatible with `--unjailed`, and needs delegated cgroup v2 controllers.
The `--require-limits` flag sets it per run.

[`require_limits`]: #setting-require_limits

## Setting `gateway` and `resolver`

- **env**: `EKVM_GATEWAY`, `EKVM_RESOLVER`
- **type**: IPv4 address
- **default**: unset (the guest gets no default route and no nameserver)

The default route this host hands its guests, and the resolver it tells them to use. Which uplink a
host has is a host fact rather than a per-run one, which is why these live here; `--gateway` and
`--resolver` override them per run.

`gateway` must be on the guest's own link, which the shipped `/30` narrows to exactly one usable
value: `10.200.0.1`, the host end of the tap. A networked boot refuses anything else up front, since
the guest could not ARP it and would come up sealed. It stays inert on a boot that asks for no NIC,
so setting it host-wide does not disturb runs that want no networking.

Setting a gateway does not build a path. The engine adds no veth, bridge, forwarding, or NAT, so
where nothing has furnished the per-VM netns the guest still reaches nothing. What it changes is
that the guest can emit those packets, so `--allow` can bound them and the audit record can show
them: the observable set widens even where the reachable set does not. Building the uplink and
allocating the addresses it needs is the hoster's, per
[decision 9](./architecture-decisions.md#9-egress-is-enabled-by-the-engine-constructed-by-the-hoster).

`resolver` is only read when a gateway is set, since a resolver the guest cannot route to is inert,
and reaching it still needs its own `--allow`. A value that is not an IPv4 address is ignored with a
warning naming the key, so a typo reads as a misconfiguration rather than as a broken engine.

[`gateway`]: #setting-gateway-and-resolver
[`resolver`]: #setting-gateway-and-resolver

## Setting `signing_key`

- **env**: `EKVM_SIGNING_KEY`
- **type**: string (path)
- **default**: a path under the data directory, generated on first use

The host `ed25519` key that signs finalized audit records. The key stays in the host process; what
reaches anything guest-visible is the detached signature. A record's
`key_id` names the key that signed it, and key custody and rotation are the hoster's responsibility.
See [`ekvm verify`](./cli-commands.md#ekvm-verify).

[`signing_key`]: #setting-signing_key

## Setting `trusted_keys`

- **env**: `EKVM_TRUSTED_KEYS`
- **type**: array of 64-hex public keys in the file (`trusted_keys = ["aa..", "bb.."]`);
  comma-separated in the environment variable
- **default**: empty

Additional public keys `ekvm verify` should trust, alongside the current signing key and any `--key`
given on the command line. Keep retired public keys listed here so rotating the host key does not
invalidate records already signed.

[`trusted_keys`]: #setting-trusted_keys

## Setting `EKVM_PROBES_OBJECT`

- **env**: `EKVM_PROBES_OBJECT` (**environment only**, no `.ekvm.toml` key)
- **type**: string (path)
- **default**: the `cargo xtask build-probes` output, else the installed copy under the data directory

An override for the built eBPF object, rarely needed. Deliberately env-only: it is a build-tree detail
rather than project configuration.

[`EKVM_PROBES_OBJECT`]: #setting-ekvm_probes_object

## Setting `EKVM_LOG_FORMAT`

- **env**: `EKVM_LOG_FORMAT` (**environment only**, daemon-scoped)
- **type**: `json`
- **default**: human-readable

Switches `ekvm serve`'s stderr logs to JSON encoding (`--log-json` is the per-launch flag form);
the one-shot commands do not read it. The daemon's log fields are documented in
[Observability for the hoster](./daemon-observability.md).

[`EKVM_LOG_FORMAT`]: #setting-ekvm_log_format

---

## Operator policy

A second group of `.ekvm.toml` keys sets the **host's** posture rather than a per-run knob. These have
**no `EKVM_*` mirror** and deliberately sit outside the flags > env > file precedence: a ceiling whose
bounded party can override it is not a ceiling.

```toml
# a shared host: 4 vCPU / 1 GiB ceiling, jail mandatory, no guest networking
max_vcpus = 4
max_mem_mib = 1024
require_jail = true
allow_net = false
```

## Setting the house defaults

- **keys**: `vcpus`, `mem_mib`, `wall_secs`, `output_cap`
- **kind**: default
- **type**: integer

The house profile used when a caller does not ask. The engine's own defaults are 1 vCPU, 256 MiB, a
30-second wall budget, and a 16 MiB output cap.

## Setting the ceilings

- **keys**: `max_vcpus`, `max_mem_mib`, `max_wall_secs`, `max_output_cap`
- **kind**: ceiling
- **type**: integer

Bounds what a caller may ask for. Ceilings and defaults compose differently, and the difference is
whether a caller actually asked:

- **An explicit request above a ceiling is refused**, naming the knob, the ask, and the bound. Silently
  serving less would be an unexpected degradation.
- **A default above a ceiling is clamped.** Nobody asked for it, so there is nothing to contradict.
  This is what lets you set only `max_wall_secs = 10` without refusing every bare run, since the
  engine's own default is 30 seconds.

## Setting the egress ceilings

- **keys**: `max_egress_v4`, `max_egress_v6`
- **kind**: ceiling
- **type**: array of CIDR strings (`max_egress_v4 = ["10.0.0.0/8"]`)

Bounds what `--allow` may name: every requested rule must fall inside one of the listed CIDRs, and a
rule outside them is refused, naming the rule and the ceiling, rather than trimmed to fit. A
malformed entry fails the whole file at parse time, so a typo'd ceiling reads as a config error
rather than a silently absent bound. Empty (the default) bounds nothing.

## Setting `require_jail`

- **kind**: posture
- **type**: boolean
- **default**: `false`

Withdraws the `--unjailed` opt-out on this host, so every run gets the jailer.

[`require_jail`]: #setting-require_jail

## Setting `allow_net`

- **kind**: posture
- **type**: boolean
- **default**: `true`

`false` refuses `--net` outright. Note that a NIC already gets deny-by-default egress, so this is a
stronger statement than the default posture: no guest networking at all.

[`allow_net`]: #setting-allow_net

## Setting `require_record`

- **kind**: posture
- **type**: boolean
- **default**: `false`

Refuses any run that would leave no audit record, including [`ekvm shell`](./cli-commands.md#ekvm-shell),
which cannot record. Satisfied on its own by [`records_dir`](#setting-records_dir).

[`require_record`]: #setting-require_record

## Setting `records_dir`

- **kind**: default
- **type**: string (path)

Every `run` writes its signed record there, as `run-<secs>-<pid>.json`, unless `--record` names a
path.

[`records_dir`]: #setting-records_dir

---

## Where this is enforcement, and where it is a guardrail

For the CLI this is a **guardrail**: a local caller owns this file, and
[Security](./security.md#what-is-not-a-security-bug) already treats them as trusted.

The real boundary is [`ekvm serve`](./daemon.md), whose clients control neither the daemon's config nor
its environment. It therefore takes its ceilings as **explicit flags** (the per-run `--max-vcpus`,
`--max-mem-mib`, `--max-wall-secs`, `--max-output-cap`, plus the daemon-wide `--max-sessions` and
committed-resource ceilings) rather than from a discovered file: a daemon must not read a
security control out of whatever directory it happened to be started in.
