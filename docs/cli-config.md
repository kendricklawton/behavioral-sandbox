# Configuration of `bsx`

Configuration layers **flags > environment (`BSX_*`) > project file > user file > defaults**.

There are **two files, and they are not read with the same authority**:

- The **user file** is `~/.bsx.toml`, read whatever directory you run from, and it may set every key
  on this page. `install.sh` writes one for you.
- The **project file** is the nearest `.bsx.toml` walking up from the current directory (the
  `.gitignore` convention), so a project pins its **limits** beside its code. It may set the house
  defaults, the ceilings, and the postures, and nothing else.

A file found above the working directory can arrive with the code it configures: clone a repository
and its `.bsx.toml` comes with it. So the keys that name a binary this host executes, an image it
boots, a key it signs or verifies with, a directory it writes into, or the identity a VMM drops to
are read from the user file, the environment, or a flag. Each key below says which. A project file
that names one is [refused](#a-project-file-that-reaches-past-its-keys), not quietly ignored.

Every `## Setting` section names its **file** line accordingly: `~/.bsx.toml` for a user-only key,
`any .bsx.toml` for one either file may set.

The file uses the [toml] format, and an **unknown key is a typed error, never a silent no-op**. Its
keys come in two kinds: the artifact and scratch keys mirror the environment names, minus the `BSX_`
prefix and lowercased, while the [operator policy] keys have no `BSX_*` mirror and sit outside the
precedence above, because a ceiling its bounded party can override is not a ceiling.

All settings are **optional**. If a setting is not specified, the **default** value is used. *Thus, if
you don't know what value to use, don't specify it.* The defaults might be tuned in the future.

Example user config:

```toml
# ~/.bsx.toml: this host's own paths
kernel = "/srv/bsx/vmlinux"
rootfs = "/srv/bsx/rootfs-guest.ext4"
marker = "GUEST-READY"
log = "info"
```

Example project config:

```toml
# .bsx.toml: pinned beside a project's code
vcpus = 2
mem_mib = 512
max_wall_secs = 60
require_record = true
```

**What is deliberately not a knob.** The read-only base plus per-run tmpfs overlay, bulk read-only
input via a second block device, and bulk writable output via a third (pulled back with
`RunningVm::collect_outputs`) are per-VM boot inputs a caller sets on `BootConfig`, not layered
config. There is no `BSX_READONLY`, `BSX_INPUT`, or `BSX_OUTPUT` to go looking for; the reasoning
is in [Architecture and design](./architecture.md).

[toml]: https://toml.io/
[operator policy]: #operator-policy

---

## Setting `firecracker`

- **env**: `BSX_FIRECRACKER`
- **file**: `~/.bsx.toml` only
- **type**: string (path or command name)
- **default**: `firecracker` (resolved on `PATH`)

The Firecracker binary the engine drives. The engine does not bundle it, so an upstream security patch
never waits on a release of this engine. v1.15 through v1.16 are supported and v1.16.1 is the pinned,
tested, hash-verified release; [`bsx doctor`](./cli-commands.md#bsx-doctor) reports both the version
and whether the binary's sha256 matches the pin.

[`firecracker`]: #setting-firecracker

## Setting `kernel`

- **env**: `BSX_KERNEL`
- **file**: `~/.bsx.toml` only
- **type**: string (path)
- **default**: `artifacts/vmlinux`

The guest kernel image to boot. Fetch one with `cargo xtask fetch-artifacts`, or point this at your
own. A missing kernel is a hard failure, not a degradation: there is nothing to boot.

[`kernel`]: #setting-kernel

## Setting `rootfs`

- **env**: `BSX_ROOTFS`
- **file**: `~/.bsx.toml` only
- **type**: string (path)
- **default**: `artifacts/rootfs-guest.ext4`

The guest root filesystem image. `cargo xtask build-rootfs` builds one reproducibly, with the static
`guest-agent` baked in; the default image carries `python3` and `node`. A read-only base is shared
across sandboxes, with a writable overlay per run, so nothing a run changes outlives it unless
explicitly collected.

[`rootfs`]: #setting-rootfs

## Setting `marker`

- **env**: `BSX_MARKER`
- **file**: any `.bsx.toml`
- **type**: string
- **default**: `GUEST-READY`

The console line that means "userspace is up", which ends the boot wait. The default is the guest
rootfs image's own ready sentinel. A foreign rootfs needs its own marker, for example its `login:`
prompt.

[`marker`]: #setting-marker

## Setting `scratch_dir`

- **env**: `BSX_SCRATCH_DIR`
- **file**: `~/.bsx.toml` only
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

- **env**: `BSX_LOG`
- **file**: any `.bsx.toml`
- **type**: string (`tracing` filter syntax)
- **default**: `warn`

The stderr log filter, for example `info` or `debug`. Logs go to stderr and only there (the one
`tracing` subscriber is initialized with a stderr writer), so
`bsx run … 2>/dev/null` stays pipe-clean. The `--log` flag overrides this per run. A filter
`tracing` cannot parse is refused up front, the same loudness as a mistyped key in this file; a
bare unknown word is not that case, since the filter grammar reads it as a target name.

[`log`]: #setting-log

## Setting `require_limits`

- **env**: `BSX_REQUIRE_LIMITS`
- **file**: any `.bsx.toml`
- **type**: boolean
- **default**: `false`

Fail closed when the cpu/memory cgroup caps can't be applied, instead of the default warn-and-boot-
uncapped. This makes the resource envelope load-bearing, which is the inverse of the default fail-open
posture (caps are a denial-of-service mitigation, not the isolation boundary).

Needs the jailer, so it is incompatible with `--unjailed`, and needs delegated cgroup v2 controllers.
The `--require-limits` flag sets it per run.

[`require_limits`]: #setting-require_limits

## Setting `jail_uid` and `jail_gid`

- **env**: `BSX_JAIL_UID`, `BSX_JAIL_GID`
- **file**: `~/.bsx.toml` only
- **type**: integer (a non-zero uid/gid)
- **default**: `10000` for both

The id the jailer switches to after building the chroot. Pick one that owns nothing else on the
host: the jailer chowns the chroot to it, so it needs no `/etc/passwd` entry.

**This is the operator's setting and never a caller's.** Every sandbox one engine starts shares it,
and so does a second `bsx serve` left at the default, so two daemons meant to separate tenants need
different ids. Processes sharing a uid can signal each other, so a guest that escaped into its own
VMM would land beside its neighbours' VMMs at the same id (`ptrace` between them is additionally
gated by Yama, which `bsx doctor` reports). Nothing on the daemon's wire protocol carries an id, by
design: a client that could name its own could name a neighbour's.

`0` is refused. It is the id the jail exists to leave, and a jailed boot that stayed root would drop
nothing. The `--jail-uid` / `--jail-gid` flags set it per run on `bsx run`, `bsx shell`, and
`bsx serve`.

[`jail_uid`]: #setting-jail_uid-and-jail_gid

## Setting `gateway` and `resolver`

- **env**: `BSX_GATEWAY`, `BSX_RESOLVER`
- **file**: `~/.bsx.toml` only
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

- **env**: `BSX_SIGNING_KEY`
- **file**: `~/.bsx.toml` only
- **type**: string (path)
- **default**: a path under the data directory, generated on first use

The host `ed25519` key that signs finalized audit records. The key stays in the host process; what
reaches anything guest-visible is the detached signature. A record's
`key_id` names the key that signed it, and key custody and rotation are the hoster's responsibility.
See [`bsx verify`](./cli-commands.md#bsx-verify).

[`signing_key`]: #setting-signing_key

## Setting `trusted_keys`

- **env**: `BSX_TRUSTED_KEYS`
- **file**: `~/.bsx.toml` only
- **type**: array of 64-hex public keys in the file (`trusted_keys = ["aa..", "bb.."]`);
  comma-separated in the environment variable
- **default**: empty

Additional public keys `bsx verify` should trust, alongside the current signing key and any `--key`
given on the command line. Keep retired public keys listed here so rotating the host key does not
invalidate records already signed.

[`trusted_keys`]: #setting-trusted_keys

## Setting `BSX_PROBES_OBJECT`

- **env**: `BSX_PROBES_OBJECT` (**environment only**, no `.bsx.toml` key)
- **type**: string (path)
- **default**: the `cargo xtask build-probes` output, else the installed copy under the data directory

An override for the built eBPF object, rarely needed. Deliberately env-only: it is a build-tree detail
rather than project configuration.

[`BSX_PROBES_OBJECT`]: #setting-bsx_probes_object

## Setting `BSX_LOG_FORMAT`

- **env**: `BSX_LOG_FORMAT` (**environment only**, daemon-scoped)
- **type**: `json`
- **default**: human-readable

Switches `bsx serve`'s stderr logs to JSON encoding (`--log-json` is the per-launch flag form);
the one-shot commands do not read it. The daemon's log fields are documented in
[Observability for the hoster](./daemon-observability.md).

[`BSX_LOG_FORMAT`]: #setting-bsx_log_format

---

## Operator policy

A second group of `.bsx.toml` keys sets the **host's** posture rather than a per-run knob. These have
**no `BSX_*` mirror** and deliberately sit outside the flags > env > file precedence: a ceiling whose
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
- **file**: any `.bsx.toml`
- **type**: integer

The house profile used when a caller does not ask. The engine's own defaults are 1 vCPU, 256 MiB, a
30-second wall budget, and a 16 MiB output cap.

`vcpus` takes the same rule as `--vcpus`: **1 or an even number up to 32**, which is what Firecracker
accepts. A file naming anything else is a parse error saying so, rather than a value carried to boot
and refused there.

## Setting the ceilings

- **keys**: `max_vcpus`, `max_mem_mib`, `max_wall_secs`, `max_output_cap`
- **kind**: ceiling
- **file**: any `.bsx.toml`
- **type**: integer

Bounds what a caller may ask for. Ceilings and defaults compose differently, and the difference is
whether a caller actually asked:

- **An explicit request above a ceiling is refused**, naming the knob, the ask, and the bound. Silently
  serving less would be an unexpected degradation.
- **A default above a ceiling is clamped.** Nobody asked for it, so there is nothing to contradict.
  This is what lets you set only `max_wall_secs = 10` without refusing every bare run, since the
  engine's own default is 30 seconds.

That clamp is why `max_vcpus` takes the 1-or-even rule too, not just `vcpus`: `vcpus = 8` under
`max_vcpus = 7` would resolve to 7, and the boot would then be refused for a count you never wrote.

## Setting the egress ceilings

- **keys**: `max_egress_v4`, `max_egress_v6`
- **kind**: ceiling
- **file**: any `.bsx.toml`
- **type**: array of CIDR strings (`max_egress_v4 = ["10.0.0.0/8"]`)

Bounds what `--allow` may name: every requested rule must fall inside one of the listed CIDRs, and a
rule outside them is refused, naming the rule and the ceiling, rather than trimmed to fit. A
malformed entry fails the whole file at parse time, so a typo'd ceiling reads as a config error
rather than a silently absent bound. Empty (the default) bounds nothing.

## Setting `require_jail`

- **kind**: posture
- **file**: any `.bsx.toml`
- **type**: boolean
- **default**: `false`

Withdraws the `--unjailed` opt-out on this host, so every run gets the jailer.

[`require_jail`]: #setting-require_jail

## Setting `allow_net`

- **kind**: posture
- **file**: any `.bsx.toml`
- **type**: boolean
- **default**: `true`

`false` refuses `--net` outright. Note that a NIC already gets deny-by-default egress, so this is a
stronger statement than the default posture: no guest networking at all.

[`allow_net`]: #setting-allow_net

## Setting `require_record`

- **kind**: posture
- **file**: any `.bsx.toml`
- **type**: boolean
- **default**: `false`

Refuses any run that would leave no audit record, including [`bsx shell`](./cli-commands.md#bsx-shell),
which cannot record. Satisfied on its own by [`records_dir`](#setting-records_dir). A
`--record-summary` alone does not satisfy it: the summary is an unsigned projection of the record,
not the record, so a summary-only run still refuses
(`require_record_refuses_a_run_that_would_leave_no_audit_record` pins this).

[`require_record`]: #setting-require_record

## Setting `records_dir`

- **kind**: default
- **file**: `~/.bsx.toml` only
- **type**: string (path)

Every `run` writes its signed record there, as `run-<secs>-<pid>.json`, unless `--record` names a
path.

[`records_dir`]: #setting-records_dir

---

## Which `~/.bsx.toml` is read

The user file names the binary this host executes, the images it boots, and the key it signs records
with, so on a shared host it is read only when its author could have been you. It is refused when:

- **it is owned by another local user** (or is a symlink another user owns, since the link chooses
  which file gets read). Your own uid, `root`, and, under `sudo`, the invoking user all count as you.
- **it is group- or world-writable** (`chmod go-w` it). Read bits are fine: `0o644`, what an editor
  writes under the usual umask, is admitted. This file's contents are paths and ceilings, already
  visible in `ps`, so what matters is who can change it, not who can see it.
- **its directory is owned by another user, or is group/world-writable without the sticky bit.** A
  directory someone else can write lets them replace the file whatever its own mode says. `/tmp` and
  friends at `0o1777` are fine, because the sticky bit stops one user unlinking another's file.

Under `sudo` the invoking user is read from `SUDO_UID`, and only when the real and effective uid are
both `0`, which is the state `sudo` produces. `su -` clears the environment and `doas` sets a name
rather than a uid, so a root shell obtained either way does not adopt your uid and reads your config
as another user's. Pass the paths with `BSX_*` there, or run under `sudo -E`.

The project file gets no such check. It carries only knobs and postures, so gating it would refuse
every `0o664` file a developer on `umask 002` writes, for nothing.

## A project file that reaches past its keys

Setting a user-only key in a project file is a refusal, before any boot, naming the key and where it
may live:

```console
$ cd /srv/work && bsx run -- true
bsx: /srv/work/.bsx.toml: `kernel` is read from /home/you/.bsx.toml or BSX_KERNEL, not from a file
found above the working directory, because such a file can arrive with the code it configures.
Remove `kernel` from this file, or set it in /home/you/.bsx.toml.
```

Refused rather than ignored, for the same reason a misspelled key is: this file's contract is that
what you wrote either takes effect or says why not. Dropping a correctly spelled, documented key
while a typo fails loudly would be the inconsistency. Nothing is lost to an attacker either way,
since whoever can plant that file can already stop the run with one malformed byte.

`a_project_file_naming_a_user_only_key_is_refused_before_any_boot` pins the refusal, and
`the_user_file_supplies_artifact_paths_when_a_project_file_shadows_it` pins the half that makes it
usable: a project file does not take your `~/.bsx.toml` down with it.

## When two files set the same knob

The project file is nearer, but nearer does not mean freer. It wins outright only for the keys that
carry no posture (`marker`, `log`, and the house defaults, which a caller could pass on the command
line anyway). For the rest, the two compose so that the result is never weaker than either file
alone:

| Key | Result |
|---|---|
| `max_vcpus`, `max_mem_mib`, `max_wall_secs`, `max_output_cap` | the smaller of the two |
| `require_jail`, `require_record`, `require_limits` | on if either says on |
| `allow_net` | `false` if either says `false` |
| `max_egress_v4`, `max_egress_v6` | the user file's list binds; a project list applies only where the user set none |

The egress rule is deliberately not an intersection. Filtering a project list against a narrower user
list can yield the empty list, and an empty list means *no restriction*, so a merge meant to tighten
would have removed the ceiling entirely (`a_project_egress_ceiling_does_not_replace_the_user_ceiling`).

## Where this is enforcement, and where it is a guardrail

Three tiers, not two.

**Your own `~/.bsx.toml` is a guardrail.** You wrote it, so the ceilings in it bound you at your own
request, and [Security](./security.md#what-is-not-a-security-bug) treats a caller harming themselves
as misuse rather than a vulnerability.

**A project `.bsx.toml` is not necessarily yours**, which is why the keys that reach host execution
and host trust are not read from one, and why the keys that are read from one can only tighten what
your own file already said.

**The real boundary is [`bsx serve`](./daemon.md)**, whose clients control neither the daemon's config
nor its environment. It therefore takes its ceilings as **explicit flags** (the per-run `--max-vcpus`,
`--max-mem-mib`, `--max-wall-secs`, `--max-output-cap`, plus the daemon-wide `--max-sessions` and
committed-resource ceilings) and reads no `.bsx.toml` at all, neither layer: a daemon must not read a
security control out of whatever directory it happened to be started in.
