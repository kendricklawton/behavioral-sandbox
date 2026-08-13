//! Boot a Firecracker microVM and read its serial console, the raw VM lifecycle beneath
//! [`crate::Sandbox`].
//!
//! [`Vm::boot`] spawns a `firecracker` child, drives its API socket through the boot sequence
//! (boot-source → root drive → machine-config → `InstanceStart`), and waits until the guest's
//! serial console shows it reached userspace. [`RunningVm`] owns the running child; dropping it, or
//! calling [`RunningVm::shutdown`], kills the VMM and reclaims its scratch dir, and the
//! cgroup-owned lifetime covers the paths `Drop` never runs on.
//!
//! **Host path only, `unsafe`-free.** Firecracker wires the guest's `ttyS0` to its own stdout, so
//! "read the child's stdout" is "read the guest console". The jailer ([`Jail`],
//! [`BootConfig::jail`]) is not run with `--daemonize`, so Firecracker keeps the piped stdout and
//! the console still reaches [`Console`].

use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::{NonZeroU8, NonZeroU32};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

use bsx_channel::ClientConnection;

use crate::console::Console;
use crate::drives::{OutputDevice, collect_output_image};
use crate::exec::{
    EXEC_KILL_SLACK, ExecBounds, PROBE_TIMEOUT, VSOCK_TIMEOUT, connect_agent_at,
    connect_agent_bounded, connect_agent_once, run_exec,
};
use crate::firecracker::{Action, ApiClient};
use crate::jail::{Chroot, Jail, remove_cgroup};
use crate::lifetime::{KillHandle, VmLifetime};
use crate::net::{GuestEgress, GuestLink, Tap};
use crate::spawn::Spawned;
use crate::{Limits, RunResult, VmmError};

/// Kernel command line for the guest. `console=ttyS0` puts its console on the serial port (which
/// Firecracker hands to our stdout); `reboot=k panic=1` make a guest panic/reboot exit the VMM
/// promptly; `pci=off` trims an unused bus; `random.trust_cpu=on` avoids an entropy stall at boot.
/// `quiet` is console loglevel 4, so informational printk stays off the serial console (every byte
/// there is a VM exit) while kernel errors and a panic (level 3 and below) still reach the console
/// tail; both userspace markers (the agent's `GUEST-READY`, a getty's `login:`) are direct tty
/// writes, not printk. `clocksource=kvm-clock` pins the paravirtual clocksource: the kernel
/// otherwise demotes kvm-clock below raw `tsc` on any invariant-TSC host, and a TSC-read clock is
/// frozen state Firecracker restores as-is, so the `clock_realtime` fix-up on `PUT /snapshot/load`
/// would land on a clock the guest never reads. Only kvm-clock lets a restored clone's wall clock
/// advance across the snapshot's age (pinned by the privileged
/// `restored_clones_do_not_share_entropy_or_freeze_the_clock` test); reads stay vmexit-free either
/// way. IPv6 boots **enabled**: the network is dual-stack and both families are deny-by-default,
/// the v6 address arriving through the `guest_ip6=` token `spawn.rs` appends (the kernel `ip=`
/// param is v4-only) with no v6 default route. Firecracker adds `root=/dev/vda` itself.
const DEFAULT_BOOT_ARGS: &str =
    "console=ttyS0 reboot=k panic=1 pci=off random.trust_cpu=on quiet clocksource=kvm-clock";

/// Substring that marks the guest reached userspace: the agent rootfs's ready sentinel, printed by
/// `guest-agent` once its vsock listener accepts. The pinned Ubuntu CI rootfs (raw boot tests only)
/// signals readiness with its getty prompt instead, so those callers set `login:` via `BSX_MARKER`.
const DEFAULT_USERSPACE_MARKER: &str = bsx_channel::GUEST_READY_MARKER;

/// Names the next per-VM scratch dir uniquely within this process (paired with the PID).
pub(crate) static VM_SEQ: AtomicU64 = AtomicU64::new(0);

/// Firecracker's own stderr, captured to a file in the scratch dir (see `Spawned::launch`).
pub(crate) const FC_STDERR: &str = "fc.stderr";

/// The vsock context id the guest gets (the host is always cid 2). The default when a boot enables
/// the exec channel; overridable per-VM via [`BootConfig::guest_cid`].
pub const DEFAULT_GUEST_CID: u32 = 3;

/// The vsock port the in-guest agent listens on for exec connections, a host↔guest contract value
/// defined in `bsx-channel` (the rootfs build writes it into the guest's init line).
pub use bsx_channel::VSOCK_PORT;

/// The vsock unix socket Firecracker creates in the scratch dir; the host connects here and speaks
/// the `CONNECT <port>` handshake to reach a guest port.
pub(crate) const VSOCK_UDS: &str = "v.sock";

/// The Firecracker id for the guest's single virtio-net device. `PUT /network-interfaces/{id}` must
/// carry the same id in its path and body, so both come from here. The `eth0` in the `ip=` boot arg
/// is the guest kernel's own enumeration, a different namespace, so it is not sourced from here.
pub(crate) const IFACE_ID: &str = "eth0";

/// How long a graceful `SendCtrlAltDel` power-off is given to land before teardown stops waiting
/// (the unconditional kill in `Drop`/`stop_and_reap` takes over), and how often that wait polls.
pub(crate) const POWER_OFF_TIMEOUT: Duration = Duration::from_secs(3);

/// How long a SIGKILLed VMM is given to be reaped before teardown detaches it and moves on
/// (`drives::kill_and_reap_briefly`). Longer than the helper grace, since this is every VM's normal
/// teardown and must not give up on a merely-busy host (a multi-vCPU Firecracker under `cpu.max`
/// still needs CPU to finish dying), but bounded so `Drop` never parks behind a process in
/// uninterruptible sleep, where no signal lands and `wait` never returns. Detaching leaves the VMM
/// **unreaped** (a zombie holding a pid slot until this process exits), not running.
pub(crate) const VMM_REAP_GRACE: Duration = Duration::from_secs(2);
pub(crate) const POWER_OFF_POLL: Duration = Duration::from_millis(50);

/// Everything needed to boot one microVM. [`default`](BootConfig::default) is the pure pinned
/// baseline, [`from_env`](BootConfig::from_env) layers the `BSX_*` overrides on top, and
/// [`with_limits`](BootConfig::with_limits) folds a [`Limits`] budget onto the resource knobs.
/// `#[non_exhaustive]`: construct through one of those and mutate fields.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BootConfig {
    /// The `firecracker` binary (name resolved via `PATH`, or an absolute path).
    pub firecracker: PathBuf,
    /// Uncompressed guest kernel image (an ELF/PVH `vmlinux`, not a `bzImage`).
    pub kernel: PathBuf,
    /// The base rootfs. A read-write boot runs against a fresh per-VM copy; a
    /// [`read_only_root`](BootConfig::read_only_root) boot shares it directly (see [`Vm::boot`]).
    pub rootfs: PathBuf,
    /// Guest vCPUs. Typed [`NonZeroU8`] like [`Limits::vcpus`], so a zero-vCPU boot can't be
    /// configured.
    pub vcpus: NonZeroU8,
    /// Guest memory, MiB. Typed [`NonZeroU32`] like [`Limits::mem_mib`].
    pub mem_mib: NonZeroU32,
    /// The guest kernel command line.
    pub boot_args: String,
    /// Console substring that signals userspace was reached.
    pub userspace_marker: String,
    /// Upper bound on boot-to-userspace before the boot is a typed timeout.
    pub boot_timeout: Duration,
    /// Wall-clock budget for each command run through this VM's `exec`: the guest agent kills the
    /// command past it, and the host's give-up deadline is derived from it. The split from
    /// `boot_timeout` lets a driver-level caller give boot and exec different ceilings;
    /// [`with_limits`](BootConfig::with_limits) folds one [`Limits::wall`] into both. See
    /// [`Limits::wall`] for the semantics, including the nonzero requirement.
    pub exec_wall: Duration,
    /// Aggregate byte cap on what the host buffers per exec (stdout + stderr + artifacts), folded
    /// from [`Limits::output_cap`].
    pub output_cap: usize,
    /// Configure a virtio-vsock device with this guest context id, enabling the exec channel
    /// ([`RunningVm::connect_agent`]). `None` (the default) boots with no vsock, the boot-only demo
    /// path; `Some(`[`DEFAULT_GUEST_CID`]`)` enables exec.
    pub guest_cid: Option<u32>,
    /// Boot the base rootfs **read-only and shared** (no per-VM copy) under a per-run **tmpfs
    /// overlay**, so `/` is writable but the base is never mutated and many VMs share one
    /// page-cache-deduped base. Requires a rootfs whose [`bsx_channel::GUEST_OVERLAY_INIT`] builds
    /// the overlay (the agent image from `cargo xtask build-rootfs`), and the driver appends
    /// `init=<that path> overlay_size=<mem/2>M` to the kernel command line: a read-only base
    /// *implies* the overlay, since a read-only `/` would break the agent's `/tmp` workdir.
    /// `false` (the default) keeps the copy-then-boot-read-write path.
    pub read_only_root: bool,
    /// A host directory to inject as **bulk read-only input**: the driver builds an ext4 from it
    /// and attaches it as a second block device (`/dev/vdb`, `O_RDONLY`) that the guest rootfs
    /// mounts at `/input`. The whole-working-dir / large-file path, where the vsock channel's
    /// [`Request::PutFile`](bsx_channel::Request::PutFile) carries only small per-frame files.
    /// `None` (the default) attaches no input device. Building the image needs `mke2fs` +
    /// `truncate`.
    pub input_dir: Option<PathBuf>,
    /// A host directory to receive **bulk output**: the driver attaches a blank, **writable** ext4
    /// as a third block device (`/dev/vd?`, labelled `bsx-output`) that the guest rootfs mounts
    /// read-write at `/output`, and [`RunningVm::collect_outputs`] pulls the tree back here. The
    /// bulk counterpart to the vsock channel's per-frame
    /// [`Response::File`](bsx_channel::Response::File) artifacts. `None` (the default) attaches no
    /// output device. Readback parses the image in-process, so it needs no host tool; the directory
    /// is created if missing, and host-escaping symlinks are dropped.
    pub output_dir: Option<PathBuf>,
    /// Give the guest a **virtio-net** interface backed by a per-VM host **tap** device. The driver
    /// creates the tap (`ip tuntap`, needs `CAP_NET_ADMIN` and `ip` from iproute2), attaches it via
    /// `PUT /network-interfaces`, and deletes it on teardown. `false` (the default) boots with **no
    /// NIC**, deny-by-default. Even when `true`, this box adds no address, route, or masquerade of
    /// its own, so the guest reaches nothing until addressing lands.
    pub enable_network: bool,
    /// Hand the guest a default route (and optionally a resolver) so it can address traffic beyond
    /// the host end of its /30. `None` (the default) leaves the gateway field of the guest's `ip=`
    /// parameter empty, so the guest installs its connected route and nothing else and an off-link
    /// destination fails with `ENETUNREACH` before a packet is emitted. Setting it names a path
    /// rather than building one (no veth, bridge, forwarding, or NAT): see [`GuestEgress`] and
    /// design decision 9. **Read only when [`enable_network`](BootConfig::enable_network) is set**,
    /// ignored otherwise rather than refused, since a gateway is a host fact set once for every
    /// sandbox. **Applies at cold boot only**: the addressing rides the kernel command line, which
    /// a restored clone inherits from the snapshot, so this is inert on [`Vm::restore`].
    pub egress: Option<GuestEgress>,
    /// Run Firecracker under its **jailer**: a chroot, a uid/gid drop, and the jailer's mount
    /// namespace confine the VMM process itself (see [`Jail`]). `None` (the default) spawns
    /// Firecracker directly. Setting it needs **real root** (the jailer `mknod`s device nodes,
    /// which `EPERM` in a non-initial user namespace) and the `jailer` binary. Composes with every
    /// other boot feature: the vsock socket is staged chroot-relative under the dropped uid, a
    /// shared base is bind-mounted in, the tap's netns is joined via `--netns`, and the input and
    /// output images are built inside the chroot.
    pub jail: Option<Jail>,
    /// Refuse the boot when the cpu/memory cgroup caps can't be applied, rather than the default
    /// fail-open (warn and boot uncapped), so a run the host cannot cap is a typed
    /// [`VmmError::LimitsUnavailable`]. The caps are unavailable two ways: the cgroup v2
    /// controllers are not delegated, or the boot is **unjailed** (the caps live on the jailed
    /// VMM's cgroup). `false` (the default) keeps the fail-open posture, since resource caps are
    /// DoS mitigation, not the isolation boundary. A host posture, not client-settable over the
    /// wire; layered `flag > env (BSX_REQUIRE_LIMITS) > file > default` at the CLI.
    pub require_limits: bool,
    /// Base directory for per-VM **scratch** dirs (`<scratch_dir>/bsx-<pid>-<n>`), holding the
    /// read-write rootfs copy, the jail chroot, block-device images, and sockets. Defaults to
    /// `/tmp` (overridable via `BSX_SCRATCH_DIR`), which is often `tmpfs`: a read-write boot's
    /// full-rootfs copy is then charged to host RAM, and on a small box that alone can exhaust
    /// memory or `ENOSPC` the tmpfs. Point this at real disk, or prefer
    /// [`read_only_root`](BootConfig::read_only_root), which shares the base with **no** copy. The
    /// base must already exist; each VM's own subdir is created and reclaimed by the driver.
    pub scratch_dir: PathBuf,
}

impl BootConfig {
    /// Layer the environment overrides (`BSX_FIRECRACKER`, `BSX_KERNEL`, `BSX_ROOTFS`,
    /// `BSX_MARKER`, `BSX_SCRATCH_DIR`, `BSX_REQUIRE_LIMITS`, `BSX_JAIL_UID`, `BSX_JAIL_GID`,
    /// `BSX_GATEWAY`, `BSX_RESOLVER`) onto [`BootConfig::default`]. The resource *quantities*
    /// (`vcpus`, `mem_mib`, `boot_timeout`) have no env key and come from [`Limits`] via
    /// [`with_limits`](BootConfig::with_limits); `require_limits` is a **posture**, so it does.
    pub fn from_env() -> Self {
        Self::from_env_with(|key| std::env::var_os(key))
    }

    /// The composable core of [`from_env`](BootConfig::from_env): every override comes through
    /// `lookup`, keyed by the `BSX_*` env name. So precedence is unit-testable without mutating the
    /// process environment (which races under the parallel runner and is `unsafe` from edition
    /// 2024), and a caller can **layer another source under the environment**, the way the CLI's
    /// `.bsx.toml` layers chain `or_else` to resolve `env > project file > user file > defaults`.
    pub fn from_env_with(lookup: impl Fn(&str) -> Option<std::ffi::OsString>) -> Self {
        let mut cfg = Self::default();
        if let Some(v) = lookup("BSX_FIRECRACKER") {
            cfg.firecracker = PathBuf::from(v);
        }
        if let Some(v) = lookup("BSX_KERNEL") {
            cfg.kernel = PathBuf::from(v);
        }
        if let Some(v) = lookup("BSX_ROOTFS") {
            cfg.rootfs = PathBuf::from(v);
        }
        // Strict UTF-8 like `env::var`: a non-UTF-8 marker can't be searched for anyway.
        if let Some(v) = lookup("BSX_MARKER").and_then(|v| v.into_string().ok()) {
            cfg.userspace_marker = v;
        }
        if let Some(v) = lookup("BSX_SCRATCH_DIR") {
            cfg.scratch_dir = PathBuf::from(v);
        }
        if let Some(v) = lookup("BSX_REQUIRE_LIMITS").and_then(|v| parse_env_bool(&v)) {
            cfg.require_limits = v;
        }
        // A host fact the operator owns, never a caller's: on a host running more than one sandbox,
        // a caller who chose its own id could name a neighbour's. Set here it survives the CLI's
        // `jail.unwrap_or_default()`, and an unjailed boot discards the whole `Jail` anyway.
        if let Some(uid) =
            lookup("BSX_JAIL_UID").and_then(|v| parse_env_jail_id(&v, "BSX_JAIL_UID"))
        {
            cfg.jail.get_or_insert_default().uid = uid;
        }
        if let Some(gid) =
            lookup("BSX_JAIL_GID").and_then(|v| parse_env_jail_id(&v, "BSX_JAIL_GID"))
        {
            cfg.jail.get_or_insert_default().gid = gid;
        }
        // A host posture like `require_limits`, not a per-run quantity. The resolver is read only
        // when a gateway resolved, so one the guest could not route to is unreachable here too.
        if let Some(gateway) = lookup("BSX_GATEWAY").and_then(|v| parse_env_ipv4(&v, "BSX_GATEWAY"))
        {
            let mut egress = GuestEgress::via(gateway);
            if let Some(resolver) =
                lookup("BSX_RESOLVER").and_then(|v| parse_env_ipv4(&v, "BSX_RESOLVER"))
            {
                egress = egress.with_resolver(resolver);
            }
            cfg.egress = Some(egress);
        }
        cfg
    }

    /// Fold a per-sandbox [`Limits`] budget onto the config: vCPUs, memory, the output cap, and the
    /// wall, which becomes both the boot deadline *and* the per-exec budget.
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.vcpus = limits.vcpus;
        self.mem_mib = limits.mem_mib;
        self.boot_timeout = limits.wall;
        self.exec_wall = limits.wall;
        self.output_cap = limits.output_cap;
        self
    }
}

/// Parse an `BSX_*` IPv4 env value. An unparseable value is `None` **and a warning** naming `key`:
/// falling back to the sealed default is the safe direction, but a typo'd gateway that silently
/// seals a sandbox reads as a broken engine.
fn parse_env_ipv4(v: &std::ffi::OsStr, key: &str) -> Option<Ipv4Addr> {
    match v.to_str().and_then(|s| s.trim().parse::<Ipv4Addr>().ok()) {
        Some(addr) => Some(addr),
        None => {
            tracing::warn!(
                %key,
                value = %v.to_string_lossy(),
                "not an IPv4 address; ignoring it (the guest gets no route from this key)"
            );
            None
        }
    }
}

/// Parse a `BSX_JAIL_UID`/`BSX_JAIL_GID` value. Zero is refused by name, since an id of 0 would
/// `setuid(0)` and drop nothing. An unparseable or zero value is `None` **and a warning**, so the
/// boot falls back to [`DEFAULT_JAIL_UID`], which still jails, rather than to no drop at all.
fn parse_env_jail_id(v: &std::ffi::OsStr, key: &str) -> Option<u32> {
    match v.to_str().and_then(|s| s.trim().parse::<u32>().ok()) {
        Some(0) | None => {
            tracing::warn!(
                %key,
                value = %v.to_string_lossy(),
                "not a usable jail id (a non-zero uid/gid); ignoring it and keeping the default"
            );
            None
        }
        id => id,
    }
}

/// Parse an `BSX_*` boolean env value, tolerant of the usual spellings and case. An unrecognized
/// value is `None` (the caller keeps the default) rather than a silent `false`, so a typo'd
/// `BSX_REQUIRE_LIMITS=ture` doesn't quietly disable a hardening opt-in.
fn parse_env_bool(v: &std::ffi::OsStr) -> Option<bool> {
    match v.to_str()?.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Refuse a `vcpu_count` outside the pinned Firecracker's domain (`[1, 32]`, and **1 or an even
/// number**) before the spawn, so a bad [`Limits::vcpus`](crate::Limits::vcpus) names the rule
/// rather than faulting `PUT /machine-config` after a VMM is already running. Only a **cold boot**
/// consults this: a restore takes its vCPU count from the snapshot state.
pub(crate) fn refuse_unsupported_vcpus(config: &BootConfig) -> Result<(), VmmError> {
    let n = config.vcpus.get();
    if !crate::vcpus_supported(n) {
        return Err(VmmError::UnsupportedVcpus(n));
    }
    Ok(())
}

/// Refuse an **unjailed** boot or restore that asked for `require_limits`: the cpu/memory caps live
/// on the jailed VMM's cgroup, so without the jailer the run would be uncapped. The
/// *jailed-but-undelegated* case is caught deeper, in [`crate::jail::cgroup_limit_args`]; this
/// catches the posture contradiction before any spawn, so it is host-safe and covers both paths.
pub(crate) fn refuse_uncappable_boot(config: &BootConfig) -> Result<(), VmmError> {
    if config.require_limits && config.jail.is_none() {
        return Err(VmmError::LimitsUnavailable(
            "require_limits is set but this boot is unjailed; the cgroup cpu/memory caps live on the \
             jailed VMM, so an unjailed run cannot be capped (jail the run, or unset require_limits)"
                .to_string(),
        ));
    }
    Ok(())
}

/// Refuse a networked boot whose configured gateway is not on the guest's own `/30`, whose two
/// usable addresses are the tap's host end and the guest's own. Any other gateway the guest cannot
/// ARP, so the kernel refuses the default route and the sandbox comes up sealed, which reads as a
/// broken option rather than as the typo it is. Checked against the link the tap builder will
/// assign, so a prefix change moves both together. Only fires when a NIC was asked for, since a
/// host-wide `BSX_GATEWAY` must stay inert on a boot that wants no networking.
pub(crate) fn refuse_offlink_gateway(config: &BootConfig) -> Result<(), VmmError> {
    let (true, Some(egress)) = (config.enable_network, config.egress) else {
        return Ok(());
    };
    let link = crate::net::v4_link();
    if !link.on_link(egress.gateway()) {
        return Err(VmmError::Vmm(format!(
            "gateway {} is not on the guest's /{} link ({} .. {}); the guest cannot ARP it, so \
             the kernel would refuse the default route and the sandbox would come up sealed \
             (use {})",
            egress.gateway(),
            link.prefix_len,
            link.host,
            link.guest,
            link.host
        )));
    }
    Ok(())
}

/// Refuse a **jailed** boot or restore whose scratch dir is on a mount the jailer's chroot cannot
/// work from: `nodev` makes the `/dev/kvm` node it mknods there inert (Firecracker fails deep in
/// boot with a raw "creating KVM object: Permission denied"), and `noexec` refuses the exec of the
/// firecracker copy it places there. Caught **before** any spawn as the typed
/// [`VmmError::ScratchDirNodev`] / [`VmmError::ScratchDirNoexec`]. An unjailed run is never
/// blocked, and an *undetermined* mount (no readable `/proc/self/mountinfo`) reads as fine, never a
/// false alarm. Host-safe (reads `/proc`, no KVM, no child), so the one guard covers boot and
/// restore.
pub(crate) fn refuse_unusable_scratch(config: &BootConfig) -> Result<(), VmmError> {
    scratch_verdict(
        config.jail.is_some(),
        crate::doctor::scratch_mount_flags(&config.scratch_dir),
        &config.scratch_dir,
    )
}

/// The pure logic behind [`refuse_unusable_scratch`], split out so the `jailed × flags` matrix is
/// unit-tested without a real `/proc`. Refuses only on a **confident** blocking flag under a jail
/// (`nodev` named first when both are set); `None` and every unjailed case pass.
fn scratch_verdict(
    jailed: bool,
    flags: Option<crate::doctor::MountFlags>,
    scratch: &Path,
) -> Result<(), VmmError> {
    if !jailed {
        return Ok(());
    }
    match flags {
        Some(f) if f.nodev => Err(VmmError::ScratchDirNodev(scratch.to_path_buf())),
        Some(f) if f.noexec => Err(VmmError::ScratchDirNoexec(scratch.to_path_buf())),
        _ => Ok(()),
    }
}

impl Default for BootConfig {
    /// The pure pinned defaults, no environment reads (that's [`BootConfig::from_env`]). The
    /// resource knobs mirror [`Limits::default`] so the two baselines cannot silently diverge.
    fn default() -> Self {
        let limits = Limits::default();
        Self {
            firecracker: PathBuf::from("firecracker"),
            kernel: PathBuf::from("artifacts/vmlinux"),
            // The agent image (`cargo xtask build-rootfs`), the one the default marker matches.
            // The Ubuntu CI image (`artifacts/rootfs.ext4`) is a raw-boot-test fixture.
            rootfs: PathBuf::from("artifacts/rootfs-guest.ext4"),
            vcpus: limits.vcpus,
            mem_mib: limits.mem_mib,
            boot_args: DEFAULT_BOOT_ARGS.to_string(),
            userspace_marker: DEFAULT_USERSPACE_MARKER.to_string(),
            boot_timeout: limits.wall,
            exec_wall: limits.wall,
            output_cap: limits.output_cap,
            guest_cid: None,
            read_only_root: false,
            input_dir: None,
            output_dir: None,
            enable_network: false,
            egress: None,
            jail: None,
            require_limits: false,
            scratch_dir: default_scratch_dir(),
        }
    }
}

fn default_scratch_dir() -> PathBuf {
    let tmp = Path::new("/tmp");
    if crate::doctor::scratch_mount_flags(tmp).is_some_and(crate::doctor::MountFlags::blocks_jail) {
        PathBuf::from("/var/tmp")
    } else {
        tmp.to_path_buf()
    }
}

/// A booted-and-ready microVM: the `firecracker` child, its API socket, scratch dir, and the
/// captured console. `Drop` kills the VMM and reclaims its residue, and the cgroup-owned lifetime
/// (the sentinel behind [`KillHandle`]) covers the paths `Drop` never runs on, losing the whole
/// *process* to Ctrl-C, SIGKILL, or OOM.
#[derive(Debug)]
#[must_use = "dropping a RunningVm kills its microVM"]
pub struct RunningVm {
    pub(crate) child: Child,
    pub(crate) workdir: PathBuf,
    pub(crate) console: Console,
    pub(crate) api: ApiClient,
    pub(crate) boot_latency: Duration,
    /// The active root-disk backing file: a per-VM copy for a read-write boot, the shared read-only
    /// base for a `read_only_root` boot, or the bundle's private copy for a restore. Held so
    /// [`snapshot`](RunningVm::snapshot) can bundle it.
    pub(crate) rootfs: PathBuf,
    /// This VM was produced by [`Vm::restore`], so [`rootfs`](Self::rootfs) is a placeholder (the
    /// live disk is an anonymous inode with no host path) and re-snapshotting it is refused.
    pub(crate) restored: bool,
    /// This VM has a bulk **input** block device (from `input_dir`), whose image lives in the
    /// scratch dir. A snapshot would bake in a path that teardown removes, so `snapshot` refuses
    /// it.
    pub(crate) has_input: bool,
    /// The vsock unix socket Firecracker created, if this VM was booted with a `guest_cid`.
    pub(crate) vsock_uds: Option<PathBuf>,
    /// The writable output image (in `workdir`) and the host directory to extract it into, when the
    /// boot config set `output_dir`; `None` otherwise. Read back by [`RunningVm::collect_outputs`].
    pub(crate) output: Option<OutputDevice>,
    /// The per-VM host tap backing the guest's virtio-net, when the boot config set
    /// `enable_network`. Lives **outside** `workdir`, so teardown must delete it explicitly.
    pub(crate) tap: Option<Tap>,
    /// The jail this VMM runs in, when the boot config set `jail`. Its chroot lives under `workdir`
    /// and is reclaimed with it, but the jailer's cgroup is outside, so teardown removes that.
    pub(crate) chroot: Option<Chroot>,
    /// The VM's lifetime cgroup, the armed sentinel that reaps the VM if this *process* dies, and
    /// the [`KillHandle`] state. Torn down with the VM on every path.
    pub(crate) lifetime: VmLifetime,
    /// Per-exec wall-clock budget, from [`BootConfig::exec_wall`] at boot/restore time; every
    /// `exec` on this VM runs under it (the host backstop is derived from it plus kill slack).
    pub(crate) exec_wall: Duration,
    /// Per-exec aggregate output cap in bytes, from [`BootConfig::output_cap`].
    pub(crate) output_cap: usize,
    /// The guest's vCPU count as configured at boot ([`BootConfig::vcpus`], what
    /// `PUT /machine-config` set), recorded into a [`Snapshot`]'s envelope so a jailed restore can
    /// derive its `cpu.max` from the clone's *true* parallelism. Never read on a restored VM, which
    /// refuses snapshotting anyway.
    pub(crate) vcpus: NonZeroU8,
    /// The guest's RAM as configured at boot ([`BootConfig::mem_mib`]), which scales the
    /// `/snapshot/create` socket timeout: that call blocks until Firecracker writes the whole
    /// memory file, so a multi-GiB guest must not be bounded by the instant-reply default.
    pub(crate) mem_mib: NonZeroU32,
}

/// A microVM snapshot written by [`RunningVm::snapshot`]: the device + vCPU **state** file, the
/// guest **memory** file (roughly the guest's RAM size), and the **root disk**, which
/// [`Vm::restore`] rebuilds a VM from on a fresh VMM. A **read-write** boot bundles a private
/// point-in-time copy, so the clone shares no writable backing with its source; a **prewarmed**
/// (`read_only_root`) boot references the shared persistent base in place, so N clones share it
/// page-cache-deduped while each gets its own in-RAM overlay, and carries the vsock exec channel.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub(crate) state: PathBuf,
    pub(crate) mem: PathBuf,
    /// The bundle's point-in-time copy of the root disk (a read-write boot), or the shared
    /// read-only base itself (a `read_only_root` boot, where [`shared_base`](Self::shared_base) is
    /// set).
    pub(crate) root_drive: PathBuf,
    /// The host path the snapshot baked in for the root disk (where the source VM booted it).
    /// Firecracker opens the disk *here* during `PUT /snapshot/load`.
    pub(crate) root_backing: PathBuf,
    /// The root disk is a **read-only shared base** at a persistent path (a `read_only_root` boot),
    /// which restore references in place, no copy and no staging. When unset, the disk is a private
    /// per-VM copy that restore stages at `root_backing`.
    pub(crate) shared_base: bool,
    /// The source ran the vsock exec channel, so restored clones can be `exec`'d. The socket path
    /// was baked in **relative** (`v.sock`), so Firecracker re-binds it in each restored VMM's own
    /// scratch dir (its cwd) rather than on one shared absolute path, letting clones coexist.
    pub(crate) has_vsock: bool,
    /// The source had a NIC, and the snapshot baked in this host tap name (`host_dev_name`).
    /// Restore recreates a tap with **exactly this name** rather than renaming it through the pin's
    /// `network_overrides` (`net.rs` records why the namespace is preferred): each clone recreates
    /// the fixed-name tap inside its **own per-VM netns**, where the baked-in guest address, MAC,
    /// and routes are already correct and no name collides.
    pub(crate) tap_name: Option<String>,
    /// The source's vCPU count, the restored clone's **true** parallelism, since the vCPUs come
    /// from the snapshot state (restore issues no `PUT /machine-config`) and nothing forces the
    /// restoring `config` to agree. A jailed restore derives its `cpu.max` from this, so a `config`
    /// mis-declaring the envelope can neither throttle nor over-grant a legitimate clone.
    pub(crate) vcpus: NonZeroU8,
}

impl Snapshot {
    /// The device + vCPU state file.
    #[must_use]
    pub fn state_path(&self) -> &Path {
        &self.state
    }

    /// The guest memory file (roughly the guest's RAM size).
    #[must_use]
    pub fn mem_path(&self) -> &Path {
        &self.mem
    }

    /// The root disk restore uses: the bundle's private copy (a read-write snapshot), or the shared
    /// read-only base referenced in place (a `read_only_root` prewarmed snapshot).
    #[must_use]
    pub fn root_drive_path(&self) -> &Path {
        &self.root_drive
    }

    /// Whether the root disk is a **shared read-only base** referenced in place (restore
    /// bind-mounts it, clones share one page cache) rather than a private per-VM copy staged at the
    /// baked-in path. The two take different jailed staging paths, so a caller can tell them apart.
    #[must_use]
    pub fn shared_base(&self) -> bool {
        self.shared_base
    }

    /// The source's vCPU count, what a clone restored from this bundle actually runs (the vCPUs
    /// come from the snapshot state, not the restoring config), and what a jailed restore's
    /// `cpu.max` is derived from. Exposed so an embedder sizing a pool can read a bundle's CPU
    /// envelope.
    #[must_use]
    pub fn vcpus(&self) -> NonZeroU8 {
        self.vcpus
    }
}

/// Boot entry point, `Vm::boot(config) -> RunningVm`.
#[derive(Debug)]
pub struct Vm;

impl Vm {
    /// Boot a microVM under `config` and return once the guest reaches userspace. By default copies
    /// the base rootfs into a fresh per-VM scratch dir and boots the copy read-write, so repeated
    /// runs stay independent and the pinned base is never mutated; with
    /// [`read_only_root`](BootConfig::read_only_root) it shares the base read-only under a per-run
    /// tmpfs overlay instead, so the base is still not written and each VM costs far less.
    /// # Errors
    /// [`VmmError::LimitsUnavailable`] if [`require_limits`](BootConfig::require_limits) is set on
    /// an unjailed boot (nothing can enforce the caps), [`VmmError::UnsupportedVcpus`] if
    /// [`Limits::vcpus`](crate::Limits::vcpus) is not 1 or an even number in `[1, 32]`,
    /// [`VmmError::NoKvm`] without `/dev/kvm`, [`VmmError::Artifact`] for a missing
    /// kernel/rootfs/binary, [`VmmError::Timeout`] if boot-to-userspace exceeds `boot_timeout`, and
    /// [`VmmError::Vmm`] for any Firecracker API or process failure. On any error the child is
    /// killed and the scratch dir removed before returning.
    pub fn boot(config: BootConfig) -> Result<RunningVm, VmmError> {
        // Every guard runs before the KVM probe and any spawn, so a misconfigured boot is a typed
        // refusal with no VMM to tear down.
        refuse_uncappable_boot(&config)?;
        refuse_unusable_scratch(&config)?;
        refuse_unsupported_vcpus(&config)?;
        refuse_offlink_gateway(&config)?;
        // KVM checked here, not in `launch`, so the launch/boot-failure machinery stays
        // unit-testable on hosts without KVM (a fake "firecracker" needs no VM).
        if !Path::new("/dev/kvm").exists() {
            return Err(VmmError::NoKvm);
        }
        // One deadline for the whole boot: host-side staging (`launch`) and the API boot
        // (`run_boot`) share it, so a slow rootfs copy can't run unbounded before the boot's own
        // timeout starts.
        let deadline = crate::spawn::boot_deadline(config.boot_timeout);
        let mut spawned = Spawned::launch(&config, deadline)?;
        let boot_latency = match spawned.run_boot(&config, deadline) {
            Ok(latency) => latency,
            Err(e) => return Err(spawned.abort(e)),
        };
        spawned.into_running(boot_latency, &config)
    }
}

impl RunningVm {
    /// Boot-to-userspace latency, measured from `InstanceStart`.
    #[must_use]
    pub fn boot_latency(&self) -> Duration {
        self.boot_latency
    }

    /// A UTF-8-lossy snapshot of the serial console captured so far.
    #[must_use]
    pub fn console(&self) -> String {
        self.console.snapshot()
    }

    /// The PID of the `firecracker` VMM process, for out-of-band supervision: cgroup placement,
    /// host-side observers, or asserting it was reaped. Valid only for the VM's lifetime, since
    /// dropping this `RunningVm` kills and reaps the process.
    #[must_use]
    pub fn vmm_pid(&self) -> u32 {
        self.child.id()
    }

    /// Whether this VM's VMM process is still running, reaping it if it has exited. A `/proc/<pid>`
    /// probe would be fooled by an **unreaped zombie** (a pooled clone's VMM is nobody's `wait()`,
    /// and a zombie keeps its `/proc` entry), where `try_wait` sees the real exit. A `try_wait`
    /// error reads as not-alive: a clone that cannot be queried is not worth handing out.
    pub(crate) fn vmm_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// A cheap, cloneable, `Send + Sync` [`KillHandle`] that force-kills this VM from any thread,
    /// the **host-gave-up path**: `exec` borrows `&self` and `shutdown` consumes `self`, so a
    /// caller blocked in `exec` cannot otherwise be stopped, and killing through the handle closes
    /// the VMM's vsock peer so the blocked call returns a typed error. `Drop`/`shutdown` still
    /// reclaims all host residue afterwards, exactly as for a crashed guest.
    #[must_use]
    pub fn kill_handle(&self) -> KillHandle {
        self.lifetime.kill_handle()
    }

    /// The VM's **IPv4 link** (host + guest ends and prefix, a [`GuestLink`]), when booted with
    /// [`enable_network`](BootConfig::enable_network); `None` otherwise. Always present on a
    /// networked VM, and the guest reaches the host end over its `eth0` and nothing beyond it.
    #[must_use]
    pub fn ipv4(&self) -> Option<GuestLink<Ipv4Addr>> {
        self.tap.as_ref().map(|t| t.v4)
    }

    /// The VM's **IPv6 link** ([`GuestLink`]), or `None` when the VM has no NIC **or** IPv6 isn't
    /// live on the host, so a `Some` here means v6 is actually reachable. Applied in-guest from the
    /// `guest_ip6=` cmdline token, since the kernel `ip=` param is v4-only.
    #[must_use]
    pub fn ipv6(&self) -> Option<GuestLink<Ipv6Addr>> {
        self.tap.as_ref().and_then(|t| t.v6)
    }

    /// The host tap interface backing this VM's NIC, when booted with
    /// [`enable_network`](BootConfig::enable_network); `None` otherwise, and the handle the
    /// host-side eBPF track binds policy to. It lives **inside** this VM's network namespace, so
    /// the loader resolves it to an ifindex within that netns: pair it with [`netns`](Self::netns).
    #[must_use]
    pub fn tap_name(&self) -> Option<&str> {
        self.tap.as_ref().map(|t| t.name.as_str())
    }

    /// This VM's **name**, the leaf of its scratch dir (`bsx-<pid>-<seq>`, this driver's pid and a
    /// per-process sequence). It is the handle everything else about the VM is already keyed on:
    /// the scratch dir, the netns, and the driver's log lines, so an audit record naming it
    /// correlates with on-disk residue. Unique among *live* VMs only, since pids are reused once a
    /// driver exits: a consumer archiving records must pair it with the run's start time.
    #[must_use]
    pub fn name(&self) -> &str {
        self.workdir
            .file_name()
            .map_or("", |n| n.to_str().unwrap_or(""))
    }

    /// The per-VM **network namespace** name backing this VM's NIC, when booted with
    /// [`enable_network`](BootConfig::enable_network); `None` otherwise. The tap the guest's
    /// virtio-net rides ([`tap_name`](Self::tap_name)) lives inside it, isolated from the host and
    /// every other VM, so the eBPF loader enters this netns (`/run/netns/<name>`) to attach.
    #[must_use]
    pub fn netns(&self) -> Option<&str> {
        self.tap.as_ref().map(|t| t.netns.as_str())
    }

    /// Whether the VM-lifetime sentinel is armed for this VM.
    #[must_use]
    pub fn sentinel_armed(&self) -> bool {
        self.lifetime.sentinel_armed()
    }

    /// Whether this VM fell back to Drop-only cleanup (sentinel could not be armed).
    #[must_use]
    pub fn sentinel_degraded(&self) -> bool {
        !self.sentinel_armed()
    }

    /// Connect to the in-guest agent over vsock and complete the channel handshake, returning a
    /// protocol-ready [`ClientConnection`]: dials Firecracker's vsock socket, speaks the
    /// `CONNECT <port>` handshake, sets read/write deadlines, then does the channel handshake. A
    /// peer close during establishment is retried within a bounded dial-retry window.
    /// # Errors
    /// [`VmmError::GuestUnavailable`] if nothing answered on `port` within the dial-retry window;
    /// [`VmmError::Vmm`] if the VM was booted without a `guest_cid` or on any other I/O or channel
    /// failure; [`VmmError::Timeout`] if the connect exceeds the deadline.
    pub fn connect_agent(&self, port: u32) -> Result<ClientConnection<UnixStream>, VmmError> {
        connect_agent_at(self.require_vsock()?, port, VSOCK_TIMEOUT)
    }

    /// Probe the exec channel: connect to the guest agent, complete the handshakes, and discard the
    /// connection (the agent serves one connection then loops back to accept). The prewarmed
    /// [`Pool`](crate::Pool)'s health check, where a dead or wedged clone surfaces as a typed
    /// error, most specifically [`VmmError::GuestUnavailable`]. Short-deadlined **and
    /// single-shot**, no dial retry: an idle healthy agent is parked in `accept()` and answers
    /// first try, so a retry window would only be spent on a corpse.
    pub(crate) fn probe_agent(&self) -> Result<(), VmmError> {
        connect_agent_once(self.require_vsock()?, VSOCK_PORT, PROBE_TIMEOUT).map(|_| ())
    }

    /// The Firecracker vsock socket, or a typed error naming the fix if the VM was booted without a
    /// `guest_cid`, so the guard and its message live once.
    fn require_vsock(&self) -> Result<&Path, VmmError> {
        self.vsock_uds.as_deref().ok_or_else(|| {
            VmmError::Vmm("this microVM was booted without vsock (set BootConfig.guest_cid)".into())
        })
    }

    /// Run `argv` in the guest, feeding it `stdin`, and collect its stdout/stderr/exit over the
    /// vsock exec protocol ([`connect_agent`](Self::connect_agent)), bounded by
    /// [`BootConfig::output_cap`]. Each call opens a fresh connection (the agent serves one command
    /// per connection and loops), and repeated `exec`s **compose into a stateful session**: the
    /// agent serves every one from the same persistent working directory, so files injected or
    /// written by one command are visible to the next until the VM and its overlay are torn down.
    /// # Errors
    /// A typed [`VmmError`] across three buckets. **Establishment**:
    /// [`VmmError::GuestUnavailable`] if the agent didn't answer within the brief dial-retry window
    /// (transient peer closes during establishment are retried first), [`VmmError::Vmm`] if the VM
    /// has no vsock, [`VmmError::Timeout`] on a stalled connect/ack. **Steady-state transport**:
    /// [`VmmError::Channel`] on a mid-exec framing/IO fault. **Guest fault**:
    /// [`VmmError::GuestExec`] if the agent couldn't run the command, [`VmmError::ExecTimeout`] if
    /// it outran its budget, [`VmmError::OutputCap`] if it flooded output. A command that merely
    /// exits non-zero (even by signal) is a normal [`RunResult`], not an error.
    pub fn exec(&mut self, argv: &[String], stdin: &[u8]) -> Result<RunResult, VmmError> {
        self.exec_with_files(argv, stdin, &[], &[], &[])
    }

    /// Run `argv` with `stdin`, first injecting `files_in` into the run's working directory and
    /// `env` into the spawned command's environment, then returning the files named in `artifacts`
    /// (paths relative to that directory) in [`RunResult::files`]. The richer form of
    /// [`exec`](Self::exec): the injected files and env ride the exec request's frames, so each is
    /// bounded by the channel's per-frame cap, and the total captured output plus artifacts is
    /// bounded by this VM's [`BootConfig::output_cap`] (default 16 MiB).
    ///
    /// **Env scope.** The variables are set on the **spawned command only** (the agent applies them
    /// via `Command::env`, never its own process), so one run's environment cannot bleed into a
    /// later run.
    ///
    /// **One exec at a time**, which is what the `&mut self` receiver is for: the agent serves
    /// every connection from one working directory, so two execs in flight against one VM would
    /// each read whatever the other last wrote under the same name, and [`RunResult::files`] could
    /// return bytes that run never produced. In sequence, that shared directory is the stateful
    /// session (see [`exec`](Self::exec)).
    ///
    /// **Secret hygiene**, held by `injected_secrets_reach_no_observable_surface`: injected file
    /// contents and env *values* reach no engine log line, [`VmmError`] rendering, or serial
    /// console, and the driver's wire copies are zero-wiped after send. An error path may name a
    /// file *path* or an env *key*, never a value. Best-effort, since the caller's own buffers and
    /// the kernel's socket buffers are out of reach.
    ///
    /// # Errors
    /// As [`exec`](Self::exec).
    pub fn exec_with_files(
        &mut self,
        argv: &[String],
        stdin: &[u8],
        files_in: &[(String, Vec<u8>)],
        env: &[(String, String)],
        artifacts: &[String],
    ) -> Result<RunResult, VmmError> {
        let uds = self.require_vsock()?;
        // The host's total patience: the command's own budget plus the agent's kill+report margin,
        // derived from the *actual* budget so a raised one can't leave the socket idle timeout
        // cutting off a long quiet command. One **absolute** deadline on the connection's reads and
        // writes and on `run_exec`'s loop, so the agent's `TimedOut` (at `budget`) reaches us first
        // and neither a silent nor a dribbling guest can park us. Absolute because a per-syscall
        // timeout is re-armed by every byte, so it bounds one `read`, not one frame.
        let budget = self.exec_wall;
        let wall = budget.saturating_add(EXEC_KILL_SLACK);
        let mut conn = connect_agent_bounded(uds, VSOCK_PORT, wall)?;
        let argv_ref: Vec<&str> = argv.iter().map(AsRef::as_ref).collect();
        let files_in_ref: Vec<(&str, &[u8])> = files_in
            .iter()
            .map(|(p, d)| (p.as_str(), d.as_slice()))
            .collect();
        let env_ref: Vec<(&str, &str)> =
            env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let artifacts_ref: Vec<&str> = artifacts.iter().map(AsRef::as_ref).collect();
        run_exec(
            &mut conn,
            &argv_ref,
            stdin,
            &files_in_ref,
            &env_ref,
            &artifacts_ref,
            ExecBounds {
                timeout: budget,
                wall,
                max_output: self.output_cap,
            },
        )
    }

    /// Pull the guest's `/output` tree back to the host directory set as
    /// [`BootConfig::output_dir`], returning the captured paths (relative to that directory,
    /// sorted). It **consumes the VM**: the VMM is stopped first (a cooperative power-off, then a
    /// hard kill) so it has released the image and flushed the guest's writes, because reading a
    /// live VMM-held image would race the guest and corrupt the ext4 journal the reader replays.
    /// Read-back is **rootless**, `ext4-view` replaying the journal in-process with no loopback,
    /// `mount`, or `sudo`. Guest-controlled contents are sanitised: `lost+found` is dropped,
    /// symlinks whose target escapes the destination are removed so a later host read cannot be
    /// redirected onto the host filesystem, and the extraction is bounded in both real bytes and
    /// wall-clock time, so a pathological image can't exhaust host disk or hang teardown.
    /// # Errors
    /// [`VmmError::Vmm`] if the VM was booted without an output device (no `output_dir`), or on a
    /// host-side readback failure; [`VmmError::OutputCap`] if the extracted tree exceeds the byte
    /// cap; [`VmmError::Timeout`] if readback outruns its deadline.
    pub fn collect_outputs(mut self) -> Result<Vec<String>, VmmError> {
        let output = self.output.clone().ok_or_else(|| {
            VmmError::Vmm(
                "this microVM was booted without an output device (set BootConfig.output_dir)"
                    .into(),
            )
        })?;
        // Stop the VMM so it releases the image fd and the on-disk ext4 is consistent *before* the
        // read. `self` drops at the end of this method, so `Drop` reclaims the scratch dir.
        self.stop_and_reap();
        collect_output_image(&output.image, &output.dest)
    }

    /// Issue the cooperative power-off ask (`SendCtrlAltDel`) **without waiting**, so a batch
    /// caller ([`Pool::shutdown`](crate::Pool::shutdown)) can ask every clone first and then poll
    /// them all against one shared grace, paying one [`POWER_OFF_TIMEOUT`] rather than one per VM.
    /// Marks teardown begun, so a `KillHandle` no-ops on the soon-to-be-reaped pid.
    pub(crate) fn request_power_off(&mut self) {
        self.lifetime.mark_down();
        let _ = self.api.put("/actions", &Action::SendCtrlAltDel);
    }

    /// Ask the guest to power off (best-effort `SendCtrlAltDel`, an x86 ACPI-ish nicety over
    /// i8042), then poll for the VMM to exit until `deadline`, returning `true` if it exited on its
    /// own. The unconditional kill is the caller's, or `Drop`'s, never this.
    fn power_off_and_wait(&mut self, deadline: Instant) -> bool {
        // Flag teardown before any reap below (this loop's `try_wait`, or the caller's kill): a
        // degraded-host `KillHandle` signals a raw pid, and `collect_outputs` reaps the VMM here
        // then runs a multi-second readback, so an unmarked recyclable pid could be `kill -9`ed
        // out from under an unrelated process. Idempotent with the later `teardown`/`abort` calls.
        self.lifetime.mark_down();
        // Firecracker rejects the i8042 action on aarch64, and any API error means the guest was
        // never asked, so polling would burn the whole grace before the caller's hard kill.
        if self.api.put("/actions", &Action::SendCtrlAltDel).is_err() {
            return false;
        }
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return true, // clean power-off (guest ran its umount on shutdown)
                Ok(None) if Instant::now() >= deadline => return false,
                Ok(None) => std::thread::sleep(POWER_OFF_POLL),
                Err(_) => return false, // `try_wait` failed (near-impossible): let the caller force it
            }
        }
    }

    /// Best-effort power-off, then a hard kill bounded by `VMM_REAP_GRACE`, so the VMM's fd to the
    /// output image is released before readback. Returns early on a VMM that outlives the grace,
    /// leaving it unreaped rather than parking teardown. Idempotent with `Drop`'s teardown.
    fn stop_and_reap(&mut self) {
        if !self.power_off_and_wait(Instant::now() + POWER_OFF_TIMEOUT) {
            // A wedged or unwaitable guest: the `-o sync` mount means the command's completed
            // writes are already on the image, and the reader replays the journal. Bounded like the
            // `Drop` teardown's reap, since a D-state VMM must not park this thread.
            if !crate::drives::kill_and_reap_briefly(&mut self.child, "firecracker", VMM_REAP_GRACE)
            {
                // Unreaped: its fd to the output image may still be open, so the readback can see
                // a torn image. The alternative is hanging here indefinitely.
                return;
            }
        }
        self.console.join();
    }

    /// Shut the microVM down and reclaim its resources: asks the guest to power off
    /// (`SendCtrlAltDel`) and waits briefly, leaving the kill and scratch-dir removal to `Drop`.
    /// # Errors
    /// Currently never returns `Err`, since teardown is best-effort. The signature stays fallible
    /// so a teardown step that can report failure is an additive change rather than a breaking one.
    pub fn shutdown(mut self) -> Result<(), VmmError> {
        let _ = self.power_off_and_wait(Instant::now() + POWER_OFF_TIMEOUT);
        Ok(())
    }
}

impl Drop for RunningVm {
    fn drop(&mut self) {
        teardown(
            &mut self.child,
            &mut self.console,
            &self.workdir,
            self.tap.as_ref(),
            self.chroot.as_ref(),
            &mut self.lifetime,
        );
    }
}

/// Best-effort teardown shared by both `Drop`s, in order: kill the VMM, join the console reader
/// (which ends once the killed child's stdout closes), delete the per-VM tap and the jailer's
/// cgroup (both outside the scratch dir, so `remove_dir_all` can't reclaim them), then remove the
/// scratch dir, which reclaims the chroot with it.
pub(crate) fn teardown(
    child: &mut Child,
    console: &mut Console,
    workdir: &Path,
    tap: Option<&Tap>,
    chroot: Option<&Chroot>,
    lifetime: &mut VmLifetime,
) {
    // Flagged *before* the reap: from here every outstanding `KillHandle` no-ops, so a late `kill`
    // can never signal a pid the `wait` below has just made recyclable.
    lifetime.mark_down();
    // Bounded, because a VMM stuck in uninterruptible sleep (a wedged KVM ioctl, a virtio flush
    // against a hung backing filesystem) survives SIGKILL until the kernel op finishes, so a bare
    // `wait` would hang this `Drop`. The console reader only ends at the child's stdout EOF, so
    // joining it is exactly as unbounded: skip it when the reap didn't land.
    if crate::drives::kill_and_reap_briefly(child, "firecracker", VMM_REAP_GRACE) {
        console.join();
    }
    // Before the scratch dir, so a slow `remove_dir_all` can't widen the window a leaked cgroup
    // lives in. The VMM is reaped above, so its cgroup is empty and removable; on the rare detach
    // `remove_cgroup` is best-effort and leaves it for the sweep.
    if let Some(cgroup) = chroot.and_then(|c| c.cgroup_dir.as_deref()) {
        remove_cgroup(cgroup);
    }
    // Reclaim the lifetime cgroup and disarm the sentinel (it wakes to already-gone dirs).
    lifetime.teardown();
    // A jailed VM may hold read-only bind mounts in its chroot (the shared rootfs base, a restore's
    // memory file and base disk). Unmount each, lazily so a still-open fd can't block, *before*
    // `remove_dir_all`, or the mount point `EBUSY`s and the whole chroot leaks.
    if let Some(chroot) = chroot {
        chroot.unmount_all();
    }
    // A jailed chroot is chowned to its leased pair, so a tree that survives this keeps that pair
    // out of the span: reusing it would put two on-host chroots under one uid.
    if reclaim_scratch(workdir, tap) == Reclaimed::No
        && let Some(chroot) = chroot
    {
        chroot.withhold_lease();
    }
}

/// Delete the VM's netns (cascading its tap away), then reclaim the scratch dir **only once the
/// netns is confirmed gone**. A transient `ip netns del` failure would otherwise leave a netns with
/// no scratch dir: invisible to the dir-keyed orphan sweep, and a permanent `netns add` collision
/// once the pid is recycled. Shared by [`teardown`] and [`Spawned::abort`](crate::spawn), so a
/// failed boot reclaims identically.
pub(crate) fn reclaim_scratch(workdir: &Path, tap: Option<&Tap>) -> Reclaimed {
    let netns_gone = match tap {
        Some(tap) => {
            tap.delete();
            !tap.netns_exists()
        }
        None => true,
    };
    if !netns_gone {
        tracing::warn!(
            workdir = %workdir.display(),
            "netns outlived teardown; keeping the scratch dir so the orphan sweep can reclaim both"
        );
        return Reclaimed::No;
    }
    match std::fs::remove_dir_all(workdir) {
        Ok(()) => Reclaimed::Yes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Reclaimed::Yes,
        Err(e) => {
            tracing::warn!(
                workdir = %workdir.display(), error = %e,
                "scratch dir survived teardown; leaving it for the orphan sweep"
            );
            Reclaimed::No
        }
    }
}

/// Whether the scratch dir is gone. Returned rather than logged because a **jailed** VM's chroot is
/// chowned to its leased uid/gid, so a surviving tree makes that pair unsafe for the next sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a scratch dir that survived decides whether its jail pair may be reused"]
pub(crate) enum Reclaimed {
    Yes,
    No,
}

/// Reclaim the scratch dir after a **tap-creation** failure, whose half-built netns
/// [`Tap::create`](crate::net::Tap::create) already tried to delete. The netns is named after the
/// scratch dir, so a lingering one keeps the dir (as [`reclaim_scratch`] does) rather than
/// stranding a dir-less netns. Called from [`spawn::create_tap_or_reclaim`](crate::spawn), which
/// has no [`Tap`] yet to hand [`reclaim_scratch`].
pub(crate) fn reclaim_scratch_after_tap_failure(workdir: &Path) {
    let netns = workdir.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if !netns.is_empty() && crate::net::netns_exists(netns) {
        tracing::warn!(
            workdir = %workdir.display(),
            %netns,
            "netns survived a failed tap create; keeping the scratch dir so the orphan sweep can reclaim both"
        );
    } else {
        let _ = std::fs::remove_dir_all(workdir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsx_test_support::ScratchDir;

    #[test]
    fn reclaim_scratch_removes_the_dir_when_there_is_no_netns() {
        // The no-tap path: nothing gates the reclaim, so the scratch dir goes. The netns-lingers
        // branch needs CAP_NET_ADMIN, so the privileged suite covers the stranded netns+dir pair.
        let base = ScratchDir::created("bsx-reclaim");
        let workdir = base.path().join("bsx-1-0");
        std::fs::create_dir(&workdir).expect("create workdir");
        assert_eq!(
            reclaim_scratch(&workdir, None),
            Reclaimed::Yes,
            "a removed dir reports itself reclaimed, which is what frees its jail pair"
        );
        assert!(
            !workdir.exists(),
            "no netns to gate on, so the dir is reclaimed"
        );
    }

    #[test]
    fn with_limits_folds_budget() {
        let cfg = BootConfig::from_env().with_limits(Limits {
            vcpus: NonZeroU8::new(4).unwrap(),
            mem_mib: NonZeroU32::new(1024).unwrap(),
            wall: Duration::from_secs(60),
            output_cap: 4096,
        });
        assert_eq!(cfg.vcpus.get(), 4);
        assert_eq!(cfg.mem_mib.get(), 1024);
        // One wall for the whole run: the fold sets the boot deadline *and* the per-exec budget.
        assert_eq!(cfg.boot_timeout, Duration::from_secs(60));
        assert_eq!(cfg.exec_wall, Duration::from_secs(60));
        assert_eq!(cfg.output_cap, 4096);
    }

    #[test]
    fn a_vcpu_count_the_vmm_would_reject_is_refused_before_the_spawn() {
        // Firecracker documents `vcpu_count` as `[1, 32]`, "either 1 or an even number", and
        // `NonZeroU8` can still spell 3 and 64, so the rest of the domain has to be a guard.
        let vcpus = |n: u8| BootConfig {
            vcpus: NonZeroU8::new(n).expect("nonzero"),
            ..BootConfig::default()
        };
        for legal in [1u8, 2, 4, 16, 32] {
            assert!(
                refuse_unsupported_vcpus(&vcpus(legal)).is_ok(),
                "{legal} vCPUs is inside Firecracker's documented domain"
            );
        }
        // Odd above 1, and past the ceiling.
        for illegal in [3u8, 5, 31, 33, 34, 64, 255] {
            assert!(
                matches!(
                    refuse_unsupported_vcpus(&vcpus(illegal)),
                    Err(VmmError::UnsupportedVcpus(n)) if n == illegal
                ),
                "{illegal} vCPUs must be refused, and the error must carry the count"
            );
        }
        // The refusal buckets with the other "fix the config and retry" faults, not as a guest
        // fault.
        assert_eq!(
            VmmError::UnsupportedVcpus(3).kind(),
            crate::ErrorKind::Infra
        );
        // The default `Limits` must itself be inside the domain, or every default boot is refused.
        assert!(refuse_unsupported_vcpus(&BootConfig::default()).is_ok());
    }

    #[test]
    fn require_limits_refuses_an_unjailed_boot() {
        // Unjailed + require_limits is a contradiction (caps live on the jailed cgroup), refused
        // before any spawn, so this is host-safe (no KVM, no child).
        let mut cfg = BootConfig {
            require_limits: true,
            ..BootConfig::default()
        };
        assert!(cfg.jail.is_none());
        assert!(matches!(
            refuse_uncappable_boot(&cfg),
            Err(VmmError::LimitsUnavailable(_))
        ));

        // The two non-contradictory postures both pass the guard: an unjailed boot that didn't ask
        // for caps, and a jailed boot that did (its delegation is checked deeper, at cgroup-arg
        // time).
        cfg.require_limits = false;
        assert!(refuse_uncappable_boot(&cfg).is_ok());
        cfg.require_limits = true;
        cfg.jail = Some(Jail::default());
        assert!(refuse_uncappable_boot(&cfg).is_ok());
    }

    #[test]
    fn a_host_wide_gateway_does_not_break_a_boot_that_wants_no_nic() {
        // `BSX_GATEWAY` and `.bsx.toml` exist so an operator sets a gateway once for the whole
        // host, so a NIC-less boot must ignore it rather than fail.
        let mut cfg = BootConfig::from_env_with(|key| match key {
            "BSX_GATEWAY" => Some(std::ffi::OsString::from("10.200.0.1")),
            _ => None,
        });
        assert!(cfg.egress.is_some(), "the host layer sets a gateway");
        assert!(!cfg.enable_network, "and this boot asked for no NIC");

        // `/dev/kvm` is the first thing past the guards, so its absence is the expected stopping
        // point; what must never appear is a complaint about the gateway itself.
        if let Err(e) = Vm::boot(cfg.clone()) {
            let msg = e.to_string();
            assert!(
                !msg.contains("gateway"),
                "a host-wide gateway must be inert on a NIC-less boot, not fatal: {msg}"
            );
        }

        // Inert, not dropped: the field survives for the boot that does want a NIC.
        cfg.enable_network = true;
        assert_eq!(
            cfg.egress.map(|e| e.gateway()),
            Some(Ipv4Addr::new(10, 200, 0, 1))
        );
    }

    #[test]
    fn a_gateway_the_guest_could_never_reach_is_refused() {
        use crate::net::GuestEgress;
        let mut cfg = BootConfig {
            enable_network: true,
            ..BootConfig::default()
        };

        // The host end of the /30 is the only address on the guest's link, so the only one that
        // works.
        cfg.egress = Some(GuestEgress::via(Ipv4Addr::new(10, 200, 0, 1)));
        assert!(refuse_offlink_gateway(&cfg).is_ok());

        // Anything else: the kernel refuses the route and the sandbox comes up sealed.
        cfg.egress = Some(GuestEgress::via(Ipv4Addr::new(192, 168, 1, 1)));
        let err = refuse_offlink_gateway(&cfg)
            .expect_err("an off-link gateway must be refused")
            .to_string();
        assert!(err.contains("192.168.1.1"), "names the bad value: {err}");
        assert!(err.contains("10.200.0.1"), "names the working one: {err}");
        // A multi-line `format!` without a trailing `\` bakes source indentation into the
        // operator's string, and the assertions above check content, not whitespace.
        assert!(
            !err.contains("  "),
            "no run of source indentation in an operator-facing message: {err:?}"
        );

        // Even an address one bit outside the /30, the near-miss a hand-edited config produces.
        cfg.egress = Some(GuestEgress::via(Ipv4Addr::new(10, 200, 0, 5)));
        assert!(refuse_offlink_gateway(&cfg).is_err());

        // And it stays inert without a NIC, so a host-wide gateway never blocks a sealed boot.
        cfg.enable_network = false;
        assert!(refuse_offlink_gateway(&cfg).is_ok());
    }

    #[test]
    fn scratch_verdict_refuses_only_a_confident_blocking_flag_under_a_jail() {
        use crate::doctor::MountFlags;
        const NODEV: Option<MountFlags> = Some(MountFlags {
            nodev: true,
            noexec: false,
        });
        const NOEXEC: Option<MountFlags> = Some(MountFlags {
            nodev: false,
            noexec: true,
        });
        const BOTH: Option<MountFlags> = Some(MountFlags {
            nodev: true,
            noexec: true,
        });
        const CLEAR: Option<MountFlags> = Some(MountFlags {
            nodev: false,
            noexec: false,
        });
        let scratch = Path::new("/some/scratch");
        // Jailed + a confident blocking flag is refused with the variant naming that flag, carrying
        // the offending path. Both flags at once name nodev.
        assert!(matches!(
            scratch_verdict(true, NODEV, scratch),
            Err(VmmError::ScratchDirNodev(p)) if p == scratch
        ));
        assert!(matches!(
            scratch_verdict(true, NOEXEC, scratch),
            Err(VmmError::ScratchDirNoexec(p)) if p == scratch
        ));
        assert!(matches!(
            scratch_verdict(true, BOTH, scratch),
            Err(VmmError::ScratchDirNodev(_))
        ));
        // Everything else passes: an unrestricted fs, an *undetermined* mount, and every unjailed
        // boot (no chroot, so neither flag matters).
        assert!(scratch_verdict(true, CLEAR, scratch).is_ok());
        assert!(scratch_verdict(true, None, scratch).is_ok());
        assert!(scratch_verdict(false, NODEV, scratch).is_ok());
        assert!(scratch_verdict(false, BOTH, scratch).is_ok());
        assert!(scratch_verdict(false, None, scratch).is_ok());
    }

    #[test]
    fn require_limits_reads_from_the_environment() {
        // `from_env_with` layers `BSX_REQUIRE_LIMITS` (a posture, not a resource quantity) onto the
        // default `false`, tolerant of spelling/case; an unrecognized value keeps the default.
        let on = BootConfig::from_env_with(|k| (k == "BSX_REQUIRE_LIMITS").then(|| "TRUE".into()));
        assert!(on.require_limits);
        let off = BootConfig::from_env_with(|k| (k == "BSX_REQUIRE_LIMITS").then(|| "0".into()));
        assert!(!off.require_limits);
        let typo =
            BootConfig::from_env_with(|k| (k == "BSX_REQUIRE_LIMITS").then(|| "ture".into()));
        assert!(
            !typo.require_limits,
            "an unrecognized value keeps the default"
        );
        assert!(!BootConfig::default().require_limits);
    }

    #[test]
    fn default_is_pure_and_matches_limits_defaults() {
        let (cfg, limits) = (BootConfig::default(), Limits::default());
        assert_eq!(cfg.vcpus, limits.vcpus);
        assert_eq!(cfg.mem_mib, limits.mem_mib);
        assert_eq!(cfg.boot_timeout, limits.wall);
        assert_eq!(cfg.exec_wall, limits.wall);
        assert_eq!(cfg.output_cap, limits.output_cap);
    }

    #[test]
    fn from_env_layers_overrides_onto_defaults() {
        // Injected lookup, not `set_var`: no process-global mutation, no parallel-test race.
        let cfg = BootConfig::from_env_with(|key| match key {
            "BSX_KERNEL" => Some("/elsewhere/vmlinux".into()),
            "BSX_MARKER" => Some("guest-ready".into()),
            _ => None,
        });
        assert_eq!(cfg.kernel, PathBuf::from("/elsewhere/vmlinux"));
        assert_eq!(cfg.userspace_marker, "guest-ready");
        let default = BootConfig::default();
        assert_eq!(cfg.rootfs, default.rootfs, "unset keys keep the default");
        assert_eq!(cfg.firecracker, default.firecracker);
    }

    #[test]
    fn a_jail_id_the_env_names_lands_on_the_jail_but_root_never_does() {
        let cfg = BootConfig::from_env_with(|key| match key {
            "BSX_JAIL_UID" => Some("20001".into()),
            "BSX_JAIL_GID" => Some("20002".into()),
            _ => None,
        });
        let jail = cfg.jail.expect("an id materialises the jail it names");
        assert_eq!((jail.uid, jail.gid), (20001, 20002));

        // Zero would `setuid(0)` and drop nothing, so it falls back to the pinned default rather
        // than to no drop at all, and `parse_env_jail_id` warns. Same for a non-id value.
        for bad in ["0", "-1", "root", ""] {
            let cfg = BootConfig::from_env_with(|key| {
                (key == "BSX_JAIL_UID").then(|| std::ffi::OsString::from(bad))
            });
            assert!(
                cfg.jail
                    .is_none_or(|j| j.uid == crate::jail::DEFAULT_JAIL_UID),
                "{bad:?} must not become the jail uid"
            );
        }
    }

    #[test]
    fn scratch_dir_defaults_to_non_nodev_base_and_honors_the_env_override() {
        let default_scratch = BootConfig::default().scratch_dir;
        assert!(
            default_scratch == std::path::Path::new("/tmp")
                || default_scratch == std::path::Path::new("/var/tmp")
        );
        let cfg = BootConfig::from_env_with(|k| {
            (k == "BSX_SCRATCH_DIR").then(|| "/mnt/disk/scratch".into())
        });
        assert_eq!(cfg.scratch_dir, PathBuf::from("/mnt/disk/scratch"));
    }
}
