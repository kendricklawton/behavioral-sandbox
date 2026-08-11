//! Run Firecracker under its **jailer**, the other half of the isolation story: hardware isolation
//! contains the *guest*, and the jailer contains the *VMM process* on the host, so a Firecracker bug or
//! a guest that breaks out into the VMM still lands in a chroot under a dropped uid/gid.
//!
//! The jailer builds a chroot, mknods the device nodes the VMM needs, places the process in a cgroup,
//! `chroot`s in, drops privileges, and `exec`s Firecracker with its API socket at a chroot-relative
//! path. Every resource the VMM opens must therefore live **inside** the chroot and be named by its
//! chroot-relative path in the API.
//!
//! - **Layout.** The chroot base is the VM's own scratch dir, so teardown's `remove_dir_all` reclaims
//!   the whole jail; the cgroup the jailer creates lives outside it and is removed explicitly. No
//!   `--daemonize`, so Firecracker keeps the piped stdout and the serial console still reaches
//!   [`crate::console`]. The driver mknods nothing itself, which is why the jailer needs real root:
//!   mknod of a device node is `EPERM` in a non-initial user namespace even with `CAP_MKNOD`.
//! - **Scope.** This confines both a jailed cold boot and a jailed restore: the chroot, the uid/gid
//!   drop, the jailer's mount namespace, cgroup cpu/memory limits derived from the guest's envelope
//!   plus a fixed `pids.max`, each fail-open on its own, and Firecracker's built-in seccomp filters,
//!   which `--no-seccomp` is never passed against.
//! - **Composition.** Every boot feature composes with the jail: the vsock exec channel bound
//!   chroot-relative under the dropped uid, the read-only overlay bind-mounted in by
//!   [`stage_ro_base_into_chroot`], a NIC whose tap lives in a per-VM netns the jailer joins, bulk IO
//!   built in place inside the chroot, and snapshot restore from a bundle staged into it.
//! - **Teardown** lives in [`crate::lifetime`]: the jailed VM's sentinel watches the jailer's cgroup at
//!   its precomputed path, so host death reaches a jailed VMM the same way.

use std::num::{NonZeroU8, NonZeroU32};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::VmmError;
use crate::console::Console;
use crate::paths::absolute;
use crate::spawn::check_sun_path;
use crate::vm::FC_STDERR;

/// The default unprivileged uid/gid the jailer drops Firecracker to. Deliberately high and unlikely
/// to collide with a real account; the resources the VMM touches live in a chroot we chown to this
/// id, so it need not exist in `/etc/passwd`. A hoster embedding the engine should override
/// [`Jail::uid`]/[`Jail::gid`] to a dedicated service account.
pub const DEFAULT_JAIL_UID: u32 = 10_000;
/// See [`DEFAULT_JAIL_UID`].
pub const DEFAULT_JAIL_GID: u32 = 10_000;

/// The chroot-relative path Firecracker binds its API socket at (its cwd is the chroot root). The
/// host reaches the same socket at `<chroot_root>/run/firecracker.socket`.
const JAILED_API_SOCKET: &str = "/run/firecracker.socket";

/// The chroot-relative path Firecracker binds the **vsock** exec-channel socket at, placed under
/// `/run` beside the API socket because the jailer makes that dir writable by the dropped uid (so the
/// unprivileged VMM can create the socket there). The host dials the same file at its absolute path
/// `<chroot_root>/run/v.sock`. Strictly shorter than [`JAILED_API_SOCKET`], so if that path cleared
/// `check_sun_path` in [`spawn_jailer`], this one does too.
pub(crate) const JAILED_VSOCK_UDS: &str = "/run/v.sock";

/// The cgroup v2 `cpu.max` accounting period, in microseconds (the kernel default). A cpu quota of
/// `n * CPU_PERIOD_US` per period means `n` cores' worth of CPU.
const CPU_PERIOD_US: u64 = 100_000;

/// Host-side memory headroom above the guest's RAM for the VMM's own footprint (heap, page tables,
/// slack), in MiB. The guest RAM is the hard floor a full-guest workload needs; the rootfs page cache
/// above it is reclaimable, so `mem_mib + this` caps the VMM without OOM-killing a legitimate boot.
/// Measured: a 256 MiB guest booting to userspace peaks ~82 MiB, far under `mem_mib + overhead`.
const MEMORY_OVERHEAD_MIB: u32 = 128;

/// Confine the VMM under Firecracker's jailer. Opt-in via [`crate::BootConfig::jail`]; `None` (the
/// default) boots Firecracker directly, the original unjailed path.
///
/// `#[non_exhaustive]`: construct via [`Jail::new`] / [`Jail::default`] and set fields, so later
/// further knobs (a netns, cgroup limits, seccomp level) can be added without breaking callers.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Jail {
    /// The `jailer` binary (a bare name resolved via `PATH`, or an absolute path). Ships alongside
    /// `firecracker`.
    pub jailer: PathBuf,
    /// The uid the jailer switches to after building the chroot. Shared by every sandbox this
    /// config starts; set [`ids`](Jail::ids) to give each one its own instead.
    pub uid: u32,
    /// The gid the jailer switches to after building the chroot. See [`uid`](Jail::uid).
    pub gid: u32,
    /// A range of ids to spend one pair at a time, overriding [`uid`](Jail::uid)/[`gid`](Jail::gid).
    ///
    /// `None` (the default) runs every sandbox under the one fixed pair, and processes sharing a uid
    /// can signal each other: a guest that escaped into its own VMM would land beside its
    /// neighbours' VMMs at the same id. A span separates them at that layer.
    pub ids: Option<JailIds>,
}

impl Jail {
    /// A jail with the pinned defaults ([`DEFAULT_JAIL_UID`]/[`DEFAULT_JAIL_GID`], `jailer` on
    /// `PATH`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Lease the uid/gid this boot runs under: one pair from [`ids`](Jail::ids) when a span is set,
    /// else the fixed [`uid`](Jail::uid)/[`gid`](Jail::gid) shared by every sandbox.
    ///
    /// # Errors
    /// [`VmmError::Vmm`] when a span is set and every pair in it is already leased.
    pub(crate) fn lease(&self) -> Result<JailLease, VmmError> {
        match &self.ids {
            Some(ids) => ids.lease(),
            None => Ok(JailLease {
                uid: self.uid,
                gid: self.gid,
                span: None,
                withheld: std::sync::atomic::AtomicBool::new(false),
            }),
        }
    }
}

/// A range of host uid/gid pairs the engine may spend, one pair per jailed sandbox.
///
/// **The operator declares the range and the engine spends it.** Uids are a host-wide namespace
/// shared with real accounts, so which of them are free is administration; handing one to each
/// sandbox is the allocation the engine already does for netns names, tap names, and cgroup paths.
/// Neither half learns what a tenant is.
///
/// Cloning shares the allocator, so a [`BootConfig`](crate::BootConfig) cloned into a
/// [`Pool`](crate::Pool) gives every clone it restores a distinct pair rather than a copy of one.
/// Set it on [`Jail::ids`]; leaving it `None` keeps the single fixed pair.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct JailIds {
    base: u32,
    /// One slot per pair, `true` while leased. A `Vec` scan rather than a free list: a span is
    /// small, and always handing out the lowest free slot keeps the ids a reader sees predictable.
    taken: Arc<Mutex<Box<[bool]>>>,
}

impl JailIds {
    /// A span of `count` consecutive pairs from `base`: the sandbox holding slot `i` runs as uid and
    /// gid `base + i`. Pick a range that owns nothing else on the host; the jailer chowns each
    /// chroot to its pair, so the ids need no `/etc/passwd` entry.
    ///
    /// # Errors
    /// [`VmmError::Vmm`] if `base` is 0 (the id the jail exists to leave), if `count` is 0, or if
    /// the range would run past `u32::MAX`.
    pub fn span(base: u32, count: u32) -> Result<Self, VmmError> {
        if base == 0 {
            return Err(VmmError::Vmm(
                "jail id span cannot start at 0: root is the id the jail exists to leave".into(),
            ));
        }
        if count == 0 {
            return Err(VmmError::Vmm(
                "jail id span must hold at least one pair".into(),
            ));
        }
        // A span running past u32 would wrap into ids it never asked for, including 0.
        base.checked_add(count - 1).ok_or_else(|| {
            VmmError::Vmm(format!(
                "jail id span {base}..+{count} runs past the end of the uid range"
            ))
        })?;
        Ok(Self {
            base,
            taken: Arc::new(Mutex::new(vec![false; count as usize].into_boxed_slice())),
        })
    }

    /// Take the lowest free pair, or fail naming the span: exhaustion is a typed error rather than
    /// a fallback onto a shared id, which would silently undo the separation the span buys.
    fn lease(&self) -> Result<JailLease, VmmError> {
        // The guard is confined to this block so nothing that could take the same lock runs while
        // it is held. `self.clone()` below is the case that matters: today it only bumps an `Arc`,
        // but a `Clone` that read the slot table would deadlock a non-reentrant `Mutex`.
        let slot = {
            let mut taken = lock(&self.taken);
            // Grouped so the sum never exceeds the span's own last id: `span` bounds
            // `base + (count - 1)`, not `base + count`, so the ungrouped form overflows on a span
            // that reaches the top of the range. `count >= 1` there, so the subtraction is safe.
            let last = self.base + (taken.len() as u32 - 1);
            let slot = taken.iter().position(|t| !t).ok_or_else(|| {
                VmmError::Vmm(format!(
                    "every jail id in {}..={last} is in use; widen the span or run fewer sandboxes \
                     at once",
                    self.base
                ))
            })?;
            taken[slot] = true;
            slot
        };
        // `slot < count`, and `span` refused a range whose last id would overflow.
        let id = self.base + slot as u32;
        Ok(JailLease {
            uid: id,
            gid: id,
            span: Some((self.clone(), slot)),
            withheld: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Give a slot back. Called only from [`JailLease`]'s drop.
    fn release(&self, slot: usize) {
        if let Some(t) = lock(&self.taken).get_mut(slot) {
            *t = false;
        }
    }
}

/// Lock a span's slot table, recovering from a poisoned mutex rather than propagating the panic.
/// A holder that panicked mid-lease leaves the table structurally intact (one `bool` written), and
/// refusing to allocate afterwards would turn one panic into every later boot failing.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The uid/gid one jailed sandbox runs under, held for as long as its chroot exists.
///
/// Returned to its span on drop **unless the tree those ids own outlived teardown**, in which case
/// [`withhold`](Self::withhold) keeps the slot out of the pool: a chroot still chowned to the pair is
/// exactly what makes handing it to the next sandbox a collision. [`Chroot`] owns the lease and
/// `RunningVm`'s `Drop` runs `teardown` before its fields drop, so the reclaim outcome is known by
/// the time this drops.
#[derive(Debug)]
pub(crate) struct JailLease {
    uid: u32,
    gid: u32,
    /// The span to give the slot back to, and which slot. `None` for the fixed
    /// [`Jail::uid`]/[`Jail::gid`] pair, which is shared and so was never taken from anything.
    span: Option<(JailIds, usize)>,
    /// Set when teardown could not reclaim the chowned tree. Atomic rather than a `bool` because
    /// teardown holds only `&Chroot`, and the VM this hangs off crosses threads.
    withheld: std::sync::atomic::AtomicBool,
}

impl JailLease {
    pub(crate) fn uid(&self) -> u32 {
        self.uid
    }
    pub(crate) fn gid(&self) -> u32 {
        self.gid
    }

    /// Keep this pair out of the span for the driver's lifetime, because the chroot chowned to it is
    /// still on the host. A withheld slot is a permanent in-process loss: the orphan sweep may
    /// reclaim the tree seconds later, but nothing tells this pool, so exhausting a span this way is
    /// a typed refusal naming the span rather than a silent uid collision.
    pub(crate) fn withhold(&self) {
        self.withheld
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Chroot {
    /// Keep this chroot's leased pair out of its span, for a teardown that could not remove the tree
    /// the pair owns. Takes `&self` because `teardown` holds only a shared reference by then.
    pub(crate) fn withhold_lease(&self) {
        self._lease.withhold();
    }
}

impl Drop for JailLease {
    fn drop(&mut self) {
        if self.withheld.load(std::sync::atomic::Ordering::Relaxed) {
            tracing::warn!(
                uid = self.uid,
                gid = self.gid,
                "jail id withheld: its chroot outlived teardown, so the pair stays out of the span"
            );
            return;
        }
        if let Some((ids, slot)) = &self.span {
            ids.release(*slot);
        }
    }
}

impl Default for Jail {
    fn default() -> Self {
        Self {
            jailer: PathBuf::from("jailer"),
            uid: DEFAULT_JAIL_UID,
            gid: DEFAULT_JAIL_GID,
            ids: None,
        }
    }
}

/// The live jail backing a running VMM: where its chroot root is (files are staged in, and the whole
/// tree is reclaimed with the scratch dir), the id it dropped to (to chown staged resources), and the
/// cgroup the jailer created (removed on teardown, since it lives outside the scratch dir).
#[derive(Debug)]
pub(crate) struct Chroot {
    /// The chroot `root/` dir on the host (`<base>/firecracker/<id>/root`). Firecracker's cwd; a
    /// chroot-relative `/x` names `<root>/x`.
    pub(crate) root: PathBuf,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    /// The leased pair, held so it cannot be handed to another sandbox while this chroot exists.
    /// Dropped after `teardown` has reclaimed the tree those ids own, and withheld from the span
    /// entirely when it has not (see [`JailLease`]).
    _lease: JailLease,
    /// The cgroup dir the jailer created for this VMM (`/sys/fs/cgroup/<...>`), learned from
    /// `/proc/<pid>/cgroup` once the VMM is up. Removed (best-effort) on teardown; `None` until read.
    pub(crate) cgroup_dir: Option<PathBuf>,
    /// The host paths of the read-only **bind mounts** staged into the chroot
    /// ([`stage_ro_base_into_chroot`]): the shared rootfs base for a `read_only_root` jailed boot,
    /// and a jailed restore's snapshot memory file + shared base disk. Each must be unmounted before
    /// the scratch dir's `remove_dir_all`, or the mount point `EBUSY`s and leaks the chroot. Empty
    /// for a read-write boot (a plain copy) or the copy fallback on a non-shared scratch.
    pub(crate) mounts: Vec<PathBuf>,
}

impl Chroot {
    /// A fresh chroot record for a just-spawned jail: `root` on the host, the pair the jailer
    /// dropped to, no cgroup learned yet, and no mounts staged yet (`run_boot`/`run_restore` record
    /// those as they bind them). One constructor so both jailed launch paths assemble it identically.
    ///
    /// Takes the **lease** rather than the [`Jail`], so the ids a chroot reports are the ones its
    /// VMM actually runs under: re-reading `jail.uid` here would report the fixed pair for a boot
    /// that leased a different one from a span.
    pub(crate) fn new(root: PathBuf, lease: JailLease) -> Self {
        Self {
            root,
            uid: lease.uid(),
            gid: lease.gid(),
            _lease: lease,
            cgroup_dir: None,
            mounts: Vec::new(),
        }
    }

    /// Detach every bind mount staged into this chroot (lazy, best-effort), the step that must run
    /// before the scratch dir's `remove_dir_all` or the mount point `EBUSY`s and leaks the chroot.
    /// One home for the invariant, shared by `teardown` and `abort`. A no-op when nothing was mounted.
    pub(crate) fn unmount_all(&self) {
        for mount in &self.mounts {
            unmount_base(mount);
        }
    }
}

/// Spawn the **jailer**, which builds the chroot and `exec`s Firecracker inside it. Returns the child
/// (whose pid is Firecracker's, since the jailer `exec`s rather than forks), its console, the host
/// path of the API socket, and the chroot root (where resources are staged before boot).
///
/// The jailer's own stderr and Firecracker's share `<workdir>/fc.stderr` (so `abort` can surface a
/// jail-setup failure like a failed mknod); Firecracker's stdout stays piped for the serial console.
/// On a spawn failure nothing is left running; the caller owns `workdir` cleanup.
pub(crate) fn spawn_jailer(
    jail: &Jail,
    ids: (u32, u32),
    firecracker: &Path,
    workdir: &Path,
    id: &str,
    cgroup_args: &[String],
    netns: Option<&Path>,
) -> Result<(Child, Console, PathBuf, PathBuf), VmmError> {
    // `--exec-file` must be an absolute path to a real binary: the jailer copies it into the chroot,
    // and derives the chroot subdir from its file name (so `.../firecracker/<id>/root`).
    let exec = resolve_exec(firecracker)?;
    let exec_name = exec.file_name().ok_or_else(|| {
        VmmError::Vmm(format!(
            "firecracker path has no file name: {}",
            exec.display()
        ))
    })?;
    let chroot_root = workdir.join(exec_name).join(id).join("root");
    // Firecracker binds `/run/firecracker.socket` relative to its cwd (the chroot root), so on the
    // host the socket is `<chroot_root>/run/firecracker.socket`.
    let socket = chroot_root.join("run/firecracker.socket");
    // The jailer's chroot nests the socket deep under the scratch dir, so this is the path most
    // likely to overflow `sun_path`, fail clearly now, not as a cryptic bind failure mid-boot.
    check_sun_path(&socket)?;

    let fc_stderr = std::fs::File::create(workdir.join(FC_STDERR))
        .map_err(|e| VmmError::Vmm(format!("create firecracker stderr log: {e}")))?;
    let mut cmd = Command::new(&jail.jailer);
    cmd.arg("--id")
        .arg(id)
        .arg("--exec-file")
        .arg(&exec)
        .arg("--uid")
        .arg(ids.0.to_string())
        .arg("--gid")
        .arg(ids.1.to_string())
        .arg("--chroot-base-dir")
        .arg(workdir)
        // This host is cgroup v2 only; the jailer defaults to v1 and would fail to find the
        // hierarchy. The jailer always creates the microVM's cgroup (teardown removes it).
        .arg("--cgroup-version")
        .arg("2");
    // CPU/memory limits: the jailer writes each `<file>=<value>` into that cgroup. Empty when
    // the host doesn't delegate the cgroup v2 controllers (see `cgroup_limit_args`), so a jailed boot
    // still runs there, just without limits.
    for arg in cgroup_args {
        cmd.arg("--cgroup").arg(arg);
    }
    // Networked boot: the jailer opens this netns handle and `setns`es into it (as root,
    // before dropping privileges) so the confined Firecracker runs in the VM's own network namespace,
    // where its tap lives. The tap was created owned by the jailed uid, so the unprivileged VMM can
    // attach it.
    if let Some(netns) = netns {
        cmd.arg("--netns").arg(netns);
    }
    // Everything after `--` is Firecracker's. No `--daemonize` (keep its stdout so the guest serial
    // console still reaches the host) and no `--no-seccomp`: Firecracker installs its built-in
    // per-thread seccomp filters by default, and we deliberately never disable them.
    cmd.arg("--")
        .arg("--api-sock")
        .arg(JAILED_API_SOCKET)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(fc_stderr));
    let mut child = cmd.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            VmmError::Artifact(format!("jailer not found: {}", jail.jailer.display()))
        } else {
            VmmError::Vmm(format!("spawn jailer: {e}"))
        }
    })?;
    let stdout = child.stdout.take();
    match Console::spawn(stdout) {
        Ok(console) => Ok((child, console, socket, chroot_root)),
        Err(e) => {
            // Bounded like every other reap on this path; no console to drain (its spawn failed).
            crate::drives::kill_and_reap_briefly(&mut child, "jailer", crate::vm::VMM_REAP_GRACE);
            // The jailer creates the VM's cgroup early (before it execs Firecracker), but on this
            // failure the lifetime sentinel isn't armed yet and no `Chroot` exists to carry the dir
            // into teardown, so remove it here (best-effort) rather than leak an empty cgroup. This
            // branch fires on `Console::spawn` EAGAIN, i.e. under exactly the many-sandbox load where
            // leaked cgroups would accrue.
            if let Some(cgroup) = jailer_cgroup_dir(firecracker, id) {
                remove_cgroup(&cgroup);
            }
            Err(e)
        }
    }
}

/// Copy `src` into the chroot as `<root>/<name>`, give it `mode`, and chown it to the jailed uid/gid
/// so the dropped-privilege Firecracker can open it. Returns the **chroot-relative** path (`/<name>`)
/// to name it by in the API. Called once the chroot exists (after the VMM's API socket is up), so it
/// never races the jailer's chroot construction.
///
/// The copy is the honest cost of the jail on a **read-write** boot: the kernel and rootfs live
/// outside the chroot, and hardlinking across the `/tmp` (tmpfs) boundary would `EXDEV`. A
/// `read_only_root` boot instead bind-mounts the shared base zero-copy ([`stage_ro_base_into_chroot`]).
pub(crate) fn stage_into_chroot(
    root: &Path,
    name: &str,
    src: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<String, VmmError> {
    let dst = root.join(name);
    std::fs::copy(src, &dst)
        .map_err(|e| VmmError::Vmm(format!("stage {} into jail: {e}", src.display())))?;
    give_to_jail(&dst, uid, gid, mode)?;
    Ok(format!("/{name}"))
}

/// Hand a chroot-resident file to the jailed uid: set `mode` and chown to `uid:gid`, so the
/// dropped-privilege Firecracker can open it. The shared tail of [`stage_into_chroot`] (copied
/// resources) and the bulk-I/O images (built in place inside the chroot, nothing to copy).
/// `std::os::unix::fs::chown` is a safe wrapper (no `unsafe` on the host path).
pub(crate) fn give_to_jail(path: &Path, uid: u32, gid: u32, mode: u32) -> Result<(), VmmError> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| VmmError::Vmm(format!("chmod staged {}: {e}", path.display())))?;
    std::os::unix::fs::chown(path, Some(uid), Some(gid)).map_err(|e| {
        VmmError::Vmm(format!(
            "chown staged {} to {uid}:{gid}: {e}",
            path.display()
        ))
    })
}

/// Stage the **read-only shared base** into the chroot for a `read_only_root` jailed boot, the
/// shared-base path, the jailed counterpart of the unjailed read-only boot that references one base in
/// place. Instead of a full per-VM copy ([`stage_into_chroot`]), **bind-mount** the one base file
/// into the chroot, so every jailed VM shares its inode (and page cache); the guest layers a per-run
/// tmpfs overlay over it (`overlay-init`), so `/` is writable but the base is never mutated.
///
/// The bind mount is made in the driver's (host) mount namespace, yet the jailer runs the VMM in an
/// `MS_SLAVE` mount namespace: a mount created under a **shared** host mount propagates *in*, so the
/// jailed Firecracker sees it. When the scratch base is **not** a shared mount (a hoster pointed
/// `scratch_dir` at a private mount, so the propagation can't reach the slave namespace), fall back
/// to a read-only **copy**, correct and still base-immutable, just not page-cache-deduped. Memory-sharing is
/// a best-effort property; the isolation is not, and the copy confines identically.
///
/// Returns the chroot-relative path to name in the API, and `Some(host_mount_path)` when a bind mount
/// was made, so teardown unmounts it before reclaiming the scratch dir (`None` for the copy fallback,
/// which needs no unmount). Base perms must let the dropped uid read it (the pinned base is `0644`); a
/// bind mount exposes the source's mode, so no chown is applied to a shared inode.
pub(crate) fn stage_ro_base_into_chroot(
    root: &Path,
    name: &str,
    src: &Path,
    scratch_dir: &Path,
    uid: u32,
    gid: u32,
    deadline: Instant,
) -> Result<(String, Option<PathBuf>), VmmError> {
    let rel = format!("/{name}");
    if !scratch_is_shared_mount(scratch_dir) {
        tracing::warn!(
            scratch = %scratch_dir.display(),
            "jailed read-only base: the scratch dir is not a shared mount, so a bind mount would not \
             reach the jailer's mount namespace; falling back to a per-VM read-only copy (correct, \
             but not page-cache-deduped). Put the scratch dir on a shared mount for the shared-base path."
        );
        // Read-only copy fallback (0444, chowned so the dropped uid can open it).
        stage_into_chroot(root, name, src, uid, gid, 0o444)?;
        return Ok((rel, None));
    }
    let src = absolute(src)?;
    let dst = root.join(name);
    // The bind-mount target must exist; create an empty placeholder the mount then shadows.
    std::fs::File::create(&dst)
        .map_err(|e| VmmError::Vmm(format!("create bind target {}: {e}", dst.display())))?;
    bind_ro(&src, &dst, deadline)?;
    Ok((rel, Some(dst)))
}

/// Bind-mount `src` onto `dst` **read-only**. Two steps on purpose: a bind mount is read-write
/// regardless of a `-o ro` on the initial call, so a second `remount,ro,bind` is what actually drops
/// write access, the base then can't be mutated through the chroot even before Firecracker opens it
/// `O_RDONLY`. Shells out to `mount` (as the tap path shells out to `ip`), keeping the host path
/// `unsafe`-free. Both invocations are bounded by the boot `deadline`, with stdout nulled and
/// stderr captured into the error:
/// mount-family syscalls can wedge in D-state (the hazard `unmount_base` already defends against),
/// and an unbounded one would hang the boot past the `Timeout` the wall promises. If the remount
/// fails, the half-made bind mount is detached before returning rather than left behind.
fn bind_ro(src: &Path, dst: &Path, deadline: Instant) -> Result<(), VmmError> {
    match run_mount(
        Command::new("mount").arg("--bind").arg(src).arg(dst),
        "mount --bind",
        deadline,
    ) {
        Ok((status, _)) if status.success() => {}
        // Detach on *every* failure path, not only the remount's: a deadline kill can land after
        // the child's `mount(2)` completed, and the caller records the mount for teardown only on
        // `Ok`, so an undetached one here would EBUSY the scratch reclaim. `unmount_base` is a
        // lazy-detach no-op when nothing was mounted. One residual stays: a D-state mount child
        // detached past the reap grace can complete *after* this detach; that leak is bounded by
        // the orphan sweep's `detach_mounts_under`, which retries the dir.
        Ok((status, stderr)) => {
            unmount_base(dst);
            return Err(VmmError::Vmm(format!(
                "bind-mount {} -> {}: {}",
                src.display(),
                dst.display(),
                crate::proc::failure_detail(status, &stderr)
            )));
        }
        Err(e) => {
            unmount_base(dst);
            return Err(e);
        }
    }
    match run_mount(
        Command::new("mount")
            .arg("-o")
            .arg("remount,ro,bind")
            .arg(dst),
        "mount -o remount,ro,bind",
        deadline,
    ) {
        Ok((status, _)) if status.success() => Ok(()),
        Ok((status, stderr)) => {
            unmount_base(dst);
            Err(VmmError::Vmm(format!(
                "remount read-only {}: {}",
                dst.display(),
                crate::proc::failure_detail(status, &stderr)
            )))
        }
        Err(e) => {
            unmount_base(dst);
            Err(e)
        }
    }
}

/// One bounded `mount` invocation: `(exit status, captured stderr)` for the caller's own error
/// wording. Timeout/spawn failures come back typed (`Timeout`/`Artifact`/`Vmm`) with the child
/// killed and reaped, per [`crate::drives::wait_bounded`].
fn run_mount(
    cmd: &mut Command,
    what: &str,
    deadline: Instant,
) -> Result<(std::process::ExitStatus, String), VmmError> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        // stderr captured, not nulled: `mount`'s own line ("only root can do that", "wrong fs
        // type", "special device does not exist") is the whole diagnosis, and an exit status
        // alone leaves a failed bind undebuggable. stdout stays null (pipe-clean result stream).
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| crate::drives::tool_spawn_error("mount", e))?;
    // A 2ms tick: `mount` completes in ~1ms, and this runs per bind mount on the jailed
    // boot/restore hot path, where a coarse tick would tax the published restore latency.
    let status = crate::drives::wait_bounded(
        &mut child,
        deadline,
        what,
        std::time::Duration::from_millis(2),
    )?;
    // Read after exit. This terminates because a bind `mount` execs no filesystem helper and
    // backgrounds nothing, so reaping the child closed the pipe's last write end.
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        use std::io::Read as _;
        let _ = pipe.read_to_string(&mut stderr);
    }
    Ok((status, stderr))
}

/// Detach a base bind mount (best-effort, **lazy**). `umount -l` never blocks on a busy mount: by
/// teardown the VMM is already reaped, but a lazy detach also means a mount left by a crashed-mid-boot
/// driver can always be cleared, so the scratch dir's `remove_dir_all` never `EBUSY`s. Failures are
/// ignored: a path that isn't a mount (the copy fallback, or one already gone) is a harmless no-op.
pub(crate) fn unmount_base(path: &Path) {
    // Bounded like `netns_del`: this runs in teardown/`Drop`, and `umount` (even lazy) can wedge in
    // the kernel behind a busy mount, which a plain `.status()` would let hang `Drop`. On timeout
    // `run_bounded` detaches; a mount left behind is retried by the orphan sweep's `detach_mounts_under`.
    let mut cmd = Command::new("umount");
    cmd.arg("-l").arg(path);
    let _ = crate::proc::run_bounded(cmd, crate::proc::TEARDOWN_HELPER_TIMEOUT, "umount -l");
}

/// Whether the filesystem mount backing `path` is a **shared** mount (carries a `shared:N` peer-group
/// tag in `/proc/self/mountinfo`). Only a mount made under a shared host mount propagates into the
/// jailer's `MS_SLAVE` namespace, so this gates the bind-mount shared-base path against the copy fallback.
/// Resolves `path` to the longest mount point that is a path-prefix of it (the mount it lives on).
fn scratch_is_shared_mount(path: &Path) -> bool {
    let Ok(target) = absolute(path) else {
        return false;
    };
    let Ok(info) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    mount_is_shared(&info, &target)
}

/// Whether the longest mount point that is a path-prefix of `target` carries a `shared:N` tag, given
/// the raw `/proc/self/mountinfo` text. Split from the I/O so the field-walk is unit-testable: a
/// mountinfo line is `id pid maj:min root MOUNTPOINT opts [optional tags...] - fstype src super`, and
/// the optional tags (where `shared:N` lives) run from field 6 up to a standalone `-`.
fn mount_is_shared(mountinfo: &str, target: &Path) -> bool {
    let mut best: Option<(usize, bool)> = None;
    for mount in crate::mountinfo::mounts(mountinfo) {
        if !target.starts_with(&mount.point) {
            continue;
        }
        let shared = mount.shared;
        let depth = mount.point.components().count();
        // `>=`, not `>`: on an *overmount* (two mounts at the same point, so equal depth) the topmost,
        // the **last** mountinfo line, governs what a later mount there inherits. Keeping the
        // first-seen line would read a point listed `shared:` first then private-later as shared, take
        // the bind path with no copy fallback, and hard-fail the jailed boot (the bind wouldn't
        // propagate). Later same-depth line wins; a strictly deeper mount point still wins over both.
        if best.map(|(d, _)| depth >= d).unwrap_or(true) {
            best = Some((depth, shared));
        }
    }
    best.map(|(_, shared)| shared).unwrap_or(false)
}

/// Resolve `firecracker` to an absolute path for `--exec-file`: an absolute path as-is, a path with a
/// directory component against the driver's cwd, and a bare name via `PATH` (mirroring how spawning
/// it directly would resolve it).
fn resolve_exec(firecracker: &Path) -> Result<PathBuf, VmmError> {
    if firecracker.is_absolute() {
        return Ok(firecracker.to_path_buf());
    }
    if firecracker.components().count() > 1 {
        return absolute(firecracker).map(|p| p.into_owned());
    }

    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let cand = dir.join(firecracker);
            if cand.is_file() {
                return Ok(cand);
            }
        }
    }
    Err(VmmError::Artifact(format!(
        "firecracker not found in PATH: {}",
        firecracker.display()
    )))
}

/// The cgroup dir the jailer will create for a VM, computed **before** the jailer is spawned:
/// `--cgroup-version 2` with no `--parent-cgroup` places the VMM at
/// `<cgroup root>/<exec-file name>/<id>`. The name component is whatever the resolved binary is
/// called: the jailer accepts any exec-file name since v1.13, so an embedder pointing
/// `BSX_FIRECRACKER` at, say, `/opt/fc` gets a `fc` component. Reading it off the resolved path rather than assuming a literal is what keeps
/// this correct either way. Precomputing it lets the lifetime sentinel
/// watch the cgroup from the moment the jailer is spawned instead of after boot; `run_boot` still
/// learns the *actual* dir from `/proc` and warns if they ever disagree.
pub(crate) fn jailer_cgroup_dir(firecracker: &Path, id: &str) -> Option<PathBuf> {
    let exec = resolve_exec(firecracker).ok()?;
    let name = exec.file_name()?.to_owned();
    Some(Path::new("/sys/fs/cgroup").join(name).join(id))
}

/// The cgroup dir the jailer placed `pid` in, read from `/proc/<pid>/cgroup` (version-independent, so
/// no assumption about the jailer's parent-cgroup layout). Unified cgroup v2 shows one `0::<path>`
/// line; the dir is `/sys/fs/cgroup<path>`. `None` for the root cgroup or an unreadable/empty entry.
pub(crate) fn read_cgroup_dir(pid: u32) -> Option<PathBuf> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let rel = text.lines().find_map(|l| l.strip_prefix("0::"))?.trim();
    if rel.is_empty() || rel == "/" {
        return None;
    }
    Some(Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/')))
}

/// Remove the jailer's cgroup for a torn-down VMM (best-effort). The VMM must already be reaped, so
/// its cgroup is empty and `rmdir`-able; `remove_dir` only removes an empty dir, so this never
/// disturbs a sibling VM sharing the parent. Tries the leaf then its parent (the shared
/// `.../firecracker` dir), the latter succeeding only once the last VM under it is gone.
pub(crate) fn remove_cgroup(dir: &Path) {
    let _ = std::fs::remove_dir(dir);
    if let Some(parent) = dir.parent() {
        // Guard against walking up to the cgroup mount root; only reap the jailer's own subtree.
        if parent != Path::new("/sys/fs/cgroup") {
            let _ = std::fs::remove_dir(parent);
        }
    }
}

/// Host-side cap on the number of tasks (processes + threads) the jailed VMM's cgroup may hold
/// (`pids.max`). A guest fork-bomb is already bounded by `memory.max` and never reaches the host (its
/// processes live in the guest's own kernel); this is **defense in depth** for the narrow case
/// of a hypervisor-level exploit that tries to fork *host* processes. Firecracker itself holds only a
/// handful of tasks (an API + VMM thread and one per vCPU), so 1024 is enormous headroom that never
/// trips a legitimate boot while still capping a runaway.
///
/// Public so the privileged readback test asserts the live cgroup carries *this* value, not a
/// hand-copied literal that could drift (the same reason [`crate::FDS_PER_VM`] is public).
pub const VMM_PIDS_MAX: u64 = 1024;

/// The cgroup v2 controllers the root delegates in `cgroup.subtree_control` (a systemd host delegates
/// cpu/memory/pids out of the box). Each is gated independently: the jailer sets a limit by enabling
/// its controller down from the root, which only works when that controller is already delegated there,
/// so passing `--cgroup <file>` for an undelegated controller would make the jailer *fail* the boot.
struct Delegated {
    cpu: bool,
    memory: bool,
    pids: bool,
}

/// Read which controllers the cgroup root delegates. Absent/unreadable (a bare container) reads all
/// false, so the caller passes no `--cgroup` and the jailed boot still runs (fail-open).
fn read_delegated() -> Delegated {
    let subtree =
        std::fs::read_to_string("/sys/fs/cgroup/cgroup.subtree_control").unwrap_or_default();
    let toks: Vec<&str> = subtree.split_whitespace().collect();
    Delegated {
        cpu: toks.contains(&"cpu"),
        memory: toks.contains(&"memory"),
        pids: toks.contains(&"pids"),
    }
}

/// Build the `--cgroup <file>=<value>` limits from the delegation state, pure, so the
/// per-controller fail-open logic is unit-tested without a live cgroup fs. `cpu.max` bounds total CPU
/// to `vcpus` cores and `memory.max` to the guest's RAM plus a fixed host-side overhead; both require
/// the cpu **and** memory controllers, so a host missing either gets no limits at all (empty). The
/// host-side `pids.max` cap is added only when the `pids` controller is *also* delegated, so a host
/// with cpu/memory but not pids keeps its cpu/memory caps (each controller fails open on its own).
fn cgroup_args_for(d: &Delegated, vcpus: NonZeroU8, mem_mib: NonZeroU32) -> Vec<String> {
    if !(d.cpu && d.memory) {
        return Vec::new();
    }
    let quota = u64::from(vcpus.get()) * CPU_PERIOD_US;
    let memory_max = (u64::from(mem_mib.get()) + u64::from(MEMORY_OVERHEAD_MIB)) * 1024 * 1024;
    let mut args = vec![
        format!("memory.max={memory_max}"),
        format!("cpu.max={quota} {CPU_PERIOD_US}"),
    ];
    if d.pids {
        args.push(format!("pids.max={VMM_PIDS_MAX}"));
    }
    args
}

/// Resolve the jailer `--cgroup` args from the delegation state, honoring a `require_limits` caller.
/// With `require_limits` set, a host that can't apply the cpu/memory caps is a typed refusal
/// ([`VmmError::LimitsUnavailable`]) instead of the default empty-args fail-open. Pure
/// (takes the [`Delegated`] state), so both the fail-open and fail-closed paths are unit-tested
/// without a live cgroup fs. `require_limits` keys on cpu **and** memory, the caps that bound the
/// resource envelope; the `pids.max` defense-in-depth cap stays best-effort either way (its absence
/// can't let a guest exceed its cpu/memory envelope, so it never forces a refusal).
fn resolve_cgroup_caps(
    require_limits: bool,
    d: &Delegated,
    vcpus: NonZeroU8,
    mem_mib: NonZeroU32,
) -> Result<Vec<String>, VmmError> {
    if require_limits && !(d.cpu && d.memory) {
        return Err(VmmError::LimitsUnavailable(
            "cgroup v2 cpu/memory controllers are not delegated to the cgroup root, so the jailed \
             microVM cannot be capped; require_limits refuses an uncapped run (a systemd host \
             delegates them by default)"
                .to_string(),
        ));
    }
    Ok(cgroup_args_for(d, vcpus, mem_mib))
}

/// The `--cgroup <file>=<value>` limits that cap the jailed VMM at the guest's own resource envelope
/// (see [`cgroup_args_for`]). Fails open when the cpu/memory controllers aren't delegated (empty
/// args, the boot still runs) *unless* `require_limits` is set, which turns that miss into a typed
/// [`VmmError::LimitsUnavailable`] refusal ([`resolve_cgroup_caps`]); warns on each fail-open path.
pub(crate) fn cgroup_limit_args(
    require_limits: bool,
    vcpus: NonZeroU8,
    mem_mib: NonZeroU32,
) -> Result<Vec<String>, VmmError> {
    let delegated = read_delegated();
    let caps_ok = delegated.cpu && delegated.memory;
    // Warn only on a fail-*open* miss: under `require_limits` the same miss returns the typed error
    // below, whose message carries the same information, so a preceding warn would just be noise.
    if !caps_ok && !require_limits {
        tracing::warn!(
            "cgroup v2 cpu/memory controllers are not delegated to the cgroup root; the jailed \
             microVM runs without CPU/memory limits (a systemd host delegates them by default)"
        );
    } else if caps_ok && !delegated.pids {
        tracing::warn!(
            "cgroup v2 pids controller is not delegated to the cgroup root; the jailed microVM runs \
             without a host-side PID cap (cpu/memory limits still apply)"
        );
    }
    resolve_cgroup_caps(require_limits, &delegated, vcpus, mem_mib)
}

/// The memory envelope to cap a **restored** jailed clone at: the larger of the caller's `config`
/// value and the guest RAM the snapshot memory file implies (`mem_file_len` bytes, since a full
/// snapshot's memory file *is* the guest's RAM). Deriving from the file's true guest RAM means the cap
/// can never fall *below* what the restored guest actually uses, the exact hazard that kept restore
/// uncapped: a `config` under-declaring the envelope must not OOM-kill a legitimate clone. Pure, so
/// the max logic is unit-tested without a real snapshot.
pub(crate) fn restore_mem_mib(config_mem_mib: NonZeroU32, mem_file_len: u64) -> NonZeroU32 {
    let from_file = u32::try_from(mem_file_len / (1024 * 1024)).unwrap_or(u32::MAX);
    NonZeroU32::new(from_file.max(config_mem_mib.get())).unwrap_or(config_mem_mib)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_span_hands_every_pair_out_once_then_refuses_by_name() {
        let ids = JailIds::span(20_000, 3).expect("a valid span");
        let held: Vec<JailLease> = (0..3).map(|_| ids.lease().expect("a free pair")).collect();
        // Distinct, and each uid equals its gid: one identity per sandbox, not a shared pool.
        let uids: Vec<u32> = held.iter().map(JailLease::uid).collect();
        assert_eq!(uids, vec![20_000, 20_001, 20_002]);
        assert!(held.iter().all(|l| l.uid() == l.gid()));

        // Exhaustion is a typed refusal naming the span, never a quiet fallback onto a shared id:
        // falling back would undo the separation the span was configured to buy, invisibly.
        let err = ids
            .lease()
            .expect_err("a full span has nothing to hand out");
        let msg = err.to_string();
        assert!(
            msg.contains("20000") && msg.contains("20002"),
            "the refusal must name the span it exhausted: {msg}"
        );
    }

    #[test]
    fn a_released_pair_is_handed_to_the_next_sandbox() {
        let ids = JailIds::span(20_000, 2).expect("a valid span");
        let first = ids.lease().expect("a free pair");
        let second = ids.lease().expect("a free pair");
        assert_eq!((first.uid(), second.uid()), (20_000, 20_001));

        // A torn-down sandbox gives its id back, so a long-lived pool churns inside its span rather
        // than exhausting it.
        drop(first);
        let third = ids.lease().expect("the released pair is free again");
        assert_eq!(third.uid(), 20_000);
        assert!(ids.lease().is_err(), "only the released one came back");
    }

    #[test]
    fn a_cloned_span_shares_its_allocator_but_a_fixed_jail_leases_the_same_pair_forever() {
        // The property the pool depends on: a `BootConfig` cloned per clone must not clone the
        // allocator's state, or every pooled sandbox would be handed the same first id.
        let ids = JailIds::span(20_000, 2).expect("a valid span");
        let a = ids.clone().lease().expect("a free pair");
        let b = ids.clone().lease().expect("a free pair");
        assert_ne!(a.uid(), b.uid(), "clones must share the allocator");

        // Without a span, `Jail`'s fixed pair is what every sandbox gets, which is exactly the
        // sharing a span exists to end. Unchanged behaviour for a caller that sets no span.
        let jail = Jail::default();
        let one = jail.lease().expect("the fixed pair");
        let two = jail.lease().expect("the fixed pair again");
        assert_eq!((one.uid(), two.uid()), (DEFAULT_JAIL_UID, DEFAULT_JAIL_UID));
    }

    #[test]
    fn a_withheld_pair_never_returns_to_its_span() {
        // The reuse contract `JailLease` documents: a chroot chowned to a pair outlives a failed
        // teardown, so handing that pair to the next sandbox would put two on-host trees under one
        // uid. Withholding costs a slot; reusing costs the separation the span is for.
        let ids = JailIds::span(30_000, 2).expect("a valid span");
        let leaked = ids.lease().expect("a free pair");
        let kept = ids.lease().expect("the second pair");
        let (leaked_uid, kept_uid) = (leaked.uid(), kept.uid());

        leaked.withhold();
        drop(leaked);
        assert!(
            ids.lease().is_err(),
            "the withheld pair must not come back, even with the span otherwise exhausted"
        );

        // The ordinary path is untouched: a pair released after a clean teardown is reusable.
        drop(kept);
        let reused = ids
            .lease()
            .expect("the cleanly released pair is free again");
        assert_eq!(reused.uid(), kept_uid);
        assert_ne!(reused.uid(), leaked_uid, "and it is not the withheld one");
    }

    #[test]
    fn a_span_refuses_a_range_it_could_not_safely_spend() {
        // 0 is the id the jail exists to leave, so a span may not start there or contain it.
        assert!(JailIds::span(0, 4).is_err());
        // An empty span would refuse every boot; say so at construction, not at the first lease.
        assert!(JailIds::span(20_000, 0).is_err());
        // A range running past u32 would wrap into ids nobody asked for, including 0.
        assert!(JailIds::span(u32::MAX, 2).is_err());
        assert!(JailIds::span(u32::MAX, 1).is_ok(), "the last id alone fits");
    }

    #[test]
    fn a_span_at_the_top_of_the_range_leases_and_names_itself() {
        // The span above is valid, so every jailed boot from it calls `lease`. Reaching the span's
        // last id must not compute `base + count` on the way: that intermediate is one past the
        // range `span` bounded, which panics the boot path in a debug build and wraps in release.
        let ids = JailIds::span(u32::MAX, 1).expect("the last id alone is a valid span");
        let leased = ids.lease().expect("the one pair is free");
        assert_eq!((leased.uid, leased.gid), (u32::MAX, u32::MAX));

        // Exhaustion is the only reader of that bound, so it is where a wrapped value would show.
        let err = ids
            .lease()
            .expect_err("the span holds one pair and it is taken");
        let msg = err.to_string();
        assert!(
            msg.contains(&format!("{}..={}", u32::MAX, u32::MAX)),
            "the refusal names the real span rather than a wrapped one: {msg}"
        );
    }

    // Poisoning a mutex takes a panic while its guard is held, so the state under test cannot be
    // reached without one. The workspace's `clippy::panic` deny does not exempt a closure passed to
    // `thread::spawn`, even inside a `#[test]`.
    #[allow(clippy::panic)]
    #[test]
    fn a_poisoned_span_still_allocates() {
        // One panicking holder must not turn every later boot into a failure: the slot table is
        // structurally intact after a poison, so the lock is recovered rather than propagated.
        let ids = JailIds::span(20_000, 2).expect("a valid span");
        let poisoner = ids.clone();
        let _ = std::thread::spawn(move || {
            let _guard = lock(&poisoner.taken);
            panic!("poison the allocator");
        })
        .join();
        assert!(ids.taken.is_poisoned(), "the panic must have poisoned it");
        assert_eq!(ids.lease().expect("still allocates").uid(), 20_000);
    }

    // A slice of real `/proc/self/mountinfo`: `/` and `/tmp` are shared peers, `/mnt/private` is a
    // private mount (no `shared:` tag), and `/mnt/slave` receives from a master but is not itself
    // shared. Only a *shared* mount propagates a later bind mount into the jailer's slave namespace.
    const MOUNTINFO: &str = "\
21 1 0:20 / / rw,relatime shared:1 - ext4 /dev/root rw
30 21 0:24 / /tmp rw,nosuid,nodev shared:128 - tmpfs tmpfs rw
40 21 0:30 / /mnt/private rw,relatime - ext4 /dev/sdb rw
50 21 0:31 / /mnt/slave rw,relatime master:9 - ext4 /dev/sdc rw
";

    #[test]
    fn a_wedged_mount_is_a_timeout_not_a_hung_boot() {
        // The branch bounding the mounts exists for: a mount-family syscall wedged in D-state used
        // to hang `Vm::boot` forever, past the wall the caller was promised. `sleep` stands in for
        // the wedge (the same stand-in `wait_bounded`'s own test uses), since a real one needs a
        // busy or broken filesystem.
        let started = Instant::now();
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        let err = run_mount(
            &mut cmd,
            "mount --bind",
            started + std::time::Duration::from_millis(100),
        )
        .expect_err("a mount past its deadline must not return a status");
        assert!(matches!(err, VmmError::Timeout(_)), "got {err:?}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "the boot must fail at its wall, not wait the wedged mount out"
        );
    }

    #[test]
    fn a_failed_bind_leaves_no_mount_behind() {
        // The failure path that must still detach: a deadline kill can land after the child's
        // `mount(2)` completed, and the caller records a mount for teardown only on `Ok`, so an
        // undetached one would EBUSY the scratch reclaim.
        //
        // The *reason* the bind fails has to differ by privilege, or the test stops testing a
        // failure. Unprivileged, binding onto a real file is EPERM. As root that bind would
        // **succeed**, and the leak assertion below would fire on a mount the test itself made, so
        // root gets a destination that does not exist (ENOENT for everyone). Either way the branch
        // under test is "mount returned non-zero", and either way nothing may be left mounted.
        let dir = std::env::temp_dir().join(format!("bsx-bindro-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let src = dir.join("src");
        std::fs::write(&src, b"base").expect("write src");
        let dst = if bsx_test_support::have_real_root() {
            dir.join("no-such-dst")
        } else {
            let dst = dir.join("dst");
            std::fs::write(&dst, b"").expect("write dst");
            dst
        };

        let err = bind_ro(
            &src,
            &dst,
            Instant::now() + std::time::Duration::from_secs(5),
        )
        .expect_err("this bind cannot succeed on either host");
        let msg = err.to_string();
        assert!(
            !msg.trim_end().ends_with(':'),
            "a failed bind must name a cause, from mount's stderr or its status: {msg}"
        );
        let mounts = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
        let leaked = mounts
            .lines()
            .any(|l| l.split(' ').nth(4) == Some(&dst.to_string_lossy()));
        assert!(
            !leaked,
            "a bind that did not fully succeed must leave nothing mounted at {dst:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shared_mount_gates_the_shared_base_path() {
        // A scratch dir on a shared mount (`/tmp`, or nested under it) takes the bind-mount memory-sharing
        // path; the longest matching mount point wins, so a file under `/tmp` reads `/tmp`'s tag.
        assert!(mount_is_shared(MOUNTINFO, Path::new("/tmp")));
        assert!(mount_is_shared(
            MOUNTINFO,
            Path::new("/tmp/bsx-42-0/firecracker")
        ));
        // The root is shared, so a path on no more-specific mount inherits its propagation.
        assert!(mount_is_shared(MOUNTINFO, Path::new("/var/lib/bsx")));
    }

    #[test]
    fn private_or_slave_scratch_falls_back_to_copy() {
        // Neither a private mount nor a pure slave propagates a later bind mount into the jailer's
        // namespace, so both must read false (the copy fallback, not a broken shared-base path).
        assert!(!mount_is_shared(
            MOUNTINFO,
            Path::new("/mnt/private/scratch")
        ));
        assert!(!mount_is_shared(MOUNTINFO, Path::new("/mnt/slave/scratch")));
    }

    #[test]
    fn cgroup_args_fail_open_per_controller() {
        let has = |args: &[String], p: &str| args.iter().any(|s| s.starts_with(p));
        let vcpus = NonZeroU8::new(2).unwrap();
        let mem_mib = NonZeroU32::new(256).unwrap();

        // Everything delegated: cpu + memory + the host-side pid cap.
        let all = Delegated {
            cpu: true,
            memory: true,
            pids: true,
        };
        let a = cgroup_args_for(&all, vcpus, mem_mib);
        assert!(has(&a, "cpu.max=") && has(&a, "memory.max="));
        assert!(a.contains(&format!("pids.max={VMM_PIDS_MAX}")));

        // cpu + memory but no pids: keep the cpu/memory caps, drop only the pid cap.
        let no_pids = Delegated {
            cpu: true,
            memory: true,
            pids: false,
        };
        let b = cgroup_args_for(&no_pids, vcpus, mem_mib);
        assert!(has(&b, "cpu.max=") && has(&b, "memory.max="));
        assert!(!has(&b, "pids.max="));

        // Missing cpu or memory: the whole set fails open (empty), never a partial `--cgroup`.
        for d in [
            Delegated {
                cpu: true,
                memory: false,
                pids: true,
            },
            Delegated {
                cpu: false,
                memory: false,
                pids: false,
            },
        ] {
            assert!(cgroup_args_for(&d, vcpus, mem_mib).is_empty());
        }
    }

    #[test]
    fn require_limits_refuses_when_cpu_memory_are_undelegated() {
        let vcpus = NonZeroU8::new(2).unwrap();
        let mem_mib = NonZeroU32::new(256).unwrap();
        let undelegated = Delegated {
            cpu: false,
            memory: false,
            pids: false,
        };

        // Fail-open default: undelegated + !require_limits yields empty args (boot uncapped), no error.
        let open = resolve_cgroup_caps(false, &undelegated, vcpus, mem_mib);
        assert!(matches!(open, Ok(ref args) if args.is_empty()));

        // Fail-closed opt-in: the same host + require_limits is a typed refusal, not a silent uncapped run.
        let closed = resolve_cgroup_caps(true, &undelegated, vcpus, mem_mib);
        assert!(matches!(closed, Err(VmmError::LimitsUnavailable(_))));
        assert_eq!(closed.unwrap_err().kind(), crate::ErrorKind::Infra);

        // With cpu+memory delegated, require_limits is satisfied and returns the caps (the pids
        // controller stays best-effort: its absence never forces a refusal).
        let no_pids = Delegated {
            cpu: true,
            memory: true,
            pids: false,
        };
        let args = resolve_cgroup_caps(true, &no_pids, vcpus, mem_mib).expect("caps applicable");
        assert!(args.iter().any(|s| s.starts_with("cpu.max=")));
        assert!(args.iter().any(|s| s.starts_with("memory.max=")));
    }

    #[test]
    fn restore_mem_cap_never_falls_below_the_snapshots_true_ram() {
        let mib = 1024 * 1024;
        // The snapshot's memory file is larger than `config` declares: the true guest RAM (the file)
        // wins, so the cap can't OOM the clone.
        assert_eq!(
            restore_mem_mib(NonZeroU32::new(256).unwrap(), 512 * mib).get(),
            512
        );
        // `config` is larger (a looser declared bound): keep it, still safe (never below the file).
        assert_eq!(
            restore_mem_mib(NonZeroU32::new(512).unwrap(), 256 * mib).get(),
            512
        );
        // A missing/zero-length memory file falls back to `config`, never zero (which `NonZeroU32`
        // couldn't hold anyway).
        assert_eq!(restore_mem_mib(NonZeroU32::new(256).unwrap(), 0).get(), 256);
    }

    #[test]
    fn overmount_is_governed_by_the_topmost_entry() {
        // Two mounts at the *same* point (an overmount): the effective propagation is the topmost,
        // the last line. A point shared-first then private-later must read *not* shared (so the copy
        // fallback fires instead of a hard-failing bind); private-first then shared-later reads shared.
        let shared_then_private = "\
21 1 0:20 / / rw shared:1 - ext4 /dev/root rw
30 21 0:24 / /scratch rw shared:128 - tmpfs a rw
31 21 0:25 / /scratch rw - tmpfs b rw
";
        assert!(
            !mount_is_shared(shared_then_private, Path::new("/scratch/x")),
            "the topmost (private) overmount governs, so this is not shared"
        );
        let private_then_shared = "\
21 1 0:20 / / rw shared:1 - ext4 /dev/root rw
30 21 0:24 / /scratch rw - tmpfs a rw
31 21 0:25 / /scratch rw shared:200 - tmpfs b rw
";
        assert!(
            mount_is_shared(private_then_shared, Path::new("/scratch/x")),
            "the topmost (shared) overmount governs"
        );
    }

    #[test]
    fn an_escaped_mount_point_is_matched_like_any_other() {
        // `scratch_dir` is operator-supplied and a path with a space is legal, so the kernel writes
        // its mount point octal-escaped. Comparing the raw field finds no covering mount, and this
        // returns `false`: the boot silently takes the per-VM copy fallback instead of the
        // page-cache-shared bind, and blames the mount's propagation for it.
        let escaped = "\
21 1 0:20 / / rw,relatime - ext4 /dev/root rw
30 21 0:24 / /my\\040scratch rw,relatime shared:128 - tmpfs tmpfs rw
";
        assert!(
            mount_is_shared(escaped, Path::new("/my scratch/bsx-1")),
            "the shared mount holding the target is found through its escaped point"
        );
        // The root is present and *not* shared here, so a false positive from the wrong line would
        // show as a failure of the assertion above rather than passing by accident.
        assert!(!mount_is_shared(escaped, Path::new("/elsewhere")));
    }

    #[test]
    fn unparseable_mountinfo_is_not_shared() {
        // A truncated or empty table can't prove a mount is shared, so default to the safe copy path.
        assert!(!mount_is_shared("", Path::new("/tmp")));
        assert!(!mount_is_shared(
            "garbage line with too few",
            Path::new("/tmp")
        ));
    }
}
