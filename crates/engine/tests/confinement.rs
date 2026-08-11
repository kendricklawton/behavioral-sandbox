//! Privileged integration tests for confinement under adversity: driver death cannot leak
//! a VM, the kill handle unblocks a wedged exec, a guest fork bomb / mem-hog is bounded
//! by the VMM's cgroup with the host unaffected, and the orphan sweep reclaims a crashed
//! driver's netns + scratch dir without touching a live sibling's.
//!
//! `#[ignore]`d because they need `/dev/kvm` and the fetched artifacts. Run via
//! `cargo xtask ci-privileged` or `cargo test -p bsx-engine -- --ignored`.
// A test binary: `panic!` (in non-`#[test]` helpers and on boot-setup failure) is the idiomatic
// assertion, which the workspace's `clippy::panic` deny doesn't auto-exempt outside `#[test]` fns.
#![allow(clippy::panic)]

mod common;

use std::ffi::OsString;
use std::io::{BufRead, BufReader};
use std::os::unix::ffi::OsStringExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bsx_engine::{BootConfig, VMM_PIDS_MAX, Vm, VmmError, sweep_orphans};

use bsx_test_support::{LimitCgroup, ScratchDir as TmpDir, process_threads};
use common::{
    cgroup_of, config, guest_rootfs_config, have_jailer_privileges, have_net_admin,
    jailed_agent_config, jailed_overlay_config,
};

/// The env var that turns `helper_boot_and_park` from a no-op into the crash-test victim. Without
/// it the helper returns immediately, so the ordinary `--ignored` sweep isn't wedged by it.
const HELPER_ENV: &str = "BSX_CONFINEMENT_HELPER";

/// The env var that turns `helper_boot_networked_and_park` into the sweep test's victim: a
/// **networked** boot, so the crash leaves the residue that matters, a per-VM netns holding a tap.
const HELPER_NET_ENV: &str = "BSX_CONFINEMENT_HELPER_NET";

/// Whether `pid` is still a live `firecracker` process (same discipline as `boot.rs`: keyed on the
/// specific pid via `comm`, so a reaped-then-recycled pid running something else reads as gone).
fn is_firecracker(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|c| c.trim() == "firecracker")
        .unwrap_or(false)
}

/// Poll `cond` up to `timeout`, returning whether it became true.
fn eventually(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if cond() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A unique scratch dir **under the host's configured scratch base**, reclaimed on drop.
///
/// Deliberately not [`TmpDir::created`], which uses `std::env::temp_dir()`: `/tmp` is `nodev` on a
/// systemd host, and the jailer cannot make its chroot's device nodes there. `ci-privileged.sh`
/// exports `BSX_SCRATCH_DIR` for exactly this reason, so a test that hard-codes `/tmp` throws that
/// away and refuses the boot before a VMM ever spawns.
///
/// This nesting also puts the dir where the engine's orphan sweep **does not look** (the tag makes
/// the name miss the `bsx-<pid>-<seq>` workdir pattern the sweep scans for), so stale residue from
/// a killed prior run is this helper's own problem: it reclaims every same-tag sibling up front,
/// detaching any mounts a dead run's chroot left first, since `remove_dir_all` alone would `EBUSY`
/// on a leaked bind mount and silently leave it to poison mountinfo for every later test.
// A free helper (not a `#[test]` fn): explicit panics are the idiomatic assertion here.
fn scratch_under(base: &Path, tag: &str) -> TmpDir {
    let prefix = format!("bsx-{tag}-");
    if let Ok(entries) = std::fs::read_dir(base) {
        for stale in entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with(&prefix))
            })
        {
            detach_mounts_under(&stale);
            let _ = std::fs::remove_dir_all(&stale);
        }
    }
    let dir = base.join(format!("bsx-{tag}-{}", std::process::id()));
    if let Err(e) = std::fs::create_dir_all(&dir) {
        panic!("create the test scratch dir {}: {e}", dir.display());
    }
    TmpDir::adopt(dir)
}

/// Lazy-detach every mount under `dir`, deepest first, mirroring the engine's own sweep helper
/// (`sweep.rs`'s `detach_mounts_under`, which is not public API): a dead run's chroot bind mount
/// otherwise blocks reclamation and, worse, keeps satisfying mountinfo scans with a stale inode.
///
/// The mount point is decoded before it is compared ([`unescape_octal`]), because `BSX_SCRATCH_DIR`
/// is operator-supplied and a space in it is legal.
fn detach_mounts_under(dir: &Path) {
    let Ok(info) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return;
    };
    let mut targets: Vec<PathBuf> = info
        .lines()
        .filter_map(|l| l.split(' ').nth(4).map(unescape_octal))
        .filter(|mp| mp.starts_with(dir))
        .collect();
    targets.sort_by_key(|mp| std::cmp::Reverse(mp.components().count()));
    for mp in targets {
        let _ = std::process::Command::new("umount")
            .arg("-l")
            .arg(&mp)
            .status();
    }
}

/// Decode a mountinfo path's octal escapes (`\040` space, `\011` tab, `\012` newline, `\134`
/// backslash) so a mount point with a space still prefix-matches correctly.
fn unescape_octal(s: &str) -> PathBuf {
    if !s.contains('\\') {
        return PathBuf::from(s);
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 4], 8)
        {
            out.push(byte);
            i += 4;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    PathBuf::from(OsString::from_vec(out))
}

/// The pid of the live VMM belonging to the boot staged under `scratch`, or `None` while none is
/// running. `Vm::boot` hands back no pid until it returns, so a test that must act *during* a boot
/// has to find the VMM from outside.
///
/// Keyed on the **per-VM cgroup**, the one handle both boot shapes share: unjailed,
/// `VmLifetime::adopt` enrolls the VMM in a cgroup named after its workdir; jailed, the jailer does
/// its own placement and the jail id *is* that same workdir name, so the name turns up in
/// `/proc/<pid>/cgroup` either way.
///
/// Every host-path match fails for a jailed VMM, which is what a whole privileged run was spent
/// learning: the jailer `exec`s Firecracker with its own argv (no `--api-sock`, no host paths), and
/// its chroot leaves `/proc/<pid>/root` naming nothing this process can match either. The cgroup is
/// the engine's own bookkeeping and survives all of it. Deliberately not gated on `comm`: a per-VM
/// cgroup holds nothing else, and the jailed process's name is one more thing not worth assuming.
fn vmm_pid_under(scratch: &Path) -> Option<u32> {
    let needle = format!("/{}", per_vm_workdir_name(scratch)?);
    std::fs::read_dir("/proc")
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
        .find(|pid| {
            std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
                .map(|c| c.contains(&needle))
                .unwrap_or(false)
        })
}

/// The name of the single per-VM workdir the driver laid down under `scratch` (`bsx-<pid>-<seq>`),
/// which is both the lifetime-cgroup name and the jail id. `None` before the boot has created it.
fn per_vm_workdir_name(scratch: &Path) -> Option<String> {
    std::fs::read_dir(scratch)
        .ok()?
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .find(|name| name.starts_with("bsx-"))
}

/// The API socket of the boot staged under `scratch`, found by walking the tree rather than by
/// parsing argv: unjailed it is `<workdir>/fc.sock`, jailed it is
/// `<workdir>/firecracker/<id>/root/run/firecracker.socket`, and only the walk covers both without
/// re-deriving the jailer's layout here.
fn api_socket_under(dir: &Path, depth: u32) -> Option<PathBuf> {
    if depth == 0 {
        return None;
    }
    for entry in std::fs::read_dir(dir).ok()?.filter_map(Result::ok) {
        let path = entry.path();
        let name = entry.file_name();
        if name == "fc.sock" || name == "firecracker.socket" {
            return Some(path);
        }
        if entry.file_type().is_ok_and(|t| t.is_dir())
            && let Some(hit) = api_socket_under(&path, depth - 1)
        {
            return Some(hit);
        }
    }
    None
}

/// Boot `cfg` on a background thread and `kill -9` its Firecracker while the driver is waiting for
/// the guest to reach userspace, returning the boot's error.
///
/// Landing in that specific wait is made deterministic rather than raced: the caller sets a
/// userspace marker the guest can never print, so the driver stays in `await_userspace` for its whole
/// boot deadline. The only timing left is letting the driver finish its API calls, which take
/// milliseconds over a unix socket.
/// The boot thread, joined on drop. What that buys: a panic anywhere in the helper (every one of its
/// diagnostic paths) unwinds through this guard **before** the scratch `TmpDir` drops, so the boot
/// runs to its own deadline and `abort()` unmounts the chroot's binds. Without it a panicking test
/// abandons the mid-boot thread, the process exits without teardown, and the leaked bind mount
/// both defeats `TmpDir`'s `remove_dir_all` (EBUSY) and poisons mountinfo for every later run,
/// pinning a rebuilt artifact's deleted inode. The cost is that a *failing* run waits out the boot deadline; a leak
/// that outlives the process is worse than a slow failure.
struct BootJoin(
    Option<std::thread::JoinHandle<Result<bsx_engine::RunningVm, bsx_engine::VmmError>>>,
);

impl BootJoin {
    fn take(
        &mut self,
    ) -> Option<std::thread::JoinHandle<Result<bsx_engine::RunningVm, bsx_engine::VmmError>>> {
        self.0.take()
    }
    fn is_finished(&self) -> bool {
        self.0
            .as_ref()
            .is_some_and(std::thread::JoinHandle::is_finished)
    }
}

impl Drop for BootJoin {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            let _ = handle.join();
        }
    }
}

// A free helper (not a `#[test]` fn): explicit panics are the idiomatic assertion here.
fn kill_the_vmm_awaiting_userspace(cfg: BootConfig) -> bsx_engine::VmmError {
    let scratch = cfg.scratch_dir.clone();
    let mut booting = BootJoin(Some(std::thread::spawn(move || Vm::boot(cfg))));

    let deadline = Instant::now() + Duration::from_secs(20);
    let sock = loop {
        if let Some(sock) = api_socket_under(&scratch, 8) {
            break sock;
        }
        // A boot that has already finished can never produce the VMM this test is waiting for, and
        // its error says why. Reporting a bare "nothing came up" here instead cost a 20-second wait
        // and pointed at the wrong thing (the real cause was a `nodev` scratch dir refused before
        // any spawn), so surface the boot's own words.
        if booting.is_finished() {
            panic_with_boot_outcome(booting.take());
        }
        if Instant::now() >= deadline {
            panic!("no firecracker came up under {}", scratch.display());
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    // The API socket answering means the VMM is past process startup; the configuration PUTs and
    // InstanceStart follow, and only then does the driver begin waiting on the console.
    while Instant::now() < deadline && std::os::unix::net::UnixStream::connect(&sock).is_err() {
        std::thread::sleep(Duration::from_millis(5));
    }
    std::thread::sleep(Duration::from_millis(500));

    let pid = match vmm_pid_under(&scratch) {
        Some(pid) => pid,
        // Two unrelated failures would otherwise wear the same face here ("the VMM died on its
        // own"), which is a guess dressed as a fact. Separate them: a boot that has already returned says what
        // went wrong in its own error, while a boot still in progress means this test cannot *see*
        // its VMM, which is a defect in the `/proc` match and not in the engine at all.
        None if booting.is_finished() => panic_with_boot_outcome(booting.take()),
        None => panic!(
            "the boot is still running, but no firecracker under {} matched: this test cannot \
             find the VMM it means to kill, so the `/proc` lookup is wrong, not the engine",
            scratch.display()
        ),
    };
    let _ = std::process::Command::new("sh")
        .args(["-c", &format!("kill -9 {pid}")])
        .status();
    let Some(handle) = booting.take() else {
        panic!("the boot thread was already joined");
    };

    match handle.join() {
        Ok(Ok(_vm)) => panic!("a VMM killed mid-boot must not yield a running VM"),
        Ok(Err(e)) => e,
        Err(_) => panic!("the boot thread panicked"),
    }
}

/// Panic with what the boot **actually did**, for the points where this test has run out of VMM to
/// act on. Always more informative than the observation that prompted it: the boot's own typed error
/// names the cause, where "no VMM here" only names the symptom.
// A free helper (not a `#[test]` fn): explicit panics are the idiomatic assertion here.
fn panic_with_boot_outcome(
    booting: Option<std::thread::JoinHandle<Result<bsx_engine::RunningVm, bsx_engine::VmmError>>>,
) -> ! {
    match booting.map(std::thread::JoinHandle::join) {
        Some(Ok(Err(e))) => panic!("the boot failed before a VMM could be killed: {e}"),
        Some(Ok(Ok(_))) => panic!(
            "the boot reached userspace on a marker no guest can print, so the driver never \
             waited where this test kills it"
        ),
        Some(Err(_)) => panic!("the boot thread panicked"),
        None => panic!("the boot thread was already joined"),
    }
}

/// A marker no guest prints, so the driver waits out its whole boot deadline in `await_userspace`.
const UNREACHABLE_MARKER: &str = "bsx-marker-that-no-guest-will-ever-print";

#[test]
#[ignore = "needs /dev/kvm + artifacts (run via `cargo xtask ci-privileged`)"]
fn a_vmm_killed_while_awaiting_userspace_leaks_nothing() {
    // The failure branch that has never run against a VMM that died on its own. Both boot-stage
    // waits check `exited()` before their deadline, and this is the later one: past the API socket,
    // past InstanceStart, waiting on the guest. It is the path that routes an error through
    // `Spawned::abort`'s whole cleanup chain, so what matters is not the message but that the
    // scratch dir goes with it. A leak here is silent and permanent: nothing reclaims it until the
    // next `sweep_orphans`, and one accumulates per killed boot.
    let mut cfg = config();
    // A private dir *under* the configured base, not a replacement for it: the base is what
    // `BSX_SCRATCH_DIR` points off a `nodev` `/tmp`, and the per-test dir is only there to make the
    // `/proc` match below unambiguous.
    let scratch = scratch_under(&cfg.scratch_dir, "killboot");
    cfg.scratch_dir = scratch.path().to_path_buf();
    cfg.userspace_marker = UNREACHABLE_MARKER.to_string();
    cfg.boot_timeout = Duration::from_secs(60);

    let err = kill_the_vmm_awaiting_userspace(cfg);
    let msg = err.to_string();
    assert!(
        msg.contains("exited before userspace"),
        "a VMM killed after InstanceStart is reported as a death, not as a boot timeout: {msg}"
    );

    let leftovers: Vec<_> = std::fs::read_dir(scratch.path())
        .expect("the scratch base survives; only the per-VM dir under it should go")
        .filter_map(Result::ok)
        .map(|e| e.file_name())
        .collect();
    assert!(
        leftovers.is_empty(),
        "abort must reclaim the killed VM's scratch dir; found {leftovers:?}"
    );
    assert!(
        vmm_pid_under(scratch.path()).is_none(),
        "no firecracker may survive the boot that failed"
    );
}

#[test]
#[ignore = "needs /dev/kvm + real root + the jailer (run via `cargo xtask ci-privileged` as root)"]
fn a_jailed_vmm_killed_mid_boot_leaves_no_mounts_behind() {
    // The jailed half, which is where a mid-boot death can leak something worse than a directory:
    // the chroot's bind mounts. `remove_dir_all` cannot remove a busy mount point, so an unmounted
    // leftover would both strand the dir and keep the shared base pinned.
    //
    // The mountinfo assertion below is the direct diagnosis but not the load-bearing one: a scratch
    // base on a non-shared mount takes the copy fallback instead of the bind, and then there is no
    // mount to leak and that check passes vacuously. The empty-scratch assertion holds either way,
    // and is what a leaked mount would actually break.
    if !have_jailer_privileges() {
        eprintln!(
            "skipping a_jailed_vmm_killed_mid_boot_leaves_no_mounts_behind: needs real root \
             (euid 0, initial userns)"
        );
        return;
    }
    let mut cfg = jailed_overlay_config();
    // The jailer makes device nodes in its chroot, so this dir must inherit the configured base
    // (`BSX_SCRATCH_DIR`, off `nodev`). Hard-coding `/tmp` here is what failed the first run.
    let scratch = scratch_under(&cfg.scratch_dir, "killjail");
    cfg.scratch_dir = scratch.path().to_path_buf();
    cfg.userspace_marker = UNREACHABLE_MARKER.to_string();
    cfg.boot_timeout = Duration::from_secs(60);

    let err = kill_the_vmm_awaiting_userspace(cfg);
    assert!(
        err.to_string().contains("exited before userspace"),
        "got {err}"
    );

    let base = scratch.path().to_string_lossy().to_string();
    let mounts = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    let leaked: Vec<_> = mounts
        .lines()
        .filter(|l| {
            l.split(' ')
                .nth(4)
                .is_some_and(|target| target.starts_with(&base))
        })
        .collect();
    assert!(
        leaked.is_empty(),
        "the chroot's binds must be unmounted when a jailed boot dies: {leaked:?}"
    );
    let leftovers: Vec<_> = std::fs::read_dir(scratch.path())
        .expect("the scratch base survives")
        .filter_map(Result::ok)
        .map(|e| e.file_name())
        .collect();
    assert!(
        leftovers.is_empty(),
        "abort must reclaim the killed jailed VM's chroot; found {leftovers:?}"
    );
}

/// The crash-test victim, run **as a subprocess** by `driver_death_cannot_leak_a_vm`: boot a VM,
/// report the VMM's pid and cgroup on stdout, then park forever, so the parent can `SIGKILL` this
/// whole process mid-run and watch what the sentinel does. `Drop` never runs here; that's the point.
#[test]
#[ignore = "crash-test helper; only meaningful under driver_death_cannot_leak_a_vm"]
fn helper_boot_and_park() {
    if std::env::var_os(HELPER_ENV).is_none() {
        return; // Not invoked as the victim: a no-op in the ordinary --ignored sweep.
    }
    let vm = Vm::boot(config()).expect("helper microVM should boot");
    let pid = vm.vmm_pid();
    // The lifetime cgroup is observable from outside: it's where the VMM now lives, and it differs
    // from this process's own cgroup exactly when enrollment worked. Report `degraded` otherwise so
    // the parent can skip rather than fail on a host without writable cgroups.
    let own = cgroup_of(std::process::id());
    match cgroup_of(pid) {
        Some(dir) if cgroup_of(pid) != own => println!("HELPER_CGROUP={}", dir.display()),
        _ => println!("HELPER_CGROUP=degraded"),
    }
    println!("HELPER_VMM_PID={pid}");
    // Park. The VM stays alive; only the parent's SIGKILL ends this process.
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

#[test]
#[ignore = "needs /dev/kvm + artifacts (run via `cargo xtask ci-privileged`)"]
fn driver_death_cannot_leak_a_vm() {
    // The cgroup-owned-lifetime headline claim, tested with a real crash: a driver process SIGKILLed mid-run (the one
    // signal no handler can catch, the stand-in for Ctrl-C, OOM, a panic-abort) does not leak its
    // VMM. The sentinel outlives the driver, wakes on the pipe EOF the kernel delivers for us, and
    // kills + removes the VM's cgroup. Run the driver as a subprocess (this same test binary,
    // invoking the parked helper above) so the kill is real, not simulated.
    let exe = std::env::current_exe().expect("current test binary");
    let mut child = std::process::Command::new(exe)
        .args([
            "--ignored",
            "--exact",
            "helper_boot_and_park",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(HELPER_ENV, "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .expect("spawn the crash-test victim");
    let child_pid = child.id();

    // Parse the victim's report. The tags are matched *anywhere* in a line, not as a prefix: the
    // victim's test harness prints its own `test … ` progress without a trailing newline, so the
    // first tag arrives glued to it. The victim's boot timeout bounds these blocking reads: a boot
    // failure ends the victim (EOF here) rather than hanging the parent.
    let tagged = |line: &str, tag: &str| -> Option<String> {
        line.split_once(tag).map(|(_, v)| v.trim().to_string())
    };
    let stdout = child.stdout.take().expect("victim stdout piped");
    let (mut vmm_pid, mut cgroup) = (None::<u32>, None::<String>);
    for line in BufReader::new(stdout).lines() {
        let line = line.expect("read victim stdout");
        if let Some(v) = tagged(&line, "HELPER_VMM_PID=") {
            vmm_pid = v.parse().ok();
        } else if let Some(v) = tagged(&line, "HELPER_CGROUP=") {
            cgroup = Some(v);
        }
        if vmm_pid.is_some() && cgroup.is_some() {
            break;
        }
    }
    let cleanup_victim_scratch = || {
        // The victim never tears down its scratch dir (that's the crash); it is residue the
        // sentinel deliberately doesn't own (see the lifetime module doc). The orphan sweep
        // owns exactly this, so dogfood it rather than hand-rolling a scan. `child_pid`
        // is dead by every path that reaches here, so its dirs are sweep candidates.
        let _ = child_pid; // ownership is by liveness now, not by prefix
        match sweep_orphans(&BootConfig::from_env().scratch_dir) {
            Ok(r) => eprintln!("post-crash sweep: {r:?}"),
            Err(e) => eprintln!("post-crash sweep failed: {e}"),
        }
    };
    let Some(vmm_pid) = vmm_pid else {
        let _ = child.kill();
        let _ = child.wait();
        cleanup_victim_scratch();
        panic!("victim never reported a VMM pid (boot failed?)");
    };
    let cgroup = cgroup.unwrap_or_default();
    if cgroup == "degraded" {
        let _ = child.kill();
        let _ = child.wait();
        // Give the victim's own Drop no chance (SIGKILL), so reap the leaked VMM ourselves.
        let _ = std::process::Command::new("sh")
            .args(["-c", &format!("kill -9 {vmm_pid}")])
            .status();
        cleanup_victim_scratch();
        // "Degraded" from the helper is ambiguous: no writable cgroup v2 on this host, or the
        // lifetime-cgroup enrollment itself regressed (the VMM left in the driver's own cgroup),
        // which is exactly this test's failure mode. Disambiguate by probing writability directly:
        // if this host can create a cgroup, enrollment had no excuse, so fail, never skip.
        let probe =
            Path::new("/sys/fs/cgroup").join(format!("bsx-degraded-probe-{}", std::process::id()));
        if std::fs::create_dir(&probe).is_ok() {
            let _ = std::fs::remove_dir(&probe);
            panic!(
                "lifetime-cgroup enrollment produced no distinct cgroup on a host with writable \
                 cgroup v2: the crash-only sentinel is inert, the exact regression this test \
                 exists to catch"
            );
        }
        eprintln!("skipping driver_death_cannot_leak_a_vm: no writable cgroup v2 here");
        return;
    }
    assert!(
        is_firecracker(vmm_pid),
        "victim's VMM should be alive before the crash"
    );

    // The crash: SIGKILL the whole driver process. No Drop, no handler, no goodbye.
    child.kill().expect("SIGKILL the victim");
    let _ = child.wait();

    // The sentinel (a child of the victim, in its own process group, now orphaned) must kill the
    // VMM via its cgroup and remove the cgroup dir, promptly, not eventually.
    assert!(
        eventually(Duration::from_secs(10), || !is_firecracker(vmm_pid)),
        "VMM {vmm_pid} must die when its driver dies (sentinel failed?)"
    );
    let cg = PathBuf::from(&cgroup);
    assert!(
        eventually(Duration::from_secs(10), || !cg.exists()),
        "the VM's lifetime cgroup {cgroup} must be removed after the crash"
    );
    cleanup_victim_scratch();
}

/// The sweep crash-test victim: like [`helper_boot_and_park`], but a **networked** boot, so the
/// crash leaves the residue the sweep exists for, a per-VM network namespace holding an orphan tap.
#[test]
#[ignore = "crash-test helper; only meaningful under sweep_reclaims_a_crashed_drivers_netns_and_scratch_dir"]
fn helper_boot_networked_and_park() {
    if std::env::var_os(HELPER_NET_ENV).is_none() {
        return; // Not invoked as the victim: a no-op in the ordinary --ignored sweep.
    }
    let mut cfg = config();
    cfg.enable_network = true;
    let vm = Vm::boot(cfg).expect("networked helper microVM should boot");
    println!("HELPER_VMM_PID={}", vm.vmm_pid());
    println!("HELPER_NETNS={}", vm.netns().unwrap_or("none"));
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

/// Whether a network namespace named `name` exists (its `/run/netns/<name>` handle is present).
fn netns_exists(name: &str) -> bool {
    Path::new("/run/netns").join(name).exists()
}

/// How many per-VM scratch dirs under `base` belong to driver `pid`.
fn scratch_dirs_of(base: &Path, pid: u32) -> usize {
    let prefix = format!("bsx-{pid}-");
    std::fs::read_dir(base)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
                .count()
        })
        .unwrap_or(0)
}

#[test]
#[ignore = "needs /dev/kvm + artifacts + CAP_NET_ADMIN (run via `cargo xtask ci-privileged`)"]
fn sweep_reclaims_a_crashed_drivers_netns_and_scratch_dir() {
    // The sweep's claim under the netns model: a networked VM's residue is a per-VM network namespace
    // (holding an orphan tap), left behind when its driver dies without teardown. It is not a
    // finite-pool reservation (each netns reuses a fixed /30), but still residue worth reclaiming. The
    // sweep must reclaim a dead driver's netns + scratch dir while sparing a concurrently-live
    // driver's, ownership by liveness, not by pattern.
    if !have_net_admin() {
        eprintln!(
            "skipping sweep_reclaims_a_crashed_drivers_netns_and_scratch_dir: no CAP_NET_ADMIN"
        );
        return;
    }
    let scratch_base = BootConfig::from_env().scratch_dir;

    // The control: a live networked VM in *this* process. The sweep must not touch it.
    let mut live_cfg = config();
    live_cfg.enable_network = true;
    let live = Vm::boot(live_cfg).expect("live networked microVM should boot");
    let live_netns = live.netns().expect("live VM has a netns").to_string();

    // The victim: a networked boot in a subprocess driver we SIGKILL mid-run (no Drop, no goodbye).
    let exe = std::env::current_exe().expect("current test binary");
    let mut child = std::process::Command::new(exe)
        .args([
            "--ignored",
            "--exact",
            "helper_boot_networked_and_park",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(HELPER_NET_ENV, "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .expect("spawn the crash-test victim");
    let victim_pid = child.id();

    let tagged = |line: &str, tag: &str| -> Option<String> {
        line.split_once(tag).map(|(_, v)| v.trim().to_string())
    };
    let stdout = child.stdout.take().expect("victim stdout piped");
    let (mut vmm_pid, mut victim_netns) = (None::<u32>, None::<String>);
    for line in BufReader::new(stdout).lines() {
        let line = line.expect("read victim stdout");
        if let Some(v) = tagged(&line, "HELPER_VMM_PID=") {
            vmm_pid = v.parse().ok();
        } else if let Some(v) = tagged(&line, "HELPER_NETNS=") {
            victim_netns = Some(v);
        }
        if vmm_pid.is_some() && victim_netns.is_some() {
            break;
        }
    }
    let (Some(vmm_pid), Some(victim_netns)) = (vmm_pid, victim_netns) else {
        let _ = child.kill();
        let _ = child.wait();
        panic!("victim never reported its VMM pid + netns (boot failed?)");
    };
    assert_ne!(victim_netns, "none", "networked victim must have a netns");
    assert_ne!(
        victim_netns, live_netns,
        "victim and live VM must own distinct netns"
    );

    // The crash.
    child.kill().expect("SIGKILL the victim");
    let _ = child.wait();

    // The sweep owns fs/net residue, never processes: those are the sentinel's, and where the
    // sentinel is degraded (no writable cgroup v2, e.g. under a plain userns), the leaked VMM is
    // reaped here by hand so the sweep's still-running-VMM guard doesn't (correctly) skip the dir.
    if !eventually(Duration::from_secs(10), || !is_firecracker(vmm_pid)) {
        let _ = std::process::Command::new("sh")
            .args(["-c", &format!("kill -9 {vmm_pid}")])
            .status();
        assert!(
            eventually(Duration::from_secs(10), || !is_firecracker(vmm_pid)),
            "leaked VMM {vmm_pid} should die when killed"
        );
    }

    // The residue is really there before the sweep, otherwise the test would pass vacuously.
    assert!(
        netns_exists(&victim_netns),
        "the crashed driver's netns {victim_netns} should linger until swept"
    );
    assert!(
        scratch_dirs_of(&scratch_base, victim_pid) > 0,
        "the crashed driver's scratch dir should linger until swept"
    );

    let report = sweep_orphans(&scratch_base).expect("sweep should run");
    eprintln!("sweep report: {report:?}");

    // The dead driver's residue is gone: the netns (and its tap) and the dir.
    assert!(
        !netns_exists(&victim_netns),
        "sweep must reclaim the orphaned netns {victim_netns}"
    );
    assert_eq!(
        scratch_dirs_of(&scratch_base, victim_pid),
        0,
        "sweep must reclaim the victim's scratch dirs"
    );
    assert!(
        report.netns_reclaimed >= 1,
        "report counts the netns: {report:?}"
    );
    assert!(
        report.dirs_reclaimed >= 1,
        "report counts the dir: {report:?}"
    );

    // The live sibling is untouched, and still fully functional, not just present.
    assert!(
        netns_exists(&live_netns),
        "sweep must spare the live driver's netns {live_netns}"
    );
    assert!(
        scratch_dirs_of(&scratch_base, std::process::id()) > 0,
        "sweep must spare the live driver's scratch dir"
    );
    live.shutdown()
        .expect("live VM shuts down clean after the sweep");
}

#[test]
#[ignore = "needs /dev/kvm + artifacts (run via `cargo xtask ci-privileged`)"]
fn kill_handle_unblocks_a_wedged_exec() {
    // The embedder kill handle: `exec` borrows `&self` and `shutdown` consumes `self`, so a
    // thread blocked in a long exec can't be stopped through the VM's own API. The handle is the
    // out-of-band path: cloneable, Send, and it kills through the cgroup file, so firing it from
    // another thread makes the VMM die, the vsock peer close, and the blocked exec return a typed
    // error long before its 30 s command (or budget) would have.
    let mut vm = Vm::boot(guest_rootfs_config()).expect("agent microVM should boot");
    let handle = vm.kill_handle();

    let killer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(2));
        handle.kill().expect("kill handle should reach the VMM");
    });

    let started = Instant::now();
    let cmd = ["sleep", "30"].map(String::from);
    let result = vm.exec(&cmd, b"");
    let elapsed = started.elapsed();
    killer.join().expect("killer thread");

    assert!(
        result.is_err(),
        "exec against a force-killed VM must return a typed error, got {result:?}"
    );
    assert!(
        elapsed >= Duration::from_secs(1),
        "exec should have been blocked when the kill fired ({elapsed:?})"
    );
    assert!(
        elapsed < Duration::from_secs(15),
        "the kill must unblock exec well before the 30 s command ends ({elapsed:?})"
    );
    // Teardown of the already-dead VM must still reclaim host residue, without hanging.
    drop(vm);
}

#[test]
#[ignore = "needs /dev/kvm + real root + delegated cgroups (run via `cargo xtask ci-privileged` as root)"]
fn guest_mem_hog_is_bounded_by_the_cgroup() {
    // Memory half: a guest allocating everything it can reach pushes the VMM's host memory
    // toward its cap, and the cap holds, accounted memory never passes `memory.max`, the kernel
    // never OOM-kills the VMM (the guest's *own* OOM killer eats the hog first, inside the
    // hardware boundary), and the VM stays responsive afterwards. Host unaffected, by observation.
    if !have_jailer_privileges() {
        eprintln!("skipping guest_mem_hog_is_bounded_by_the_cgroup: needs real root");
        return;
    }
    let cfg = guest_rootfs_config();
    let (vcpus, mem_mib) = (u32::from(cfg.vcpus.get()), cfg.mem_mib.get());
    let Some(cg) = LimitCgroup::create(vcpus, mem_mib, "mem-hog") else {
        eprintln!(
            "skipping guest_mem_hog_is_bounded_by_the_cgroup: cgroup v2 not writable/delegated"
        );
        return;
    };
    let mut vm = Vm::boot(cfg).expect("agent microVM should boot");
    cg.enter(vm.vmm_pid());

    // Touch pages, don't just reserve them: `bytearray` zero-fills, so every chunk is real guest
    // RAM the VMM must back with host memory, charged to the limited cgroup. The hog ends either
    // in Python's MemoryError or under the guest kernel's OOM killer; both are fine, both are
    // *inside the VM*. What must not happen is the exec channel dying or the host cap breaking.
    // One literal with explicit `\n`s and single-space block indents: a Rust `\`-continuation would
    // strip the next line's leading whitespace and silently destroy Python's indentation.
    let hog = [
        "python3",
        "-c",
        "bufs = []\ntry:\n while True: bufs.append(bytearray(16 * 1024 * 1024))\nexcept MemoryError: pass\nprint('hog-done')",
    ]
    .map(String::from);
    let result = vm
        .exec(&hog, b"")
        .expect("the mem-hog exec must complete (guest OOM, not VMM death)");
    // The cap held. `memory.peak` is the high-water mark of what the kernel charged this cgroup;
    // it must be a real load (the hog charged here) and must not pass the cap. `maybe_read`
    // because the file itself is version-gated: the `expect` names the real requirement where
    // `read`'s ENOENT panic would not.
    let peak: u64 = cg
        .maybe_read("memory.peak")
        .expect("memory.peak missing (kernel >= 5.19)")
        .trim()
        .parse()
        .expect("parse memory.peak");
    let max: u64 = cg
        .read("memory.max")
        .trim()
        .parse()
        .expect("parse memory.max");
    eprintln!(
        "mem-hog: guest exit {}, host memory.peak {peak} / memory.max {max}",
        result.exit_code,
    );
    assert!(
        peak > 64 * 1024 * 1024,
        "the hog should have pushed real memory through the cgroup (peak {peak})"
    );
    assert!(
        peak <= max,
        "memory.peak {peak} must never pass memory.max {max}"
    );
    // The host never had to OOM-kill the VMM: the 128 MiB overhead budget
    // absorbed the VMM's worst case while the guest's own OOM killer handled the hog.
    assert_eq!(
        cg.stat("memory.events", "oom_kill"),
        0,
        "the host cap must bound the VMM without OOM-killing it"
    );

    // The VM survived its guest's worst day: still exec-responsive.
    let echo = ["echo", "alive"].map(String::from);
    let out = vm.exec(&echo, b"").expect("post-hog exec should run");
    assert_eq!(out.stdout, b"alive\n");
    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + real root + delegated cgroups (run via `cargo xtask ci-privileged` as root)"]
fn pids_max_is_applied_live_to_the_running_vms_cgroup() {
    // The `pids.max` defense-in-depth cap: the driver asks the jailer to set it, and the
    // wire-shape unit tests in `jail.rs` assert the `--cgroup pids.max=<N>` *argument* is built. What
    // nothing checked until now is that the cap actually *took*, that the value is live on the
    // running VM's cgroup, not merely requested. A jailer that dropped the arg, a mis-derived cgroup
    // path, or a kernel that rejected the write would all pass the arg-string tests and still leave
    // the guest uncapped. So boot a real jailed VM and read the value back off its cgroup.
    if !have_jailer_privileges() {
        eprintln!("skipping pids_max_is_applied_live_to_the_running_vms_cgroup: needs real root");
        return;
    }
    // The driver sets `pids.max` only when the `pids` controller is delegated to the cgroup root (it
    // can't enable a controller the root won't delegate). Without it the driver *correctly* fails
    // open and applies no cap, so there is nothing to read back: skip, don't fail. Mirrors the
    // driver's own `read_delegated` prerequisite.
    let subtree =
        std::fs::read_to_string("/sys/fs/cgroup/cgroup.subtree_control").unwrap_or_default();
    if !subtree.split_whitespace().any(|c| c == "pids") {
        eprintln!(
            "skipping pids_max_is_applied_live_to_the_running_vms_cgroup: pids controller not \
             delegated to the cgroup root (driver fails open, no cap to observe)"
        );
        return;
    }

    let vm = Vm::boot(jailed_agent_config()).expect("jailed microVM should boot");
    // The VMM lives in the jailer-created, limits-bearing cgroup (the same lifetime cgroup the
    // crash-leak test tracks). With pids delegated and jailer privileges, enrollment cannot be
    // degraded, so a missing cgroup is itself the regression, not a skip.
    let cgroup = cgroup_of(vm.vmm_pid())
        .expect("a jailed VMM must live in its own limits-bearing cgroup, not the root");
    let pids_max = std::fs::read_to_string(cgroup.join("pids.max"))
        .unwrap_or_else(|e| panic!("read pids.max off {}: {e}", cgroup.display()));

    assert_eq!(
        pids_max.trim(),
        VMM_PIDS_MAX.to_string(),
        "the jailer must apply the driver's pids.max cap live to the VM cgroup; read back `{}` from {}",
        pids_max.trim(),
        cgroup.display()
    );
    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + real root + delegated cgroups (run via `cargo xtask ci-privileged` as root)"]
fn guest_fork_bomb_is_bounded_by_the_cgroup() {
    // CPU half: a storm of spinning guest processes. Two bounds hold at once. Hardware
    // isolation means guest processes simply don't exist on the host, the VMM's thread count
    // stays flat no matter how hard the guest forks. And the cgroup's cpu.max means the whole VM
    // (vCPUs + VMM overhead threads) cannot burn more than its quota of host CPU. The storm's own
    // exit also exercises tree reaping: its spinners are reaped by the guest agent's per-exec cgroup, so
    // the guest is idle again for the follow-up exec.
    if !have_jailer_privileges() {
        eprintln!("skipping guest_fork_bomb_is_bounded_by_the_cgroup: needs real root");
        return;
    }
    let cfg = guest_rootfs_config();
    let mem_mib = cfg.mem_mib.get();
    // Half a core, deliberately *below* the one-vCPU hardware bound: a quota equal to the vCPU
    // count is satisfied by the silicon alone, which would make the CPU assert below unfalsifiable.
    let Some(cg) = LimitCgroup::create_cpu_millicores(500, mem_mib, "fork-bomb") else {
        eprintln!(
            "skipping guest_fork_bomb_is_bounded_by_the_cgroup: cgroup v2 not writable/delegated"
        );
        return;
    };
    let mut vm = Vm::boot(cfg).expect("agent microVM should boot");
    cg.enter(vm.vmm_pid());

    let threads_before = process_threads(vm.vmm_pid());
    // `process_threads` degrades to 0 on a failed read, and 0 == 0 would pass the flat-count
    // assert below while measuring nothing; a live VMM always has several threads.
    assert!(
        threads_before >= 2,
        "thread probe read failed ({threads_before}); the isolation assert would be vacuous"
    );
    let usage_before = cg.stat("cpu.stat", "usage_usec");
    let started = Instant::now();

    // 100 spinning shells for 6 s: a bounded storm rather than the classic unbounded `:(){ :|:& };:`
    // so the guest agent stays schedulable and the run is measurable (the *unbounded* variant would
    // starve the agent inside the guest, a guest-availability problem, while this test is about
    // what the host feels). 6 s, not shorter, so the half-core quota's expected burn (~3 s) sits
    // clearly under the cap while an unenforced full-core burn (~6 s) sits clearly over it. The
    // spinners outlive their parent command on purpose: the agent's tree reaping cleans them up.
    let storm = [
        "sh",
        "-c",
        "i=0; while [ \"$i\" -lt 100 ]; do i=$((i+1)); while :; do :; done & done; sleep 6; echo storm-live",
    ]
    .map(String::from);
    let out = vm
        .exec(&storm, b"")
        .expect("the fork storm exec must complete");
    let elapsed = started.elapsed();
    assert_eq!(out.exit_code, 0, "storm command should exit 0");
    assert!(
        out.stdout.ends_with(b"storm-live\n"),
        "storm should have run its course"
    );

    // Hardware isolation, observed: 100 guest processes created zero host threads.
    let threads_after = process_threads(vm.vmm_pid());
    assert_eq!(
        threads_after, threads_before,
        "guest forks must not create host threads (hardware isolation)"
    );

    // The cgroup CPU bound, observed and falsifiable: the quota is half a core, so the cap is
    // half the wall clock plus slack for the VMM's non-vCPU threads. An unenforced `cpu.max`
    // (the vCPU spinning a full core for the window) overshoots this.
    let usage = cg.stat("cpu.stat", "usage_usec") - usage_before;
    let cap = elapsed.as_micros() as u64 / 2 + 2_000_000;
    eprintln!(
        "fork storm: {elapsed:?} wall, {usage} usec of host CPU (cap {cap}), \
         threads {threads_before} -> {threads_after}"
    );
    assert!(
        usage <= cap,
        "host CPU burned ({usage} usec) must stay within the cgroup quota ({cap} usec)"
    );

    // The per-exec cgroup reaped the orphaned spinners with the storm's exec cgroup: the guest is idle again.
    let echo = ["echo", "alive"].map(String::from);
    let after = vm.exec(&echo, b"").expect("post-storm exec should run");
    assert_eq!(after.stdout, b"alive\n");
    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + real root (run via `cargo xtask ci-privileged` as root)"]
fn two_concurrent_sandboxes_run_under_distinct_jail_uids() {
    // The axis `a_hostile_run_cannot_starve_or_observe_a_co_resident_run` does not cover: it scopes
    // itself to starvation (cgroup quota) and observation (per-VM netns), leaving the identity the
    // VMMs run *as*. Processes sharing a uid can signal each other whatever their cgroup or netns,
    // so two guests that each breached KVM into their own VMM could kill each other's sandbox.
    // Reading `/proc` proves the separation is in force, not merely configured.
    if !have_jailer_privileges() {
        eprintln!(
            "skipping two_concurrent_sandboxes_run_under_distinct_jail_uids: needs real root"
        );
        return;
    }
    // `Uid:` is real/effective/saved/fs; the jailer's `setuid` sets all four, so the first answers it.
    let vmm_uid = |pid: u32| -> u32 {
        std::fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("Uid:"))
                    .and_then(|v| v.split_whitespace().next())
                    .and_then(|u| u.parse::<u32>().ok())
            })
            .expect("read and parse the VMM's uid")
    };
    let span = bsx_engine::JailIds::span(20_000, 4).expect("a valid span");
    let booted: Vec<bsx_engine::RunningVm> = (0..2)
        .map(|_| {
            let mut cfg = guest_rootfs_config();
            let mut jail = bsx_engine::Jail::default();
            jail.ids = Some(span.clone());
            cfg.jail = Some(jail);
            Vm::boot(cfg).expect("a jailed microVM should boot")
        })
        .collect();

    let uids: Vec<u32> = booted.iter().map(|vm| vmm_uid(vm.vmm_pid())).collect();
    assert_ne!(
        uids[0], uids[1],
        "two concurrent sandboxes must not share a jail uid (both were {})",
        uids[0]
    );
    for uid in &uids {
        assert!(
            (20_000..20_004).contains(uid),
            "a leased uid must come from the declared span, got {uid}"
        );
        assert_ne!(*uid, 0, "a jailed VMM must never run as root");
    }

    for vm in booted {
        vm.shutdown().expect("shutdown should succeed");
    }

    // Teardown returns the ids, so a long-lived host churns inside its span rather than exhausting
    // it. `RunningVm`'s drop runs teardown before its fields drop, which is what makes a released id
    // safe to reuse: the chroot chowned to it is already gone.
    let mut cfg = guest_rootfs_config();
    let mut jail = bsx_engine::Jail::default();
    jail.ids = Some(span);
    cfg.jail = Some(jail);
    let reused = Vm::boot(cfg).expect("a released id should be reusable");
    assert_eq!(
        vmm_uid(reused.vmm_pid()),
        20_000,
        "the lowest released id comes back first"
    );
    reused.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + real root + delegated cgroups (run via `cargo xtask ci-privileged` as root)"]
fn a_hostile_run_cannot_starve_or_observe_a_co_resident_run() {
    // The explicitly multi-tenant assertion: a hostile run storming the host's CPU alongside
    // a well-behaved run on the *same host* can neither **starve** it (the victim's work still
    // completes, correctly and within a bound) nor **observe** it (distinct VMMs; network isolation is
    // the per-VM netns's job, net.rs). Each run is capped at its own cgroup, so the attacker cannot
    // take more than its quota, so the victim's share is bounded by that cap; the wall-clock
    // ceiling is a sanity check layered on top of it, not the mechanism itself.
    if !have_jailer_privileges() {
        eprintln!(
            "skipping a_hostile_run_cannot_starve_or_observe_a_co_resident_run: needs real root"
        );
        return;
    }
    let cfg = guest_rootfs_config();
    let (vcpus, mem_mib) = (u32::from(cfg.vcpus.get()), cfg.mem_mib.get());
    let (Some(victim_cg), Some(attacker_cg)) = (
        LimitCgroup::create(vcpus, mem_mib, "victim"),
        LimitCgroup::create(vcpus, mem_mib, "attacker"),
    ) else {
        eprintln!(
            "skipping a_hostile_run_cannot_starve_or_observe_a_co_resident_run: cgroup v2 not writable/delegated"
        );
        return;
    };

    // Two co-resident runs, each in its own capped cgroup, the per-run isolation a hoster relies on.
    let mut victim = Vm::boot(cfg.clone()).expect("victim microVM should boot");
    victim_cg.enter(victim.vmm_pid());
    let mut attacker = Vm::boot(cfg).expect("attacker microVM should boot");
    attacker_cg.enter(attacker.vmm_pid());
    assert_ne!(
        victim.vmm_pid(),
        attacker.vmm_pid(),
        "co-resident runs are distinct VMM processes (the attacker can't see the victim's)"
    );

    // A CPU-bound victim workload with a checkable result and a measurable solo time (the attacker VM
    // is idle here, so this is a clean baseline). One literal, explicit `\n`s + single-space indent.
    let work = [
        "python3",
        "-c",
        "s=0\nfor i in range(20000000): s+=i\nprint(s)",
    ]
    .map(String::from);
    const EXPECTED: &str = "199999990000000";
    let solo_started = Instant::now();
    let solo = victim
        .exec(&work, b"")
        .expect("victim solo workload should run");
    let solo_wall = solo_started.elapsed();
    assert_eq!(
        String::from_utf8_lossy(&solo.stdout).trim(),
        EXPECTED,
        "victim workload should compute its known result"
    );

    // The attacker storms the CPU (100 spinners for 6 s) in its own thread while the victim reruns its
    // workload concurrently. The `Vm` moves into the thread (it is `Send`); we get it back to read its
    // cgroup and shut it down.
    let storm = [
        "sh",
        "-c",
        "i=0; while [ \"$i\" -lt 100 ]; do i=$((i+1)); while :; do :; done & done; sleep 6; echo storm-live",
    ]
    .map(String::from);
    let attack_started = Instant::now();
    let usage_before = attacker_cg.stat("cpu.stat", "usage_usec");
    let storm_thread = std::thread::spawn(move || {
        let out = attacker.exec(&storm, b"");
        (attacker, out)
    });
    std::thread::sleep(Duration::from_millis(500)); // let the storm ramp before timing the victim

    let under_started = Instant::now();
    // Capture, don't assert yet: nothing between spawning the storm thread and joining it may panic,
    // or a failed victim assertion would detach the thread and leave its VM un-torn-down.
    let under = victim.exec(&work, b"");
    let under_wall = under_started.elapsed();

    let (attacker, storm_out) = storm_thread
        .join()
        .expect("attacker thread should not panic");
    let attack_wall = attack_started.elapsed();

    // With the storm thread joined (its VM now ours again), it's safe to assert.
    let under = under.expect("victim workload should run under attack");
    assert_eq!(
        String::from_utf8_lossy(&under.stdout).trim(),
        EXPECTED,
        "the victim's result must be correct under attack (not starved to death or corrupted)"
    );
    assert_eq!(
        storm_out.expect("attacker storm should run").exit_code,
        0,
        "the attacker's storm command should exit 0"
    );

    // The attacker stayed within its cgroup CPU quota, it could not monopolize the host, so the
    // victim's share was protected by the cap regardless of the scheduler.
    let attacker_cpu = attacker_cg.stat("cpu.stat", "usage_usec") - usage_before;
    let cpu_cap = attack_wall.as_micros() as u64 * u64::from(vcpus) + 2_000_000;
    assert!(
        attacker_cpu <= cpu_cap,
        "attacker host CPU ({attacker_cpu} usec) must stay within its cgroup quota ({cpu_cap} usec)"
    );

    // Not slowed past a bound: a generous ceiling that only trips on gross starvation (timing is
    // host-dependent, so the actual bound is the cap above; this is the sanity check).
    const SLOWDOWN_MAX: u32 = 10;
    let ceiling = solo_wall * SLOWDOWN_MAX + Duration::from_secs(5);
    eprintln!(
        "co-resident: victim solo {solo_wall:?} vs under attack {under_wall:?} (ceiling {ceiling:?})"
    );
    assert!(
        under_wall <= ceiling,
        "victim was slowed past the bound: {under_wall:?} > {ceiling:?} (starvation)"
    );

    victim.shutdown().expect("victim shutdown should succeed");
    attacker
        .shutdown()
        .expect("attacker shutdown should succeed");
}

/// A private tmpfs mounted with the given options, unmounted and removed on drop, so a failing
/// assertion leaves no mount behind on the host (the no-leak rule applies to the tests too).
struct FlaggedMount {
    dir: PathBuf,
}

impl FlaggedMount {
    /// Mounting over the point replaces the flags in effect there, so the host's own `/tmp`
    /// posture (`nodev` on systemd, `noexec` on hardened baselines) is irrelevant underneath.
    // A free helper (not a `#[test]` fn): explicit panics are the idiomatic assertion here.
    fn tmpfs(name: &str, options: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("bsx-{name}-{}", std::process::id()));
        if let Err(e) = std::fs::create_dir_all(&dir) {
            panic!("create the mount point {}: {e}", dir.display());
        }
        let status = match std::process::Command::new("mount")
            .args(["-t", "tmpfs", "-o", options, "tmpfs"])
            .arg(&dir)
            .status()
        {
            Ok(s) => s,
            Err(e) => panic!("run mount: {e}"),
        };
        assert!(
            status.success(),
            "mount -t tmpfs -o {options} at {} must succeed under root",
            dir.display()
        );
        Self { dir }
    }

    fn path(&self) -> &Path {
        &self.dir
    }
}

impl Drop for FlaggedMount {
    fn drop(&mut self) {
        let _ = std::process::Command::new("umount").arg(&self.dir).status();
        let _ = std::fs::remove_dir(&self.dir);
    }
}

#[test]
#[ignore = "needs real root (mounts private tmpfs instances; run via `cargo xtask ci-privileged`)"]
fn nodev_and_noexec_scratch_mounts_refuse_a_jailed_boot() {
    // The unit fixtures prove the mountinfo *parse* against strings the test wrote; this proves
    // the chain against the real kernel: a genuine `nodev` / `noexec` mount, read back from the
    // live `/proc/self/mountinfo`, refuses the jailed boot with the variant naming that flag,
    // before any VMM is spawned or the scratch dir is touched.
    if !have_jailer_privileges() {
        eprintln!(
            "skipping nodev_and_noexec_scratch_mounts_refuse_a_jailed_boot: needs real root \
             (euid 0, initial userns)"
        );
        return;
    }
    for options in ["nodev", "noexec"] {
        let mount = FlaggedMount::tmpfs(&format!("scratch-{options}"), options);
        let mut cfg = jailed_agent_config();
        cfg.scratch_dir = mount.path().to_path_buf();
        let err = match Vm::boot(cfg) {
            Err(e) => e,
            Ok(_vm) => panic!("a jailed boot on a {options} scratch mount must be refused"),
        };
        let named_the_flag = match (options, &err) {
            ("nodev", VmmError::ScratchDirNodev(p)) | ("noexec", VmmError::ScratchDirNoexec(p)) => {
                p == mount.path()
            }
            _ => false,
        };
        assert!(
            named_the_flag,
            "a {options} scratch mount must refuse with the variant naming the flag and the \
             offending path {}; got: {err}",
            mount.path().display()
        );
        // Refused before anything was staged: the scratch mount is still empty, so no VMM, no
        // rootfs copy, and no chroot ever touched it.
        let leftovers: Vec<_> = std::fs::read_dir(mount.path())
            .expect("read the scratch mount back")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            leftovers.is_empty(),
            "the refusal must precede staging; scratch holds {leftovers:?}"
        );
    }
}
