//! Privileged integration tests for Phase-6 confinement under adversity: driver death cannot leak
//! a VM, the kill handle unblocks a wedged exec (P6.7), a guest fork bomb / mem-hog is bounded
//! by the VMM's cgroup with the host unaffected (P6.8), and the orphan sweep reclaims a crashed
//! driver's netns + scratch dir without touching a live sibling's (P6.9a).
//!
//! `#[ignore]`d because they need `/dev/kvm` and the fetched artifacts. Run via
//! `cargo xtask ci-privileged` or `cargo test -p agent-vmm -- --ignored`.
// A test binary: `panic!` (in non-`#[test]` helpers and on boot-setup failure) is the idiomatic
// assertion, which the workspace's `clippy::panic` deny doesn't auto-exempt outside `#[test]` fns.
#![allow(clippy::panic)]

mod common;

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use agent_vmm::{sweep_orphans, BootConfig, Vm};

use common::{agent_rootfs_config, config, have_jailer_privileges, have_net_admin};

/// The env var that turns `helper_boot_and_park` from a no-op into the crash-test victim. Without
/// it the helper returns immediately, so the ordinary `--ignored` sweep isn't wedged by it.
const HELPER_ENV: &str = "AGENT_CONFINEMENT_HELPER";

/// The env var that turns `helper_boot_networked_and_park` into the P6.9a sweep test's victim: a
/// **networked** boot, so the crash leaves the residue that matters — a per-VM netns holding a tap.
const HELPER_NET_ENV: &str = "AGENT_CONFINEMENT_HELPER_NET";

/// Whether `pid` is still a live `firecracker` process (same discipline as `boot.rs`: keyed on the
/// specific pid via `comm`, so a reaped-then-recycled pid running something else reads as gone).
fn is_firecracker(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|c| c.trim() == "firecracker")
        .unwrap_or(false)
}

/// The cgroup dir `pid` currently lives in (`/sys/fs/cgroup` + the `0::` line), or `None`.
fn cgroup_of(pid: u32) -> Option<PathBuf> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let rel = text.lines().find_map(|l| l.strip_prefix("0::"))?.trim();
    if rel.is_empty() || rel == "/" {
        return None;
    }
    Some(Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/')))
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

/// The crash-test victim, run **as a subprocess** by `driver_death_cannot_leak_a_vm`: boot a VM,
/// report the VMM's pid and cgroup on stdout, then park forever — so the parent can `SIGKILL` this
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
    // P6.7's headline claim, tested with a real crash: a driver process SIGKILLed mid-run (the one
    // signal no handler can catch — the stand-in for Ctrl-C, OOM, a panic-abort) does not leak its
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
        // (P6.9a) owns exactly this, so dogfood it rather than hand-rolling a scan. `child_pid`
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
    // VMM via its cgroup and remove the cgroup dir — promptly, not eventually.
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

/// The P6.9a crash-test victim: like [`helper_boot_and_park`], but a **networked** boot, so the
/// crash leaves the residue the sweep exists for — a per-VM network namespace holding an orphan tap.
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
    let prefix = format!("agent-{pid}-");
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
    // P6.9a's claim under the netns model: a networked VM's residue is a per-VM network namespace
    // (holding an orphan tap), left behind when its driver dies without teardown. It is no longer a
    // finite-pool reservation (each netns reuses a fixed /30), but still residue worth reclaiming. The
    // sweep must reclaim a dead driver's netns + scratch dir while sparing a concurrently-live
    // driver's — ownership by liveness, not by pattern.
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

    // The sweep owns fs/net residue, never processes: those are the sentinel's — and where the
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

    // The residue is really there before the sweep — otherwise the test would pass vacuously.
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

    // The live sibling is untouched — and still fully functional, not just present.
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
    // The embedder kill handle (P6.7): `exec` borrows `&self` and `shutdown` consumes `self`, so a
    // thread blocked in a long exec can't be stopped through the VM's own API. The handle is the
    // out-of-band path: cloneable, Send, and it kills through the cgroup file — so firing it from
    // another thread makes the VMM die, the vsock peer close, and the blocked exec return a typed
    // error long before its 30 s command (or budget) would have.
    let vm = Vm::boot(agent_rootfs_config()).expect("agent microVM should boot");
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

/// A cgroup carrying the engine's own limit derivation (`jail::cgroup_limit_args`, P6.2/decision
/// 013): `cpu.max` = exactly `vcpus` cores, `memory.max` = guest RAM + the 128 MiB VMM overhead.
/// Built by the test because the limits normally arrive via the jailer, and exec-under-jail is a
/// later Phase-6 migration — so P6.8 pins the *same-derived* caps onto the exec-capable boot path
/// and proves they bind under load. `None` (skip) where cgroups aren't writable/delegated.
struct LimitCgroup {
    dir: PathBuf,
    parent: PathBuf,
}

impl LimitCgroup {
    fn create(vcpus: u32, mem_mib: u32, tag: &str) -> Option<Self> {
        let parent =
            PathBuf::from("/sys/fs/cgroup").join(format!("agent-p68-{}", std::process::id()));
        std::fs::create_dir(&parent).ok()?;
        // Enable the controllers for the leaf. The parent holds no processes, so the cgroup v2
        // no-internal-processes rule doesn't apply; this still needs cpu+memory delegated to the
        // cgroup root (the same prerequisite the jailer limits have).
        let this = Self {
            dir: parent.join(tag),
            parent,
        };
        std::fs::write(this.parent.join("cgroup.subtree_control"), "+cpu +memory").ok()?;
        std::fs::create_dir(&this.dir).ok()?;
        let memory_max = (u64::from(mem_mib) + 128) * 1024 * 1024;
        let cpu_quota = u64::from(vcpus) * 100_000;
        std::fs::write(this.dir.join("memory.max"), memory_max.to_string()).ok()?;
        std::fs::write(this.dir.join("cpu.max"), format!("{cpu_quota} 100000")).ok()?;
        Some(this)
    }

    /// Move `pid` (its whole thread group) into the limited cgroup.
    fn enter(&self, pid: u32) {
        if let Err(e) = std::fs::write(self.dir.join("cgroup.procs"), pid.to_string()) {
            panic!("move VMM {pid} into {}: {e}", self.dir.display());
        }
    }

    fn read(&self, file: &str) -> String {
        std::fs::read_to_string(self.dir.join(file)).unwrap_or_default()
    }

    /// A named counter out of a flat `key value` stat file (`memory.events`, `cpu.stat`).
    fn stat(&self, file: &str, key: &str) -> u64 {
        self.read(file)
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0)
    }
}

impl Drop for LimitCgroup {
    fn drop(&mut self) {
        // The VM must already be reaped (declare the cgroup before the VM, so it drops after).
        let _ = std::fs::remove_dir(&self.dir);
        let _ = std::fs::remove_dir(&self.parent);
    }
}

#[test]
#[ignore = "needs /dev/kvm + real root + delegated cgroups (run via `cargo xtask ci-privileged` as root)"]
fn guest_mem_hog_is_bounded_by_the_cgroup() {
    // P6.8, memory half: a guest allocating everything it can reach pushes the VMM's host memory
    // toward its cap, and the cap holds — accounted memory never passes `memory.max`, the kernel
    // never OOM-kills the VMM (the guest's *own* OOM killer eats the hog first, inside the
    // hardware boundary), and the VM stays responsive afterwards. Host unaffected, by observation.
    if !have_jailer_privileges() {
        eprintln!("skipping guest_mem_hog_is_bounded_by_the_cgroup: needs real root");
        return;
    }
    let cfg = agent_rootfs_config();
    let (vcpus, mem_mib) = (cfg.vcpus, cfg.mem_mib);
    let Some(cg) = LimitCgroup::create(vcpus, mem_mib, "mem-hog") else {
        eprintln!(
            "skipping guest_mem_hog_is_bounded_by_the_cgroup: cgroup v2 not writable/delegated"
        );
        return;
    };
    let vm = Vm::boot(cfg).expect("agent microVM should boot");
    cg.enter(vm.vmm_pid());

    // Touch pages, don't just reserve them: `bytearray` zero-fills, so every chunk is real guest
    // RAM the VMM must back with host memory — charged to the limited cgroup. The hog ends either
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
    eprintln!(
        "mem-hog: guest exit {}, host memory.peak {} / memory.max {}",
        result.exit_code,
        cg.read("memory.peak").trim(),
        cg.read("memory.max").trim(),
    );

    // The cap held. `memory.peak` is the high-water mark of what the kernel charged this cgroup;
    // it must be a real load (the hog charged here) and must not pass the cap.
    let peak: u64 = cg
        .read("memory.peak")
        .trim()
        .parse()
        .expect("parse memory.peak (kernel >= 5.19)");
    let max: u64 = cg
        .read("memory.max")
        .trim()
        .parse()
        .expect("parse memory.max");
    assert!(
        peak > 64 * 1024 * 1024,
        "the hog should have pushed real memory through the cgroup (peak {peak})"
    );
    assert!(
        peak <= max,
        "memory.peak {peak} must never pass memory.max {max}"
    );
    // The host never had to OOM-kill the VMM: the 128 MiB overhead budget (decision 012 addendum)
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
fn guest_fork_bomb_is_bounded_by_the_cgroup() {
    // P6.8, CPU half: a storm of spinning guest processes. Two bounds hold at once. Hardware
    // isolation means guest processes simply don't exist on the host — the VMM's thread count
    // stays flat no matter how hard the guest forks. And the cgroup's cpu.max means the whole VM
    // (vCPUs + VMM overhead threads) cannot burn more than its quota of host CPU. The storm's own
    // exit also exercises P6.4: its spinners are reaped by the guest agent's per-exec cgroup, so
    // the guest is idle again for the follow-up exec.
    if !have_jailer_privileges() {
        eprintln!("skipping guest_fork_bomb_is_bounded_by_the_cgroup: needs real root");
        return;
    }
    let cfg = agent_rootfs_config();
    let (vcpus, mem_mib) = (cfg.vcpus, cfg.mem_mib);
    let Some(cg) = LimitCgroup::create(vcpus, mem_mib, "fork-bomb") else {
        eprintln!(
            "skipping guest_fork_bomb_is_bounded_by_the_cgroup: cgroup v2 not writable/delegated"
        );
        return;
    };
    let vm = Vm::boot(cfg).expect("agent microVM should boot");
    cg.enter(vm.vmm_pid());

    let threads = |pid: u32| -> u64 {
        std::fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("Threads:"))
                    .and_then(|v| v.trim().parse().ok())
            })
            .unwrap_or(0)
    };
    let threads_before = threads(vm.vmm_pid());
    let usage_before = cg.stat("cpu.stat", "usage_usec");
    let started = Instant::now();

    // 100 spinning shells for 3 s: a bounded storm rather than the classic unbounded `:(){ :|:& };:`
    // so the guest agent stays schedulable and the run is measurable (the *unbounded* variant would
    // starve the agent inside the guest — a guest-availability problem, while this test is about
    // what the host feels). The spinners outlive their parent command on purpose: P6.4's tree
    // reaping is what cleans them up.
    let storm = [
        "sh",
        "-c",
        "i=0; while [ \"$i\" -lt 100 ]; do i=$((i+1)); while :; do :; done & done; sleep 3; echo storm-live",
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
    let threads_after = threads(vm.vmm_pid());
    assert_eq!(
        threads_after, threads_before,
        "guest forks must not create host threads (hardware isolation)"
    );

    // The cgroup CPU bound, observed: everything the VM burned during the storm is capped by
    // quota × wall-clock (`vcpus` cores' worth), plus slack for the VMM's non-vCPU threads.
    let usage = cg.stat("cpu.stat", "usage_usec") - usage_before;
    let cap = elapsed.as_micros() as u64 * u64::from(vcpus) + 2_000_000;
    eprintln!(
        "fork storm: {elapsed:?} wall, {usage} usec of host CPU (cap {cap}), \
         threads {threads_before} -> {threads_after}"
    );
    assert!(
        usage <= cap,
        "host CPU burned ({usage} usec) must stay within the cgroup quota ({cap} usec)"
    );

    // P6.4 reaped the orphaned spinners with the storm's exec cgroup: the guest is idle again.
    let echo = ["echo", "alive"].map(String::from);
    let after = vm.exec(&echo, b"").expect("post-storm exec should run");
    assert_eq!(after.stdout, b"alive\n");
    vm.shutdown().expect("shutdown should succeed");
}
