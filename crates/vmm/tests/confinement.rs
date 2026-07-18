//! Privileged integration tests for confinement under adversity: driver death cannot leak
//! a VM, the kill handle unblocks a wedged exec, a guest fork bomb / mem-hog is bounded
//! by the VMM's cgroup with the host unaffected, and the orphan sweep reclaims a crashed
//! driver's netns + scratch dir without touching a live sibling's.
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

use agent_test_support::{process_threads, LimitCgroup};
use common::{agent_rootfs_config, cgroup_of, config, have_jailer_privileges, have_net_admin};

/// The env var that turns `helper_boot_and_park` from a no-op into the crash-test victim. Without
/// it the helper returns immediately, so the ordinary `--ignored` sweep isn't wedged by it.
const HELPER_ENV: &str = "AGENT_CONFINEMENT_HELPER";

/// The env var that turns `helper_boot_networked_and_park` into the sweep test's victim: a
/// **networked** boot, so the crash leaves the residue that matters, a per-VM netns holding a tap.
const HELPER_NET_ENV: &str = "AGENT_CONFINEMENT_HELPER_NET";

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
    // The sweep's claim under the netns model: a networked VM's residue is a per-VM network namespace
    // (holding an orphan tap), left behind when its driver dies without teardown. It is no longer a
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
    let cfg = agent_rootfs_config();
    let (vcpus, mem_mib) = (u32::from(cfg.vcpus.get()), cfg.mem_mib.get());
    let Some(cg) = LimitCgroup::create(vcpus, mem_mib, "mem-hog") else {
        eprintln!(
            "skipping guest_mem_hog_is_bounded_by_the_cgroup: cgroup v2 not writable/delegated"
        );
        return;
    };
    let vm = Vm::boot(cfg).expect("agent microVM should boot");
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
    let cfg = agent_rootfs_config();
    let (vcpus, mem_mib) = (u32::from(cfg.vcpus.get()), cfg.mem_mib.get());
    let Some(cg) = LimitCgroup::create(vcpus, mem_mib, "fork-bomb") else {
        eprintln!(
            "skipping guest_fork_bomb_is_bounded_by_the_cgroup: cgroup v2 not writable/delegated"
        );
        return;
    };
    let vm = Vm::boot(cfg).expect("agent microVM should boot");
    cg.enter(vm.vmm_pid());

    let threads_before = process_threads(vm.vmm_pid());
    let usage_before = cg.stat("cpu.stat", "usage_usec");
    let started = Instant::now();

    // 100 spinning shells for 3 s: a bounded storm rather than the classic unbounded `:(){ :|:& };:`
    // so the guest agent stays schedulable and the run is measurable (the *unbounded* variant would
    // starve the agent inside the guest, a guest-availability problem, while this test is about
    // what the host feels). The spinners outlive their parent command on purpose: the agent's tree
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
    let threads_after = process_threads(vm.vmm_pid());
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

    // The per-exec cgroup reaped the orphaned spinners with the storm's exec cgroup: the guest is idle again.
    let echo = ["echo", "alive"].map(String::from);
    let after = vm.exec(&echo, b"").expect("post-storm exec should run");
    assert_eq!(after.stdout, b"alive\n");
    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + real root + delegated cgroups (run via `cargo xtask ci-privileged` as root)"]
fn a_hostile_run_cannot_starve_or_observe_a_co_resident_run() {
    // The explicitly multi-tenant assertion (P15.8): a hostile run storming the host's CPU alongside
    // a well-behaved run on the *same host* can neither **starve** it (the victim's work still
    // completes, correctly and within a bound) nor **observe** it (distinct VMMs; network isolation is
    // the per-VM netns's job, net.rs). Each run is capped at its own cgroup, so the attacker cannot
    // take more than its quota, the victim's share is protected *by construction*; the wall-clock
    // ceiling is a sanity check layered on top of that guarantee, not the guarantee itself.
    if !have_jailer_privileges() {
        eprintln!(
            "skipping a_hostile_run_cannot_starve_or_observe_a_co_resident_run: needs real root"
        );
        return;
    }
    let cfg = agent_rootfs_config();
    let (vcpus, mem_mib) = (u32::from(cfg.vcpus.get()), cfg.mem_mib.get());
    let (Some(victim_cg), Some(attacker_cg)) = (
        LimitCgroup::create(vcpus, mem_mib, "victim"),
        LimitCgroup::create(vcpus, mem_mib, "attacker"),
    ) else {
        eprintln!("skipping a_hostile_run_cannot_starve_or_observe_a_co_resident_run: cgroup v2 not writable/delegated");
        return;
    };

    // Two co-resident runs, each in its own capped cgroup, the per-run isolation a hoster relies on.
    let victim = Vm::boot(cfg.clone()).expect("victim microVM should boot");
    victim_cg.enter(victim.vmm_pid());
    let attacker = Vm::boot(cfg).expect("attacker microVM should boot");
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
    // host-dependent, so the real guarantee is the cap above; this is the sanity check).
    const SLOWDOWN_MAX: u32 = 10;
    let ceiling = solo_wall * SLOWDOWN_MAX + Duration::from_secs(5);
    eprintln!("co-resident: victim solo {solo_wall:?} vs under attack {under_wall:?} (ceiling {ceiling:?})");
    assert!(
        under_wall <= ceiling,
        "victim was slowed past the bound: {under_wall:?} > {ceiling:?} (starvation)"
    );

    victim.shutdown().expect("victim shutdown should succeed");
    attacker
        .shutdown()
        .expect("attacker shutdown should succeed");
}
