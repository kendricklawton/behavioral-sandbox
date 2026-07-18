//! End-to-end test: a CPU-heavy run reports higher CPU than an idle one, attributed to the
//! sandbox's own cgroup.
//!
//! `#[ignore]`d: it boots a real microVM (needs `/dev/kvm` + the agent rootfs) and attaches the
//! `sched_switch` accounting probe (needs `CAP_BPF`+`CAP_PERFMON` + kernel BTF + the built object). Run
//! via `cargo xtask ci-privileged`. Uses `agent-vmm` as a **dev-dependency only**, so the loader library
//! stays independent of the driver: the two tracks bridge by plain values (a VMM pid → its cgroup).
//!
//! The proof is the metering primitive doing its job: with the meter targeting the VMM's cgroup, an idle
//! guest (`sleep`) charges near-zero host CPU to that cgroup, while a guest pegging a vCPU (a busy Python
//! loop) charges most of a core's worth, measured from the host's scheduler, attributed to exactly the
//! sandbox's cgroup, never the driver's.
#![allow(clippy::panic)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use agent_probes_loader::{cgroup_id_of_pid, check_support, object_path, ResourceMeter};
use agent_vmm::{BootConfig, Vm, DEFAULT_GUEST_CID, GUEST_READY_MARKER};

/// The workspace root, from this crate's manifest dir, so the artifact paths are cwd-independent.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Why this host can't run the test (a skip reason), or `None` when it can, so it prints *why* it
/// skipped, like the other probe tests.
fn skip_reason() -> Option<String> {
    if let Err(e) = check_support() {
        return Some(e.to_string());
    }
    if !object_path().is_file() {
        return Some(format!(
            "BPF object {} not built (run `cargo xtask build-probes`)",
            object_path().display()
        ));
    }
    if !Path::new("/dev/kvm").exists() {
        return Some("/dev/kvm not present".into());
    }
    if !workspace_root()
        .join("artifacts/rootfs-agent.ext4")
        .is_file()
    {
        return Some("agent rootfs not built (run `cargo xtask build-rootfs`)".into());
    }
    None
}

/// An agent-rootfs boot config pointed at the workspace artifacts (absolute paths, so it's
/// cwd-independent). Read-only shared base + tmpfs overlay, vsock exec on. **No** networking: the meter
/// scopes to the VMM's cgroup, which needs nothing on the tap.
fn agent_config() -> BootConfig {
    let root = workspace_root();
    let mut cfg = BootConfig::from_env();
    if std::env::var_os("AGENT_KERNEL").is_none() {
        cfg.kernel = root.join("artifacts/vmlinux");
    }
    cfg.rootfs = root.join("artifacts/rootfs-agent.ext4");
    cfg.userspace_marker = GUEST_READY_MARKER.to_string();
    cfg.guest_cid = Some(DEFAULT_GUEST_CID);
    cfg.read_only_root = true;
    cfg.boot_timeout = Duration::from_secs(30);
    cfg
}

/// The wall-clock window each phase (idle, busy) runs for. Long enough that a full core of busy CPU is
/// unmistakably larger than an idle guest's, short enough to keep the test quick.
const PHASE: Duration = Duration::from_millis(1500);

/// How long to wait after each guest command before reading the CPU total. The meter charges a slice
/// at **switch-out** (that is when `sched_switch` fires), so a pegged vCPU thread's whole slice lands
/// only once the guest goes idle and the vCPU blocks in HLT; reading the instant `exec` returns races
/// that chain and could miss the entire busy slice on a quiet host core.
const SETTLE: Duration = Duration::from_millis(300);

#[test]
#[ignore = "needs /dev/kvm + CAP_BPF/CAP_PERFMON + BTF + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn a_cpu_heavy_run_reports_more_cpu_than_an_idle_one_attributed_to_the_sandbox() {
    if let Some(why) = skip_reason() {
        eprintln!(
            "skipping a_cpu_heavy_run_reports_more_cpu_than_an_idle_one_attributed_to_the_sandbox: {why}"
        );
        return;
    }

    // Boot a sandbox (unjailed on purpose: the proof is the cgroup accounting, not the jailer, and
    // the unjailed path doesn't need the jail-uid device ACL). Its VMM runs in a per-VM lifetime cgroup
    //; that is the cgroup the meter attributes to.
    let vm = Vm::boot(agent_config()).expect("an agent microVM should boot");
    let vmm_pid = vm.vmm_pid();
    let cgroup = cgroup_id_of_pid(vmm_pid).expect("resolve the VMM's cgroup id");

    // Attach the meter once and target this sandbox's cgroup, the bridge (VMM pid → cgroup id).
    let mut meter = ResourceMeter::load().expect("load + attach the resource meter");
    meter.add_target(cgroup).expect("meter the sandbox cgroup");

    // Idle phase: the guest sleeps, so the VMM parks its vCPU and charges near-zero host CPU. Reset the
    // cgroup's total first so we measure only this phase. Python for both phases (not busybox `sleep`,
    // whose float support is a build option): same interpreter, only the workload differs, so the
    // comparison isolates exactly the thing under test.
    meter.reset(cgroup).expect("zero the idle baseline");
    let secs = PHASE.as_secs_f64();
    let idle = vm
        .exec(
            &[
                "python3".into(),
                "-c".into(),
                format!("import time; time.sleep({secs})"),
            ],
            b"",
        )
        .expect("run the idle guest command");
    assert_eq!(idle.exit_code, 0, "idle command failed: {idle:?}");
    std::thread::sleep(SETTLE); // let the vCPU's switch-out land (charges post at switch-out)
    let idle_cpu = meter.cpu_time(cgroup).expect("read idle CPU");

    // Busy phase: a Python loop spins a vCPU flat out for the same wall time, so the VMM's vCPU thread
    // runs hot and the host charges most of a core to the sandbox's cgroup.
    meter.reset(cgroup).expect("zero the busy baseline");
    let busy_src = format!(
        "import time\nend = time.monotonic() + {secs}\nwhile time.monotonic() < end:\n    pass\n"
    );
    let busy = vm
        .exec(&["python3".into(), "-c".into(), busy_src], b"")
        .expect("run the CPU-heavy guest command");
    assert_eq!(busy.exit_code, 0, "busy command failed: {busy:?}");
    // The settle matters most here: the pegged vCPU may have run its whole slice without a single
    // switch, and the charge posts only when the guest idles and the vCPU thread blocks.
    std::thread::sleep(SETTLE);
    let busy_cpu = meter.cpu_time(cgroup).expect("read busy CPU");

    eprintln!("idle CPU {idle_cpu:?}, busy CPU {busy_cpu:?} over a {PHASE:?} window per phase");

    // The headline: the CPU-heavy run reports materially more CPU than the idle one.
    assert!(
        busy_cpu > idle_cpu,
        "busy CPU ({busy_cpu:?}) must exceed idle CPU ({idle_cpu:?})"
    );
    // And by a wide margin, not a hair: a pegged vCPU should charge a large fraction of the wall window,
    // while an idle guest charges a small one. Loose bounds so scheduler noise can't flake it.
    assert!(
        busy_cpu >= PHASE / 2,
        "a full-core busy loop should charge at least half the {PHASE:?} window, got {busy_cpu:?}"
    );
    assert!(
        busy_cpu > idle_cpu * 3,
        "busy CPU ({busy_cpu:?}) should dwarf idle CPU ({idle_cpu:?})"
    );

    // Attribution: the busy time landed on *this* sandbox's cgroup and **nowhere else**. It is the only
    // registered target (and meter-all is off), so the CPU map must hold exactly one entry: ours, with
    // the charge on it. The exclusivity is the real "attributed correctly" proof.
    let all = meter.cpu_ns_all().expect("read the whole CPU map");
    assert_eq!(
        all.len(),
        1,
        "only the metered sandbox cgroup may appear in the CPU map, got {all:?}"
    );
    assert!(
        all.iter().any(|&(id, ns)| id == cgroup && ns > 0),
        "the sandbox cgroup {cgroup} must carry the charged CPU, got {all:?}"
    );

    drop(meter);
    vm.shutdown().expect("shut the sandbox down");
}
