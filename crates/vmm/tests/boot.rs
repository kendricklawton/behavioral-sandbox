//! Privileged boot integration test: boot a real Firecracker microVM to userspace and tear it
//! down, repeatably and without leaks.
//!
//! `#[ignore]`d because it needs `/dev/kvm` and the fetched artifacts. Run it with
//! `cargo xtask ci-privileged` (which guards on both) or `cargo test -p agent-vmm -- --ignored`.
// A test binary: `panic!` (in non-`#[test]` helpers and on boot-setup failure) is the idiomatic
// assertion, which the workspace's `clippy::panic` deny doesn't auto-exempt outside `#[test]` fns.
#![allow(clippy::panic)]

use std::path::PathBuf;
use std::time::Duration;

use agent_vmm::{BootConfig, Vm, DEFAULT_GUEST_CID, GUEST_READY_MARKER};

/// A host scratch dir removed on drop, so a panicking assertion can't leak it. (The unit tests have
/// their own copy; the integration crate is separate, so it needs one too.)
struct TmpDir(PathBuf);
impl TmpDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("agent-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Self(dir)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The hex sha256 of `bytes`, via the host `sha256sum` (no crate dep — mirrors the input test's
/// host-side hash of the injected payload). A free helper (not a `#[test]` fn), so it uses explicit
/// panics rather than `expect`, which the workspace lints only re-allow inside test functions.
fn sha256_hex(bytes: &[u8]) -> String {
    use std::io::Write as _;
    let mut child = match std::process::Command::new("sha256sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => panic!("spawn sha256sum: {e}"),
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(bytes);
    }
    let out = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => panic!("host sha256: {e}"),
    };
    match String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
    {
        Some(h) => h.to_string(),
        None => panic!("empty sha256sum output"),
    }
}

/// A boot config pointed at the workspace's fetched artifacts (absolute, so it's cwd-independent).
/// Explicit `AGENT_KERNEL`/`AGENT_ROOTFS` overrides still win — they're the documented escape
/// hatch for hosts without the pinned artifacts (e.g. non-x86_64).
fn config() -> BootConfig {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut cfg = BootConfig::from_env();
    if std::env::var_os("AGENT_KERNEL").is_none() {
        cfg.kernel = root.join("artifacts/vmlinux");
    }
    if std::env::var_os("AGENT_ROOTFS").is_none() {
        cfg.rootfs = root.join("artifacts/rootfs.ext4");
    }
    cfg.boot_timeout = Duration::from_secs(30);
    cfg
}

#[test]
#[ignore = "needs /dev/kvm + artifacts (run via `cargo xtask ci-privileged`)"]
fn boots_to_userspace_and_shuts_down() {
    let cfg = config();
    let marker = cfg.userspace_marker.clone();
    let vm = Vm::boot(cfg).expect("microVM should boot to userspace");

    // Boot returns only after the marker is seen, so this is guaranteed — but assert it anyway to
    // document what "reached userspace" means, and that the console was actually captured.
    assert!(
        vm.console().contains(&marker),
        "console should show the userspace marker {marker:?}; got:\n{}",
        vm.console()
    );

    let latency = vm.boot_latency();
    assert!(latency > Duration::ZERO, "boot latency should be measured");
    assert!(
        latency < Duration::from_secs(30),
        "boot latency {latency:?} should be well under the deadline"
    );

    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + artifacts (run via `cargo xtask ci-privileged`)"]
fn boots_with_a_vsock_device() {
    // Real Firecracker must accept `PUT /vsock` and boot to userspace with the device configured.
    // (This proves just the config path on the stock Ubuntu rootfs; the full host→guest-agent
    // round trip is `execs_a_command_in_the_microvm`, against the agent rootfs.)
    let mut cfg = config();
    cfg.guest_cid = Some(DEFAULT_GUEST_CID);
    let marker = cfg.userspace_marker.clone();

    let vm = Vm::boot(cfg).expect("microVM with vsock should boot to userspace");
    assert!(
        vm.console().contains(&marker),
        "guest should still reach userspace with vsock configured"
    );
    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + artifacts (run via `cargo xtask ci-privileged`)"]
fn snapshots_a_running_microvm() {
    // P5.1: pause a booted VM and take a full snapshot (memory + state) via the API. The bundle is
    // three real files, and the VM is resumed so it stays usable afterward.
    let vm = Vm::boot(config()).expect("microVM should boot to userspace");
    let bundle = TmpDir::new("snap-p51");
    let snap = vm
        .snapshot(bundle.path())
        .expect("pause + full snapshot should succeed");

    for (label, path) in [
        ("state", snap.state_path()),
        ("memory", snap.mem_path()),
        ("root disk", snap.root_drive_path()),
    ] {
        let meta = std::fs::metadata(path)
            .unwrap_or_else(|e| panic!("{label} file {path:?} should exist: {e}"));
        assert!(meta.len() > 0, "{label} file should be non-empty");
    }
    // The memory file is roughly the guest's RAM (256 MiB default) — a sanity floor, not an exact
    // size, so this doesn't couple to Firecracker's exact memory-file layout.
    let mem_len = std::fs::metadata(snap.mem_path()).expect("mem meta").len();
    assert!(
        mem_len >= 128 * 1024 * 1024,
        "memory file {mem_len} bytes looks too small for a full snapshot"
    );

    // Resume worked, so the VM is still alive and shuts down cleanly.
    vm.shutdown()
        .expect("post-snapshot shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + artifacts (run via `cargo xtask ci-privileged`)"]
fn restores_a_snapshot_onto_a_fresh_vmm() {
    // P5.2: snapshot a VM, throw it away, then restore from the bundle on a fresh VMM and confirm it
    // resumes. Measures restore latency alongside the source's cold boot for the comparison.
    let cfg = config();
    let source = Vm::boot(cfg.clone()).expect("source microVM should boot");
    let cold_boot = source.boot_latency();

    let bundle = TmpDir::new("snap-p52");
    let snap = source
        .snapshot(bundle.path())
        .expect("snapshot should succeed");
    // Drop the source entirely: its scratch dir (and the private rootfs copy it booted from) are
    // reclaimed, so a successful restore proves the bundle is self-contained.
    source.shutdown().expect("source shutdown should succeed");

    let restored = Vm::restore(&snap, &cfg).expect("restore should load and resume");
    let restore_latency = restored.boot_latency();
    assert!(
        restore_latency > Duration::ZERO,
        "restore latency should be measured"
    );

    // Liveness: the restored VMM is a real, running process, and it stays up past resume (a bundle
    // that loaded but instantly died would fail `run_restore`, but assert it held for a beat too).
    let pid = restored.vmm_pid();
    let alive = |pid: u32| std::path::Path::new(&format!("/proc/{pid}")).exists();
    assert!(alive(pid), "restored VMM (pid {pid}) should be alive");
    std::thread::sleep(Duration::from_millis(200));
    assert!(alive(pid), "restored VMM should stay alive after resume");

    eprintln!("cold boot {cold_boot:?} vs snapshot restore {restore_latency:?}");
    restored
        .shutdown()
        .expect("restored shutdown should succeed");
}

/// Boot the agent rootfs, warm the Python runtime (so the interpreter + stdlib are page-cache-hot in
/// the guest's memory), and take a snapshot of *that* warm state. Returns the source's cold-boot
/// latency alongside the bundle so callers can compare it to restore.
// A free helper (not a `#[test]` fn), so it uses explicit `panic!` rather than `.expect()`, which the
// workspace lints only re-allow inside test functions.
fn warm_python_snapshot(bundle: &TmpDir) -> (agent_vmm::Snapshot, Duration) {
    let source = match Vm::boot(agent_rootfs_config()) {
        Ok(vm) => vm,
        Err(e) => panic!("agent microVM should boot: {e}"),
    };
    let cold_boot = source.boot_latency();
    // "Runtime loaded": run Python once so the snapshot captures a guest with the interpreter and its
    // imports already resident, not a bare boot.
    let warm = ["python3", "-c", "import json, os, sys"].map(String::from);
    match source.exec(&warm, &[]) {
        Ok(out) if out.exit_code == 0 => {}
        Ok(out) => panic!("warm-up python should exit 0, got {}", out.exit_code),
        Err(e) => panic!("warm-up exec should run: {e}"),
    }
    let snap = match source.snapshot(bundle.path()) {
        Ok(s) => s,
        Err(e) => panic!("warm snapshot (read_only_root + vsock) should succeed: {e}"),
    };
    if let Err(e) = source.shutdown() {
        panic!("source shutdown should succeed: {e}");
    }
    (snap, cold_boot)
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn warm_snapshot_restores_and_runs_code() {
    // P5.3: snapshot a warm agent VM (runtime loaded), throw the source away, restore a clone off the
    // shared read-only base, and run Python on it — the exec channel survives the snapshot (Firecracker
    // re-binds vsock on restore), so a warm clone runs code without paying the cold boot.
    let bundle = TmpDir::new("snap-warm");
    let (snap, cold_boot) = warm_python_snapshot(&bundle);
    // A warm (read_only_root) snapshot references the shared base in place, so the bundle carries no
    // root-disk copy: the disk path points outside the bundle dir, not at a copy within it.
    assert!(
        !snap.root_drive_path().starts_with(bundle.path()),
        "a read_only_root snapshot should reference the shared base, not copy it into the bundle"
    );

    let restored = Vm::restore(&snap, &agent_rootfs_config()).expect("warm restore should resume");
    let restore_latency = restored.boot_latency();
    let argv = ["python3", "-c", "print(2 + 2)"].map(String::from);
    let out = restored
        .exec(&argv, &[])
        .expect("exec on the restored warm clone should succeed");
    assert_eq!(out.exit_code, 0, "python should exit 0");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "4",
        "restored warm clone should run Python and return 4"
    );
    // A restored VM's live disk is an anonymous inode with no host path, so re-snapshotting it must be
    // refused, not silently bundle a stale / shared-writable disk.
    let redo = TmpDir::new("snap-warm-redo");
    assert!(
        restored.snapshot(redo.path()).is_err(),
        "re-snapshotting a restored VM should be refused"
    );

    eprintln!("warm: cold boot {cold_boot:?} vs restore {restore_latency:?} + exec");
    restored
        .shutdown()
        .expect("restored shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn restores_concurrent_clones_from_one_warm_snapshot() {
    // P5.4: restore several clones from one warm snapshot and keep them all alive at once. Each shares
    // the read-only base (density) but is an independent VM — its own vsock socket (bound relative to
    // its own scratch dir, so no collision) and its own in-RAM overlay. Prove it by running a distinct
    // computation on each concurrently-alive clone and getting each clone's own answer back.
    const N: usize = 3;
    let bundle = TmpDir::new("snap-warm-clones");
    let (snap, _cold) = warm_python_snapshot(&bundle);

    let clones: Vec<_> = (0..N)
        .map(|i| {
            Vm::restore(&snap, &agent_rootfs_config())
                .unwrap_or_else(|e| panic!("clone {i} should restore concurrently: {e}"))
        })
        .collect();

    // All N are alive simultaneously with distinct VMMs.
    let pids: std::collections::BTreeSet<u32> = clones.iter().map(|c| c.vmm_pid()).collect();
    assert_eq!(
        pids.len(),
        N,
        "each clone should be its own live VMM process"
    );

    // Each clone runs its own code and returns its own result, while the others are still alive.
    for (i, clone) in clones.iter().enumerate() {
        let argv = ["python3", "-c", &format!("print({i} * {i})")].map(String::from);
        let out = clone
            .exec(&argv, &[])
            .unwrap_or_else(|e| panic!("exec on clone {i} should succeed: {e}"));
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            (i * i).to_string(),
            "clone {i} should compute its own value independently"
        );
    }

    for clone in clones {
        clone.shutdown().expect("clone shutdown should succeed");
    }
}

#[test]
#[ignore = "needs /dev/kvm + CAP_NET_ADMIN + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn restored_networked_clone_gets_a_fresh_identity() {
    // P5.5 (decision 011), network identity: the kernel `ip=` config runs once at the source's boot
    // and can't re-fire on restore, so the clone would wake with the snapshot's baked-in address on a
    // link it no longer matches. The driver recreates the snapshot's tap (fresh /30 on the host end)
    // and the agent applies the guest's fresh address over vsock — this proves the clone ends up on
    // its NEW /30 (old address gone), reachable at the transport layer, still deny-by-default.
    if !have_net_admin() {
        eprintln!("skipping: creating a tap needs CAP_NET_ADMIN");
        return;
    }

    // A networked snapshot without vsock has no channel to re-address the clone: refused, typed.
    // (The stock rootfs config: it boots to `login:` with no vsock, exactly the shape under test —
    // the agent rootfs can't boot vsock-less, since its readiness marker is the agent's post-bind.)
    let mut no_vsock = config();
    no_vsock.enable_network = true;
    let vm = Vm::boot(no_vsock).expect("networked VM without vsock should still boot");
    let refused = TmpDir::new("snap-net-novsock");
    assert!(
        vm.snapshot(refused.path()).is_err(),
        "a networked snapshot without the vsock exec channel must be refused"
    );
    vm.shutdown().expect("no-vsock VM shutdown");

    // Source: networked + vsock + warm. Snapshot it, remember its identity, then drop it (freeing
    // its tap name and /30 — the recreated tap needs the name; the /30 must be provably re-allocated).
    let mut cfg = agent_rootfs_config();
    cfg.enable_network = true;
    let source = Vm::boot(cfg.clone()).expect("networked agent microVM should boot");
    let source_guest_ip = source.guest_ip().expect("source guest ip");
    let source_tap = source.tap_name().expect("source tap name").to_string();
    let bundle = TmpDir::new("snap-net-warm");
    let snap = source
        .snapshot(bundle.path())
        .expect("networked warm snapshot should succeed");
    source.shutdown().expect("source shutdown");

    let clone = Vm::restore(&snap, &cfg).expect("networked warm restore should resume");

    // Same tap name (the snapshot baked it in; v1.9 has no network_overrides), fresh /30.
    assert_eq!(
        clone.tap_name(),
        Some(source_tap.as_str()),
        "the clone must reuse the snapshot's recorded tap name"
    );
    let clone_guest_ip = clone.guest_ip().expect("clone guest ip");
    assert_ne!(
        clone_guest_ip, source_guest_ip,
        "the clone must get a fresh /30, not the source's baked-in one"
    );

    // In-guest: eth0 carries exactly the new address; the baked-in one is gone.
    let addrs = clone
        .exec(
            &[
                "ip".into(),
                "-4".into(),
                "addr".into(),
                "show".into(),
                "dev".into(),
                "eth0".into(),
            ],
            b"",
        )
        .expect("read the clone's eth0 addresses");
    let addrs = String::from_utf8_lossy(&addrs.stdout).into_owned();
    assert!(
        addrs.contains(&clone_guest_ip.to_string()),
        "clone eth0 should carry its fresh address {clone_guest_ip}; got:\n{addrs}"
    );
    assert!(
        !addrs.contains(&source_guest_ip.to_string()),
        "clone eth0 must not keep the snapshot's baked-in address {source_guest_ip}; got:\n{addrs}"
    );

    // Transport-layer proof on the NEW link: a real host listener on the fresh /30 is reachable.
    let clone_host_ip = clone.host_ip().expect("clone host ip");
    let listener = std::net::TcpListener::bind((clone_host_ip, 0)).expect("bind on the fresh /30");
    let port = listener.local_addr().expect("local addr").port();
    let connect = clone
        .exec(
            &[
                "python3".into(),
                "-c".into(),
                format!(
                    "import socket; socket.create_connection((\"{clone_host_ip}\", {port}), timeout=3).close()"
                ),
            ],
            b"",
        )
        .expect("guest connect to the fresh host end");
    assert_eq!(
        connect.exit_code,
        0,
        "clone should reach a listener on its fresh /30; console:\n{}",
        clone.console()
    );

    // Deny-by-default carried over the restore: still no default route.
    let off = clone
        .exec(
            &[
                "ping".into(),
                "-c".into(),
                "1".into(),
                "-W".into(),
                "1".into(),
                "192.0.2.1".into(),
            ],
            b"",
        )
        .expect("ping an off-subnet address");
    assert_ne!(
        off.exit_code, 0,
        "restored clone must stay deny-by-default (no default route)"
    );

    clone.shutdown().expect("clone shutdown");
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn restored_clones_do_not_share_entropy_or_freeze_the_clock() {
    // P5.5 (decision 011), entropy + clocks. Every clone wakes from the same memory image, so if the
    // kernel CRNG never reseeded, two clones' first `getrandom` draws would be byte-identical — the
    // classic clone-entropy vulnerability (shared session keys/nonces/UUIDs). The pinned stack has
    // both halves of the fix (Firecracker v1.9 ships VMGenID; kernel 6.1 has the vmgenid driver,
    // which reseeds the CRNG on a generation bump): this proves it end to end. Clock skew is
    // measured and reported, not asserted (decision 011 records the posture).
    let bundle = TmpDir::new("snap-entropy");
    let (snap, _cold) = warm_python_snapshot(&bundle);

    let draw = |label: &str| {
        let clone = Vm::restore(&snap, &agent_rootfs_config())
            .unwrap_or_else(|e| panic!("clone {label} should restore: {e}"));
        let out = clone
            .exec(
                &[
                    "python3".into(),
                    "-c".into(),
                    // One read, immediately after restore — the dangerous window, before any natural
                    // interrupt-entropy reseed could paper over shared CRNG state.
                    "import os, time; print(os.urandom(16).hex()); print(int(time.time()))".into(),
                ],
                b"",
            )
            .unwrap_or_else(|e| panic!("clone {label} exec: {e}"));
        assert_eq!(out.exit_code, 0, "clone {label} python should exit 0");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let mut lines = stdout.lines();
        let hex = lines.next().unwrap_or_default().trim().to_string();
        let epoch: i64 = lines.next().unwrap_or_default().trim().parse().unwrap_or(0);
        assert_eq!(
            hex.len(),
            32,
            "clone {label} should print 16 random bytes as hex"
        );
        clone
            .shutdown()
            .unwrap_or_else(|e| panic!("clone {label} shutdown: {e}"));
        (hex, epoch)
    };

    let (hex_a, epoch_a) = draw("A");
    let (hex_b, _epoch_b) = draw("B");
    assert_ne!(
        hex_a, hex_b,
        "two clones' first urandom draws must differ (VMGenID must reseed the CRNG on restore)"
    );

    // Clock posture (measured, not asserted): report the restored guest's wall-clock skew vs the
    // host. kvm-clock keeps the monotonic clock sane; CLOCK_REALTIME may lag by the snapshot age.
    let host_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    eprintln!(
        "clock: restored clone A wall-clock skew vs host ≈ {}s",
        host_epoch - epoch_a
    );
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn pool_serves_warm_clones_and_discards_dead_ones() {
    // P5.6: the warm Pool. Prefill keeps clones exec-ready so `take` is a pop (µs) plus a fast
    // health probe — not a cold boot. A clone that died while pooled is a typed GuestUnavailable
    // from the probe, so `take` discards it and serves the next (or restores inline when dry)
    // instead of surfacing an infra failure — the retry semantics the P2.7 deferral promised.
    use agent_vmm::Pool;

    let bundle = TmpDir::new("snap-pool");
    let (snap, cold_boot) = warm_python_snapshot(&bundle);

    let mut pool =
        Pool::new(snap, agent_rootfs_config(), 2).expect("pool should prefill two warm clones");
    assert_eq!(pool.ready(), 2, "prefill should hit the target");

    // Fast path: take a ready clone and run code on it. The take is a pop + probe, so it must come
    // in far under a cold boot (the measured margin is printed, the bound asserted is generous).
    let t0 = std::time::Instant::now();
    let vm = pool.take().expect("take from a full pool");
    let take_latency = t0.elapsed();
    let out = vm
        .exec(&["python3".into(), "-c".into(), "print(1 + 1)".into()], b"")
        .expect("exec on a pooled clone");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "2");
    assert!(
        take_latency < cold_boot,
        "take ({take_latency:?}) should be far under a cold boot ({cold_boot:?})"
    );
    eprintln!("pool: take {take_latency:?} vs cold boot {cold_boot:?}");
    vm.shutdown().expect("pooled clone shutdown");
    assert_eq!(pool.ready(), 1, "take should consume ready stock");

    // Kill the remaining pooled clone's VMM behind the pool's back: the next take must *not* hand
    // out the corpse — the probe fails typed, the corpse is discarded, and (the pool now being dry)
    // a fresh clone is restored inline and served.
    let pids = pool.vmm_pids();
    assert_eq!(pids.len(), 1);
    let killed = std::process::Command::new("kill")
        .args(["-9", &pids[0].to_string()])
        .status()
        .expect("kill the pooled VMM");
    assert!(killed.success(), "SIGKILL the pooled VMM");
    std::thread::sleep(Duration::from_millis(100)); // let the socket die

    let vm2 = pool
        .take()
        .expect("take must discard the dead clone and restore a fresh one");
    let out2 = vm2
        .exec(&["python3".into(), "-c".into(), "print(2 + 2)".into()], b"")
        .expect("exec on the replacement clone");
    assert_eq!(String::from_utf8_lossy(&out2.stdout).trim(), "4");
    vm2.shutdown().expect("replacement clone shutdown");
    assert_eq!(pool.ready(), 0, "the corpse was discarded, not re-pooled");

    // Explicit top-up back to target, then graceful teardown of the stock.
    let restored = pool.refill().expect("refill should restore to target");
    assert_eq!(restored, 2);
    assert_eq!(pool.ready(), 2);
    pool.shutdown();
}

/// A boot config pointed at the **agent rootfs** (`cargo xtask build-rootfs`): readiness is the
/// agent's post-bind marker, and vsock is on. Deliberately not `AGENT_ROOTFS`-overridable — the
/// in-VM exec tests are about *that* image specifically.
fn agent_rootfs_config() -> BootConfig {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut cfg = BootConfig::from_env();
    if std::env::var_os("AGENT_KERNEL").is_none() {
        cfg.kernel = root.join("artifacts/vmlinux");
    }
    cfg.rootfs = root.join("artifacts/rootfs-agent.ext4");
    cfg.userspace_marker = GUEST_READY_MARKER.to_string();
    cfg.guest_cid = Some(DEFAULT_GUEST_CID);
    // Read-only shared base + a per-run tmpfs overlay (P3.3): `/` is writable in-guest but the base
    // file is never mutated. This is what makes the agent's `/tmp` working dir usable, so the exec
    // tests below exercise the overlay end to end.
    cfg.read_only_root = true;
    cfg.boot_timeout = Duration::from_secs(30);
    cfg
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn execs_a_command_in_the_microvm() {
    // Closes Phase 2's provisional "in a microVM" gate: the agent baked into `rootfs-agent.ext4`
    // actually binds vsock in a real guest, so `exec` round-trips end to end — not against a faked
    // socket. Boot returns once the agent's readiness marker reaches the console, so the connect
    // can't race the bind.
    let vm = Vm::boot(agent_rootfs_config())
        .expect("agent microVM should boot and the agent should announce readiness");
    let out = vm
        .exec(&["echo".into(), "hi".into()], b"")
        .expect("exec `echo hi` in the guest");
    assert_eq!(
        out.stdout,
        b"hi\n",
        "guest stdout should be `hi`; console:\n{}",
        vm.console()
    );
    assert_eq!(out.exit_code, 0, "`echo hi` should exit 0");
    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn execs_python_in_the_microvm() {
    // The reference language runtime: `build-rootfs` installs python3 from the pinned Alpine
    // branch, and a real interpreter (dynamic musl binary + its stdlib, not a shell builtin) runs
    // in the guest and computes — proving the image carries a working userland, not just busybox.
    let vm = Vm::boot(agent_rootfs_config())
        .expect("agent microVM should boot and the agent should announce readiness");
    let out = vm
        .exec(&["python3".into(), "-c".into(), "print(2+2)".into()], b"")
        .expect("exec python in the guest");
    assert_eq!(
        out.stdout,
        b"4\n",
        "python should print 4; console:\n{}",
        vm.console()
    );
    assert_eq!(out.exit_code, 0, "python should exit 0");
    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn python_script_writes_a_file_and_we_capture_it() {
    // Phase 3's runtime payoff, end to end: inject a small **Python script** as a file, run the real
    // interpreter on it inside a microVM, and pull back the file it wrote — the exec surface's
    // inject → run → capture loop with an actual language runtime (using the stdlib, `json`), not a
    // shell builtin. This is the per-file channel path (P2.5); the bulk block-device paths are
    // P3.4/P3.5.
    let vm = Vm::boot(agent_rootfs_config())
        .expect("agent microVM should boot and the agent should announce readiness");

    // A real script: import a stdlib module, compute, and write a file in the working dir.
    let script = "import json\n\
                  with open('result.json', 'w') as f:\n\
                  \x20\x20\x20\x20json.dump({'answer': 6 * 7}, f)\n";

    let out = vm
        .exec_with_files(
            &["python3".into(), "script.py".into()],
            b"",
            &[("script.py".into(), script.as_bytes().to_vec())],
            &["result.json".into()],
        )
        .expect("run the python script and capture its output file");

    assert_eq!(
        out.exit_code,
        0,
        "python should exit 0; console:\n{}",
        vm.console()
    );
    // Exactly the one requested artifact comes back, holding what the script computed.
    assert_eq!(out.files.len(), 1, "one artifact requested and returned");
    let (path, data) = &out.files[0];
    assert_eq!(path, "result.json");
    let text = String::from_utf8_lossy(data);
    assert!(
        text.contains("\"answer\"") && text.contains("42"),
        "captured file should hold the JSON the script wrote; got {text:?}"
    );
    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn runs_node_a_second_interpreter() {
    // P3.9 runtime-agnostic proof, second half: a *different* interpreter (Node) runs unchanged
    // through the same exec path as Python — the rootfs isn't Python-specific. Inject a small `.js`,
    // run the real `node` on it, and capture the file it writes (the per-file channel path, P2.5).
    let vm = Vm::boot(agent_rootfs_config())
        .expect("agent microVM should boot and the agent should announce readiness");

    // A real Node script: use the runtime's own APIs (JSON + fs) to write a file.
    let script = "const fs = require('fs');\n\
                  fs.writeFileSync('result.json', JSON.stringify({ answer: 6 * 7 }));\n";

    let out = vm
        .exec_with_files(
            &["node".into(), "script.js".into()],
            b"",
            &[("script.js".into(), script.as_bytes().to_vec())],
            &["result.json".into()],
        )
        .expect("run the node script and capture its output file");

    assert_eq!(
        out.exit_code,
        0,
        "node should exit 0; console:\n{}",
        vm.console()
    );
    assert_eq!(out.files.len(), 1, "one artifact requested and returned");
    let (path, data) = &out.files[0];
    assert_eq!(path, "result.json");
    let text = String::from_utf8_lossy(data);
    assert!(
        text.contains("\"answer\"") && text.contains("42"),
        "captured file should hold the JSON Node wrote; got {text:?}"
    );
    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs + the static example (run via `cargo xtask ci-privileged`)"]
fn runs_a_static_native_binary_and_captures_its_artifact() {
    // P3.9 runtime-agnostic proof: a **static native ELF** (no interpreter, no libc, no loader) runs
    // unchanged through the same exec path. Inject the binary read-only via a block device (P3.4),
    // exec it, and capture the file it writes via the output device (P3.5) — showing the engine runs
    // *any* Linux binary handed in at runtime, not just the baked-in interpreters. (Contrast the
    // Wasmtime sibling, which needs code recompiled to wasm32.)
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let bin = root.join("target/x86_64-unknown-linux-musl/release/examples/writefile");
    assert!(
        bin.is_file(),
        "missing static example at {} — run `cargo xtask build-guest-example` (ci-privileged does)",
        bin.display()
    );

    let indir = TmpDir::new("p39in");
    let outdir = TmpDir::new("p39out");
    std::fs::create_dir_all(indir.path()).expect("input dir");
    // `fs::copy` preserves the 0755 mode, which `mke2fs -d` carries into the read-only `/input` image,
    // so the guest can exec it directly (the mount is `-o ro`, not `noexec`).
    std::fs::copy(&bin, indir.path().join("writefile")).expect("stage the native binary");

    let mut cfg = agent_rootfs_config();
    cfg.input_dir = Some(indir.path().to_path_buf());
    cfg.output_dir = Some(outdir.path().to_path_buf());
    let vm = Vm::boot(cfg).expect("microVM with input + output devices should boot");
    let out = vm
        .exec(
            &["/input/writefile".into(), "/output/answer.txt".into()],
            b"",
        )
        .expect("run the injected native binary");
    assert_eq!(
        out.exit_code,
        0,
        "native binary should exit 0; console:\n{}",
        vm.console()
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("writefile ok"),
        "native binary should print its marker; got {:?}",
        String::from_utf8_lossy(&out.stdout)
    );

    // Consumes the VM: stop it, then read the output device back.
    let captured = vm.collect_outputs().expect("pull /output back");
    assert!(
        captured.iter().any(|p| p == "answer.txt"),
        "the native binary's artifact should be captured; got {captured:?}"
    );
    let text = std::fs::read_to_string(outdir.path().join("answer.txt")).expect("read answer.txt");
    assert!(
        text.contains("6*7=42"),
        "captured file should hold the native binary's payload; got {text:?}"
    );
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn injects_a_large_file_via_block_device() {
    // P3.4: a whole-working-dir / large-file input path the vsock channel can't carry. Stage a file
    // **larger than the 1 MiB channel frame cap** (the whole point) in a host dir, inject it as a
    // read-only block device, and prove the guest reads it back byte-for-byte from `/input`.
    let dir = std::env::temp_dir().join(format!("agent-p34-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("input dir");
    let payload: Vec<u8> = (0..4 * 1024 * 1024).map(|i| (i % 251) as u8).collect(); // 4 MiB, > 1 MiB
    std::fs::write(dir.join("big.bin"), &payload).expect("write input file");

    let mut cfg = agent_rootfs_config();
    cfg.input_dir = Some(dir.clone());
    let vm = Vm::boot(cfg).expect("microVM with an input block device should boot");
    let out = vm
        .exec(
            &[
                "sh".into(),
                "-c".into(),
                "wc -c < /input/big.bin && sha256sum /input/big.bin".into(),
            ],
            b"",
        )
        .expect("read the injected file from /input");
    let _ = std::fs::remove_dir_all(&dir);

    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("4194304"),
        "guest should see the 4 MiB file; got:\n{text}\nconsole:\n{}",
        vm.console()
    );
    // Content integrity end to end: the sha256 the guest computed must match the host bytes.
    let mut hasher_input = std::process::Command::new("sha256sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn sha256sum");
    use std::io::Write as _;
    hasher_input
        .stdin
        .take()
        .expect("stdin")
        .write_all(&payload)
        .expect("feed payload");
    let host_hash = hasher_input.wait_with_output().expect("host sha256");
    let host_hex = String::from_utf8_lossy(&host_hash.stdout);
    let host_hex = host_hex.split_whitespace().next().expect("host hash hex");
    assert!(
        text.contains(host_hex),
        "guest sha256 must match host {host_hex}; guest output:\n{text}"
    );
    assert_eq!(out.exit_code, 0);
    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn collects_outputs_via_block_device() {
    // P3.5: the whole-working-dir / large-file *output* path the vsock channel can't carry — the
    // counterpart to `injects_a_large_file_via_block_device`. Boot with a writable output device, have
    // the guest write a file **larger than the 1 MiB channel frame cap**, a nested file, and a
    // host-escaping symlink into `/output`; pull the tree back and prove it arrived byte-for-byte —
    // and that the escaping symlink was dropped, not recreated live on the host.
    let dir = TmpDir::new("p35");

    let mut cfg = agent_rootfs_config();
    cfg.output_dir = Some(dir.path().to_path_buf());
    let vm = Vm::boot(cfg).expect("microVM with an output block device should boot");
    let out = vm
        .exec(
            &[
                "sh".into(),
                "-c".into(),
                "mkdir -p /output/sub \
                 && head -c 4194304 /dev/urandom > /output/big.bin \
                 && printf nested > /output/sub/y \
                 && ln -s /etc/passwd /output/escape \
                 && sha256sum /output/big.bin"
                    .into(),
            ],
            b"",
        )
        .expect("write outputs in the guest");
    assert_eq!(
        out.exit_code,
        0,
        "guest write failed; console:\n{}",
        vm.console()
    );
    let guest_hash = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .expect("guest sha256 hex")
        .to_string();

    // Consumes the VM: stops it, then reads the image back.
    let captured = vm.collect_outputs().expect("pull the output tree back");

    // The large file and the nested file arrived; the escaping symlink is absent from the manifest.
    assert!(
        captured.iter().any(|p| p == "big.bin"),
        "big.bin missing from {captured:?}"
    );
    assert!(
        captured.iter().any(|p| p == "sub/y"),
        "sub/y missing from {captured:?}"
    );
    assert!(
        !captured.iter().any(|p| p == "escape"),
        "escaping symlink should be dropped: {captured:?}"
    );

    // Byte-for-byte integrity of a > 1 MiB file the channel frame can't carry in one piece.
    let big = std::fs::read(dir.path().join("big.bin")).expect("read big.bin back");
    assert_eq!(big.len(), 4 * 1024 * 1024, "big.bin should be 4 MiB");
    assert_eq!(
        sha256_hex(&big),
        guest_hash,
        "host readback must match the guest's sha256"
    );

    let nested = std::fs::read(dir.path().join("sub/y")).expect("read sub/y");
    assert_eq!(nested, b"nested");

    // Security (S1): the `escape -> /etc/passwd` symlink must not exist as a live host symlink, and
    // the ext4 `lost+found` housekeeping dir must be pruned.
    assert!(
        std::fs::symlink_metadata(dir.path().join("escape")).is_err(),
        "host-escaping symlink must be removed, not recreated on the host"
    );
    assert!(
        std::fs::symlink_metadata(dir.path().join("lost+found")).is_err(),
        "lost+found must be pruned"
    );
}

#[test]
#[ignore = "needs /dev/kvm + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn overlay_is_writable_and_base_is_untouched() {
    // P3.3 acceptance: the read-only base is shared (no copy), a per-run tmpfs overlay makes `/`
    // writable in-guest, and the base file on the host is never mutated.
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/rootfs-agent.ext4");
    let before = std::fs::metadata(&base).expect("stat base");
    let (before_len, before_mtime) = (before.len(), before.modified().expect("base mtime"));

    // Boot twice: writing to `/etc` (a path that lives on the read-only base) succeeds only because
    // the overlay redirects the write to the tmpfs upper. A fresh tmpfs per boot, so each is clean.
    for i in 0..2 {
        let vm = Vm::boot(agent_rootfs_config())
            .unwrap_or_else(|e| panic!("overlay microVM boot {i} failed: {e}"));
        let out = vm
            .exec(
                &[
                    "sh".into(),
                    "-c".into(),
                    "echo overlaid > /etc/p3_3 && cat /etc/p3_3".into(),
                ],
                b"",
            )
            .expect("write+read a normally-read-only path via the overlay");
        assert_eq!(
            out.stdout,
            b"overlaid\n",
            "overlay `/etc` should be writable; console:\n{}",
            vm.console()
        );
        assert_eq!(out.exit_code, 0);
        vm.shutdown().expect("shutdown should succeed");
    }

    // The read-only block device makes this a guarantee, not a hope: the guest opened the base
    // `O_RDONLY`, so it cannot have changed size or been rewritten.
    let after = std::fs::metadata(&base).expect("stat base again");
    assert_eq!(after.len(), before_len, "base image size must not change");
    assert_eq!(
        after.modified().expect("base mtime after"),
        before_mtime,
        "base image must not be rewritten"
    );
}

#[test]
#[ignore = "needs /dev/kvm + CAP_NET_ADMIN + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn attaches_a_tap_and_the_guest_sees_a_deny_by_default_nic() {
    // P4.1: with `enable_network`, the driver creates a host tap and attaches it as virtio-net, so
    // the guest gets an `eth0` carrying the driver's locally-administered MAC. This test pins the NIC
    // + MAC and the deny-by-default invariant (no default route); guest addressing itself is P4.2's
    // `addresses_the_guest_and_routes_host_to_guest`. Needs CAP_NET_ADMIN.
    if !have_net_admin() {
        eprintln!("skipping: creating a tap needs CAP_NET_ADMIN");
        return;
    }
    let mut cfg = agent_rootfs_config();
    cfg.enable_network = true;
    let vm = Vm::boot(cfg).expect("agent microVM with a NIC should boot to readiness");

    // The driver exposes the tap name as the eBPF-binding handle (P4.6): it must be a real,
    // `fc`-prefixed host interface the Phase-8 loader can resolve and attach `tc`/XDP to.
    let tap = vm
        .tap_name()
        .expect("a networked VM should expose its tap name");
    assert!(
        tap.starts_with("fc"),
        "tap name should be fc-prefixed; got {tap:?}"
    );
    let present = std::process::Command::new("ip")
        .args(["link", "show", "dev", tap])
        .output()
        .expect("run ip link show");
    assert!(
        present.status.success(),
        "the exposed tap name {tap} should be a live host interface"
    );

    // The NIC is present with our LAA MAC (first octet 0x02 = locally administered + unicast); the
    // guest kernel exposes it at `/sys/class/net/eth0/address` regardless of link state.
    let mac = vm
        .exec(&["cat".into(), "/sys/class/net/eth0/address".into()], b"")
        .expect("read the guest NIC address");
    assert_eq!(
        mac.exit_code,
        0,
        "eth0 should exist; console:\n{}",
        vm.console()
    );
    assert!(
        String::from_utf8_lossy(&mac.stdout)
            .trim()
            .starts_with("02:"),
        "guest eth0 should carry the driver's locally-administered MAC; got {:?}",
        String::from_utf8_lossy(&mac.stdout)
    );

    // Deny-by-default: the guest has no default route (P4.2 adds a connected /30, never a route to
    // the world) — `ip route` lists no `default`.
    let routes = vm
        .exec(&["ip".into(), "route".into()], b"")
        .expect("list guest routes");
    assert!(
        !String::from_utf8_lossy(&routes.stdout).contains("default"),
        "deny-by-default: guest must have no default route; got {:?}",
        String::from_utf8_lossy(&routes.stdout)
    );

    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + CAP_NET_ADMIN + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn addresses_the_guest_and_routes_host_to_guest() {
    // P4.2: static addressing over the tap. The kernel configures `eth0` with the guest's /30 IP via
    // the `ip=` boot param, giving a connected route to the host end and NO default route — so
    // host<->guest works but the guest reaches nothing else (deny-by-default). Needs CAP_NET_ADMIN.
    if !have_net_admin() {
        eprintln!("skipping: creating a tap needs CAP_NET_ADMIN");
        return;
    }
    let mut cfg = agent_rootfs_config();
    cfg.enable_network = true;
    let vm = Vm::boot(cfg).expect("agent microVM with a NIC should boot to readiness");
    let host_ip = vm.host_ip().expect("host ip when networked").to_string();
    let guest_ip = vm.guest_ip().expect("guest ip when networked").to_string();

    // The guest kernel configured eth0 with its assigned address.
    let addr = vm
        .exec(
            &[
                "ip".into(),
                "-4".into(),
                "addr".into(),
                "show".into(),
                "eth0".into(),
            ],
            b"",
        )
        .expect("show guest eth0");
    assert!(
        String::from_utf8_lossy(&addr.stdout).contains(&guest_ip),
        "guest eth0 should carry {guest_ip}; got:\n{}\nconsole:\n{}",
        String::from_utf8_lossy(&addr.stdout),
        vm.console()
    );

    // Host<->guest reachability: the guest can reach the host end of the point-to-point /30.
    let ping = vm
        .exec(
            &[
                "ping".into(),
                "-c".into(),
                "1".into(),
                "-W".into(),
                "1".into(),
                host_ip.clone(),
            ],
            b"",
        )
        .expect("ping the host tap IP");
    assert_eq!(
        ping.exit_code,
        0,
        "guest should reach the host tap IP {host_ip}; console:\n{}",
        vm.console()
    );

    // Deny-by-default: an off-subnet address is unreachable (a fast ENETUNREACH, no route — not a
    // timeout), proving there's no default route or masquerade opening the guest to the world.
    let off = vm
        .exec(
            &[
                "ping".into(),
                "-c".into(),
                "1".into(),
                "-W".into(),
                "1".into(),
                "192.0.2.1".into(), // RFC 5737 TEST-NET-1, provably off the /30
            ],
            b"",
        )
        .expect("ping an off-subnet address");
    assert_ne!(
        off.exit_code, 0,
        "deny-by-default: the guest must not reach an off-subnet address"
    );

    vm.shutdown().expect("shutdown should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + CAP_NET_ADMIN + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn two_vms_cannot_reach_each_others_tap() {
    // P4.4: per-VM isolation. Two concurrently-booted networked VMs get distinct /30s — the driver
    // makes each host-address assignment the /30's atomic reservation, so a folded-index collision
    // retries instead of sharing a subnet — and with no default route a guest can only address its
    // own connected /30. So VM-A cannot even reach VM-B's tap. Needs CAP_NET_ADMIN.
    if !have_net_admin() {
        eprintln!("skipping: creating a tap needs CAP_NET_ADMIN");
        return;
    }
    let mut cfg_a = agent_rootfs_config();
    cfg_a.enable_network = true;
    let vm_a = Vm::boot(cfg_a).expect("VM A with a NIC should boot to readiness");
    let mut cfg_b = agent_rootfs_config();
    cfg_b.enable_network = true;
    let vm_b = Vm::boot(cfg_b).expect("VM B with a NIC should boot to readiness");

    let a_host = vm_a.host_ip().expect("A host ip when networked");
    let a_guest = vm_a.guest_ip().expect("A guest ip when networked");
    let b_host = vm_b.host_ip().expect("B host ip when networked");
    let b_guest = vm_b.guest_ip().expect("B guest ip when networked");

    // The allocator handed the two VMs disjoint /30s: no shared subnet to bridge them.
    assert_ne!(
        a_host, b_host,
        "the two VMs must get distinct host /30 ends"
    );
    assert_ne!(
        a_guest, b_guest,
        "the two VMs must get distinct guest addresses"
    );

    // From A, B's addresses are off A's only (connected) route: a fast ENETUNREACH, not a timeout —
    // the same deny-by-default lever that blocks the world also isolates one VM from another.
    for target in [b_host.to_string(), b_guest.to_string()] {
        let out = vm_a
            .exec(
                &[
                    "ping".into(),
                    "-c".into(),
                    "1".into(),
                    "-W".into(),
                    "1".into(),
                    target.clone(),
                ],
                b"",
            )
            .expect("ping VM B from VM A");
        assert_ne!(
            out.exit_code,
            0,
            "VM A must not reach VM B's address {target}; console:\n{}",
            vm_a.console()
        );
    }

    vm_a.shutdown().expect("shutdown A should succeed");
    vm_b.shutdown().expect("shutdown B should succeed");
}

#[test]
#[ignore = "needs /dev/kvm + CAP_NET_ADMIN + the agent rootfs (run via `cargo xtask ci-privileged`)"]
fn guest_reaches_an_allowed_host_endpoint_but_not_a_blocked_one() {
    // P4.7: prove the allow/deny posture at the transport layer, not just ICMP. Per decision 008,
    // "allowed" in Phase 4 is host-local (world-egress allow-listing is eBPF-enforced in P8): the
    // guest completes a real TCP connection to a listener bound on the host tap IP, and cannot reach
    // an off-subnet endpoint (no route, fast failure). Needs CAP_NET_ADMIN.
    if !have_net_admin() {
        eprintln!("skipping: creating a tap needs CAP_NET_ADMIN");
        return;
    }
    let mut cfg = agent_rootfs_config();
    cfg.enable_network = true;
    let vm = Vm::boot(cfg).expect("agent microVM with a NIC should boot to readiness");
    let host_ip = vm.host_ip().expect("host ip when networked");

    // A genuine host-side endpoint on the tap's host address. `bind` already starts listening, and the
    // kernel queues the connection in the backlog, so the guest's connect completes even before the
    // acceptor thread runs — no bind/connect race. Port 0 picks a free ephemeral port.
    let listener =
        std::net::TcpListener::bind((host_ip, 0)).expect("bind a host endpoint on the tap IP");
    let port = listener.local_addr().expect("listener local addr").port();
    let acceptor = std::thread::spawn(move || {
        // One accepted connection is enough to prove reachability; drop it and finish.
        let _ = listener.accept();
    });

    // Allowed: the guest's TCP connect to the host endpoint succeeds (python3 exits 0; an unreachable
    // peer would raise and exit non-zero). python3 is in the agent rootfs (see execs_python_*).
    let allowed = vm
        .exec(
            &[
                "python3".into(),
                "-c".into(),
                format!(
                    "import socket; s=socket.socket(); s.settimeout(3); s.connect(('{host_ip}',{port}))"
                ),
            ],
            b"",
        )
        .expect("guest connects to the allowed host endpoint");
    assert_eq!(
        allowed.exit_code,
        0,
        "guest should reach the allowed host endpoint {host_ip}:{port}; console:\n{}",
        vm.console()
    );

    // Blocked: an off-subnet endpoint has no route, so connect fails (raises, exits non-zero). RFC 5737
    // TEST-NET-1 is provably off the /30. The same port keeps the two probes symmetric.
    let blocked = vm
        .exec(
            &[
                "python3".into(),
                "-c".into(),
                format!(
                    "import socket; s=socket.socket(); s.settimeout(3); s.connect(('192.0.2.1',{port}))"
                ),
            ],
            b"",
        )
        .expect("guest attempts a blocked endpoint");
    assert_ne!(
        blocked.exit_code, 0,
        "deny-by-default: the guest must not reach an off-subnet endpoint"
    );

    vm.shutdown().expect("shutdown should succeed");
    let _ = acceptor.join();
}

/// Whether this process holds `CAP_NET_ADMIN` (effective) — needed to create a tap. Creating a tap
/// is privileged (unlike the rootless block-device builds), so the NIC tests skip without it rather
/// than fail on a box that can do KVM but not net-admin. `CAP_NET_ADMIN` is bit 12 of `CapEff`.
fn have_net_admin() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("CapEff:").map(|v| v.trim().to_string()))
        })
        .and_then(|hex| u64::from_str_radix(&hex, 16).ok())
        .is_some_and(|caps| caps & (1 << 12) != 0)
}

/// Host tap interfaces currently present (`fc*`), for the leak assertion below.
fn fc_interfaces() -> std::collections::BTreeSet<String> {
    std::fs::read_dir("/sys/class/net")
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with("fc"))
                .collect()
        })
        .unwrap_or_default()
}

/// Whether `pid` is still a live `firecracker` process. A reaped child leaves `/proc` entirely, so a
/// `firecracker` still present at a VMM pid we booted means teardown failed to kill+reap it. Keyed on
/// the *specific* pid (via `comm`), not a scan, so it can't be confused by other parallel tests' VMMs
/// (they have different pids); a reaped-then-recycled pid running something else reads as gone.
fn is_firecracker(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|c| c.trim() == "firecracker")
        .unwrap_or(false)
}

#[test]
#[ignore = "needs /dev/kvm + CAP_NET_ADMIN + artifacts (run via `cargo xtask ci-privileged`)"]
fn repeated_boots_leave_no_leaks() {
    // After two boot/teardown cycles, nothing this test spawned may survive: no per-VM scratch dir,
    // no orphaned firecracker VMM process, and (with CAP_NET_ADMIN) no per-VM tap. The tap is the
    // one resource outside the scratch dir, so it's reclaimed separately from `remove_dir_all`;
    // without the capability, networking is off and this still covers the scratch-dir + process paths.
    let net = have_net_admin();
    let taps_before = fc_interfaces();
    let mut vmm_pids = Vec::new();

    // Two full cycles back to back; the second only works if the first was fully reclaimed.
    for i in 0..2 {
        let mut cfg = config();
        cfg.enable_network = net;
        let vm = Vm::boot(cfg).unwrap_or_else(|e| panic!("boot {i} failed: {e}"));
        vmm_pids.push(vm.vmm_pid());
        // `shutdown` consumes the VM, so its `Drop` (kill + reap + reclaim) has run by the time it
        // returns — the leak checks below therefore observe the fully-torn-down state.
        vm.shutdown()
            .unwrap_or_else(|e| panic!("shutdown {i} failed: {e}"));
    }

    // This process's per-VM scratch dirs (`/tmp/agent-<pid>-<n>`) must all be gone.
    let prefix = format!("agent-{}-", std::process::id());
    let leftovers = std::fs::read_dir("/tmp")
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
                .count()
        })
        .unwrap_or(0);
    assert_eq!(leftovers, 0, "per-VM scratch dirs should be cleaned up");

    // Every firecracker VMM we booted must have been killed and reaped — no orphaned process.
    let orphans: Vec<_> = vmm_pids
        .iter()
        .copied()
        .filter(|&p| is_firecracker(p))
        .collect();
    assert!(orphans.is_empty(), "orphaned firecracker VMMs: {orphans:?}");

    // No tap interface survived the cycles either (only asserted when networking was enabled).
    if net {
        let leaked: Vec<_> = fc_interfaces().difference(&taps_before).cloned().collect();
        assert!(leaked.is_empty(), "leaked tap interfaces: {leaked:?}");
    }
}
