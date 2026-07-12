//! Privileged boot integration test: boot a real Firecracker microVM to userspace and tear it
//! down, repeatably and without leaks.
//!
//! `#[ignore]`d because it needs `/dev/kvm` and the fetched artifacts. Run it with
//! `cargo xtask ci-privileged` (which guards on both) or `cargo test -p agent-vmm -- --ignored`.

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
#[ignore = "needs /dev/kvm + artifacts (run via `cargo xtask ci-privileged`)"]
fn repeated_boots_leave_no_leaks() {
    // Two full cycles back to back; the second only works if the first was fully reclaimed.
    for i in 0..2 {
        let vm = Vm::boot(config()).unwrap_or_else(|e| panic!("boot {i} failed: {e}"));
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
}
