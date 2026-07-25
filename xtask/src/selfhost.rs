//! `cargo xtask self-host`, the one command a self-hoster runs to stand the engine up end to end:
//! obtain the pinned guest kernel + rootfs, build the guest image and the eBPF probe object, install
//! the `ebpf-kvm-engine` binary, and (on a KVM host) boot one sandbox to prove it works.
//!
//! Every step reuses the same tested building blocks the individual `xtask` commands do, so this is
//! orchestration, not a second code path. **Vendor-aware:** with `EBPF_KVM_ENGINE_VENDOR_DIR` set, the fetch +
//! rootfs steps resolve from the local mirror (`cargo xtask vendor`), so the whole build runs offline,
//! no Firecracker S3 bucket, no Alpine CDN.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::{
    build_probes, cargo, guest_rootfs_path, kernel_path, run_tool_env, vendor_dir, workspace_root,
};

/// The binaries a self-host installs: the CLI and the driver daemon, both from the `cli` crate.
const BINARIES: &[&str] = &["ebpf-kvm-engine"];

/// `cargo xtask self-host [--prefix DIR] [--no-run]`: build the artifacts + binaries and prove one
/// sandbox boots. `--prefix` is the install dir (default `~/.local/bin`); `--no-run` skips the boot
/// proof (build + install only).
pub(crate) fn self_host(prefix: Option<PathBuf>, no_run: bool) -> Result<()> {
    let offline = vendor_dir().is_some();
    println!(
        "self-host: {} build\n",
        if offline {
            "offline (from the vendored mirror)"
        } else {
            "online (from pinned upstream)"
        }
    );

    println!("== 1/5  obtain the pinned guest kernel ==");
    // Only the guest kernel is needed to boot the ebpf-kvm-engine rootfs; the Ubuntu boot rootfs is the CI
    // login test's artifact, not this, so don't drag it (and its size) into a self-host.
    let kernel = kernel_path();
    let fetched = crate::artifacts::artifacts()?
        .into_iter()
        .find(|a| a.dest == kernel)
        .context("no pinned guest kernel for this architecture")?;
    crate::artifacts::fetch_one(&fetched)?;

    println!("\n== 2/5  build the guest rootfs (ebpf-kvm-engine baked in) ==");
    crate::rootfs::build_rootfs(false, false)?;

    println!("\n== 3/5  build the eBPF probe object (the audit half) ==");
    build_probes()?;

    println!("\n== 4/5  build + install the ebpf-kvm-engine binary ==");
    cargo(&["build", "--release", "--locked", "-p", "cli"])?;
    let prefix = resolve_prefix(prefix)?;
    let engine_bin = install_binaries(&prefix)?;

    write_starter_config()?;

    println!("\n== 5/5  run a sandbox ==");
    prove(&engine_bin, no_run)?;

    println!(
        "\n✓ self-host complete. Binary in {}; start the daemon with `ebpf-kvm-engine serve` (see \
         `ebpf-kvm-engine serve --help`).",
        prefix.display()
    );
    Ok(())
}

/// Write `~/.ebpf-kvm-engine.toml` with **absolute** artifact paths, matching what `install.sh` does for a
/// packaged install.
///
/// Without it a self-hosted binary only works from inside the source tree: the artifact defaults are
/// resolved relative to the working directory, so the same binary reports "Ready" in the repo and
/// fails with a missing kernel/rootfs one directory up. Config discovery walks up from the cwd, so
/// this file covers any cwd **under `$HOME`**, not literally everywhere; from outside `$HOME` (say
/// `/tmp`) pass the paths by env or flag. Never overwrites an existing file (your config is yours),
/// and `EBPF_KVM_ENGINE_NO_TOML=1` skips it, the same escape hatch `install.sh` offers.
///
/// On a host whose default scratch base (`/tmp`) is mounted `nodev` (every systemd default: Arch,
/// Ubuntu), the jailer's chroot `/dev/kvm` there is inert and the jailed default fails
/// `ScratchDirNodev`; so when the detector flags it, a `scratch_dir` on a non-`nodev` path is written
/// too, so the first `sudo ebpf-kvm-engine run` works rather than needing a hand-edit (P20.16a).
fn write_starter_config() -> Result<()> {
    if std::env::var_os("EBPF_KVM_ENGINE_NO_TOML").is_some() {
        return Ok(());
    }
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        println!("  (HOME unset: skipping the starter .ebpf-kvm-engine.toml)");
        return Ok(());
    };
    let dest = home.join(".ebpf-kvm-engine.toml");
    if dest.exists() {
        println!("  {} exists, left alone", dest.display());
        return Ok(());
    }
    let mut body = format!(
        "# Written by `cargo xtask self-host`; the engine reads the nearest .ebpf-kvm-engine.toml walking up\n\
         # from the cwd, so this covers any working directory under $HOME. Absolute paths, so the\n\
         # installed binary no longer depends on being run from the source tree.\n\
         kernel = \"{}\"\n\
         rootfs = \"{}\"\n",
        kernel_path().display(),
        guest_rootfs_path().display()
    );
    let scratch = starter_scratch_dir(&home);
    let mut wrote_scratch = false;
    if let Some(scratch) = &scratch {
        std::fs::create_dir_all(scratch)
            .with_context(|| format!("create scratch dir {}", scratch.display()))?;
        body.push_str(&format!(
            "# /tmp is mounted `nodev` on this host, so the jailer's chroot /dev/kvm there is inert; a\n\
             # non-nodev scratch dir so the jailed default boots (the check in crates/vmm/src/doctor.rs).\n\
             scratch_dir = \"{}\"\n",
            scratch.display()
        ));
        wrote_scratch = true;
    }
    std::fs::write(&dest, body).with_context(|| format!("write {}", dest.display()))?;
    if wrote_scratch {
        println!(
            "  wrote {} (kernel + rootfs paths, and scratch_dir: /tmp is nodev here)",
            dest.display()
        );
    } else {
        println!("  wrote {} (kernel + rootfs paths)", dest.display());
    }
    Ok(())
}

/// The non-`nodev` scratch dir to pin for a jailed boot, or `None` when the default `/tmp` base is
/// already fine (or no better home exists). `$XDG_DATA_HOME/ebpf-kvm-engine/scratch` (default
/// `~/.local/share/...`), the same per-user data root `install.sh` uses; skipped when that path is
/// *also* `nodev`, since pinning one nodev dir over another fixes nothing (`doctor` still flags it).
fn starter_scratch_dir(home: &Path) -> Option<PathBuf> {
    if !vmm::doctor::scratch_is_nodev(Path::new("/tmp")).unwrap_or(false) {
        return None;
    }
    let scratch = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".local/share"))
        .join("ebpf-kvm-engine/scratch");
    if vmm::doctor::scratch_is_nodev(&scratch).unwrap_or(false) {
        println!(
            "  note: /tmp is nodev and so is {}; set EBPF_KVM_ENGINE_SCRATCH_DIR to a non-nodev path",
            scratch.display()
        );
        return None;
    }
    Some(scratch)
}

/// The install directory: `--prefix` if given, else `~/.local/bin`. Created if absent.
fn resolve_prefix(prefix: Option<PathBuf>) -> Result<PathBuf> {
    let prefix = match prefix {
        Some(p) => p,
        None => {
            let home = std::env::var_os("HOME")
                .context("HOME is unset — pass an install dir with `--prefix DIR`")?;
            PathBuf::from(home).join(".local/bin")
        }
    };
    std::fs::create_dir_all(&prefix)
        .with_context(|| format!("create install dir {}", prefix.display()))?;
    Ok(prefix)
}

/// Copy each built release binary into `prefix` (executable), returning the installed `ebpf-kvm-engine` path
/// for the boot proof. A missing build output is a clear error (the `cargo build` above should have
/// produced it), not a silent skip.
fn install_binaries(prefix: &Path) -> Result<PathBuf> {
    // Honour `CARGO_TARGET_DIR` (as `dist` does): the build above respects it, so resolving the
    // output against `./target` unconditionally would install whatever stale binary happened to sit
    // there from an earlier default-target-dir build, silently, with a fresh build's log above it.
    let release = std::env::var_os("CARGO_TARGET_DIR")
        .map_or_else(|| workspace_root().join("target"), PathBuf::from)
        .join("release");
    let mut engine_bin = None;
    for name in BINARIES {
        let src = release.join(name);
        if !src.is_file() {
            bail!(
                "built binary {} not found — did `cargo build --release -p cli` succeed?",
                src.display()
            );
        }
        let dest = prefix.join(name);
        std::fs::copy(&src, &dest)
            .with_context(|| format!("install {} -> {}", src.display(), dest.display()))?;
        set_executable(&dest)?;
        println!("  installed {} -> {}", name, dest.display());
        if *name == "ebpf-kvm-engine" {
            engine_bin = Some(dest);
        }
    }
    engine_bin.context("the `ebpf-kvm-engine` binary was not among the installed set")
}

/// Boot one sandbox with the just-installed `ebpf-kvm-engine` to prove the whole stack runs, or, when there's
/// no KVM (or `--no-run`), print the exact command so the proof is one copy-paste away. Runs
/// `--unjailed` (the jailed default needs real root); production self-hosts run jailed, behind the
/// same KVM boundary.
fn prove(engine_bin: &Path, no_run: bool) -> Result<()> {
    let kernel = kernel_path();
    let rootfs = guest_rootfs_path();
    let env = [
        (
            "EBPF_KVM_ENGINE_KERNEL",
            kernel.to_string_lossy().into_owned(),
        ),
        (
            "EBPF_KVM_ENGINE_ROOTFS",
            rootfs.to_string_lossy().into_owned(),
        ),
    ];
    let hint = format!(
        "EBPF_KVM_ENGINE_KERNEL={} EBPF_KVM_ENGINE_ROOTFS={} {} run --unjailed -- echo self-host-ok",
        kernel.display(),
        rootfs.display(),
        engine_bin.display()
    );

    if no_run {
        println!("  (--no-run) build + install only; prove it with:\n    {hint}");
        return Ok(());
    }
    if !Path::new("/dev/kvm").exists() {
        println!("  no /dev/kvm on this host — run the proof on a KVM box with:\n    {hint}");
        return Ok(());
    }

    let env_refs: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    run_tool_env(
        &engine_bin.to_string_lossy(),
        &[
            OsStr::new("run"),
            OsStr::new("--unjailed"),
            OsStr::new("--"),
            OsStr::new("echo"),
            OsStr::new("self-host-ok"),
        ],
        &env_refs,
    )
    .context("the self-host boot proof failed — see the error above")?;
    println!("  ✓ sandbox booted and ran a command");
    Ok(())
}

/// `chmod 0755` on an installed binary (the copy may not have preserved the mode bits).
fn set_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).with_context(|| format!("chmod +x {}", path.display()))
}
