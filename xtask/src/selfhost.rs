//! `cargo xtask self-host`, the one command a self-hoster runs to stand the engine up end to end:
//! obtain the pinned guest kernel + rootfs, build the guest image and the eBPF probe object, install
//! the `agent` binary, and (on a KVM host) boot one sandbox to prove it works.
//!
//! Every step reuses the same tested building blocks the individual `xtask` commands do, so this is
//! orchestration, not a second code path. **Vendor-aware:** with `AGENT_VENDOR_DIR` set, the fetch +
//! rootfs steps resolve from the local mirror (`cargo xtask vendor`), so the whole build runs offline,
//! no Firecracker S3 bucket, no Alpine CDN.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::{
    agent_rootfs_path, build_probes, cargo, kernel_path, run_tool_env, vendor_dir, workspace_root,
};

/// The binaries a self-host installs: the CLI and the driver daemon, both from the `agent-cli` crate.
const BINARIES: &[&str] = &["agent"];

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
    // Only the guest kernel is needed to boot the agent rootfs; the Ubuntu boot rootfs is the CI
    // login test's artifact, not this, so don't drag it (and its size) into a self-host.
    let kernel = kernel_path();
    let fetched = crate::artifacts::artifacts()?
        .into_iter()
        .find(|a| a.dest == kernel)
        .context("no pinned guest kernel for this architecture")?;
    crate::artifacts::fetch_one(&fetched)?;

    println!("\n== 2/5  build the guest rootfs (agent baked in) ==");
    crate::rootfs::build_rootfs(false, false)?;

    println!("\n== 3/5  build the eBPF probe object (the audit half) ==");
    build_probes()?;

    println!("\n== 4/5  build + install the agent binary ==");
    cargo(&["build", "--release", "--locked", "-p", "agent-cli"])?;
    let prefix = resolve_prefix(prefix)?;
    let agent = install_binaries(&prefix)?;

    println!("\n== 5/5  run a sandbox ==");
    prove(&agent, no_run)?;

    println!(
        "\n✓ self-host complete. Binary in {}; start the daemon with `agent serve` (see \
         `agent serve --help`).",
        prefix.display()
    );
    Ok(())
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

/// Copy each built release binary into `prefix` (executable), returning the installed `agent` path
/// for the boot proof. A missing build output is a clear error (the `cargo build` above should have
/// produced it), not a silent skip.
fn install_binaries(prefix: &Path) -> Result<PathBuf> {
    let release = workspace_root().join("target/release");
    let mut agent = None;
    for name in BINARIES {
        let src = release.join(name);
        if !src.is_file() {
            bail!(
                "built binary {} not found — did `cargo build --release -p agent-cli` succeed?",
                src.display()
            );
        }
        let dest = prefix.join(name);
        std::fs::copy(&src, &dest)
            .with_context(|| format!("install {} -> {}", src.display(), dest.display()))?;
        set_executable(&dest)?;
        println!("  installed {} -> {}", name, dest.display());
        if *name == "agent" {
            agent = Some(dest);
        }
    }
    agent.context("the `agent` binary was not among the installed set")
}

/// Boot one sandbox with the just-installed `agent` to prove the whole stack runs, or, when there's
/// no KVM (or `--no-run`), print the exact command so the proof is one copy-paste away. Runs
/// `--unjailed` (the jailed default needs real root); production self-hosts run jailed, behind the
/// same KVM boundary.
fn prove(agent: &Path, no_run: bool) -> Result<()> {
    let kernel = kernel_path();
    let rootfs = agent_rootfs_path();
    let env = [
        ("AGENT_KERNEL", kernel.to_string_lossy().into_owned()),
        ("AGENT_ROOTFS", rootfs.to_string_lossy().into_owned()),
    ];
    let hint = format!(
        "AGENT_KERNEL={} AGENT_ROOTFS={} {} run --unjailed -- echo self-host-ok",
        kernel.display(),
        rootfs.display(),
        agent.display()
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
        &agent.to_string_lossy(),
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
