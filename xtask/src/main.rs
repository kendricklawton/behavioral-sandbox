//! `cargo xtask <cmd>` — dev orchestration for the agent sandbox engine.
//!
//! - **`ci`** — the host-safe gate (fmt · clippy `-D warnings` · build · test · docs · `deny`).
//!   Runs everywhere, needs no KVM or root, and mirrors `.github/workflows/ci.yml`.
//! - **`ci-privileged`** — the KVM/eBPF integration tests (the `#[ignore]`d ones). Needs
//!   `/dev/kvm` and elevated caps, so it's never part of the everyday loop. Builds the guest
//!   agent + the agent rootfs first, so the in-VM exec test has something to boot.
//! - **`setup`** — checks the host can do KVM + eBPF and reports what's missing.
//! - **`build-rootfs`** — assemble the reproducible guest rootfs (Alpine base + baked-in agent).
//! - **`bench-boot`** — measure boot-to-userspace latency (percentiles) vs. the base size. Needs KVM.
//!
//! The eBPF crate (`crates/probes`) builds for `bpfel-unknown-none` and is excluded from the host
//! workspace; its object build folds into `ci` at ROADMAP Phase 8.
#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use agent_vmm::{BootConfig, Vm, DEFAULT_GUEST_CID, GUEST_READY_MARKER};
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "xtask",
    about = "dev orchestration for the agent sandbox engine"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Host-safe gate: fmt · clippy `-D warnings` · build · test · docs · cargo-deny.
    Ci,
    /// Privileged integration tests (KVM + eBPF) — the `#[ignore]`d tests. Needs `/dev/kvm` + caps.
    CiPrivileged,
    /// Check the host can do KVM + eBPF; report what's missing.
    Setup,
    /// Download + sha256-verify the pinned guest kernel and rootfs into `artifacts/` (needs `curl`).
    FetchArtifacts,
    /// Build the guest agent as a static musl binary (baked into the rootfs by `build-rootfs`).
    BuildGuestAgent,
    /// Build the P3.9 static native-ELF fixture (`examples/writefile`) for the guest target — the
    /// runtime-agnostic test injects and runs it to prove the engine executes any static Linux binary.
    BuildGuestExample,
    /// Assemble the guest rootfs: a minimal Alpine base + the guest runtimes (python3) + the static
    /// agent + a vsock init, as an ext4 image at `artifacts/rootfs-agent.ext4` (needs `curl`,
    /// `tar`, `mke2fs`, `truncate`). Reproducible: two builds are byte-identical.
    BuildRootfs {
        /// Build a second time and assert the image is byte-identical, and fail if the resolved
        /// package closure has drifted from the committed lockfile. The reproducibility gate.
        #[arg(long)]
        verify: bool,
        /// Re-record the resolved package closure into the committed lockfile — the "re-pin" step
        /// after Alpine's branch repo bumps a package out from under the floating install.
        #[arg(long)]
        update_lock: bool,
    },
    /// Measure boot-to-userspace latency (percentiles) of the agent rootfs, on both the read-only
    /// shared base and the read-write per-VM copy, so the base **size**'s effect on boot is visible
    /// (P3.7). Needs `/dev/kvm` + the built agent rootfs.
    BenchBoot {
        /// How many boots to time per path (more → tighter tail percentiles). Default 100 — the
        /// floor at which a `p99` has any sample above it; below it `p99` prints `—`.
        #[arg(long, default_value_t = 100)]
        runs: usize,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Ci => ci(),
        Cmd::CiPrivileged => ci_privileged(),
        Cmd::Setup => setup(),
        Cmd::FetchArtifacts => fetch_artifacts(),
        Cmd::BuildGuestAgent => build_guest_agent().map(|_| ()),
        Cmd::BuildGuestExample => build_guest_example().map(|_| ()),
        Cmd::BuildRootfs {
            verify,
            update_lock,
        } => build_rootfs(verify, update_lock),
        Cmd::BenchBoot { runs } => bench_boot(runs),
    }
}

/// The musl target the guest agent is built for: a fully static binary that runs in the guest with
/// no dynamic loader or libc to bake into the rootfs.
const GUEST_TARGET: &str = "x86_64-unknown-linux-musl";

/// Build the guest agent as a static binary for the guest and return its path. Kept out of the `ci`
/// gate (it needs the musl target installed and produces an artifact the host doesn't run);
/// `build-rootfs` bakes the result into the image.
fn build_guest_agent() -> Result<PathBuf> {
    build_guest_musl(GuestBin::Agent)
}

/// Build the P3.9 static native-ELF fixture (`crates/guest-agent/examples/writefile.rs`) for the
/// guest target and return its path. A statically linked musl binary with no interpreter/libc, which
/// the runtime-agnostic test injects and execs to prove the engine runs *any* Linux binary. Built
/// like the agent (musl, `--locked`) and verified static.
fn build_guest_example() -> Result<PathBuf> {
    build_guest_musl(GuestBin::Example)
}

/// A static musl guest binary `xtask` builds: the agent itself, or the P3.9 native-ELF fixture.
enum GuestBin {
    Agent,
    Example,
}

impl GuestBin {
    /// The cargo target selector, the built binary's path under `target/<triple>/release/`, and a
    /// human label — the only things that differ between the two builds.
    fn spec(&self) -> (&'static [&'static str], &'static str, &'static str) {
        match self {
            GuestBin::Agent => (
                &["--bin", "agent-guest"],
                "release/agent-guest",
                "guest agent",
            ),
            GuestBin::Example => (
                &["--example", "writefile"],
                "release/examples/writefile",
                "guest example",
            ),
        }
    }
}

/// Build a static musl guest binary (`--locked`, the guest musl target) and verify it's actually
/// statically linked before returning its path. The shared body of [`build_guest_agent`] and
/// [`build_guest_example`], which differ only in [`GuestBin::spec`].
fn build_guest_musl(kind: GuestBin) -> Result<PathBuf> {
    ensure_guest_target()?;
    let (selector, subpath, label) = kind.spec();
    let mut args = vec!["build", "--release", "--locked", "-p", "agent-guest"];
    args.extend_from_slice(selector);
    args.extend_from_slice(&["--target", GUEST_TARGET]);
    cargo(&args)?;
    let bin = workspace_root()
        .join("target")
        .join(GUEST_TARGET)
        .join(subpath);
    verify_static(&bin, label)?;
    println!("\n✓ {label} built (static): {}", bin.display());
    Ok(bin)
}

/// Fail with a clear fix if the guest musl target isn't installed — cargo would otherwise error more
/// obscurely deep in the build.
fn ensure_guest_target() -> Result<()> {
    let installed = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .context("running rustup (is it installed?)")?;
    if !String::from_utf8_lossy(&installed.stdout)
        .lines()
        .any(|t| t == GUEST_TARGET)
    {
        bail!("missing target {GUEST_TARGET} — run `rustup target add {GUEST_TARGET}` first");
    }
    Ok(())
}

/// Verify the built binary is actually statically linked — "measured, not marketed." A sys-crate or
/// `build.rs` can silently reintroduce a `NEEDED` dynamic dependency, and a dynamically-linked
/// binary baked into a scratch rootfs would fail at boot with a confusing loader error. Two checks,
/// so the guarantee matches the claim: `readelf -d` finds no `(NEEDED)` shared objects, **and**
/// `readelf -l` finds no `INTERP` program header — a fully static binary needs no runtime loader, so
/// a static-PIE (no `NEEDED` but with an interpreter) is also rejected.
fn verify_static(bin: &Path, what: &str) -> Result<()> {
    // `readelf -d` (dynamic section): a static binary lists no `(NEEDED)` shared objects.
    let Some(dynamic) = readelf(bin, "-d") else {
        // No `readelf` (binutils) on this host: don't fake a guarantee we couldn't check.
        println!("  ! could not run `readelf` to verify staticness — install binutils to check");
        return Ok(());
    };
    let needed: Vec<_> = dynamic.lines().filter(|l| l.contains("(NEEDED)")).collect();
    if !needed.is_empty() {
        bail!(
            "{what} is NOT statically linked — it needs {} shared object(s):\n{}",
            needed.len(),
            needed.join("\n")
        );
    }
    // `readelf -l` (program headers): a fully static binary carries no `INTERP` segment (loader).
    let Some(segments) = readelf(bin, "-l") else {
        println!("  ! could not run `readelf -l` to verify no interpreter — install binutils");
        return Ok(());
    };
    if segments.lines().any(|l| l.contains("INTERP")) {
        bail!("{what} carries a PT_INTERP program header — it wants a runtime loader, not static");
    }
    Ok(())
}

/// Run `readelf <flag> <bin>` and return its stdout, or `None` if `readelf` is absent/failed — the
/// caller decides whether a missing tool is a soft skip (we don't fake a guarantee we can't check).
fn readelf(bin: &Path, flag: &str) -> Option<String> {
    match Command::new("readelf").arg(flag).arg(bin).output() {
        Ok(o) if o.status.success() => Some(String::from_utf8_lossy(&o.stdout).into_owned()),
        _ => None,
    }
}

// ---- rootfs build (ROADMAP P3.1) -------------------------------------------------------------

/// A fixed rootfs UUID so repeated builds don't churn it (Firecracker roots by device, not UUID).
/// Reused as the ext4 directory-hash seed (P3.6): the seed only guards against adversarial
/// directory-hash flooding, which a trusted, pinned build-time image doesn't face — so a fixed seed
/// costs nothing and buys byte-for-byte determinism.
const ROOTFS_UUID: &str = "5b3a9c1e-0000-4000-8000-000000000001";

/// A fixed build epoch for the rootfs image (P3.6). `mke2fs` honours `SOURCE_DATE_EPOCH`: it stamps
/// the filesystem's create/write/check times with it and **clamps every `-d`-copied file mtime down
/// to it**, so repeated builds don't churn timestamps. A constant, deliberately — a `git log` or
/// wall-clock date would vary across shallow clones and over time, defeating the purpose. Together
/// with the fixed UUID + hash seed, this makes two builds byte-identical. 2024-01-01T00:00:00Z.
const ROOTFS_SOURCE_DATE_EPOCH: &str = "1704067200";

/// Image size. Headroom over the payload so `apk.static --root` has room without a re-size. Bumped
/// 128→256 at P3.9 when Node (its `icu-libs`/`simdjson`/`ada-libs` closure, ~64 MiB) joined python3.
const ROOTFS_SIZE_MIB: u32 = 256;

/// Soft ceiling on the base rootfs's real footprint (P3.7 — "keep the base small"). `build-rootfs`
/// fails past it, a regression guard against accidental bloat. The image is ~132 MiB (Alpine +
/// python3 + **Node** + the agent, P3.9); this leaves ~28 MiB headroom. Adding another runtime is a
/// deliberate bump of this *and* `ROOTFS_SIZE_MIB`, not a silent creep — and a prompt to ask whether
/// the base is still "small."
const ROOTFS_BUDGET_MIB: u64 = 160;

/// The init the image ships, replacing Alpine's OpenRC `inittab`. busybox is PID 1 (it reaps
/// orphans and a crashed child is respawned, neither of which the `forbid(unsafe_code)` agent should
/// own). `sysinit` mounts the pseudo-filesystems a fresh ext4 lacks — a rootless `mke2fs -d` seeds
/// no device nodes, so `devtmpfs` is what provides `/dev/ttyS0` + the vsock device (the guest kernel
/// must auto-mount it, `CONFIG_DEVTMPFS_MOUNT`, for PID 1's own console). The agent then respawns on
/// the contract vsock port (`agent_channel::AGENT_VSOCK_PORT` — the same constant the host dials,
/// so the two sides can't drift), attached to `ttyS0` so its readiness line reaches the serial
/// console the host scans.
fn rootfs_inittab() -> String {
    format!(
        "\
# Minimal init for the agent sandbox rootfs (replaces Alpine's OpenRC inittab).
::sysinit:/bin/mount -t devtmpfs dev /dev
::sysinit:/bin/mount -t proc proc /proc
::sysinit:/bin/mount -t sysfs sys /sys
# Bulk input/output block devices (P3.4/P3.5): mount whichever the driver attached, by label — so
# their /dev/vdX order doesn't matter. Best-effort: a missing device is skipped, so plain boots are
# unaffected. Runs after devtmpfs/proc are up (findfs needs the device nodes + /proc/partitions).
::sysinit:/sbin/mount-drives
ttyS0::respawn:/usr/local/bin/agent-guest vsock:{port}
::ctrlaltdel:/sbin/reboot
::shutdown:/bin/umount -a -r
",
        port = agent_channel::AGENT_VSOCK_PORT
    )
}

/// `/sbin/mount-drives` — mounts the driver-attached data block devices (P3.4 input, P3.5 output) by
/// **filesystem label**, so their `/dev/vdX` enumeration order is irrelevant (a boot may attach
/// input, output, both, or neither). `findfs LABEL=…` resolves each label from the superblock via
/// busybox's volume_id (no udev / `/dev/disk/by-label` needed); a label with no matching device
/// yields an empty result, so that mount is silently skipped and a plain boot is unaffected. `-t ext4`
/// because busybox `mount`'s type autodetection is weaker than util-linux's; the output mount is
/// `-o sync` so a command's writes are flushed straight to the device, surviving a hard-kill teardown.
/// Labels come from `agent-channel`, the one definition the driver (which stamps them) also uses.
fn mount_drives_script() -> String {
    format!(
        "\
#!/bin/sh
# Mount driver-attached data block devices by label (order-independent, best-effort).
in=$(findfs LABEL={input} 2>/dev/null) && [ -n \"$in\" ] && /bin/mount -t ext4 -o ro \"$in\" /input
out=$(findfs LABEL={output} 2>/dev/null) && [ -n \"$out\" ] && /bin/mount -t ext4 -o sync \"$out\" /output
",
        input = agent_channel::INPUT_LABEL,
        output = agent_channel::OUTPUT_LABEL,
    )
}

/// The Alpine branch the guest userland comes from: the minirootfs base and the package repo the
/// runtime packages install from. One pin, used by both, so base and packages can't skew branches.
const ALPINE_BRANCH: &str = "v3.24";

/// The language runtimes baked into the guest image: python3 (P3.2's reference) + **nodejs** (P3.9's
/// second, differently-shaped interpreter, proving the rootfs isn't Python-specific — a static native
/// ELF is injected at runtime rather than baked, so it isn't listed here). Installed by `apk.static`
/// from the pinned branch. The install **floats** within that stable
/// branch — Alpine branch repos carry only the latest revision per package, so an exact `pkg=ver-rN`
/// pin would just *fail* the build the day upstream bumps (the old `.apk` is gone from the CDN), not
/// reproduce it. Instead P3.6 **records** the resolved closure in a committed lockfile and detects
/// drift (`build-rootfs --verify`), keeping the everyday build working; durable pinning would mean
/// vendoring the `.apk` closure as sha-pinned artifacts (a later hardening step).
const GUEST_PACKAGES: &[&str] = &["python3", "nodejs"];

/// The overlay init (`/sbin/overlay-init`), run as PID 1 when the driver boots this image
/// **read-only** (`BootConfig::read_only_root`). It stacks a per-run tmpfs over the read-only base
/// so `/` is writable but the base is never mutated, then `pivot_root`s in and `exec`s the real
/// init. `pivot_root` (not `switch_root`): the base stays mounted as the overlay lowerdir, shadowed
/// at `/rom` — `switch_root` would try to free a root that's still in use. PATH is set explicitly
/// because the kernel gives PID 1 no PATH; `$overlay_size` arrives from the kernel command line (the
/// driver appends `overlay_size=<N>M`, which the kernel routes into PID 1's environment).
const OVERLAY_INIT: &str = "\
#!/bin/sh
export PATH=/sbin:/bin:/usr/sbin:/usr/bin
size=\"${overlay_size:-64m}\"
mount -t tmpfs -o \"size=$size\" tmpfs /overlay
mkdir -p /overlay/up /overlay/work /overlay/root
mount -t overlay overlay -o lowerdir=/,upperdir=/overlay/up,workdir=/overlay/work /overlay/root
mkdir -p /overlay/root/rom
cd /overlay/root
pivot_root . rom
exec chroot . /sbin/init
";

/// The pinned Alpine minirootfs — a real musl+busybox userland (so init and a shell just work, and
/// `apk` adds the [`GUEST_PACKAGES`] runtimes). A *build input*, deliberately separate from
/// [`artifacts`] (the boot kernel+rootfs the `ci-privileged` hash-guard requires present).
fn alpine_artifact() -> Result<Artifact> {
    let dir = artifacts_dir();
    match std::env::consts::ARCH {
        "x86_64" => Ok(Artifact {
            url: format!(
                "https://dl-cdn.alpinelinux.org/alpine/{ALPINE_BRANCH}/releases/x86_64/\
                 alpine-minirootfs-3.24.1-x86_64.tar.gz"
            ),
            sha256: "41f73e3cf5fa919b8aa5ca6b30dc48f0da2720776d7423e2a7748211456fe081",
            dest: dir.join("alpine-minirootfs.tar.gz"),
        }),
        other => bail!("no pinned Alpine minirootfs for arch {other} yet (x86_64 only)"),
    }
}

/// The pinned static `apk` (from Alpine's `apk-tools-static` package — itself a tarball): the
/// installer that puts [`GUEST_PACKAGES`] into the staging dir **rootless**, on any host distro.
fn apk_tools_artifact() -> Result<Artifact> {
    let dir = artifacts_dir();
    match std::env::consts::ARCH {
        "x86_64" => Ok(Artifact {
            url: format!(
                "https://dl-cdn.alpinelinux.org/alpine/{ALPINE_BRANCH}/main/x86_64/\
                 apk-tools-static-3.0.6-r0.apk"
            ),
            sha256: "a62f54609910d1eb23d8ebcf69dd7954280fe76047452bb88410122cbca14a6e",
            dest: dir.join("apk-tools-static.apk"),
        }),
        other => bail!("no pinned apk-tools-static for arch {other} yet (x86_64 only)"),
    }
}

/// One full rootfs assembly into `out_image`: extract the pinned Alpine base, install the guest
/// packages, bake the static agent + init in, and build the ext4 from the staging dir with
/// `mke2fs -d` (rootless — no loopback, no `sudo`). A distinct output path from the pinned Ubuntu
/// `rootfs.ext4`, so its hash-guard + the Phase-1 `login:` boot test are untouched. Returns the
/// image's sha256 and the resolved package closure, so [`build_rootfs`] can check reproducibility.
fn assemble_rootfs(out_image: &Path) -> Result<RootfsBuild> {
    let agent = build_guest_agent()?;

    let base = alpine_artifact()?;
    fetch_one(&base)?;

    let dir = artifacts_dir();
    let staging = dir.join("rootfs-staging");
    if staging.exists() {
        std::fs::remove_dir_all(&staging)
            .with_context(|| format!("clean staging {}", staging.display()))?;
    }
    std::fs::create_dir_all(&staging)?;

    // Extract the Alpine base (preserves symlinks + mode bits).
    run_tool(
        "tar",
        &[
            OsStr::new("xzf"),
            base.dest.as_os_str(),
            OsStr::new("-C"),
            staging.as_os_str(),
        ],
    )?;

    // Install the guest runtimes (P3.2: python3) into the staging root with the pinned static apk —
    // rootless, on any host distro. Packages are signature-verified against the keys the minirootfs
    // itself ships (`/etc/apk/keys`). `--no-scripts` because pre/post-install scripts need a chroot
    // (root); the runtime packages are file payloads, and the in-VM exec test proves they run.
    install_guest_packages(&staging)?;

    // Bake the static agent in at /usr/local/bin/agent-guest.
    let bindir = staging.join("usr/local/bin");
    std::fs::create_dir_all(&bindir)?;
    let agent_dest = bindir.join("agent-guest");
    std::fs::copy(&agent, &agent_dest)
        .with_context(|| format!("copy agent into {}", agent_dest.display()))?;
    set_mode_0755(&agent_dest)?;

    // Replace Alpine's OpenRC inittab with our minimal vsock init.
    std::fs::write(staging.join("etc/inittab"), rootfs_inittab()).context("write /etc/inittab")?;

    // Bake the overlay init + its mountpoint: when the driver boots this image read-only, the
    // kernel runs `/sbin/overlay-init` (PID 1), which stacks a per-run tmpfs over the RO base so `/`
    // is writable, then hands off to the real init. `/overlay` must exist in the image because the
    // root is read-only at that point — you can't `mkdir` a mountpoint on a read-only `/`.
    let overlay_init = staging.join("sbin/overlay-init");
    std::fs::write(&overlay_init, OVERLAY_INIT).context("write /sbin/overlay-init")?;
    set_mode_0755(&overlay_init)?;
    std::fs::create_dir_all(staging.join("overlay")).context("create /overlay mountpoint")?;

    // The by-label mount helper (P3.4 input, P3.5 output) + its mountpoints. Baked, not `mkdir`'d at
    // runtime, so they're image properties that hold regardless of whether `/` is the writable
    // overlay or a base. `/sbin/mount-drives` is run from the inittab sysinit line.
    let mount_drives = staging.join("sbin/mount-drives");
    std::fs::write(&mount_drives, mount_drives_script()).context("write /sbin/mount-drives")?;
    set_mode_0755(&mount_drives)?;
    std::fs::create_dir_all(staging.join("input")).context("create /input mountpoint")?;
    std::fs::create_dir_all(staging.join("output")).context("create /output mountpoint")?;

    // Build the ext4 from the staging dir — rootless, via `mke2fs -d`, and **deterministic** (P3.6):
    // a fixed UUID + directory-hash seed, plus `SOURCE_DATE_EPOCH` — which stamps the superblock
    // create/write/check times and clamps the copied file mtimes down to the epoch — make two builds
    // byte-identical. `lazy_itable_init=0` writes the inode table eagerly, so its bytes are fixed here
    // rather than finished non-deterministically by the guest kernel on first mount.
    let _ = std::fs::remove_file(out_image);
    run_tool(
        "truncate",
        &[
            OsStr::new("-s"),
            OsStr::new(&format!("{ROOTFS_SIZE_MIB}M")),
            out_image.as_os_str(),
        ],
    )?;
    let ext_opts = format!("hash_seed={ROOTFS_UUID},lazy_itable_init=0");
    run_tool_env(
        "mke2fs",
        &[
            OsStr::new("-F"),
            OsStr::new("-q"),
            OsStr::new("-t"),
            OsStr::new("ext4"),
            OsStr::new("-b"),
            OsStr::new("4096"),
            OsStr::new("-m"),
            OsStr::new("0"),
            OsStr::new("-U"),
            OsStr::new(ROOTFS_UUID),
            OsStr::new("-E"),
            OsStr::new(&ext_opts),
            OsStr::new("-d"),
            staging.as_os_str(),
            out_image.as_os_str(),
        ],
        &[("SOURCE_DATE_EPOCH", ROOTFS_SOURCE_DATE_EPOCH)],
    )?;

    // Record the resolved package closure before the staging tree (with its apk db) is removed.
    let packages = resolved_packages(&staging)?;
    // The image is the product — don't leave the extracted staging tree behind.
    std::fs::remove_dir_all(&staging)
        .with_context(|| format!("clean up staging {}", staging.display()))?;

    Ok(RootfsBuild {
        image_sha256: sha256_of(out_image)?,
        packages,
    })
}

/// The result of one rootfs assembly: the image's content hash and the exact resolved package
/// closure (sorted `name-version-rN`), the two things a reproducibility check compares.
struct RootfsBuild {
    image_sha256: String,
    packages: Vec<String>,
}

/// `cargo xtask build-rootfs [--verify] [--update-lock]`. The default (no flags) is one command: it
/// assembles the deterministic image, prints its sha256, and warns if the package closure drifted
/// from the committed lockfile. `--update-lock` re-records that lockfile (the "re-pin" after an
/// upstream bump); `--verify` proves reproducibility — a second build must be byte-identical — and
/// turns closure drift into a hard failure. `ci-privileged` runs `--verify` as the gate.
fn build_rootfs(verify: bool, update_lock: bool) -> Result<()> {
    let out = agent_rootfs_path();
    let build = assemble_rootfs(&out)?;
    println!("\n✓ rootfs built (agent baked in): {}", out.display());
    println!("  sha256: {}", build.image_sha256);

    // Keep the base small (P3.7): report the real footprint and fail on bloat past the budget.
    let used_mib = image_used_bytes(&out)? / (1024 * 1024);
    println!("  size:   {used_mib} MiB used / {ROOTFS_BUDGET_MIB} MiB budget");
    if used_mib > ROOTFS_BUDGET_MIB {
        bail!(
            "rootfs base is over budget: {used_mib} MiB > {ROOTFS_BUDGET_MIB} MiB — keep the base \
             small (P3.7), or raise ROOTFS_BUDGET_MIB (+ ROOTFS_SIZE_MIB) deliberately"
        );
    }

    if update_lock {
        write_packages_lock(&build.packages)?;
        println!(
            "  ✓ recorded {} packages in {}",
            build.packages.len(),
            packages_lock_path().display()
        );
    } else {
        check_packages_lock(&build.packages, verify)?;
    }

    if verify {
        // Prove determinism: a second full build must be byte-for-byte identical. Built to a temp
        // path so the canonical image (which the boot test uses) stays in place; removed after.
        let tmp = artifacts_dir().join("rootfs-agent.verify.ext4");
        let again = assemble_rootfs(&tmp)?;
        let _ = std::fs::remove_file(&tmp);
        if again.image_sha256 != build.image_sha256 {
            bail!(
                "rootfs build is NOT reproducible — two builds differ:\n  {}\n  {}",
                build.image_sha256,
                again.image_sha256
            );
        }
        println!("  ✓ reproducible: two builds are byte-identical");
    }

    // The full runnable hint, printed from the contract constants so it can't drift from the code.
    println!(
        "  exec inside a microVM with:\n  AGENT_ROOTFS={} AGENT_MARKER={} cargo run -p agent-cli -- run -- echo hi",
        out.display(),
        agent_channel::GUEST_READY_MARKER
    );
    Ok(())
}

/// The committed lockfile recording the exact guest package closure (P3.6). Lives next to the build
/// code — **not** in the gitignored `artifacts/` — so it's version-controlled and a diff shows
/// exactly when Alpine's branch repo moved a package under the floating install.
fn packages_lock_path() -> PathBuf {
    workspace_root().join("xtask/rootfs-packages.lock")
}

/// The resolved package closure from a staging tree's apk database: every installed package (the
/// pinned base + the `apk add` dependency closure) as sorted `name-version-rN`. The db content is
/// deterministic for a given set of package revisions, so this is a stable fingerprint of the
/// rootfs's software — it changes only when a package revision does.
fn resolved_packages(staging: &Path) -> Result<Vec<String>> {
    let db = staging.join("lib/apk/db/installed");
    let text =
        std::fs::read_to_string(&db).with_context(|| format!("read apk db {}", db.display()))?;
    let mut pkgs = Vec::new();
    let (mut name, mut version): (Option<&str>, Option<&str>) = (None, None);
    for line in text.lines() {
        if let Some(n) = line.strip_prefix("P:") {
            name = Some(n);
        } else if let Some(v) = line.strip_prefix("V:") {
            version = Some(v);
        } else if line.is_empty() {
            // A blank line ends a package record; emit the one we just read.
            if let (Some(n), Some(v)) = (name.take(), version.take()) {
                pkgs.push(format!("{n}-{v}"));
            }
        }
    }
    if let (Some(n), Some(v)) = (name, version) {
        pkgs.push(format!("{n}-{v}")); // last record may lack a trailing blank line
    }
    pkgs.sort();
    Ok(pkgs)
}

/// Write the committed package lockfile (the `--update-lock` action).
fn write_packages_lock(packages: &[String]) -> Result<()> {
    let path = packages_lock_path();
    let mut body = String::from(
        "# Resolved guest rootfs package closure (P3.6) — the exact Alpine packages baked into\n\
         # artifacts/rootfs-agent.ext4. Regenerate after an upstream bump with:\n\
         #   cargo xtask build-rootfs --update-lock\n\
         # Drift from this list means Alpine's branch repo moved and the image no longer reproduces.\n",
    );
    for p in packages {
        body.push_str(p);
        body.push('\n');
    }
    std::fs::write(&path, body).with_context(|| format!("write {}", path.display()))
}

/// Compare the freshly-resolved closure against the committed lockfile. `hard` (set by `--verify`)
/// makes drift or a missing lockfile a build failure; otherwise it's a warning, so the everyday
/// build still succeeds even after an upstream bump (it just tells you to re-pin).
fn check_packages_lock(built: &[String], hard: bool) -> Result<()> {
    let path = packages_lock_path();
    let recorded = match std::fs::read_to_string(&path) {
        Ok(text) => text
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>(),
        Err(_) => {
            let msg = format!(
                "no package lockfile at {} — run `cargo xtask build-rootfs --update-lock`",
                path.display()
            );
            if hard {
                bail!("{msg}");
            }
            println!("  ! {msg}");
            return Ok(());
        }
    };
    if recorded.as_slice() != built {
        let msg = format!(
            "guest package closure drifted from {} (Alpine bumped a package) — the image no longer \
             matches the lockfile; run `cargo xtask build-rootfs --update-lock` to re-pin",
            path.display()
        );
        if hard {
            bail!("{msg}");
        }
        println!("  ! {msg}");
    }
    Ok(())
}

// ---- boot benchmark (ROADMAP P3.7) -----------------------------------------------------------

/// Real (non-sparse) bytes an image occupies — the base's actual footprint, matching `du`. The ext4
/// carries free space, but `mke2fs`/`truncate` leave it unallocated, so allocated blocks ≈ the used
/// payload.
fn image_used_bytes(path: &Path) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    Ok(meta.blocks().saturating_mul(512))
}

/// Measure boot-to-userspace latency of the agent rootfs (P3.7). Boots `runs` times on **each** of
/// two paths — the P3.3 read-only *shared* base (no per-VM copy) and the read-write *copy* base — and
/// reports percentiles for both, so the base **size**'s effect on boot is visible: the copy path
/// duplicates the whole image per boot, the shared path doesn't. "Measured, not marketed."
fn bench_boot(runs: usize) -> Result<()> {
    if !Path::new("/dev/kvm").exists() {
        bail!("bench-boot needs /dev/kvm (run on a KVM-capable host)");
    }
    if runs == 0 {
        bail!("--runs must be >= 1");
    }
    let kernel = kernel_path();
    let rootfs = agent_rootfs_path();
    for (what, p) in [("kernel", &kernel), ("agent rootfs", &rootfs)] {
        if !p.is_file() {
            bail!(
                "missing {what} at {} — run `cargo xtask fetch-artifacts` + `cargo xtask build-rootfs`",
                p.display()
            );
        }
    }

    let used_mib = image_used_bytes(&rootfs)? / (1024 * 1024);
    println!("bench-boot: agent rootfs {used_mib} MiB, {runs} boots per path\n");

    for (label, read_only_root) in [
        ("read-only shared base", true),
        ("read-write per-VM copy", false),
    ] {
        let mut latencies = Vec::with_capacity(runs);
        for i in 0..runs {
            let mut cfg = BootConfig::from_env();
            cfg.kernel = kernel.clone();
            cfg.rootfs = rootfs.clone();
            cfg.userspace_marker = GUEST_READY_MARKER.to_string();
            cfg.guest_cid = Some(DEFAULT_GUEST_CID);
            cfg.read_only_root = read_only_root;
            let vm = Vm::boot(cfg).with_context(|| format!("{label}: boot {i} failed"))?;
            latencies.push(vm.boot_latency().as_millis() as u64);
            vm.shutdown().ok();
        }
        report_percentiles(label, &mut latencies);
    }
    println!(
        "\nBoth paths boot in well under a second. The {used_mib} MiB base is cheap to duplicate (the\n\
         host page cache serves the copy), so its size barely moves boot latency here — keeping the\n\
         base small mainly buys density (page-cache dedup across VMs + disk), not boot time."
    );
    Ok(())
}

/// Print min/p50/p90/p99/max of `samples` (ms), sorting in place. Nearest-rank, no interpolation. A
/// percentile whose rank lands on the last sample has no observation above it — it's `max` relabeled,
/// which is dishonest at small `n` (e.g. `p99` needs n≥100 to mean anything). Those print `—`, so a
/// short bench can't dress up its slowest boot as a tail percentile.
fn report_percentiles(label: &str, samples: &mut [u64]) {
    samples.sort_unstable();
    let n = samples.len();
    let pct = |p: usize| -> String {
        let rank = (p * n).div_ceil(100).clamp(1, n); // 1-based nearest rank
        if rank >= n {
            format!("{:>5}", "—")
        } else {
            format!("{:>5}", samples[rank - 1])
        }
    };
    println!(
        "  {label:<24} min {:>5}  p50 {}  p90 {}  p99 {}  max {:>5}  (ms, n={n})",
        samples[0],
        pct(50),
        pct(90),
        pct(99),
        samples[n - 1],
    );
}

/// Install [`GUEST_PACKAGES`] into the staging root with the pinned `apk.static` — no chroot, no
/// root, no host `apk`. The `.apk` is a tarball; its `sbin/apk.static` is extracted to a scratch
/// dir that's removed after the install (the packages land in `staging`, the tool is ephemeral).
fn install_guest_packages(staging: &Path) -> Result<()> {
    if GUEST_PACKAGES.is_empty() {
        return Ok(());
    }
    let tools = apk_tools_artifact()?;
    fetch_one(&tools)?;

    let tooldir = artifacts_dir().join("apk-tools");
    if tooldir.exists() {
        std::fs::remove_dir_all(&tooldir)?;
    }
    std::fs::create_dir_all(&tooldir)?;
    run_tool(
        "tar",
        &[
            OsStr::new("xzf"),
            tools.dest.as_os_str(),
            OsStr::new("-C"),
            tooldir.as_os_str(),
        ],
    )?;

    let apk = tooldir.join("sbin/apk.static");
    let repo = format!("https://dl-cdn.alpinelinux.org/alpine/{ALPINE_BRANCH}/main");
    // The host's arch, not a literal: Alpine's arch names match Rust's for the arches we'll pin
    // (x86_64/aarch64), and the pinned-artifact fns above already bail on anything unpinned — so
    // this stays correct by itself when a second arch lands, instead of silently installing
    // x86_64 packages into an aarch64 image.
    let mut args: Vec<&OsStr> = vec![
        OsStr::new("--root"),
        staging.as_os_str(),
        OsStr::new("--arch"),
        OsStr::new(std::env::consts::ARCH),
        OsStr::new("--repository"),
        OsStr::new(&repo),
        OsStr::new("--no-scripts"),
        OsStr::new("--no-cache"),
        OsStr::new("add"),
    ];
    args.extend(GUEST_PACKAGES.iter().map(OsStr::new));
    let apk_str = apk.to_string_lossy().into_owned();
    let result = run_tool(&apk_str, &args);

    // The tool is scratch either way — clean it before propagating any install failure.
    let _ = std::fs::remove_dir_all(&tooldir);
    result?;

    // Drop apk's install log: it records each action with a **wall-clock** timestamp, the one piece
    // of the install that isn't reproducible (the package db itself is deterministic). It has no
    // runtime purpose in the guest, so removing it makes the image byte-identical across builds (P3.6).
    let apk_log = staging.join("var/log/apk.log");
    if apk_log.exists() {
        std::fs::remove_file(&apk_log).with_context(|| format!("remove {}", apk_log.display()))?;
    }
    Ok(())
}

/// The host-safe gate. `--locked` everywhere so a stale `Cargo.lock` fails here, not at release.
fn ci() -> Result<()> {
    cargo(&["fmt", "--all", "--check"])?;
    cargo(&[
        "clippy",
        "--workspace",
        "--all-targets",
        "--locked",
        "--",
        "-D",
        "warnings",
    ])?;
    // Mirror CI's global `RUSTFLAGS=-D warnings` so the local gate and the runner agree on
    // rustc lints too, not just clippy's.
    cargo_env(
        &["build", "--workspace", "--locked"],
        &[("RUSTFLAGS", "-D warnings")],
    )?;
    cargo_env(
        &["test", "--workspace", "--locked"],
        &[("RUSTFLAGS", "-D warnings")],
    )?;
    cargo_env(
        &["doc", "--no-deps", "--workspace", "--locked"],
        &[("RUSTDOCFLAGS", "-D warnings")],
    )?;
    cargo(&["deny", "check"])?;
    println!("\n✓ all checks passed");
    Ok(())
}

/// Booting a microVM and loading/attaching eBPF need `/dev/kvm` + elevated caps, so those tests are
/// `#[ignore]`d and run only here, on a machine that has them.
fn ci_privileged() -> Result<()> {
    if !Path::new("/dev/kvm").exists() {
        bail!("/dev/kvm not present — privileged tests need KVM (run on a KVM-capable host)");
    }
    // This gate builds and verifies the static guest agent (below), and that verification is the
    // *only* thing standing between a silently-reintroduced dynamic dependency and a confusing
    // in-guest loader failure. `verify_static` soft-skips when `readelf` is absent (so ad-hoc
    // `build-rootfs` still works), so require it *here* — a missing binutils must fail the gate
    // loudly, not quietly disarm the check.
    if !in_path("readelf") {
        bail!(
            "readelf (binutils) not found — the privileged gate verifies the guest agent is \
               statically linked and won't run that check blind; install binutils"
        );
    }
    // The boot tests need the pinned kernel + rootfs; fail with the fix rather than a cryptic
    // boot error. `fetch-artifacts` (not this gate) does the network download; here we verify
    // the hashes too — the sha256 is the contract, and a hand-placed or corrupted artifact
    // should fail this gate, not the boot inside it.
    for a in artifacts()? {
        if !a.dest.is_file() {
            bail!(
                "missing artifact {} — run `cargo xtask fetch-artifacts` first",
                a.dest.display()
            );
        }
        let got = sha256_of(&a.dest)?;
        if got != a.sha256 {
            bail!(
                "artifact {} does not match its pin (expected {}, got {}) — re-run \
                 `cargo xtask fetch-artifacts`",
                a.dest.display(),
                a.sha256,
                got
            );
        }
    }
    // The in-VM exec test boots a rootfs with the agent baked in — build it here (not from inside a
    // `#[test]`, which mustn't shell out to a musl `cargo build`). Idempotent: the Alpine base is
    // cached by sha256, so this is a rebuild of the agent + the image, not a re-download. `--verify`
    // makes this the reproducibility gate: it builds twice, asserts byte-identical, and fails on
    // package-closure drift from the lockfile.
    build_rootfs(true, false)?;
    // The runtime-agnostic test (P3.9) injects a static native binary; build it here (musl), like the
    // agent — the same "don't shell a musl `cargo build` from a `#[test]`" rule. It is a *fixture*,
    // not part of the image, so it's built separately, not baked into the rootfs.
    build_guest_example()?;
    cargo(&["test", "--workspace", "--locked", "--", "--ignored"])?;
    println!("\n✓ privileged integration passed");
    Ok(())
}

/// Print a checklist of the host prerequisites; read-only, never fails the build.
fn setup() -> Result<()> {
    println!("agent — host capability check\n");
    check("/dev/kvm present", Path::new("/dev/kvm").exists());
    check("/dev/kvm writable (kvm group or root)", kvm_writable());
    check(
        "kernel BTF (/sys/kernel/btf/vmlinux)",
        Path::new("/sys/kernel/btf/vmlinux").exists(),
    );
    check("firecracker in PATH", in_path("firecracker"));
    check("jailer in PATH", in_path("jailer"));
    check("bpf-linker installed", in_path("bpf-linker"));
    check("mke2fs (rootfs + input block device)", in_path("mke2fs"));
    check(
        "e2fsck + debugfs (output readback)",
        in_path("e2fsck") && in_path("debugfs"),
    );
    check(
        "readelf (binutils — static-link verification)",
        in_path("readelf"),
    );
    check("ip (iproute2 — per-VM tap device)", in_path("ip"));
    check(
        "guest kernel + rootfs (cargo xtask fetch-artifacts)",
        kernel_path().is_file() && boot_rootfs_path().is_file(),
    );
    println!("\nMissing items are covered in CONTRIBUTING.md → Prerequisites.");
    Ok(())
}

/// A pinned boot artifact: a stable URL, its expected sha256 (the real contract — the URL is
/// replaceable), and where it lands under `artifacts/`.
struct Artifact {
    url: String,
    sha256: &'static str,
    dest: PathBuf,
}

/// The kernel + rootfs pinned for the host architecture. Matched to Firecracker v1.9's CI
/// artifacts (uncompressed `vmlinux` + a minimal Ubuntu ext4). Only x86_64 is pinned so far.
fn artifacts() -> Result<Vec<Artifact>> {
    let base = "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.9";
    match std::env::consts::ARCH {
        "x86_64" => Ok(vec![
            Artifact {
                url: format!("{base}/x86_64/vmlinux-6.1.102"),
                sha256: "3b6e45c66d1b66d4fb0a1528107abbe890972f94e902bafe85fdf5108288c575",
                dest: kernel_path(),
            },
            Artifact {
                url: format!("{base}/x86_64/ubuntu-22.04.ext4"),
                sha256: "b930af6ed56c5347c200eddfa4ae4701eed6f7d7fb30a6b9b8d2d30bfc2a2ed7",
                dest: boot_rootfs_path(),
            },
        ]),
        other => bail!(
            "no pinned artifacts for arch {other} yet (x86_64 only) — set AGENT_KERNEL/AGENT_ROOTFS \
             to your own uncompressed vmlinux + ext4 rootfs"
        ),
    }
}

/// The workspace root (not the cwd), so the commands work from anywhere.
fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or_else(|| Path::new("."))
}

/// `artifacts/` under the workspace root.
fn artifacts_dir() -> PathBuf {
    workspace_root().join("artifacts")
}

/// The artifact filenames under [`artifacts_dir`], defined once so the many readers/writers
/// (`build-rootfs`, `bench-boot`, `setup`, `fetch-artifacts`) can't drift apart: the pinned guest
/// kernel, the Phase-1 boot rootfs (fetched), and the agent rootfs (`build-rootfs` output).
fn kernel_path() -> PathBuf {
    artifacts_dir().join("vmlinux")
}
fn boot_rootfs_path() -> PathBuf {
    artifacts_dir().join("rootfs.ext4")
}
fn agent_rootfs_path() -> PathBuf {
    artifacts_dir().join("rootfs-agent.ext4")
}

/// Download each pinned kernel/rootfs artifact (skipping any already present with the right hash).
fn fetch_artifacts() -> Result<()> {
    let items = artifacts()?;
    for a in &items {
        fetch_one(a)?;
    }
    println!("\n✓ artifacts ready in {}", artifacts_dir().display());
    Ok(())
}

/// Fetch one artifact into place if it isn't already present with the right hash. Downloads to a
/// `.part` and renames only after the hash verifies, so an interrupted download can never leave a
/// plausible-looking file at the final path (`ci-privileged` gates on presence alone).
fn fetch_one(a: &Artifact) -> Result<()> {
    let name = a
        .dest
        .file_name()
        .map_or_else(|| a.dest.clone(), PathBuf::from);
    if a.dest.is_file() && sha256_of(&a.dest)? == a.sha256 {
        println!("✓ {} already present (sha256 ok)", name.display());
        return Ok(());
    }
    if let Some(parent) = a.dest.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    println!("↓ {} <- {}", name.display(), a.url);
    let part = a.dest.with_extension("part");
    if let Err(e) = curl_download(&a.url, &part) {
        let _ = std::fs::remove_file(&part);
        return Err(e);
    }
    let got = sha256_of(&part)?;
    if got != a.sha256 {
        let _ = std::fs::remove_file(&part);
        bail!(
            "sha256 mismatch for {}: expected {}, got {} (removed)",
            name.display(),
            a.sha256,
            got
        );
    }
    std::fs::rename(&part, &a.dest)
        .with_context(|| format!("move {} into place", part.display()))?;
    println!("✓ {} verified", name.display());
    Ok(())
}

/// `curl -fSL` a URL to `dest` (fail on HTTP error, follow redirects).
fn curl_download(url: &str, dest: &Path) -> Result<()> {
    let status = Command::new("curl")
        .args(["-fSL", "-o"])
        .arg(dest)
        .arg(url)
        .status()
        .context("running curl (is it installed?)")?;
    if !status.success() {
        bail!("curl failed for {url}");
    }
    Ok(())
}

/// The sha256 of a file, via the `sha256sum` CLI (no hashing crate on the dev-tooling path).
fn sha256_of(path: &Path) -> Result<String> {
    let out = Command::new("sha256sum")
        .arg(path)
        .output()
        .context("running sha256sum (is it installed?)")?;
    if !out.status.success() {
        bail!("sha256sum failed for {}", path.display());
    }
    let text = String::from_utf8(out.stdout).context("sha256sum output not UTF-8")?;
    let hash = text
        .split_whitespace()
        .next()
        .context("empty sha256sum output")?;
    Ok(hash.to_string())
}

/// Run an external build tool, echoing the command; fail with context if it's missing or errors.
fn run_tool(program: &str, args: &[&OsStr]) -> Result<()> {
    run_tool_env(program, args, &[])
}

/// [`run_tool`] with extra environment scoped to **this child only** (not `std::env::set_var`, which
/// is process-global and would leak into every later tool). Used to hand `mke2fs` its
/// `SOURCE_DATE_EPOCH` without affecting `tar`/`apk`/`truncate`.
fn run_tool_env(program: &str, args: &[&OsStr], env: &[(&str, &str)]) -> Result<()> {
    let shown: Vec<_> = args.iter().map(|a| a.to_string_lossy()).collect();
    println!("$ {program} {}", shown.join(" "));
    let mut cmd = Command::new(program);
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let status = cmd
        .status()
        .with_context(|| format!("running {program} (is it installed?)"))?;
    if !status.success() {
        bail!("{program} failed");
    }
    Ok(())
}

/// `chmod 0755` — the agent must be executable inside the image even if the copy didn't preserve it.
fn set_mode_0755(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).with_context(|| format!("chmod +x {}", path.display()))
}

fn check(label: &str, ok: bool) {
    println!("  [{}] {label}", if ok { "✓" } else { " " });
}

fn kvm_writable() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok()
}

fn in_path(bin: &str) -> bool {
    let Ok(path) = std::env::var("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| dir.join(bin).is_file())
}

fn cargo(args: &[&str]) -> Result<()> {
    cargo_env(args, &[])
}

fn cargo_env(args: &[&str], env: &[(&str, &str)]) -> Result<()> {
    println!("$ cargo {}", args.join(" "));
    let mut cmd = Command::new(env!("CARGO"));
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let status = cmd
        .status()
        .with_context(|| format!("running cargo {}", args.join(" ")))?;
    if !status.success() {
        bail!("cargo {} failed", args.join(" "));
    }
    Ok(())
}
