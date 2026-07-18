//! The reproducible guest rootfs build: a pinned Alpine base + the guest
//! runtimes + the static agent + a vsock init, assembled rootless into an ext4 image that two
//! builds reproduce byte-identically.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::artifacts::{fetch_one, sha256_of, Artifact};
use crate::bench::image_used_bytes;
use crate::guest_bins::build_guest_agent;
use crate::{agent_rootfs_path, artifacts_dir, run_tool, run_tool_env, vendor_dir, workspace_root};

/// The apk cache subdirectory (under a build's `artifacts/` or a vendor mirror): the `.apk` closure +
/// its `APKINDEX`, populated online once and installed from offline thereafter. Defined here with the
/// rest of the apk machinery; `vendor` imports it (so the module edge points one way, `vendor` →
/// `rootfs`, not a cycle).
pub(crate) const APK_CACHE_SUBDIR: &str = "apk-cache";

/// A fixed rootfs UUID so repeated builds don't churn it (Firecracker roots by device, not UUID).
/// Reused as the ext4 directory-hash seed: the seed only guards against adversarial
/// directory-hash flooding, which a trusted, pinned build-time image doesn't face, so a fixed seed
/// costs nothing and buys byte-for-byte determinism.
const ROOTFS_UUID: &str = "5b3a9c1e-0000-4000-8000-000000000001";

/// A fixed build epoch for the rootfs image. `mke2fs` honours `SOURCE_DATE_EPOCH`: it stamps
/// the filesystem's create/write/check times with it and **clamps every `-d`-copied file mtime down
/// to it**, so repeated builds don't churn timestamps. A constant, deliberately, a `git log` or
/// wall-clock date would vary across shallow clones and over time, defeating the purpose. Together
/// with the fixed UUID + hash seed, this makes two builds byte-identical. 2024-01-01T00:00:00Z.
const ROOTFS_SOURCE_DATE_EPOCH: &str = "1704067200";

/// Image size. Headroom over the payload so `apk.static --root` has room without a re-size. Bumped
/// 128→256 when Node (its `icu-libs`/`simdjson`/`ada-libs` closure, ~64 MiB) joined python3.
const ROOTFS_SIZE_MIB: u32 = 256;

/// Soft ceiling on the base rootfs's real footprint ("keep the base small"). `build-rootfs`
/// fails past it, a regression guard against accidental bloat. The image is ~132 MiB (Alpine +
/// python3 + **Node** + the agent); this leaves ~28 MiB headroom. Adding another runtime is a
/// deliberate bump of this *and* `ROOTFS_SIZE_MIB`, not a silent creep, and a prompt to ask whether
/// the base is still "small."
const ROOTFS_BUDGET_MIB: u64 = 160;

/// The init the image ships, replacing Alpine's OpenRC `inittab`. busybox is PID 1 (it reaps
/// orphans and a crashed child is respawned, neither of which the `forbid(unsafe_code)` agent should
/// own). `sysinit` mounts the pseudo-filesystems a fresh ext4 lacks, a rootless `mke2fs -d` seeds
/// no device nodes, so `devtmpfs` is what provides `/dev/ttyS0` + the vsock device (the guest kernel
/// must auto-mount it, `CONFIG_DEVTMPFS_MOUNT`, for PID 1's own console). The agent then respawns on
/// the contract vsock port (`agent_channel::AGENT_VSOCK_PORT`, the same constant the host dials,
/// so the two sides can't drift), attached to `ttyS0` so its readiness line reaches the serial
/// console the host scans.
fn rootfs_inittab() -> String {
    format!(
        "\
# Minimal init for the agent sandbox rootfs (replaces Alpine's OpenRC inittab).
::sysinit:/bin/mount -t devtmpfs dev /dev
::sysinit:/bin/mount -t proc proc /proc
::sysinit:/bin/mount -t sysfs sys /sys
# cgroup v2: the agent runs each command in its own cgroup and reaps the whole process tree
# via `cgroup.kill`, so a double-forked grandchild or `setsid` daemon can't outlive the command and
# wedge the exec connection. `/sys/fs/cgroup` is provided by the sysfs mount above.
::sysinit:/bin/mount -t cgroup2 cgroup2 /sys/fs/cgroup
# Bulk input/output block devices: mount whichever the driver attached, by label — so
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

/// `/sbin/mount-drives`, mounts the driver-attached data block devices (input + output) by
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

/// The language runtimes baked into the guest image: python3 (the reference runtime) + **nodejs** (its
/// second, differently-shaped interpreter, proving the rootfs isn't Python-specific, a static native
/// ELF is injected at runtime rather than baked, so it isn't listed here). Installed by `apk.static`
/// from the pinned branch. The install **floats** within that stable
/// branch, Alpine branch repos carry only the latest revision per package, so an exact `pkg=ver-rN`
/// pin would just *fail* the build the day upstream bumps (the old `.apk` is gone from the CDN), not
/// reproduce it. Instead the build **records** the resolved closure in a committed lockfile and detects
/// drift (`build-rootfs --verify`), keeping the everyday build working; durable pinning would mean
/// vendoring the `.apk` closure as sha-pinned artifacts (a later hardening step).
const GUEST_PACKAGES: &[&str] = &["python3", "nodejs"];

/// The overlay init (`/sbin/overlay-init`), run as PID 1 when the driver boots this image
/// **read-only** (`BootConfig::read_only_root`). It stacks a per-run tmpfs over the read-only base
/// so `/` is writable but the base is never mutated, then `pivot_root`s in and `exec`s the real
/// init. `pivot_root` (not `switch_root`): the base stays mounted as the overlay lowerdir, shadowed
/// at `/rom`, `switch_root` would try to free a root that's still in use. PATH is set explicitly
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

/// The pinned Alpine minirootfs, a real musl+busybox userland (so init and a shell just work, and
/// `apk` adds the [`GUEST_PACKAGES`] runtimes). A *build input*, deliberately separate from
/// [`artifacts`](crate::artifacts::artifacts) (the boot kernel+rootfs the `ci-privileged`
/// hash-guard requires present).
pub(crate) fn alpine_artifact() -> Result<Artifact> {
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

/// The pinned static `apk` (from Alpine's `apk-tools-static` package, itself a tarball): the
/// installer that puts [`GUEST_PACKAGES`] into the staging dir **rootless**, on any host distro.
pub(crate) fn apk_tools_artifact() -> Result<Artifact> {
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
/// `mke2fs -d` (rootless, no loopback, no `sudo`). A distinct output path from the pinned Ubuntu
/// `rootfs.ext4`, so its hash-guard + the `login:` boot test are untouched. Returns the
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

    // Install the guest runtimes (python3) into the staging root with the pinned static apk,
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
    // root is read-only at that point, you can't `mkdir` a mountpoint on a read-only `/`.
    let overlay_init = staging.join("sbin/overlay-init");
    std::fs::write(&overlay_init, OVERLAY_INIT).context("write /sbin/overlay-init")?;
    set_mode_0755(&overlay_init)?;
    std::fs::create_dir_all(staging.join("overlay")).context("create /overlay mountpoint")?;

    // The by-label mount helper (input + output) + its mountpoints. Baked, not `mkdir`'d at
    // runtime, so they're image properties that hold regardless of whether `/` is the writable
    // overlay or a base. `/sbin/mount-drives` is run from the inittab sysinit line.
    let mount_drives = staging.join("sbin/mount-drives");
    std::fs::write(&mount_drives, mount_drives_script()).context("write /sbin/mount-drives")?;
    set_mode_0755(&mount_drives)?;
    std::fs::create_dir_all(staging.join("input")).context("create /input mountpoint")?;
    std::fs::create_dir_all(staging.join("output")).context("create /output mountpoint")?;

    // Build the ext4 from the staging dir, rootless, via `mke2fs -d`, and **deterministic**:
    // a fixed UUID + directory-hash seed, plus `SOURCE_DATE_EPOCH`, which stamps the superblock
    // create/write/check times and clamps the copied file mtimes down to the epoch, make two builds
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
    // The image is the product, don't leave the extracted staging tree behind.
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
/// upstream bump); `--verify` proves reproducibility, a second build must be byte-identical, and
/// turns closure drift into a hard failure. `ci-privileged` runs `--verify` as the CI gate.
pub(crate) fn build_rootfs(verify: bool, update_lock: bool) -> Result<()> {
    let out = agent_rootfs_path();
    let build = assemble_rootfs(&out)?;
    println!("\n✓ rootfs built (agent baked in): {}", out.display());
    println!("  sha256: {}", build.image_sha256);

    // Keep the base small: report the real footprint and fail on bloat past the budget.
    let used_mib = image_used_bytes(&out)? / (1024 * 1024);
    println!("  size:   {used_mib} MiB used / {ROOTFS_BUDGET_MIB} MiB budget");
    if used_mib > ROOTFS_BUDGET_MIB {
        bail!(
            "rootfs base is over budget: {used_mib} MiB > {ROOTFS_BUDGET_MIB} MiB — keep the base \
             small, or raise ROOTFS_BUDGET_MIB (+ ROOTFS_SIZE_MIB) deliberately"
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

/// The committed lockfile recording the exact guest package closure. Lives next to the build
/// code, **not** in the gitignored `artifacts/`, so it's version-controlled and a diff shows
/// exactly when Alpine's branch repo moved a package under the floating install.
fn packages_lock_path() -> PathBuf {
    workspace_root().join("xtask/rootfs-packages.lock")
}

/// The resolved package closure from a staging tree's apk database: every installed package (the
/// pinned base + the `apk add` dependency closure) as sorted `name-version-rN`. The db content is
/// deterministic for a given set of package revisions, so this is a stable fingerprint of the
/// rootfs's software, it changes only when a package revision does.
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
        "# Resolved guest rootfs package closure — the exact Alpine packages baked into\n\
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

/// Where `apk.static` sources the guest packages, the one axis that differs between the online build,
/// an offline vendored build, and the `vendor` snapshot that populates the mirror.
enum ApkSource<'a> {
    /// Fetch from the pinned Alpine CDN, caching nothing, the default online build.
    Network,
    /// Install **offline** from a vendored apk cache (`--cache-dir <dir> --no-network`), so a fresh
    /// host never reaches the CDN. The cache holds the sha-pinned `.apk` closure + its `APKINDEX`.
    VendorCache(&'a Path),
    /// Fetch from the CDN **and** populate `<dir>` with the resolved `.apk`s + index, what
    /// `cargo xtask vendor` runs once to snapshot the closure for later offline installs.
    PopulateCache(&'a Path),
}

/// Install [`GUEST_PACKAGES`] into the staging root with the pinned `apk.static`, no chroot, no
/// root, no host `apk`. Vendor-aware: with `AGENT_VENDOR_DIR` set it installs offline from the
/// vendored apk cache, otherwise it fetches from the pinned Alpine CDN. The `.apk` is a tarball; its
/// `sbin/apk.static` is extracted to a scratch dir removed after the install (the packages land in
/// `staging`, the tool is ephemeral).
fn install_guest_packages(staging: &Path) -> Result<()> {
    if GUEST_PACKAGES.is_empty() {
        return Ok(());
    }
    let tools = apk_tools_artifact()?;
    fetch_one(&tools)?;
    let (tooldir, apk) = extract_apk_static(&tools.dest, &artifacts_dir())?;

    // Bind the cache path so an `ApkSource` borrow can point at it for the whole call.
    let vendored_cache = vendor_dir().map(|v| v.join(APK_CACHE_SUBDIR));
    let source = match &vendored_cache {
        Some(dir) => ApkSource::VendorCache(dir),
        None => ApkSource::Network,
    };
    let result = run_apk_add(&apk, staging, &source);

    // The tool is scratch either way, clean it before propagating any install failure.
    let _ = std::fs::remove_dir_all(&tooldir);
    result?;

    // Drop apk's install log: it records each action with a **wall-clock** timestamp, the one piece
    // of the install that isn't reproducible (the package db itself is deterministic). It has no
    // runtime purpose in the guest, so removing it makes the image byte-identical across builds.
    let apk_log = staging.join("var/log/apk.log");
    if apk_log.exists() {
        std::fs::remove_file(&apk_log).with_context(|| format!("remove {}", apk_log.display()))?;
    }
    Ok(())
}

/// Extract the pinned static `apk` from its (already-fetched) tarball into `<scratch_base>/apk-tools`,
/// returning `(tooldir, apk_static_path)`. The caller removes `tooldir` when done, the tool is
/// ephemeral, the packages it installs are the product. `scratch_base` is caller-chosen so the
/// `vendor` command keeps its scratch inside the mirror dir, not the workspace `artifacts/`.
fn extract_apk_static(tools_tar: &Path, scratch_base: &Path) -> Result<(PathBuf, PathBuf)> {
    let tooldir = scratch_base.join("apk-tools");
    if tooldir.exists() {
        std::fs::remove_dir_all(&tooldir)?;
    }
    std::fs::create_dir_all(&tooldir)?;
    run_tool(
        "tar",
        &[
            OsStr::new("xzf"),
            tools_tar.as_os_str(),
            OsStr::new("-C"),
            tooldir.as_os_str(),
        ],
    )?;
    let apk = tooldir.join("sbin/apk.static");
    Ok((tooldir, apk))
}

/// Run `apk.static add` for [`GUEST_PACKAGES`] into `staging`, sourced per [`ApkSource`]. The
/// package set, arch, and repo are identical across sources, only the fetch/cache flags differ, so
/// the resolved closure (and thus [`resolved_packages`]) is the same whether built online or from the
/// vendored cache, keeping the lockfile contract intact.
fn run_apk_add(apk: &Path, staging: &Path, source: &ApkSource) -> Result<()> {
    let repo = format!("https://dl-cdn.alpinelinux.org/alpine/{ALPINE_BRANCH}/main");
    // The host's arch, not a literal: Alpine's arch names match Rust's for the arches we pin
    // (x86_64/aarch64), and the pinned-artifact fns bail on anything unpinned, so this stays
    // correct by itself when a second arch lands, not silently installing x86_64 into an aarch64 image.
    let mut args: Vec<OsString> = vec![
        OsString::from("--root"),
        staging.as_os_str().to_owned(),
        OsString::from("--arch"),
        OsString::from(std::env::consts::ARCH),
        OsString::from("--repository"),
        OsString::from(&repo),
        OsString::from("--no-scripts"),
    ];
    match source {
        // `--no-cache`: don't leave apk's cache behind on an ordinary online build.
        ApkSource::Network => args.push(OsString::from("--no-cache")),
        // `--no-network`: install purely from the vendored cache (the sha-pinned closure + index).
        ApkSource::VendorCache(dir) => {
            args.push(OsString::from("--cache-dir"));
            args.push(absolute(dir).into_os_string());
            args.push(OsString::from("--no-network"));
        }
        // Online, but keep every fetched `.apk` + the index in the cache dir, the vendor snapshot.
        ApkSource::PopulateCache(dir) => {
            args.push(OsString::from("--cache-dir"));
            args.push(absolute(dir).into_os_string());
        }
    }
    args.push(OsString::from("add"));
    args.extend(GUEST_PACKAGES.iter().map(|p| OsString::from(*p)));

    let apk_str = apk.to_string_lossy().into_owned();
    let arg_refs: Vec<&OsStr> = args.iter().map(OsString::as_os_str).collect();
    run_tool(&apk_str, &arg_refs)
}

/// `apk.static update` into `cache_dir`, fetch + cache the repo's `APKINDEX` so a later offline
/// `add --no-network` can resolve against it. A plain `add --cache-dir` caches the packages it pulls
/// but not necessarily the index, so the vendor snapshot seeds it explicitly.
fn run_apk_update(apk: &Path, staging: &Path, cache_dir: &Path) -> Result<()> {
    let repo = format!("https://dl-cdn.alpinelinux.org/alpine/{ALPINE_BRANCH}/main");
    let args: Vec<OsString> = vec![
        OsString::from("--root"),
        staging.as_os_str().to_owned(),
        OsString::from("--arch"),
        OsString::from(std::env::consts::ARCH),
        OsString::from("--repository"),
        OsString::from(&repo),
        OsString::from("--cache-dir"),
        absolute(cache_dir).into_os_string(),
        OsString::from("update"),
    ];
    let apk_str = apk.to_string_lossy().into_owned();
    let arg_refs: Vec<&OsStr> = args.iter().map(OsString::as_os_str).collect();
    run_tool(&apk_str, &arg_refs)
}

/// Make `path` absolute (against the current dir, `xtask` runs from the workspace root). apk
/// resolves a *relative* `--cache-dir` against its `--root`, which would put the cache inside the
/// staging tree instead of where the packages actually live, so every cache path handed to apk goes
/// through here first.
fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    std::env::current_dir()
        .map(|cwd| cwd.join(path))
        .unwrap_or_else(|_| path.to_path_buf())
}

/// Populate a vendored apk cache with the resolved guest-package closure (the `.apk` files **and**
/// the `APKINDEX`) by running one **online** `apk add` into a throwaway root. Called by
/// `cargo xtask vendor`; afterwards an offline build installs from this cache (`--no-network`), so a
/// fresh host never touches the Alpine CDN, the durable hardening decision 007 deferred. The
/// throwaway root exists only so apk has the base's `/etc/apk/keys` to verify signatures against; it
/// is removed, leaving just the cache. `base_tar`/`apk_tools_tar` are the (already sha-verified)
/// vendored tarballs, so this reuses them rather than re-downloading.
pub(crate) fn populate_apk_cache(
    cache_dir: &Path,
    base_tar: &Path,
    apk_tools_tar: &Path,
) -> Result<()> {
    if GUEST_PACKAGES.is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(cache_dir)
        .with_context(|| format!("create apk cache {}", cache_dir.display()))?;

    // Keep all scratch inside the mirror dir (the cache's parent), not the workspace `artifacts/`, so
    // `vendor --dir /elsewhere` is self-contained and can't clobber a concurrent build's scratch.
    let scratch = cache_dir.parent().unwrap_or(cache_dir);

    // A throwaway staging with the pinned Alpine base, so apk installs into a real root (its keys +
    // db). Removed after; only the cache is the product.
    let staging = scratch.join("apk-cache-root");
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    std::fs::create_dir_all(&staging)?;
    run_tool(
        "tar",
        &[
            OsStr::new("xzf"),
            base_tar.as_os_str(),
            OsStr::new("-C"),
            staging.as_os_str(),
        ],
    )?;

    let (tooldir, apk) = extract_apk_static(apk_tools_tar, scratch)?;
    // Seed the index first (`update`), then the packages (`add`), both into the cache, so a later
    // offline `add --no-network` can resolve the closure against the cached `APKINDEX`.
    let result = run_apk_update(&apk, &staging, cache_dir)
        .and_then(|()| run_apk_add(&apk, &staging, &ApkSource::PopulateCache(cache_dir)));
    let _ = std::fs::remove_dir_all(&tooldir);
    let _ = std::fs::remove_dir_all(&staging);
    result
}

/// `chmod 0755`, the agent must be executable inside the image even if the copy didn't preserve it.
fn set_mode_0755(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).with_context(|| format!("chmod +x {}", path.display()))
}
