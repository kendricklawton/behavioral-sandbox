//! The reproducible guest image builds: a pinned Alpine base + an image's packages + the static
//! agent, assembled rootless into a directory tree that two builds reproduce byte-identically.
//! Two images share the machinery ([`IMAGES`]): the headless one every verb boots by default, and
//! the desktop one that boots to a Wayland session.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::artifacts::{Artifact, fetch_one, sha256_of};

use crate::guest_bins::build_guest_agent;
use crate::{artifacts_dir, run_tool, vendor_dir, workspace_root};

/// The apk cache subdirectory (under a build's `artifacts/` or a vendor mirror): the `.apk` closure +
/// its `APKINDEX`, populated online once and installed from offline thereafter. Defined here with the
/// rest of the apk machinery; `vendor` imports it (so the module edge points one way, `vendor` →
/// `rootfs`, not a cycle).
pub(crate) const APK_CACHE_SUBDIR: &str = "apk-cache";

/// Soft ceiling on the base rootfs's real footprint ("keep the base small"). `build-rootfs`
/// fails past it, a regression guard against accidental bloat. The tree is ~132 MiB (Alpine +
/// python3 + **Node** + the agent); this leaves ~28 MiB headroom. Adding another runtime is a
/// deliberate bump of this, not a silent creep, and a prompt to ask whether the base is still
/// "small."
const ROOTFS_BUDGET_MIB: u64 = 160;

/// The desktop image's ceiling. Measured 2026-09-02: 291 MiB, of which `libLLVM` is 182 and
/// `libgallium` 42, both arriving through wlroots' EGL dependency on Mesa and both what phase 5's
/// virgl driver needs, so they are carried rather than pruned.
const DESKTOP_BUDGET_MIB: u64 = 320;

/// The guest path this builder bakes the agent in at, shared with the host that boots it as a
/// VM's workload (`bsx shell`): the definition lives in `bsx-channel` beside the port they also
/// share. `verify_guest_contract` reads it back off the staged tree.
use bsx_channel::GUEST_AGENT_PATH;

/// An absolute *guest* path resolved inside the staging tree. The leading `/` has to go, or
/// `Path::join` would discard the staging root and address the build host's own filesystem.
fn in_staging(staging: &Path, guest_path: &str) -> PathBuf {
    staging.join(guest_path.trim_start_matches('/'))
}

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

/// The desktop image's packages: a single-window Wayland compositor (`cage`, on wlroots), a
/// terminal for it, the seat daemon and udev the compositor finds its devices through, the keymaps
/// xkbcommon reads, and one font. No Mesa driver: the session renders with pixman.
const DESKTOP_PACKAGES: &[&str] = &[
    "cage",
    "foot",
    "seatd",
    "eudev",
    "xkeyboard-config",
    "font-dejavu",
];

/// Where the desktop image carries its session program, on the guest's default `PATH`.
pub(crate) const SESSION_PATH: &str = "/usr/local/bin/bsx-session";

/// One guest image: its name under `artifacts/`, what goes into it beyond the base and the agent,
/// and the ceiling it is held to.
pub(crate) struct ImageSpec {
    /// The directory under `artifacts/`, and what a person calls it.
    pub(crate) name: &'static str,
    /// The `build-rootfs` flags that select it, for the re-exec under `fakeroot`.
    flags: &'static [&'static str],
    /// The Alpine repositories `apk` resolves against, in order.
    repos: &'static [&'static str],
    /// The packages installed on top of the base.
    packages: &'static [&'static str],
    /// Programs this builder writes into the tree beyond the agent: guest path and contents,
    /// mode 0755.
    programs: &'static [(&'static str, &'static str)],
    /// Paths a package must have provided, checked before the tree is published.
    required: &'static [&'static str],
    /// The footprint ceiling.
    budget_mib: u64,
    /// The committed lockfile's name under `xtask/`.
    lock: &'static str,
}

/// The headless image every verb boots by default.
pub(crate) const GUEST: ImageSpec = ImageSpec {
    name: "rootfs-guest",
    flags: &[],
    repos: &["main"],
    packages: GUEST_PACKAGES,
    programs: &[],
    required: &[],
    budget_mib: ROOTFS_BUDGET_MIB,
    lock: "rootfs-packages.lock",
};

/// The desktop image: `bsx run --display WxH --root artifacts/rootfs-desktop -- bsx-session`
/// boots to a terminal in a Wayland session.
pub(crate) const DESKTOP: ImageSpec = ImageSpec {
    name: "rootfs-desktop",
    flags: &["--desktop"],
    repos: &["main", "community"],
    packages: DESKTOP_PACKAGES,
    programs: &[(SESSION_PATH, include_str!("../guest/bsx-session"))],
    required: &[
        "/usr/bin/cage",
        "/usr/bin/foot",
        "/usr/bin/seatd",
        "/sbin/udevd",
        "/bin/udevadm",
    ],
    budget_mib: DESKTOP_BUDGET_MIB,
    lock: "rootfs-desktop-packages.lock",
};

/// Every image, for the `vendor` snapshot that has to carry both closures.
pub(crate) const IMAGES: &[&ImageSpec] = &[&GUEST, &DESKTOP];

/// The pinned Alpine minirootfs, a real musl+busybox userland (so init and a shell just work, and
/// `apk` adds the [`GUEST_PACKAGES`] runtimes).
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
///
/// **Mirrored, because the upstream URL expires.** An Alpine branch repo carries only the newest revision
/// of each package, so a pinned `pkg-ver-rN` filename 404s the day upstream publishes the next one,
/// breaking every fresh clone while cached hosts keep building. The version cannot float either, since
/// this is the installer itself and the sha256 is the only thing between a fresh clone and executing an
/// unverified binary as part of the build.
///
/// The mirror is the `build-inputs` pre-release, so it stays out of `releases/latest`, which
/// `install.sh` reads. The sha256 below is upstream's, so the copy is checkable against Alpine rather than
/// trusted on this repo's say-so:
/// `https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/apk-tools-static-3.0.7-r0.apk`, GPL-2.0-only
/// with source at `https://gitlab.alpinelinux.org/alpine/apk-tools`. The asset carries a `.tgz` extension
/// because GitHub's uploader rejects `.apk`, and an `.apk` *is* a gzip-compressed tar, so the bytes are
/// untouched.
///
/// Bumping it means uploading the new revision to that release and putting the filename and `sha256sum`
/// here, then rebuilding: the installer writes the package database the guest image hashes over.
pub(crate) fn apk_tools_artifact() -> Result<Artifact> {
    let dir = artifacts_dir();
    match std::env::consts::ARCH {
        "x86_64" => Ok(Artifact {
            url: "https://github.com/kendricklawton/behavioral-sandbox/releases/download/build-inputs/\
                  apk-tools-static-3.0.7-r0.tgz"
                .to_string(),
            sha256: "ed1c5e82177844249b7c4ecc2653b78eed096be20496b7fb860a9e165b2e5ce1",
            dest: dir.join("apk-tools-static.apk"),
        }),
        other => bail!("no pinned apk-tools-static for arch {other} yet (x86_64 only)"),
    }
}

/// One full rootfs assembly into `out_dir`: extract the pinned Alpine base, install the guest
/// packages, and bake the static agent in. The product is a **directory tree**, which is what
/// libkrun's virtiofs root takes; there is no image and nothing here needs root or a loopback.
/// Returns the tree's hash and the resolved package closure, so [`build_rootfs`] can check
/// reproducibility.
fn assemble_rootfs(image: &ImageSpec, out_dir: &Path) -> Result<RootfsBuild> {
    let agent = build_guest_agent()?;

    let base = alpine_artifact()?;
    fetch_one(&base)?;

    let dir = artifacts_dir();
    // Per-pid staging so two concurrent `xtask` invocations (or a build racing a `--verify`
    // rebuild) don't extract into and clean the same scratch tree. Removed at the end of a
    // successful build; a crashed run leaves at most one stale `rootfs-staging.<pid>` under the
    // gitignored `artifacts/`.
    let staging = dir.join(format!("rootfs-staging.{}", std::process::id()));
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
    install_guest_packages(image, &staging)?;

    // Bake the static agent in at the path the init line respawns.
    let agent_dest = in_staging(&staging, GUEST_AGENT_PATH);
    if let Some(bindir) = agent_dest.parent() {
        std::fs::create_dir_all(bindir)?;
    }
    std::fs::copy(&agent, &agent_dest)
        .with_context(|| format!("copy agent into {}", agent_dest.display()))?;
    set_mode_0755(&agent_dest)?;

    // The image's own programs, from this repo rather than a package.
    for (guest_path, contents) in image.programs {
        let dest = in_staging(&staging, guest_path);
        if let Some(dir) = dest.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&dest, contents)
            .with_context(|| format!("write {guest_path} into the staged tree"))?;
        set_mode_0755(&dest)?;
    }

    // The mount point every run's results directory lands on (`bsx_record::RESULTS_GUEST_PATH`):
    // the root is read-only, so a directory the mount preamble needs has to be in the image.
    std::fs::create_dir_all(in_staging(&staging, "/results"))?;

    // Last gate before the tree is published: everything the guest depends on is present, at the
    // mode it needs.
    verify_guest_contract(image, &staging)?;
    verify_staged_ownership(&staging)?;

    // Record the resolved package closure while the apk db is still in the tree, then drop the db
    // and the caches: they are build bookkeeping, not part of the image a guest boots.
    let packages = resolved_packages(&staging)?;
    for scratch in ["var/cache/apk", "etc/apk/cache"] {
        let _ = std::fs::remove_dir_all(staging.join(scratch));
    }

    // Rename last, so the canonical path only ever names a fully-staged tree. A crashed build
    // leaves an obvious `rootfs-staging.<pid>` under the gitignored `artifacts/` instead of a
    // half-populated tree at the path every consumer reads.
    let tree_sha256 = tree_sha256(&staging)?;
    if out_dir.exists() {
        std::fs::remove_dir_all(out_dir).with_context(|| format!("clear {}", out_dir.display()))?;
    }
    std::fs::rename(&staging, out_dir).with_context(|| {
        format!(
            "move the built rootfs into place: {} -> {}",
            staging.display(),
            out_dir.display()
        )
    })?;

    Ok(RootfsBuild {
        tree_sha256,
        packages,
    })
}

/// A single hash over the whole staged tree: one `mode kind sha256-or-target path` line per entry,
/// sorted by path, hashed. This is what `--verify` compares, so it has to cover everything a guest
/// can observe, which a hash of file *contents* alone would not: an exec bit dropped from the agent,
/// or a symlink retargeted, changes the image without changing any file's bytes.
///
/// Directories contribute their mode and nothing else; their membership is already implied by the
/// paths beneath them.
fn tree_sha256(root: &Path) -> Result<String> {
    use std::os::unix::fs::PermissionsExt;

    let mut entries: Vec<PathBuf> = Vec::new();
    walk_tree(root, &mut entries)?;
    entries.sort();
    let mut manifest = String::new();
    for path in &entries {
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned();
        // `symlink_metadata`, never `metadata`: the resolver link points at a runtime procfs path
        // that does not exist in the tree, and following it would error on a legitimate image.
        let meta =
            std::fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
        let mode = meta.permissions().mode() & 0o7777;
        let (kind, body) = if meta.is_symlink() {
            let target = std::fs::read_link(path)
                .with_context(|| format!("read link {}", path.display()))?;
            ("l", target.to_string_lossy().into_owned())
        } else if meta.is_dir() {
            ("d", String::new())
        } else {
            ("f", sha256_of(path)?)
        };
        manifest.push_str(&format!("{mode:04o} {kind} {body} {rel}\n"));
    }
    let manifest_file = root.with_extension("manifest");
    std::fs::write(&manifest_file, &manifest)
        .with_context(|| format!("write {}", manifest_file.display()))?;
    let hash = sha256_of(&manifest_file)?;
    let _ = std::fs::remove_file(&manifest_file);
    Ok(hash)
}

/// Every path under `root` (files, dirs and symlinks), depth-first. A symlink is recorded, never
/// followed, so a link out of the tree cannot pull the host's filesystem into the hash.
fn walk_tree(root: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(root).with_context(|| format!("read {}", root.display()))? {
        let path = entry
            .with_context(|| format!("read an entry of {}", root.display()))?
            .path();
        let meta =
            std::fs::symlink_metadata(&path).with_context(|| format!("stat {}", path.display()))?;
        out.push(path.clone());
        if meta.is_dir() {
            walk_tree(&path, out)?;
        }
    }
    Ok(())
}

/// The guest-image contract, checked against the staged tree before it is published.
/// Reads back the same constants the writes above use, so a rename applied to only one of a path's
/// two places (the file, and the init line or command line naming it) fails the build here instead
/// of producing an image that boots into something absent.
///
/// It proves the staged tree carries what the constants promise at the modes the guest needs.
/// It does not prove the image *boots*, since nothing here runs a kernel, and nothing in the tree
/// does today.
///
/// The staged tree has to be owned by uid/gid **0**, which is what the Alpine tarball ships and what a
/// guest expects of its own `/`. Unprivileged `tar` cannot set ownership, so without the `fakeroot`
/// re-exec the tree hash depends on who ran the build, which the
/// reproducibility check cannot see: it builds twice inside one process and so compares two builds sharing
/// a uid.
///
/// Separate from [`verify_guest_contract`] on purpose. That one checks paths and content, and its unit
/// tests construct minimal trees as whoever runs `cargo test`; this checks a property of the *build
/// environment*, so it belongs on the build path rather than in a contract a fixture can satisfy.
fn verify_staged_ownership(staging: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let probe = GUEST_AGENT_PATH;
    let staged = in_staging(staging, probe);
    let meta = std::fs::metadata(&staged).with_context(|| format!("stat the staged {probe}"))?;
    let (uid, gid) = (meta.uid(), meta.gid());
    if (uid, gid) != (0, 0) {
        bail!(
            "the staged {probe} is {uid}:{gid}, not 0:0, so the tree would carry the builder's \
             identity and hash differently than the same source built by anyone else. \
             `build_rootfs` re-execs under `fakeroot` to arrange this; reaching here means that \
             did not happen."
        );
    }
    Ok(())
}

fn verify_guest_contract(image: &ImageSpec, staging: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // The consequence travels with the check, so a failure explains itself to whoever renamed
    // something rather than just naming a file.
    let path = GUEST_AGENT_PATH;
    let consequence = "a guest would come up with no exec channel, so every run would hang \
                       waiting for the readiness marker";
    let staged = in_staging(staging, path);
    let meta = std::fs::metadata(&staged).with_context(|| {
        format!("guest-image contract: {path} is missing from the staged rootfs ({consequence})")
    })?;
    if !meta.is_file() {
        bail!("guest-image contract: {path} is not a regular file ({consequence})");
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o755 {
        bail!(
            "guest-image contract: {path} is mode {mode:04o}, not 0755, so the guest cannot \
             execute it ({consequence})"
        );
    }
    // The agent's pty path spawns through `setsid -c`, the session/ctty step its
    // `#![forbid(unsafe_code)]` cannot take between fork and exec. Present as a symlink into
    // busybox on Alpine, so this asks for existence, not a file kind.
    let setsid = "/usr/bin/setsid";
    if !in_staging(staging, setsid).exists() {
        bail!(
            "guest-image contract: {setsid} is missing from the staged rootfs (the agent's pty \
             sessions spawn through it; `bsx shell` would get a refusal for every command)"
        );
    }
    for path in image.required {
        if !in_staging(staging, path).exists() {
            bail!(
                "guest-image contract: {path} is missing from the staged {} tree (a package the \
                 image lists no longer provides it)",
                image.name
            );
        }
    }
    for (path, _) in image.programs {
        let mode = std::fs::metadata(in_staging(staging, path))
            .with_context(|| format!("guest-image contract: {path} was not written"))?
            .permissions()
            .mode()
            & 0o777;
        if mode != 0o755 {
            bail!("guest-image contract: {path} is mode {mode:04o}, not 0755");
        }
    }
    Ok(())
}

/// The result of one rootfs assembly: the tree's hash ([`tree_sha256`]) and the exact resolved
/// package closure (sorted `name-version-rN`), the two things a reproducibility check compares.
struct RootfsBuild {
    tree_sha256: String,
    packages: Vec<String>,
}

/// `cargo xtask build-rootfs [--verify] [--update-lock]`. The default (no flags) is one command: it
/// assembles the deterministic guest tree and prints its hash. `--update-lock` re-records the
/// package lockfile (the "re-pin" after an upstream bump); `--verify` proves reproducibility, a
/// second build must hash identically. Every mode reports package-closure drift and none fails on
/// it, so an Alpine bump never costs a gate run.
/// Re-exec this xtask under `fakeroot` when the caller is unprivileged, returning `true` if it ran
/// the build in a child (so the caller should stop).
///
/// The guest rootfs must be owned by uid/gid **0**, what the Alpine tarball ships and what a guest expects
/// of its own `/`. Unprivileged `tar` cannot set ownership and `tar --owner` does not override it, so an
/// unprivileged build without this yields a tree owned by the builder's uid and a hash that depends on
/// who ran it.
///
/// One `fakeroot` has to wrap the *whole* assembly rather than each command, because the faked ownership
/// lives in one process's bookkeeping, so extracting under one invocation and staging under
/// another loses it. `FAKEROOTKEY` is set inside a session, which is what stops this recursing.
fn reexec_under_fakeroot_if_needed(
    image: &ImageSpec,
    verify: bool,
    update_lock: bool,
) -> Result<bool> {
    if crate::effective_uid()? == 0 || std::env::var_os("FAKEROOTKEY").is_some() {
        return Ok(false);
    }
    if crate::dev_tool_path("fakeroot").is_none() {
        bail!(
            "building the guest rootfs unprivileged needs `fakeroot`, so the image is owned by \
             uid 0 rather than by you (an image owned by uid {} boots but is not the image anyone \
             else builds). Install fakeroot, or run this under sudo.",
            crate::effective_uid()?
        );
    }
    let exe = std::env::current_exe().context("locate the xtask binary to re-exec")?;
    // Re-exec **only the rootfs build**, reconstructed from this call's own arguments, never the
    // caller's argv. Replaying argv re-runs whatever invoked us: under `dist` the child ran the
    // entire packaging (eBPF object, musl binary, stage, tar), the parent then ran steps 3 to 5 a
    // second time on top of it, and the two tarballs differed. Only this build needs uid 0.
    let mut args: Vec<&str> = vec!["build-rootfs"];
    if verify {
        args.push("--verify");
    }
    if update_lock {
        args.push("--update-lock");
    }
    args.extend(image.flags.iter().copied());
    println!("  (re-exec under fakeroot: the guest rootfs must be uid 0)");
    let mut cmd_args: Vec<&std::ffi::OsStr> = vec![exe.as_os_str()];
    cmd_args.extend(args.iter().map(std::ffi::OsStr::new));
    crate::run_tool("fakeroot", &cmd_args).context("the fakeroot build failed")?;
    Ok(true)
}

pub(crate) fn build_rootfs(image: &ImageSpec, verify: bool, update_lock: bool) -> Result<()> {
    if reexec_under_fakeroot_if_needed(image, verify, update_lock)? {
        return Ok(());
    }
    let out = artifacts_dir().join(image.name);
    let build = assemble_rootfs(image, &out)?;
    println!(
        "\n✓ {} built (agent baked in): {}",
        image.name,
        out.display()
    );
    println!("  sha256: {} (over the tree manifest)", build.tree_sha256);

    // Keep the image small: report the real footprint and fail on bloat past the budget.
    let used_mib = tree_used_bytes(&out)? / (1024 * 1024);
    let budget = image.budget_mib;
    println!("  size:   {used_mib} MiB used / {budget} MiB budget");
    if used_mib > budget {
        bail!(
            "{} is over budget: {used_mib} MiB > {budget} MiB — keep the image small, or raise \
             its budget deliberately",
            image.name
        );
    }

    if update_lock {
        write_packages_lock(image, &build.packages)?;
        println!(
            "  ✓ recorded {} packages in {}",
            build.packages.len(),
            packages_lock_path(image).display()
        );
    } else {
        report_packages_lock_drift(image, &build.packages);
    }

    if verify {
        // Prove determinism: a second full build must produce an identical tree. Built to a temp
        // path so the canonical tree stays in place, and cleaned up on *every* path, before
        // propagating a build error, so a failed second build leaks nothing.
        let tmp = artifacts_dir().join(format!("{}.verify", image.name));
        let result = assemble_rootfs(image, &tmp);
        let _ = std::fs::remove_dir_all(&tmp);
        let again = result?;
        if again.tree_sha256 != build.tree_sha256 {
            bail!(
                "rootfs build is NOT reproducible — two builds differ:\n  {}\n  {}",
                build.tree_sha256,
                again.tree_sha256
            );
        }
        println!("  ✓ reproducible: two builds hash identically");
    }

    println!(
        "  the tree is a virtiofs root: the supervisor that boots one is `scratch/ROADMAP.md` \
         phase 2"
    );
    Ok(())
}

/// Real (non-sparse) bytes the staged tree occupies, matching `du`, so the budget is measured
/// against what a host actually stores rather than an apparent size.
fn tree_used_bytes(root: &Path) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;
    let mut paths = Vec::new();
    walk_tree(root, &mut paths)?;
    let mut total = 0u64;
    for p in &paths {
        let meta = std::fs::symlink_metadata(p).with_context(|| format!("stat {}", p.display()))?;
        total = total.saturating_add(meta.blocks().saturating_mul(512));
    }
    Ok(total)
}

/// The committed lockfile recording the exact guest package closure. Lives next to the build
/// code, **not** in the gitignored `artifacts/`, so it's version-controlled and a diff shows
/// exactly when Alpine's branch repo moved a package under the floating install.
fn packages_lock_path(image: &ImageSpec) -> PathBuf {
    workspace_root().join("xtask").join(image.lock)
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
fn write_packages_lock(image: &ImageSpec, packages: &[String]) -> Result<()> {
    let path = packages_lock_path(image);
    let flags = image
        .flags
        .iter()
        .map(|f| format!("{f} "))
        .collect::<String>();
    let mut body = format!(
        "# Resolved guest image package closure: the exact Alpine packages baked into\n\
         # artifacts/{}. Regenerate after an upstream bump with:\n\
         #   cargo xtask build-rootfs {flags}--update-lock\n\
         # Drift from this list means Alpine's branch repo moved and the image no longer reproduces.\n",
        image.name
    );
    for p in packages {
        body.push_str(p);
        body.push('\n');
    }
    std::fs::write(&path, body).with_context(|| format!("write {}", path.display()))
}

/// Report how the freshly-resolved closure differs from the committed lockfile, naming each package
/// that moved. Never fatal: an Alpine bump is upstream's timing, not a defect in the tree, and
/// failing here costs a whole gate run without producing a reviewed image (the build already
/// resolved fresh from the branch either way). `.github/workflows/rootfs-packages.yml` is the
/// enforcer, where re-pinning is a person reading the diff.
fn report_packages_lock_drift(image: &ImageSpec, built: &[String]) {
    let path = packages_lock_path(image);
    let flags = image
        .flags
        .iter()
        .map(|f| format!("{f} "))
        .collect::<String>();
    let Ok(text) = std::fs::read_to_string(&path) else {
        println!(
            "  ! no package lockfile at {} — run `cargo xtask build-rootfs {flags}--update-lock`",
            path.display()
        );
        return;
    };
    let recorded: Vec<String> = text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(str::to_string)
        .collect();
    if let Some(drift) = lock_drift(&recorded, built) {
        println!(
            "  ! guest package closure drifted from {} (Alpine bumped a package):\n{drift}  \
             run `cargo xtask build-rootfs {flags}--update-lock` and commit the lockfile to re-pin",
            path.display()
        );
    }
}

/// The packages that differ between the committed lockfile and this build, as `-` (recorded) and
/// `+` (built) lines, or `None` when the two match. Names what moved, so a gate log answers "which
/// package" without a reader diffing the lockfile by hand.
fn lock_drift(recorded: &[String], built: &[String]) -> Option<String> {
    let mut lines = String::new();
    for p in recorded {
        if !built.contains(p) {
            lines.push_str(&format!("      - {p}\n"));
        }
    }
    for p in built {
        if !recorded.contains(p) {
            lines.push_str(&format!("      + {p}\n"));
        }
    }
    (!lines.is_empty()).then_some(lines)
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
/// root, no host `apk`. Vendor-aware: with `BSX_VENDOR_DIR` set it installs offline from the
/// vendored apk cache, otherwise it fetches from the pinned Alpine CDN. The `.apk` is a tarball; its
/// `sbin/apk.static` is extracted to a scratch dir removed after the install (the packages land in
/// `staging`, the tool is ephemeral).
fn install_guest_packages(image: &ImageSpec, staging: &Path) -> Result<()> {
    if image.packages.is_empty() {
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
    let result = run_apk_add(&apk, staging, &source, image);

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

/// Extract the pinned static `apk` from its (already-fetched) tarball into
/// `<scratch_base>/apk-tools.<pid>`, returning `(tooldir, apk_static_path)`. The caller removes
/// `tooldir` when done, the tool is ephemeral, the packages it installs are the product.
/// `scratch_base` is caller-chosen so the `vendor` command keeps its scratch inside the mirror dir,
/// not the workspace `artifacts/`. The dir is per-pid (like the `rootfs-staging.<pid>` tree) so two
/// concurrent builds can't `remove_dir_all` each other's tool mid-`apk`.
fn extract_apk_static(tools_tar: &Path, scratch_base: &Path) -> Result<(PathBuf, PathBuf)> {
    let tooldir = scratch_base.join(format!("apk-tools.{}", std::process::id()));
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

/// The `--root`, `--arch` and `--repository` arguments every `apk.static` call for `image` starts
/// with. The host's arch, not a literal: Alpine's arch names match Rust's for the arches we pin
/// (x86_64/aarch64), and the pinned-artifact fns bail on anything unpinned, so this stays correct
/// by itself when a second arch lands, not silently installing x86_64 into an aarch64 image.
fn apk_base_args(image: &ImageSpec, staging: &Path) -> Vec<OsString> {
    let mut args = vec![
        OsString::from("--root"),
        staging.as_os_str().to_owned(),
        OsString::from("--arch"),
        OsString::from(std::env::consts::ARCH),
    ];
    for repo in image.repos {
        args.push(OsString::from("--repository"));
        args.push(OsString::from(format!(
            "https://dl-cdn.alpinelinux.org/alpine/{ALPINE_BRANCH}/{repo}"
        )));
    }
    args
}

/// Run `apk.static add` for the image's packages into `staging`, sourced per [`ApkSource`]. The
/// package set, arch, and repos are identical across sources, only the fetch/cache flags differ, so
/// the resolved closure (and thus [`resolved_packages`]) is the same whether built online or from the
/// vendored cache, keeping the lockfile contract intact.
fn run_apk_add(apk: &Path, staging: &Path, source: &ApkSource, image: &ImageSpec) -> Result<()> {
    let mut args = apk_base_args(image, staging);
    args.push(OsString::from("--no-scripts"));
    match source {
        // `--no-cache`: don't leave apk's cache behind on an ordinary online build.
        ApkSource::Network => args.push(OsString::from("--no-cache")),
        // `--no-network`: install purely from the vendored cache (the sha-pinned closure + index).
        ApkSource::VendorCache(dir) => {
            args.push(OsString::from("--cache-dir"));
            args.push(absolute(dir)?.into_os_string());
            args.push(OsString::from("--no-network"));
        }
        // Online, but keep every fetched `.apk` + the index in the cache dir, the vendor snapshot.
        ApkSource::PopulateCache(dir) => {
            args.push(OsString::from("--cache-dir"));
            args.push(absolute(dir)?.into_os_string());
        }
    }
    args.push(OsString::from("add"));
    args.extend(image.packages.iter().map(|p| OsString::from(*p)));

    let apk_str = apk.to_string_lossy().into_owned();
    let arg_refs: Vec<&OsStr> = args.iter().map(OsString::as_os_str).collect();
    run_tool(&apk_str, &arg_refs)
}

/// `apk.static update` into `cache_dir`, fetch + cache the repo's `APKINDEX` so a later offline
/// `add --no-network` can resolve against it. A plain `add --cache-dir` caches the packages it pulls
/// but not necessarily the index, so the vendor snapshot seeds it explicitly.
fn run_apk_update(apk: &Path, staging: &Path, cache_dir: &Path, image: &ImageSpec) -> Result<()> {
    let mut args = apk_base_args(image, staging);
    args.push(OsString::from("--cache-dir"));
    args.push(absolute(cache_dir)?.into_os_string());
    args.push(OsString::from("update"));
    let apk_str = apk.to_string_lossy().into_owned();
    let arg_refs: Vec<&OsStr> = args.iter().map(OsString::as_os_str).collect();
    run_tool(&apk_str, &arg_refs)
}

/// Make `path` absolute (against the current dir, `xtask` runs from the workspace root). apk
/// resolves a *relative* `--cache-dir` against its `--root`, which would put the cache inside the
/// staging tree instead of where the packages actually live, so every cache path handed to apk goes
/// through here first.
fn absolute(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    // Propagate a `current_dir` failure: silently returning the relative path would reintroduce the
    // exact apk-resolves-cache-inside-staging bug this function exists to prevent.
    let cwd = std::env::current_dir()
        .context("resolving the current dir to make an apk cache path absolute")?;
    Ok(cwd.join(path))
}

/// Populate a vendored apk cache with the resolved guest-package closure (the `.apk` files **and**
/// the `APKINDEX`) by running one **online** `apk add` into a throwaway root. Called by
/// `cargo xtask vendor`; afterwards an offline build installs from this cache (`--no-network`), so a
/// fresh host never touches the Alpine CDN, the one hardening the reproducible-rootfs build had
/// deferred. The
/// throwaway root exists only so apk has the base's `/etc/apk/keys` to verify signatures against; it
/// is removed, leaving just the cache. `base_tar`/`apk_tools_tar` are the (already sha-verified)
/// vendored tarballs, so this reuses them rather than re-downloading.
pub(crate) fn populate_apk_cache(
    cache_dir: &Path,
    base_tar: &Path,
    apk_tools_tar: &Path,
) -> Result<()> {
    for image in IMAGES {
        populate_apk_cache_for(image, cache_dir, base_tar, apk_tools_tar)?;
    }
    Ok(())
}

/// One image's closure into the shared cache: the `.apk` files are per package and the index per
/// repository, so two images' snapshots overlap where their closures do.
fn populate_apk_cache_for(
    image: &ImageSpec,
    cache_dir: &Path,
    base_tar: &Path,
    apk_tools_tar: &Path,
) -> Result<()> {
    if image.packages.is_empty() {
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
    let result = run_apk_update(&apk, &staging, cache_dir, image)
        .and_then(|()| run_apk_add(&apk, &staging, &ApkSource::PopulateCache(cache_dir), image));
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

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use super::{GUEST, GUEST_AGENT_PATH, in_staging, lock_drift, verify_guest_contract};

    /// The drift report is the whole of what a gate log says about an Alpine bump, so it names the
    /// packages that moved rather than only that something did: a version bump reads as one `-`/`+`
    /// pair, and a package entering or leaving the closure reads as a lone `+` or `-`. A report
    /// naming nothing leaves a reader diffing the lockfile by hand to find which.
    #[test]
    fn the_drift_report_names_what_moved() {
        let recorded = [
            "libexpat-2.8.2-r0".to_string(),
            "python3-3.14.5-r0".to_string(),
        ];
        let built = [
            "expat-2.8.2-r0".to_string(),
            "libexpat-2.8.2-r0".to_string(),
            "python3-3.14.7-r0".to_string(),
        ];

        assert_eq!(lock_drift(&recorded, &recorded), None);

        let drift = lock_drift(&recorded, &built).expect("the closures differ");
        assert!(drift.contains("- python3-3.14.5-r0"), "{drift}");
        assert!(drift.contains("+ python3-3.14.7-r0"), "{drift}");
        assert!(drift.contains("+ expat-2.8.2-r0"), "{drift}");
        // The package both sides share must not appear, or every bump reprints the whole closure.
        assert!(!drift.contains("libexpat"), "{drift}");
    }

    /// A per-test scratch tree, removed on drop so a failing assertion can't leave one behind.
    fn temp_dir(name: &str) -> bsx_test_support::ScratchDir {
        bsx_test_support::ScratchDir::created(&format!("contract-{name}"))
    }

    /// A staging tree that satisfies the contract: the agent at 0755. Each negative test breaks
    /// exactly one thing from here, so what it proves is that *that* fault is what the check
    /// catches.
    fn good_staging(root: &Path) {
        let staged = in_staging(root, GUEST_AGENT_PATH);
        std::fs::create_dir_all(staged.parent().expect("the agent path has a parent")).unwrap();
        std::fs::write(&staged, "#!/bin/sh\n").unwrap();
        let mut perms = std::fs::metadata(&staged).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&staged, perms).unwrap();
        let setsid = in_staging(root, "/usr/bin/setsid");
        std::fs::create_dir_all(setsid.parent().expect("the setsid path has a parent")).unwrap();
        std::fs::write(&setsid, "").unwrap();
    }

    #[test]
    fn a_complete_staging_tree_satisfies_the_contract() {
        let tmp = temp_dir("ok");
        good_staging(tmp.path());
        verify_guest_contract(&GUEST, tmp.path())
            .expect("a fully staged tree satisfies the contract");
    }

    #[test]
    fn a_missing_agent_names_itself_and_its_consequence() {
        let tmp = temp_dir("missing");
        good_staging(tmp.path());
        std::fs::remove_file(in_staging(tmp.path(), GUEST_AGENT_PATH)).unwrap();
        let err = verify_guest_contract(&GUEST, tmp.path())
            .expect_err("a missing agent must fail the build")
            .to_string();
        assert!(err.contains(GUEST_AGENT_PATH), "{err}");
        assert!(err.contains("no exec channel"), "{err}");
    }

    #[test]
    fn an_unexecutable_agent_is_caught_before_it_ships() {
        let tmp = temp_dir("mode");
        good_staging(tmp.path());
        // The exact fault a forgotten `set_mode_0755` produces: the file is there, so an
        // existence-only check would pass it, and the guest would fail at exec time instead.
        let staged = in_staging(tmp.path(), GUEST_AGENT_PATH);
        let mut perms = std::fs::metadata(&staged).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&staged, perms).unwrap();
        let err = verify_guest_contract(&GUEST, tmp.path())
            .expect_err("a non-executable agent must fail the build")
            .to_string();
        assert!(err.contains("0644"), "{err}");
        assert!(err.contains("cannot"), "{err}");
    }

    /// The tree hash has to see a mode change, not just content: an agent that lost its exec bit is
    /// byte-identical and would slip past a contents-only hash, which is exactly the drift
    /// `--verify` exists to catch.
    #[test]
    fn the_tree_hash_moves_when_only_a_mode_moves() {
        let tmp = temp_dir("hash-mode");
        good_staging(tmp.path());
        let before = super::tree_sha256(tmp.path()).expect("hash the staged tree");
        let staged = in_staging(tmp.path(), GUEST_AGENT_PATH);
        let mut perms = std::fs::metadata(&staged).unwrap().permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&staged, perms).unwrap();
        let after = super::tree_sha256(tmp.path()).expect("hash the staged tree again");
        assert_ne!(before, after, "a mode change must move the tree hash");
    }

    /// And a symlink's *target*, for the same reason: retargeting a link changes nothing's bytes.
    #[test]
    fn the_tree_hash_moves_when_a_symlink_is_retargeted() {
        let tmp = temp_dir("hash-link");
        good_staging(tmp.path());
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink("/one", &link).unwrap();
        let before = super::tree_sha256(tmp.path()).expect("hash the staged tree");
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink("/two", &link).unwrap();
        let after = super::tree_sha256(tmp.path()).expect("hash the staged tree again");
        assert_ne!(
            before, after,
            "a retargeted symlink must move the tree hash"
        );
    }
}
