//! The bulk input/output block devices (P3.4/P3.5): build their ext4 images rootless
//! (`mke2fs -d`), and read the output tree back from an untrusted image safely (fsck'd, bounded,
//! symlink-sanitized) after the guest is dead.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The filesystem labels the driver stamps on the data devices so the guest mounts them by label,
/// not by enumeration-order `/dev/vdX` (a boot may attach input, output, both, or neither). Defined
/// in `agent-channel` — the one host↔guest contract both the driver and the rootfs build consume.
use agent_channel::{INPUT_LABEL, OUTPUT_LABEL};

use crate::paths::path_str;
use crate::VmmError;

/// Size of the blank writable output image (P3.5). A fixed cap for now — it's the natural bulk-output
/// bound (the guest can't write more than the filesystem holds), mirroring the channel path's
/// [`MAX_EXEC_OUTPUT`]. Built with `lazy_itable_init=0` so the guest kernel never balloons the
/// metadata: a fresh image is ~a few MiB of real host blocks, growing only with what's written.
const OUTPUT_IMAGE_MIB: u32 = 256;

/// Hard ceiling on the **real host bytes** [`RunningVm::collect_outputs`] will write while extracting
/// the output image. `debugfs rdump` materialises filesystem holes as zeros, so a hostile guest could
/// stage a sparse file with a huge logical size inside the capped image and inflate the readback — a
/// watcher aborts once the extracted tree's allocated blocks pass this bound. Generous headroom over
/// [`OUTPUT_IMAGE_MIB`] (a legitimate tree's real bytes can't exceed the image), so only abuse trips.
const OUTPUT_EXTRACT_CAP: u64 = 2 * (OUTPUT_IMAGE_MIB as u64) * 1024 * 1024; // 512 MiB

/// Wall-clock bound on the output readback (`e2fsck` + `debugfs rdump`), so a pathological image can
/// never hang the host teardown. Read-back is off the boot path; generous is fine.
const OUTPUT_READBACK_TIMEOUT: Duration = Duration::from_secs(120);
/// A booted VM's writable output device: the ext4 image the guest mounts at `/output`, and the host
/// directory its tree is extracted into on [`RunningVm::collect_outputs`].
#[derive(Debug, Clone)]
pub(crate) struct OutputDevice {
    pub(crate) image: PathBuf,
    pub(crate) dest: PathBuf,
}
/// Build a read-only ext4 from `src_dir` for the bulk-input block device (P3.4), populated
/// **rootless** via `mke2fs -d` (no loopback, no `sudo`). Sized from the tree's byte total with
/// slack and given enough inodes for its file count; the image lands in `workdir` (the per-VM
/// scratch dir) so teardown reclaims it. Returns the image path.
pub(crate) fn build_input_image(src_dir: &Path, workdir: &Path) -> Result<PathBuf, VmmError> {
    require_dir(src_dir, "input directory")?;
    let (bytes, files) = measure_tree(src_dir)?;
    // ext4 has a small floor and `mke2fs` needs metadata headroom; over-sizing only wastes scratch
    // (reclaimed on teardown) while under-sizing fails the build, so size up generously. `-N` gives
    // enough inodes that many tiny files exhaust bytes before inodes.
    let size_mib = (bytes / (1024 * 1024) * 3 / 2).max(8) + 8;
    let inodes = files + 256;

    let image = workdir.join("input.ext4");
    run_host_tool(
        "truncate",
        &[
            OsStr::new("-s"),
            OsStr::new(&format!("{size_mib}M")),
            image.as_os_str(),
        ],
    )?;
    run_host_tool(
        "mke2fs",
        &[
            OsStr::new("-F"),
            OsStr::new("-q"),
            OsStr::new("-t"),
            OsStr::new("ext4"),
            OsStr::new("-m"),
            OsStr::new("0"),
            OsStr::new("-N"),
            OsStr::new(&inodes.to_string()),
            // Label so the guest mounts by label, not `/dev/vdX` order (see `INPUT_LABEL`).
            OsStr::new("-L"),
            OsStr::new(INPUT_LABEL),
            OsStr::new("-d"),
            src_dir.as_os_str(),
            image.as_os_str(),
        ],
    )?;
    Ok(image)
}

/// Build a **blank, writable** ext4 for the bulk-output block device (P3.5), rootless via `mke2fs`.
/// No `-d` (nothing to seed) and `lazy_itable_init=0`/`lazy_journal_init=0` so the guest kernel never
/// lazily zeroes the inode table at runtime — that would balloon the sparse image toward its full
/// [`OUTPUT_IMAGE_MIB`] on the host regardless of how little the command writes. Labelled
/// [`OUTPUT_LABEL`] so the guest mounts it by label. The image lands in `workdir` (reclaimed on
/// teardown); [`RunningVm::collect_outputs`] reads it back after the VMM exits.
pub(crate) fn build_output_image(workdir: &Path) -> Result<PathBuf, VmmError> {
    let image = workdir.join("output.ext4");
    run_host_tool(
        "truncate",
        &[
            OsStr::new("-s"),
            OsStr::new(&format!("{OUTPUT_IMAGE_MIB}M")),
            image.as_os_str(),
        ],
    )?;
    run_host_tool(
        "mke2fs",
        &[
            OsStr::new("-F"),
            OsStr::new("-q"),
            OsStr::new("-t"),
            OsStr::new("ext4"),
            OsStr::new("-m"),
            OsStr::new("0"),
            OsStr::new("-L"),
            OsStr::new(OUTPUT_LABEL),
            OsStr::new("-E"),
            OsStr::new("lazy_itable_init=0,lazy_journal_init=0"),
            image.as_os_str(),
        ],
    )?;
    Ok(image)
}

/// One walk of `dir` for `(total_bytes, file_count)`, to size the input image. Bounded: an input
/// past a sane ceiling is a typed error, not a giant image. Symlinks are counted (each is an inode)
/// but not descended — `mke2fs -d` copies them verbatim, so a link resolves inside the *guest* fs,
/// never the host's, and there's no symlink-loop or host-escape via traversal.
fn measure_tree(dir: &Path) -> Result<(u64, u64), VmmError> {
    const MAX_INPUT_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB bulk-input ceiling
    let mut bytes = 0u64;
    let mut files = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d)
            .map_err(|e| VmmError::Artifact(format!("read input dir {}: {e}", d.display())))?;
        for entry in entries {
            let entry = entry.map_err(|e| VmmError::Artifact(format!("read input entry: {e}")))?;
            let ft = entry
                .file_type()
                .map_err(|e| VmmError::Artifact(format!("stat input entry: {e}")))?;
            if ft.is_dir() {
                stack.push(entry.path());
            } else {
                files += 1;
                if let Ok(meta) = entry.metadata() {
                    bytes = bytes.saturating_add(meta.len());
                }
            }
        }
        if bytes > MAX_INPUT_BYTES {
            return Err(VmmError::Artifact(format!(
                "input directory exceeds the {MAX_INPUT_BYTES}-byte bulk-input ceiling"
            )));
        }
    }
    Ok((bytes, files))
}

/// Like [`require_file`] but for a directory.
fn require_dir(path: &Path, what: &str) -> Result<(), VmmError> {
    if path.is_dir() {
        Ok(())
    } else {
        Err(VmmError::Artifact(format!(
            "{what} not found or not a directory: {}",
            path.display()
        )))
    }
}

/// Run a host build tool (`truncate`/`mke2fs`) for a data block device. A missing tool is a typed
/// [`VmmError::Artifact`] — the driver's only other external process is `firecracker`, so these are
/// real new runtime dependencies, surfaced clearly rather than as a cryptic spawn failure.
fn run_host_tool(program: &str, args: &[&OsStr]) -> Result<(), VmmError> {
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|e| tool_spawn_error(program, e))?;
    if !status.success() {
        return Err(VmmError::Vmm(format!(
            "{program} failed building a block device image"
        )));
    }
    Ok(())
}

/// Map a failure to spawn one of the driver's host helpers (`mke2fs`/`truncate`/`e2fsck`/`debugfs`
/// for the block devices, `ip` for the tap) to a typed error: a missing binary is a clear
/// [`VmmError::Artifact`] (install hint), anything else a [`VmmError::Vmm`].
pub(crate) fn tool_spawn_error(program: &str, e: std::io::Error) -> VmmError {
    if e.kind() == std::io::ErrorKind::NotFound {
        VmmError::Artifact(format!(
            "{program} not found (a host tool the driver shells out to — install e2fsprogs/coreutils/iproute2)"
        ))
    } else {
        VmmError::Vmm(format!("run {program}: {e}"))
    }
}

/// Read the writable output image back into the host `dest` directory, rootless. Ordered so the tree
/// is consistent and safe before it's returned: recover the journal (`e2fsck`), extract under a
/// byte/time cap (`debugfs rdump`), drop `lost+found`, neutralise host-escaping symlinks, then list
/// what survived. Called only after the VMM has exited (see [`RunningVm::collect_outputs`]).
pub(crate) fn collect_output_image(image: &Path, dest: &Path) -> Result<Vec<String>, VmmError> {
    std::fs::create_dir_all(dest)
        .map_err(|e| VmmError::Vmm(format!("create output dir {}: {e}", dest.display())))?;
    fsck_output_image(image)?;
    rdump_capped(image, dest, OUTPUT_EXTRACT_CAP, OUTPUT_READBACK_TIMEOUT)?;
    // Guest-controlled tree: drop the ext4 housekeeping dir and any symlink that would redirect a
    // later host read onto the host filesystem, before the caller (or its tooling) touches the files.
    let _ = std::fs::remove_dir_all(dest.join("lost+found"));
    sanitize_symlinks(dest)?;
    collect_paths(dest)
}

/// `e2fsck -fy` the image: force a full check and auto-answer, recovering the journal and clearing the
/// "not cleanly unmounted" state a hard-killed guest leaves, so `debugfs` sees a consistent tree. The
/// exit status is a bitmask — 0 clean, 1 errors corrected, 2 corrected + reboot advised (moot for an
/// image file); `>= 4` means errors left uncorrected or an operational failure, which is a real error.
fn fsck_output_image(image: &Path) -> Result<(), VmmError> {
    let status = Command::new("e2fsck")
        .arg("-fy")
        .arg(image)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| tool_spawn_error("e2fsck", e))?;
    match status.code() {
        Some(0) => Ok(()),
        // Errors were found and corrected (1) or corrected + reboot-advised (2): the tree is now
        // consistent, but a hard-killed guest's in-flight writes may have been rolled back with the
        // journal. Record it so a recovered output shows up in the flight recorder, not as pristine.
        Some(code) if code < 4 => {
            tracing::warn!(
                exit = code,
                "e2fsck corrected the output image before readback; captured artifacts may be missing the guest's last writes"
            );
            Ok(())
        }
        Some(code) => Err(VmmError::Vmm(format!(
            "e2fsck could not repair the output image (exit {code})"
        ))),
        None => Err(VmmError::Vmm("e2fsck terminated by a signal".into())),
    }
}

/// Extract the image tree into `dest` with `debugfs rdump`, bounded so a hostile guest can't blow up
/// the host. `debugfs` materialises filesystem holes as real zeros, so a sparse file staged in the
/// capped image could still inflate the readback — a poll loop aborts the extraction once `dest`'s
/// **allocated** bytes pass `byte_cap`, or once it outruns `timeout`. rdump prints benign
/// "changing ownership" warnings when run non-root (it can't chown to the guest's uids) and still
/// exits 0; those are ignored — only a non-zero exit or a tripped bound is an error.
fn rdump_capped(
    image: &Path,
    dest: &Path,
    byte_cap: u64,
    timeout: Duration,
) -> Result<(), VmmError> {
    // debugfs parses its `-R` request by whitespace, with no quoting — reject a whitespace dest
    // rather than silently truncate the path (the dest is operator-set, so this is a clear config
    // error, not a guest-reachable one).
    let dest_str = path_str(dest)?;
    if dest_str.chars().any(char::is_whitespace) {
        return Err(VmmError::Vmm(format!(
            "output dir path must not contain whitespace (debugfs -R limitation): {dest_str}"
        )));
    }
    let mut child = Command::new("debugfs")
        .arg("-R")
        .arg(format!("rdump / {dest_str}"))
        .arg(image)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| tool_spawn_error("debugfs", e))?;

    let deadline = Instant::now() + timeout;
    loop {
        let waited = match child.try_wait() {
            Ok(w) => w,
            Err(e) => {
                // Don't leak a live debugfs on a `wait` error: kill and reap before surfacing it.
                let _ = child.kill();
                let _ = child.wait();
                return Err(VmmError::Vmm(format!("wait on debugfs: {e}")));
            }
        };
        match waited {
            Some(status) => {
                return match status.code() {
                    Some(0) => Ok(()),
                    Some(code) => Err(VmmError::Vmm(format!("debugfs rdump failed (exit {code})"))),
                    None => Err(VmmError::Vmm("debugfs rdump terminated by a signal".into())),
                };
            }
            None => {
                if dir_alloc_bytes(dest) > byte_cap {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(VmmError::OutputCap {
                        limit: byte_cap.min(usize::MAX as u64) as usize,
                    });
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(VmmError::Timeout(
                        "output readback exceeded its deadline".into(),
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Sum of **allocated** bytes (`blocks * 512`, real host disk, not logical size) under `dir`. Walks
/// with `file_type`/`DirEntry::metadata` (both `lstat`-like), so a guest symlink is counted as the
/// link itself and never followed — the walk can't be lured onto the host filesystem while sizing.
fn dir_alloc_bytes(dir: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    let mut total = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            match entry.file_type() {
                Ok(ft) if ft.is_dir() => stack.push(entry.path()),
                Ok(_) => {
                    if let Ok(meta) = entry.metadata() {
                        total = total.saturating_add(meta.blocks().saturating_mul(512));
                    }
                }
                Err(_) => {}
            }
        }
    }
    total
}

/// Remove every symlink under `dest` whose target escapes `dest`. `debugfs rdump` recreates a guest
/// symlink verbatim as a **host** symlink, so an un-sanitised `link -> /etc/shadow` (or one that
/// climbs out with `..`) would make a later host read of the results read host files — the inverse of
/// the input side, where `mke2fs -d` resolves links inside the guest image. In-tree links (e.g.
/// `a -> sub/b`) are kept.
///
/// Containment is checked by **canonical resolution**, not lexically: a lexical `..`-depth count is
/// unsound because a kept in-tree symlink makes a `Normal` path component *not* descend a real level
/// — a guest can chain `d -> .` with `evil -> d/../../etc/shadow` to pass a lexical check while
/// resolving above `dest`. `Path::canonicalize` follows every intermediate link to the real target,
/// which we require to sit under the canonical `dest`; a target that doesn't resolve (dangling, or
/// pointing outside to a nonexistent path) can't be proven in-tree, so it's dropped. Safe from
/// TOCTOU: the VMM is already reaped and `dest` is host-private, so nothing mutates the tree
/// concurrently. The walk itself never traverses a symlink (`lstat`-like `file_type`), so it can't be
/// redirected onto the host mid-scan.
fn sanitize_symlinks(dest: &Path) -> Result<(), VmmError> {
    let root = dest
        .canonicalize()
        .map_err(|e| VmmError::Vmm(format!("canonicalize output dir {}: {e}", dest.display())))?;
    let mut stack = vec![dest.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d)
            .map_err(|e| VmmError::Vmm(format!("scan output dir {}: {e}", d.display())))?;
        for entry in entries {
            let entry = entry.map_err(|e| VmmError::Vmm(format!("read output entry: {e}")))?;
            let ft = entry
                .file_type()
                .map_err(|e| VmmError::Vmm(format!("stat output entry: {e}")))?;
            let path = entry.path();
            if ft.is_symlink() {
                // Follow the link (and any intermediate links) to a real path; keep only if it
                // stays within the canonical destination.
                let contained = path
                    .canonicalize()
                    .map(|real| real.starts_with(&root))
                    .unwrap_or(false);
                if !contained {
                    let target = std::fs::read_link(&path).unwrap_or_default();
                    std::fs::remove_file(&path).map_err(|e| {
                        VmmError::Vmm(format!("drop escaping symlink {}: {e}", path.display()))
                    })?;
                    tracing::warn!(
                        link = %path.display(),
                        target = %target.display(),
                        "dropped output symlink escaping the destination"
                    );
                }
            } else if ft.is_dir() {
                stack.push(path);
            }
        }
    }
    Ok(())
}

/// The captured tree as relative-path strings (files and surviving symlinks, directories descended),
/// sorted for a deterministic result. Purely a manifest of what `collect_outputs` produced.
fn collect_paths(dest: &Path) -> Result<Vec<String>, VmmError> {
    let mut out = Vec::new();
    let mut stack = vec![dest.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d)
            .map_err(|e| VmmError::Vmm(format!("list output dir {}: {e}", d.display())))?;
        for entry in entries {
            let entry = entry.map_err(|e| VmmError::Vmm(format!("read output entry: {e}")))?;
            let ft = entry
                .file_type()
                .map_err(|e| VmmError::Vmm(format!("stat output entry: {e}")))?;
            let path = entry.path();
            if ft.is_dir() {
                stack.push(path);
            } else if let Ok(rel) = path.strip_prefix(dest) {
                out.push(rel.to_string_lossy().into_owned());
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TestDir;

    #[test]
    fn sanitize_symlinks_drops_escapes_including_chained_intermediate_links() {
        use std::os::unix::fs::symlink;
        let dir = TestDir::new("agent-sanitize");
        let dest = dir.path();

        // A real file + a legitimate in-tree symlink to it: must survive.
        std::fs::write(dest.join("real.txt"), b"hi").expect("write real file");
        symlink("real.txt", dest.join("good")).expect("in-tree link");

        // A direct absolute escape (`link -> /etc/passwd`): must be dropped.
        symlink("/etc/passwd", dest.join("abs")).expect("absolute link");

        // The chained bypass that defeats a *lexical* check: `d -> .` makes `d` a `Normal` component
        // that doesn't descend a real level, so `evil -> d/../../…/etc/passwd` climbs above `dest` on
        // disk while a lexical `..`-depth count never goes negative. Must be dropped.
        symlink(".", dest.join("d")).expect("self link");
        symlink("d/../../../../../../etc/passwd", dest.join("evil")).expect("chained link");

        sanitize_symlinks(dest).expect("sanitize");

        assert!(dest.join("real.txt").exists(), "real file untouched");
        assert!(
            dest.join("good").symlink_metadata().is_ok(),
            "in-tree symlink should be kept"
        );
        assert!(
            dest.join("abs").symlink_metadata().is_err(),
            "absolute escape must be dropped"
        );
        assert!(
            dest.join("evil").symlink_metadata().is_err(),
            "chained intermediate-symlink escape must be dropped"
        );
    }

    #[test]
    fn output_dir_with_whitespace_is_rejected_before_debugfs() {
        // A whitespace dest would be split by debugfs's `-R` parser; catch it as a typed error rather
        // than silently truncating the extraction path. (No debugfs is spawned — the guard fires first.)
        let err = rdump_capped(
            Path::new("/nonexistent/img.ext4"),
            Path::new("/tmp/has a space"),
            OUTPUT_EXTRACT_CAP,
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(
            matches!(err, VmmError::Vmm(ref m) if m.contains("whitespace")),
            "got {err:?}"
        );
    }
}
