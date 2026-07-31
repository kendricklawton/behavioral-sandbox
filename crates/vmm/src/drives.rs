//! The bulk input/output block devices: build their ext4 images rootless
//! (`mke2fs -d`), and read the output tree back from an untrusted image safely (fsck'd, bounded,
//! symlink-sanitized) after the guest is dead.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// The filesystem labels the driver stamps on the data devices so the guest mounts them by label,
/// not by enumeration-order `/dev/vdX` (a boot may attach input, output, both, or neither). Defined
/// in `channel`, the one host↔guest contract both the driver and the rootfs build consume.
use channel::{INPUT_LABEL, OUTPUT_LABEL};

use crate::paths::path_str;
use crate::VmmError;

/// Size of the blank writable output image. A fixed cap for now, it's the natural bulk-output
/// bound (the guest can't write more than the filesystem holds), mirroring the channel path's
/// [`MAX_EXEC_OUTPUT`]. Built with `lazy_itable_init=0` so the guest kernel never balloons the
/// metadata: a fresh image is ~a few MiB of real host blocks, growing only with what's written.
const OUTPUT_IMAGE_MIB: u32 = 256;

/// Hard ceiling on the **real host bytes** [`RunningVm::collect_outputs`] will write while extracting
/// the output image. `debugfs rdump` materialises filesystem holes as zeros, so a hostile guest could
/// stage a sparse file with a huge logical size inside the capped image and inflate the readback, a
/// watcher aborts once the extracted tree's allocated blocks pass this bound. Generous headroom over
/// [`OUTPUT_IMAGE_MIB`] (a legitimate tree's real bytes can't exceed the image), so only abuse trips.
const OUTPUT_EXTRACT_CAP: u64 = 2 * (OUTPUT_IMAGE_MIB as u64) * 1024 * 1024; // 512 MiB

/// Wall-clock bound on the output readback (`e2fsck` + `debugfs rdump`), so a pathological image can
/// never hang the host teardown. Read-back is off the boot path; generous is fine.
const OUTPUT_READBACK_TIMEOUT: Duration = Duration::from_secs(120);
/// The readback tools' `wait_bounded` tick: off the boot path, so latency is cheap, and rdump's
/// over-budget callback walks the extracted tree each tick, so faster would cost real CPU.
const READBACK_POLL: Duration = Duration::from_millis(50);
/// How long a killed helper is given to be reaped before it is detached (see
/// [`kill_and_reap_briefly`]). Short: a killable child dies at once, and anything slower is the
/// D-state case, where waiting longer only lengthens the hang.
const HELPER_REAP_GRACE: Duration = Duration::from_millis(200);
/// How much of a readback helper's stderr is kept to name a failure. One screenful: enough for
/// e2fsprogs' one-line causes ("No space left on device"), small enough that a crafted image can't
/// make the *diagnostic* the expensive part.
const STDERR_TAIL_CAP: u64 = 4096;
/// A booted VM's writable output device: the ext4 image the guest mounts at `/output`, and the host
/// directory its tree is extracted into on [`RunningVm::collect_outputs`].
#[derive(Debug, Clone)]
pub(crate) struct OutputDevice {
    pub(crate) image: PathBuf,
    pub(crate) dest: PathBuf,
}
/// Build a read-only ext4 from `src_dir` for the bulk-input block device, populated
/// **rootless** via `mke2fs -d` (no loopback, no `sudo`). Sized from the tree's byte total with
/// slack and given enough inodes for its file count; the image lands in `workdir` (the per-VM
/// scratch dir) so teardown reclaims it. Returns the image path.
pub(crate) fn build_input_image(
    src_dir: &Path,
    workdir: &Path,
    deadline: Instant,
) -> Result<PathBuf, VmmError> {
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
        deadline,
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
        deadline,
    )?;
    Ok(image)
}

/// Build a **blank, writable** ext4 for the bulk-output block device, rootless via `mke2fs`.
/// No `-d` (nothing to seed) and `lazy_itable_init=0`/`lazy_journal_init=0` so the guest kernel never
/// lazily zeroes the inode table at runtime, that would balloon the sparse image toward its full
/// [`OUTPUT_IMAGE_MIB`] on the host regardless of how little the command writes. Labelled
/// [`OUTPUT_LABEL`] so the guest mounts it by label. The image lands in `workdir` (reclaimed on
/// teardown); [`RunningVm::collect_outputs`] reads it back after the VMM exits.
pub(crate) fn build_output_image(workdir: &Path, deadline: Instant) -> Result<PathBuf, VmmError> {
    let image = workdir.join("output.ext4");
    run_host_tool(
        "truncate",
        &[
            OsStr::new("-s"),
            OsStr::new(&format!("{OUTPUT_IMAGE_MIB}M")),
            image.as_os_str(),
        ],
        deadline,
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
        deadline,
    )?;
    Ok(image)
}

/// One walk of `dir` for `(total_bytes, file_count)`, to size the input image. Bounded: an input
/// past a sane ceiling is a typed error, not a giant image. Symlinks are counted (each is an inode)
/// but not descended, `mke2fs -d` copies them verbatim, so a link resolves inside the *guest* fs,
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
/// [`VmmError::Artifact`], the driver's only other external process is `firecracker`, so these are
/// real new runtime dependencies, surfaced clearly rather than as a cryptic spawn failure.
fn run_host_tool(program: &str, args: &[&OsStr], deadline: Instant) -> Result<(), VmmError> {
    // Bounded (not a bare `.output()`): a scratch filesystem that has stopped answering would
    // otherwise stall the boot with no typed error. stderr is captured so a real failure (e.g.
    // `mke2fs` on a full scratch fs) names the cause, and stdin/stdout are nulled so no tool line
    // can land on the pipe-clean structured-result stdout.
    //
    // The wall is whichever of the two runs out first: the **caller's** boot deadline, which is
    // the wall the run was actually promised, or [`IMAGE_TOOL_TIMEOUT`], which caps a wedged tool
    // on a boot with a generous (or absent) budget. A private constant alone would let a hung
    // `mke2fs` sit for two minutes under a ten-second wall.
    let wall = deadline
        .saturating_duration_since(Instant::now())
        .min(crate::proc::IMAGE_TOOL_TIMEOUT);
    let mut cmd = Command::new(program);
    cmd.args(args);
    let (status, stderr) = crate::proc::output_bounded(cmd, wall, program)?;
    if !status.success() {
        return Err(VmmError::Vmm(format!(
            "{program} failed building a block device image: {}",
            // Never just the stderr: `mke2fs` killed by a signal writes none, and the exit status
            // is then the whole diagnosis.
            crate::proc::failure_detail(status, &stderr)
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
    // One deadline for the whole readback: fsck and rdump share the bound the constant promises,
    // rather than each stage getting its own fresh wall.
    let deadline = Instant::now() + OUTPUT_READBACK_TIMEOUT;
    fsck_output_image(image, deadline)?;
    rdump_capped(image, dest, OUTPUT_EXTRACT_CAP, deadline)?;
    // Guest-controlled tree: drop the ext4 housekeeping dir and any symlink that would redirect a
    // later host read onto the host filesystem, before the caller (or its tooling) touches the files.
    let _ = std::fs::remove_dir_all(dest.join("lost+found"));
    sanitize_symlinks(dest)?;
    collect_paths(dest)
}

/// `e2fsck -fy` the image: force a full check and auto-answer, recovering the journal and clearing the
/// "not cleanly unmounted" state a hard-killed guest leaves, so `debugfs` sees a consistent tree. The
/// image's contents are wholly guest-chosen, and a crafted filesystem can send e2fsck into a
/// pathological repair, so it runs under the readback deadline ([`wait_bounded`]), never an
/// open-ended `.status()`. The exit status is a bitmask, 0 clean, 1 errors corrected, 2 corrected +
/// reboot advised (moot for an image file); `>= 4` means errors left uncorrected or an operational
/// failure, which is a real error.
fn fsck_output_image(image: &Path, deadline: Instant) -> Result<(), VmmError> {
    let (sink, back) = match stderr_capture() {
        Some((sink, back)) => (sink, Some(back)),
        None => (Stdio::null(), None),
    };
    let mut child = Command::new("e2fsck")
        .arg("-fy")
        .arg(image)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(sink)
        .spawn()
        .map_err(|e| tool_spawn_error("e2fsck", e))?;
    let status = wait_bounded(&mut child, deadline, "e2fsck", READBACK_POLL, || None)?;
    let stderr = captured_stderr(back);
    match status.code() {
        Some(0) => Ok(()),
        // Errors were found and corrected (1) or corrected + reboot-advised (2): the tree is now
        // consistent, but a hard-killed guest's in-flight writes may have been rolled back with the
        // journal. Record it so a recovered output shows up in the audit log, not as pristine.
        Some(code) if code < 4 => {
            tracing::warn!(
                exit = code,
                "e2fsck corrected the output image before readback; captured artifacts may be missing the guest's last writes"
            );
            Ok(())
        }
        Some(_) => Err(VmmError::Vmm(format!(
            "e2fsck could not repair the output image: {}",
            crate::proc::failure_detail(status, &stderr)
        ))),
        None => Err(VmmError::Vmm(format!(
            "e2fsck terminated by a signal: {}",
            crate::proc::failure_detail(status, &stderr)
        ))),
    }
}

/// A capture sink for a readback helper's stderr: `(the child's handle, our read-back handle)` onto
/// one already-unlinked file.
///
/// **Not a pipe.** Nothing reads a pipe until the child has exited, so a helper that emits more than
/// the ~64 KiB pipe buffer blocks on its own write and is only freed by the deadline kill: a
/// 120-second wedge with no diagnostic, which is worse than the bare exit code this capture replaced.
/// `debugfs` reports per failed file and the tree is guest-controlled, so that volume is reachable on
/// purpose, not just in theory. A file has no such limit and the read stays bounded either way.
///
/// `None` when the sink can't be made, which degrades to "no stderr" (the exit status becomes the
/// whole diagnosis) rather than failing a readback over its own diagnostics.
fn stderr_capture() -> Option<(Stdio, std::fs::File)> {
    let (sink, back) = crate::proc::scratch_pair("readback").ok()?;
    Some((Stdio::from(sink), back))
}

/// The head of a captured stderr, for naming a failure whose cause only the tool knows (a full output
/// dir, a corrupt image). Bounded: an unbounded read would let a crafted image dictate how much host
/// memory the *diagnostic* costs.
fn captured_stderr(back: Option<std::fs::File>) -> String {
    back.and_then(|f| crate::proc::read_head(f, STDERR_TAIL_CAP).ok())
        .unwrap_or_default()
}

/// Extract the image tree into `dest` with `debugfs rdump`, bounded so a hostile guest can't blow up
/// the host. `debugfs` materialises filesystem holes as real zeros, so a sparse file staged in the
/// capped image could still inflate the readback, a poll loop aborts the extraction once `dest`'s
/// **allocated** bytes pass `byte_cap`, or once it outruns `timeout`. rdump prints benign
/// "changing ownership" warnings when run non-root (it can't chown to the guest's uids) and still
/// exits 0; those are ignored. Its stderr is captured (see [`stderr_capture`]) for two reasons: a
/// real failure, most plainly a full `dest`, then names its cause instead of reporting a bare exit
/// code, **and** rdump exits 0 even when it extracted nothing, so stderr is the only place that
/// failure is visible at all (see [`rdump_failures`]).
fn rdump_capped(
    image: &Path,
    dest: &Path,
    byte_cap: u64,
    deadline: Instant,
) -> Result<(), VmmError> {
    // debugfs parses its `-R` request by whitespace, with no quoting, reject a whitespace dest
    // rather than silently truncate the path (the dest is operator-set, so this is a clear config
    // error, not a guest-reachable one).
    let dest_str = path_str(dest)?;
    if dest_str.chars().any(char::is_whitespace) {
        return Err(VmmError::Vmm(format!(
            "output dir path must not contain whitespace (debugfs -R limitation): {dest_str}"
        )));
    }
    let (sink, back) = match stderr_capture() {
        Some((sink, back)) => (sink, Some(back)),
        None => (Stdio::null(), None),
    };
    let mut child = Command::new("debugfs")
        .arg("-R")
        .arg(format!("rdump / {dest_str}"))
        .arg(image)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(sink)
        .spawn()
        .map_err(|e| tool_spawn_error("debugfs", e))?;

    // The extra bound rdump carries over a plain wait: abort the moment the extracted tree's
    // allocated blocks pass `byte_cap` (a sparse-file blow-up materialising as real host zeros),
    // not only when it outruns the deadline.
    let status = wait_bounded(&mut child, deadline, "debugfs rdump", READBACK_POLL, || {
        (dir_alloc_bytes(dest) > byte_cap).then_some(VmmError::OutputCap {
            limit: byte_cap.min(usize::MAX as u64) as usize,
        })
    })?;
    let stderr = captured_stderr(back);
    // `debugfs` exits **0 even when every file failed to extract**, reporting each on stderr only
    // (observed: a whole tree of "Permission denied while opening ..." with status 0). Trusting the
    // exit code alone therefore hands the caller an empty output dir and calls it a successful
    // readback, which is the audit-honesty failure of claiming artifacts that were never written.
    // So a real rdump complaint is an error whatever the status says.
    let complaints = rdump_failures(&stderr);
    if !complaints.is_empty() {
        return Err(VmmError::Vmm(format!(
            "debugfs rdump could not extract the output image: {complaints}"
        )));
    }
    match status.code() {
        Some(0) => Ok(()),
        _ => Err(VmmError::Vmm(format!(
            "debugfs rdump failed: {}",
            crate::proc::failure_detail(status, &stderr)
        ))),
    }
}

/// The `rdump:` lines that report a real extraction failure, joined, or empty when there are none.
///
/// Run non-root, rdump cannot chown to the guest's uids and says so per file; that is expected and
/// must not fail a readback, so it is the one prefix filtered out. Everything else it prefixes with
/// `rdump:` is a file it did not write.
fn rdump_failures(stderr: &str) -> String {
    stderr
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("rdump:"))
        .filter(|l| !l.contains("changing ownership"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Poll `child` to exit under `deadline`, killing and reaping it on any exit path so a shelled-out
/// helper run against guest-controlled or wedge-prone state (`e2fsck`/`debugfs` on a guest image,
/// the jail's `mount`) can never park the host thread. `over_budget` is checked each tick for an extra abort condition (rdump's byte cap);
/// returning `Some(err)` kills the child and surfaces that error. A `try_wait` failure, the
/// deadline, or an over-budget signal all kill and *briefly* reap ([`kill_and_reap_briefly`]:
/// an unkillable D-state child is detached, never waited on) before returning a typed error;
/// the `what` label names the tool in the timeout/wait messages.
///
/// `poll` is the tick, and the caller owns the trade: it bounds both the added latency for a
/// fast helper (the readback tools tolerate 50ms, a boot-path `mount` finishing in ~1ms does
/// not) and how often `over_budget` runs (rdump's callback walks the extracted tree, so a fast
/// tick there would make the watchdog itself expensive).
pub(crate) fn wait_bounded(
    child: &mut Child,
    deadline: Instant,
    what: &str,
    poll: Duration,
    mut over_budget: impl FnMut() -> Option<VmmError>,
) -> Result<ExitStatus, VmmError> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {
                if let Some(err) = over_budget() {
                    kill_and_reap_briefly(child, what, HELPER_REAP_GRACE);
                    return Err(err);
                }
                if Instant::now() >= deadline {
                    kill_and_reap_briefly(child, what, HELPER_REAP_GRACE);
                    return Err(VmmError::Timeout(format!("{what} exceeded its deadline")));
                }
                std::thread::sleep(poll);
            }
            Err(e) => {
                kill_and_reap_briefly(child, what, HELPER_REAP_GRACE);
                return Err(VmmError::Vmm(format!("wait on {what}: {e}")));
            }
        }
    }
}

/// Kill `child` and reap it, but only briefly: a child SIGKILL cannot reach (D-state, the very
/// wedge these helpers are bounded against) would turn the reap's `wait` into the hang the
/// deadline just prevented. Past `grace` it is detached with a warning and lingers as a zombie
/// until this process exits, the same trade `proc::run_bounded` makes on the teardown path: the
/// no-hang promise outranks a zombie. Returns whether the child was actually reaped, so a caller
/// with follow-on work that depends on the process being gone (joining its console reader, which
/// only ends at the child's stdout EOF) can skip that work instead of blocking on it.
pub(crate) fn kill_and_reap_briefly(child: &mut Child, what: &str, grace: Duration) -> bool {
    let _ = child.kill();
    let deadline = Instant::now() + grace;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            _ => {
                tracing::warn!(
                    child = what,
                    "killed child could not be reaped (running past the grace, D-state?, or a \
                     wait error); detaching it"
                );
                return false;
            }
        }
    }
}

/// Sum of **allocated** bytes (`blocks * 512`, real host disk, not logical size) under `dir`. Walks
/// with `file_type`/`DirEntry::metadata` (both `lstat`-like), so a guest symlink is counted as the
/// link itself and never followed, the walk can't be lured onto the host filesystem while sizing.
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
/// climbs out with `..`) would make a later host read of the results read host files, the inverse of
/// the input side, where `mke2fs -d` resolves links inside the guest image. In-tree links (e.g.
/// `a -> sub/b`) are kept.
///
/// Containment is checked by **canonical resolution**, not lexically: a lexical `..`-depth count is
/// unsound because a kept in-tree symlink makes a `Normal` path component *not* descend a real level,
/// a guest can chain `d -> .` with `evil -> d/../../etc/shadow` to pass a lexical check while
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
                // A non-UTF-8 name has no lossless `String`, and a `to_string_lossy` U+FFFD form
                // names no file on disk (an embedder resolving it gets ENOENT), so drop it with a
                // warning rather than hand back a broken manifest entry (the sanitizer's posture).
                match rel.to_str() {
                    Some(s) => out.push(s.to_owned()),
                    None => tracing::warn!(
                        path = %rel.display(),
                        "output artifact has a non-UTF-8 name; omitted from the manifest"
                    ),
                }
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_support::ScratchDir;

    #[test]
    fn sanitize_symlinks_drops_escapes_including_chained_intermediate_links() {
        use std::os::unix::fs::symlink;
        let dir = ScratchDir::created("ekvm-sanitize");
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
    fn wait_bounded_kills_a_child_that_outruns_the_deadline() {
        // Stands in for e2fsck/debugfs wedged on a pathological guest image: a long sleeper must be
        // killed and reaped at the deadline, returning a typed Timeout, never parking the thread.
        let mut child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        let started = Instant::now();
        let err = wait_bounded(
            &mut child,
            started + Duration::from_millis(100),
            "sleep",
            Duration::from_millis(10),
            || None,
        )
        .expect_err("a 30s sleep must not finish before a 100ms deadline");
        assert!(matches!(err, VmmError::Timeout(_)), "got {err:?}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "must return promptly at the deadline, not wait out the child"
        );
        // The child was killed and reaped inside `wait_bounded`, so its pid is gone (no zombie: we
        // already `wait`ed it). A second reap here would be the only other claimant.
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists()
                || std::fs::read_to_string(format!("/proc/{pid}/stat"))
                    .ok()
                    .and_then(|s| s
                        .split(") ")
                        .nth(1)
                        .and_then(|r| r.split(' ').next())
                        .map(str::to_owned))
                    != Some("Z".to_string()),
            "the killed child must be reaped, not left a zombie"
        );
    }

    #[test]
    fn a_signal_killed_host_tool_is_named_by_its_status_not_a_bare_colon() {
        // `run_host_tool`'s live failure path. A tool killed by a signal writes no stderr, and the
        // error used to be built from stderr alone, so it ended at the colon and named no cause.
        // `sh -c 'kill -9 $$'` stands in for the OOM killer or a deadline kill reaching `mke2fs`.
        let err = run_host_tool(
            "sh",
            &[OsStr::new("-c"), OsStr::new("kill -9 $$")],
            Instant::now() + Duration::from_secs(5),
        )
        .expect_err("a signal-killed tool must be an error");
        let msg = err.to_string();
        assert!(
            !msg.trim_end().ends_with(':'),
            "a silent tool must still be described: {msg}"
        );
        assert!(
            msg.contains("signal"),
            "the status is the only fact a signal-killed tool leaves: {msg}"
        );
    }

    #[test]
    fn an_unreapable_child_is_detached_rather_than_waited_on() {
        // The `false` return of `kill_and_reap_briefly`, which teardown uses to decide whether to
        // skip `console.join()`. A real D-state child needs a wedged FUSE/NFS mount; a zero grace
        // reaches the same arm, since the reap loop gives up before its first sleep. The race (the
        // kernel delivering SIGKILL *and* the process being reaped between `kill` and one
        // `try_wait`) is vanishingly small, and a flake here would itself be worth knowing about.
        let mut child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep");
        let started = Instant::now();
        let reaped = kill_and_reap_briefly(&mut child, "sleep", Duration::ZERO);
        assert!(
            !reaped,
            "a zero grace cannot reap: it must report the detach"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "detaching must be prompt, never a wait on the child"
        );
        let _ = child.wait(); // this test's own cleanup, not the code under test
    }

    #[test]
    fn wait_bounded_returns_a_quick_child_status() {
        let mut child = Command::new("true")
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn true");
        let status = wait_bounded(
            &mut child,
            Instant::now() + Duration::from_secs(5),
            "true",
            Duration::from_millis(10),
            || None,
        )
        .expect("a fast child returns its status");
        assert!(status.success(), "`true` exits 0");
    }

    #[test]
    fn output_dir_with_whitespace_is_rejected_before_debugfs() {
        // A whitespace dest would be split by debugfs's `-R` parser; catch it as a typed error rather
        // than silently truncating the extraction path. (No debugfs is spawned, the guard fires first.)
        let err = rdump_capped(
            Path::new("/nonexistent/img.ext4"),
            Path::new("/tmp/has a space"),
            OUTPUT_EXTRACT_CAP,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(
            matches!(err, VmmError::Vmm(ref m) if m.contains("whitespace")),
            "got {err:?}"
        );
    }

    #[test]
    fn an_rdump_that_extracted_nothing_is_a_failure_whatever_its_exit_code_said() {
        // Measured, not assumed: `debugfs -R "rdump / <unwritable>"` prints one line per file it
        // could not write and **exits 0**. Reading the status alone therefore reports a successful
        // readback over an empty output dir, which is the engine claiming artifacts it does not
        // have. This is the pure half of that check.
        let failed = "debugfs 1.47.4 (6-Mar-2025)\n\
                      rdump: Permission denied while making directory /out//lost+found\n\
                      rdump: Permission denied while opening /out//payload-0\n";
        let complaints = rdump_failures(failed);
        assert!(
            complaints.contains("payload-0") && complaints.contains("lost+found"),
            "every file rdump dropped must survive into the error: {complaints}"
        );

        // The one prefix that must *not* fail a readback: run non-root, rdump cannot chown to the
        // guest's uids and says so per file while extracting them perfectly well.
        let benign = "debugfs 1.47.4 (6-Mar-2025)\n\
                      rdump: Operation not permitted while changing ownership of /out//payload-0\n";
        assert_eq!(
            rdump_failures(benign),
            "",
            "an ownership warning is expected non-root and must not fail the readback"
        );
        assert_eq!(rdump_failures(""), "", "silence is success");
    }

    #[test]
    fn a_readback_that_wrote_nothing_is_never_reported_as_a_successful_one() {
        // The live counterpart of the pure test above, through the real `collect_output_image`. An
        // unwritable dest stands in for the full one: both make rdump fail per file and exit 0, and
        // this one needs no root, so the branch is covered by the everyday gate rather than only by
        // the privileged run.
        //
        // Guarded because it *inverts* under root: root writes through mode 0555, the readback then
        // genuinely succeeds, and the assertion below would fail on a correct engine. A test whose
        // meaning flips with privilege has to say so.
        if test_support::have_real_root() {
            eprintln!(
                "skipping a_readback_that_wrote_nothing_is_never_reported_as_a_successful_one: \
                 root writes through an unwritable dir, so there is no failure to observe"
            );
            return;
        }
        let dir = test_support::ScratchDir::created("rdump-unwritable");
        let tree = dir.path().join("tree");
        std::fs::create_dir_all(&tree).expect("seed dir");
        std::fs::write(tree.join("payload"), b"guest output").expect("seed payload");
        let deadline = Instant::now() + Duration::from_secs(60);
        let Ok(image) = build_input_image(&tree, dir.path(), deadline) else {
            eprintln!(
                "skipping a_readback_that_wrote_nothing_is_never_reported_as_a_successful_one: \
                 no working mke2fs"
            );
            return;
        };

        use std::os::unix::fs::PermissionsExt as _;
        let dest = dir.path().join("out");
        std::fs::create_dir_all(&dest).expect("dest dir");
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o555)).expect("chmod");

        let err = collect_output_image(&image, &dest)
            .expect_err("a readback that extracted nothing is not a success");
        let msg = err.to_string();
        assert!(
            msg.contains("payload"),
            "the error must name the file that never made it out: {msg}"
        );

        // Restore write permission so the scratch guard can reclaim the tree on drop.
        let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755));
    }

    #[test]
    #[ignore = "mounts a tmpfs; needs real root (run via `cargo xtask ci-privileged`)"]
    fn a_full_scratch_names_mke2fs_as_the_cause() {
        // The case `run_host_tool`'s captured stderr was written for. `truncate` succeeds (a sparse
        // file costs nothing), then `mke2fs` writes real metadata and hits ENOSPC. Without the
        // capture the boot would fail with a bare exit code and the operator would have no way to
        // tell a full scratch dir from a corrupt image.
        let Some(fs) = test_support::SmallFs::create(8, "mke2fs-full") else {
            eprintln!("skipping a_full_scratch_names_mke2fs_as_the_cause: needs real root");
            return;
        };
        // Zero headroom, not a comfortable margin. What a 256 MiB ext4 costs on disk is an
        // e2fsprogs question, not a constant: recent versions punch holes where they used to write
        // the zeroed inode table and journal, so the image's *allocated* size is metadata only and
        // has been shrinking. This test left 256 KiB and passed here (e2fsprogs 1.47.4 needs
        // exactly that much) while mke2fs finished inside it on the hosted privileged runner,
        // failing the gate on the version difference. A full filesystem is the one precondition no
        // version can satisfy, and `truncate` is sparse, so it still gets as far as mke2fs.
        fs.fill_leaving(0);

        // Report the fixture's real state on failure rather than only "it succeeded": if this ever
        // trips, the questions are whether the small filesystem was still mounted and how much room
        // it actually had, and these tests fail on hosts where nobody can attach a shell after. The
        // message is built after the call, so it describes the filesystem as mke2fs left it.
        let err = build_output_image(fs.path(), Instant::now() + Duration::from_secs(30))
            .expect_err(&format!(
                "mke2fs built a 256 MiB image on a filesystem that cannot hold one. Fixture {}",
                fs.state()
            ));
        let msg = err.to_string();
        assert!(
            !msg.trim_end().ends_with(':'),
            "a failed image build must name a cause, not end in a bare colon: {msg}"
        );
        // Which tool failed, not just that one did. With the filesystem completely full, `truncate`
        // is the other candidate, and its ENOSPC would satisfy the "space" assertion below while
        // testing something this test does not claim to cover.
        assert!(
            msg.contains("mke2fs"),
            "the failure under test is mke2fs's, not another tool's: {msg}"
        );
        assert!(
            msg.to_lowercase().contains("space"),
            "the cause must be mke2fs's own words about the full filesystem: {msg}"
        );
    }

    #[test]
    #[ignore = "mounts a tmpfs; needs real root (run via `cargo xtask ci-privileged`)"]
    fn a_full_output_dir_names_debugfs_as_the_cause() {
        // `debugfs` and `e2fsck` used to discard their stderr, so a readback into a full output dir
        // reported `(exit 1)` and nothing else. The image here is legitimate; only the destination
        // is out of space, which is precisely the failure an exit code cannot distinguish.
        let Some(fs) = test_support::SmallFs::create(8, "rdump-full") else {
            eprintln!("skipping a_full_output_dir_names_debugfs_as_the_cause: needs real root");
            return;
        };
        // The image is built on the *host* filesystem and seeded with real content: this test is
        // about the destination being full, and rdump of an empty image would write nothing at all
        // and succeed on any headroom.
        let src = test_support::ScratchDir::created("rdump-src");
        let tree = src.path().join("tree");
        std::fs::create_dir_all(&tree).expect("seed dir");
        for i in 0..4 {
            std::fs::write(tree.join(format!("payload-{i}")), vec![b'x'; 1024 * 1024])
                .expect("seed payload");
        }
        let deadline = Instant::now() + Duration::from_secs(60);
        let Ok(image) = build_input_image(&tree, src.path(), deadline) else {
            eprintln!("skipping a_full_output_dir_names_debugfs_as_the_cause: no working mke2fs");
            return;
        };

        let dest = fs.path().join("out");
        // Leave enough for the `create_dir_all` and e2fsck's own bookkeeping, but far less than the
        // extracted tree, so the failure lands inside rdump rather than before it.
        fs.fill_leaving(128 * 1024);
        let started = Instant::now();
        let err =
            collect_output_image(&image, &dest).expect_err("a full dest cannot hold the readback");
        let msg = err.to_string();

        // The trap this test would otherwise fall into: a readback that *wedges* also produces an
        // error with no bare exit code and no trailing colon, so the weaker assertions below would
        // pass on a 120-second timeout that captured no stderr at all, proving nothing.
        assert!(
            !matches!(err, VmmError::Timeout(_)),
            "the readback must fail on the full disk, not wedge until its deadline: {msg}"
        );
        assert!(
            started.elapsed() < OUTPUT_READBACK_TIMEOUT / 2,
            "a full dest must fail promptly, not near the readback wall: {:?}",
            started.elapsed()
        );
        assert!(
            !msg.trim_end().ends_with(':'),
            "a failed readback must name a cause, not end in a bare colon: {msg}"
        );
        // `failure_detail` falls back to the exit status only when stderr was empty, so a message
        // ending in one is exactly the pre-fix behaviour: the tool spoke and nobody listened.
        assert!(
            !msg.contains("exit status:") && !msg.contains("(exit "),
            "the detail must be the tool's own stderr, not its exit status: {msg}"
        );
    }
}
