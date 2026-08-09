//! The bulk input/output block devices: build their ext4 images rootless
//! (`mke2fs -d`), and read the output tree back from an untrusted image in-process (`ext4-view`,
//! bounded, symlink-sanitized) after the guest is dead.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

use ext4_view::{Ext4, FileType, PathBuf as GuestPath};

/// The filesystem labels the driver stamps on the data devices so the guest mounts them by label,
/// not by enumeration-order `/dev/vdX` (a boot may attach input, output, both, or neither). Defined
/// in `bsx-channel`, the one host↔guest contract both the driver and the rootfs build consume.
use bsx_channel::{INPUT_LABEL, OUTPUT_LABEL};

use crate::VmmError;

/// Size of the blank writable output image. A fixed cap, and the natural bulk-output
/// bound (the guest can't write more than the filesystem holds), mirroring the channel path's
/// [`MAX_EXEC_OUTPUT`]. Built with `lazy_itable_init=0` so the guest kernel never balloons the
/// metadata: a fresh image is ~a few MiB of real host blocks, growing only with what's written.
const OUTPUT_IMAGE_MIB: u32 = 256;

/// Hard ceiling on the **real host bytes** [`RunningVm::collect_outputs`] will write while extracting
/// the output image. A hole in a guest file reads back as zeros, so a hostile guest could stage a
/// sparse file with a huge logical size inside the capped image and inflate the readback; the walk
/// charges what it writes against this bound. Generous headroom over [`OUTPUT_IMAGE_MIB`] (a
/// legitimate tree's real bytes can't exceed the image), so only abuse trips.
const OUTPUT_EXTRACT_CAP: u64 = 2 * (OUTPUT_IMAGE_MIB as u64) * 1024 * 1024; // 512 MiB

/// Wall-clock bound on the output readback, so a pathological image can never hang the host
/// teardown. Read-back is off the boot path; generous is fine.
const OUTPUT_READBACK_TIMEOUT: Duration = Duration::from_secs(120);
/// How deep the readback will descend a guest tree. A crafted image can point a directory entry at
/// an ancestor, and this is one of the two bounds that holds such a cycle (see [`Walk::dir`]).
const MAX_OUTPUT_DEPTH: u32 = 64;
/// How many directory entries the readback will visit. The other half of the cycle bound, and the
/// one that also holds a wide tree of empty directories, which costs host inodes but no bytes.
const MAX_OUTPUT_ENTRIES: u64 = 500_000;
/// Copy buffer for one guest file. An upper bound, not a stride: the reader answers a `read` with at
/// most one filesystem block, so the buffer is rarely filled. Each read is charged against the byte
/// cap as it lands, which is what enforces the cap mid-file rather than at file boundaries.
const READBACK_CHUNK: usize = 64 * 1024;
/// How long a killed helper is given to be reaped before it is detached (see
/// [`kill_and_reap_briefly`]). Short: a killable child dies at once, and anything slower is the
/// D-state case, where waiting longer only lengthens the hang.
const HELPER_REAP_GRACE: Duration = Duration::from_millis(200);
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

/// Map a failure to spawn one of the driver's host helpers (`mke2fs`/`truncate` for the block
/// devices, `ip` for the tap) to a typed error: a missing binary is a clear
/// [`VmmError::Artifact`] (install hint), anything else a [`VmmError::Vmm`].
pub(crate) fn tool_spawn_error(program: &str, e: std::io::Error) -> VmmError {
    if e.kind() == std::io::ErrorKind::NotFound {
        VmmError::Artifact(format!(
            "{program} not found (a host tool the driver shells out to: install e2fsprogs/coreutils/iproute2)"
        ))
    } else {
        VmmError::Vmm(format!("run {program}: {e}"))
    }
}

/// Read the writable output image back into the host `dest` directory, rootless and in-process.
/// Ordered so the tree is safe before it's returned: walk the image under a byte/entry/time cap,
/// neutralise host-escaping symlinks, then list what survived. Called only after the VMM has exited
/// (see [`RunningVm::collect_outputs`]).
///
/// The image is wholly guest-authored, so it is parsed in-process by `ext4-view`, an `unsafe`-free
/// reader on the `#![forbid(unsafe_code)]` host path. The reader replays the image's journal, which
/// is what makes a hard-killed guest's dirty image readable.
pub(crate) fn collect_output_image(image: &Path, dest: &Path) -> Result<Vec<String>, VmmError> {
    std::fs::create_dir_all(dest)
        .map_err(|e| VmmError::Vmm(format!("create output dir {}: {e}", dest.display())))?;
    let fs = std::panic::catch_unwind(|| Ext4::load_from_path(image))
        .map_err(|_| {
            VmmError::Vmm(format!(
                "read the output image {}: ext4 image parsing panicked",
                image.display()
            ))
        })?
        .map_err(|e| VmmError::Vmm(format!("read the output image {}: {e}", image.display())))?;

    let walk_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Walk::new(dest, OUTPUT_EXTRACT_CAP).run(&fs)
    }));
    match walk_res {
        Ok(res) => res?,
        Err(_) => {
            return Err(VmmError::Vmm(format!(
                "read the output image {}: ext4 tree walk panicked",
                image.display()
            )));
        }
    }
    sanitize_symlinks(dest)?;
    collect_paths(dest)
}

/// Remove a **symlink** already sitting at `host_path` before the walk creates anything there.
///
/// `File::create` and `create_dir_all` both follow a link, so a link planted in `output_dir` ahead of
/// the readback redirects the create onto whatever it names: the guest's bytes land outside `dest`,
/// and [`sanitize_symlinks`] then removes the link, so the manifest reports a clean run that wrote
/// nothing. [`Walk::dir`] calls this for every entry, which is what keeps a create inside `dest`.
/// A regular file or directory already at the name is left alone; only a link redirects a write.
fn clear_planted_link(host_path: &Path) -> Result<(), VmmError> {
    match host_path.symlink_metadata() {
        Ok(meta) if meta.is_symlink() => std::fs::remove_file(host_path)
            .map_err(|e| VmmError::Vmm(format!("clear the link at {}: {e}", host_path.display()))),
        _ => Ok(()),
    }
}

/// One extraction of a guest image into a host directory, carrying the three bounds a guest-authored
/// tree is walked under.
///
/// **Every bound is a typed error, never a silent stop.** A truncated tree reported as a clean
/// readback is the audit-honesty failure of claiming artifacts that were never written.
struct Walk<'a> {
    dest: &'a Path,
    /// Ceiling on written bytes. A field rather than a constant so a test can drive the bound with
    /// a fixture instead of half a gigabyte of guest output.
    byte_cap: u64,
    /// Real host bytes written so far, against [`OUTPUT_EXTRACT_CAP`]. A hole in a guest file reads
    /// back as zeros, so a sparse file staged inside the capped image is counted at the size it
    /// actually costs the host.
    bytes: u64,
    /// Directory entries visited so far, against [`MAX_OUTPUT_ENTRIES`]. Entries only: a file's
    /// copy chunks check the clock but must not spend this budget, or one large legitimate file
    /// would report a tree that has too many entries.
    entries: u64,
    deadline: Instant,
    /// One copy buffer for the whole walk, heap-allocated: a per-file array would put
    /// [`READBACK_CHUNK`] on the stack under [`MAX_OUTPUT_DEPTH`] frames of recursion, and a
    /// per-file `Vec` would allocate once per file in a tree that can hold many.
    buf: Box<[u8]>,
}

impl<'a> Walk<'a> {
    fn new(dest: &'a Path, byte_cap: u64) -> Self {
        Self {
            dest,
            byte_cap,
            bytes: 0,
            entries: 0,
            deadline: Instant::now() + OUTPUT_READBACK_TIMEOUT,
            buf: vec![0u8; READBACK_CHUNK].into_boxed_slice(),
        }
    }

    /// Extract the image's root into `dest`.
    fn run(&mut self, fs: &Ext4) -> Result<(), VmmError> {
        let root = GuestPath::try_from("/")
            .map_err(|e| VmmError::Vmm(format!("build the guest root path: {e}")))?;
        self.dir(fs, &root, self.dest.to_path_buf(), 0)
    }

    /// Extract one guest directory into `host_dir`, recursing at `depth`.
    ///
    /// A crafted image can name a directory whose entry points back at an ancestor, so the walk is
    /// bounded by depth and total entries rather than by a visited set: `ext4-view` exposes no inode
    /// number to deduplicate on, and both bounds hold a cycle whether or not one is expressible.
    fn dir(
        &mut self,
        fs: &Ext4,
        guest_dir: &GuestPath,
        host_dir: PathBuf,
        depth: u32,
    ) -> Result<(), VmmError> {
        if depth > MAX_OUTPUT_DEPTH {
            return Err(VmmError::Vmm(format!(
                "output tree is deeper than {MAX_OUTPUT_DEPTH} levels at {}",
                host_dir.display()
            )));
        }
        let entries = fs
            .read_dir(guest_dir)
            .map_err(|e| VmmError::Vmm(format!("read guest dir {}: {e}", guest_dir.display())))?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                VmmError::Vmm(format!("read entry in {}: {e}", guest_dir.display()))
            })?;
            self.entry()?;

            let name = entry.file_name();
            // `.` and `..` are real entries in an ext4 directory block and the iterator yields them;
            // descending either is how a walk of a legitimate tree loops forever.
            if name == "." || name == ".." {
                continue;
            }
            // `lost+found` is ext4 housekeeping, not the guest's output.
            if depth == 0 && name == "lost+found" {
                continue;
            }
            // A name with no `str` form names no host file a caller could open. `DirEntryName`
            // already rejects `/` and NUL, so a name that is valid UTF-8 is a single path component
            // and cannot climb out of `host_dir`.
            let Ok(name) = name.as_str() else {
                tracing::warn!(
                    dir = %guest_dir.display(),
                    "output entry has a non-UTF-8 name; skipped"
                );
                continue;
            };
            let guest_path = entry.path();
            let host_path = host_dir.join(name);
            let meta = entry.metadata().map_err(|e| {
                VmmError::Vmm(format!("stat guest entry {}: {e}", guest_path.display()))
            })?;

            let file_type = meta.file_type();
            // Only for the arms below that create something: a node type the walk skips must not
            // delete whatever is already at that name.
            if matches!(
                file_type,
                FileType::Directory | FileType::Regular | FileType::Symlink
            ) {
                clear_planted_link(&host_path)?;
            }
            match file_type {
                FileType::Directory => {
                    std::fs::create_dir_all(&host_path).map_err(|e| {
                        VmmError::Vmm(format!("create {}: {e}", host_path.display()))
                    })?;
                    self.dir(fs, &guest_path, host_path, depth + 1)?;
                }
                FileType::Regular => self.file(fs, &guest_path, &host_path)?,
                FileType::Symlink => {
                    let target = fs.read_link(&guest_path).map_err(|e| {
                        VmmError::Vmm(format!("read guest symlink {}: {e}", guest_path.display()))
                    })?;
                    // A target with no `str` form names nothing a host read could follow, so it is
                    // dropped here rather than recreated as a link the sanitizer cannot resolve.
                    let Ok(target) = target.to_str() else {
                        tracing::warn!(
                            path = %guest_path.display(),
                            "output symlink has a non-UTF-8 target; skipped"
                        );
                        continue;
                    };
                    // `symlink` refuses to replace an existing name, where `File::create` and
                    // `create_dir_all` both tolerate one, so a reused `output_dir` would fail on
                    // this arm alone. Clear the way to keep the three arms consistent.
                    if host_path.symlink_metadata().is_ok() {
                        let _ = std::fs::remove_file(&host_path)
                            .or_else(|_| std::fs::remove_dir_all(&host_path));
                    }
                    // Recreated verbatim, then judged by `sanitize_symlinks` against the real `dest`:
                    // an escaping target is dropped there, where containment is resolved rather than
                    // guessed from the link text.
                    std::os::unix::fs::symlink(target, &host_path).map_err(|e| {
                        VmmError::Vmm(format!("create symlink {}: {e}", host_path.display()))
                    })?;
                }
                // Block/char devices, fifos and sockets carry guest-chosen major/minor numbers and
                // no data. They are named in the log and skipped rather than recreated on the host.
                other => tracing::warn!(
                    path = %guest_path.display(),
                    file_type = ?other,
                    "output entry is not a file, directory or symlink; skipped"
                ),
            }
        }
        Ok(())
    }

    /// Copy one guest file to `host_path`, charging its bytes against the cap as they are written.
    ///
    fn file(
        &mut self,
        fs: &Ext4,
        guest_path: &GuestPath,
        host_path: &Path,
    ) -> Result<(), VmmError> {
        let mut src = fs
            .open(guest_path)
            .map_err(|e| VmmError::Vmm(format!("open guest file {}: {e}", guest_path.display())))?;
        let mut dst = std::fs::File::create(host_path)
            .map_err(|e| VmmError::Vmm(format!("create {}: {e}", host_path.display())))?;
        loop {
            self.check_clock()?;
            let n = std::io::Read::read(&mut src, &mut self.buf).map_err(|e| {
                VmmError::Vmm(format!("read guest file {}: {e}", guest_path.display()))
            })?;
            if n == 0 {
                return Ok(());
            }
            // Charged before the write, so the cap bounds what reaches the host rather than
            // discovering the overrun once it is already on disk.
            self.bytes = self.bytes.saturating_add(n as u64);
            if self.bytes > self.byte_cap {
                return Err(VmmError::OutputCap {
                    limit: self.byte_cap.min(usize::MAX as u64) as usize,
                });
            }
            std::io::Write::write_all(&mut dst, &self.buf[..n])
                .map_err(|e| VmmError::Vmm(format!("write {}: {e}", host_path.display())))?;
        }
    }

    /// Charge one directory entry against the entry count, and check the clock.
    fn entry(&mut self) -> Result<(), VmmError> {
        self.entries += 1;
        if self.entries > MAX_OUTPUT_ENTRIES {
            return Err(VmmError::Vmm(format!(
                "output tree has more than {MAX_OUTPUT_ENTRIES} entries"
            )));
        }
        self.check_clock()
    }

    /// Check the wall clock alone, for work that is not a new entry.
    fn check_clock(&self) -> Result<(), VmmError> {
        if Instant::now() >= self.deadline {
            return Err(VmmError::Timeout(
                "the output readback exceeded its deadline".into(),
            ));
        }
        Ok(())
    }
}

/// Poll `child` to exit under `deadline`, killing and reaping it on any exit path so a shelled-out
/// helper run against wedge-prone state (the jail's `mount`, a version probe) can never park the
/// host thread. A `try_wait` failure or the deadline kills and *briefly* reaps
/// ([`kill_and_reap_briefly`]: an unkillable D-state child is detached, never waited on) before
/// returning a typed error; the `what` label names the tool in the timeout/wait messages.
///
/// `poll` is the tick, and the caller owns the trade: it bounds the added latency for a fast helper
/// (a teardown helper tolerates a lazy tick, a boot-path `mount` finishing in ~1ms does not).
pub(crate) fn wait_bounded(
    child: &mut Child,
    deadline: Instant,
    what: &str,
    poll: Duration,
) -> Result<ExitStatus, VmmError> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {
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
    reap_briefly(|| child.try_wait(), what, grace)
}

/// The reap loop of [`kill_and_reap_briefly`], over any `try_wait`. A child SIGKILL genuinely
/// cannot reach needs a wedged FUSE/NFS mount to produce, so the detach arm is reachable in a test
/// only through this seam: a `try_wait` that answers `Ok(None)` is the D-state child's whole
/// observable behavior here.
fn reap_briefly(
    mut try_wait: impl FnMut() -> std::io::Result<Option<ExitStatus>>,
    what: &str,
    grace: Duration,
) -> bool {
    let deadline = Instant::now() + grace;
    loop {
        match try_wait() {
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

/// Remove every symlink under `dest` whose target escapes `dest`. The walk recreates a guest symlink
/// verbatim as a **host** symlink, so an un-sanitised `link -> /etc/shadow` (or one that
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
    use bsx_test_support::ScratchDir;
    use std::process::Stdio;

    #[test]
    fn sanitize_symlinks_drops_escapes_including_chained_intermediate_links() {
        use std::os::unix::fs::symlink;
        let dir = ScratchDir::created("bsx-sanitize");
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
        // Stands in for a host helper wedged on pathological state: a long sleeper must be
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
        // `run_host_tool`'s live failure path. A tool killed by a signal writes no stderr, so an
        // error built from stderr alone would end at the colon and name no cause.
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
        // skip `console.join()`. A `try_wait` that never yields a status is what a D-state child
        // looks like from here, and driving it directly makes the arm a decision rather than a
        // scheduling outcome: a live child racing SIGKILL delivery could be reaped either way.
        let mut polls = 0u32;
        let started = Instant::now();
        let reaped = reap_briefly(
            || {
                polls += 1;
                Ok(None)
            },
            "wedged",
            Duration::from_millis(50),
        );
        assert!(!reaped, "a child that never reaps must report the detach");
        assert!(polls >= 2, "the grace must be polled, not skipped: {polls}");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "detaching must be prompt, never a wait on the child"
        );
    }

    #[test]
    fn a_wait_error_detaches_instead_of_looping_on_it() {
        // The other half of the `_` arm: an `Err` from `try_wait` is unrecoverable, so retrying it
        // for the whole grace would just spend the budget to reach the same answer.
        let started = Instant::now();
        let reaped = reap_briefly(
            || Err(std::io::Error::other("no child processes")),
            "erroring",
            Duration::from_secs(30),
        );
        assert!(!reaped, "a wait error cannot be a successful reap");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "an error is final: it must not be retried across the grace"
        );
    }

    #[test]
    fn a_killable_child_is_reaped_within_the_real_grace() {
        // The `true` return, over a live child. Unlike the detach arm this direction is decidable:
        // a SIGKILLed `sleep` is reapable well inside `HELPER_REAP_GRACE`, and the loop keeps
        // polling until it is.
        let mut child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep");
        let started = Instant::now();
        assert!(
            kill_and_reap_briefly(&mut child, "sleep", HELPER_REAP_GRACE),
            "a killable child must be reaped, never left to the detach arm"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the reap must land inside the grace, not wait out the child"
        );
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
        )
        .expect("a fast child returns its status");
        assert!(status.success(), "`true` exits 0");
    }

    /// Build a real ext4 from `tree` with `mke2fs -d`, then read it back through the live
    /// `collect_output_image`. `None` when the host has no usable `mke2fs`, which is a skip, not a
    /// failure: the readback under test is in-process, but staging a genuine image is not.
    fn round_trip(tag: &str, tree: &Path, dir: &Path) -> Option<(PathBuf, Vec<String>)> {
        let deadline = Instant::now() + Duration::from_secs(60);
        let image = build_input_image(tree, dir, deadline).ok().or_else(|| {
            eprintln!("skipping {tag}: no working mke2fs");
            None
        })?;
        let dest = dir.join("out");
        let paths = collect_output_image(&image, &dest).expect("read the image back");
        Some((dest, paths))
    }

    #[test]
    fn a_guest_tree_round_trips_through_the_in_process_reader() {
        // A real mke2fs-written ext4 read back in-process, no child process involved. Nested dirs
        // and an in-tree symlink, because those are the shapes the walk has to descend and recreate
        // rather than just copy.
        let dir = bsx_test_support::ScratchDir::created("readback-roundtrip");
        let tree = dir.path().join("tree");
        std::fs::create_dir_all(tree.join("sub/deeper")).expect("seed dirs");
        std::fs::write(tree.join("top.txt"), b"top level").expect("seed file");
        std::fs::write(tree.join("sub/nested.bin"), vec![7u8; 100_000]).expect("seed nested");
        std::fs::write(tree.join("sub/deeper/leaf"), b"leaf").expect("seed leaf");
        std::os::unix::fs::symlink("sub/nested.bin", tree.join("inside"))
            .expect("seed in-tree symlink");

        let Some((dest, paths)) = round_trip(
            "a_guest_tree_round_trips_through_the_in_process_reader",
            &tree,
            dir.path(),
        ) else {
            return;
        };

        assert_eq!(
            std::fs::read(dest.join("top.txt")).expect("read top"),
            b"top level"
        );
        assert_eq!(
            std::fs::read(dest.join("sub/deeper/leaf")).expect("read leaf"),
            b"leaf"
        );
        // A multi-chunk file, so the copy loop is exercised past one `READBACK_CHUNK`.
        assert_eq!(
            std::fs::read(dest.join("sub/nested.bin")).expect("read nested"),
            vec![7u8; 100_000]
        );
        // An in-tree link is kept as a link, not flattened into a copy.
        let link = dest.join("inside");
        assert!(
            link.symlink_metadata().expect("stat link").is_symlink(),
            "an in-tree symlink must survive as a symlink"
        );
        assert_eq!(
            std::fs::read(&link).expect("read through the link"),
            vec![7u8; 100_000]
        );

        // The manifest names every file, and never `lost+found`, which is ext4 housekeeping.
        for want in ["top.txt", "sub/nested.bin", "sub/deeper/leaf", "inside"] {
            assert!(
                paths.iter().any(|p| p == want),
                "manifest missing {want}: {paths:?}"
            );
        }
        assert!(
            !paths.iter().any(|p| p.starts_with("lost+found")),
            "lost+found is not the guest's output: {paths:?}"
        );
    }

    #[test]
    fn a_link_planted_in_the_destination_cannot_redirect_the_readback() {
        // `output_dir` is operator-chosen, so it can already hold a symlink when the readback runs:
        // an operator's own, or one planted by anything else with write access between runs. Both
        // `File::create` and `create_dir_all` follow a link, so without `clear_planted_link` the
        // guest's bytes land wherever it points, and `sanitize_symlinks` then removes the link so
        // the manifest reports a clean run that wrote nothing. Writes must stay inside `dest`.
        let dir = bsx_test_support::ScratchDir::created("readback-planted");
        let outside_file = dir.path().join("OUTSIDE");
        std::fs::write(&outside_file, b"host content").expect("seed outside file");
        let outside_dir = dir.path().join("OUTSIDE_DIR");
        std::fs::create_dir_all(&outside_dir).expect("seed outside dir");

        let tree = dir.path().join("tree");
        std::fs::create_dir_all(tree.join("d")).expect("seed guest dir");
        std::fs::write(tree.join("d/x"), b"guest data").expect("seed nested");
        std::fs::write(tree.join("f"), b"guest data").expect("seed file");

        let deadline = Instant::now() + Duration::from_secs(60);
        let Ok(image) = build_input_image(&tree, dir.path(), deadline) else {
            eprintln!("skipping a_link_planted_in_the_destination: no working mke2fs");
            return;
        };

        // The names the guest is about to write, already present as links pointing out of `dest`.
        let dest = dir.path().join("out");
        std::fs::create_dir_all(&dest).expect("dest");
        std::os::unix::fs::symlink(&outside_file, dest.join("f")).expect("plant a file link");
        std::os::unix::fs::symlink(&outside_dir, dest.join("d")).expect("plant a dir link");

        collect_output_image(&image, &dest).expect("the readback");

        assert_eq!(
            std::fs::read(&outside_file).expect("read the outside file"),
            b"host content",
            "a planted link must not redirect a file write out of the destination"
        );
        assert!(
            !outside_dir.join("x").exists(),
            "a planted link must not redirect a directory write out of the destination"
        );
        // And the guest's data is where it belongs.
        assert_eq!(
            std::fs::read(dest.join("f")).expect("read the extracted file"),
            b"guest data"
        );
        assert_eq!(
            std::fs::read(dest.join("d/x")).expect("read the extracted nested file"),
            b"guest data"
        );
    }

    #[test]
    fn a_second_collection_into_the_same_dest_replaces_what_is_there() {
        // An embedder may point two runs at one `output_dir`. Files and directories tolerate that
        // on their own (`File::create` truncates, `create_dir_all` is idempotent); a symlink is the
        // one node type whose syscall refuses to replace, so without help the second run fails on
        // that arm alone.
        let dir = bsx_test_support::ScratchDir::created("readback-recollect");
        let tree = dir.path().join("tree");
        std::fs::create_dir_all(tree.join("d")).expect("seed dir");
        std::fs::write(tree.join("f"), b"content").expect("seed file");
        std::os::unix::fs::symlink("f", tree.join("l")).expect("seed link");

        let deadline = Instant::now() + Duration::from_secs(60);
        let Ok(image) = build_input_image(&tree, dir.path(), deadline) else {
            eprintln!("skipping a_second_collection_into_the_same_dest: no working mke2fs");
            return;
        };
        let dest = dir.path().join("out");
        collect_output_image(&image, &dest).expect("the first collection");
        let again = collect_output_image(&image, &dest).expect("a reused dest is not an error");

        assert!(
            again.iter().any(|p| p == "l"),
            "the link must be back: {again:?}"
        );
        assert_eq!(
            std::fs::read(dest.join("f")).expect("read the file"),
            b"content"
        );
    }

    #[test]
    fn a_large_file_does_not_spend_the_entry_budget() {
        // The entry bound exists to hold a directory cycle. If the copy loop charged its chunks to
        // the same counter, one legitimate multi-megabyte file would be reported as a tree with too
        // many entries, and the diagnostic would name the wrong problem.
        let dir = bsx_test_support::ScratchDir::created("readback-entries");
        let tree = dir.path().join("tree");
        std::fs::create_dir_all(&tree).expect("seed dir");
        // Many `READBACK_CHUNK`s, so a chunk-counting walk is unmistakable against a 4-entry root.
        let chunks = 64;
        std::fs::write(tree.join("big"), vec![3u8; chunks * READBACK_CHUNK]).expect("seed big");

        let deadline = Instant::now() + Duration::from_secs(60);
        let Ok(image) = build_input_image(&tree, dir.path(), deadline) else {
            eprintln!("skipping a_large_file_does_not_spend_the_entry_budget: no working mke2fs");
            return;
        };
        let dest = dir.path().join("out");
        std::fs::create_dir_all(&dest).expect("dest");
        let fs = Ext4::load_from_path(&image).expect("load the image");
        let mut walk = Walk::new(&dest, OUTPUT_EXTRACT_CAP);
        walk.run(&fs).expect("the walk");

        // The root holds `.`, `..`, `lost+found` and `big`; the file's 64 chunks are not entries.
        assert!(
            walk.entries < chunks as u64,
            "a {chunks}-chunk file spent the entry budget: {} entries counted",
            walk.entries
        );
        assert_eq!(
            std::fs::metadata(dest.join("big")).expect("stat big").len(),
            (chunks * READBACK_CHUNK) as u64
        );
    }

    #[test]
    fn an_escaping_symlink_does_not_survive_the_readback() {
        // `mke2fs -d` copies a symlink verbatim into the image, so this is the guest's real escape
        // attempt: the reader recreates the link and the sanitizer has to be what drops it. The
        // in-tree link beside it must be untouched, or "sanitized" would just mean "deleted".
        let dir = bsx_test_support::ScratchDir::created("readback-escape");
        let tree = dir.path().join("tree");
        std::fs::create_dir_all(&tree).expect("seed dir");
        std::fs::write(tree.join("real"), b"kept").expect("seed file");
        std::os::unix::fs::symlink("/etc/shadow", tree.join("escape")).expect("seed escape");
        std::os::unix::fs::symlink("real", tree.join("inside")).expect("seed in-tree");

        let Some((dest, paths)) = round_trip(
            "an_escaping_symlink_does_not_survive_the_readback",
            &tree,
            dir.path(),
        ) else {
            return;
        };

        assert!(
            dest.join("escape").symlink_metadata().is_err(),
            "a link out of the destination must not survive: {paths:?}"
        );
        assert!(
            dest.join("inside").symlink_metadata().is_ok(),
            "an in-tree link must survive: {paths:?}"
        );
    }

    #[test]
    fn the_byte_cap_stops_a_readback_that_would_outgrow_it() {
        // The sparse-file blow-up in miniature: the cap is charged per chunk while copying, so a
        // file larger than the ceiling fails part-way rather than after it has landed on the host.
        let dir = bsx_test_support::ScratchDir::created("readback-cap");
        let tree = dir.path().join("tree");
        std::fs::create_dir_all(&tree).expect("seed dir");
        std::fs::write(tree.join("big"), vec![0u8; 512 * 1024]).expect("seed big file");

        let deadline = Instant::now() + Duration::from_secs(60);
        let Ok(image) = build_input_image(&tree, dir.path(), deadline) else {
            eprintln!("skipping the_byte_cap_stops_a_readback_that_would_outgrow_it: no mke2fs");
            return;
        };
        let dest = dir.path().join("out");
        std::fs::create_dir_all(&dest).expect("dest");
        let fs = Ext4::load_from_path(&image).expect("load the image");

        let err = Walk::new(&dest, 64 * 1024)
            .run(&fs)
            .expect_err("a tree past the cap is not a successful readback");
        assert!(
            matches!(err, VmmError::OutputCap { .. }),
            "the cap must be its own typed error, not a generic one: {err}"
        );
    }

    #[test]
    fn a_readback_into_an_unwritable_dest_names_the_file_it_could_not_write() {
        // A readback that cannot write must fail loudly and name what it could not write; silently
        // returning an empty manifest is the audit-honesty failure of claiming a clean run.
        if bsx_test_support::have_real_root() {
            eprintln!(
                "skipping a_readback_into_an_unwritable_dest_names_the_file_it_could_not_write: \
                 root writes through an unwritable dir, so there is no failure to observe"
            );
            return;
        }
        let dir = bsx_test_support::ScratchDir::created("readback-unwritable");
        let tree = dir.path().join("tree");
        std::fs::create_dir_all(&tree).expect("seed dir");
        std::fs::write(tree.join("payload"), b"guest output").expect("seed payload");

        let deadline = Instant::now() + Duration::from_secs(60);
        let Ok(image) = build_input_image(&tree, dir.path(), deadline) else {
            eprintln!("skipping a_readback_into_an_unwritable_dest_names_the_file: no mke2fs");
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
        let Some(fs) = bsx_test_support::SmallFs::create(8, "mke2fs-full") else {
            eprintln!("skipping a_full_scratch_names_mke2fs_as_the_cause: needs real root");
            return;
        };
        // Zero headroom rather than a comfortable margin. What a 256 MiB ext4 costs on disk is an
        // e2fsprogs question rather than a constant, since a version that punches holes instead of writing
        // the zeroed inode table and journal leaves the image's *allocated* size as metadata only. A full
        // filesystem is the one precondition no version can satisfy, and `truncate` is sparse, so it still
        // gets as far as mke2fs.
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
    fn a_full_output_dir_names_the_file_and_the_cause() {
        // A readback into a full output dir must report the write that failed and the kernel's own
        // reason. The image here is legitimate; only the destination is out of space.
        let Some(fs) = bsx_test_support::SmallFs::create(8, "readback-full") else {
            eprintln!("skipping a_full_output_dir_names_the_file_and_the_cause: needs real root");
            return;
        };
        // The image is built on the *host* filesystem and seeded with real content: this test is
        // about the destination being full, and an empty image would write nothing at all and
        // succeed on any headroom.
        let src = bsx_test_support::ScratchDir::created("readback-src");
        let tree = src.path().join("tree");
        std::fs::create_dir_all(&tree).expect("seed dir");
        for i in 0..4 {
            std::fs::write(tree.join(format!("payload-{i}")), vec![b'x'; 1024 * 1024])
                .expect("seed payload");
        }
        let deadline = Instant::now() + Duration::from_secs(60);
        let Ok(image) = build_input_image(&tree, src.path(), deadline) else {
            eprintln!("skipping a_full_output_dir_names_the_file_and_the_cause: no working mke2fs");
            return;
        };

        let dest = fs.path().join("out");
        // Leave enough for the `create_dir_all`, but far less than the extracted tree, so the
        // failure lands inside the copy rather than before it.
        fs.fill_leaving(128 * 1024);
        let started = Instant::now();
        let err =
            collect_output_image(&image, &dest).expect_err("a full dest cannot hold the readback");
        let msg = err.to_string();

        // The trap this test would otherwise fall into: a readback that *wedges* also produces an
        // error with no trailing colon, so the weaker assertions below would pass on a 120-second
        // timeout, proving nothing.
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
        assert!(
            msg.contains("payload"),
            "the error must name the file it could not write: {msg}"
        );
    }

    #[test]
    fn a_corrupt_ext4_image_returns_a_typed_vmm_error_without_panicking() {
        let dir = bsx_test_support::ScratchDir::created("corrupt-ext4");
        let image_path = dir.path().join("corrupt.ext4");
        let dest = dir.path().join("out");
        std::fs::write(&image_path, vec![0xffu8; 4096]).expect("write corrupt image");
        let err = collect_output_image(&image_path, &dest).expect_err("corrupt image must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("read the output image"),
            "expected typed Vmm error for corrupt ext4 image, got: {msg}"
        );
    }
}
