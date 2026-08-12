//! Test-only helpers shared by more than one crate's tests: the host-capability predicates, scratch
//! guards and small filesystems the privileged integration binaries need, and the deterministic
//! generator the in-gate fuzz suites drive their decoders with.
//!
//! Rust compiles each `tests/*.rs` as its own crate, so a helper used by more than one has to live
//! in a real (dev-)dependency crate rather than be copy-pasted. Never shipped (`publish = false`)
//! and pure-std, so it stays a leaf every suite can borrow without coupling.
#![forbid(unsafe_code)]
// The helpers panic as the idiomatic test assertion, which the workspace's `clippy::panic` deny
// doesn't auto-exempt outside `#[test]` fns.
#![allow(clippy::panic)]

use std::path::{Path, PathBuf};

/// The workspace root, from the calling crate's manifest dir, so a test finds `artifacts/` whatever
/// the cwd. `CARGO_MANIFEST_DIR` expands where this crate is compiled (`crates/test-support`), so
/// the same two levels up hold for every caller.
#[must_use]
pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Why this host cannot boot a guest, or `None` when it can: the two artifacts every VM test needs.
///
/// A test that skips itself is a **pass**, so the predicates deciding that belong in one place
/// rather than in each `tests/*.rs`. Returns a reason a test can print, so a skip says why.
#[must_use]
pub fn vm_skip_reason() -> Option<String> {
    if !Path::new("/dev/kvm").exists() {
        return Some("/dev/kvm not present".into());
    }
    if !workspace_root()
        .join("artifacts/rootfs-guest.ext4")
        .is_file()
    {
        return Some("guest rootfs not built (run `cargo xtask build-rootfs`)".into());
    }
    None
}

/// Refuses to run a test that measures **process-global** state beside its siblings.
///
/// libtest runs tests in parallel by default. A test asserting on open fds, thread count, mounts, or
/// every `bsx-<pid>-*` scratch dir is measuring the whole test *binary*, since `std::process::id()`
/// is shared: a concurrent sibling's live VM is indistinguishable from a leak. Call it first in such
/// a test, or in the fixture that makes it global (see [`SmallFs::create`]).
pub fn require_serial(what: &str) {
    let args: Vec<String> = std::env::args().collect();
    let env = std::env::var("RUST_TEST_THREADS").ok();
    if serial_requested(&args, env.as_deref()) {
        return;
    }
    panic!(
        "{what} asserts on process-global state (fds, threads, mounts, or every bsx-<pid>-* dir), \
         so it cannot run beside another test in this binary, and libtest runs tests in parallel by \
         default. Re-run with `--test-threads=1`, or use `cargo xtask ci-privileged`, which passes \
         it for you."
    );
}

/// Whether the harness was told to run one test at a time, by flag or by environment. Pure, so the
/// spellings libtest accepts (`--test-threads=1`, `--test-threads 1`, `RUST_TEST_THREADS`) are
/// unit-tested rather than assumed.
fn serial_requested(args: &[String], env: Option<&str>) -> bool {
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if let Some(v) = arg.strip_prefix("--test-threads=") {
            return v.trim() == "1";
        }
        if arg == "--test-threads" {
            return it.next().map(|v| v.trim()) == Some("1");
        }
    }
    // The flag wins over the environment.
    env.map(str::trim) == Some("1")
}

/// A `Write` sink that appends into a shared buffer, for a test asserting on what was **logged**.
///
/// `tracing::subscriber::with_default` is thread-local, so a subscriber has to be installed inside
/// each thread whose output matters while the buffer stays shared: [`subscriber`](Self::subscriber)
/// hands out one per thread over the same [`LogSink`], and [`contents`](Self::contents) reads them
/// all back. Behind the `tracing-capture` feature, so the crates that borrow only the pure-std
/// helpers keep an empty dependency list.
#[cfg(feature = "tracing-capture")]
#[derive(Clone, Default)]
pub struct LogSink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

#[cfg(feature = "tracing-capture")]
impl std::io::Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "tracing-capture")]
impl LogSink {
    /// A subscriber writing every level into this sink, to install on one thread.
    #[must_use]
    pub fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync + use<> {
        let sink = self.clone();
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || sink.clone())
            .finish()
    }

    /// Everything captured so far, lossily decoded.
    #[must_use]
    pub fn contents(&self) -> String {
        String::from_utf8_lossy(
            &self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
        .into_owned()
    }
}

/// A `xorshift64*` PRNG: deterministic, seedable, zero-dependency. Not cryptographic, it only has to
/// spray varied bytes at a decoder reproducibly.
///
/// Shared because the crates that fuzz their own decoders in-gate are leaves that will not take a
/// `proptest`/`arbitrary` tree as a dev-dependency, and this crate's empty `[dependencies]` costs
/// them nothing. Fixed seeds mean a failure reproduces exactly and the gate never flakes.
pub struct Rng(u64);

impl Rng {
    /// Seeds the generator. Forces the state odd, because zero is a fixed point for xorshift.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    /// Draws the next 64-bit value, advancing the state.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A value in `0..n`, and 0 when `n == 0`, so callers never divide by zero.
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    /// One byte, taken from the high bits, which `xorshift64*` mixes best.
    pub fn byte(&mut self) -> u8 {
        (self.next_u64() >> 33) as u8
    }

    /// `len` random bytes.
    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }

    /// A byte vector of a random length in `0..max`, the two draws sequenced so neither borrows
    /// `self` inside the other's call.
    pub fn bytes_upto(&mut self, max: usize) -> Vec<u8> {
        let len = self.below(max);
        self.bytes(len)
    }
}

/// A host scratch dir reclaimed on drop, so a panicking assertion or an early `?` return can't leak
/// it. Unique per (pid, tag, sequence), so parallel tests in one process never collide.
pub struct ScratchDir(PathBuf);

impl ScratchDir {
    /// Reserves a unique scratch path (clearing any stale copy) without creating the dir, for
    /// callers handing it to code that creates it.
    #[must_use]
    pub fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "bsx-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        Self(dir)
    }

    /// Like [`new`](Self::new) but also creates the directory. Panics if it can't be created.
    #[must_use]
    pub fn created(tag: &str) -> Self {
        let this = Self::new(tag);
        if let Err(e) = std::fs::create_dir_all(&this.0) {
            panic!("create scratch dir {}: {e}", this.0.display());
        }
        this
    }

    /// Adopts an existing dir (one the code under test produced) so it is reclaimed on drop.
    #[must_use]
    pub fn adopt(dir: PathBuf) -> Self {
        Self(dir)
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Host-side memory headroom above the guest's RAM for the VMM's own footprint, in MiB. Mirrors
/// `jail`'s `MEMORY_OVERHEAD_MIB`, so a test cgroup caps the VMM exactly where the jailer would.
const MEMORY_OVERHEAD_MIB: u64 = 128;
/// The cgroup v2 `cpu.max` accounting period in microseconds (the kernel default), mirroring
/// `jail`'s `CPU_PERIOD_US`. A quota of `n * this` per period is `n` cores' worth of CPU.
const CPU_PERIOD_US: u64 = 100_000;

/// A cgroup carrying the engine's own limit derivation: `cpu.max` = `vcpus` cores, `memory.max` =
/// guest RAM + the fixed VMM overhead.
///
/// Built by the test because those limits normally arrive via the jailer, which pins the
/// same-derived caps onto an exec-capable boot path. Reclaims its dirs on drop, so declare it
/// *before* the VM to make it drop after.
pub struct LimitCgroup {
    dir: PathBuf,
    parent: PathBuf,
}

impl LimitCgroup {
    /// Creates a leaf cgroup with the derived caps, or `None` where cgroup v2 isn't writable or
    /// delegated. The parent dir is `tag`-scoped so two of these in one test get independent
    /// parents: `create_dir` errors on an existing path, which would otherwise make the second
    /// `None` and silently skip the test.
    #[must_use]
    pub fn create(vcpus: u32, mem_mib: u32, tag: &str) -> Option<Self> {
        Self::create_with_quota(u64::from(vcpus) * CPU_PERIOD_US, mem_mib, tag)
    }

    /// Like [`create`](Self::create), but with the CPU quota in `millicores` (1000 = one core).
    ///
    /// A quota equal to the vCPU count is satisfied by the hardware alone, which makes an
    /// enforcement assert built on it unfalsifiable; pinning the quota *below* the vCPU bound is
    /// what distinguishes "the cgroup capped it" from "the vCPU count capped it".
    pub fn create_cpu_millicores(millicores: u64, mem_mib: u32, tag: &str) -> Option<Self> {
        Self::create_with_quota(millicores * CPU_PERIOD_US / 1000, mem_mib, tag)
    }

    fn create_with_quota(cpu_quota_us: u64, mem_mib: u32, tag: &str) -> Option<Self> {
        let parent =
            PathBuf::from("/sys/fs/cgroup").join(format!("bsx-test-{}-{tag}", std::process::id()));
        std::fs::create_dir(&parent).ok()?;
        let this = Self {
            dir: parent.join("leaf"),
            parent,
        };
        // The parent holds no processes, so the cgroup v2 no-internal-processes rule doesn't apply;
        // this still needs cpu+memory delegated to the cgroup root (the jailer's prerequisite too).
        std::fs::write(this.parent.join("cgroup.subtree_control"), "+cpu +memory").ok()?;
        std::fs::create_dir(&this.dir).ok()?;
        let memory_max = ((u64::from(mem_mib) + MEMORY_OVERHEAD_MIB) * 1024 * 1024).to_string();
        std::fs::write(this.dir.join("memory.max"), &memory_max).ok()?;
        let cpu_max = format!("{cpu_quota_us} {CPU_PERIOD_US}");
        std::fs::write(this.dir.join("cpu.max"), &cpu_max).ok()?;
        // The writes succeeding proves delegation only if these paths are a cgroup at all: a
        // v1/hybrid host (or any tmpfs shadowing /sys/fs/cgroup) presents ordinary files that
        // accept every write above. Panic rather than return `None`, [`SmallFs::create`]'s
        // posture: a fixture that is silently a plain directory greens every enforcement test
        // without capping anything, and `None` reads as an ordinary skip.
        if let Err(why) = leaf_holds_the_limits(&this.dir, &memory_max, &cpu_max) {
            panic!(
                "{} accepted the limit writes but is not a working cgroup v2 leaf: {why}. The \
                 enforcement tests need cgroup v2 mounted at /sys/fs/cgroup with cpu+memory \
                 delegated; a v1/hybrid host presents that path as ordinary files instead",
                this.dir.display()
            );
        }
        Some(this)
    }

    /// Moves `pid` (its whole thread group) into the limited cgroup. Panics if the write fails.
    pub fn enter(&self, pid: u32) {
        if let Err(e) = std::fs::write(self.dir.join("cgroup.procs"), pid.to_string()) {
            panic!("move pid {pid} into {}: {e}", self.dir.display());
        }
    }

    /// The raw contents of a control file in the leaf (`memory.peak`, `memory.max`, …). Panics if
    /// unreadable, since a defaulted `""` would green an enforcement assert over a file that was
    /// never read.
    #[must_use]
    pub fn read(&self, file: &str) -> String {
        let path = self.dir.join(file);
        match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => panic!("read control file {}: {e}", path.display()),
        }
    }

    /// [`read`](Self::read) for a control file that may legitimately not exist (a kernel-version
    /// gate like `memory.peak`, 5.19+), so the caller names the real requirement in its own
    /// `expect` rather than failing on a bare ENOENT.
    #[must_use]
    pub fn maybe_read(&self, file: &str) -> Option<String> {
        std::fs::read_to_string(self.dir.join(file)).ok()
    }

    /// A named counter out of a flat `key value` stat file (`memory.events`, `cpu.stat`). Panics on
    /// an unreadable file, an absent key, or a malformed value: every caller asserts on a key
    /// cgroup v2 guarantees, so its absence means the measurement didn't happen, not that it was
    /// zero.
    #[must_use]
    pub fn stat(&self, file: &str, key: &str) -> u64 {
        match self
            .read(file)
            .lines()
            // The space after the key is part of the match: a bare `strip_prefix` would let a
            // shorter key claim a longer one's line (`oom` matching `oom_kill 3`).
            .find_map(|l| l.strip_prefix(key)?.strip_prefix(' '))
            .map(|v| v.trim().parse())
        {
            Some(Ok(n)) => n,
            Some(Err(e)) => panic!("parse `{key}` in {file}: {e}"),
            None => panic!("no `{key}` line in {file} (nothing measured, not zero)"),
        }
    }
}

impl Drop for LimitCgroup {
    fn drop(&mut self) {
        // The VM must already be reaped (declare the cgroup before the VM, so it drops after).
        let _ = std::fs::remove_dir(&self.dir);
        let _ = std::fs::remove_dir(&self.parent);
    }
}

/// Why `dir` is not a cgroup v2 leaf holding exactly these limits, or `Ok(())` when it is. The
/// kernel's own evidence is required (`cgroup.controllers` is a file cgroupfs creates, never a
/// writer), then both limits are read back, so "the write succeeded" is never the proof. Takes the
/// dir as an argument so the check runs against a staged directory in tests.
fn leaf_holds_the_limits(dir: &Path, memory_max: &str, cpu_max: &str) -> Result<(), String> {
    if std::fs::read_to_string(dir.join("cgroup.controllers")).is_err() {
        return Err(
            "no cgroup.controllers beside the limit files, so this is a plain directory, not a \
             cgroup"
                .into(),
        );
    }
    for (file, wrote) in [("memory.max", memory_max), ("cpu.max", cpu_max)] {
        match std::fs::read_to_string(dir.join(file)) {
            Ok(back) if back.trim() == wrote => {}
            Ok(back) => {
                return Err(format!(
                    "{file} reads back {:?} where {wrote:?} was written, so the cap did not take",
                    back.trim()
                ));
            }
            Err(e) => return Err(format!("{file} was written but is unreadable: {e}")),
        }
    }
    Ok(())
}

/// A size-bounded filesystem a test can fill, the vehicle for the engine's disk-full paths: the
/// all-or-nothing restore staging, the snapshot bundle's partial-write sweep, the image builders.
///
/// tmpfs rather than a loop-backed ext4: it needs no free loop device and no `mkfs`, and gives the
/// same `ENOSPC` on write. The trade is that ext4-specific exhaustion (inodes, block-group
/// allocation) is out of reach. `dev` is not decoration: a tmpfs is `nodev` by default and the
/// jailer makes device nodes in a chroot staged on the scratch dir, so a `nodev` fixture would fail
/// a jailed boot for a reason unrelated to the disk being full. `None` (skip) without real root,
/// since mounting needs `CAP_SYS_ADMIN`. Unmounts and reclaims on drop, so declare it *before*
/// anything writing into it.
pub struct SmallFs {
    // Dropped after the unmount below, which is what makes the reclaim hit the host dir rather than
    // the tmpfs's contents.
    dir: ScratchDir,
}

impl SmallFs {
    /// Mounts a `mib`-megabyte tmpfs on a fresh scratch dir. Panics if the mount reports success but
    /// did not take, since silently handing back the host's own filesystem would let every
    /// disk-full test pass without filling anything.
    #[must_use]
    pub fn create(mib: u64, tag: &str) -> Option<Self> {
        // Root first: without it this fixture skips, so refusing a parallel run here would nag a
        // dev about an invocation for a test they cannot run either way.
        if !have_real_root() {
            return None;
        }
        // Mounting is process-wide, and this fixture's premise is a filesystem of a known size at a
        // known path. A sibling mounting concurrently breaks that premise, and the symptom lands
        // elsewhere: the tool under test simply succeeds where the test required it to fail.
        require_serial(&format!("the SmallFs fixture ({tag})"));
        let dir = ScratchDir::created(tag);
        let ok = std::process::Command::new("mount")
            .arg("-t")
            .arg("tmpfs")
            .arg("-o")
            .arg(format!("size={mib}M,dev"))
            .arg("tmpfs")
            .arg(dir.path())
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            return None;
        }
        let this = Self { dir };
        assert!(
            this.is_mounted(),
            "mount reported success but {} carries no tmpfs: a fixture that is silently the host \
             filesystem would green every disk-full test without filling anything",
            this.path().display()
        );
        // `is_mounted` alone only proves *something* is mounted. With the size option dropped or
        // misparsed, tmpfs falls back to half of RAM and the mount check still passes, so assert
        // the size took, with slack for tmpfs rounding.
        if let Some((total, _)) = this.size_bytes() {
            let asked = mib * 1024 * 1024;
            assert!(
                total <= asked * 2,
                "asked for a {mib} MiB fixture at {} but got {total} bytes: the size option did \
                 not take, so this filesystem cannot be filled and every disk-full test built on \
                 it would pass without testing anything",
                this.path().display()
            );
        }
        Some(this)
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Fills the filesystem, then hands back `headroom` bytes of it.
    ///
    /// Writing until `ENOSPC` and shrinking needs no `statvfs` (this crate is pure-std) and leaves
    /// the actual remaining space at `headroom` rather than at whatever a free-block calculation
    /// guessed. **Any non-zero headroom is a wager that the target allocates more than that**, and
    /// losing it quietly leaves the caller passing while testing nothing: pass `0` unless a small
    /// write genuinely has to succeed first. Panics on an I/O error other than a full disk.
    pub fn fill_leaving(&self, headroom: u64) {
        use std::io::Write as _;
        let path = self.path().join("bsx-filler");
        let mut file = match std::fs::File::create(&path) {
            Ok(f) => f,
            Err(e) => panic!("create the filler in {}: {e}", self.path().display()),
        };
        let chunk = vec![0u8; 64 * 1024];
        loop {
            match file.write_all(&chunk) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::StorageFull => break,
                Err(e) => panic!("fill {}: {e}", path.display()),
            }
        }
        // What the filesystem took, not what the loop counted: `write_all` can fail having
        // delivered part of its chunk, and those bytes reach the file without reaching any
        // caller-side tally. Truncating to an undercount would hand back space this method
        // promises is gone.
        let taken = match file.metadata() {
            Ok(m) => m.len(),
            Err(e) => panic!("measure the filler {}: {e}", path.display()),
        };
        assert!(
            taken > 0,
            "the fixture was already full before the filler was written"
        );
        if let Err(e) = file.set_len(taken.saturating_sub(headroom)) {
            panic!("shrink the filler to leave {headroom} bytes: {e}");
        }
    }

    /// This fixture's `(total, available)` bytes via `df`, or `None` if `df` is missing or its
    /// output does not parse, so a diagnostic can never be the thing that fails a test.
    ///
    /// **`-k -P`, not `--output=`**: the latter is a GNU coreutils extension busybox `df` lacks, and
    /// this backs the size assertion in [`create`](Self::create), which a flag the host might not
    /// support would silently skip. `-P` is POSIX and pins the column layout, so a long device name
    /// cannot wrap the row and shift the fields.
    #[must_use]
    pub fn size_bytes(&self) -> Option<(u64, u64)> {
        let out = std::process::Command::new("df")
            .args(["-k", "-P"])
            .arg(self.path())
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        // POSIX columns: Filesystem, 1024-blocks, Used, Available, Capacity, Mounted-on.
        let fields: Vec<&str> = text.lines().nth(1)?.split_whitespace().collect();
        let kb =
            |i: usize| -> Option<u64> { fields.get(i)?.parse::<u64>().ok()?.checked_mul(1024) };
        Some((kb(1)?, kb(3)?))
    }

    /// A one-line dump of what this fixture actually is right now, for a failure message.
    ///
    /// A disk-full test fails saying the tool "unexpectedly succeeded", a symptom of the *fixture*:
    /// whether the small filesystem is still mounted and how much room it really had are the useful
    /// questions, and these tests only fail on hosts where nobody can attach a shell afterwards.
    #[must_use]
    pub fn state(&self) -> String {
        let size = self.size_bytes().map_or_else(
            || "size unknown (df failed)".to_string(),
            |(total, avail)| format!("{total} bytes total, {avail} available"),
        );
        format!(
            "{}: mounted={}, {size}",
            self.path().display(),
            self.is_mounted()
        )
    }

    /// Whether a filesystem is mounted at this fixture's dir, read from `/proc/self/mountinfo`
    /// (field 5 is the mount point). The fail-closed half of [`create`](Self::create).
    #[must_use]
    pub fn is_mounted(&self) -> bool {
        let target = self.path().to_string_lossy().to_string();
        std::fs::read_to_string("/proc/self/mountinfo")
            .unwrap_or_default()
            .lines()
            .any(|l| l.split(' ').nth(4) == Some(&target))
    }
}

impl Drop for SmallFs {
    fn drop(&mut self) {
        let unmounted = std::process::Command::new("umount")
            .arg(self.dir.path())
            .status()
            .is_ok_and(|s| s.success());
        if !unmounted {
            // Something still holds the mount (a helper the test detached rather than reaped). A
            // lazy unmount detaches it now and lets the kernel free it when the last reference
            // goes, so a leaked mount can't poison the next run's fixture.
            let _ = std::process::Command::new("umount")
                .arg("-l")
                .arg(self.dir.path())
                .status();
        }
    }
}

/// `CAP_NET_ADMIN` (capability bit 12), which creating a netns/tap needs. Defined beside
/// [`have_cap`] so the bit number and the parse reading it live in one audited place.
pub const CAP_NET_ADMIN: u32 = 12;

/// Whether this process's **effective** capability set holds `cap` (a bit number, e.g.
/// [`CAP_NET_ADMIN`]), read from the `CapEff:` hex mask in `/proc/self/status`. A privileged test
/// skips rather than fails when this is false, so a false "no caps" is a test that proves nothing.
#[must_use]
pub fn have_cap(cap: u32) -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| parse_cap_eff(&s))
        .is_some_and(|mask| cap < 64 && (mask >> cap) & 1 == 1)
}

/// The low 64 bits of the `CapEff:` hex mask out of `/proc/<pid>/status` text, or `None` when the
/// line is absent or unparseable. Only the trailing 16 hex digits (bits 0-63, where every
/// capability lives) are read, so a wider future field can't overflow the `u64` parse into a false
/// "no caps". Pure, so the guard is unit-tested without a live `/proc`.
fn parse_cap_eff(status: &str) -> Option<u64> {
    let hex = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))?
        .trim();
    if hex.is_empty() || !hex.is_ascii() {
        return None;
    }
    let low64 = &hex[hex.len().saturating_sub(16)..];
    u64::from_str_radix(low64, 16).ok()
}

/// Whether this process is real root (effective uid 0), the gate for putting a VMM under a test
/// cgroup. A privileged test skips rather than fails when this is false.
#[must_use]
pub fn have_real_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Uid:").map(|v| v.trim().to_string()))
        })
        // `Uid:` is real/effective/saved/fs; the effective uid is the second field.
        .and_then(|v| {
            v.split_whitespace()
                .nth(1)
                .and_then(|e| e.parse::<u32>().ok())
        })
        .is_some_and(|euid| euid == 0)
}

/// A process's host thread count (`/proc/<pid>/status` `Threads:`), for the hardware-isolation
/// assertion that guest forks never become host threads. `0` if the process is gone.
///
/// The workspace's one thread-count read: the confinement and hardening suites measure a VMM pid
/// with it, and `bsx-engine`'s boot soak and wedged-dial test measure their own. **`0` on a failed
/// read is why every caller floors its baseline first**: a flat-count assertion would otherwise pass
/// as `0 == 0` having measured nothing.
#[must_use]
pub fn process_threads(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Threads:"))
                .and_then(|v| v.trim().parse().ok())
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{
        CAP_NET_ADMIN, Rng, ScratchDir, leaf_holds_the_limits, parse_cap_eff, process_threads,
        serial_requested, workspace_root,
    };

    /// The generator repeats for a seed and never sticks, the two properties the fuzz suites that
    /// share it rely on.
    ///
    /// Reproducibility is the whole reason these suites hand-rolled a PRNG instead of taking
    /// `proptest`: a failure has to be re-runnable from its seed alone. A state that sticks is the
    /// silent version of the same loss, a suite drawing one value forever and reporting a pass.
    #[test]
    fn the_generator_repeats_for_a_seed_and_never_sticks() {
        let draws = |seed| {
            let mut rng = Rng::new(seed);
            (0..64).map(|_| rng.next_u64()).collect::<Vec<_>>()
        };
        assert_eq!(draws(7), draws(7), "the same seed must replay a failure");
        assert_ne!(
            draws(7),
            draws(8),
            "a different seed must explore elsewhere"
        );

        // Zero is xorshift's fixed point, so `new` forces the state odd; without that the whole
        // corpus below would be one value repeated.
        let zeroed = draws(0);
        assert!(
            zeroed.iter().any(|&x| x != zeroed[0]),
            "a zero seed must still advance"
        );

        // `below(0)` is the divide-by-zero the callers lean on being handled, since they pass a
        // collection length.
        assert_eq!(Rng::new(1).below(0), 0);
        let mut rng = Rng::new(3);
        assert!((0..256).all(|_| rng.below(4) < 4), "`below` stays in range");
        assert_eq!(Rng::new(5).bytes(9).len(), 9);
        assert!(Rng::new(5).bytes_upto(16).len() <= 16);
    }

    /// The root resolves from **this** crate's manifest dir, not the caller's.
    ///
    /// `CARGO_MANIFEST_DIR` expands where the macro is written, so hoisting this helper out of the
    /// test binaries that each had their own copy silently re-anchored it from `crates/<caller>` to
    /// `crates/test-support`. Both are two levels down, which is why the same `../..` still holds,
    /// and this is what says so rather than leaving it to a privileged run to discover.
    #[test]
    fn the_workspace_root_resolves_from_this_crates_manifest_dir() {
        let root = workspace_root();
        assert!(
            root.join("crates/test-support/Cargo.toml").is_file(),
            "workspace_root() must land on the workspace, got {}",
            root.display()
        );
        // The artifact paths every caller builds on it, so a wrong root is caught here, not by a
        // privileged suite skipping itself with "guest rootfs not built".
        assert!(
            root.join("crates").is_dir() && root.join("xtask").is_dir(),
            "the root holds the workspace's own directories: {}",
            root.display()
        );
    }

    #[test]
    fn the_thread_count_is_live_for_a_live_pid_and_zero_for_a_gone_one() {
        // Both halves of the contract three suites are built on. A live process always has at least
        // this thread, so the floor the callers assert (`>= 1`, `>= 2`) is reachable...
        let live = process_threads(std::process::id());
        assert!(
            live >= 1,
            "this process has at least one thread, got {live}"
        );

        // ...and a pid that cannot exist reads as `0` rather than propagating an error, which is
        // exactly what makes those floors load-bearing: without them a flat-count assertion passes
        // as `0 == 0` on a VMM that died mid-test.
        assert_eq!(
            process_threads(u32::MAX),
            0,
            "no /proc entry for a pid past pid_max"
        );
    }

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn every_spelling_of_the_serial_flag_is_recognised() {
        assert!(serial_requested(
            &args(&["bin", "--ignored", "--test-threads=1"]),
            None
        ));
        assert!(serial_requested(
            &args(&["bin", "--test-threads", "1"]),
            None
        ));
        assert!(serial_requested(&args(&["bin"]), Some("1")));

        assert!(!serial_requested(&args(&["bin", "--ignored"]), None));
        assert!(!serial_requested(&args(&["bin", "--test-threads=8"]), None));
        assert!(!serial_requested(
            &args(&["bin", "--test-threads", "8"]),
            None
        ));
        assert!(!serial_requested(&args(&["bin"]), Some("8")));
        // A trailing `--test-threads` with no value is not a serial run.
        assert!(!serial_requested(&args(&["bin", "--test-threads"]), None));
        assert!(serial_requested(
            &args(&["bin", "--test-threads=1"]),
            Some("8")
        ));
        assert!(!serial_requested(
            &args(&["bin", "--test-threads=8"]),
            Some("1")
        ));
    }

    /// The reproduced host shape: a tmpfs (or v1 hierarchy) at /sys/fs/cgroup accepts every
    /// limit write into ordinary files. `cgroup.controllers` is a file only cgroupfs creates, so
    /// its absence is what unmasks the imposter, staged here byte-for-byte.
    #[test]
    fn a_plain_directory_holding_the_limit_files_is_not_a_cgroup() {
        let dir = ScratchDir::created("not-a-cgroup");
        std::fs::write(dir.path().join("memory.max"), "671088640").expect("stage");
        std::fs::write(dir.path().join("cpu.max"), "100000 100000").expect("stage");
        let why = leaf_holds_the_limits(dir.path(), "671088640", "100000 100000")
            .expect_err("ordinary files must not pass for a cgroup");
        assert!(
            why.contains("cgroup.controllers"),
            "the refusal names the missing kernel evidence: {why}"
        );
    }

    /// On a real leaf the caps must read back as written: an accepted-but-clamped write is a
    /// fixture that vouches for a limit the kernel is not holding.
    #[test]
    fn the_limits_must_read_back_as_written() {
        let dir = ScratchDir::created("cgroup-shaped");
        std::fs::write(dir.path().join("cgroup.controllers"), "cpu memory\n").expect("stage");
        std::fs::write(dir.path().join("memory.max"), "671088640\n").expect("stage");
        std::fs::write(dir.path().join("cpu.max"), "100000 100000\n").expect("stage");
        assert!(leaf_holds_the_limits(dir.path(), "671088640", "100000 100000").is_ok());

        std::fs::write(dir.path().join("memory.max"), "9223372036854771712\n").expect("restage");
        let why = leaf_holds_the_limits(dir.path(), "671088640", "100000 100000")
            .expect_err("a cap that did not take must be refused");
        assert!(why.contains("memory.max"), "{why}");
    }

    #[test]
    fn cap_eff_parses_the_effective_line_only() {
        let status = "Name:\tthing\nCapInh:\t0000000000000000\nCapPrm:\tffffffffffffffff\n\
                      CapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\n";
        assert_eq!(parse_cap_eff(status), Some(0x0000_01ff_ffff_ffff));
    }

    #[test]
    fn cap_eff_absent_or_malformed_is_none() {
        assert_eq!(parse_cap_eff("CapPrm:\t00\n"), None);
        assert_eq!(parse_cap_eff("CapEff:\tnothex\n"), None);
        assert_eq!(parse_cap_eff("CapEff:\t\n"), None);
        assert_eq!(parse_cap_eff(""), None);
    }

    #[test]
    fn cap_eff_reads_low_64_bits_of_a_hypothetically_wider_field() {
        let mask = 1u64 << CAP_NET_ADMIN;
        let wide = format!("CapEff:\tdeadbeef{mask:016x}\n"); // 8 extra high digits
        assert_eq!(parse_cap_eff(&wide), Some(mask));
    }
}
