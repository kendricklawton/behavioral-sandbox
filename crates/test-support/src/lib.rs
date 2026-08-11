//! Test-only helpers shared by the privileged integration-test binaries **across crates**
//! (`bsx` and `bsx-probes-loader` tests).
//!
//! Rust compiles each `tests/*.rs` as its own crate, so a helper used by more than one has to live
//! in a real (dev-)dependency crate rather than be copy-pasted. Never shipped (`publish = false`)
//! and pure-std, so it stays a leaf both suites can borrow without coupling.
#![forbid(unsafe_code)]
// The helpers panic as the idiomatic test assertion, which the workspace's `clippy::panic` deny
// doesn't auto-exempt outside `#[test]` fns.
#![allow(clippy::panic)]

use std::path::{Path, PathBuf};

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
        let memory_max = (u64::from(mem_mib) + MEMORY_OVERHEAD_MIB) * 1024 * 1024;
        std::fs::write(this.dir.join("memory.max"), memory_max.to_string()).ok()?;
        std::fs::write(
            this.dir.join("cpu.max"),
            format!("{cpu_quota_us} {CPU_PERIOD_US}"),
        )
        .ok()?;
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
        let mut written: u64 = 0;
        loop {
            match file.write_all(&chunk) {
                Ok(()) => written += chunk.len() as u64,
                Err(e) if e.kind() == std::io::ErrorKind::StorageFull => break,
                Err(e) => panic!("fill {}: {e}", path.display()),
            }
        }
        assert!(
            written > 0,
            "the fixture was already full before the filler was written"
        );
        if let Err(e) = file.set_len(written.saturating_sub(headroom)) {
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
    use super::{CAP_NET_ADMIN, parse_cap_eff, process_threads, serial_requested};

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
