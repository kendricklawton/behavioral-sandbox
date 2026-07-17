//! Test-only helpers shared by the privileged integration-test binaries **across crates**
//! (`agent-vmm` and `agent-probes-loader` tests). Rust compiles each `tests/*.rs` as its own crate,
//! so a helper used by more than one has to live in a real (dev-)dependency crate rather than be
//! copy-pasted: this is that crate.
//!
//! It is **never shipped** (`publish = false`, a dev-dependency only) and pure-std (no engine deps),
//! so it stays a leaf both the driver and the loader suites can borrow without coupling.
// A test-support crate: `enter` panics as the idiomatic test assertion (the caller treats it like an
// `assert`), which the workspace's `clippy::panic` deny doesn't auto-exempt outside `#[test]` fns —
// the same file-level opt-out the integration-test binaries carry.
#![allow(clippy::panic)]

use std::path::PathBuf;

/// Host-side memory headroom above the guest's RAM for the VMM's own footprint, in MiB. Mirrors the
/// engine's own derivation (`jail`'s `MEMORY_OVERHEAD_MIB`, decision 013), so a test cgroup caps the
/// VMM exactly where the jailer would.
const MEMORY_OVERHEAD_MIB: u64 = 128;
/// The cgroup v2 `cpu.max` accounting period, in microseconds (the kernel default). A quota of
/// `n * this` per period is `n` cores' worth of CPU. Mirrors `jail`'s `CPU_PERIOD_US`.
const CPU_PERIOD_US: u64 = 100_000;

/// A cgroup carrying the engine's own limit derivation (decision 013): `cpu.max` = `vcpus` cores,
/// `memory.max` = guest RAM + the fixed VMM overhead. Built by the test because those limits normally
/// arrive via the jailer, and exec-under-jail is a later migration — so this pins the *same-derived*
/// caps onto an exec-capable boot path and proves they bind under load. `None` (skip) where cgroup v2
/// isn't writable/delegated. Reclaims its dirs on drop (declare it *before* the VM, so it drops after).
pub struct LimitCgroup {
    dir: PathBuf,
    parent: PathBuf,
}

impl LimitCgroup {
    /// Create a leaf cgroup with the derived caps. The parent dir is `tag`-scoped so two of these in
    /// one test (a co-resident victim and attacker) get **independent** parents: `create_dir` errors
    /// on an existing path, which would otherwise silently make the second `None` and skip the whole
    /// test. Returns `None` where cgroup v2 isn't writable or delegated.
    #[must_use]
    pub fn create(vcpus: u32, mem_mib: u32, tag: &str) -> Option<Self> {
        let parent = PathBuf::from("/sys/fs/cgroup")
            .join(format!("agent-test-{}-{tag}", std::process::id()));
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
        let cpu_quota = u64::from(vcpus) * CPU_PERIOD_US;
        std::fs::write(this.dir.join("memory.max"), memory_max.to_string()).ok()?;
        std::fs::write(
            this.dir.join("cpu.max"),
            format!("{cpu_quota} {CPU_PERIOD_US}"),
        )
        .ok()?;
        Some(this)
    }

    /// Move `pid` (its whole thread group) into the limited cgroup. Panics if the write fails — the
    /// idiomatic test assertion (the caller treats this like an `assert`).
    pub fn enter(&self, pid: u32) {
        if let Err(e) = std::fs::write(self.dir.join("cgroup.procs"), pid.to_string()) {
            panic!("move pid {pid} into {}: {e}", self.dir.display());
        }
    }

    /// The raw contents of a control file in the leaf (`memory.peak`, `memory.max`, …); empty if
    /// unreadable.
    #[must_use]
    pub fn read(&self, file: &str) -> String {
        std::fs::read_to_string(self.dir.join(file)).unwrap_or_default()
    }

    /// A named counter out of a flat `key value` stat file (`memory.events`, `cpu.stat`); `0` if
    /// the key is absent.
    #[must_use]
    pub fn stat(&self, file: &str, key: &str) -> u64 {
        self.read(file)
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0)
    }
}

impl Drop for LimitCgroup {
    fn drop(&mut self) {
        // The VM must already be reaped (declare the cgroup before the VM, so it drops after).
        let _ = std::fs::remove_dir(&self.dir);
        let _ = std::fs::remove_dir(&self.parent);
    }
}

/// `CAP_NET_ADMIN` (capability bit 12): creating a netns/tap needs it, so the network-gated
/// privileged tests skip without it. Defined beside [`have_cap`] so the bit number and the parse
/// that reads it live in one audited place.
pub const CAP_NET_ADMIN: u32 = 12;

/// Whether this process's **effective** capability set holds `cap` (a capability bit number, e.g.
/// [`CAP_NET_ADMIN`]). Reads the `CapEff:` hex mask from `/proc/self/status`; a privileged test
/// *skips* (never fails) when this is false, so the parse must never read a capable host as
/// incapable — a false "no caps" here is a test that silently proves nothing.
#[must_use]
pub fn have_cap(cap: u32) -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| parse_cap_eff(&s))
        .is_some_and(|mask| cap < 64 && (mask >> cap) & 1 == 1)
}

/// The low 64 bits of the `CapEff:` hex mask out of `/proc/<pid>/status` text, or `None` when the
/// line is absent or unparseable. Mirrors the loader's audited production parse
/// (`agent-probes-loader`'s `parse_cap_eff`, which the host path can't share with a dev-only
/// crate): only the **trailing 16 hex digits** (bits 0–63, where every capability lives) are read,
/// so a hypothetically wider future field can't overflow the `u64` parse into a false "no caps".
/// Pure (takes the text), so the guard is unit-tested without a live `/proc`.
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

/// Whether this process is real root (effective uid 0) — the gate for putting a VMM under a test
/// cgroup. Reads `/proc/self/status`; a privileged test *skips* (never fails) when this is false.
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
/// assertion: guest forks must never become host threads. `0` if the process is gone.
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
    use super::{parse_cap_eff, CAP_NET_ADMIN};

    #[test]
    fn cap_eff_parses_the_effective_line_only() {
        // A real `/proc/self/status` carries several `Cap*` rows; only `CapEff:` is the effective
        // set (mirrors the loader's own pin on its production parse).
        let status = "Name:\tthing\nCapInh:\t0000000000000000\nCapPrm:\tffffffffffffffff\n\
                      CapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\n";
        assert_eq!(parse_cap_eff(status), Some(0x0000_01ff_ffff_ffff));
    }

    #[test]
    fn cap_eff_absent_or_malformed_is_none() {
        assert_eq!(parse_cap_eff("CapPrm:\t00\n"), None); // no CapEff line at all
        assert_eq!(parse_cap_eff("CapEff:\tnothex\n"), None); // present but unparseable
        assert_eq!(parse_cap_eff("CapEff:\t\n"), None); // present but empty
        assert_eq!(parse_cap_eff(""), None);
    }

    #[test]
    fn cap_eff_reads_low_64_bits_of_a_hypothetically_wider_field() {
        // The finding this helper exists for: a `CapEff` wider than 16 hex digits must not overflow
        // the `u64` parse into `None` — which a skip-gated test would read as "no caps" and
        // silently skip on a fully capable host. Only the low 64 bits (where CAP_NET_ADMIN lives)
        // are read.
        let mask = 1u64 << CAP_NET_ADMIN;
        let wide = format!("CapEff:\tdeadbeef{mask:016x}\n"); // 8 extra high digits
        assert_eq!(parse_cap_eff(&wide), Some(mask));
    }
}
