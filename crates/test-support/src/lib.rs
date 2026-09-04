//! Test-only helpers shared by more than one crate's tests: a scratch dir that reclaims itself, a
//! log sink for asserting on what was logged, and the deterministic generator the in-gate fuzz
//! suites drive their decoders with.
//!
//! Rust compiles each `tests/*.rs` as its own crate, so a helper used by more than one has to live
//! in a real (dev-)dependency crate rather than be copy-pasted. Never shipped (`publish = false`)
//! and pure-std, so it stays a leaf every suite can borrow without coupling.
//!
//! One host-capability probe lives here too ([`hypervisor_unusable`]), because the leak tests and the
//! benches both refuse a host that cannot boot a VM and should refuse it with one message.

#![forbid(unsafe_code)]
// The helpers panic as the idiomatic test assertion, which the workspace's `clippy::panic` deny
// doesn't auto-exempt outside `#[test]` fns.
#![allow(clippy::panic)]

use std::path::{Path, PathBuf};

/// Why a hypervisor cannot back a VM from this process, or `None` when it can.
///
/// Asks the question **this** host can answer, which is the same capability either way: Linux opens
/// `/dev/kvm` read-write, as a VMM needs, and the common failure is a user outside the `kvm` group.
/// macOS asks the kernel whether the machine virtualises at all, because reaching
/// Hypervisor.framework itself would need the caller to carry `com.apple.security.hypervisor`, and
/// a test binary is never signed.
#[must_use]
pub fn hypervisor_unusable() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
        {
            Ok(_) => None,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some("/dev/kvm is absent".into()),
            Err(e) => Some(format!(
                "/dev/kvm cannot be opened read-write ({e}); membership of the kvm group is the \
                 usual fix"
            )),
        }
    }
    #[cfg(target_os = "macos")]
    {
        let answers = std::process::Command::new("sysctl")
            .args(["-n", "kern.hv_support"])
            .output()
            .is_ok_and(|out| out.status.success() && out.stdout.starts_with(b"1"));
        if !answers {
            return Some("this machine reports no Hypervisor.framework support".to_string());
        }
        // The machine can, and a test still cannot. Hypervisor.framework refuses a process that
        // does not carry `com.apple.security.hypervisor`, and cargo rewrites `target/debug/bsx`
        // (and so drops any signature) as part of the very run that would use it, so a suite has
        // no signed binary to spawn. Booting a VM from the test harness on macOS therefore needs
        // the signing question answered first; a *manual* run after `cargo xtask sign` works, which
        // is how the benches are run.
        Some(
            "a VM booted from a test needs an entitled `bsx`, and cargo drops the signature \
             during the same run that would spawn it (`cargo xtask sign` covers a manual run)"
                .to_string(),
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Some("no hypervisor this project knows how to reach".to_string())
    }
}

/// A `Write` sink that appends into a shared buffer, for a test asserting on what was **logged**.
///
/// `with_default` is thread-local, so [`subscriber`](Self::subscriber) hands out one per thread
/// over the same sink and [`contents`](Self::contents) reads them all back.
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

/// A `xorshift64*` PRNG: deterministic, seedable, zero-dependency. Not cryptographic; it sprays
/// varied bytes at a decoder reproducibly, so a failure replays from its seed.
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

    /// A string of a random length in `0..max_len` drawn from `alphabet`. The alphabet stays with
    /// the caller, because what is worth generating is each wire's own question.
    pub fn string_from(&mut self, alphabet: &[char], max_len: usize) -> String {
        let n = self.below(max_len);
        (0..n)
            .map(|_| alphabet[self.below(alphabet.len())])
            .collect()
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
