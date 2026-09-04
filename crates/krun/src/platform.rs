//! The two host primitives whose syscalls differ by platform, each behind one name.
//!
//! - **[`size_locked_fd`]**: the shared frame region's backing fd, fixed at a size no holder can
//!   change. A reader maps it in another process, so a resize under that mapping would fault it.
//!   Linux seals a `memfd`; macOS gets the same from a POSIX shm object, which the kernel lets
//!   `ftruncate` exactly once.
//! - **[`Ready`]**: the fd libkrun polls for input readiness, readable exactly while events wait.
//!   Linux uses an `eventfd`, macOS a pipe. They disarm differently, which is the whole reason
//!   this is a type and not a bare fd: one read clears an eventfd's counter, while a pipe stays
//!   readable until it is drained.

use std::io;
use std::os::fd::OwnedFd;

pub(crate) use imp::{Ready, size_locked_fd};

#[cfg(target_os = "linux")]
mod imp {
    use super::{OwnedFd, io};
    use std::os::fd::AsRawFd;

    /// An fd of exactly `len` bytes, sealed against resizing, ready to map shared.
    pub(crate) fn size_locked_fd(len: usize) -> io::Result<OwnedFd> {
        use rustix::fs::{MemfdFlags, SealFlags};
        let fd = rustix::fs::memfd_create(
            "bsx-frames",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )?;
        rustix::fs::ftruncate(&fd, len as u64)?;
        rustix::fs::fcntl_add_seals(&fd, SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL)?;
        Ok(fd)
    }

    /// An eventfd: armed by incrementing its counter, disarmed by the read that zeroes it.
    #[derive(Debug)]
    pub(crate) struct Ready(OwnedFd);

    impl Ready {
        pub(crate) fn new() -> io::Result<Self> {
            use rustix::event::EventfdFlags;
            Ok(Self(rustix::event::eventfd(
                0,
                EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK,
            )?))
        }

        pub(crate) fn arm(&self) {
            let _ = rustix::io::write(&self.0, &1u64.to_ne_bytes());
        }

        pub(crate) fn disarm(&self) {
            let mut counter = [0u8; 8];
            let _ = rustix::io::read(&self.0, &mut counter);
        }

        pub(crate) fn as_raw_fd(&self) -> std::os::raw::c_int {
            self.0.as_raw_fd()
        }

        /// A dup of the polled fd, so a test can poll it without holding the queue's lock.
        #[cfg(test)]
        pub(crate) fn try_clone(&self) -> io::Result<OwnedFd> {
            self.0.try_clone()
        }
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::{OwnedFd, io};
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Names are unlinked immediately, so this only has to outrun a concurrent create in this
    /// process; the pid keeps it clear of any other.
    static NEXT_NAME: AtomicU64 = AtomicU64::new(0);

    /// An fd of exactly `len` bytes whose size the kernel then refuses to change, ready to map
    /// shared. macOS has no `memfd` and no seals, but a POSIX shm object accepts **one**
    /// `ftruncate` in its life and fails `EINVAL` on every later one, from any process holding
    /// it. That is the property `SharedFrames` needs, so the size is set once, here.
    pub(crate) fn size_locked_fd(len: usize) -> io::Result<OwnedFd> {
        use rustix::fs::Mode;
        use rustix::shm::OFlags;

        // `shm_open` needs a name even though nothing looks it up, and macOS caps it near 31
        // bytes, so this stays short rather than descriptive.
        let mut last = None;
        for _ in 0..16 {
            let name = format!(
                "/bsx.{}.{}",
                std::process::id(),
                NEXT_NAME.fetch_add(1, Ordering::Relaxed)
            );
            match rustix::shm::open(
                name.as_str(),
                OFlags::CREATE | OFlags::EXCL | OFlags::RDWR,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(fd) => {
                    // Unlinked at once so the fd is the only handle, as a memfd is: a leaked
                    // name would outlive the process and collide with the next run's pid.
                    rustix::shm::unlink(name.as_str())?;
                    rustix::fs::ftruncate(&fd, len as u64)?;
                    return Ok(fd);
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last.map_or_else(
            || io::Error::other("no shm name was tried"),
            io::Error::from,
        ))
    }

    /// A pipe: armed by a byte, disarmed by draining to `EAGAIN`. Draining rather than reading
    /// once is what makes it match an eventfd, whose single read clears any number of writes.
    #[derive(Debug)]
    pub(crate) struct Ready {
        read: OwnedFd,
        write: OwnedFd,
    }

    impl Ready {
        pub(crate) fn new() -> io::Result<Self> {
            use rustix::fs::{OFlags, fcntl_setfl};
            use rustix::io::{FdFlags, fcntl_setfd};

            // macOS has no `pipe2`, so the flags `pipe_with` would carry are set after the fact.
            let (read, write) = rustix::pipe::pipe()?;
            for fd in [&read, &write] {
                fcntl_setfd(fd, FdFlags::CLOEXEC)?;
                fcntl_setfl(fd, OFlags::NONBLOCK)?;
            }
            Ok(Self { read, write })
        }

        /// A write that fails because the pipe is full still leaves it readable, which is what
        /// armed means, so a full pipe needs no separate handling.
        pub(crate) fn arm(&self) {
            let _ = rustix::io::write(&self.write, &[1u8]);
        }

        pub(crate) fn disarm(&self) {
            let mut buf = [0u8; 64];
            while let Ok(n) = rustix::io::read(&self.read, &mut buf) {
                if n == 0 {
                    break;
                }
            }
        }

        /// The read end: what libkrun polls.
        pub(crate) fn as_raw_fd(&self) -> std::os::raw::c_int {
            self.read.as_raw_fd()
        }

        /// A dup of the polled fd, so a test can poll it without holding the queue's lock.
        #[cfg(test)]
        pub(crate) fn try_clone(&self) -> io::Result<OwnedFd> {
            self.read.try_clone()
        }
    }
}
