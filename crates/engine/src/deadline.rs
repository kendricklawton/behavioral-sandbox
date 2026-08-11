//! A unix socket bounded by one **absolute deadline** instead of a per-syscall timeout.
//!
//! - **The threat is the slow drip, not the silent peer.** `SO_RCVTIMEO`/`SO_SNDTIMEO` are re-armed
//!   by the kernel on every syscall, so a peer that never pauses a full timeout's worth is never cut
//!   off: the option bounds one syscall, and `read_exact` of an `N`-byte frame makes `N` of them.
//!   Shrinking the option to the budget left before one absolute deadline makes the sum of them
//!   honour a single wall clock, which is what turns a dribbling peer from a host hang into a typed
//!   `TimedOut`. Writes are bounded the same way: a peer that reads slowly would otherwise park the
//!   host in `write_all`.
//! - **A spent budget is refused, never armed.** The kernel reads a zero timeout as "block forever",
//!   so arming one is the hang this exists to prevent.
//!
//! `crates/cli` holds its own copy for the daemon's sockets and cannot share this type across the
//! crate boundary; `every_deadline_bounded_socket_refuses_a_spent_budget` pins each copy to the same
//! invariant.

use std::borrow::Borrow;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// A socket whose every read and write is bounded by one absolute `deadline`.
///
/// Generic over how the socket is held so the Firecracker API path can borrow one it keeps using
/// afterwards (`&UnixStream`) while the exec path owns its own (`UnixStream`).
pub(crate) struct DeadlineStream<S> {
    stream: S,
    deadline: Instant,
    /// Names the exchange in the `TimedOut` error, e.g. `"firecracker API"`.
    what: &'static str,
}

impl<S> DeadlineStream<S> {
    pub(crate) fn new(stream: S, deadline: Instant, what: &'static str) -> Self {
        Self {
            stream,
            deadline,
            what,
        }
    }

    /// The budget left, or `None` when it is spent.
    fn remaining(&self) -> Option<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        (!left.is_zero()).then_some(left)
    }
}

impl<S: Borrow<UnixStream>> Read for DeadlineStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let Some(remaining) = self.remaining() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("{} response exceeded its deadline", self.what),
            ));
        };
        let mut sock: &UnixStream = self.stream.borrow();
        sock.set_read_timeout(Some(remaining))?;
        sock.read(buf)
    }
}

impl<S: Borrow<UnixStream>> Write for DeadlineStream<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let Some(remaining) = self.remaining() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("{} request exceeded its deadline", self.what),
            ));
        };
        let mut sock: &UnixStream = self.stream.borrow();
        sock.set_write_timeout(Some(remaining))?;
        sock.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut sock: &UnixStream = self.stream.borrow();
        sock.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A spent budget is a typed `TimedOut`, not a zero timeout armed on the socket.
    #[test]
    fn a_spent_budget_refuses_rather_than_arming_a_blocking_timeout() {
        let (a, _b) = UnixStream::pair().expect("socketpair");
        let mut spent = DeadlineStream::new(a, Instant::now() - Duration::from_secs(1), "test");
        let err = spent
            .read(&mut [0u8; 8])
            .expect_err("a spent budget must not read");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            err.to_string().contains("test response"),
            "the refusal names the exchange: {err}"
        );
        let err = spent
            .write(b"x")
            .expect_err("a spent budget must not write");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            err.to_string().contains("test request"),
            "the refusal names the exchange: {err}"
        );
    }

    /// A borrowed socket is bounded exactly like an owned one, so the two call sites share one type.
    #[test]
    fn a_borrowed_socket_is_bounded_like_an_owned_one() {
        let (a, _b) = UnixStream::pair().expect("socketpair");
        let mut borrowed = DeadlineStream::new(&a, Instant::now() - Duration::from_secs(1), "test");
        let err = borrowed
            .read(&mut [0u8; 8])
            .expect_err("a spent budget must not read");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }

    /// A live budget arms the socket and reads what is there, so the bound does not break traffic.
    #[test]
    fn a_live_budget_reads_normally() {
        let (a, mut b) = UnixStream::pair().expect("socketpair");
        b.write_all(b"hello").expect("write the peer's half");
        let mut bounded = DeadlineStream::new(a, Instant::now() + Duration::from_secs(5), "test");
        let mut buf = [0u8; 5];
        bounded.read_exact(&mut buf).expect("a live budget reads");
        assert_eq!(&buf, b"hello");
    }
}
