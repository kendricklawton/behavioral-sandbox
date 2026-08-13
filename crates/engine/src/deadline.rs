//! A unix socket bounded by one **absolute deadline** instead of a per-syscall timeout.
//!
//! - **The threat is the slow drip, not the silent peer.** The kernel re-arms
//!   `SO_RCVTIMEO`/`SO_SNDTIMEO` on every syscall, and `read_exact` of an `N`-byte frame makes `N`
//!   of them, so a peer that never pauses a full timeout's worth is never cut off. Shrinking the
//!   option to the budget left before one absolute deadline makes their sum honour a single wall
//!   clock. Writes are additionally **capped per syscall** ([`WRITE_CHUNK`]), because `sendmsg`
//!   loops inside the kernel until the whole buffer is gone.
//! - **A spent budget is refused, never armed.** The kernel reads a zero timeout as "block
//!   forever", so arming one is the hang this exists to prevent.
//!
//! `crates/cli` holds its own copy for the daemon's sockets and cannot share this type across the
//! crate boundary; `every_deadline_bounded_socket_refuses_a_spent_budget` pins both to the same
//! invariant.

use std::borrow::Borrow;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// A socket whose every read and write is bounded by one absolute `deadline`. Generic over how the
/// socket is held so the Firecracker API path can borrow one it keeps using afterwards
/// (`&UnixStream`) while the exec path owns its own (`UnixStream`).
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

/// The most one bounded `write` hands the kernel at a time, because the deadline is checked
/// between syscalls: `sendmsg` loops *inside the kernel* until the caller's whole buffer is sent,
/// re-applying `SO_SNDTIMEO` to each internal wait, so a whole frame in one `write` is one syscall
/// a slowly draining peer stretches. Reads need no such cap, since `recvmsg` returns what is
/// available rather than filling the buffer.
const WRITE_CHUNK: usize = 64 * 1024;

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
        sock.write(&buf[..buf.len().min(WRITE_CHUNK)])
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

    /// A guest that drains slowly cannot stretch one `write` past the deadline.
    ///
    /// The host writes the exec request (argv, stdin, injected files) to an agent a hostile guest
    /// fully controls, so this is the host path design rule 5 governs. Without the per-syscall cap
    /// the whole frame goes to the kernel in one `sendmsg`, which loops internally re-applying
    /// `SO_SNDTIMEO`, and the deadline check between calls never runs.
    #[test]
    fn a_slow_draining_peer_cannot_stretch_one_write_past_the_deadline() {
        let (a, mut b) = UnixStream::pair().expect("socketpair");
        let peer = std::thread::spawn(move || {
            // Fast enough to keep each `write` progressing, slow enough that draining the payload
            // would take far longer than the budget below.
            let mut buf = vec![0u8; 32 * 1024];
            for _ in 0..400 {
                std::thread::sleep(Duration::from_millis(50));
                match b.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });

        let mut bounded =
            DeadlineStream::new(a, Instant::now() + Duration::from_millis(300), "test");
        let started = Instant::now();
        let err = bounded
            .write_all(&vec![0u8; 8 * 1024 * 1024])
            .expect_err("a slow-draining peer must hit the deadline");
        let held = started.elapsed();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            held < Duration::from_secs(5),
            "the write must end at the absolute deadline; held {held:?}"
        );
        drop(bounded);
        let _ = peer.join();
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
