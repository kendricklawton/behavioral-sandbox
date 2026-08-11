//! A read half bounded by one **absolute deadline** instead of a bare socket timeout.
//!
//! - **The threat is the slow drip, not the silent peer.** `SO_RCVTIMEO` is re-armed by the OS on
//!   every byte, so a per-read timeout alone lets a peer sending one byte just inside the interval
//!   stretch a single message indefinitely while holding the thread that reads it. Shrinking the
//!   socket timeout to the time left before one absolute deadline makes the sum of all reads honor
//!   one wall clock. `bsx-engine` holds its own copies of this discipline and cannot share this type
//!   across the crate boundary, so `every_deadline_bounded_socket_refuses_a_spent_budget` pins each
//!   copy to the same invariant.

use std::io::Read;
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// The one sockopt [`DeadlineStream`] arms, as a trait because std puts the method on
/// `UnixStream` and `TcpStream` without a shared one.
pub(crate) trait SetReadTimeout {
    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()>;
}

impl SetReadTimeout for UnixStream {
    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        UnixStream::set_read_timeout(self, dur)
    }
}

impl SetReadTimeout for TcpStream {
    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        TcpStream::set_read_timeout(self, dur)
    }
}

/// `Read` is implemented for `&TcpStream`, so a caller that needs its stream back after the
/// bounded read (the metrics endpoint writes the response next) wraps a borrow.
impl SetReadTimeout for &TcpStream {
    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        TcpStream::set_read_timeout(self, dur)
    }
}

/// A stream whose reads are bounded by one absolute deadline per message: the whole message must
/// complete within one `budget` of its first-awaited byte. A `None` budget reads plain (the
/// daemon's idle-timeout opt-out).
pub(crate) struct DeadlineStream<S> {
    stream: S,
    /// The per-message budget; [`rearm`](Self::rearm) restarts the clock for the next message.
    budget: Option<Duration>,
    /// When the in-flight message must be complete.
    deadline: Option<Instant>,
    /// What blew the deadline, carried on the `TimedOut` error a caller logs.
    what: &'static str,
}

impl<S> DeadlineStream<S> {
    pub(crate) fn new(stream: S, budget: Option<Duration>, what: &'static str) -> Self {
        let mut s = Self {
            stream,
            budget,
            deadline: None,
            what,
        };
        s.rearm();
        s
    }

    /// Start the next message's budget clock (a no-op when the deadline is disabled).
    pub(crate) fn rearm(&mut self) {
        self.deadline = self.budget.map(|b| Instant::now() + b);
    }
}

impl<S: Read + SetReadTimeout> Read for DeadlineStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(deadline) = self.deadline {
            // Shrink the socket timeout to the time left, so the sum of all reads honors one wall
            // clock. A spent budget is the timeout itself, checked ahead of arming it: a zero
            // `set_read_timeout` means "block forever", the very hang this wrapper exists to stop.
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, self.what));
            }
            self.stream.set_read_timeout(Some(remaining))?;
        }
        self.stream.read(buf)
    }
}
