//! Both directions of a socket bounded by one **absolute deadline**, not a bare socket timeout.
//!
//! - **The threat is the slow peer, not the silent one.** The OS re-arms
//!   `SO_RCVTIMEO`/`SO_SNDTIMEO` per syscall, so a bare socket timeout bounds one `read`/`write`,
//!   not one message: a peer that keeps each syscall progressing stretches one message while
//!   holding the thread carrying it. Shrinking the sockopt to the time left before one absolute
//!   deadline makes the sum of the syscalls honor one wall clock.
//! - **The two directions differ in what a peer spends.** A slow *sender* pays nothing, so the
//!   read side is the cheap attack; a slow *receiver* must keep draining to hold the writer, so
//!   the write side costs more to mount and its overrun is bounded by the reply size.
//! - `bsx-engine` holds its own copies of this discipline and cannot share this type across the
//!   crate boundary, so `every_deadline_bounded_socket_refuses_a_spent_budget` pins each copy.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// The read sockopt [`DeadlineStream`] arms, as a trait because std puts the method on
/// `UnixStream` and `TcpStream` without a shared one.
pub(crate) trait SetReadTimeout {
    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()>;
}

/// The write sockopt, a trait separate from [`SetReadTimeout`] so a read-only caller never has to
/// name a write timeout it does not arm.
pub(crate) trait SetWriteTimeout {
    fn set_write_timeout(&self, dur: Option<Duration>) -> std::io::Result<()>;
}

impl SetWriteTimeout for UnixStream {
    fn set_write_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        UnixStream::set_write_timeout(self, dur)
    }
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

/// A stream whose reads and writes are bounded by one absolute deadline per message: the whole
/// message must complete within one `budget` of [`rearm`](Self::rearm). A `None` budget passes
/// through plain (the daemon's `--idle-timeout` opt-out).
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

    /// The wrapped stream, for a caller that needs the socket itself (the daemon peeks it for a
    /// pipelined `cancel` while an exec runs).
    pub(crate) fn get_ref(&self) -> &S {
        &self.stream
    }

    /// The time left on the in-flight message, or `None` when the deadline is disabled.
    /// `Some(ZERO)` is a spent budget and must be refused rather than armed: the kernel reads a
    /// zero `SO_RCVTIMEO`/`SO_SNDTIMEO` as "block forever", the hang this wrapper exists to stop.
    fn remaining(&self) -> Option<Duration> {
        self.deadline
            .map(|d| d.saturating_duration_since(Instant::now()))
    }
}

impl<S: Read + SetReadTimeout> Read for DeadlineStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(remaining) = self.remaining() {
            // The refusal precedes the arming, since a zero timeout means "block forever".
            if remaining.is_zero() {
                return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, self.what));
            }
            self.stream.set_read_timeout(Some(remaining))?;
        }
        self.stream.read(buf)
    }
}

/// The most one bounded `write` hands the kernel at a time, since the deadline is checked only
/// *between* syscalls: a unix socket's `sendmsg` loops inside the kernel until the whole buffer is
/// sent, re-applying `SO_SNDTIMEO` to each internal wait, so one 16 MiB reply is a single `write`
/// that blocks for minutes while a slow peer drains it. Chunking bounds the overshoot to one chunk.
const WRITE_CHUNK: usize = 64 * 1024;

impl<S: Write + SetWriteTimeout> Write for DeadlineStream<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(remaining) = self.remaining() {
            if remaining.is_zero() {
                return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, self.what));
            }
            self.stream.set_write_timeout(Some(remaining))?;
            let chunk = &buf[..buf.len().min(WRITE_CHUNK)];
            return self.stream.write(chunk);
        }
        self.stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}
