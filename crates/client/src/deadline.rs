//! One **absolute budget** per call instead of a bare socket timeout.
//!
//! - **The threat is the slow peer, not the silent one.** `SO_RCVTIMEO` and `SO_SNDTIMEO` are
//!   re-armed by the OS per syscall, so a bare socket timeout bounds one `read`/`write`, not one
//!   call: a daemon dribbling a byte at a time inside the interval stretches a call indefinitely.
//!   Shrinking the sockopt to the time left before one absolute deadline makes the sum of all the
//!   syscalls honor the bound the caller named.
//! - The parked thread here is the caller's own, not a shared daemon slot; what this bounds is the
//!   *promise* of `set_read_timeout`/`set_write_timeout`, which are documented as per-call bounds.
//! - The daemon and the engine hold their own copies of this discipline (`bsx` and `bsx-engine`
//!   cannot be dependencies here without voiding this crate's wire-only proof);
//!   `every_deadline_bounded_socket_refuses_a_spent_budget` pins each copy to the same invariant.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// The most one bounded `write` hands the kernel at a time.
///
/// **The deadline is only checked between syscalls, so the syscalls have to be small.** A unix
/// socket's `sendmsg` loops *inside the kernel* until the caller's whole buffer is sent,
/// re-applying `SO_SNDTIMEO` to each internal wait, so handing it a 4 MiB request is one `write`
/// call that can block for as long as a slow reader keeps draining it. Chunking bounds the
/// overshoot to one chunk, which the armed sockopt bounds in turn.
const WRITE_CHUNK: usize = 64 * 1024;

/// A stream whose reads and writes are bounded by one absolute deadline per call: the whole
/// message must complete within one budget of [`rearm`](Self::rearm). A `None` budget passes
/// through plain.
#[derive(Debug)]
pub(crate) struct DeadlineStream {
    stream: UnixStream,
    /// The per-call budget; [`rearm`](Self::rearm) restarts the clock for the next call.
    budget: Option<Duration>,
    /// When the in-flight call must be complete.
    deadline: Option<Instant>,
    /// What blew the deadline, carried on the `TimedOut` error a caller matches.
    what: &'static str,
}

impl DeadlineStream {
    /// Starts with no budget, the unbounded default [`crate::Client::connect`] documents.
    pub(crate) fn new(stream: UnixStream, what: &'static str) -> Self {
        Self {
            stream,
            budget: None,
            deadline: None,
            what,
        }
    }

    /// Sets the per-call budget, effective from the next [`rearm`](Self::rearm).
    ///
    /// Disabling clears the sockopt a bounded call last armed, or it would stay on the socket (one
    /// file description, shared by every clone) and fire on a later unbounded call. Both
    /// directions are cleared, because a direction whose budget is still live re-arms on its next
    /// syscall anyway. The daemon's copy fixes its budget at construction and cannot need this.
    pub(crate) fn set_budget(&mut self, budget: Option<Duration>) -> std::io::Result<()> {
        if budget.is_none() {
            self.stream.set_read_timeout(None)?;
            self.stream.set_write_timeout(None)?;
        }
        self.budget = budget;
        self.deadline = None;
        Ok(())
    }

    /// Start a call's budget clock (a no-op when no budget is set).
    pub(crate) fn rearm(&mut self) {
        self.deadline = self.budget.map(|b| Instant::now() + b);
    }

    /// The time left on the in-flight call, or `None` when the deadline is disabled.
    ///
    /// `Some(ZERO)` is the spent budget and must be refused rather than armed: the kernel reads a
    /// zero `SO_RCVTIMEO`/`SO_SNDTIMEO` as "block forever", the hang this wrapper exists to stop.
    fn remaining(&self) -> Option<Duration> {
        self.deadline
            .map(|d| d.saturating_duration_since(Instant::now()))
    }

    /// A fired sockopt surfaces as `WouldBlock`; a caller branching on "did my budget lapse" needs
    /// one kind, so the wrapper renames it to the `TimedOut` its spent-budget refusal already uses.
    fn timed_out(&self, e: std::io::Error) -> std::io::Error {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            std::io::Error::new(std::io::ErrorKind::TimedOut, self.what)
        } else {
            e
        }
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let Some(remaining) = self.remaining() else {
            return self.stream.read(buf);
        };
        // Shrink the socket timeout to the time left, so the sum of all reads honors one wall
        // clock. The refusal precedes the arming, since a zero timeout means "block forever".
        if remaining.is_zero() {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, self.what));
        }
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.read(buf).map_err(|e| self.timed_out(e))
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let Some(remaining) = self.remaining() else {
            return self.stream.write(buf);
        };
        // The same shrink as the read half, against the receiving end of the same shape: a peer
        // draining just fast enough to keep each `write` returning re-arms `SO_SNDTIMEO` every
        // time, so only an absolute deadline bounds the whole request.
        if remaining.is_zero() {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, self.what));
        }
        self.stream.set_write_timeout(Some(remaining))?;
        let chunk = &buf[..buf.len().min(WRITE_CHUNK)];
        self.stream.write(chunk).map_err(|e| self.timed_out(e))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}
