//! One **absolute budget** per call instead of a bare socket timeout.
//!
//! - **The threat is the slow peer, not the silent one.** The OS re-arms
//!   `SO_RCVTIMEO`/`SO_SNDTIMEO` per syscall, so a bare socket timeout bounds one `read`/`write`,
//!   not one call: a daemon that keeps each syscall progressing stretches a call indefinitely.
//!   Shrinking the sockopt to the time left before one absolute deadline makes the sum of the
//!   syscalls honor the caller's bound.
//! - The parked thread is the caller's own, not a shared daemon slot.
//! - `bsx` and `bsx-engine` hold their own copies of this discipline (depending on either would
//!   void this crate's wire-only proof); `every_deadline_bounded_socket_refuses_a_spent_budget`
//!   pins them.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// The most one bounded `write` hands the kernel at a time, since the deadline is checked only
/// *between* syscalls: a unix socket's `sendmsg` loops inside the kernel until the whole buffer is
/// sent, re-applying `SO_SNDTIMEO` to each internal wait, so one 4 MiB `write` blocks for as long
/// as a slow reader keeps draining it. Chunking bounds the overshoot to one chunk.
const WRITE_CHUNK: usize = 64 * 1024;

/// A stream whose reads and writes are bounded by one absolute deadline per call: the whole message
/// must complete within one budget of [`rearm`](Self::rearm). A `None` budget passes through plain.
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

    /// Sets the per-call budget, effective from the next [`rearm`](Self::rearm). Disabling clears
    /// both sockopts, or the one a bounded call last armed stays on the socket (one file
    /// description, shared by every clone) and fires on a later unbounded call.
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

    /// The time left on the in-flight call, or `None` when the deadline is disabled. `Some(ZERO)`
    /// is a spent budget and must be refused rather than armed: the kernel reads a zero
    /// `SO_RCVTIMEO`/`SO_SNDTIMEO` as "block forever", the hang this wrapper exists to stop.
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
        // The refusal precedes the arming, since a zero timeout means "block forever".
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
