//! The lease: a thread that asks the sandbox for its display and forwards each present.
//!
//! The same client as `bsx __frames`, feeding a channel the window's subscription drains. A
//! present is forwarded as its record says, slot and damage, and the frame is never copied here;
//! the upload in [`crate::frame`] reads the mapped slot itself. Once the display is mapped the
//! thread opens the input session too, and hands it to the window, whose events go down it.
//!
//! - **Leaving the run ends the lease.** The subscription's stream carries a stop handle, and
//!   dropping it shuts the lease's connection, so the thread's blocked read returns and the
//!   thread, the mapping and the socket all go with the run that was left.
//! - **A reconfigure is a new lease.** A guest that sets a new mode ends the lease with a
//!   reconfigure record; the thread leases again and hands the window a new mapping, whose
//!   layout the frame widget follows.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use iced::futures::Stream;
use iced::futures::channel::mpsc;

use bsx_supervisor::control::{self, Event, LeaseStop};

use crate::Message;

/// How long to keep asking for a lease while the guest has no scanout yet.
const CONFIGURE_WAIT: Duration = Duration::from_secs(30);

/// What ends the lease thread from the window's side.
#[derive(Default)]
struct Stop {
    cancelled: AtomicBool,
    lease: Mutex<Option<LeaseStop>>,
}

impl Stop {
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        if let Some(stop) = self
            .lease
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            stop.stop();
        }
    }

    fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// The subscription's stream: the thread's messages, and the stop that goes with the stream.
pub(crate) struct Feed {
    receiver: mpsc::UnboundedReceiver<Message>,
    stop: Arc<Stop>,
}

impl Stream for Feed {
    type Item = Message;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Message>> {
        Pin::new(&mut self.receiver).poll_next(cx)
    }
}

impl Drop for Feed {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

/// Starts the lease thread for `name` and returns the messages it sends, as the subscription's
/// stream. `log`, when set, gets one line per present read.
pub(crate) fn stream((name, log): &(String, Option<PathBuf>)) -> Feed {
    let (sender, receiver) = mpsc::unbounded();
    let name = name.clone();
    let log = log.clone();
    let stop = Arc::new(Stop::default());
    let thread_stop = Arc::clone(&stop);
    std::thread::spawn(move || {
        let ended = match run(&name, log.as_deref(), &sender, &thread_stop) {
            Ok(why) => why,
            Err(why) => why,
        };
        let _ = sender.unbounded_send(Message::Ended(ended));
    });
    Feed { receiver, stop }
}

/// Leases, maps, and forwards until the lease ends, leasing again after each reconfigure.
/// `Ok` carries the ordinary end.
fn run(
    name: &str,
    log: Option<&Path>,
    sender: &mpsc::UnboundedSender<Message>,
    stop: &Stop,
) -> Result<String, String> {
    let socket = bsx_supervisor::socket::path_for(name).map_err(|e| e.to_string())?;
    let mut log = log
        .map(|path| std::fs::File::create(path).map_err(|e| format!("{}: {e}", path.display())))
        .transpose()?;
    let mut leased_before = false;
    loop {
        match run_one_lease(&socket, &mut log, sender, stop, leased_before)? {
            Some(why) => return Ok(why),
            None => {
                leased_before = true;
                eprintln!("bsx-app: the display was reconfigured; leasing again");
            }
        }
    }
}

/// One lease: `Some` with why it ended for good, `None` for a reconfigure to lease after.
fn run_one_lease(
    socket: &Path,
    log: &mut Option<std::fs::File>,
    sender: &mpsc::UnboundedSender<Message>,
    stop: &Stop,
    leased_before: bool,
) -> Result<Option<String>, String> {
    let deadline = Instant::now() + CONFIGURE_WAIT;
    let mut lease = loop {
        if stop.cancelled() {
            return Ok(Some("the run was left".to_string()));
        }
        match control::display(socket) {
            Ok(lease) => break lease,
            Err(control::Error::Refused(why)) if why.contains("ask again") => {
                if Instant::now() > deadline {
                    return Err(format!("{why} (gave up after {CONFIGURE_WAIT:?})"));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            // A socket gone after a lease was held is the VM ending.
            Err(control::Error::Io(e))
                if leased_before
                    && matches!(
                        e.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                    ) =>
            {
                return Ok(Some("the lease ended".to_string()));
            }
            Err(e) => return Err(e.to_string()),
        }
    };
    *stop
        .lease
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = lease.stop_handle().ok();
    let scanout = lease.scanout();
    let memfd = lease
        .take_memfd()
        .ok_or_else(|| "the lease carried no memfd".to_string())?;
    let layout = bsx_krun::SharedLayout::new(
        scanout.width,
        scanout.height,
        bsx_krun::PixelFormat::from_raw(scanout.format),
        scanout.stride,
        scanout.slots,
        scanout.slot_bytes,
        scanout.generation,
    );
    let mapped = bsx_krun::SharedFrames::map(memfd, layout).map_err(|e| e.to_string())?;
    if sender
        .unbounded_send(Message::Mapped(Arc::new(mapped)))
        .is_err()
    {
        return Ok(Some("the window closed".to_string()));
    }
    match control::input(socket) {
        Ok(session) => {
            let session = Arc::new(Mutex::new(Some(session)));
            if sender.unbounded_send(Message::Input(session)).is_err() {
                return Ok(Some("the window closed".to_string()));
            }
        }
        Err(e) => eprintln!("bsx-app: no input session: {e}"),
    }
    loop {
        match lease.next_event() {
            Ok(Event::Presented {
                frame_id,
                slot,
                damage,
            }) => {
                if let Some(log) = log.as_mut() {
                    let _ = writeln!(log, "{frame_id}\t{}", monotonic_ns());
                }
                let sent = sender.unbounded_send(Message::Presented {
                    frame_id,
                    slot,
                    damage,
                });
                if sent.is_err() {
                    return Ok(Some("the window closed".to_string()));
                }
            }
            Ok(Event::Reconfigured) => return Ok(None),
            Ok(_) => {}
            Err(_) if stop.cancelled() => return Ok(Some("the run was left".to_string())),
            Err(control::Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(Some("the lease ended".to_string()));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

/// The host's monotonic clock in nanoseconds: the one timestamp two processes on this host can
/// compare.
pub(crate) fn monotonic_ns() -> u128 {
    let t = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    u128::try_from(t.tv_sec).unwrap_or(0) * 1_000_000_000 + u128::try_from(t.tv_nsec).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Threads this process has, from the kernel's count.
    fn threads() -> usize {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("Threads:"))
                    .and_then(|n| n.trim().parse().ok())
            })
            .unwrap_or(0)
    }

    /// Dropping the feed ends its thread: for a name no VM answers under, the thread's retries
    /// stop at the cancel and it exits, so leaving a run leaves nothing running for it.
    #[test]
    fn dropping_the_feed_ends_its_thread() {
        use iced::futures::StreamExt;
        let before = threads();
        let feed = stream(&("no-such-vm-for-this-test".to_string(), None));
        // The thread reports the failed lease and ends by itself for a name with no socket; what
        // this pins is that the report goes to the feed and the count comes back down.
        let ended =
            iced::futures::executor::block_on(async { feed.take(1).collect::<Vec<_>>().await });
        assert!(
            matches!(ended.as_slice(), [Message::Ended(why)] if why.contains("control socket")),
            "{ended:?}"
        );
        // Other tests' threads come and go beside this one, so the count is a ceiling, not a
        // number: the lease thread is gone when the process holds no more than it did.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while threads() > before && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(threads() <= before, "the lease thread is gone");
    }

    /// A cancelled stop ends the retry loop of a thread still waiting for a scanout: the thread
    /// is told before it leases, and after, through the lease's own handle.
    #[test]
    fn a_cancel_before_the_lease_stops_the_retries() {
        let stop = Stop::default();
        assert!(!stop.cancelled());
        stop.cancel();
        assert!(stop.cancelled());
        let (sender, _receiver) = mpsc::unbounded();
        let outcome = run("no-such-vm-either", None, &sender, &stop);
        assert!(
            matches!(&outcome, Ok(why) if why == "the run was left"),
            "{outcome:?}"
        );
    }
}
