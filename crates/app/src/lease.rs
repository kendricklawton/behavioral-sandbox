//! The lease: a thread that asks the sandbox for its display and forwards each present.
//!
//! The same client as `bsx __frames`, feeding a channel the window's subscription drains. A
//! present is forwarded as its record says, slot and damage, and the frame is never copied here;
//! the upload in [`crate::frame`] reads the mapped slot itself.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use iced::futures::channel::mpsc;

use bsx_supervisor::control::{self, Event};

use crate::Message;

/// How long to keep asking for a lease while the guest has no scanout yet.
const CONFIGURE_WAIT: Duration = Duration::from_secs(30);

/// Starts the lease thread for `name` and returns the messages it sends, as the subscription's
/// stream. `log`, when set, gets one line per present read.
pub(crate) fn stream((name, log): &(String, Option<PathBuf>)) -> mpsc::UnboundedReceiver<Message> {
    let (sender, receiver) = mpsc::unbounded();
    let name = name.clone();
    let log = log.clone();
    std::thread::spawn(move || {
        let ended = match run(&name, log.as_deref(), &sender) {
            Ok(why) => why,
            Err(why) => why,
        };
        let _ = sender.unbounded_send(Message::Ended(ended));
    });
    receiver
}

/// Leases, maps, and forwards until the lease ends. `Ok` carries the ordinary end.
fn run(
    name: &str,
    log: Option<&Path>,
    sender: &mpsc::UnboundedSender<Message>,
) -> Result<String, String> {
    let socket = bsx_supervisor::socket::path_for(name).map_err(|e| e.to_string())?;
    let deadline = Instant::now() + CONFIGURE_WAIT;
    let mut lease = loop {
        match control::display(&socket) {
            Ok(lease) => break lease,
            Err(control::Error::Refused(why)) if why.contains("ask again") => {
                if Instant::now() > deadline {
                    return Err(format!("{why} (gave up after {CONFIGURE_WAIT:?})"));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(e.to_string()),
        }
    };
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
    let mut log = log
        .map(|path| std::fs::File::create(path).map_err(|e| format!("{}: {e}", path.display())))
        .transpose()?;
    if sender
        .unbounded_send(Message::Mapped(Arc::new(mapped)))
        .is_err()
    {
        return Ok("the window closed".to_string());
    }
    loop {
        match lease.next_event() {
            Ok(Event::Presented {
                frame_id,
                slot,
                damage,
            }) => {
                if let Some(log) = &mut log {
                    let _ = writeln!(log, "{frame_id}\t{}", monotonic_ns());
                }
                let sent = sender.unbounded_send(Message::Presented {
                    frame_id,
                    slot,
                    damage,
                });
                if sent.is_err() {
                    return Ok("the window closed".to_string());
                }
            }
            Ok(Event::Reconfigured) => return Err("the display was reconfigured".to_string()),
            Ok(_) => {}
            Err(control::Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok("the lease ended".to_string());
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
