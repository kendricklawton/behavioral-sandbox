//! `bsx __frames`: a second process reading a sandbox's display through the control socket.
//!
//! The 4.9 client, in the shape the application (4.10) will use: lease the display, map the memfd
//! the answer carries, and consume one record per present, each naming the slot the frame is in.
//! Nothing is copied on the way; the pixels are read where libkrun wrote them.
//!
//! - **The frame log is the measurement.** Each record is logged with the host's monotonic clock,
//!   the same clock the helper's own `--frame-log` uses, so the two logs line up frame id by frame
//!   id and their difference is the boundary's cost.
//! - **A screenshot is the proof.** `--screenshot` writes the last frame read through the mapping
//!   as a PPM, so a test can check that the pixels a guest drew are the pixels that crossed.
//! - **A reconfigure is a new lease.** A guest that sets a new mode disables and reconfigures its
//!   scanout; the record that says so ends the lease, and the reader asks again, so the frames
//!   after it come at the new size.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::Args;

use bsx_supervisor::control::{self, Event};

/// How long to keep asking for a lease while the guest has no scanout yet.
const CONFIGURE_WAIT: Duration = Duration::from_secs(30);

#[derive(Debug, Args)]
pub(crate) struct FramesArgs {
    /// The sandbox, by name.
    pub(crate) name: String,
    /// Append one `frame_id<TAB>nanoseconds` line here per frame read.
    #[arg(long, value_name = "PATH")]
    pub(crate) log: Option<PathBuf>,
    /// Stop after this many frames; otherwise read until the lease ends.
    #[arg(long, value_name = "N")]
    pub(crate) count: Option<u64>,
    /// Write the last frame read as a binary PPM here.
    #[arg(long, value_name = "PATH")]
    pub(crate) screenshot: Option<PathBuf>,
}

pub(crate) fn run(args: &FramesArgs) -> ExitCode {
    match read(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("bsx __frames: {msg}");
            ExitCode::from(crate::EXIT_OPERATIONAL)
        }
    }
}

fn read(args: &FramesArgs) -> Result<(), String> {
    let socket = bsx_supervisor::socket::path_for(&args.name).map_err(|e| e.to_string())?;
    let mut log = args
        .log
        .clone()
        .map(crate::window::FrameLog::create)
        .transpose()
        .map_err(|e| e.to_string())?;
    let mut read = 0u64;
    loop {
        match read_one_lease(&socket, args, &mut log, &mut read)? {
            Some(()) => return Ok(()),
            None => eprintln!("bsx __frames: the display was reconfigured; leasing again"),
        }
    }
}

/// Leases the display until the lease ends: `Some` when the reader is done (the count reached,
/// or the VM gone), `None` when the scanout was reconfigured and a new lease is wanted.
fn read_one_lease(
    socket: &std::path::Path,
    args: &FramesArgs,
    log: &mut Option<crate::window::FrameLog>,
    read: &mut u64,
) -> Result<Option<()>, String> {
    let deadline = Instant::now() + CONFIGURE_WAIT;
    let mut lease = loop {
        match control::display(socket) {
            Ok(lease) => break lease,
            Err(control::Error::Refused(why)) if why.contains("ask again") => {
                if Instant::now() > deadline {
                    return Err(format!("{why} (gave up after {CONFIGURE_WAIT:?})"));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            // A socket that is gone or refuses after a lease was held is the VM ending, which
            // is how a reader that asks again after a reconfigure learns the run is over.
            Err(control::Error::Io(e))
                if *read > 0
                    && matches!(
                        e.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                    ) =>
            {
                return Ok(Some(()));
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
    let mut last = None;
    let mut outcome = Some(());
    while args.count.is_none_or(|n| *read < n) {
        match lease.next_event() {
            Ok(Event::Presented { frame_id, slot, .. }) => {
                if let Some(log) = log.as_mut() {
                    log.record(frame_id);
                }
                last = Some((frame_id, slot));
                *read += 1;
            }
            Ok(Event::Reconfigured) => {
                outcome = None;
                break;
            }
            Ok(_) => {}
            Err(control::Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.to_string()),
        }
    }
    // Written for every lease that saw a frame, so the file holds the last frame of the last
    // lease: after a reconfigure, the new size.
    if let (Some(path), Some((frame_id, slot))) = (&args.screenshot, last) {
        let view = mapped
            .frame(frame_id, slot)
            .ok_or_else(|| format!("slot {slot} is outside the layout"))?;
        crate::window::write_ppm(&view.to_frame(), path).map_err(|e| e.to_string())?;
    }
    Ok(outcome)
}
