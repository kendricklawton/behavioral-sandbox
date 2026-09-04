//! The window a sandbox's display is shown in, on a thread of the helper that **is** the VM.
//!
//! The frames land in this process: libkrun's gpu thread writes them into the
//! [`MemoryFramebuffer`] the helper registered, and there is no other process to show them from
//! without copying every frame across a boundary. So the window lives here too, on a thread
//! spawned before `krun_start_enter` takes the main one, the way the control socket's does.
//!
//! - **Frames are pushed, not polled.** The framebuffer's wake hook fires on every present, from
//!   libkrun's gpu thread; with a window it posts a user event to the loop, and without one it
//!   signals the headless sink's condvar. Either way the thread does nothing until a frame lands
//!   and sees it the moment it does, so this thread adds no interval of its own to a frame's
//!   path. The callback libkrun calls still knows nothing about windows.
//! - **The window is the sandbox's lifetime, not the other way round.** Closing it ends the VM
//!   the way `bsx stop` does; the VM ending takes the window with it, because the process exits.
//! - **The frame follows the window.** A window the user resizes shows the frame scaled to fit,
//!   its aspect kept, and the pointer is measured against where the frame landed. The other
//!   direction does not exist: libkrun 1.19.4 answers the guest's display-info query from a fixed
//!   table and exports nothing that changes it, so a resized window cannot ask the guest for a
//!   new mode, and the scanout stays the size `--display` gave it.
//! - **Its keyboard and pointer are the guest's.** Every key, motion, button and wheel event the
//!   window gets is translated (`crate::input`) and queued for the guest; nothing is kept back.
//! - **No display server is not an error.** The event loop is a capability probe: where it cannot
//!   be built the display runs without a window, warned once, and a `--screenshot` and a
//!   `--frame-log` still work. That is what lets the end-to-end tests and `bench-frames` read
//!   frames on a headless runner.
//! - **Linux only, for now.** winit lets the loop run off the main thread on X11 and Wayland;
//!   macOS insists on the main thread, which libkrun holds. That is phase 6's to reconcile.

use std::io::{self, Write};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};

use bsx_krun::{Frame, MemoryFramebuffer, PixelFormat};
use winit::application::ApplicationHandler;
use winit::event::{MouseScrollDelta, WindowEvent};
use winit::event_loop::{ActiveEventLoop, EventLoop};
use winit::window::{Window, WindowId};

use bsx_input::{Area, Held};

use crate::input::{self, Inputs};

/// The scanout shown. libkrun numbers them from zero and one display makes one.
const SCANOUT: u32 = 0;

/// Starts the display thread: a window when a display server answers, the screenshot and frame
/// log sinks either way. Returns once the thread is running, not once the window is up.
pub(crate) fn spawn(
    framebuffer: Arc<Mutex<MemoryFramebuffer>>,
    size: (NonZeroU32, NonZeroU32),
    title: &str,
    screenshot: Option<PathBuf>,
    frame_log: Option<PathBuf>,
    inputs: Inputs,
) -> io::Result<()> {
    let title = format!("bsx: {title}");
    let log = frame_log.map(FrameLog::create).transpose()?;
    std::thread::Builder::new()
        .name("bsx-display".to_string())
        .spawn(move || {
            let mut sinks = Sinks {
                screenshot,
                log,
                shown: None,
            };
            let event_loop = match event_loop_off_main_thread() {
                Ok(l) => l,
                Err(why) => {
                    eprintln!(
                        "bsx __vmm: warning: no window ({why}); the display runs without one"
                    );
                    headless(&framebuffer, &mut sinks);
                    return;
                }
            };
            // From here the window is the sandbox's lifetime: however this thread ends, the
            // guard stops the VM, or a closed window leaves a sandbox nobody can see.
            let _stop = StopOnExit;
            let proxy = event_loop.create_proxy();
            lock(&framebuffer).set_wake(move || {
                let _ = proxy.send_event(());
            });
            let mut app = App {
                framebuffer,
                size,
                title,
                sinks,
                inputs,
                held: Held::default(),
                placement: Placement::NONE,
                window: None,
            };
            let _ = event_loop.run_app(&mut app);
        })
        .map(drop)
}

/// Ends the VM when dropped, which is when the display thread ends for any reason.
struct StopOnExit;

impl Drop for StopOnExit {
    fn drop(&mut self) {
        crate::vmm::stop_this_vm();
    }
}

/// An event loop on this thread rather than the main one, which is about to enter libkrun.
fn event_loop_off_main_thread() -> Result<EventLoop<()>, winit::error::EventLoopError> {
    use winit::platform::wayland::EventLoopBuilderExtWayland;
    use winit::platform::x11::EventLoopBuilderExtX11;
    let mut builder = EventLoop::builder();
    EventLoopBuilderExtX11::with_any_thread(&mut builder, true);
    EventLoopBuilderExtWayland::with_any_thread(&mut builder, true);
    builder.build()
}

/// The framebuffer's lock, recovered if poisoned: a backend that panicked already answered
/// libkrun with an error, and what it holds is still the latest frame.
fn lock(framebuffer: &Mutex<MemoryFramebuffer>) -> std::sync::MutexGuard<'_, MemoryFramebuffer> {
    framebuffer
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The display with no window: the screenshot and frame log alone, woken per present, until the
/// process ends.
fn headless(framebuffer: &Mutex<MemoryFramebuffer>, sinks: &mut Sinks) {
    let landed = Arc::new((Mutex::new(false), Condvar::new()));
    let signal = Arc::clone(&landed);
    lock(framebuffer).set_wake(move || {
        let (flag, cv) = &*signal;
        *flag
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        cv.notify_one();
    });
    let (flag, cv) = &*landed;
    loop {
        {
            let mut ready = flag
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            while !*ready {
                ready = cv
                    .wait(ready)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            *ready = false;
        }
        if let Some(frame) = new_frame(framebuffer, &mut sinks.shown, sinks.log.as_mut()) {
            sinks.deliver(&frame);
        }
    }
}

/// The latest frame if its id differs from `shown`, cloned out from under the lock so libkrun
/// is held off only for the copy. The frame log is written before the copy, so it records when
/// the frame was seen, not when it had been copied.
fn new_frame(
    framebuffer: &Mutex<MemoryFramebuffer>,
    shown: &mut Option<u32>,
    log: Option<&mut FrameLog>,
) -> Option<Frame> {
    let guard = lock(framebuffer);
    let frame = guard.latest_frame(SCANOUT)?;
    if *shown == Some(frame.frame_id) {
        return None;
    }
    *shown = Some(frame.frame_id);
    if let Some(log) = log {
        log.record(frame.frame_id);
    }
    Some(frame.to_frame())
}

/// Where the frames go besides the window: the screenshot file and the frame log, and the id of
/// the frame last delivered so the same one is never delivered twice.
struct Sinks {
    screenshot: Option<PathBuf>,
    log: Option<FrameLog>,
    shown: Option<u32>,
}

impl Sinks {
    /// Records `frame` in every sink that is on. The log was written when the frame was seen, in
    /// [`new_frame`]; this is the rest.
    fn deliver(&mut self, frame: &Frame) {
        if let Some(path) = &self.screenshot {
            let _ = write_ppm(frame, path);
        }
    }
}

/// One `frame_id<TAB>nanoseconds` line per frame seen, on the host's `CLOCK_MONOTONIC` so two
/// processes line up. Unbuffered, so a killed VM's log is whole up to its last frame.
pub(crate) struct FrameLog {
    file: std::fs::File,
}

impl FrameLog {
    pub(crate) fn create(path: PathBuf) -> io::Result<Self> {
        Ok(Self {
            file: std::fs::File::create(path)?,
        })
    }

    pub(crate) fn record(&mut self, frame_id: u32) {
        let _ = writeln!(self.file, "{frame_id}\t{}", monotonic_ns());
    }
}

/// The host's monotonic clock in nanoseconds: the one timestamp two processes on this host can
/// compare.
pub(crate) fn monotonic_ns() -> u128 {
    let t = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    u128::try_from(t.tv_sec).unwrap_or(0) * 1_000_000_000 + u128::try_from(t.tv_nsec).unwrap_or(0)
}

/// Where the frame sits in the window, in window pixels: what the pointer is measured against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Placement {
    pub(crate) x: u32,
    pub(crate) y: u32,
    pub(crate) width: u32,
    pub(crate) height: u32,
}

impl Placement {
    /// No frame on screen.
    pub(crate) const NONE: Self = Self {
        x: 0,
        y: 0,
        width: 0,
        height: 0,
    };
}

/// The placement as the pointer measures against it.
fn area(p: Placement) -> Area {
    Area::new(
        f64::from(p.x),
        f64::from(p.y),
        f64::from(p.width),
        f64::from(p.height),
    )
}

/// The window's state, driven by winit's callbacks.
struct App {
    framebuffer: Arc<Mutex<MemoryFramebuffer>>,
    size: (NonZeroU32, NonZeroU32),
    title: String,
    sinks: Sinks,
    inputs: Inputs,
    /// What the guest thinks is down, released when the window loses focus.
    held: Held,
    /// Where the last paint put the frame.
    placement: Placement,
    window: Option<Shown>,
}

/// A window and the surface that puts pixels on it.
struct Shown {
    window: Arc<Window>,
    surface: softbuffer::Surface<Arc<Window>, Arc<Window>>,
}

impl App {
    /// Draws the latest frame fitted to the window as it is now, and remembers where it went.
    fn paint(&mut self) {
        let Some(shown) = self.window.as_mut() else {
            return;
        };
        let size = shown.window.inner_size();
        let (Some(width), Some(height)) =
            (NonZeroU32::new(size.width), NonZeroU32::new(size.height))
        else {
            return;
        };
        if shown.surface.resize(width, height).is_err() {
            return;
        }
        let Ok(mut pixels) = shown.surface.buffer_mut() else {
            return;
        };
        let frame = lock(&self.framebuffer)
            .latest_frame(SCANOUT)
            .map(|v| v.to_frame());
        pixels.fill(0);
        if let Some(frame) = &frame {
            self.placement = fit((frame.width, frame.height), (width.get(), height.get()));
            composite(frame, self.placement, width.get(), &mut pixels);
        }
        let _ = pixels.present();
    }

    /// A frame may have landed: delivers it to the sinks and asks for a redraw. Called on each
    /// wake, and once when the window is up in case one landed before the wake was set.
    fn frame_arrived(&mut self) {
        if let Some(frame) = new_frame(
            &self.framebuffer,
            &mut self.sinks.shown,
            self.sinks.log.as_mut(),
        ) {
            self.sinks.deliver(&frame);
            if let Some(shown) = &self.window {
                shown.window.request_redraw();
            }
        }
    }

    /// Releases everything the guest thinks is down.
    fn release_all(&mut self) {
        let (keys, buttons) = self.held.release_all();
        if !keys.is_empty() {
            let _ = self.inputs.keyboard.send(&keys);
        }
        if !buttons.is_empty() {
            let _ = self.inputs.pointer.send(&buttons);
        }
    }
}

impl ApplicationHandler for App {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.window.is_some() {
            return;
        }
        let (width, height) = self.size;
        let attributes = Window::default_attributes()
            .with_title(self.title.clone())
            .with_inner_size(winit::dpi::PhysicalSize::new(width.get(), height.get()))
            .with_resizable(true);
        let Ok(window) = event_loop.create_window(attributes) else {
            event_loop.exit();
            return;
        };
        let window = Arc::new(window);
        let Ok(context) = softbuffer::Context::new(Arc::clone(&window)) else {
            event_loop.exit();
            return;
        };
        let Ok(surface) = softbuffer::Surface::new(&context, Arc::clone(&window)) else {
            event_loop.exit();
            return;
        };
        self.window = Some(Shown { window, surface });
        self.frame_arrived();
    }

    fn user_event(&mut self, _event_loop: &ActiveEventLoop, (): ()) {
        self.frame_arrived();
    }

    fn window_event(&mut self, event_loop: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        use winit::platform::scancode::PhysicalKeyExtScancode;
        match event {
            WindowEvent::CloseRequested => event_loop.exit(),
            WindowEvent::RedrawRequested => self.paint(),
            WindowEvent::Resized(_) => {
                if let Some(shown) = &self.window {
                    shown.window.request_redraw();
                }
            }
            WindowEvent::Focused(false) => self.release_all(),
            WindowEvent::KeyboardInput { event, .. } => {
                let pressed = event.state.is_pressed();
                if let Some(code) = event.physical_key.to_scancode()
                    && let Some(report) = bsx_input::key(code, pressed, event.repeat)
                {
                    self.held.key(report[0].code, pressed);
                    let _ = self.inputs.keyboard.send(&report);
                }
            }
            WindowEvent::CursorMoved { position, .. } => {
                let report = bsx_input::position(position.x, position.y, area(self.placement));
                let _ = self.inputs.pointer.send(&report);
            }
            WindowEvent::MouseInput { state, button, .. } => {
                if let Some(code) = input::button_code(button) {
                    let pressed = state.is_pressed();
                    self.held.button(code, pressed);
                    let _ = self.inputs.pointer.send(&bsx_input::button(code, pressed));
                }
            }
            WindowEvent::MouseWheel { delta, .. } => {
                let (dx, dy) = match delta {
                    MouseScrollDelta::LineDelta(x, y) => (x, y),
                    // The window's pixel count as a line; clamped so the cast is exact.
                    MouseScrollDelta::PixelDelta(p) => (
                        (p.x / bsx_input::WHEEL_LINE_PIXELS).clamp(-1000.0, 1000.0) as f32,
                        (p.y / bsx_input::WHEEL_LINE_PIXELS).clamp(-1000.0, 1000.0) as f32,
                    ),
                };
                let report = bsx_input::wheel(dx, dy);
                if !report.is_empty() {
                    let _ = self.inputs.pointer.send(&report);
                }
            }
            _ => {}
        }
    }
}

/// Where a `frame` of that size sits in a `window` of that size: scaled to the largest size that
/// fits with its aspect kept, and centred. A frame or window with a zero side places nothing.
pub(crate) fn fit(frame: (u32, u32), window: (u32, u32)) -> Placement {
    let (fw, fh) = (u64::from(frame.0), u64::from(frame.1));
    let (ww, wh) = (u64::from(window.0), u64::from(window.1));
    if fw == 0 || fh == 0 || ww == 0 || wh == 0 {
        return Placement::NONE;
    }
    // Which side binds: the window is wider than the frame's aspect or it is not.
    let (width, height) = if ww * fh <= wh * fw {
        (ww, (ww * fh / fw).max(1))
    } else {
        ((wh * fw / fh).max(1), wh)
    };
    // Every value is at most a window side, which came in as a `u32`.
    Placement {
        x: ((ww - width) / 2) as u32,
        y: ((wh - height) / 2) as u32,
        width: width as u32,
        height: height as u32,
    }
}

/// Where a pixel's red, green and blue bytes sit in memory for `format`, or `None` for a format
/// this cannot read. The names list bytes low to high, so `B8G8R8X8` is `[B, G, R, X]`: the one
/// libkrun was measured sending (2026-09-02), and it composited to the colours the guest drew.
pub(crate) fn rgb_offsets(format: PixelFormat) -> Option<[usize; 3]> {
    Some(match format {
        PixelFormat::B8G8R8A8Unorm | PixelFormat::B8G8R8X8Unorm => [2, 1, 0],
        PixelFormat::A8R8G8B8Unorm | PixelFormat::X8R8G8B8Unorm => [1, 2, 3],
        PixelFormat::R8G8B8A8Unorm | PixelFormat::R8G8B8X8Unorm => [0, 1, 2],
        PixelFormat::A8B8G8R8Unorm | PixelFormat::X8B8G8R8Unorm => [3, 2, 1],
        _ => return None,
    })
}

/// Draws `frame` into the `place` rectangle of `out`, softbuffer's `0x00RRGGBB` layout,
/// nearest-neighbour when the sizes differ. The rest of `out` is untouched, as is all of it for a
/// place that does not fit. Pure, so it is testable without a window.
pub(crate) fn composite(frame: &Frame, place: Placement, width: u32, out: &mut [u32]) {
    let Some([r, g, b]) = rgb_offsets(frame.format) else {
        return;
    };
    if frame.width == 0 || frame.height == 0 || place.width == 0 || place.height == 0 {
        return;
    }
    let (fw, fh) = (frame.width as usize, frame.height as usize);
    let (pw, ph) = (place.width as usize, place.height as usize);
    let stride = fw * 4;
    let pixel = |px: &[u8]| (u32::from(px[r]) << 16) | (u32::from(px[g]) << 8) | u32::from(px[b]);
    for dy in 0..ph {
        let sy = dy * fh / ph;
        let Some(src_row) = frame.pixels.get(sy * stride..sy * stride + stride) else {
            return;
        };
        let start = (place.y as usize + dy) * width as usize + place.x as usize;
        let Some(dst_row) = out.get_mut(start..start + pw) else {
            return;
        };
        if pw == fw {
            for (dst, px) in dst_row.iter_mut().zip(src_row.chunks_exact(4)) {
                *dst = pixel(px);
            }
        } else {
            for (dx, dst) in dst_row.iter_mut().enumerate() {
                let sx = dx * fw / pw;
                *dst = pixel(&src_row[sx * 4..sx * 4 + 4]);
            }
        }
    }
}

/// Writes `frame` to `path` as a binary PPM (`P6`), through a sibling temporary and a rename, so
/// a reader never sees half a frame. PPM because it needs no encoder and every image tool reads it.
pub(crate) fn write_ppm(frame: &Frame, path: &Path) -> io::Result<()> {
    let [r, g, b] = rgb_offsets(frame.format).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!("cannot write a {:?} frame", frame.format),
        )
    })?;
    let mut out = format!("P6\n{} {}\n255\n", frame.width, frame.height).into_bytes();
    out.reserve(frame.pixels.len() / 4 * 3);
    for px in frame.pixels.chunks_exact(4) {
        out.extend_from_slice(&[px[r], px[g], px[b]]);
    }
    let tmp = path.with_extension("ppm.tmp");
    std::fs::write(&tmp, &out)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A frame is only ever made by the backend, so a test gets one the way libkrun would:
    /// through a real `MemoryFramebuffer`.
    fn frame(format: PixelFormat, width: u32, height: u32, pixels: &[u8]) -> Frame {
        use bsx_krun::DisplayBackend;
        let mut fb = MemoryFramebuffer::new();
        fb.configure_scanout(0, width, height, width, height, format)
            .expect("a shape this can size");
        let alloc = fb.alloc_frame(0).expect("a slot");
        let id = alloc.frame_id;
        alloc.buffer.copy_from_slice(pixels);
        fb.present_frame(0, id, None).expect("back");
        fb.latest_frame(0).expect("presented").to_frame()
    }

    /// The frame as it sits, one to one.
    fn whole(f: &Frame) -> Placement {
        Placement {
            x: 0,
            y: 0,
            width: f.width,
            height: f.height,
        }
    }

    /// Every format the header names lands its channels where softbuffer reads them, checked
    /// with a pixel whose four bytes all differ so a swapped offset cannot pass.
    #[test]
    fn every_known_format_composites_its_channels_into_place() {
        let cases = [
            (PixelFormat::B8G8R8A8Unorm, [0x33, 0x22, 0x11, 0xFF]),
            (PixelFormat::B8G8R8X8Unorm, [0x33, 0x22, 0x11, 0x00]),
            (PixelFormat::A8R8G8B8Unorm, [0xFF, 0x11, 0x22, 0x33]),
            (PixelFormat::X8R8G8B8Unorm, [0x00, 0x11, 0x22, 0x33]),
            (PixelFormat::R8G8B8A8Unorm, [0x11, 0x22, 0x33, 0xFF]),
            (PixelFormat::R8G8B8X8Unorm, [0x11, 0x22, 0x33, 0x00]),
            (PixelFormat::A8B8G8R8Unorm, [0xFF, 0x33, 0x22, 0x11]),
            (PixelFormat::X8B8G8R8Unorm, [0x00, 0x33, 0x22, 0x11]),
        ];
        for (format, bytes) in cases {
            let f = frame(format, 1, 1, &bytes);
            let mut out = [0xDEAD_BEEF];
            composite(&f, whole(&f), 1, &mut out);
            assert_eq!(out, [0x0011_2233], "{format:?}: R=11 G=22 B=33");
        }
    }

    /// A frame fits the window at the largest size that keeps its aspect, centred on the axis
    /// with room to spare; the same size is the identity, and a zero side places nothing.
    #[test]
    fn a_frame_fits_the_window_with_its_aspect_kept_and_centred() {
        let p = |x, y, width, height| Placement {
            x,
            y,
            width,
            height,
        };
        assert_eq!(fit((320, 240), (320, 240)), p(0, 0, 320, 240), "as is");
        assert_eq!(fit((320, 240), (640, 480)), p(0, 0, 640, 480), "doubled");
        assert_eq!(
            fit((320, 240), (640, 240)),
            p(160, 0, 320, 240),
            "wide: bars beside"
        );
        assert_eq!(
            fit((320, 240), (320, 480)),
            p(0, 120, 320, 240),
            "tall: bars above"
        );
        assert_eq!(fit((320, 240), (160, 120)), p(0, 0, 160, 120), "halved");
        assert_eq!(
            fit((320, 240), (100, 100)),
            p(0, 12, 100, 75),
            "shrunk to the width"
        );
        assert_eq!(
            fit((4000, 1), (2, 2)),
            p(0, 0, 2, 1),
            "never thinner than a pixel"
        );
        assert_eq!(fit((0, 240), (320, 240)), Placement::NONE);
        assert_eq!(fit((320, 240), (320, 0)), Placement::NONE);
    }

    /// Scaling picks the nearest source pixel: doubled, each pixel becomes a 2x2 block; halved,
    /// every other one survives; and the placement's offset lands the frame where it says.
    #[test]
    fn compositing_scales_by_nearest_pixel_into_the_placement() {
        let f = frame(
            PixelFormat::R8G8B8X8Unorm,
            2,
            2,
            &[
                1, 0, 0, 0, 2, 0, 0, 0, //
                3, 0, 0, 0, 4, 0, 0, 0,
            ],
        );
        let (r1, r2, r3, r4) = (0x0001_0000, 0x0002_0000, 0x0003_0000, 0x0004_0000);
        let mut doubled = [9u32; 4 * 4];
        composite(
            &f,
            Placement {
                x: 0,
                y: 0,
                width: 4,
                height: 4,
            },
            4,
            &mut doubled,
        );
        assert_eq!(
            doubled,
            [
                r1, r1, r2, r2, //
                r1, r1, r2, r2, //
                r3, r3, r4, r4, //
                r3, r3, r4, r4,
            ]
        );
        let mut halved = [9u32; 1];
        composite(
            &f,
            Placement {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
            },
            1,
            &mut halved,
        );
        assert_eq!(halved, [r1]);
        let mut offset = [9u32; 4 * 3];
        composite(
            &f,
            Placement {
                x: 1,
                y: 1,
                width: 2,
                height: 2,
            },
            4,
            &mut offset,
        );
        assert_eq!(
            offset,
            [
                9, 9, 9, 9, //
                9, r1, r2, 9, //
                9, r3, r4, 9,
            ]
        );
    }

    /// A placement that runs past the surface writes nothing past it, row by row, and a
    /// zero-sized one writes nothing at all.
    #[test]
    fn compositing_stops_at_the_surface_edge() {
        let f = frame(PixelFormat::R8G8B8X8Unorm, 1, 2, &[1, 0, 0, 0, 2, 0, 0, 0]);
        let mut short = [9u32; 1];
        composite(&f, whole(&f), 1, &mut short);
        assert_eq!(
            short,
            [0x0001_0000],
            "the first row landed, the second had nowhere"
        );
        let mut none = [9u32; 2];
        composite(&f, Placement::NONE, 1, &mut none);
        assert_eq!(none, [9, 9]);
    }

    /// A format this cannot read composites nothing and refuses to be written, rather than
    /// guessing at channels.
    #[test]
    fn an_unknown_format_is_left_alone_not_guessed_at() {
        assert_eq!(rgb_offsets(PixelFormat::Unknown(77)), None);
        let mut f = frame(PixelFormat::R8G8B8X8Unorm, 1, 1, &[1, 2, 3, 4]);
        f.format = PixelFormat::Unknown(77);
        let mut out = [7u32];
        composite(&f, whole(&f), 1, &mut out);
        assert_eq!(out, [7]);
        let dir = bsx_test_support::ScratchDir::created("ppm-unknown");
        assert!(write_ppm(&f, &dir.path().join("x.ppm")).is_err());
    }

    /// The PPM is the frame's RGB bytes under a `P6` header, written whole: no temporary is
    /// left beside it.
    #[test]
    fn a_screenshot_is_a_whole_ppm_of_the_frames_rgb() {
        let f = frame(
            PixelFormat::B8G8R8X8Unorm,
            2,
            1,
            &[0x33, 0x22, 0x11, 0, 0x66, 0x55, 0x44, 0],
        );
        let dir = bsx_test_support::ScratchDir::created("ppm");
        let path = dir.path().join("frame.ppm");
        write_ppm(&f, &path).expect("written");
        assert_eq!(
            std::fs::read(&path).expect("readable"),
            b"P6\n2 1\n255\n\x11\x22\x33\x44\x55\x66"
        );
        assert!(
            !path.with_extension("ppm.tmp").exists(),
            "the temporary was renamed away"
        );
    }

    /// The sinks deliver each new frame once: a frame log line per distinct id, and none for a
    /// wake that found the frame already delivered.
    #[test]
    fn the_sinks_record_each_frame_once() {
        let dir = bsx_test_support::ScratchDir::created("frame-log");
        let path = dir.path().join("frames.tsv");
        let fb = Mutex::new(MemoryFramebuffer::new());
        let mut sinks = Sinks {
            screenshot: None,
            log: Some(FrameLog::create(path.clone()).expect("created")),
            shown: None,
        };
        {
            use bsx_krun::DisplayBackend;
            let mut guard = fb.lock().expect("unpoisoned");
            guard
                .configure_scanout(0, 1, 1, 1, 1, PixelFormat::B8G8R8X8Unorm)
                .expect("configured");
            for _ in 0..2 {
                let id = guard.alloc_frame(0).expect("a slot").frame_id;
                guard.present_frame(0, id, None).expect("presented");
            }
        }
        // Two presents, the second superseding the first: one frame is new, the next wake finds
        // nothing newer.
        for _ in 0..3 {
            if let Some(frame) = new_frame(&fb, &mut sinks.shown, sinks.log.as_mut()) {
                sinks.deliver(&frame);
            }
        }
        let text = std::fs::read_to_string(&path).expect("the log");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "one line for the one frame delivered: {text:?}"
        );
        let (id, ns) = lines[0].split_once('\t').expect("id, tab, ns");
        assert_eq!(id, "1", "the latest frame's id");
        assert!(ns.parse::<u128>().is_ok(), "nanoseconds: {ns:?}");
    }
}
