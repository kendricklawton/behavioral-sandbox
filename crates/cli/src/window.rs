//! The window a sandbox's display is shown in, on a thread of the helper that **is** the VM.
//!
//! The frames land in this process: libkrun's gpu thread writes them into the
//! [`MemoryFramebuffer`] the helper registered, and there is no other process to show them from
//! without copying every frame across a boundary. So the window lives here too, on a thread
//! spawned before `krun_start_enter` takes the main one, the way the control socket's does.
//!
//! - **The compositor polls.** Every [`FRAME_POLL`] it locks the framebuffer, and a new frame id
//!   is a redraw and, if asked, a screenshot. Polling keeps the callback libkrun calls from
//!   knowing anything about windows, at the price of up to one poll of latency.
//! - **The window is the sandbox's lifetime, not the other way round.** Closing it ends the VM
//!   the way `bsx stop` does; the VM ending takes the window with it, because the process exits.
//! - **No display server is not an error.** The event loop is a capability probe: where it cannot
//!   be built the display runs without a window, warned once, and a `--screenshot` still works.
//!   That is what lets the end-to-end test read a frame on a headless runner.
//! - **Linux only, for now.** winit lets the loop run off the main thread on X11 and Wayland;
//!   macOS insists on the main thread, which libkrun holds. That is phase 6's to reconcile.

use std::io;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bsx_krun::{Frame, MemoryFramebuffer, PixelFormat};
use winit::application::ApplicationHandler;
use winit::event::WindowEvent;
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};
use winit::window::{Window, WindowId};

/// How often the framebuffer is checked for a new frame: the latency a frame can see, and the
/// most redraws a second this will drive.
const FRAME_POLL: Duration = Duration::from_millis(16);

/// The scanout shown. libkrun numbers them from zero and one display makes one.
const SCANOUT: u32 = 0;

/// Starts the display thread: a window when a display server answers, the screenshot sink either
/// way. Returns once the thread is running, not once the window is up.
pub(crate) fn spawn(
    framebuffer: Arc<Mutex<MemoryFramebuffer>>,
    size: (NonZeroU32, NonZeroU32),
    title: &str,
    screenshot: Option<PathBuf>,
) -> io::Result<()> {
    let title = format!("bsx: {title}");
    std::thread::Builder::new()
        .name("bsx-display".to_string())
        .spawn(move || {
            let event_loop = match event_loop_off_main_thread() {
                Ok(l) => l,
                Err(why) => {
                    eprintln!(
                        "bsx __vmm: warning: no window ({why}); the display runs without one"
                    );
                    headless(&framebuffer, screenshot.as_deref());
                    return;
                }
            };
            // From here the window is the sandbox's lifetime: however this thread ends, on the
            // loop returning after a close or on a panic unwinding out of it, the guard stops
            // the VM the way `bsx stop` does. A window that vanished from a VM still running
            // would be a sandbox nobody can see and nobody asked to keep.
            let _stop = StopOnExit;
            let mut app = App {
                framebuffer,
                size,
                title,
                screenshot,
                window: None,
                shown: None,
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

/// The display with no window: the screenshot sink alone, until the process ends.
fn headless(framebuffer: &Mutex<MemoryFramebuffer>, screenshot: Option<&Path>) {
    let mut shown = None;
    loop {
        std::thread::sleep(FRAME_POLL);
        if let Some(frame) = new_frame(framebuffer, &mut shown)
            && let Some(path) = screenshot
        {
            let _ = write_ppm(&frame, path);
        }
    }
}

/// The latest frame if its id differs from `shown`, cloned out from under the lock so libkrun
/// is held off only for the copy.
fn new_frame(framebuffer: &Mutex<MemoryFramebuffer>, shown: &mut Option<u32>) -> Option<Frame> {
    let guard = framebuffer
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let frame = guard.latest_frame(SCANOUT)?;
    if *shown == Some(frame.frame_id) {
        return None;
    }
    *shown = Some(frame.frame_id);
    Some(frame.clone())
}

/// The window's state, driven by winit's callbacks.
struct App {
    framebuffer: Arc<Mutex<MemoryFramebuffer>>,
    size: (NonZeroU32, NonZeroU32),
    title: String,
    screenshot: Option<PathBuf>,
    window: Option<Shown>,
    /// The id of the frame on screen, so a poll that finds the same one does nothing.
    shown: Option<u32>,
}

/// A window and the surface that puts pixels on it.
struct Shown {
    window: Arc<Window>,
    surface: softbuffer::Surface<Arc<Window>, Arc<Window>>,
}

impl App {
    /// Draws the latest frame, one to one from the top-left corner.
    fn paint(&mut self) {
        let Some(shown) = self.window.as_mut() else {
            return;
        };
        let (width, height) = self.size;
        if shown.surface.resize(width, height).is_err() {
            return;
        }
        let Ok(mut pixels) = shown.surface.buffer_mut() else {
            return;
        };
        let frame = {
            let guard = self
                .framebuffer
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.latest_frame(SCANOUT).cloned()
        };
        pixels.fill(0);
        if let Some(frame) = &frame {
            composite(frame, width.get(), height.get(), &mut pixels);
        }
        let _ = pixels.present();
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
            .with_resizable(false);
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
        event_loop.set_control_flow(ControlFlow::WaitUntil(Instant::now() + FRAME_POLL));
    }

    fn window_event(&mut self, event_loop: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        match event {
            WindowEvent::CloseRequested => event_loop.exit(),
            WindowEvent::RedrawRequested => self.paint(),
            _ => {}
        }
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        if let Some(frame) = new_frame(&self.framebuffer, &mut self.shown) {
            if let Some(path) = &self.screenshot {
                let _ = write_ppm(&frame, path);
            }
            if let Some(shown) = &self.window {
                shown.window.request_redraw();
            }
        }
        event_loop.set_control_flow(ControlFlow::WaitUntil(Instant::now() + FRAME_POLL));
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

/// Copies `frame` into `out`, a `width` by `height` surface of `0x00RRGGBB` pixels (softbuffer's
/// layout), one to one from the top-left; the rest of `out` is left as it was, and a frame in a
/// format this cannot read leaves all of it. Pure, so the conversion is testable without a
/// window.
pub(crate) fn composite(frame: &Frame, width: u32, height: u32, out: &mut [u32]) {
    let Some([r, g, b]) = rgb_offsets(frame.format) else {
        return;
    };
    let cols = frame.width.min(width) as usize;
    let rows = frame.height.min(height) as usize;
    let stride = frame.width as usize * 4;
    for y in 0..rows {
        let Some(src_row) = frame.pixels.get(y * stride..y * stride + cols * 4) else {
            return;
        };
        let Some(dst_row) = out.get_mut(y * width as usize..y * width as usize + cols) else {
            return;
        };
        for (dst, px) in dst_row.iter_mut().zip(src_row.chunks_exact(4)) {
            *dst = (u32::from(px[r]) << 16) | (u32::from(px[g]) << 8) | u32::from(px[b]);
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
        fb.latest_frame(0).expect("presented").clone()
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
            composite(&f, 1, 1, &mut out);
            assert_eq!(out, [0x0011_2233], "{format:?}: R=11 G=22 B=33");
        }
    }

    /// A frame larger than the window is clipped and one smaller leaves the rest untouched, and
    /// neither reads or writes past a row.
    #[test]
    fn compositing_clips_to_the_smaller_of_frame_and_window() {
        let f = frame(
            PixelFormat::R8G8B8X8Unorm,
            3,
            2,
            &[
                1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, //
                4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0,
            ],
        );
        let mut small = [9u32; 2];
        composite(&f, 2, 1, &mut small);
        assert_eq!(small, [0x0001_0000, 0x0002_0000]);
        let mut big = [9u32; 4 * 3];
        composite(&f, 4, 3, &mut big);
        assert_eq!(
            big,
            [
                0x0001_0000,
                0x0002_0000,
                0x0003_0000,
                9, //
                0x0004_0000,
                0x0005_0000,
                0x0006_0000,
                9, //
                9,
                9,
                9,
                9,
            ]
        );
    }

    /// A format this cannot read composites nothing and refuses to be written, rather than
    /// guessing at channels.
    #[test]
    fn an_unknown_format_is_left_alone_not_guessed_at() {
        assert_eq!(rgb_offsets(PixelFormat::Unknown(77)), None);
        let mut f = frame(PixelFormat::R8G8B8X8Unorm, 1, 1, &[1, 2, 3, 4]);
        f.format = PixelFormat::Unknown(77);
        let mut out = [7u32];
        composite(&f, 1, 1, &mut out);
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
}
