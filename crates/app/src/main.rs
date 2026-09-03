//! `bsx-app`: a sandbox's display in a window, through iced. The roadmap 4.10 spike.
//!
//! One window and nothing else: lease the display of a named sandbox over its control socket,
//! map the frames where libkrun wrote them, and put each frame on screen as a texture upload of
//! the part that changed. What it exists to answer, each with a number: whether iced's winit and
//! the tree's are one, which wgpu backend comes up on this host, and how many frames a second
//! reach the screen against the rate the helper saw them.
//!
//! - **The frame logs are the measurement.** `--log` records each present as it is read and
//!   `--drawn-log` each upload, both on the host's monotonic clock, the clock the helper's own
//!   `--frame-log` uses, so three logs line up frame id by frame id.
//! - **The sandbox is not touched.** The app is a reader of a display the CLI started; stopping
//!   the sandbox ends the lease, and the app exits with it.
#![forbid(unsafe_code)]

mod frame;
mod lease;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use clap::Parser;
use iced::widget::{center, shader, text};
use iced::{Element, Fill, Size, Subscription, Task, window};

use bsx_krun::SharedFrames;
use bsx_supervisor::control::{Damage, InputSession};

/// Exit code for an operational failure, the CLI's convention.
const EXIT_OPERATIONAL: u8 = 2;

/// Presents the app remembers the damage of, so an upload after a run of missed redraws covers
/// exactly what changed since the frame it last uploaded.
const HISTORY: usize = 64;

#[derive(Parser)]
#[command(
    name = "bsx-app",
    version,
    about = "Show a sandbox's display in a window (the iced spike, roadmap 4.10)."
)]
struct Cli {
    /// The sandbox, by name (`bsx ls`).
    name: String,
    /// Append one `frame_id<TAB>nanoseconds` line here per present record read.
    #[arg(long, value_name = "PATH")]
    log: Option<PathBuf>,
    /// Append one `frame_id<TAB>nanoseconds` line here per frame uploaded to the GPU.
    #[arg(long, value_name = "PATH")]
    drawn_log: Option<PathBuf>,
    /// Append each input line sent to the guest here, as it went down the session.
    #[arg(long, value_name = "PATH")]
    input_log: Option<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    frame::report_adapter();
    let sinks = match frame::Sinks::open(cli.drawn_log.as_deref(), cli.input_log.as_deref()) {
        Ok(sinks) => Arc::new(sinks),
        Err(e) => {
            eprintln!("bsx-app: opening a log: {e}");
            return ExitCode::from(EXIT_OPERATIONAL);
        }
    };
    let name = cli.name.clone();
    let log = cli.log.clone();
    let boot = move || App::new(name.clone(), log.clone(), Arc::clone(&sinks));
    let title = format!("bsx: {}", cli.name);
    let ran = iced::application(boot, App::update, App::view)
        .subscription(App::subscription)
        .title(move |_: &App| title.clone())
        .theme(|_: &App| iced::Theme::Dark)
        .window_size(Size::new(640.0, 480.0))
        .run();
    match ran {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bsx-app: {e}");
            ExitCode::from(EXIT_OPERATIONAL)
        }
    }
}

/// What the lease thread tells the window.
#[derive(Debug)]
enum Message {
    /// The lease landed and its memfd is mapped.
    Mapped(Arc<SharedFrames>),
    /// A frame was presented into `slot`.
    Presented {
        frame_id: u32,
        slot: u32,
        damage: Damage,
    },
    /// The input session is open: the window's keyboard and pointer reach the guest.
    Input(InputSession),
    /// The lease ended, with why; the sandbox stopping is the ordinary case.
    Ended(String),
}

struct App {
    name: String,
    log: Option<PathBuf>,
    sinks: Arc<frame::Sinks>,
    frames: Option<Arc<SharedFrames>>,
    /// The presents read, newest last, each with what changed.
    history: Arc<Vec<frame::Present>>,
    /// Where the window's keyboard and pointer go, once the session is open.
    input: Arc<Mutex<Option<InputSession>>>,
    read: u64,
}

impl App {
    fn new(name: String, log: Option<PathBuf>, sinks: Arc<frame::Sinks>) -> Self {
        Self {
            name,
            log,
            sinks,
            frames: None,
            history: Arc::new(Vec::new()),
            input: Arc::new(Mutex::new(None)),
            read: 0,
        }
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Mapped(frames) => {
                let layout = frames.layout();
                eprintln!(
                    "bsx-app: mapped {}x{} {:?}, stride {}, {} slots",
                    layout.width, layout.height, layout.format, layout.stride, layout.slots
                );
                self.frames = Some(frames);
                let size = Size::new(layout.width as f32, layout.height as f32);
                window::latest().and_then(move |id| window::resize(id, size))
            }
            Message::Presented {
                frame_id,
                slot,
                damage,
            } => {
                self.read += 1;
                let history = Arc::make_mut(&mut self.history);
                if history.len() >= HISTORY {
                    history.remove(0);
                }
                history.push(frame::Present {
                    frame_id,
                    slot,
                    damage,
                });
                Task::none()
            }
            Message::Input(session) => {
                *self
                    .input
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(session);
                eprintln!("bsx-app: the keyboard and pointer reach the guest");
                Task::none()
            }
            Message::Ended(why) => {
                eprintln!(
                    "bsx-app: {why}; read {} presents, uploaded {} frames",
                    self.read,
                    self.sinks.uploaded()
                );
                iced::exit()
            }
        }
    }

    fn view(&self) -> Element<'_, Message> {
        match &self.frames {
            Some(frames) => shader(frame::Program {
                frames: Arc::clone(frames),
                history: Arc::clone(&self.history),
                sinks: Arc::clone(&self.sinks),
                input: Arc::clone(&self.input),
            })
            .width(Fill)
            .height(Fill)
            .into(),
            None => center(text(format!("leasing the display of {}…", self.name))).into(),
        }
    }

    fn subscription(&self) -> Subscription<Message> {
        Subscription::run_with((self.name.clone(), self.log.clone()), lease::stream)
    }
}
