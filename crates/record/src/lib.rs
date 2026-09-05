//! The run record: what the notebook keeps for one sandbox's lifetime, and where.
//!
//! A run is one directory under the runs directory, named by its id: a `record` file of
//! `key value` lines, the output files the verb captured, and `results/`, the directory the
//! guest sees as `/results`. The CLI writes it at start and at end; the CLI and the app both read
//! it, so neither shows a run the other cannot.
//!
//! - **Local, and only here.** `$BSX_RUNS_DIR`, else `$XDG_DATA_HOME/bsx/runs`, else
//!   `~/.local/share/bsx/runs`, created `0700`. Nothing in this crate opens a socket.
//! - **An id is one directory name, by an allow-list.** [`valid_id`] holds an id to
//!   `a-z A-Z 0-9 - _`, and every method that reads, writes or removes refuses one it rejects:
//!   the id is joined to a path and [`Store::remove`] hands the result to `remove_dir_all`.
//! - **The record is rewritten whole, atomically.** A reader sees the old text or the new, never
//!   a torn one: the end is written to a temporary file and renamed over the record.
//! - **Output is capped, and the cap is visible.** A capped file stops at the cap and leaves a
//!   `.truncated` sidecar, so a reader knows the file is not the whole output rather than reading
//!   a marker line as if the guest wrote it.
//! - **Retention is a count.** Ended runs beyond `$BSX_RUNS_KEEP` (default 200) are removed,
//!   oldest first, each time a run is created; a live run is never pruned.
//! - **An export is one file.** [`RunDir::export_tar`] writes the run directory as a ustar
//!   archive: a symlink inside is carried as a link entry and never followed.

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::fmt;
use std::io::{self, Read, Write};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// The record format's version, the first line of every record.
pub const FORMAT: u32 = 1;
/// The guest path every run's results directory is mounted at.
pub const RESULTS_GUEST_PATH: &str = "/results";
/// Ended runs kept when nothing says otherwise.
const DEFAULT_KEEP: usize = 200;
/// Bytes an output file holds when nothing says otherwise: 4 MiB.
const DEFAULT_CAP: u64 = 4 * 1024 * 1024;

/// What the guest could do to its root.
///
/// The record's own spelling of `bsx_supervisor::RootFs`, which this crate cannot name without
/// depending on the crate that links libkrun; `the_record_and_the_config_spell_the_posture_alike`
/// in `bsx` holds the two in step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Rootfs {
    /// Writes to the root failed.
    #[default]
    ReadOnly,
    /// Writes to the root went through to the image tree.
    Writable,
}

impl Rootfs {
    /// The word the record spells this as, which is also the `--rootfs` value.
    #[must_use]
    pub fn as_word(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::Writable => "writable",
        }
    }

    /// The posture a word names, or `None` for one this build does not know.
    #[must_use]
    pub fn from_word(word: &str) -> Option<Self> {
        match word {
            "read-only" => Some(Self::ReadOnly),
            "writable" => Some(Self::Writable),
            _ => None,
        }
    }
}

/// What the guest could reach off the machine. The record's spelling of `bsx_supervisor::Net`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Network {
    /// Loopback and nothing else.
    #[default]
    None,
    /// libkrun's transparent socket impersonation: the guest reached what the host could.
    Tsi,
}

impl Network {
    /// The word the record spells this as, which is also the `--net` value.
    #[must_use]
    pub fn as_word(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Tsi => "tsi",
        }
    }

    /// The posture a word names, or `None` for one this build does not know.
    #[must_use]
    pub fn from_word(word: &str) -> Option<Self> {
        match word {
            "none" => Some(Self::None),
            "tsi" => Some(Self::Tsi),
            _ => None,
        }
    }
}

/// The display a run had: non-zero by type, as `bsx_supervisor::Display` is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DisplayMode {
    /// Width in pixels.
    pub width: NonZeroU32,
    /// Height in pixels.
    pub height: NonZeroU32,
    /// The refresh rate the guest was told, in Hz, or `None` for the library's default.
    pub refresh: Option<NonZeroU32>,
}

impl DisplayMode {
    /// A display `width` by `height` pixels.
    #[must_use]
    pub fn new(width: NonZeroU32, height: NonZeroU32) -> Self {
        Self {
            width,
            height,
            refresh: None,
        }
    }

    /// The same display, with the guest told `hz`.
    #[must_use]
    pub fn with_refresh(mut self, hz: NonZeroU32) -> Self {
        self.refresh = Some(hz);
        self
    }

    /// The `WIDTHxHEIGHT` or `WIDTHxHEIGHT@HZ` spelling, which is the `--display` value.
    #[must_use]
    pub fn as_spec(self) -> String {
        match self.refresh {
            Some(hz) => format!("{}x{}@{hz}", self.width, self.height),
            None => format!("{}x{}", self.width, self.height),
        }
    }

    /// The display a spec names, or `None` for one that is not `WIDTHxHEIGHT[@HZ]`, all non-zero.
    #[must_use]
    pub fn parse(spec: &str) -> Option<Self> {
        let (size, refresh) = match spec.split_once('@') {
            Some((size, hz)) => (size, Some(hz.parse().ok()?)),
            None => (spec, None),
        };
        let (width, height) = size.split_once('x')?;
        Some(Self {
            width: width.parse().ok()?,
            height: height.parse().ok()?,
            refresh,
        })
    }
}

/// Which verb started the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verb {
    /// `bsx run`: one command, its stdout and stderr captured.
    Run,
    /// `bsx shell`: a pty session, the terminal's output captured.
    Shell,
    /// `bsx up`: a long-lived sandbox, each `exec`'s output appended.
    Up,
}

impl Verb {
    /// The word the record spells this verb as.
    #[must_use]
    pub fn as_word(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Shell => "shell",
            Self::Up => "up",
        }
    }

    fn from_word(word: &str) -> Option<Self> {
        match word {
            "run" => Some(Self::Run),
            "shell" => Some(Self::Shell),
            "up" => Some(Self::Up),
            _ => None,
        }
    }
}

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum End {
    /// The command exited with this code.
    Exit(i32),
    /// The VM was killed by this signal.
    Signal(i32),
    /// `bsx stop` ended it.
    Stopped,
    /// Its socket was found dead with no end recorded: the VM went without anyone watching.
    Gone,
    /// The verb failed before or while the command ran; the captured stderr says why.
    Failed,
}

impl fmt::Display for End {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exit(code) => write!(f, "exit {code}"),
            Self::Signal(sig) => write!(f, "signal {sig}"),
            Self::Stopped => f.write_str("stopped"),
            Self::Gone => f.write_str("gone"),
            Self::Failed => f.write_str("failed"),
        }
    }
}

impl End {
    fn parse(text: &str) -> Option<Self> {
        let mut words = text.split_whitespace();
        let end = match (words.next()?, words.next()) {
            ("exit", Some(code)) => Self::Exit(code.parse().ok()?),
            ("signal", Some(sig)) => Self::Signal(sig.parse().ok()?),
            ("stopped", None) => Self::Stopped,
            ("gone", None) => Self::Gone,
            ("failed", None) => Self::Failed,
            _ => return None,
        };
        words.next().is_none().then_some(end)
    }
}

/// What the sandbox could touch, as settled before it booted.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Posture {
    /// The guest root directory.
    pub root: PathBuf,
    /// What the guest may do to its root.
    pub rootfs: Rootfs,
    /// Host directories mounted read-write, as `(guest path, host path)`.
    pub mounts: Vec<(PathBuf, PathBuf)>,
    /// Extra virtiofs shares, as `(tag, host path)`.
    pub shares: Vec<(String, PathBuf)>,
    /// The network posture.
    pub network: Network,
    /// The display, or `None` for a headless sandbox.
    pub display: Option<DisplayMode>,
    /// Whether the guest got a sound card.
    pub sound: bool,
    /// Whether the run's results directory was mounted at [`RESULTS_GUEST_PATH`].
    pub results: bool,
    /// vCPUs.
    pub vcpus: u8,
    /// Guest RAM in MiB.
    pub mem_mib: u32,
}

impl Posture {
    /// A posture with these limits and nothing shared, to fill in.
    #[must_use]
    pub fn new(root: PathBuf, vcpus: u8, mem_mib: u32) -> Self {
        Self {
            root,
            vcpus,
            mem_mib,
            ..Self::default()
        }
    }

    /// One sentence naming what the sandbox may do and what it may not: the posture as a
    /// person reads it before starting, the same words in the CLI and the app.
    #[must_use]
    pub fn sentence(&self) -> String {
        let mut can = vec![format!(
            "read {}{}",
            self.root.display(),
            if self.rootfs == Rootfs::Writable {
                " and write it"
            } else {
                ""
            }
        )];
        for (guest, host) in &self.mounts {
            can.push(format!("write {} as {}", host.display(), guest.display()));
        }
        for (tag, host) in &self.shares {
            can.push(format!("reach {} by the tag {tag}", host.display()));
        }
        if self.results {
            can.push(format!("write its results to {RESULTS_GUEST_PATH}"));
        }
        if self.network == Network::Tsi {
            can.push("reach the network through the host".to_string());
        }
        if let Some(display) = self.display {
            can.push(format!("show a {} display", display.as_spec()));
        }
        if self.sound {
            can.push("play and capture sound".to_string());
        }
        let mut cannot = vec!["read anything else on this machine".to_string()];
        if self.network != Network::Tsi {
            cannot.push("reach the network".to_string());
        }
        if self.display.is_none() {
            cannot.push("show a display".to_string());
        }
        if !self.sound {
            cannot.push("play or capture sound".to_string());
        }
        format!(
            "This sandbox will: {}. It will not: {}.",
            can.join(", "),
            cannot.join(", ")
        )
    }
}

/// One run: what was asked, what it could touch, when it ran, and how it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Record {
    /// `<started_ms>-<name>`: unique on this machine, and sorted is chronological.
    pub id: String,
    /// The VM's name while it ran.
    pub name: String,
    /// Which verb started it.
    pub verb: Verb,
    /// The command, one word per element.
    pub command: Vec<String>,
    /// What it could touch.
    pub posture: Posture,
    /// When it started, milliseconds since the Unix epoch.
    pub started_ms: u64,
    /// The VM process, while known.
    pub pid: Option<u32>,
    /// When it ended, if it has.
    pub ended_ms: Option<u64>,
    /// How it ended, if it has.
    pub end: Option<End>,
}

impl Record {
    /// A record for a run starting now.
    #[must_use]
    pub fn begin(name: &str, verb: Verb, command: Vec<String>, posture: Posture) -> Self {
        let started_ms = now_ms();
        Self {
            id: format!("{started_ms}-{name}"),
            name: name.to_string(),
            verb,
            command,
            posture,
            started_ms,
            pid: None,
            ended_ms: None,
            end: None,
        }
    }

    /// Marks the run ended now.
    pub fn finish(&mut self, end: End) {
        self.ended_ms = Some(now_ms());
        self.end = Some(end);
    }

    /// Whether the run has no end yet.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.end.is_none()
    }

    /// The record as its file holds it.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let mut line = |key: &str, value: &dyn fmt::Display| {
            out.push_str(key);
            out.push(' ');
            out.push_str(&value.to_string());
            out.push('\n');
        };
        line("record", &FORMAT);
        line("id", &self.id);
        line("name", &self.name);
        line("verb", &self.verb.as_word());
        for arg in &self.command {
            line("arg", arg);
        }
        let p = &self.posture;
        line(
            "root",
            &format!("{} {}", p.root.display(), p.rootfs.as_word()),
        );
        for (guest, host) in &p.mounts {
            line(
                "mount",
                &format!("{} <- {}", guest.display(), host.display()),
            );
        }
        for (tag, host) in &p.shares {
            line("share", &format!("{tag} <- {}", host.display()));
        }
        line("network", &p.network.as_word());
        if let Some(display) = p.display {
            line("display", &display.as_spec());
        }
        line("sound", &if p.sound { "on" } else { "off" });
        line("results", &if p.results { "on" } else { "off" });
        line("limits", &format!("{} {}", p.vcpus, p.mem_mib));
        line("started", &self.started_ms);
        if let Some(pid) = self.pid {
            line("pid", &pid);
        }
        if let Some(ended) = self.ended_ms {
            line("ended", &ended);
        }
        if let Some(end) = self.end {
            line("end", &end);
        }
        out
    }

    /// A record read back from its text.
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let mut record = Self {
            id: String::new(),
            name: String::new(),
            verb: Verb::Run,
            command: Vec::new(),
            posture: Posture::default(),
            started_ms: 0,
            pid: None,
            ended_ms: None,
            end: None,
        };
        let mut seen_format = false;
        for (n, raw) in text.lines().enumerate() {
            let line = raw.trim_end();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line.split_once(' ').unwrap_or((line, ""));
            let bad = || ParseError(format!("line {}: {line:?}", n + 1));
            match key {
                "record" => {
                    let format: u32 = value.parse().map_err(|_| bad())?;
                    if format != FORMAT {
                        return Err(ParseError(format!(
                            "record format {format}; this build reads {FORMAT}"
                        )));
                    }
                    seen_format = true;
                }
                "id" => record.id = value.to_string(),
                "name" => record.name = value.to_string(),
                "verb" => record.verb = Verb::from_word(value).ok_or_else(bad)?,
                "arg" => record.command.push(value.to_string()),
                "root" => {
                    let (root, rootfs) = value.rsplit_once(' ').ok_or_else(bad)?;
                    record.posture.root = PathBuf::from(root);
                    record.posture.rootfs = Rootfs::from_word(rootfs).ok_or_else(bad)?;
                }
                "mount" => {
                    let (guest, host) = value.split_once(" <- ").ok_or_else(bad)?;
                    record
                        .posture
                        .mounts
                        .push((PathBuf::from(guest), PathBuf::from(host)));
                }
                "share" => {
                    let (tag, host) = value.split_once(" <- ").ok_or_else(bad)?;
                    record
                        .posture
                        .shares
                        .push((tag.to_string(), PathBuf::from(host)));
                }
                "network" => record.posture.network = Network::from_word(value).ok_or_else(bad)?,
                "display" => {
                    record.posture.display = Some(DisplayMode::parse(value).ok_or_else(bad)?)
                }
                "sound" => record.posture.sound = value == "on",
                "results" => record.posture.results = value == "on",
                "limits" => {
                    let (vcpus, mem) = value.split_once(' ').ok_or_else(bad)?;
                    record.posture.vcpus = vcpus.parse().map_err(|_| bad())?;
                    record.posture.mem_mib = mem.parse().map_err(|_| bad())?;
                }
                "started" => record.started_ms = value.parse().map_err(|_| bad())?,
                "pid" => record.pid = Some(value.parse().map_err(|_| bad())?),
                "ended" => record.ended_ms = Some(value.parse().map_err(|_| bad())?),
                "end" => record.end = Some(End::parse(value).ok_or_else(bad)?),
                // A key this build does not know is one a later build wrote: carried past, not
                // refused, so an older reader still lists the run.
                _ => {}
            }
        }
        if !seen_format {
            return Err(ParseError("no `record` line".to_string()));
        }
        if record.name.is_empty() {
            return Err(ParseError("no name".to_string()));
        }
        if !valid_id(&record.id) {
            return Err(ParseError(format!(
                "{:?} is not a usable id: {}",
                record.id,
                id_rule()
            )));
        }
        Ok(record)
    }
}

/// The most characters a run id may have, which bounds the directory name it becomes.
const MAX_ID: usize = 128;

/// Whether `id` may become a directory under the runs directory.
///
/// [`Store::remove`] hands the joined path to `remove_dir_all`, so this is an allow-list.
#[must_use]
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// The sentence [`valid_id`] enforces, for an error that has to say why.
fn id_rule() -> String {
    format!("1 to {MAX_ID} of a-z, A-Z, 0-9, `-` and `_`, since the id becomes a directory name")
}

/// The id refused before it is joined to a path.
fn checked_id(id: &str) -> io::Result<&str> {
    if valid_id(id) {
        return Ok(id);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{id:?} is not a usable run id: {}", id_rule()),
    ))
}

/// A record file this build could not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the record: {}", self.0)
    }
}

impl std::error::Error for ParseError {}

/// `ms` since the Unix epoch as `YYYY-MM-DD HH:MM:SSZ`, in UTC: one spelling in the CLI and
/// the app, with no time-zone table to carry.
#[must_use]
pub fn format_time(ms: u64) -> String {
    let secs = ms / 1000;
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    // Civil-from-days, as in Howard Hinnant's date algorithms.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// `ms` of duration as `4m12s`, `15s`, or `0.8s`.
#[must_use]
pub fn format_duration(ms: u64) -> String {
    let secs = ms / 1000;
    if secs >= 3600 {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else if secs >= 10 {
        format!("{secs}s")
    } else {
        format!("{}.{}s", secs, (ms % 1000) / 100)
    }
}

/// Milliseconds since the Unix epoch, now.
#[must_use]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The runs directory, from the environment: `$BSX_RUNS_DIR`, else `$XDG_DATA_HOME/bsx/runs`,
/// else `~/.local/share/bsx/runs`.
pub fn runs_dir() -> io::Result<PathBuf> {
    runs_dir_from(
        std::env::var_os("BSX_RUNS_DIR"),
        std::env::var_os("XDG_DATA_HOME"),
        std::env::var_os("HOME"),
    )
    .ok_or_else(|| io::Error::other("no runs directory: set BSX_RUNS_DIR, XDG_DATA_HOME or HOME"))
}

/// [`runs_dir`] with the environment reads lifted out.
#[must_use]
pub fn runs_dir_from(
    runs: Option<OsString>,
    xdg_data: Option<OsString>,
    home: Option<OsString>,
) -> Option<PathBuf> {
    runs.map(PathBuf::from)
        .or_else(|| xdg_data.map(|d| PathBuf::from(d).join("bsx/runs")))
        .or_else(|| home.map(|h| PathBuf::from(h).join(".local/share/bsx/runs")))
}

/// Ended runs to keep: `$BSX_RUNS_KEEP`, else 200.
#[must_use]
pub fn keep_count() -> usize {
    std::env::var("BSX_RUNS_KEEP")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_KEEP)
}

/// Bytes an output file holds: `$BSX_OUTPUT_CAP_KIB` KiB, else 4 MiB.
#[must_use]
pub fn output_cap() -> u64 {
    std::env::var("BSX_OUTPUT_CAP_KIB")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map_or(DEFAULT_CAP, |kib| kib.saturating_mul(1024))
}

/// The runs directory as a store of records.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    /// The store at the runs directory the environment names, created if absent.
    pub fn open() -> io::Result<Self> {
        Self::at(runs_dir()?)
    }

    /// The store at `dir`, created `0700` if absent.
    pub fn at(dir: PathBuf) -> io::Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        builder.mode(0o700);
        builder.create(&dir)?;
        Ok(Self { dir })
    }

    /// Where the store is.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The directory of the run with `id`, joined and not checked.
    ///
    /// Every method here that touches the filesystem refuses an id [`valid_id`] rejects.
    #[must_use]
    pub fn dir_of(&self, id: &str) -> RunDir {
        RunDir {
            path: self.dir.join(id),
        }
    }

    /// Creates the run's directory and its `results/`, writes the record, and prunes ended runs
    /// beyond [`keep_count`].
    pub fn create(&self, record: &Record) -> io::Result<RunDir> {
        let run = self.dir_of(checked_id(&record.id)?);
        std::fs::create_dir(&run.path)?;
        std::fs::create_dir(run.results())?;
        self.save(record)?;
        let _ = self.prune(keep_count());
        Ok(run)
    }

    /// Writes the record whole, atomically.
    pub fn save(&self, record: &Record) -> io::Result<()> {
        let run = self.dir_of(checked_id(&record.id)?);
        let tmp = run.path.join("record.tmp");
        std::fs::write(&tmp, record.to_text())?;
        std::fs::rename(&tmp, run.record_path())
    }

    /// Reads the run with `id`.
    pub fn read(&self, id: &str) -> io::Result<Record> {
        let text = std::fs::read_to_string(self.dir_of(checked_id(id)?).record_path())?;
        Record::parse(&text).map_err(io::Error::other)
    }

    /// Every run that can be read, newest first. A directory whose record cannot be read is
    /// skipped rather than failing the list.
    pub fn list(&self) -> io::Result<Vec<Record>> {
        let mut records = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            if !entry.path().is_dir() {
                continue;
            }
            let id = entry.file_name().to_string_lossy().into_owned();
            if let Ok(record) = self.read(&id) {
                records.push(record);
            }
        }
        records.sort_by(|a, b| b.started_ms.cmp(&a.started_ms).then(b.id.cmp(&a.id)));
        Ok(records)
    }

    /// The run `key` names: by id, else the newest by name.
    pub fn find(&self, key: &str) -> io::Result<Option<Record>> {
        if let Ok(record) = self.read(key) {
            return Ok(Some(record));
        }
        Ok(self.list()?.into_iter().find(|r| r.name == key))
    }

    /// The newest open run named `name`, which is the record a live VM of that name belongs to.
    pub fn open_run(&self, name: &str) -> io::Result<Option<Record>> {
        Ok(self
            .list()?
            .into_iter()
            .find(|r| r.name == name && r.is_open()))
    }

    /// Removes the run with `id` and everything it captured.
    pub fn remove(&self, id: &str) -> io::Result<()> {
        std::fs::remove_dir_all(self.dir_of(checked_id(id)?).path)
    }

    /// Removes ended runs beyond the newest `keep`, oldest first, and says how many went.
    pub fn prune(&self, keep: usize) -> io::Result<usize> {
        let ended: Vec<Record> = self.list()?.into_iter().filter(|r| !r.is_open()).collect();
        let mut removed = 0;
        for record in ended.iter().skip(keep) {
            if self.remove(&record.id).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Writes the run as `bsx-<id>.tar` into `dest` when `dest` is a directory, or exactly at
    /// `dest` otherwise, and returns the path written. Each caller writes its own temporary and
    /// renames it whole, so concurrent exports replace one another rather than tear.
    pub fn export(&self, id: &str, dest: &Path) -> io::Result<PathBuf> {
        let run = self.dir_of(checked_id(id)?);
        if !run.path().is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no run {id} in the notebook"),
            ));
        }
        let target = if dest.is_dir() {
            dest.join(format!("bsx-{id}.tar"))
        } else {
            dest.to_path_buf()
        };
        static EXPORT_SEQ: AtomicU64 = AtomicU64::new(0);
        let tmp = target.with_extension(format!(
            "tar.{}.{}.tmp",
            std::process::id(),
            EXPORT_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let written = std::fs::File::create(&tmp).and_then(|file| {
            let mut out = io::BufWriter::new(file);
            run.export_tar(&mut out)?;
            out.flush()
        });
        match written {
            Ok(()) => {
                std::fs::rename(&tmp, &target)?;
                Ok(target)
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                Err(e)
            }
        }
    }
}

/// One run's directory and the files in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunDir {
    path: PathBuf,
}

impl RunDir {
    /// The directory itself.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The record file.
    #[must_use]
    pub fn record_path(&self) -> PathBuf {
        self.path.join("record")
    }

    /// The directory the guest sees as [`RESULTS_GUEST_PATH`].
    #[must_use]
    pub fn results(&self) -> PathBuf {
        self.path.join("results")
    }

    /// What a `run`'s command wrote to stdout.
    #[must_use]
    pub fn stdout(&self) -> PathBuf {
        self.path.join("stdout")
    }

    /// What a `run`'s command wrote to stderr, with the VM's own messages.
    #[must_use]
    pub fn stderr(&self) -> PathBuf {
        self.path.join("stderr")
    }

    /// What a `shell` session's terminal showed.
    #[must_use]
    pub fn shell_log(&self) -> PathBuf {
        self.path.join("shell.log")
    }

    /// What each `exec` into an `up` sandbox printed, each under a `# <ms> <command>` line.
    #[must_use]
    pub fn exec_log(&self) -> PathBuf {
        self.path.join("exec.log")
    }

    /// Opens `file` for appending under the output cap.
    pub fn append(&self, file: &Path) -> io::Result<Capped> {
        Capped::open(file, output_cap())
    }

    /// The files in `results/`, relative, with their sizes, sorted by name.
    pub fn result_files(&self) -> io::Result<Vec<(PathBuf, u64)>> {
        let mut files = Vec::new();
        let root = self.results();
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(meta) = entry.metadata() else {
                    continue;
                };
                if meta.is_dir() {
                    stack.push(path);
                } else if let Ok(rel) = path.strip_prefix(&root) {
                    files.push((rel.to_path_buf(), meta.len()));
                }
            }
        }
        files.sort();
        Ok(files)
    }

    /// Writes the run directory as a ustar archive under one `<id>/` top-level entry.
    ///
    /// A symlink is carried as a link entry and never opened, a file that changes mid-export
    /// keeps the size its header pinned, and an entry ustar cannot carry is refused, not bent.
    pub fn export_tar(&self, out: &mut impl Write) -> io::Result<()> {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;
        let top = self
            .path
            .file_name()
            .ok_or_else(|| io::Error::other("the run directory has no name to archive under"))?
            .as_bytes()
            .to_vec();
        let mut stack = vec![(self.path.clone(), top)];
        while let Some((dir, at)) = stack.pop() {
            let meta = std::fs::symlink_metadata(&dir)?;
            let mut dirname = at.clone();
            dirname.push(b'/');
            out.write_all(&tar_header(
                &dirname,
                &TarEntry::Directory,
                mtime_of(&meta),
            )?)?;
            let mut children: Vec<std::fs::DirEntry> =
                std::fs::read_dir(&dir)?.collect::<Result<_, _>>()?;
            children.sort_by_cached_key(std::fs::DirEntry::file_name);
            let mut subdirs = Vec::new();
            for child in children {
                let path = child.path();
                let meta = std::fs::symlink_metadata(&path)?;
                let mut name = at.clone();
                name.push(b'/');
                name.extend_from_slice(child.file_name().as_bytes());
                if meta.file_type().is_symlink() {
                    let target = std::fs::read_link(&path)?;
                    let entry = TarEntry::Symlink {
                        target: target.as_os_str().as_bytes(),
                    };
                    out.write_all(&tar_header(&name, &entry, mtime_of(&meta))?)?;
                } else if meta.is_dir() {
                    subdirs.push((path, name));
                } else if meta.is_file() {
                    let mode = if meta.permissions().mode() & 0o100 == 0 {
                        0o644
                    } else {
                        0o755
                    };
                    let entry = TarEntry::File {
                        size: meta.len(),
                        mode,
                    };
                    out.write_all(&tar_header(&name, &entry, mtime_of(&meta))?)?;
                    copy_pinned(&path, &meta, out)?;
                }
                // A fifo, socket or device node is left behind: opening one is not a read.
            }
            subdirs.reverse();
            stack.extend(subdirs);
        }
        out.write_all(&[0u8; BLOCK])?;
        out.write_all(&[0u8; BLOCK])?;
        Ok(())
    }
}

/// A ustar header or content block.
const BLOCK: usize = 512;

/// The largest entry ustar's eleven octal digits carry: 8 GiB - 1.
const MAX_ENTRY: u64 = 0o77_777_777_777;

/// What one archive entry is, carrying only what its kind writes into the header.
enum TarEntry<'a> {
    Directory,
    File { size: u64, mode: u32 },
    Symlink { target: &'a [u8] },
}

impl TarEntry<'_> {
    fn typeflag(&self) -> u8 {
        match self {
            Self::Directory => b'5',
            Self::File { .. } => b'0',
            Self::Symlink { .. } => b'2',
        }
    }

    fn size(&self) -> u64 {
        match self {
            Self::File { size, .. } => *size,
            Self::Directory | Self::Symlink { .. } => 0,
        }
    }

    fn mode(&self) -> u32 {
        match self {
            Self::Directory => 0o755,
            Self::File { mode, .. } => *mode,
            Self::Symlink { .. } => 0o777,
        }
    }

    fn link(&self) -> &[u8] {
        match self {
            Self::Symlink { target } => target,
            Self::Directory | Self::File { .. } => b"",
        }
    }
}

/// One ustar header block, checksummed last, refused when any field cannot hold its value.
fn tar_header(path: &[u8], entry: &TarEntry<'_>, mtime: u64) -> io::Result<[u8; BLOCK]> {
    let (prefix, name) = split_name(path)?;
    let link = entry.link();
    if link.len() > 100 {
        return Err(io::Error::other(format!(
            "{}: the link target does not fit a ustar header",
            String::from_utf8_lossy(path)
        )));
    }
    let size = entry.size();
    if size > MAX_ENTRY {
        return Err(io::Error::other(format!(
            "{}: {size} bytes is more than one ustar entry carries",
            String::from_utf8_lossy(path)
        )));
    }
    let mut block = [0u8; BLOCK];
    block[..name.len()].copy_from_slice(name);
    block[345..345 + prefix.len()].copy_from_slice(prefix);
    octal(&mut block[100..108], u64::from(entry.mode()));
    octal(&mut block[108..116], 0);
    octal(&mut block[116..124], 0);
    octal(&mut block[124..136], size);
    octal(&mut block[136..148], mtime);
    block[156] = entry.typeflag();
    block[157..157 + link.len()].copy_from_slice(link);
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");
    octal(&mut block[329..337], 0);
    octal(&mut block[337..345], 0);
    block[148..156].fill(b' ');
    let sum: u32 = block.iter().map(|b| u32::from(*b)).sum();
    octal(&mut block[148..155], u64::from(sum));
    block[155] = b' ';
    Ok(block)
}

/// The `prefix`/`name` split for `path`: the largest cut both fields hold, or a refusal.
fn split_name(path: &[u8]) -> io::Result<(&[u8], &[u8])> {
    if path.len() <= 100 {
        return Ok((&[], path));
    }
    // The last byte of a directory's path is `/`; a cut there would leave an empty name.
    let splittable = path.len() - usize::from(path.ends_with(b"/"));
    for i in (0..splittable.min(156)).rev() {
        if path[i] == b'/' && path.len() - i - 1 <= 100 {
            return Ok((&path[..i], &path[i + 1..]));
        }
    }
    Err(io::Error::other(format!(
        "{} does not fit a ustar header's name fields",
        String::from_utf8_lossy(path)
    )))
}

/// Writes `value` as zero-padded octal digits with a trailing NUL, the ustar numeric shape.
/// The caller bounds `value` to the field: digits past it are dropped.
fn octal(field: &mut [u8], value: u64) {
    let digits = field.len() - 1;
    for (i, byte) in field[..digits].iter_mut().enumerate() {
        let shift = 3 * (digits - 1 - i);
        *byte = b'0' + ((value >> shift) & 0o7) as u8;
    }
    field[digits] = 0;
}

/// The entry's own mtime in whole seconds, or zero when the clock cannot say.
fn mtime_of(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs())
}

/// Copies exactly the size `judged` pinned: growth stays behind, a shrink is zero-filled, and a
/// path no longer naming the judged inode is refused, never read.
fn copy_pinned(path: &Path, judged: &std::fs::Metadata, out: &mut impl Write) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let file = std::fs::File::open(path)?;
    let opened = file.metadata()?;
    if (opened.dev(), opened.ino()) != (judged.dev(), judged.ino()) {
        return Err(io::Error::other(format!(
            "{} changed while exporting",
            path.display()
        )));
    }
    let size = judged.len();
    let mut pinned = file.take(size);
    let copied = io::copy(&mut pinned, out)?;
    write_zeros(out, size - copied)?;
    write_zeros(out, size.next_multiple_of(BLOCK as u64) - size)?;
    Ok(())
}

/// Writes `n` zero bytes.
fn write_zeros(out: &mut impl Write, mut n: u64) -> io::Result<()> {
    let zeros = [0u8; BLOCK];
    while n > 0 {
        let step = n.min(BLOCK as u64) as usize;
        out.write_all(&zeros[..step])?;
        n -= step as u64;
    }
    Ok(())
}

/// A writer that stops at a cap and leaves a `.truncated` sidecar when it did.
#[derive(Debug)]
pub struct Capped {
    file: std::fs::File,
    path: PathBuf,
    remaining: u64,
    truncated: bool,
}

impl Capped {
    /// Opens `path` for appending, with `cap` bytes allowed in total across the file.
    pub fn open(path: &Path, cap: u64) -> io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(path)?;
        let held = file.metadata().map_or(0, |m| m.len());
        Ok(Self {
            file,
            path: path.to_path_buf(),
            remaining: cap.saturating_sub(held),
            truncated: false,
        })
    }

    /// Whether the cap was hit.
    #[must_use]
    pub fn truncated(&self) -> bool {
        self.truncated
    }
}

impl Write for Capped {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let allowed = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        if allowed < buf.len() && !self.truncated {
            self.truncated = true;
            let _ = std::fs::write(self.path.with_extension("truncated"), b"");
        }
        if allowed > 0 {
            self.file.write_all(&buf[..allowed])?;
            self.remaining -= allowed as u64;
        }
        // The bytes past the cap are accepted and dropped: the caller's copy to its own stdout
        // must not stall because the record is full.
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn posture() -> Posture {
        let mut p = Posture::new(PathBuf::from("/img/rootfs"), 2, 768);
        p.rootfs = Rootfs::ReadOnly;
        p.mounts
            .push((PathBuf::from("/mnt"), PathBuf::from("/home/x/out dir")));
        p.shares
            .push(("src".to_string(), PathBuf::from("/home/x/src")));
        p.network = Network::None;
        p.display = DisplayMode::parse("640x480@60");
        p.sound = true;
        p.results = true;
        p
    }

    /// A record survives its text: every field, including a path with a space, a multi-word
    /// command, and the end once it has one; an unknown key is passed over.
    #[test]
    fn a_record_round_trips_through_its_text() {
        let mut record = Record::begin(
            "fetch-42",
            Verb::Run,
            vec!["python3".into(), "/mnt/fetch it.py".into()],
            posture(),
        );
        record.pid = Some(4242);
        let open = Record::parse(&record.to_text()).expect("parses");
        assert_eq!(open, record);
        assert!(open.is_open());
        record.finish(End::Exit(3));
        let text = record.to_text() + "future-key something\n";
        let ended = Record::parse(&text).expect("parses with a key it does not know");
        assert_eq!(ended, record);
        assert_eq!(ended.end, Some(End::Exit(3)));
        assert!(ended.ended_ms.is_some());
        assert!(record.id.ends_with("-fetch-42"));
    }

    /// A record from another format, without its format line, or with a line this build cannot
    /// read, is refused with the line named rather than read wrong.
    #[test]
    fn a_record_this_build_cannot_read_is_refused() {
        assert!(Record::parse("id x\nname y\n").is_err(), "no format line");
        assert!(
            Record::parse("record 2\nid x\nname y\n").is_err(),
            "a later format"
        );
        let err = Record::parse("record 1\nid x\nname y\nlimits many\n").expect_err("bad limits");
        assert!(err.to_string().contains("line 4"), "{err}");
        assert_eq!(End::parse("exit 0"), Some(End::Exit(0)));
        assert_eq!(End::parse("signal 9"), Some(End::Signal(9)));
        assert_eq!(End::parse("stopped"), Some(End::Stopped));
        assert_eq!(End::parse("stopped now"), None);
        assert_eq!(End::parse("exit"), None);
        assert_eq!(End::parse("failed"), Some(End::Failed));
    }

    /// The clock spells a moment in UTC and a span in the unit a reader wants.
    #[test]
    fn times_are_spelled_in_utc_and_spans_by_size() {
        assert_eq!(format_time(0), "1970-01-01 00:00:00Z");
        assert_eq!(format_time(1_756_860_007_123), "2025-09-03 00:40:07Z");
        assert_eq!(format_time(951_782_400_000), "2000-02-29 00:00:00Z");
        assert_eq!(format_duration(800), "0.8s");
        assert_eq!(format_duration(15_000), "15s");
        assert_eq!(format_duration(252_000), "4m12s");
        assert_eq!(format_duration(3_720_000), "1h02m");
    }

    /// The store creates a run with its results directory, lists newest first, finds by id and
    /// by name, tells a live run from an ended one, and prunes ended runs beyond the count.
    #[test]
    fn the_store_creates_lists_finds_and_prunes() {
        let dir = bsx_test_support::ScratchDir::created("record-store");
        let store = Store::at(dir.path().join("runs")).expect("a store");
        let mut first = Record::begin("a", Verb::Up, vec![], posture());
        first.started_ms -= 10;
        first.id = format!("{}-a", first.started_ms);
        let second = Record::begin("b", Verb::Run, vec!["true".into()], posture());
        let mut third = Record::begin("a", Verb::Run, vec!["ls".into()], posture());
        third.started_ms += 10;
        third.id = format!("{}-a", third.started_ms);
        for r in [&first, &second, &third] {
            let run = store.create(r).expect("created");
            assert!(run.results().is_dir(), "results/ exists from the start");
        }
        let ids: Vec<_> = store
            .list()
            .expect("listed")
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(
            ids,
            [third.id.clone(), second.id.clone(), first.id.clone()],
            "newest first"
        );
        assert_eq!(
            store.find("a").expect("found").map(|r| r.id),
            Some(third.id.clone()),
            "the newest by name"
        );
        assert_eq!(
            store.find(&first.id).expect("found").map(|r| r.id),
            Some(first.id.clone()),
            "by id"
        );
        assert_eq!(store.find("nobody").expect("no error"), None);

        let mut ended = second.clone();
        ended.finish(End::Stopped);
        store.save(&ended).expect("saved");
        assert_eq!(store.open_run("b").expect("no error"), None, "b has ended");
        assert_eq!(
            store.open_run("a").expect("no error").map(|r| r.id),
            Some(third.id.clone()),
            "the newest open a"
        );
        assert_eq!(
            store.prune(0).expect("pruned"),
            1,
            "only the ended run goes"
        );
        assert_eq!(store.list().expect("listed").len(), 2);
        store.remove(&first.id).expect("removed");
        assert!(store.read(&first.id).is_err());
    }

    /// A capped file holds the first `cap` bytes, accepts the rest without failing the writer,
    /// and leaves a sidecar saying it was cut.
    #[test]
    fn a_capped_file_stops_at_the_cap_and_says_so() {
        let dir = bsx_test_support::ScratchDir::created("record-cap");
        let path = dir.path().join("stdout");
        let mut out = Capped::open(&path, 10).expect("opened");
        out.write_all(b"12345").expect("under the cap");
        assert!(!out.truncated());
        out.write_all(b"6789012345")
            .expect("past the cap is accepted");
        assert!(out.truncated());
        out.write_all(b"more").expect("still accepted");
        assert_eq!(std::fs::read(&path).expect("read"), b"1234567890");
        assert!(path.with_extension("truncated").exists());
        let mut again = Capped::open(&path, 10).expect("reopened");
        again.write_all(b"x").expect("accepted");
        assert_eq!(
            std::fs::read(&path).expect("read").len(),
            10,
            "already full"
        );
        assert_eq!(
            runs_dir_from(None, Some("/xdg".into()), Some("/home/u".into())),
            Some(PathBuf::from("/xdg/bsx/runs"))
        );
        assert_eq!(
            runs_dir_from(None, None, Some("/home/u".into())),
            Some(PathBuf::from("/home/u/.local/share/bsx/runs"))
        );
        assert_eq!(runs_dir_from(None, None, None), None);
    }

    /// The posture sentence names what is granted and what is not, and never claims more than
    /// the record says.
    #[test]
    fn the_posture_sentence_names_both_sides() {
        let s = posture().sentence();
        assert!(s.contains("read /img/rootfs"), "{s}");
        assert!(s.contains("write /home/x/out dir as /mnt"), "{s}");
        assert!(s.contains("write its results to /results"), "{s}");
        assert!(s.contains("show a 640x480@60 display"), "{s}");
        assert!(
            s.contains("It will not: read anything else on this machine, reach the network."),
            "{s}"
        );
        let bare = Posture::new(PathBuf::from("/img"), 1, 512).sentence();
        assert!(bare.contains("It will not: read anything else on this machine, reach the network, show a display, play or capture sound."), "{bare}");
    }

    /// An id is one directory name. A record file naming a traversing id does not parse, and the
    /// store refuses one directly, so the directory beside the store survives a `remove` that
    /// points at it.
    #[test]
    fn an_id_that_would_leave_the_store_is_refused_by_every_door() {
        let dir = bsx_test_support::ScratchDir::created("record-id");
        let neighbour = dir.path().join("neighbour");
        std::fs::create_dir_all(neighbour.join("keep")).expect("a directory beside the store");
        let store = Store::at(dir.path().join("runs")).expect("a store");

        for bad in [
            "../neighbour",
            "..",
            "/etc",
            "a/b",
            "",
            &"x".repeat(MAX_ID + 1),
        ] {
            assert!(!valid_id(bad), "{bad:?} must not be a usable id");
            for outcome in [
                store.remove(bad).err(),
                store.read(bad).err(),
                store.create(&record_with_id(bad)).err(),
                store.save(&record_with_id(bad)).err(),
            ] {
                assert!(outcome.is_some(), "{bad:?} must be refused");
                let e = outcome.expect("the refusal");
                assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{bad:?}: {e}");
            }
        }
        assert!(
            neighbour.join("keep").is_dir(),
            "the neighbour is untouched"
        );

        // The other door: a record file carrying a traversing id, which `list` and `find` would
        // otherwise hand back for `remove` to act on.
        let planted = store.dir().join("1756860007123-planted");
        std::fs::create_dir_all(&planted).expect("a run directory");
        let mut record = record_with_id("1756860007123-planted");
        record.id = "../neighbour".to_string();
        std::fs::write(planted.join("record"), record.to_text()).expect("the planted record");
        assert_eq!(store.list().expect("listed"), vec![], "it does not parse");
        assert_eq!(store.find("../neighbour").expect("no error"), None);
        assert!(
            neighbour.join("keep").is_dir(),
            "the neighbour is still there"
        );
    }

    fn record_with_id(id: &str) -> Record {
        let mut record = Record::begin("named", Verb::Run, vec!["true".into()], posture());
        record.id = id.to_string();
        record
    }

    /// One archive entry as [`read_tar`] saw it.
    struct Entry {
        path: String,
        kind: u8,
        size: u64,
        link: String,
        content: Vec<u8>,
    }

    /// Parses ustar: every checksum recomputed, prefix joined, the two-block trailer required.
    fn read_tar(bytes: &[u8]) -> Vec<Entry> {
        let mut entries = Vec::new();
        let mut at = 0;
        loop {
            let block = &bytes[at..at + BLOCK];
            if block.iter().all(|b| *b == 0) {
                assert!(
                    bytes[at + BLOCK..at + 2 * BLOCK].iter().all(|b| *b == 0),
                    "the trailer is two zero blocks"
                );
                assert_eq!(bytes.len(), at + 2 * BLOCK, "nothing follows the trailer");
                return entries;
            }
            let sum: u64 = block
                .iter()
                .enumerate()
                .map(|(i, b)| u64::from(if (148..156).contains(&i) { b' ' } else { *b }))
                .sum();
            assert_eq!(sum, parse_octal(&block[148..156]), "checksum at {at}");
            assert_eq!(&block[257..263], b"ustar\0", "magic at {at}");
            let size = parse_octal(&block[124..136]);
            let prefix = field_str(&block[345..500]);
            let name = field_str(&block[..100]);
            let path = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            let link = field_str(&block[157..257]);
            let kind = block[156];
            at += BLOCK;
            let held = usize::try_from(size).expect("a test-sized entry");
            let content = bytes[at..at + held].to_vec();
            at += held.div_ceil(BLOCK) * BLOCK;
            entries.push(Entry {
                path,
                kind,
                size,
                link,
                content,
            });
        }
    }

    fn parse_octal(field: &[u8]) -> u64 {
        field
            .iter()
            .take_while(|b| **b != 0 && **b != b' ')
            .fold(0, |v, b| v * 8 + u64::from(*b - b'0'))
    }

    fn field_str(field: &[u8]) -> String {
        let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
        String::from_utf8_lossy(&field[..end]).into_owned()
    }

    /// A writer that runs `act` once, on first seeing `needle` in a written block.
    struct SabotageOnSight<'a> {
        out: Vec<u8>,
        needle: &'a [u8],
        act: Option<Box<dyn FnOnce() + 'a>>,
    }

    impl Write for SabotageOnSight<'_> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if buf.windows(self.needle.len()).any(|w| w == self.needle)
                && let Some(act) = self.act.take()
            {
                act();
            }
            self.out.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// The archive holds the whole run directory under one top entry, depth-first and sorted,
    /// and an unchanged run exports the same bytes twice.
    #[test]
    fn a_run_directory_round_trips_through_its_tar() {
        let dir = bsx_test_support::ScratchDir::created("record-tar");
        let store = Store::at(dir.path().join("runs")).expect("a store");
        let record = record_with_id("1756860007123-x");
        let run = store.create(&record).expect("created");
        std::fs::write(run.stdout(), b"hello\n").expect("stdout");
        std::fs::create_dir_all(run.results().join("sub")).expect("a results subdir");
        std::fs::write(run.results().join("sub/out.txt"), b"data").expect("a result");
        std::fs::create_dir(run.results().join("empty")).expect("an empty dir");

        let mut first = Vec::new();
        run.export_tar(&mut first).expect("exported");
        let mut second = Vec::new();
        run.export_tar(&mut second).expect("exported again");
        assert_eq!(first, second, "an unchanged run exports the same bytes");

        let entries = read_tar(&first);
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "1756860007123-x/",
                "1756860007123-x/record",
                "1756860007123-x/stdout",
                "1756860007123-x/results/",
                "1756860007123-x/results/empty/",
                "1756860007123-x/results/sub/",
                "1756860007123-x/results/sub/out.txt",
            ]
        );
        let stdout = entries
            .iter()
            .find(|e| e.path.ends_with("/stdout"))
            .expect("stdout");
        assert_eq!(
            (stdout.kind, stdout.content.as_slice()),
            (b'0', b"hello\n".as_slice())
        );
        assert_eq!(entries.iter().filter(|e| e.kind == b'5').count(), 4);
    }

    /// A path longer than the name field is split across prefix and name, and joins back.
    #[test]
    fn a_long_path_is_split_across_prefix_and_name() {
        let dir = bsx_test_support::ScratchDir::created("record-tar-long");
        let store = Store::at(dir.path().join("runs")).expect("a store");
        let record = record_with_id("1756860007123-long");
        let run = store.create(&record).expect("created");
        let a = "a".repeat(60);
        let b = "b".repeat(60);
        std::fs::create_dir_all(run.results().join(&a).join(&b)).expect("deep dirs");
        std::fs::write(run.results().join(&a).join(&b).join("deep.txt"), b"deep")
            .expect("a result");
        let mut tar = Vec::new();
        run.export_tar(&mut tar).expect("exported");
        let expected = format!("1756860007123-long/results/{a}/{b}/deep.txt");
        assert!(expected.len() > 100, "the fixture is long enough to split");
        let entry = read_tar(&tar)
            .into_iter()
            .find(|e| e.path == expected)
            .expect("the deep entry, joined back");
        assert_eq!(entry.content, b"deep");
    }

    /// A symlink is archived as itself: the target string is kept, the target is never opened.
    #[test]
    fn a_symlink_is_archived_as_itself_and_never_followed() {
        let dir = bsx_test_support::ScratchDir::created("record-tar-link");
        std::fs::write(dir.path().join("outside.txt"), b"SENTINEL-DO-NOT-ARCHIVE")
            .expect("the outside file");
        let store = Store::at(dir.path().join("runs")).expect("a store");
        let record = record_with_id("1756860007123-link");
        let run = store.create(&record).expect("created");
        std::os::unix::fs::symlink("../../../outside.txt", run.results().join("leak"))
            .expect("a symlink");
        let mut tar = Vec::new();
        run.export_tar(&mut tar).expect("exported");
        let entry = read_tar(&tar)
            .into_iter()
            .find(|e| e.path.ends_with("/leak"))
            .expect("the link entry");
        assert_eq!((entry.kind, entry.size), (b'2', 0));
        assert_eq!(entry.link, "../../../outside.txt");
        assert!(
            !tar.windows(b"SENTINEL".len()).any(|w| w == b"SENTINEL"),
            "the target's bytes are nowhere in the archive"
        );
    }

    /// A file mutated after its header keeps the pinned size, so the next entry still parses.
    #[test]
    fn a_file_that_grows_or_shrinks_mid_export_keeps_its_pinned_size() {
        let dir = bsx_test_support::ScratchDir::created("record-tar-pin");
        let store = Store::at(dir.path().join("runs")).expect("a store");
        let record = record_with_id("1756860007123-pin");
        let run = store.create(&record).expect("created");
        std::fs::write(run.results().join("grows.txt"), b"12345678").expect("a file");
        std::fs::write(run.results().join("shrinks.txt"), b"abcdefgh").expect("a file");

        let grows = run.results().join("grows.txt");
        let mut out = SabotageOnSight {
            out: Vec::new(),
            needle: b"grows.txt",
            act: Some(Box::new(move || {
                let mut f = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&grows)
                    .expect("append");
                f.write_all(b"MORE").expect("grown");
            })),
        };
        run.export_tar(&mut out).expect("exported");
        let entries = read_tar(&out.out);
        let grown = entries
            .iter()
            .find(|e| e.path.ends_with("/grows.txt"))
            .expect("the grown entry");
        assert_eq!(
            (grown.size, grown.content.as_slice()),
            (8, b"12345678".as_slice()),
            "what grew past the header stays behind"
        );

        let shrinks = run.results().join("shrinks.txt");
        let mut out = SabotageOnSight {
            out: Vec::new(),
            needle: b"shrinks.txt",
            act: Some(Box::new(move || {
                std::fs::write(&shrinks, b"ab").expect("shrunk");
            })),
        };
        run.export_tar(&mut out).expect("exported");
        let entries = read_tar(&out.out);
        let shrunk = entries
            .iter()
            .find(|e| e.path.ends_with("/shrinks.txt"))
            .expect("the shrunk entry");
        assert_eq!(shrunk.size, 8, "the header's size holds");
        assert_eq!(&shrunk.content[..2], b"ab");
        assert_eq!(
            shrunk.content[2..],
            [0u8; 6],
            "the shortfall is zero-filled"
        );
    }

    /// A path swapped for a symlink between its header and its read is refused, not followed.
    #[test]
    fn an_entry_swapped_mid_export_is_refused() {
        let dir = bsx_test_support::ScratchDir::created("record-tar-swap");
        let outside = dir.path().join("other.txt");
        std::fs::write(&outside, b"other").expect("the other file");
        let store = Store::at(dir.path().join("runs")).expect("a store");
        let record = record_with_id("1756860007123-swap");
        let run = store.create(&record).expect("created");
        std::fs::write(run.results().join("swap.txt"), b"original").expect("a file");
        let swap = run.results().join("swap.txt");
        let mut out = SabotageOnSight {
            out: Vec::new(),
            needle: b"swap.txt",
            act: Some(Box::new(move || {
                std::fs::remove_file(&swap).expect("removed");
                std::os::unix::fs::symlink(&outside, &swap).expect("swapped for a symlink");
            })),
        };
        let err = run
            .export_tar(&mut out)
            .expect_err("a swapped entry is refused");
        assert!(err.to_string().contains("changed while exporting"), "{err}");
        assert!(err.to_string().contains("swap.txt"), "{err}");
    }

    /// The checksum is the header's bytes with its own field as spaces, written last.
    #[test]
    fn every_header_checksum_adds_up() {
        let entry = TarEntry::File {
            size: 5,
            mode: 0o644,
        };
        let block = tar_header(b"x/y", &entry, 1_756_860_007).expect("a header");
        let sum: u64 = block
            .iter()
            .enumerate()
            .map(|(i, b)| u64::from(if (148..156).contains(&i) { b' ' } else { *b }))
            .sum();
        assert_eq!(sum, parse_octal(&block[148..156]));
        assert_eq!(block[156], b'0');
        assert_eq!(&block[257..263], b"ustar\0");
    }

    /// A file past what eleven octal digits carry is refused with its path, nothing read.
    #[test]
    fn an_entry_too_big_for_ustar_is_refused() {
        let dir = bsx_test_support::ScratchDir::created("record-tar-big");
        let store = Store::at(dir.path().join("runs")).expect("a store");
        let record = record_with_id("1756860007123-big");
        let run = store.create(&record).expect("created");
        let f = std::fs::File::create(run.results().join("big.bin")).expect("created");
        f.set_len(MAX_ENTRY + 1).expect("a sparse 8 GiB length");
        let mut sink = Vec::new();
        let err = run.export_tar(&mut sink).expect_err("too big to carry");
        assert!(err.to_string().contains("big.bin"), "{err}");
    }

    /// A name no split fits, and a link target past the linkname field, are refused by path.
    #[test]
    fn an_unencodable_name_or_linkname_is_refused_with_its_path() {
        let dir = bsx_test_support::ScratchDir::created("record-tar-name");
        let store = Store::at(dir.path().join("runs")).expect("a store");
        let record = record_with_id("1756860007123-name");
        let run = store.create(&record).expect("created");
        let long = "n".repeat(120);
        std::fs::write(run.results().join(&long), b"x").expect("a file");
        let mut sink = Vec::new();
        let err = run.export_tar(&mut sink).expect_err("no split fits");
        assert!(err.to_string().contains("does not fit"), "{err}");
        assert!(err.to_string().contains(&long), "{err}");
        std::fs::remove_file(run.results().join(&long)).expect("removed");

        std::os::unix::fs::symlink("t".repeat(150), run.results().join("longlink"))
            .expect("a symlink");
        let mut sink = Vec::new();
        let err = run
            .export_tar(&mut sink)
            .expect_err("the target is too long");
        assert!(err.to_string().contains("link target"), "{err}");
        assert!(err.to_string().contains("longlink"), "{err}");
    }

    /// `Store::export` names the file by the id, replaces an earlier export, honours an exact
    /// path, refuses an unknown id, and leaves no temporary behind.
    #[test]
    fn the_store_exports_beside_and_replaces() {
        let dir = bsx_test_support::ScratchDir::created("record-tar-store");
        let store = Store::at(dir.path().join("runs")).expect("a store");
        let record = record_with_id("1756860007123-exp");
        let run = store.create(&record).expect("created");
        std::fs::write(run.stdout(), b"out").expect("stdout");
        let dest = dir.path().join("dest");
        std::fs::create_dir(&dest).expect("a dest dir");

        let written = store.export(&record.id, &dest).expect("exported");
        assert_eq!(written, dest.join("bsx-1756860007123-exp.tar"));
        assert!(!read_tar(&std::fs::read(&written).expect("read")).is_empty());
        let again = store.export(&record.id, &dest).expect("re-exported");
        assert_eq!(again, written, "replaced in place");

        let exact = dir.path().join("exact.tar");
        assert_eq!(
            store.export(&record.id, &exact).expect("to a file path"),
            exact
        );
        assert!(exact.is_file());

        let missing = store.export("1756860007999-none", &dest);
        assert!(
            matches!(missing, Err(e) if e.kind() == io::ErrorKind::NotFound),
            "an unknown id is not found"
        );
        let leftovers: Vec<_> = std::fs::read_dir(&dest)
            .expect("listed")
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "no temporary file stays");
    }
}
