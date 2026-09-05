//! Spawn, track, stop and reap the helper processes that **are** virtual machines.
//!
//! `krun_start_enter` never returns, so a VM cannot be an object a caller holds a method on: it is
//! a process, and this crate is what holds the other end of it. Both shipped binaries use this, so
//! a VM started by the GUI and a VM started by the CLI are the same kind of thing.
//!
//! - **One [`Vm`] per live helper, and `Drop` tears it down.** A supervisor that leaks a helper
//!   leaks somebody's laptop RAM, so the teardown is tied to the value rather than to a code path
//!   that an early `?` can skip.
//! - **The helper is reached through `current_exe()`, never `PATH`.** Spawning `bsx` by name would
//!   run whatever the environment resolves, which on a shared host is not necessarily this build.
//! - **The argv spelling lives here**, because this crate writes it and `crates/cli` parses it with
//!   no dependency edge between them. `the_helper_flags_match_the_parser` in `xtask` holds the two
//!   together, which is the repo's pattern for a fact stated in two places.
//!
//! **Nothing here waits for a guest to be ready.** A spawned helper is a running *process*; whether
//! the guest inside it got as far as running anything is a question only something in-guest can
//! answer, and that arrives with phase 3's agent. [`Vm::wait`] reports how the process ended, which
//! is the honest limit of what a supervisor can see today.
#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::num::{NonZeroU8, NonZeroU32};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

/// The hidden subcommand that turns this executable into a VM. Written here, parsed in
/// `crates/cli/src/vmm.rs`.
pub const HELPER_SUBCOMMAND: &str = "__vmm";

/// Set on every helper this crate spawns, and refused if it is already set.
///
/// **This stops a fork bomb**: [`Vm::spawn`] re-executes `current_exe()`, so a binary that does
/// not dispatch [`HELPER_SUBCOMMAND`] re-executes itself without bound.
const HELPER_MARKER: &str = "BSX_VMM";

/// The guest's network posture, mirrored from the CLI so the supervisor writes the helper flag
/// from one definition. [`None`](Self::None) is the default because libkrun's own default is a
/// TSI-hijacking vsock that reaches the host's network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Net {
    /// No network beyond loopback.
    #[default]
    None,
    /// libkrun's transparent socket impersonation: the guest reaches what the host can.
    Tsi,
}

impl Net {
    /// The `--net` value the helper parses. One definition, checked against the parser by
    /// `the_helper_flags_match_the_parser` like every other flag spelling.
    #[must_use]
    pub fn as_flag(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Tsi => "tsi",
        }
    }
}

/// What the guest may do to the image tree its root filesystem comes from.
///
/// [`ReadOnly`](Self::ReadOnly) is the default because one image tree boots every sandbox.
/// Enforced at the virtiofs device, and invisible to the guest: `/proc/mounts` still says `rw`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum RootFs {
    /// The guest's writes to its root fail with `EROFS`. Writable state comes from a
    /// [`mount`](VmConfig::mounts), which is the caller saying which host directory it meant.
    #[default]
    ReadOnly,
    /// The guest writes through to the shared image tree, and its edits outlive the VM.
    Writable,
}

impl RootFs {
    /// The `--rootfs` value the helper parses. One definition, checked against the parser by
    /// `the_helper_flags_match_the_parser` like every other flag spelling.
    #[must_use]
    pub fn as_flag(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::Writable => "writable",
        }
    }
}

/// A display the guest gets, and the window it is shown in: the same size, one to one.
///
/// Non-zero by type: a zero-sized display is not a display, and libkrun would report the failure
/// after the boot rather than before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Display {
    /// Width in pixels.
    pub width: NonZeroU32,
    /// Height in pixels.
    pub height: NonZeroU32,
    /// The refresh rate the guest is told, in Hz, or `None` for libkrun's own default. The guest
    /// paces its page flips to this, so it is the ceiling on how often a well-behaved guest
    /// draws; it changes nothing on the host side.
    pub refresh: Option<NonZeroU32>,
}

impl Display {
    /// A display `width` by `height` pixels.
    #[must_use]
    pub fn new(width: NonZeroU32, height: NonZeroU32) -> Self {
        Self {
            width,
            height,
            refresh: None,
        }
    }

    /// The same display, with the guest told `hz` as its refresh rate.
    #[must_use]
    pub fn with_refresh(mut self, hz: NonZeroU32) -> Self {
        self.refresh = Some(hz);
        self
    }

    /// The `WIDTHxHEIGHT` or `WIDTHxHEIGHT@HZ` spelling the helper parses.
    #[must_use]
    pub fn as_spec(self) -> String {
        match self.refresh {
            Some(hz) => format!("{}x{}@{hz}", self.width, self.height),
            None => format!("{}x{}", self.width, self.height),
        }
    }
}

/// What a caller asks for when it starts a VM.
///
/// Deliberately not a builder with a typestate: unlike libkrun's own API there is no ordering to
/// enforce here, so a struct with defaults is the honest shape and a builder would be ceremony.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VmConfig {
    /// The host directory served as the guest's root.
    pub root: PathBuf,
    /// The program to run inside the guest.
    pub exec: PathBuf,
    /// vCPUs.
    pub vcpus: NonZeroU8,
    /// Guest RAM in MiB.
    pub mem_mib: NonZeroU32,
    /// The guest working directory, if any.
    pub workdir: Option<PathBuf>,
    /// Arguments after the program name.
    pub args: Vec<OsString>,
    /// `KEY=VALUE` entries for the guest environment.
    pub env: Vec<OsString>,
    /// Extra virtiofs shares, as `(tag, host path)`.
    pub shares: Vec<(String, PathBuf)>,
    /// Host directories made read-write inside the guest, as `(guest path, host path)`: the
    /// project-directory case, where edits land on real files. The helper wraps the workload in a
    /// mount preamble, so the image needs `/bin/sh` and `mount`.
    pub mounts: Vec<(PathBuf, PathBuf)>,
    /// A vsock mapping as `(guest port, host unix socket path)`: the guest listens on the port,
    /// and a host process reaches it by connecting to the socket. One is enough for the agent
    /// channel, which is what it exists for.
    pub vsock: Option<(u32, PathBuf)>,
    /// The network posture. [`Net::None`] by default, because libkrun's default is not: it adds
    /// an implicit vsock whose TSI hijacking proxies the guest's sockets onto the host.
    pub net: Net,
    /// What the guest may do to the image tree its root comes from. [`RootFs::ReadOnly`] by
    /// default, because the tree is shared by every sandbox this host boots.
    pub rootfs: RootFs,
    /// What the guest's console (the helper's stdin and stdout) is attached to.
    pub console: Console,
    /// A display for the guest, shown in a window the VM's own process opens. `None` is a guest
    /// with no display device at all, which is every headless sandbox.
    pub display: Option<Display>,
    /// A file kept holding the display's latest frame as a binary PPM, rewritten on every change.
    /// A development knob: it is what lets a test read the pixels a guest drew.
    pub screenshot: Option<PathBuf>,
    /// A file appended with one `frame_id<TAB>nanoseconds` line per frame the display thread
    /// sees, timed from the thread's start. A development knob: what `cargo xtask bench-frames`
    /// reads to measure how many frames a second cross from the guest.
    pub frame_log: Option<PathBuf>,
    /// Whether the guest gets a virtio-snd card, backed by the host's audio server. `false` by
    /// default (rule 3): a two-way hole is opened by an explicit `--sound`, never ambient.
    pub sound: bool,
    /// A file to take everything this VM says, instead of the caller's stderr.
    ///
    /// **A VM outliving its caller must not hold the caller's stderr**, which a pipe would leave
    /// waiting for an EOF. Takes the guest console too, which [`Console::Detached`] discards.
    pub log: Option<PathBuf>,
}

/// What the guest's console is attached to: the helper's stdin feeds it and its output is the
/// helper's stdout. stderr stays inherited either way, since it carries a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Console {
    /// The caller's own stdin and stdout, which is what makes `bsx run` behave like the command
    /// it wraps.
    #[default]
    Inherited,
    /// Nothing of the caller's: input from `/dev/null`, output to [`VmConfig::log`] or discarded.
    /// For a caller with its own session channel, where an attached console would compete for the
    /// caller's stdin.
    Detached,
    /// The caller's stdin, and pipes for the console and the helper's stderr that the caller
    /// drains through [`Vm::take_stdout`] and [`Vm::take_stderr`]: how `bsx run` copies the
    /// guest's output to its own and to the run's record. [`VmConfig::log`] is not used.
    Piped,
}

impl VmConfig {
    /// A machine that serves `root` and runs `exec`, at one vCPU and 512 MiB.
    ///
    /// The defaults are small on purpose: a sandbox nobody sized should cost a laptop as little as
    /// it can while still booting, and phase 3 surfaces the knobs.
    pub fn new(root: impl Into<PathBuf>, exec: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            exec: exec.into(),
            vcpus: NonZeroU8::MIN,
            // Written as a `match` rather than `expect`: the workspace denies `expect` outside
            // tests, and a constant with no failure case should not pretend to have one.
            mem_mib: match NonZeroU32::new(512) {
                Some(m) => m,
                None => NonZeroU32::MIN,
            },
            workdir: None,
            args: Vec::new(),
            env: Vec::new(),
            shares: Vec::new(),
            mounts: Vec::new(),
            vsock: None,
            net: Net::None,
            rootfs: RootFs::ReadOnly,
            console: Console::Inherited,
            log: None,
            display: None,
            screenshot: None,
            frame_log: None,
            sound: false,
        }
    }

    /// The argument vector that re-enters this executable as this machine, named `name`.
    ///
    /// The name travels here because the helper binds the control socket; keeping it would start
    /// a VM discovery cannot see. Public so the flag spellings have one definition.
    #[must_use]
    pub fn helper_argv(&self, name: &str) -> Vec<OsString> {
        let mut argv: Vec<OsString> = vec![
            HELPER_SUBCOMMAND.into(),
            "--name".into(),
            name.into(),
            "--root".into(),
            self.root.clone().into(),
            "--vcpus".into(),
            self.vcpus.to_string().into(),
            "--mem".into(),
            self.mem_mib.to_string().into(),
            "--exec".into(),
            self.exec.clone().into(),
        ];
        if let Some(dir) = &self.workdir {
            argv.push("--workdir".into());
            argv.push(dir.clone().into());
        }
        for a in &self.args {
            argv.push("--arg".into());
            argv.push(a.clone());
        }
        for e in &self.env {
            argv.push("--env".into());
            argv.push(e.clone());
        }
        for (tag, path) in &self.shares {
            argv.push("--share".into());
            let mut spec = OsString::from(tag);
            spec.push("=");
            spec.push(path);
            argv.push(spec);
        }
        argv.push("--net".into());
        argv.push(self.net.as_flag().into());
        argv.push("--rootfs".into());
        argv.push(self.rootfs.as_flag().into());
        for (guest, host) in &self.mounts {
            argv.push("--mount".into());
            let mut spec = OsString::from(guest);
            spec.push("=");
            spec.push(host);
            argv.push(spec);
        }
        if let Some((port, path)) = &self.vsock {
            argv.push("--vsock".into());
            let mut spec = OsString::from(port.to_string());
            spec.push("=");
            spec.push(path);
            argv.push(spec);
        }
        if let Some(display) = self.display {
            argv.push("--display".into());
            argv.push(display.as_spec().into());
        }
        if let Some(path) = &self.screenshot {
            argv.push("--screenshot".into());
            argv.push(path.clone().into());
        }
        if let Some(path) = &self.frame_log {
            argv.push("--frame-log".into());
            argv.push(path.clone().into());
        }
        if self.sound {
            argv.push("--sound".into());
        }
        argv
    }
}

/// A supervisor failure, kept separate from the guest's own exit status: a guest that fails is not
/// a supervisor error, and conflating them would make "the sandbox broke" and "the code you ran
/// returned 1" the same event.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// This executable could not be located, so there is nothing to re-execute.
    HelperPath(std::io::Error),
    /// The helper process could not be spawned.
    Spawn(std::io::Error),
    /// This process is already a VM helper, so spawning would re-execute it forever. A caller that
    /// hits this has not dispatched [`HELPER_SUBCOMMAND`] before reaching for [`Vm::spawn`].
    AlreadyHelper,
    /// A name the control socket would refuse. Caught before anything is spawned, because the
    /// helper would only fail on it after the caller has lost the synchronous error path.
    Name(String),
    /// Waiting on, signalling, or reaping the helper failed.
    Wait(std::io::Error),
    /// The file a caller asked to take the helper's stderr could not be opened.
    Log(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HelperPath(e) => write!(f, "locating this executable to re-execute it: {e}"),
            Self::Spawn(e) => write!(f, "spawning the VM helper: {e}"),
            Self::AlreadyHelper => write!(
                f,
                "refusing to spawn: this process is already a VM helper ({HELPER_MARKER} is set), \
                 so re-executing it would recurse. Dispatch the `{HELPER_SUBCOMMAND}` subcommand \
                 before spawning."
            ),
            Self::Name(name) => write!(
                f,
                "{name:?} is not a usable VM name: {}, since the name becomes the control \
                 socket's filename",
                socket::name_rule()
            ),
            Self::Wait(e) => write!(f, "waiting on the VM helper: {e}"),
            Self::Log(e) => write!(f, "opening the VM's log: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::HelperPath(e) | Self::Spawn(e) | Self::Wait(e) | Self::Log(e) => Some(e),
            Self::AlreadyHelper | Self::Name(_) => None,
        }
    }
}

/// This executable, for re-execution as a VM. `current_exe()`, not a `PATH` lookup: the two
/// halves share an argv contract that only matches within one build.
pub fn helper_path() -> Result<PathBuf, Error> {
    std::env::current_exe().map_err(Error::HelperPath)
}

/// How a helper process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Exit {
    /// The process exited with this code. For a VM that got as far as running its workload, this is
    /// the **guest's** code, because libkrun exits the helper with it.
    Code(i32),
    /// The process was killed by a signal: what dropping a [`Vm`] does, what an operator's `kill`
    /// does, and what the stop path 2.7 adds will do. Carries the signal number.
    Signal(i32),
}

/// A live VM: the helper process, and the promise that dropping this reaps it.
///
/// Not `Clone`: two values naming one process would each try to tear it down, and the second would
/// be signalling a pid the kernel may already have reused.
#[derive(Debug)]
pub struct Vm {
    /// `None` once the helper has been reaped, so `Drop` does not signal a pid the kernel may have
    /// handed to somebody else. Taking the child out is what makes that unrepresentable, rather
    /// than a `reaped: bool` two code paths have to keep in step.
    child: Option<Child>,
    /// The name a caller gave this VM. The helper binds `<runtime>/bsx/<name>.sock` with it, which
    /// is what [`discover`] lists.
    name: String,
}

impl Vm {
    /// Spawns a helper process for `cfg`, re-executing this binary through [`helper_path`]. The
    /// name becomes its control socket, so [`discover`] can list it. The helper inherits stdio,
    /// so a VM's output is the caller's.
    pub fn spawn(name: impl Into<String>, cfg: &VmConfig) -> Result<Self, Error> {
        let name = name.into();
        let child = helper_command(&name, cfg)?.spawn().map_err(Error::Spawn)?;
        Ok(Self {
            child: Some(child),
            name,
        })
    }

    /// The console pipe of a [`Console::Piped`] VM, once; `None` for any other console.
    pub fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.child.as_mut().and_then(|c| c.stdout.take())
    }

    /// The helper's stderr pipe of a [`Console::Piped`] VM, once; `None` for any other console.
    pub fn take_stderr(&mut self) -> Option<std::process::ChildStderr> {
        self.child.as_mut().and_then(|c| c.stderr.take())
    }

    /// The name this VM was given.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The helper's process id, which is the VM's: there is no other process to point at.
    ///
    /// Zero once the helper has been reaped, which no live process has, so a stale read is
    /// recognisable rather than pointing at whoever holds that pid now.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.child.as_ref().map_or(0, Child::id)
    }

    /// Waits for the VM to end and reports how.
    ///
    /// Consumes `self`, because after this there is no process left to supervise and a `Vm` that
    /// outlived its helper would let a caller signal a reused pid.
    pub fn wait(mut self) -> Result<Exit, Error> {
        let Some(mut child) = self.child.take() else {
            // Only reachable if a future path took the child without consuming `self`; reporting
            // it beats inventing an exit status for a process nobody is holding.
            return Err(Error::Wait(std::io::Error::other(
                "the helper was already reaped",
            )));
        };
        let status = child.wait().map_err(Error::Wait)?;
        Ok(exit_of(&status))
    }

    /// Stops the VM and reaps it, reporting how it ended.
    ///
    /// **A power cut, not a shutdown**: no exit handler runs, libkrun's graceful surface being
    /// efi-only. SIGKILL, which with no handler is indistinguishable from SIGTERM.
    pub fn stop(mut self) -> Result<Exit, Error> {
        let Some(mut child) = self.child.take() else {
            return Err(Error::Wait(std::io::Error::other(
                "the helper was already reaped",
            )));
        };
        // `ESRCH` is the VM ending on its own, a race no caller can close; `wait` still reports.
        let _ = child.kill();
        let status = child.wait().map_err(Error::Wait)?;
        Ok(exit_of(&status))
    }

    /// Gives up ownership of the helper and returns its process id: the VM keeps running.
    ///
    /// **How a VM outlives the command that started it**, and the one exception to the rule that a
    /// dropped [`Vm`] cannot strand a helper. It stays reachable by name through [`discover`].
    pub fn detach(mut self) -> Result<u32, Error> {
        let Some(child) = self.child.take() else {
            return Err(Error::Wait(std::io::Error::other(
                "the helper was already reaped",
            )));
        };
        Ok(child.id())
    }

    /// Whether the helper has already ended, without blocking. `None` while it is still running.
    ///
    /// Reaps on the way past when it has, so a caller polling this does not leave a zombie.
    pub fn try_wait(&mut self) -> Result<Option<Exit>, Error> {
        let Some(child) = self.child.as_mut() else {
            return Ok(None);
        };
        match child.try_wait().map_err(Error::Wait)? {
            Some(status) => {
                // Reaped: drop the handle so `Drop` does not signal the pid again.
                self.child = None;
                Ok(Some(exit_of(&status)))
            }
            None => Ok(None),
        }
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        // `kill` then `wait`, or a killed child is a zombie in a long-lived process. Both results
        // are discarded: an `ESRCH` is a child that already exited, and a panic here would abort.
        let Some(child) = self.child.as_mut() else {
            return;
        };
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// The `Command` that re-executes this binary as `cfg`'s machine.
///
/// Split from [`Vm::spawn`] so the "this executable, never `PATH`" property is testable without
/// racing a child that exits before `/proc` can be read.
fn helper_command(name: &str, cfg: &VmConfig) -> Result<Command, Error> {
    helper_command_unless_helper(name, cfg, std::env::var_os(HELPER_MARKER).is_some())
}

/// The body of [`helper_command`] with the environment read lifted out, so a test can drive the
/// recursion guard both ways without setting a variable this crate cannot set.
fn helper_command_unless_helper(
    name: &str,
    cfg: &VmConfig,
    already_helper: bool,
) -> Result<Command, Error> {
    if already_helper {
        return Err(Error::AlreadyHelper);
    }
    if !socket::valid_name(name) {
        return Err(Error::Name(name.to_string()));
    }
    // Opened once and duplicated, because the console and the helper's stderr are two streams of
    // one VM's account of itself and interleaving them in one file is the point.
    let log = match &cfg.log {
        // 0600 and truncating: one boot, one log, and not a file anyone else can read.
        Some(path) => Some(
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)
                .map_err(Error::Log)?,
        ),
        None => None,
    };
    let console_out = match (cfg.console, &log) {
        (Console::Inherited, _) => Stdio::inherit(),
        (Console::Piped, _) => Stdio::piped(),
        (Console::Detached, Some(file)) => file.try_clone().map_err(Error::Log)?.into(),
        (Console::Detached, None) => Stdio::null(),
    };
    let mut cmd = Command::new(helper_path()?);
    #[cfg(target_os = "macos")]
    if let Some(value) = kernel_payload_path() {
        cmd.env("DYLD_FALLBACK_LIBRARY_PATH", value);
    }
    cmd.args(cfg.helper_argv(name))
        .env(HELPER_MARKER, "1")
        .stdin(match cfg.console {
            Console::Inherited | Console::Piped => Stdio::inherit(),
            Console::Detached => Stdio::null(),
        })
        .stdout(console_out)
        .stderr(match (cfg.console, log) {
            (Console::Piped, _) => Stdio::piped(),
            (_, Some(file)) => file.into(),
            (_, None) => Stdio::inherit(),
        });
    Ok(cmd)
}

/// What the helper needs on `DYLD_FALLBACK_LIBRARY_PATH` to load libkrun's kernel payload.
///
/// libkrun loads it with `dlopen("libkrunfw.5.dylib")`, a bare name the loader resolves against its
/// own paths, which on macOS do not include the prefix a package manager installs to. `DYLD_*` is
/// read at `exec`, so the helper cannot set this for itself and it has to arrive on the spawn.
///
/// The operator's own value keeps precedence, and dyld's default list is put back after it, since
/// setting the variable at all replaces it.
#[cfg(target_os = "macos")]
fn kernel_payload_path() -> Option<OsString> {
    let dir = bsx_krun::KRUNFW_DIR?;
    let mut value = std::env::var_os("DYLD_FALLBACK_LIBRARY_PATH").unwrap_or_default();
    if !value.is_empty() {
        value.push(":");
    }
    value.push(dir);
    value.push(":/usr/local/lib:/usr/lib");
    Some(value)
}

/// Reads an `ExitStatus` into [`Exit`]. Split out so the signal path is testable without arranging
/// a real signalled child in a unit test.
fn exit_of(status: &std::process::ExitStatus) -> Exit {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(code), _) => Exit::Code(code),
        (None, Some(sig)) => Exit::Signal(sig),
        // Neither code nor signal is something this code does not model; not a zero exit.
        (None, None) => Exit::Signal(0),
    }
}

/// Where a VM's control socket lives, and how a caller tells a live one from a leftover.
///
/// There is no daemon: the sockets **are** the registry. One outliving its helper is expected, so
/// [`socket::is_live`] connects rather than checking presence.
pub mod socket {
    use std::io;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    /// The directory holding one socket per live VM.
    const DIR_NAME: &str = "bsx";

    /// Longest a VM name may be. Not a taste limit: the socket path goes into `sockaddr_un.sun_path`,
    /// which is 108 bytes on Linux and 104 on macOS, and an over-long path fails at `bind` with a
    /// message about an address rather than about the name that caused it.
    const MAX_NAME: usize = 64;

    /// The runtime directory, created `0700` if absent.
    ///
    /// `$XDG_RUNTIME_DIR`, else `$TMPDIR` (per-user on macOS), else `/tmp`, which is **shared**
    /// and is why the mode and owner are checked rather than assumed.
    pub fn runtime_dir() -> io::Result<PathBuf> {
        use std::os::unix::fs::DirBuilderExt;
        let base = std::env::var_os("XDG_RUNTIME_DIR")
            .or_else(|| std::env::var_os("TMPDIR"))
            .map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
        let dir = base.join(DIR_NAME);
        // Created at its final mode: create-then-chmod leaves a window at the caller's umask.
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        builder.mode(0o700);
        builder.create(&dir)?;
        require_private(&dir)?;
        Ok(dir)
    }

    /// Refuses a runtime directory anyone else can write or own: under `/tmp` another user could
    /// create `bsx/` first. Checked on every resolution, since the directory outlives its maker.
    fn require_private(dir: &Path) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(dir)?;
        if meta.uid() != real_uid() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} is owned by uid {}, not by you",
                    dir.display(),
                    meta.uid()
                ),
            ));
        }
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} is mode {:04o}; a control-socket directory must not be group- or \
                     world-accessible",
                    dir.display(),
                    meta.permissions().mode() & 0o7777
                ),
            ));
        }
        Ok(())
    }

    /// This process's real uid. Through `rustix` rather than `/proc/self/status`, which is a
    /// Linux-only path and left every macOS check failing closed against a uid nobody has. The
    /// crate keeps its `#![forbid(unsafe_code)]`, because the `unsafe` is the dependency's.
    fn real_uid() -> u32 {
        rustix::process::getuid().as_raw()
    }

    /// The rule a usable name satisfies, spelled by the function every refusal quotes.
    ///
    /// Public so a caller refusing a name at the flag the operator typed states the same rule
    /// this module enforces, rather than keeping a second copy of the alphabet and the length.
    #[must_use]
    pub fn name_rule() -> String {
        format!("1..={MAX_NAME} characters of [A-Za-z0-9_-]")
    }

    /// Whether `name` may become a socket file.
    ///
    /// **A VM name reaches the filesystem**, so this is an allow-list, not a filter.
    pub fn valid_name(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= MAX_NAME
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    }

    /// The socket path for `name`, or an error naming why the name was refused.
    pub fn path_for(name: &str) -> io::Result<PathBuf> {
        if !valid_name(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{name:?} is not a usable VM name: {}, since the name becomes a filename",
                    name_rule()
                ),
            ));
        }
        Ok(runtime_dir()?.join(format!("{name}.sock")))
    }

    /// The control socket path for `name` under the runtime directory a process with
    /// `XDG_RUNTIME_DIR=base` has, for a caller that already holds that directory and does not
    /// want this process's own. Nothing is created or checked.
    pub fn path_in(base: &Path, name: &str) -> io::Result<PathBuf> {
        if !valid_name(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{name:?} is not a usable VM name: {}, since the name becomes a filename",
                    name_rule()
                ),
            ));
        }
        Ok(base.join(DIR_NAME).join(format!("{name}.sock")))
    }

    /// The agent-channel socket path for `name`, beside its control socket so a process that did
    /// not start the VM finds both. libkrun binds it, so presence says configured, not answering.
    pub fn agent_path_for(name: &str) -> io::Result<PathBuf> {
        // Through `path_for` for the name check, so an unusable name is refused with the same
        // message here as there rather than becoming a second rule.
        let control = path_for(name)?;
        let dir = control
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        Ok(agent_in(&dir, name))
    }

    /// The agent socket for `name` inside `dir`, for a caller that already has the directory:
    /// [`agent_path_for`] resolves the runtime directory and this does not.
    pub(crate) fn agent_in(dir: &Path, name: &str) -> PathBuf {
        dir.join(format!("{name}{AGENT_SUFFIX}"))
    }

    /// Where a detached VM's stderr goes, beside its sockets: it can neither write the caller's
    /// terminal nor hold its pipe, and a VM that came up wrong still has to say why.
    pub fn log_path_for(name: &str) -> io::Result<PathBuf> {
        let control = path_for(name)?;
        let dir = control
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        Ok(log_in(&dir, name))
    }

    /// [`log_path_for`] against a directory already in hand.
    pub(crate) fn log_in(dir: &Path, name: &str) -> PathBuf {
        dir.join(format!("{name}{LOG_SUFFIX}"))
    }

    /// What a detached VM's log is named. Neither this nor [`AGENT_SUFFIX`] is `.sock`, so a scan
    /// for VMs counts neither.
    const LOG_SUFFIX: &str = ".log";

    /// What an agent-channel socket is named, given a VM name. Beside [`super::discover`]'s
    /// `SUFFIX`, and different from it, so a scan for VMs never counts a channel as one.
    const AGENT_SUFFIX: &str = ".agent";

    /// Whether something is listening on `path` right now. Connects rather than checking for the
    /// file, which every ended helper leaves behind.
    #[must_use]
    pub fn is_live(path: &Path) -> bool {
        std::os::unix::net::UnixStream::connect(path).is_ok()
    }

    /// Removes `path` if nothing is listening on it. Returns whether it removed anything.
    ///
    /// A helper binding between the check and the unlink would lose its socket, so callers run
    /// this only on a name they own.
    pub fn clear_if_stale(path: &Path) -> io::Result<bool> {
        if !path.exists() || is_live(path) {
            return Ok(false);
        }
        match std::fs::remove_file(path) {
            Ok(()) => Ok(true),
            // Somebody else cleared it first, which is the outcome this wanted anyway.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }
}

/// The request/response grammar a VM's control socket speaks, and the client half of it.
///
/// - **One request, one response, then close.** No session is state to leak.
/// - **The identity is the socket, not a pid**, so no `kill` on a number the kernel may have reused.
/// - **Lines of ASCII tokens, carrying no path**, which can contain a newline.
pub mod control {
    use std::io::{self, BufRead, BufReader, Read, Write};
    use std::num::{NonZeroU8, NonZeroU32};
    use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::time::Duration;

    use super::{Net, RootFs};

    /// The grammar's version, reported in every [`Request::Info`] answer so a client meeting an
    /// older or newer VM can say so instead of misreading its fields. 2 added [`Request::Display`],
    /// 3 put the damage rectangle in each present record, 4 added [`Request::Input`].
    pub const PROTOCOL_VERSION: u8 = 4;

    /// The slot number a present record carries when the scanout was reconfigured instead: the
    /// client's mapping is of an allocation that is no longer the scanout's.
    pub const RECONFIGURED_SLOT: u32 = u32::MAX;

    /// How long a caller waits on a VM's control socket. A VM answers from a thread that does
    /// nothing else, so anything slower than this is a VM that has stopped answering, and `ls`
    /// must not hang on one.
    const IO_TIMEOUT: Duration = Duration::from_secs(2);

    /// Longest answer a client will read. The reply is a fixed handful of short lines; the cap is
    /// what stops a socket that is not a VM (or a VM gone wrong) from being read forever.
    const MAX_REPLY: u64 = 4096;

    /// What a caller can ask a live VM.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum Request {
        /// Report the machine's shape and posture.
        Info,
        /// Stop the VM. It answers first and dies after, so a caller learns the request was
        /// accepted rather than inferring it from a closed connection.
        Stop,
        /// Lease the display: the answer carries the memfd holding the scanout's frame slots and
        /// their layout, and the connection then streams one record per present until the caller
        /// closes it. Refused while no scanout is configured, and by a VM with no display.
        Display,
        /// Feed the keyboard and pointer: after `ok`, the connection carries `kbd|ptr TYPE CODE
        /// VALUE` lines, one event each, until the caller closes it, and whatever those lines left
        /// down is released then. Refused by a VM with no display, which has no devices.
        Input,
    }

    impl Request {
        /// The word this request travels as.
        #[must_use]
        pub fn as_word(self) -> &'static str {
            match self {
                Self::Info => "info",
                Self::Stop => "stop",
                Self::Display => "display",
                Self::Input => "input",
            }
        }

        /// The request `word` names, or `None` for one this build does not know.
        #[must_use]
        pub fn from_word(word: &str) -> Option<Self> {
            match word {
                "info" => Some(Self::Info),
                "stop" => Some(Self::Stop),
                "display" => Some(Self::Display),
                "input" => Some(Self::Input),
                _ => None,
            }
        }
    }

    /// Whether a VM carries an agent channel, which is what decides if it can be `exec`ed into.
    ///
    /// Reports what the VM was **configured** with, not whether the guest is answering: only a
    /// completed handshake proves that, and it is the caller doing the exec that finds out.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    #[non_exhaustive]
    pub enum Channel {
        /// No channel was mapped: this VM runs one workload and nothing can talk to it.
        #[default]
        Absent,
        /// A vsock port is mapped onto a socket beside this VM's, so a caller can reach the agent.
        Present,
    }

    impl Channel {
        /// The word this travels as.
        #[must_use]
        pub fn as_word(self) -> &'static str {
            match self {
                Self::Absent => "absent",
                Self::Present => "present",
            }
        }
    }

    /// What a VM reports about itself.
    ///
    /// Public fields, because this is data the code hands back: a caller moves what it needs out,
    /// and a later measurement arrives as another field.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub struct Info {
        /// The helper's process id, which is the VM's.
        pub pid: u32,
        /// vCPUs the machine was given.
        pub vcpus: NonZeroU8,
        /// Guest RAM in MiB.
        pub mem_mib: NonZeroU32,
        /// The network posture.
        pub net: Net,
        /// What the guest may do to the image tree it booted from.
        pub rootfs: RootFs,
        /// Whether an agent channel was mapped.
        pub channel: Channel,
    }

    impl Info {
        /// An answer for a VM with this shape. A constructor rather than a struct literal because
        /// the type is `#[non_exhaustive]`, which is what lets a field be added without breaking
        /// the caller that reads one.
        #[must_use]
        pub fn new(
            pid: u32,
            vcpus: NonZeroU8,
            mem_mib: NonZeroU32,
            net: Net,
            rootfs: RootFs,
            channel: Channel,
        ) -> Self {
            Self {
                pid,
                vcpus,
                mem_mib,
                net,
                rootfs,
                channel,
            }
        }

        /// Writes this as the body of an `ok` reply, one `key value` line each.
        fn write_body(&self, out: &mut impl Write) -> io::Result<()> {
            writeln!(out, "proto {PROTOCOL_VERSION}")?;
            writeln!(out, "pid {}", self.pid)?;
            writeln!(out, "vcpus {}", self.vcpus)?;
            writeln!(out, "mem_mib {}", self.mem_mib)?;
            writeln!(out, "net {}", self.net.as_flag())?;
            writeln!(out, "rootfs {}", self.rootfs.as_flag())?;
            writeln!(out, "channel {}", self.channel.as_word())
        }

        /// Reads back what [`write_body`](Self::write_body) wrote; `pub(crate)` so the round trip
        /// is testable. Every field is required: defaults would report a machine nobody configured.
        pub(crate) fn parse_body(text: &str) -> Result<Self, Error> {
            let mut fields: Vec<(&str, &str)> = Vec::new();
            for line in text.lines().filter(|l| !l.is_empty()) {
                let (key, value) = line
                    .split_once(' ')
                    .ok_or_else(|| Error::Protocol(format!("{line:?} is not `key value`")))?;
                fields.push((key, value));
            }
            let get = |key: &str| -> Result<&str, Error> {
                fields
                    .iter()
                    .find(|(k, _)| *k == key)
                    .map(|(_, v)| *v)
                    .ok_or_else(|| Error::Protocol(format!("the answer carries no {key}")))
            };
            let number = |key: &str| -> Result<u32, Error> {
                get(key)?
                    .parse()
                    .map_err(|_| Error::Protocol(format!("{key} is not a number")))
            };
            let proto = number("proto")?;
            if proto != u32::from(PROTOCOL_VERSION) {
                return Err(Error::Protocol(format!(
                    "the VM speaks control protocol {proto}, this build speaks {PROTOCOL_VERSION}"
                )));
            }
            let vcpus = u8::try_from(number("vcpus")?)
                .ok()
                .and_then(NonZeroU8::new)
                .ok_or_else(|| Error::Protocol("vcpus is not a machine".to_string()))?;
            let mem_mib = NonZeroU32::new(number("mem_mib")?)
                .ok_or_else(|| Error::Protocol("mem_mib is not a machine".to_string()))?;
            let net = match get("net")? {
                w if w == Net::None.as_flag() => Net::None,
                w if w == Net::Tsi.as_flag() => Net::Tsi,
                w => return Err(Error::Protocol(format!("unknown net posture {w:?}"))),
            };
            let rootfs = match get("rootfs")? {
                w if w == RootFs::ReadOnly.as_flag() => RootFs::ReadOnly,
                w if w == RootFs::Writable.as_flag() => RootFs::Writable,
                w => return Err(Error::Protocol(format!("unknown root posture {w:?}"))),
            };
            let channel = match get("channel")? {
                w if w == Channel::Absent.as_word() => Channel::Absent,
                w if w == Channel::Present.as_word() => Channel::Present,
                w => return Err(Error::Protocol(format!("unknown channel state {w:?}"))),
            };
            Ok(Self::new(
                number("pid")?,
                vcpus,
                mem_mib,
                net,
                rootfs,
                channel,
            ))
        }
    }

    /// How a leased display's memory is laid out: `slots` regions of `slot_bytes`, each a `width`
    /// by `height` frame in the virtio-gpu `format` at `stride` bytes a row. The numbers only; a
    /// client decides what to do with a format it does not know.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub struct Scanout {
        /// Frame width in pixels.
        pub width: u32,
        /// Frame height in pixels.
        pub height: u32,
        /// The `KRUN_DISPLAY_FORMAT_*` number.
        pub format: u32,
        /// Bytes per row.
        pub stride: u32,
        /// Regions in the memfd.
        pub slots: u32,
        /// Bytes per region.
        pub slot_bytes: u64,
        /// Which allocation this is; a reconfigure to a new size makes a new one.
        pub generation: u32,
    }

    impl Scanout {
        /// A layout with these numbers.
        #[must_use]
        pub fn new(
            width: u32,
            height: u32,
            format: u32,
            stride: u32,
            slots: u32,
            slot_bytes: u64,
            generation: u32,
        ) -> Self {
            Self {
                width,
                height,
                format,
                stride,
                slots,
                slot_bytes,
                generation,
            }
        }

        pub(crate) fn body(&self) -> String {
            format!(
                "proto {PROTOCOL_VERSION}\nwidth {}\nheight {}\nformat {}\nstride {}\nslots {}\n\
                 slot_bytes {}\ngeneration {}\n",
                self.width,
                self.height,
                self.format,
                self.stride,
                self.slots,
                self.slot_bytes,
                self.generation
            )
        }

        pub(crate) fn parse_body(text: &str) -> Result<Self, Error> {
            let fields = fields_of(text)?;
            let number = |key: &str| -> Result<u64, Error> {
                fields
                    .iter()
                    .find(|(k, _)| *k == key)
                    .map(|(_, v)| *v)
                    .ok_or_else(|| Error::Protocol(format!("the answer carries no {key}")))?
                    .parse()
                    .map_err(|_| Error::Protocol(format!("{key} is not a number")))
            };
            let small = |key: &str| -> Result<u32, Error> {
                u32::try_from(number(key)?)
                    .map_err(|_| Error::Protocol(format!("{key} does not fit")))
            };
            if small("proto")? != u32::from(PROTOCOL_VERSION) {
                return Err(Error::Protocol(format!(
                    "the VM speaks control protocol {}, this build speaks {PROTOCOL_VERSION}",
                    number("proto")?
                )));
            }
            Ok(Self::new(
                small("width")?,
                small("height")?,
                small("format")?,
                small("stride")?,
                small("slots")?,
                number("slot_bytes")?,
                small("generation")?,
            ))
        }
    }

    /// The `key value` lines of an answer body.
    fn fields_of(text: &str) -> Result<Vec<(&str, &str)>, Error> {
        text.lines()
            .filter(|l| !l.is_empty())
            .map(|line| {
                line.split_once(' ')
                    .ok_or_else(|| Error::Protocol(format!("{line:?} is not `key value`")))
            })
            .collect()
    }

    /// A control exchange that did not produce an answer.
    #[derive(Debug)]
    #[non_exhaustive]
    pub enum Error {
        /// The socket could not be reached, or the exchange failed on it. A connection refused
        /// here is the ordinary "that VM has ended", not a broken machine.
        Io(io::Error),
        /// The VM answered something this build cannot read.
        Protocol(String),
        /// The VM refused the request and said why.
        Refused(String),
        /// The VM has no scanout configured yet, so a display lease is worth asking for again.
        /// Separate from [`Error::Refused`] because it is a wait, not a failure.
        NotReady,
    }

    /// The refusal a VM sends while its guest has not configured a scanout, named by both ends so
    /// the retry is a variant rather than a reader matching on the words.
    pub const NOT_READY: &str = "no scanout is configured yet; ask again";

    /// The error a non-`ok` status line means: `err <why>`, with [`NOT_READY`] as its own variant.
    fn refusal(status: &str) -> Error {
        match status.strip_prefix("err ") {
            Some(NOT_READY) => Error::NotReady,
            Some(why) => Error::Refused(why.to_string()),
            None => Error::Protocol(format!("{status:?} is neither ok nor err")),
        }
    }

    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Io(e) => write!(f, "the control socket: {e}"),
                Self::Protocol(m) => write!(f, "the VM answered something unreadable: {m}"),
                Self::Refused(m) => write!(f, "the VM refused: {m}"),
                Self::NotReady => write!(f, "the VM has no scanout configured yet"),
            }
        }
    }

    impl std::error::Error for Error {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Io(e) => Some(e),
                _ => None,
            }
        }
    }

    impl From<io::Error> for Error {
        fn from(e: io::Error) -> Self {
            Self::Io(e)
        }
    }

    /// Reads one request from a connected caller. `Ok(None)` is a word this build does not know,
    /// which the server answers rather than treating as a failure.
    ///
    /// The server half, called by the helper that **is** the VM.
    pub fn read_request(stream: impl io::Read) -> io::Result<Option<Request>> {
        let mut line = String::new();
        BufReader::new(stream.take(MAX_REPLY)).read_line(&mut line)?;
        Ok(Request::from_word(line.trim_end()))
    }

    /// Writes the answer to `request`, or the refusal for a word this build does not know.
    ///
    /// Answering [`Request::Stop`] stops nothing: the helper replies, then ends its own process.
    pub fn write_answer(
        out: &mut impl Write,
        request: Option<Request>,
        info: &Info,
    ) -> io::Result<()> {
        match request {
            Some(Request::Info) => {
                writeln!(out, "ok")?;
                info.write_body(out)?;
            }
            Some(Request::Stop) => writeln!(out, "ok")?,
            // The display answer carries an fd a plain writer cannot send, and input needs the
            // same devices: the server answers both itself when it has them.
            Some(Request::Display | Request::Input) => {
                writeln!(out, "err this VM has no display")?;
            }
            None => writeln!(
                out,
                "err unrecognized request; this VM speaks {}, {}, {} and {}",
                Request::Info.as_word(),
                Request::Stop.as_word(),
                Request::Display.as_word(),
                Request::Input.as_word()
            )?,
        }
        out.flush()
    }

    /// Writes an `err` answer saying `why`.
    pub fn write_refusal(out: &mut impl Write, why: &str) -> io::Result<()> {
        writeln!(out, "err {why}")?;
        out.flush()
    }

    /// Answers [`Request::Display`]: the `ok` line, the layout, a blank line, and the memfd as
    /// the message's ancillary data, in one `sendmsg` so the fd arrives with the first byte. The
    /// caller then streams present records on the same connection with [`write_present`].
    pub fn write_display_answer(
        stream: &UnixStream,
        memfd: BorrowedFd<'_>,
        scanout: &Scanout,
    ) -> io::Result<()> {
        let text = format!("ok\n{}\n", scanout.body());
        let mut space = [std::mem::MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = rustix::net::SendAncillaryBuffer::new(&mut space);
        let fds = [memfd];
        control.push(rustix::net::SendAncillaryMessage::ScmRights(&fds));
        let sent = rustix::net::sendmsg(
            stream.as_fd(),
            &[io::IoSlice::new(text.as_bytes())],
            &mut control,
            rustix::net::SendFlags::empty(),
        )
        .map_err(io::Error::from)?;
        if sent != text.len() {
            return Err(io::Error::other("the display answer was sent in part"));
        }
        Ok(())
    }

    /// The part of a frame that changed since the one before it, in pixels.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub struct Damage {
        /// Left edge.
        pub x: u32,
        /// Top edge.
        pub y: u32,
        /// Width.
        pub width: u32,
        /// Height.
        pub height: u32,
    }

    impl Damage {
        /// A rectangle at `(x, y)` of `width` by `height`.
        #[must_use]
        pub fn new(x: u32, y: u32, width: u32, height: u32) -> Self {
            Self {
                x,
                y,
                width,
                height,
            }
        }
    }

    /// Bytes in one present record: six `u32`s.
    const RECORD_LEN: usize = 24;

    /// Writes one present record: `frame_id`, `slot`, then the damage's `x`, `y`, `width` and
    /// `height`, each four bytes little-endian.
    pub fn write_present(
        out: &mut impl Write,
        frame_id: u32,
        slot: u32,
        damage: Damage,
    ) -> io::Result<()> {
        let mut record = [0u8; RECORD_LEN];
        for (at, word) in [
            frame_id,
            slot,
            damage.x,
            damage.y,
            damage.width,
            damage.height,
        ]
        .into_iter()
        .enumerate()
        {
            record[at * 4..at * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out.write_all(&record)
    }

    /// What a leased display reports next.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum Event {
        /// Frame `frame_id` is in slot `slot` of the mapped memory.
        Presented {
            /// The id it was presented under.
            frame_id: u32,
            /// The region it occupies.
            slot: u32,
            /// The part that changed since the frame before it.
            damage: Damage,
        },
        /// The scanout was reconfigured to a new size: the mapping is stale, and the VM will send
        /// nothing more on this lease. Ask again for a new one.
        Reconfigured,
    }

    /// A leased display: the memfd and its layout, and the connection the present records come
    /// down. Dropping it ends the lease.
    #[derive(Debug)]
    pub struct DisplayLease {
        memfd: Option<OwnedFd>,
        scanout: Scanout,
        stream: UnixStream,
        /// Record bytes that arrived with the answer.
        pending: Vec<u8>,
    }

    impl DisplayLease {
        /// How the memfd is laid out.
        #[must_use]
        pub fn scanout(&self) -> Scanout {
            self.scanout
        }

        /// The memfd, once: it is the caller's to map.
        pub fn take_memfd(&mut self) -> Option<OwnedFd> {
            self.memfd.take()
        }

        /// A handle another thread ends this lease with, since [`next_event`](Self::next_event)
        /// blocks for as long as the VM has nothing to say.
        pub fn stop_handle(&self) -> io::Result<LeaseStop> {
            Ok(LeaseStop {
                stream: self.stream.try_clone()?,
            })
        }

        /// Waits for the next record. `Io` with `UnexpectedEof` is the VM closing the lease,
        /// which is what a VM ending does.
        pub fn next_event(&mut self) -> Result<Event, Error> {
            let mut record = [0u8; RECORD_LEN];
            let have = self.pending.len().min(RECORD_LEN);
            record[..have].copy_from_slice(&self.pending[..have]);
            self.pending.drain(..have);
            self.stream.read_exact(&mut record[have..])?;
            let word = |at: usize| {
                u32::from_le_bytes([
                    record[at * 4],
                    record[at * 4 + 1],
                    record[at * 4 + 2],
                    record[at * 4 + 3],
                ])
            };
            let (frame_id, slot) = (word(0), word(1));
            Ok(if slot == RECONFIGURED_SLOT {
                Event::Reconfigured
            } else {
                Event::Presented {
                    frame_id,
                    slot,
                    damage: Damage::new(word(2), word(3), word(4), word(5)),
                }
            })
        }
    }

    /// Ends a [`DisplayLease`] from another thread: shutting the connection makes the blocked
    /// read return, and the VM drops its side.
    #[derive(Debug)]
    pub struct LeaseStop {
        stream: UnixStream,
    }

    impl LeaseStop {
        /// Ends the lease.
        pub fn stop(&self) {
            let _ = self.stream.shutdown(std::net::Shutdown::Both);
        }
    }

    /// Leases the display of the VM listening on `socket`: connects, asks, and reads the answer
    /// with its fd. The lease's reads have no timeout, because a present may be any time away.
    pub fn display(socket: &Path) -> Result<DisplayLease, Error> {
        let stream = UnixStream::connect(socket)?;
        lease_on(stream)
    }

    /// The client half of a display lease on an already connected `stream`.
    pub(crate) fn lease_on(mut stream: UnixStream) -> Result<DisplayLease, Error> {
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        writeln!(stream, "{}", Request::Display.as_word())?;
        stream.flush()?;

        // The answer text ends at a blank line; whatever follows it is the first records.
        let mut buf = vec![0u8; 4096];
        let mut space = [std::mem::MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = rustix::net::RecvAncillaryBuffer::new(&mut space);
        let got = rustix::net::recvmsg(
            stream.as_fd(),
            &mut [io::IoSliceMut::new(&mut buf)],
            &mut control,
            rustix::net::RecvFlags::empty(),
        )
        .map_err(io::Error::from)?;
        let mut memfd = None;
        for message in control.drain() {
            if let rustix::net::RecvAncillaryMessage::ScmRights(fds) = message {
                for fd in fds {
                    memfd = Some(fd);
                }
            }
        }
        // An `ok` answer ends at a blank line; a refusal is its one line. Read until whichever
        // this is has fully arrived.
        let mut text = buf[..got.bytes].to_vec();
        let complete = |text: &[u8]| {
            text.windows(2).any(|w| w == b"\n\n")
                || (text.starts_with(b"err") && text.contains(&b'\n'))
        };
        while !complete(&text) {
            if text.len() >= MAX_REPLY as usize {
                return Err(Error::Protocol(
                    "the display answer never ended".to_string(),
                ));
            }
            let mut more = [0u8; 256];
            let n = stream.read(&mut more)?;
            if n == 0 {
                return Err(Error::Io(io::Error::from(io::ErrorKind::UnexpectedEof)));
            }
            text.extend_from_slice(&more[..n]);
        }
        let end = text
            .windows(2)
            .position(|w| w == b"\n\n")
            .map_or(text.len(), |at| at + 2);
        let pending = text.split_off(end);
        let answer = String::from_utf8_lossy(&text).into_owned();
        let (status, body) = answer.split_once('\n').unwrap_or((answer.trim_end(), ""));
        match status {
            "ok" => {}
            other => {
                return Err(refusal(other));
            }
        }
        let scanout = Scanout::parse_body(body)?;
        let Some(memfd) = memfd else {
            return Err(Error::Protocol(
                "the display answer carried no memfd".to_string(),
            ));
        };
        // The lease blocks for frames, so the handshake's deadline is cleared here, and only
        // tried: macOS refuses `SO_RCVTIMEO` with `EINVAL` once the peer has closed, and a peer
        // that closed sends no more frames, so a socket left with the deadline reads EOF rather
        // than waiting on it.
        let _ = stream.set_read_timeout(None);
        Ok(DisplayLease {
            memfd: Some(memfd),
            scanout,
            stream,
            pending,
        })
    }

    /// Asks the VM listening on `socket` for its shape.
    pub fn info(socket: &Path) -> Result<Info, Error> {
        Info::parse_body(&exchange(socket, Request::Info)?)
    }

    /// Asks the VM listening on `socket` to stop, and returns once it has accepted.
    ///
    /// **A power cut, not a shutdown**, as [`Vm::stop`](super::Vm::stop). Returning means the
    /// request was taken, not that the process is gone.
    pub fn stop(socket: &Path) -> Result<(), Error> {
        exchange(socket, Request::Stop).map(drop)
    }

    /// An open input session: the connection the lines go down. Dropping it ends the session,
    /// and the VM then releases whatever the lines left down.
    #[derive(Debug)]
    pub struct InputSession {
        stream: UnixStream,
    }

    impl InputSession {
        /// Sends one `kbd|ptr TYPE CODE VALUE` line. The grammar is `bsx-input`'s; this carries
        /// the text.
        pub fn send(&mut self, line: &str) -> io::Result<()> {
            writeln!(self.stream, "{line}")
        }
    }

    /// Opens an input session on the VM listening on `socket`: connects, asks, and reads the
    /// `ok`. The refusal is a VM with no display.
    pub fn input(socket: &Path) -> Result<InputSession, Error> {
        let stream = UnixStream::connect(socket)?;
        input_on(stream)
    }

    /// The client half of an input session on an already connected `stream`.
    pub(crate) fn input_on(mut stream: UnixStream) -> Result<InputSession, Error> {
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        writeln!(stream, "{}", Request::Input.as_word())?;
        stream.flush()?;
        // One status line and nothing after it from the VM, so an unbuffered read loses nothing.
        let mut status = String::new();
        BufReader::new((&stream).take(MAX_REPLY)).read_line(&mut status)?;
        match status.trim_end() {
            "ok" => Ok(InputSession { stream }),
            other => Err(refusal(other)),
        }
    }

    /// One request, one answer: connect, ask, read to EOF, and split the status line off the body.
    fn exchange(socket: &Path, request: Request) -> Result<String, Error> {
        let mut stream = UnixStream::connect(socket)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        writeln!(stream, "{}", request.as_word())?;
        stream.flush()?;

        let mut reply = String::new();
        (&mut stream).take(MAX_REPLY).read_to_string(&mut reply)?;
        let (status, body) = reply.split_once('\n').unwrap_or((reply.trim_end(), ""));
        match status {
            "ok" => Ok(body.to_string()),
            other => Err(refusal(other)),
        }
    }
}

/// Every live VM on this machine, found by scanning the runtime directory.
///
/// **There is no daemon and no registry**: a VM exists because a helper is listening. The cost is
/// that a scan is point-in-time, which a caller must handle anyway.
pub mod discover {
    use std::io;
    use std::path::{Path, PathBuf};

    use super::socket;

    /// A VM found on this machine.
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    #[non_exhaustive]
    pub struct Found {
        /// The VM's name, taken from its socket's filename.
        pub name: String,
        /// The socket that answered.
        pub socket: PathBuf,
    }

    /// The socket-file extension, so the scan and the path builder agree on what a VM looks like.
    const SUFFIX: &str = ".sock";

    /// Lists the VMs currently listening, in name order. Skips leftovers without deleting them:
    /// this is a read, and [`reap_stale`] is the write.
    pub fn live() -> io::Result<Vec<Found>> {
        live_in(&socket::runtime_dir()?)
    }

    /// [`live`] against an explicit directory, for a caller whose helpers were pointed elsewhere:
    /// a test giving its VMs a private `XDG_RUNTIME_DIR` scans `<that>/bsx`, where the real one
    /// would mix in whatever else is running.
    pub fn live_in(dir: &Path) -> io::Result<Vec<Found>> {
        let mut found: Vec<Found> = entries_in(dir)?
            .into_iter()
            .filter(|(_, path)| socket::is_live(path))
            .map(|(name, socket)| Found { name, socket })
            .collect();
        found.sort();
        Ok(found)
    }

    /// Removes every socket file nobody is listening on, returning how many went. Separate from
    /// [`live`], because a caller asking what runs should not modify the directory.
    pub fn reap_stale() -> io::Result<usize> {
        reap_stale_in(&socket::runtime_dir()?)
    }

    /// [`reap_stale`] against an explicit directory, for the caller [`live_in`] exists for.
    pub fn reap_stale_in(dir: &Path) -> io::Result<usize> {
        let mut removed = 0;
        for (name, path) in entries_in(dir)? {
            if socket::clear_if_stale(&path)? {
                removed += 1;
                // The channel goes with the VM, or `exec` connects to a dead one and blocks.
                let _ = std::fs::remove_file(socket::agent_in(dir, &name));
                let _ = std::fs::remove_file(socket::log_in(dir, &name));
            }
        }
        Ok(removed)
    }

    /// Every `<name>.sock` in the runtime directory, live or not. A name
    /// [`socket::valid_name`] refuses is skipped, or a `Found` could not be passed back in.
    fn entries_in(dir: &Path) -> io::Result<Vec<(String, PathBuf)>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            let Some(name) = path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_suffix(SUFFIX))
            else {
                continue;
            };
            if socket::valid_name(name) {
                out.push((name.to_string(), path));
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn cfg() -> VmConfig {
        VmConfig::new("/srv/root", "/bin/sh")
    }

    /// The argv is the contract with the parser in `crates/cli`. Order matters for the positional
    /// reader on the other side, and the `=` in a share's host path is the case a naive rightmost
    /// split would corrupt.
    #[test]
    fn the_argv_carries_every_configured_field() {
        let mut c = cfg();
        c.workdir = Some(PathBuf::from("/work"));
        c.args = vec!["-c".into(), "echo hi".into()];
        c.env = vec!["KEY=value".into()];
        c.shares = vec![("data".to_string(), PathBuf::from("/opt/a=b"))];
        c.mounts = vec![(PathBuf::from("/project"), PathBuf::from("/srv/code"))];
        c.vsock = Some((1024, PathBuf::from("/run/agent.sock")));
        c.net = Net::Tsi;
        c.rootfs = RootFs::Writable;
        c.display = Some(Display::new(
            NonZeroU32::new(800).expect("non-zero"),
            NonZeroU32::new(600).expect("non-zero"),
        ));
        c.screenshot = Some(PathBuf::from("/tmp/frame.ppm"));
        c.frame_log = Some(PathBuf::from("/tmp/frames.tsv"));
        c.sound = true;

        let argv: Vec<String> = c
            .helper_argv("vm-under-test")
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();

        assert_eq!(
            argv[0], HELPER_SUBCOMMAND,
            "the helper is entered by subcommand"
        );
        for expected in [
            "--name",
            "vm-under-test",
            "--root",
            "/srv/root",
            "--vcpus",
            "1",
            "--mem",
            "512",
            "--exec",
            "/bin/sh",
            "--workdir",
            "/work",
            "--arg",
            "-c",
            "--arg",
            "echo hi",
            "--env",
            "KEY=value",
            "--share",
            "data=/opt/a=b",
            "--mount",
            "/project=/srv/code",
            "--vsock",
            "1024=/run/agent.sock",
            "--net",
            "tsi",
            "--rootfs",
            "writable",
            "--display",
            "800x600",
            "--screenshot",
            "/tmp/frame.ppm",
            "--frame-log",
            "/tmp/frames.tsv",
            "--sound",
        ] {
            assert!(
                argv.contains(&expected.to_string()),
                "{expected} missing from {argv:?}"
            );
        }
    }

    /// A display spells itself the way the helper parses it, with the refresh rate only when one
    /// was asked for.
    #[test]
    fn a_display_spec_carries_its_refresh_rate_only_when_set() {
        let d = Display::new(
            NonZeroU32::new(640).expect("non-zero"),
            NonZeroU32::new(480).expect("non-zero"),
        );
        assert_eq!(d.as_spec(), "640x480");
        assert_eq!(
            d.with_refresh(NonZeroU32::new(120).expect("non-zero"))
                .as_spec(),
            "640x480@120"
        );
    }

    /// The safe posture is what a caller gets for saying nothing, and it travels on the argv
    /// *explicitly*: a helper that inferred the default from a missing flag would be a second
    /// place the default is written, and the two could disagree.
    #[test]
    fn a_config_nobody_configured_asks_for_a_read_only_root() {
        assert_eq!(RootFs::default(), RootFs::ReadOnly);
        assert_eq!(cfg().rootfs, RootFs::ReadOnly);
        let argv: Vec<String> = cfg()
            .helper_argv("vm-under-test")
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let at = argv
            .iter()
            .position(|a| a == "--rootfs")
            .expect("the posture is always on the argv");
        assert_eq!(argv.get(at + 1).map(String::as_str), Some("read-only"));
    }

    /// An absent option contributes no flag at all, rather than an empty one the parser would
    /// then have to interpret.
    #[test]
    fn an_unset_option_contributes_no_flag() {
        let argv = cfg().helper_argv("plain");
        let flat: Vec<_> = argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        for absent in [
            "--workdir",
            "--arg",
            "--env",
            "--share",
            "--vsock",
            "--mount",
            "--display",
            "--screenshot",
            "--frame-log",
            "--sound",
        ] {
            assert!(
                !flat.contains(&absent.to_string()),
                "{absent} should not appear: {flat:?}"
            );
        }
    }

    /// The helper is this executable. Under the test harness that is the test binary, which is the
    /// same property a shipped `bsx` relies on: re-execute *me*, not whatever `PATH` says.
    #[test]
    fn the_helper_is_this_executable() {
        let path = helper_path().expect("current_exe resolves");
        assert!(path.is_absolute(), "spawnable: {path:?}");
        assert!(path.exists(), "names a real file: {path:?}");
    }

    /// The program is **this executable**, through `current_exe`, not "bsx" on a `PATH` search.
    /// Checked on the `Command`, since a spawned child would race its own exit.
    #[test]
    fn the_spawn_command_runs_this_executable_not_a_path_lookup() {
        let cmd = helper_command("vm", &cfg()).expect("build the helper command");
        assert_eq!(
            Path::new(cmd.get_program()),
            helper_path().expect("current_exe resolves"),
            "the helper must be re-executed, never looked up on PATH"
        );
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args.first().map(String::as_str), Some(HELPER_SUBCOMMAND));
    }

    /// The helper is told where libkrun's kernel payload is, or a boot dies on `dlopen` of a bare
    /// name with libkrun's own "Couldn't find or load libkrunfw" and no VM.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_helper_is_told_where_the_kernel_payload_is() {
        let Some(dir) = bsx_krun::KRUNFW_DIR else {
            eprintln!(
                "skipped: no libkrunfw was found when bsx-krun was built, so there is no \
                 directory to hand the helper"
            );
            return;
        };
        let cmd = helper_command("vm", &cfg()).expect("build the helper command");
        let (_, value) = cmd
            .get_envs()
            .find(|(k, _)| *k == "DYLD_FALLBACK_LIBRARY_PATH")
            .expect("the helper carries DYLD_FALLBACK_LIBRARY_PATH");
        let value = value.expect("with a value").to_string_lossy().into_owned();
        let entries: Vec<&str> = value.split(':').collect();
        assert!(entries.contains(&dir), "{value:?} must name {dir}");
        // The *tail*, not mere presence: cargo sets this variable for its own test binaries and
        // its value already holds `/usr/lib`, so `contains` here would pass without this code
        // having run. What is pinned is that dyld's default is put back and stays the last resort,
        // since setting the variable at all replaces it.
        assert!(
            value.ends_with(":/usr/local/lib:/usr/lib"),
            "dyld's default must be restored, and last: {value:?}"
        );
        let dir_at = entries.iter().position(|e| *e == dir).expect("named above");
        let usr_at = entries.len() - 1;
        assert!(
            dir_at < usr_at,
            "libkrunfw must be searched before the default: {value:?}"
        );
    }

    /// A helper's exit code reaches the caller through `wait`, which is how a guest's status gets
    /// back to whoever asked for the sandbox. Built around `/bin/sh` rather than a real VM: what is
    /// under test is the supervisor's wait path, and a boot would make this need `/dev/kvm`.
    #[test]
    fn a_helpers_exit_code_reaches_the_caller() {
        let vm = Vm {
            child: Some(
                Command::new("/bin/sh")
                    .args(["-c", "exit 7"])
                    .spawn()
                    .expect("spawn a child that exits 7"),
            ),
            name: "seven".to_string(),
        };
        assert_eq!(vm.wait().expect("wait on the child"), Exit::Code(7));
    }

    /// The recursion guard, driven through the pure half rather than `Vm::spawn`, so a regression
    /// fails here instead of by filling the machine with processes.
    #[test]
    fn a_helper_refuses_to_spawn_another_helper() {
        let err = helper_command_unless_helper("vm", &cfg(), true)
            .expect_err("a helper must refuse to spawn a helper");
        assert!(matches!(err, Error::AlreadyHelper), "got {err:?}");
        assert!(
            err.to_string().contains(HELPER_SUBCOMMAND),
            "names the fix: {err}"
        );
        helper_command_unless_helper("vm", &cfg(), false)
            .expect("and builds normally when this process is not a helper");
    }

    /// The name a caller spawns with has to reach the helper's argv: the helper is what binds the
    /// control socket, so a spawn that kept the name to itself would start a VM `discover` cannot
    /// see, while `Vm::name()` claims otherwise.
    #[test]
    fn the_spawned_name_reaches_the_helper_argv() {
        let cmd = helper_command("visible", &cfg()).expect("build the helper command");
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let at = args
            .iter()
            .position(|a| a == "--name")
            .expect("the helper must be told its name");
        assert_eq!(args.get(at + 1).map(String::as_str), Some("visible"));
    }

    /// A name the socket module would refuse becomes a synchronous error, not a helper that dies
    /// after `spawn` already returned `Ok`.
    #[test]
    fn a_name_the_socket_would_refuse_is_refused_before_anything_spawns() {
        let err = helper_command_unless_helper("../escape", &cfg(), false)
            .expect_err("a traversal cannot become a socket filename");
        assert!(
            matches!(&err, Error::Name(n) if n == "../escape"),
            "got {err:?}"
        );
        assert!(
            err.to_string().contains("[A-Za-z0-9_-]"),
            "states the rule: {err}"
        );
    }

    /// The marker has to reach the child, or the guard above never trips for a real helper.
    #[test]
    fn a_spawned_helper_carries_the_marker() {
        let cmd = helper_command("vm", &cfg()).expect("build the helper command");
        let marked = cmd
            .get_envs()
            .any(|(k, v)| k == HELPER_MARKER && v.is_some());
        assert!(marked, "the child must carry {HELPER_MARKER}");
    }

    /// A killed helper is reported as a signal, not as an exit code, so a supervisor can tell "the
    /// guest returned 9" from "somebody killed the VM". These are the same number otherwise.
    #[test]
    fn a_signalled_helper_is_not_reported_as_an_exit_code() {
        let mut vm = Vm {
            child: Some(
                Command::new("/bin/sleep")
                    .arg("300")
                    .spawn()
                    .expect("spawn a long-lived child"),
            ),
            name: "signalled".to_string(),
        };
        if let Some(child) = vm.child.as_mut() {
            child.kill().expect("kill the child");
        }
        assert!(
            matches!(
                vm.wait().expect("wait on the killed child"),
                Exit::Signal(_)
            ),
            "a killed helper is a signal, not a code"
        );
    }

    /// `stop` ends a running VM and reports it as a signal, not as an exit code, so a caller can
    /// tell a stopped sandbox from one whose workload returned.
    #[test]
    fn stopping_a_running_vm_reports_a_signal() {
        let vm = Vm {
            child: Some(
                Command::new("/bin/sleep")
                    .arg("300")
                    .spawn()
                    .expect("spawn a long-lived child"),
            ),
            name: "stopme".to_string(),
        };
        let pid = vm.pid();
        assert!(matches!(vm.stop().expect("stop the vm"), Exit::Signal(_)));
        assert!(
            !pid_is_live(pid),
            "and the process is gone, not left as a zombie"
        );
    }

    /// A VM that ended on its own is still reported honestly by `stop`, which has a real status
    /// to hand back rather than an invented one. The common case for a short workload.
    #[test]
    fn stopping_a_vm_that_already_finished_reports_its_real_exit() {
        let vm = Vm {
            child: Some(
                Command::new("/bin/sh")
                    .args(["-c", "exit 3"])
                    .spawn()
                    .expect("spawn a short-lived child"),
            ),
            name: "gone".to_string(),
        };
        // Exit without reaping, so `stop` meets a finished but unreaped child: polled as a
        // zombie in `/proc`, because a fixed sleep loses the race under load.
        let pid = vm.pid();
        for _ in 0..500 {
            if !pid_is_live(pid) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(
            vm.stop().expect("stopping a finished VM is not an error"),
            Exit::Code(3),
            "the guest's own exit code survives a stop that raced it"
        );
    }

    /// Once a caller has reaped through `try_wait`, there is no process left and no status to
    /// invent, so `stop` says so instead of reporting a fabricated exit.
    #[test]
    fn stopping_an_already_reaped_vm_is_refused() {
        let mut vm = Vm {
            child: Some(
                Command::new("/bin/sh")
                    .args(["-c", "exit 0"])
                    .spawn()
                    .expect("spawn a short-lived child"),
            ),
            name: "reaped".to_string(),
        };
        for _ in 0..500 {
            if vm.try_wait().expect("poll").is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let err = vm.stop().expect_err("there is nothing left to stop");
        assert!(err.to_string().contains("already reaped"), "{err}");
    }

    /// Reaping twice must not signal a pid the kernel may have reused. `try_wait` drops the handle
    /// once it reaps, so the later `Drop` has nothing to kill.
    #[test]
    fn a_reaped_helper_is_not_signalled_again() {
        let mut vm = Vm {
            child: Some(
                Command::new("/bin/sh")
                    .args(["-c", "exit 0"])
                    .spawn()
                    .expect("spawn a short-lived child"),
            ),
            name: "reaped".to_string(),
        };
        for _ in 0..500 {
            if vm.try_wait().expect("poll the child").is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(vm.pid(), 0, "a reaped helper reports no pid");
        drop(vm);
    }

    /// The one path that leaves a helper running, so this asserts the exception works and that
    /// the value is consumed: after a detach nothing is left that would reap the process.
    #[test]
    fn a_detached_vm_outlives_the_handle_that_started_it() {
        let child = Command::new("/bin/sleep")
            .arg("300")
            .spawn()
            .expect("spawn a long-lived child");
        let expected = child.id();
        let vm = Vm {
            child: Some(child),
            name: "detached".to_string(),
        };
        let pid = vm.detach().expect("a live helper detaches");
        assert_eq!(pid, expected, "the caller is told which process it let go");
        assert!(pid_is_live(pid), "detaching must not tear the helper down");
        // Not the process under test's business to leave running.
        let _ = Command::new("/bin/kill").arg(pid.to_string()).status();
    }

    /// Dropping a `Vm` must not leave the helper running: drops one and asks the kernel whether
    /// the pid is gone.
    #[test]
    fn dropping_a_vm_kills_and_reaps_its_helper() {
        let child = Command::new("/bin/sleep")
            .arg("300")
            .spawn()
            .expect("spawn a long-lived child");
        let pid = child.id();
        let vm = Vm {
            child: Some(child),
            name: "sleeper".to_string(),
        };
        assert!(pid_is_live(pid), "the child is running before the drop");
        drop(vm);
        assert!(!pid_is_live(pid), "the drop killed and reaped it");
    }

    /// Whether `pid` still exists as a live (non-zombie) process, read from the process table
    /// rather than probed with a signal: a reaped child's pid can be reused, and this test is
    /// asserting on the exact pid it spawned. The zombie half is the point, so a bare `kill(0)`
    /// will not do; `/proc` where there is one, `ps` where there is not.
    fn pid_is_live(pid: u32) -> bool {
        #[cfg(target_os = "linux")]
        {
            let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
                return false;
            };
            !status
                .lines()
                .any(|l| l.starts_with("State:") && l.contains('Z'))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let Ok(out) = Command::new("ps")
                .args(["-o", "state=", "-p", &pid.to_string()])
                .output()
            else {
                return false;
            };
            let state = String::from_utf8_lossy(&out.stdout);
            let state = state.trim();
            !state.is_empty() && !state.starts_with('Z')
        }
    }
}

/// Waits, bounded, for `path` to stop answering a connect.
///
/// Closing a listener is not synchronous on macOS: a connect can still be accepted for a moment
/// after the close, so a test that binds, drops and immediately asserts staleness is asserting a
/// promise the platform does not make. The window is why a stale socket can survive one
/// `reap_stale` pass there and go on the next.
#[cfg(test)]
fn wait_until_not_live(path: &std::path::Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while socket::is_live(path) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[cfg(test)]
mod socket_tests {
    use std::os::unix::net::UnixListener;

    use super::socket;

    /// A VM name becomes a filename, so anything that could leave the runtime directory is refused.
    /// An allow-list, so a sequence nobody thought of is refused by default rather than permitted.
    #[test]
    fn a_name_that_could_escape_the_runtime_directory_is_refused() {
        for good in ["vm", "my-vm_2", "A", &"n".repeat(64)] {
            assert!(socket::valid_name(good), "{good:?} should be usable");
        }
        for bad in [
            "",
            "..",
            "../escape",
            "/absolute",
            "has/slash",
            "has space",
            "dot.sock",
            "nul\0byte",
            &"n".repeat(65),
        ] {
            assert!(!socket::valid_name(bad), "{bad:?} must be refused");
        }
    }

    /// The refusal has to say what a usable name is, or a caller guesses.
    #[test]
    fn a_refused_name_explains_the_rule() {
        let err = socket::path_for("../escape").expect_err("a traversal is refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        let msg = err.to_string();
        assert!(msg.contains("../escape"), "names the input: {msg}");
        assert!(msg.contains("filename"), "says why it matters: {msg}");
    }

    /// The whole point of the module: a socket file is **not** evidence of a live VM. Every clean
    /// shutdown leaves one, because `krun_start_enter` exits the process without unwinding.
    #[test]
    fn a_listening_socket_is_live_and_a_leftover_file_is_not() {
        let dir = bsx_test_support::ScratchDir::created("sock-live");
        let path = dir.path().join("vm.sock");

        let listener = UnixListener::bind(&path).expect("bind a socket");
        assert!(
            socket::is_live(&path),
            "a bound socket with a listener is live"
        );
        assert!(
            !socket::clear_if_stale(&path).expect("check a live socket"),
            "a live socket must never be removed"
        );

        // Dropping the listener closes it but leaves the file, which is exactly the state a helper
        // leaves behind when libkrun exits the process.
        drop(listener);
        assert!(path.exists(), "the file outlives the listener");
        super::wait_until_not_live(&path);
        assert!(!socket::is_live(&path), "nothing is listening any more");
        assert!(
            socket::clear_if_stale(&path).expect("clear the leftover"),
            "a leftover is removed"
        );
        assert!(!path.exists(), "and is gone afterwards");
    }

    /// Clearing a path that was never there is not an error: a caller reaping a VM that failed
    /// before it bound should not have to distinguish the two.
    #[test]
    fn clearing_an_absent_socket_is_not_an_error() {
        let dir = bsx_test_support::ScratchDir::created("sock-absent");
        let missing = dir.path().join("never-existed.sock");
        assert!(!socket::clear_if_stale(&missing).expect("an absent socket is fine"));
    }
}

#[cfg(test)]
mod control_tests {
    #![allow(clippy::panic)]

    use std::io::BufRead;
    use std::num::{NonZeroU8, NonZeroU32};
    use std::os::fd::AsFd;

    use super::control;
    use super::control::{Channel, Info, PROTOCOL_VERSION, Request, write_answer};
    use super::{Net, RootFs};

    fn info() -> Info {
        Info::new(
            4242,
            NonZeroU8::MIN,
            NonZeroU32::new(512).expect("512 is not zero"),
            Net::Tsi,
            RootFs::Writable,
            Channel::Present,
        )
    }

    /// What the VM writes is what a client reads back, field for field. The round trip is the
    /// whole contract: the two halves are in one crate here and in two processes in life.
    #[test]
    fn an_answer_round_trips_through_the_wire_form() {
        let mut wire = Vec::new();
        write_answer(&mut wire, Some(Request::Info), &info()).expect("a Vec accepts the answer");
        let text = String::from_utf8(wire).expect("the answer is text");
        let body = text
            .strip_prefix("ok\n")
            .expect("an answered request leads with ok");
        assert_eq!(Info::parse_body(body).expect("the body parses"), info());
    }

    /// Every field is required. A VM whose answer is missing one is a VM this build cannot
    /// describe, and defaulting the gap would report a machine nobody configured.
    #[test]
    fn an_answer_missing_a_field_is_refused_rather_than_defaulted() {
        let mut wire = Vec::new();
        write_answer(&mut wire, Some(Request::Info), &info()).expect("a Vec accepts the answer");
        let text = String::from_utf8(wire).expect("the answer is text");
        let full = text.strip_prefix("ok\n").expect("leads with ok");
        for dropped in [
            "proto", "pid", "vcpus", "mem_mib", "net", "rootfs", "channel",
        ] {
            let thinned: String = full
                .lines()
                .filter(|l| !l.starts_with(&format!("{dropped} ")))
                .map(|l| format!("{l}\n"))
                .collect();
            let err = Info::parse_body(&thinned)
                .expect_err("a missing field must refuse")
                .to_string();
            assert!(err.contains(dropped), "names what was missing: {err}");
        }
    }

    /// A VM speaking a different grammar is reported as that, not read as if it were this one.
    #[test]
    fn a_different_protocol_version_is_refused_by_number() {
        let body = format!("proto {}\npid 1\n", u32::from(PROTOCOL_VERSION) + 1);
        let err = Info::parse_body(&body)
            .expect_err("a version this build does not speak must refuse")
            .to_string();
        assert!(err.contains("control protocol"), "{err}");
    }

    /// A word this VM does not know is answered, not dropped: a caller learns what the VM speaks
    /// instead of reading a closed connection and guessing.
    #[test]
    fn an_unknown_request_is_answered_with_what_this_vm_speaks() {
        assert_eq!(Request::from_word("info"), Some(Request::Info));
        assert_eq!(Request::from_word("stop"), Some(Request::Stop));
        assert_eq!(Request::from_word("shutdown"), None);

        let mut wire = Vec::new();
        write_answer(&mut wire, None, &info()).expect("a Vec accepts the refusal");
        let text = String::from_utf8(wire).expect("the refusal is text");
        assert!(text.starts_with("err "), "{text}");
        assert!(text.contains("info") && text.contains("stop"), "{text}");
    }

    /// Answering a stop does not stop anything: the process ending is what ends a VM, and a
    /// library cannot do that for its caller.
    #[test]
    fn a_stop_is_acknowledged_and_carries_no_body() {
        let mut wire = Vec::new();
        write_answer(&mut wire, Some(Request::Stop), &info()).expect("a Vec accepts the answer");
        assert_eq!(String::from_utf8(wire).expect("text"), "ok\n");
    }

    /// A request arrives as one line, and a caller that pads it with the rest of a session does
    /// not confuse the reader.
    #[test]
    fn a_request_is_read_off_the_first_line() {
        let read = |bytes: &str| super::control::read_request(bytes.as_bytes()).expect("no io");
        assert_eq!(read("info\n"), Some(Request::Info));
        assert_eq!(read("input\n"), Some(Request::Input));
        assert_eq!(read("stop\nleftover\n"), Some(Request::Stop));
        assert_eq!(read("nonsense\n"), None);
        assert_eq!(read(""), None, "a caller that says nothing asks nothing");
    }
    /// The display answer carries the layout and the memfd in one message, the first records may
    /// arrive in the same read, and every record after it names its frame and slot; a
    /// reconfigure record ends the lease's stream of presents.
    #[test]
    fn a_display_answer_carries_the_layout_the_fd_and_then_records() {
        use std::os::fd::AsRawFd;
        let (server, client) = std::os::unix::net::UnixStream::pair().expect("a socket pair");
        let dir = bsx_test_support::ScratchDir::created("display-lease");
        let file = std::fs::File::create(dir.path().join("frames")).expect("a file to hand over");
        let scanout = control::Scanout::new(320, 240, 2, 1280, 4, 307_200, 3);
        let answered = std::thread::spawn(move || {
            let mut request = String::new();
            std::io::BufReader::new(&server)
                .read_line(&mut request)
                .expect("the request");
            assert_eq!(request.trim_end(), "display");
            control::write_display_answer(&server, file.as_fd(), &scanout).expect("answered");
            let whole = control::Damage::new(0, 0, 320, 240);
            control::write_present(&mut &server, 41, 2, whole).expect("a record");
            control::write_present(&mut &server, 42, 3, control::Damage::new(16, 8, 4, 2))
                .expect("a record");
            control::write_present(&mut &server, 0, control::RECONFIGURED_SLOT, whole)
                .expect("the end");
            file
        });
        let mut lease = control::lease_on(client).expect("leased");
        assert_eq!(lease.scanout(), scanout, "the layout as sent");
        let memfd = lease.take_memfd().expect("the fd came with the answer");
        // The original stays open across the comparison: a closed number can be handed out again.
        let original = answered.join().expect("the server thread");
        assert_ne!(
            memfd.as_raw_fd(),
            original.as_raw_fd(),
            "a passed fd is a new descriptor"
        );
        assert!(lease.take_memfd().is_none(), "taken once");
        assert_eq!(
            lease.next_event().expect("first"),
            control::Event::Presented {
                frame_id: 41,
                slot: 2,
                damage: control::Damage::new(0, 0, 320, 240),
            }
        );
        assert_eq!(
            lease.next_event().expect("second"),
            control::Event::Presented {
                frame_id: 42,
                slot: 3,
                damage: control::Damage::new(16, 8, 4, 2),
            }
        );
        assert_eq!(
            lease.next_event().expect("the end"),
            control::Event::Reconfigured
        );
    }

    /// An input session is the request, the `ok`, and then the caller's lines until it hangs
    /// up; a VM that refuses is read as the refusal.
    #[test]
    fn an_input_session_is_ok_and_then_the_callers_lines() {
        use std::io::{BufReader, Read, Write};
        let (server, client) = std::os::unix::net::UnixStream::pair().expect("a socket pair");
        let served = std::thread::spawn(move || {
            let mut request = String::new();
            let mut reader = BufReader::new(&server);
            reader.read_line(&mut request).expect("the request");
            assert_eq!(request.trim_end(), "input");
            writeln!(&server, "ok").expect("answered");
            let mut lines = String::new();
            reader.read_to_string(&mut lines).expect("the lines to EOF");
            lines
        });
        let mut session = control::input_on(client).expect("an open session");
        session.send("kbd 1 30 1").expect("a line");
        session.send("kbd 0 0 0").expect("a line");
        drop(session);
        assert_eq!(
            served.join().expect("the server"),
            "kbd 1 30 1\nkbd 0 0 0\n"
        );

        let (server, client) = std::os::unix::net::UnixStream::pair().expect("a socket pair");
        std::thread::spawn(move || {
            let mut request = String::new();
            BufReader::new(&server)
                .read_line(&mut request)
                .expect("the request");
            control::write_refusal(&mut &server, "this VM has no display").expect("refused");
        });
        let outcome = control::input_on(client);
        assert!(
            matches!(&outcome, Err(control::Error::Refused(why)) if why == "this VM has no display"),
            "not the refusal: {outcome:?}"
        );
    }

    /// A refusal is one line with no terminator, and the client reads it as the refusal rather
    /// than waiting for a blank line that never comes.
    #[test]
    fn a_refused_display_lease_is_read_as_the_refusal() {
        let (mut server, client) = std::os::unix::net::UnixStream::pair().expect("a socket pair");
        let refused = std::thread::spawn(move || {
            let mut request = String::new();
            std::io::BufReader::new(&server)
                .read_line(&mut request)
                .expect("the request");
            control::write_refusal(&mut server, control::NOT_READY).expect("refused");
        });
        let err = control::lease_on(client).expect_err("refused");
        refused.join().expect("the server thread");
        assert!(matches!(&err, control::Error::NotReady), "{err}");
    }

    /// The layout body round-trips, and a body from another protocol version is refused.
    #[test]
    fn a_scanout_layout_round_trips_and_checks_the_protocol() {
        let scanout = control::Scanout::new(1920, 1080, 2, 7680, 4, 8_294_400, 0);
        let body = scanout.body();
        assert_eq!(
            control::Scanout::parse_body(&body).expect("parsed"),
            scanout
        );
        let old = body.replacen(
            &format!("proto {}", control::PROTOCOL_VERSION),
            "proto 1",
            1,
        );
        assert!(control::Scanout::parse_body(&old).is_err());
    }
}

#[cfg(test)]
mod discover_tests {
    use std::os::unix::net::UnixListener;

    use super::{discover, socket};

    /// The scan itself: a listening socket is a VM, a leftover is not, and neither a file that is
    /// not a socket nor one whose name the API would refuse becomes an entry.
    #[test]
    fn a_scan_reports_listeners_and_skips_everything_else() {
        let dir = bsx_test_support::ScratchDir::created("discover");
        let d = dir.path();

        let _listener = UnixListener::bind(d.join("alive.sock")).expect("bind the live one");
        // A leftover: bound, then closed, exactly as a helper leaves it.
        let ended = UnixListener::bind(d.join("ended.sock")).expect("bind then drop");
        drop(ended);
        super::wait_until_not_live(&d.join("ended.sock"));
        // Not a socket at all, and a socket whose name could not be passed back into the API.
        std::fs::write(d.join("notes.txt"), b"not a vm").expect("write a stray file");
        let bad = UnixListener::bind(d.join("bad name.sock")).expect("bind a badly named socket");
        drop(bad);
        super::wait_until_not_live(&d.join("bad name.sock"));

        let found = discover::live_in(d).expect("scan the directory");
        let names: Vec<&str> = found.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            ["alive"],
            "only the listening, well-named socket is a VM"
        );
        assert_eq!(found[0].socket, d.join("alive.sock"));
    }

    /// A VM's agent channel sits beside its control socket under the same name, and must not look
    /// like a VM to a scan, or every VM would be listed twice.
    #[test]
    fn the_agent_channel_sits_beside_the_control_socket_and_is_not_a_vm() {
        let control = socket::path_for("chan-test").expect("a usable name");
        let agent = socket::agent_path_for("chan-test").expect("a usable name");
        assert_eq!(control.parent(), agent.parent(), "same directory");
        assert_ne!(control, agent);
        assert!(!agent.to_string_lossy().ends_with(".sock"), "{agent:?}");

        let dir = bsx_test_support::ScratchDir::created("agent-socket-scan");
        let listener =
            std::os::unix::net::UnixListener::bind(dir.path().join("live.agent")).expect("bind");
        assert_eq!(
            discover::live_in(dir.path()).expect("scan"),
            vec![],
            "a channel socket is not a VM, however live it is"
        );
        drop(listener);
    }

    /// Reaping a VM's leftover control socket takes its channel with it. A channel left behind is
    /// a path `exec` would connect to and then wait on forever, for a VM that has ended.
    #[test]
    fn reaping_a_dead_vm_takes_its_agent_channel_too() {
        let dir = bsx_test_support::ScratchDir::created("agent-socket-reap");
        let control = dir.path().join("gone.sock");
        let channel = socket::agent_in(dir.path(), "gone");
        std::fs::write(&control, b"").expect("stage a leftover control socket");
        std::fs::write(&channel, b"").expect("stage a leftover channel socket");

        assert_eq!(discover::reap_stale_in(dir.path()).expect("reap"), 1);
        assert!(!control.exists(), "the control socket went");
        assert!(!channel.exists(), "its channel went with it");
    }

    /// Listing must not delete: a leftover survives a scan, and only `reap_stale` removes it.
    #[test]
    fn a_scan_does_not_remove_leftovers_but_reaping_does() {
        let dir = bsx_test_support::ScratchDir::created("discover-reap");
        let d = dir.path();
        let leftover = d.join("ended.sock");
        let _listener = UnixListener::bind(d.join("alive.sock")).expect("bind the live one");
        drop(UnixListener::bind(&leftover).expect("bind then drop"));
        super::wait_until_not_live(&leftover);

        discover::live_in(d).expect("scan");
        assert!(leftover.exists(), "a read must not delete");

        assert_eq!(
            discover::reap_stale_in(d).expect("reap"),
            1,
            "one leftover went"
        );
        assert!(!leftover.exists(), "and it is gone");
        assert!(d.join("alive.sock").exists(), "the live one is untouched");
    }

    /// The real scan must not blow up on a directory holding things that are not VM sockets, which
    /// is what `/tmp`-fallback hosts will look like.
    #[test]
    fn a_scan_of_the_real_runtime_directory_succeeds() {
        // Whatever is running on this machine, listing it is not an error, and every name it
        // returns must be one the API would accept back.
        let found = discover::live().expect("scanning the runtime directory is not an error");
        for vm in &found {
            assert!(
                socket::valid_name(&vm.name),
                "{:?} came back unusable",
                vm.name
            );
            assert!(vm.socket.ends_with(format!("{}.sock", vm.name)));
        }
    }
}
