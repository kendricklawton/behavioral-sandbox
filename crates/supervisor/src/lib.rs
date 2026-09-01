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
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

/// The hidden subcommand that turns this executable into a VM. Written here, parsed in
/// `crates/cli/src/vmm.rs`.
pub const HELPER_SUBCOMMAND: &str = "__vmm";

/// Set on every helper this crate spawns, and refused if it is already set.
///
/// **This stops a fork bomb.** [`Vm::spawn`] re-executes `current_exe()`, so a binary that links
/// this crate but does not dispatch [`HELPER_SUBCOMMAND`] before it spawns re-executes *itself*,
/// which spawns again, without bound. Observed while wiring this up. The marker turns that into one
/// wasted process and a message naming the mistake.
const HELPER_MARKER: &str = "BSX_VMM";

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
    /// Host directories made read-write inside the guest, as `(guest path, host path)`. Edits
    /// land on the host: this is the project-directory case, where the sandbox works on real
    /// files. The helper wraps the workload in a mount preamble, so a VM with mounts needs
    /// `/bin/sh` and `mount` in its image.
    pub mounts: Vec<(PathBuf, PathBuf)>,
    /// A vsock mapping as `(guest port, host unix socket path)`: the guest listens on the port,
    /// and a host process reaches it by connecting to the socket. One is enough for the agent
    /// channel, which is what it exists for.
    pub vsock: Option<(u32, PathBuf)>,
    /// What the guest's console (the helper's stdin and stdout) is attached to.
    pub console: Console,
}

/// What the guest's console is attached to: the helper's stdin feeds it and its output is the
/// helper's stdout, so the two travel together.
///
/// stderr stays inherited either way: it is where the helper reports a refusal, and a caller
/// detaching the console should still see why a boot failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Console {
    /// The caller's own stdin and stdout, which is what makes `bsx run` behave like the command
    /// it wraps.
    #[default]
    Inherited,
    /// Nothing: input from `/dev/null`, output discarded. For a caller whose session travels a
    /// channel of its own (the interactive shell), where an attached console would *compete for
    /// the caller's stdin* — libkrun reads it into the guest console, so every keystroke it won
    /// would vanish from the session (watched happen) — and interleave boot noise into a raw
    /// terminal.
    Detached,
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
            console: Console::Inherited,
        }
    }

    /// The argument vector that re-enters this executable as this machine, named `name`.
    ///
    /// The name is on the argv because the helper is what binds the control socket: a spawn that
    /// kept the name to itself would start a VM that discovery cannot see. Public so a caller can
    /// print what would be run, and so the flag spellings have exactly one definition for the lint
    /// in `xtask` to compare against the parser.
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
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::HelperPath(e) | Self::Spawn(e) | Self::Wait(e) => Some(e),
            Self::AlreadyHelper | Self::Name(_) => None,
        }
    }
}

/// This executable, for re-execution as a VM.
///
/// `current_exe()` rather than the name `bsx`: a `PATH` lookup runs whichever build the environment
/// points at, and the helper has to be *this* one, since the two halves share an argv contract that
/// only matches within a single build.
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
    /// name travels on the helper's argv and becomes its control socket, so the VM this starts is
    /// one [`discover`] can list; a name [`socket::valid_name`] refuses is refused here, before
    /// there is a process to fail asynchronously.
    ///
    /// The helper inherits stdio: a VM's output is the caller's output, which is what makes
    /// `bsx run` behave like running the command. Redirecting it is the caller's business.
    pub fn spawn(name: impl Into<String>, cfg: &VmConfig) -> Result<Self, Error> {
        let name = name.into();
        let child = helper_command(&name, cfg)?.spawn().map_err(Error::Spawn)?;
        Ok(Self {
            child: Some(child),
            name,
        })
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
    /// **This is a power cut, not a shutdown.** The guest is given no chance to run an exit
    /// handler, flush a buffer, or unmount anything: the VMM process dies and the guest ceases to
    /// exist with it. Measured, not assumed — a guest with `trap ... TERM` installed, sent SIGTERM
    /// through its helper, never ran the trap and the helper died 143.
    ///
    /// libkrun's only graceful surface is `krun_get_shutdown_eventfd`, which is efi-only and
    /// returns `-ENOTSUP` against a stock build, so there is nothing gentler to call. A guest that
    /// must finish work first has to be asked in-band before this, which is what phase 3's agent is
    /// for; until then, anything a guest needs to keep it must write as it goes.
    ///
    /// Sends SIGKILL rather than SIGTERM. With no handler in libkrun the two are indistinguishable
    /// to the guest, and reaching for a signal crate to send a politer one that behaves identically
    /// would be a dependency buying a gesture.
    pub fn stop(mut self) -> Result<Exit, Error> {
        let Some(mut child) = self.child.take() else {
            return Err(Error::Wait(std::io::Error::other(
                "the helper was already reaped",
            )));
        };
        // An `ESRCH` here is the VM having ended on its own between a caller's check and this call,
        // which is a race no caller can close and not a failure to stop anything: the `wait` below
        // still reports how it went.
        let _ = child.kill();
        let status = child.wait().map_err(Error::Wait)?;
        Ok(exit_of(&status))
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
        // A dropped `Vm` must not leave a helper running: that is a stranded VM holding a laptop's
        // RAM with nothing left that knows about it. `kill` then `wait`, because a killed child
        // that is never waited on is a zombie, and this process may be long-lived.
        //
        // Both results are discarded deliberately. The child may have exited on its own between the
        // last check and here, which makes `kill` fail with ESRCH and is not a problem; and a panic
        // in `drop` would replace whatever error is unwinding with an abort.
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

/// The body of [`helper_command`] with the environment read lifted out.
///
/// Split so the recursion guard is a pure decision a test can drive both ways. Setting an
/// environment variable is `unsafe` in this edition and this crate forbids `unsafe`, so a test that
/// exercised the guard through the real environment could not be written here at all.
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
    let mut cmd = Command::new(helper_path()?);
    cmd.args(cfg.helper_argv(name))
        .env(HELPER_MARKER, "1")
        .stdin(match cfg.console {
            Console::Inherited => Stdio::inherit(),
            Console::Detached => Stdio::null(),
        })
        .stdout(match cfg.console {
            Console::Inherited => Stdio::inherit(),
            Console::Detached => Stdio::null(),
        })
        .stderr(Stdio::inherit());
    Ok(cmd)
}

/// Reads an `ExitStatus` into [`Exit`]. Split out so the signal path is testable without arranging
/// a real signalled child in a unit test.
fn exit_of(status: &std::process::ExitStatus) -> Exit {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(code), _) => Exit::Code(code),
        (None, Some(sig)) => Exit::Signal(sig),
        // `ExitStatus` on Unix is one or the other; a status that is neither is the kernel telling
        // us something this code does not model, and reporting it as a signal-less kill is more
        // honest than claiming a zero exit.
        (None, None) => Exit::Signal(0),
    }
}

/// Where a VM's control socket lives, and how a caller tells a live one from a leftover.
///
/// Each helper binds `<runtime>/<name>.sock` before it becomes a VM, and that socket is live for
/// exactly as long as the VM is. There is no daemon: the sockets *are* the registry, which is what
/// lets a VM started by the GUI be visible to the CLI.
///
/// **A socket file outliving its helper is expected, not exceptional.** `krun_start_enter` exits the
/// process for us, which does not unwind, so nothing in the helper gets to remove its own socket. A
/// leftover is therefore normal after every clean shutdown, and [`socket::is_live`] is what separates the
/// two: it connects, and a socket nobody is listening on refuses. Presence is never taken as
/// evidence of a running VM.
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
    /// `$XDG_RUNTIME_DIR` first, which is per-user and already `0700` on a systemd host. Falling
    /// back to `$TMPDIR` covers macOS, where `TMPDIR` is per-user, and `/tmp` is the last resort,
    /// which is **shared**, and is why the mode and owner are checked rather than assumed.
    pub fn runtime_dir() -> io::Result<PathBuf> {
        use std::os::unix::fs::DirBuilderExt;
        let base = std::env::var_os("XDG_RUNTIME_DIR")
            .or_else(|| std::env::var_os("TMPDIR"))
            .map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
        let dir = base.join(DIR_NAME);
        // Created at its final mode rather than created and then tightened: create-then-chmod
        // leaves a window at the caller's umask, and this directory can sit under a shared `/tmp`.
        // Recursive, so a directory that already exists is not an error; whether the existing one
        // is acceptable is the check below, on every resolution.
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        builder.mode(0o700);
        builder.create(&dir)?;
        require_private(&dir)?;
        Ok(dir)
    }

    /// Refuses a runtime directory anyone else can write or that anyone else owns.
    ///
    /// The fallback path can be `/tmp`, where another local user can create `bsx/` first and then
    /// read every control socket placed in it. Checked on every resolution rather than only at
    /// creation, because the directory outlives the process that made it.
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

    /// This process's real uid, read from `/proc/self/status` so the crate keeps its
    /// `#![forbid(unsafe_code)]` and takes no libc dependency for one integer.
    fn real_uid() -> u32 {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("Uid:"))
                    .and_then(|l| l.split_whitespace().next().map(str::to_owned))
            })
            .and_then(|f| f.parse().ok())
            // A `/proc` this cannot read is a host this cannot check, and claiming uid 0 would make
            // the owner check pass by accident. `u32::MAX` is not a real uid, so it fails closed.
            .unwrap_or(u32::MAX)
    }

    /// The rule a usable name satisfies, spelled by the function every refusal quotes.
    pub(crate) fn name_rule() -> String {
        format!("1..={MAX_NAME} characters of [A-Za-z0-9_-]")
    }

    /// Whether `name` may become a socket file.
    ///
    /// **A VM name reaches the filesystem**, so `../../etc/x` or an absolute path would place a
    /// socket outside the runtime directory, and an empty name would collide with the directory
    /// itself. Restricted to an explicit alphabet rather than filtered for known-bad sequences: a
    /// deny-list is a guess about what is dangerous, and an allow-list is a statement about what is
    /// permitted.
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

    /// Whether something is listening on `path` right now.
    ///
    /// Connects rather than checking for the file: a socket file is left behind by every helper
    /// that ends, so presence proves nothing. A refused connection is the kernel saying the bound
    /// socket has no listener, which is exactly "the VM is gone".
    #[must_use]
    pub fn is_live(path: &Path) -> bool {
        std::os::unix::net::UnixStream::connect(path).is_ok()
    }

    /// Removes `path` if nothing is listening on it. Returns whether it removed anything.
    ///
    /// The race is real and deliberately narrow: a helper could bind between the check and the
    /// unlink, and lose its socket. Callers run this on a name they are about to reuse or have just
    /// reaped, where no other helper is entitled to that name.
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

/// Every live VM on this machine, found by scanning the runtime directory.
///
/// **There is no daemon and no registry.** The sockets are the state: a VM exists because a helper
/// is listening, and it stops existing when that helper does. This is what lets a VM started by the
/// GUI be visible to the CLI, and the reverse, with neither process knowing about the other.
///
/// The cost is that a scan is a point-in-time answer. A VM can end between the scan and the caller
/// reading the result, which no design without a supervising daemon can avoid, and which a caller
/// must handle anyway because that is also true of a VM it started itself.
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

    /// Lists the VMs currently listening, in name order.
    ///
    /// Skips leftovers rather than reporting them: a socket nobody is listening on is a VM that has
    /// already ended, and listing it would make `ls` grow forever. Skips, deliberately, without
    /// deleting: this is a read, and a caller running it has no claim on names it does not own.
    /// [`reap_stale`] is the write.
    pub fn live() -> io::Result<Vec<Found>> {
        live_in(&socket::runtime_dir()?)
    }

    /// [`live`] against an explicit directory, for a caller whose helpers were pointed somewhere
    /// other than the runtime directory: a test or bench that gives its VMs a private
    /// `XDG_RUNTIME_DIR` scans `<that>/bsx` with this, where the real directory would mix in
    /// whatever else the machine is running.
    pub fn live_in(dir: &Path) -> io::Result<Vec<Found>> {
        let mut found: Vec<Found> = entries_in(dir)?
            .into_iter()
            .filter(|(_, path)| socket::is_live(path))
            .map(|(name, socket)| Found { name, socket })
            .collect();
        found.sort();
        Ok(found)
    }

    /// Removes every socket file nobody is listening on, returning how many went.
    ///
    /// Separate from [`live`] because deleting is not a side effect a lister should have: a caller
    /// asking what is running should not silently modify the directory, and a caller tidying up
    /// should have to say so.
    pub fn reap_stale() -> io::Result<usize> {
        reap_stale_in(&socket::runtime_dir()?)
    }

    /// [`reap_stale`] against an explicit directory, for the caller [`live_in`] exists for.
    pub fn reap_stale_in(dir: &Path) -> io::Result<usize> {
        let mut removed = 0;
        for (_, path) in entries_in(dir)? {
            if socket::clear_if_stale(&path)? {
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Every `<name>.sock` in the runtime directory, live or not.
    ///
    /// A name that would not be accepted by [`socket::valid_name`] is skipped: the directory is
    /// this user's, but a file placed there by hand should not be able to produce a `Found` whose
    /// name cannot be passed back into the API that produced it.
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
        ] {
            assert!(
                argv.contains(&expected.to_string()),
                "{expected} missing from {argv:?}"
            );
        }
    }

    /// An absent option contributes no flag at all, rather than an empty one the parser would then
    /// have to interpret.
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

    /// The claim that matters about spawning: the program is **this executable**, resolved through
    /// `current_exe`, not the string "bsx" handed to a `PATH` search. Checked on the `Command`
    /// rather than on a spawned child, which would race the child's exit before `/proc` could be
    /// read and turn a real assertion into a flaky one.
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

    /// The recursion guard. A binary that links this crate and forgets to dispatch the helper
    /// subcommand re-executes itself, which spawns again, without bound; the marker turns that into
    /// one refusal. Asserted with the variable set, because that is the state a helper is in.
    ///
    /// Driven through the pure half rather than `Vm::spawn`, so a regression fails here instead of
    /// by filling the machine with processes.
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

    /// A VM that ended on its own is still reported honestly by `stop`, rather than the race being
    /// hidden: the child is reaped here, so `stop` has a real status to hand back and does not
    /// invent one. This is the common case for a short workload, where the guest finishes between
    /// the caller deciding to stop it and the signal landing.
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
        // Wait for it to exit *without* reaping through `try_wait`, so `stop` meets a finished but
        // unreaped child, which is exactly the race being modelled. An unreaped exit shows as a
        // zombie in `/proc`, so that is what is polled for: a fixed sleep was watched losing this
        // race under a loaded gate run and reporting the kill it caused as the failure.
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

    /// Dropping a `Vm` must not leave the helper running. Spawns something long-lived, drops it,
    /// and asks the kernel whether the pid is gone.
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

    /// Whether `pid` still exists as a live (non-zombie) process, read from `/proc` rather than
    /// with a signal: a reaped child's pid can be reused, and this test is asserting on the exact
    /// pid it spawned.
    fn pid_is_live(pid: u32) -> bool {
        let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
            return false;
        };
        !status
            .lines()
            .any(|l| l.starts_with("State:") && l.contains('Z'))
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
        drop(UnixListener::bind(d.join("ended.sock")).expect("bind then drop"));
        // Not a socket at all, and a socket whose name could not be passed back into the API.
        std::fs::write(d.join("notes.txt"), b"not a vm").expect("write a stray file");
        drop(UnixListener::bind(d.join("bad name.sock")).expect("bind a badly named socket"));

        let found = discover::live_in(d).expect("scan the directory");
        let names: Vec<&str> = found.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            ["alive"],
            "only the listening, well-named socket is a VM"
        );
        assert_eq!(found[0].socket, d.join("alive.sock"));
    }

    /// Listing must not delete. A caller asking what is running should not quietly change the
    /// directory, so the leftover survives a scan and only `reap_stale` removes it.
    #[test]
    fn a_scan_does_not_remove_leftovers_but_reaping_does() {
        let dir = bsx_test_support::ScratchDir::created("discover-reap");
        let d = dir.path();
        let leftover = d.join("ended.sock");
        let _listener = UnixListener::bind(d.join("alive.sock")).expect("bind the live one");
        drop(UnixListener::bind(&leftover).expect("bind then drop"));

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
