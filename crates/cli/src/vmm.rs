//! `bsx __vmm`, the hidden subcommand that **becomes** a virtual machine.
//!
//! `krun_start_enter` does not return: it takes over the calling process and exits with the guest's
//! status. So a VM is not a thread or an object a supervisor holds, it is a *process*, and this
//! module is what that process runs. Everything else in phase 2 follows from that one fact.
//!
//! - **Hidden, not private.** `#[command(hide = true)]` keeps it out of `--help` because it is not
//!   a verb anyone types, but it stays a normal subcommand: a caller debugging a boot can run it by
//!   hand and see exactly what the supervisor would have run.
//! - **Reached through `current_exe()`, never `PATH`.** A supervisor that spawned `bsx` by name
//!   would run whatever `PATH` resolved to, which on a shared host is somebody else's binary. The
//!   helper is *this* executable, re-executed; the spawn side of that lives in the supervisor
//!   (`scratch/ROADMAP.md` 2.4), and this module is only the side that gets re-executed.
//! - **The config arrives as arguments**, not as a file or a socket. It is inspectable in `ps`,
//!   which is a debugging property worth having now and a problem to revisit when a sandbox can
//!   carry a secret (`scratch/ROADMAP.md` phase 3): argv is world-readable on Linux.
//! - **Its exit code is the guest's**, because libkrun exits the process for us. The only codes
//!   this module chooses are the ones for failing before the guest ever runs.
//!
//! **A VM that cannot run anything still boots and exits 0.** libkrun defers its filesystem checks
//! to boot: given a root that does not exist it starts, serves an empty tree, finds no init, and
//! exits successfully in about 280 ms. That is indistinguishable to a supervisor from a guest that
//! ran and succeeded, so the host paths are checked *here*, before entering, where a bad one can
//! still be an error. It closes the cheap half of the problem and not the whole of it: a root that
//! exists but carries no working init boots and exits 0 exactly the same way, and only something
//! in-guest (phase 3's agent and its readiness marker) can tell those apart.

use std::ffi::OsStr;
use std::num::{NonZeroU8, NonZeroU32};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;

#[cfg(test)]
use crate::{Cli, Cmd};

/// The subcommand name, declared once here so the supervisor that spawns it and the parser that
/// reads it cannot drift into a binary invoked with a subcommand it does not have.
pub(crate) const HELPER_SUBCOMMAND: &str = "__vmm";

/// Everything the helper needs to build a machine and enter it.
///
/// Flat and repeatable rather than a nested config format: a `--share` given twice is two shares,
/// which keeps the wire between supervisor and helper inspectable with no parser of our own.
#[derive(Args, Debug)]
pub(crate) struct VmmArgs {
    /// The host directory served as the guest's root over virtiofs.
    #[arg(long, value_name = "DIR")]
    pub(crate) root: PathBuf,
    /// vCPUs. libkrun's own ceiling is a `u8`, and zero is not a machine.
    #[arg(long, default_value = "1")]
    pub(crate) vcpus: NonZeroU8,
    /// Guest RAM in MiB.
    #[arg(long, value_name = "MIB", default_value = "512")]
    pub(crate) mem: NonZeroU32,
    /// The program to run inside the guest.
    #[arg(long, value_name = "PROG")]
    pub(crate) exec: PathBuf,
    /// The guest working directory.
    #[arg(long, value_name = "DIR")]
    pub(crate) workdir: Option<PathBuf>,
    /// An argument for the guest program, after the program name. Repeatable, order preserved.
    #[arg(long = "arg", value_name = "ARG", allow_hyphen_values = true)]
    pub(crate) args: Vec<String>,
    /// A `KEY=VALUE` entry for the guest environment. Repeatable.
    #[arg(long = "env", value_name = "KEY=VALUE")]
    pub(crate) env: Vec<String>,
    /// An extra virtiofs share as `TAG=HOSTPATH`. Repeatable.
    #[arg(long = "share", value_name = "TAG=HOSTPATH")]
    pub(crate) shares: Vec<String>,
    /// The VM's name, which is also its control socket's filename. Without it the VM runs but is
    /// invisible to `ls`, which is the right default for a helper run by hand.
    #[arg(long, value_name = "NAME")]
    pub(crate) name: Option<String>,
    /// A vsock mapping as `PORT=HOSTSOCKET`: the guest listens on the vsock port, and a host
    /// process reaches it by connecting to the unix socket.
    #[arg(long, value_name = "PORT=HOSTSOCKET")]
    pub(crate) vsock: Option<String>,
}

/// A `TAG=HOSTPATH` share split at its **first** `=`, so a host path containing `=` survives.
/// `None` when there is no separator or either half is empty, which the caller reports rather than
/// silently mounting something unintended.
pub(crate) fn split_share(spec: &str) -> Option<(&str, &Path)> {
    let (tag, path) = spec.split_once('=')?;
    if tag.is_empty() || path.is_empty() {
        return None;
    }
    Some((tag, Path::new(path)))
}

/// A `PORT=HOSTSOCKET` vsock spec split at its **first** `=`, so a socket path containing `=`
/// survives. `None` when the port is not a number or the path is empty.
pub(crate) fn split_vsock(spec: &str) -> Option<(u32, &Path)> {
    let (port, path) = spec.split_once('=')?;
    if path.is_empty() {
        return None;
    }
    Some((port.parse().ok()?, Path::new(path)))
}

/// Whether `entry` can be a guest environment entry: an `=` with a non-empty key. The value may
/// be empty, because `FOO=` is how an environment unsets-but-keeps a variable.
pub(crate) fn well_formed_env(entry: &str) -> bool {
    matches!(entry.split_once('='), Some((key, _)) if !key.is_empty())
}

/// Build the machine and enter it. **Returns only on failure**, mirroring the wrapper's own
/// `enter`, because a success means this process is now the guest and will exit with its status.
pub(crate) fn run(args: &VmmArgs) -> ExitCode {
    match build_and_enter(args) {
        Ok(never) => match never {},
        Err(e) => {
            eprintln!("bsx __vmm: {e}");
            ExitCode::from(crate::EXIT_OPERATIONAL)
        }
    }
}

/// The failure this helper can report: a bad argument it refuses, or libkrun declining to start.
#[derive(Debug)]
enum HelperError {
    /// A host path that is not a directory. Checked here because libkrun would accept it and boot
    /// an empty machine that exits 0, which a supervisor reads as success.
    NotADirectory {
        /// Which argument named it, so the message says whether it was the root or a share.
        what: &'static str,
        /// The path as given.
        path: PathBuf,
    },
    /// A `--share` that is not `TAG=HOSTPATH`.
    Share(String),
    /// A `--env` that is not `KEY=VALUE`.
    Env(String),
    /// A `--vsock` that is not `PORT=HOSTSOCKET`.
    Vsock(String),
    /// The control socket could not be placed or bound.
    Socket(std::io::Error),
    /// libkrun refused a call, including the one that was supposed to never return.
    Krun(bsx_krun::Error),
}

impl std::fmt::Display for HelperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotADirectory { what, path } => write!(
                f,
                "{what} {} is not a directory; libkrun would boot an empty machine and exit 0",
                path.display()
            ),
            Self::Share(s) => write!(f, "--share {s:?} is not TAG=HOSTPATH"),
            Self::Vsock(v) => write!(f, "--vsock {v:?} is not PORT=HOSTSOCKET"),
            Self::Env(e) => write!(
                f,
                "--env {e:?} is not KEY=VALUE; the guest's environ would carry it as a string \
                 no libc parses back"
            ),
            Self::Socket(e) => write!(f, "the control socket: {e}"),
            Self::Krun(e) => write!(f, "{e}"),
        }
    }
}

impl From<bsx_krun::Error> for HelperError {
    fn from(e: bsx_krun::Error) -> Self {
        Self::Krun(e)
    }
}

/// Returns `Infallible` in the `Ok` position: there is no success value because a successful start
/// never comes back here. The type says so, so nobody writes code after it.
fn build_and_enter(args: &VmmArgs) -> Result<std::convert::Infallible, HelperError> {
    // Every argument is checked before the control socket is bound, so a refused invocation does
    // not leave a socket file behind for a VM that never existed. A *libkrun* failure after the
    // bind still leaves one, which is the leftover the supervisor's stale check exists for.
    require_dir("the root", &args.root)?;
    let mut shares = Vec::with_capacity(args.shares.len());
    for spec in &args.shares {
        let (tag, path) = split_share(spec).ok_or_else(|| HelperError::Share(spec.clone()))?;
        require_dir("a share", path)?;
        shares.push((tag, path));
    }
    for entry in &args.env {
        if !well_formed_env(entry) {
            return Err(HelperError::Env(entry.clone()));
        }
    }
    let vsock = args
        .vsock
        .as_deref()
        .map(|spec| split_vsock(spec).ok_or_else(|| HelperError::Vsock(spec.to_string())))
        .transpose()?;

    // Bound **before** entering, and served from a thread, because `krun_start_enter` never gives
    // this one back. That other threads keep running under it is not an assumption: a C program
    // with a ticker thread was watched printing straight through a guest's boot, life and exit.
    //
    // The listener moves into its accept thread and nothing here holds it. libkrun exits the
    // process when the guest ends, which does not unwind, so there is nothing a `Drop` here could
    // clean up: the socket file outliving this process is the normal case, and the supervisor's
    // stale check is what handles it.
    if let Some(name) = args.name.as_deref() {
        bind_control_socket(name)?;
    }

    let mut machine = bsx_krun::Context::new()?
        .root(&args.root)?
        .vm_config(args.vcpus, args.mem)?;

    for (tag, path) in shares {
        machine = machine.share(tag, path)?;
    }
    if let Some((port, path)) = vsock {
        // `listen = true` per the header: the guest listens on the port and connections are
        // initiated from the host side, which is the agent-channel direction.
        machine = machine.vsock_port(port, path, true)?;
    }
    if let Some(dir) = &args.workdir {
        machine = machine.workdir(dir)?;
    }

    let argv: Vec<&OsStr> = args.args.iter().map(OsStr::new).collect();
    let env: Vec<&OsStr> = args.env.iter().map(OsStr::new).collect();
    machine = machine.exec(&args.exec, &argv, &env)?;

    // Past here the process either becomes the guest or reports why it could not.
    Err(HelperError::Krun(machine.enter()))
}

/// Binds this VM's control socket and serves it from a background thread.
///
/// Accepts and closes: the verbs that will travel over it are phase 3's (`scratch/ROADMAP.md` 3.8).
/// What it provides today is exactly what discovery needs, which is a socket that answers while the
/// VM is alive and refuses once it is not.
fn bind_control_socket(name: &str) -> Result<(), HelperError> {
    let path = bsx_supervisor::socket::path_for(name).map_err(HelperError::Socket)?;
    // A leftover from a previous helper with this name would make `bind` fail with EADDRINUSE. Only
    // cleared when nothing is listening, so a name genuinely in use still refuses.
    bsx_supervisor::socket::clear_if_stale(&path).map_err(HelperError::Socket)?;
    let listener = std::os::unix::net::UnixListener::bind(&path).map_err(HelperError::Socket)?;
    // `bind` applies the umask, which commonly leaves the socket world-connectable. The runtime
    // directory is already `0700`, so this is the second lock rather than the only one: a directory
    // whose mode is loosened later should not silently expose every VM's control channel.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(HelperError::Socket)?;

    std::thread::Builder::new()
        .name(format!("bsx-ctl-{name}"))
        .spawn(move || {
            // Accept forever. A caller that connects gets a closed connection, which is enough to
            // answer "is this VM alive". Errors are ignored rather than logged: this thread has no
            // way to report anything once the main thread is a guest, and a panic here would take
            // down a running VM over a failed accept.
            for stream in listener.incoming() {
                drop(stream);
            }
        })
        .map_err(HelperError::Socket)?;
    Ok(())
}

/// Refuses a host path that is not a directory, before it can become a machine that boots into
/// nothing. Follows symlinks (`is_dir`, not `symlink_metadata`) because a link to a real directory
/// is a perfectly good root and libkrun would resolve it the same way.
fn require_dir(what: &'static str, path: &Path) -> Result<(), HelperError> {
    if path.is_dir() {
        return Ok(());
    }
    Err(HelperError::NotADirectory {
        what,
        path: path.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    // `panic!` is the assertion in the let-else arm below; the tree-wide deny is for the host
    // path, and this module is not on it.
    #![allow(clippy::panic)]

    use super::*;

    /// The check that stops a silent success. Without it libkrun boots, finds nothing, and exits 0,
    /// which is the one failure a supervisor cannot see.
    #[test]
    fn a_root_that_is_not_a_directory_is_refused_before_boot() {
        let missing = Path::new("/nonexistent-bsx-root");
        let err = require_dir("the root", missing).expect_err("a missing root cannot boot");
        assert!(
            matches!(&err, HelperError::NotADirectory { what, path }
                if *what == "the root" && path == missing),
            "got {err:?}"
        );
        assert!(
            err.to_string().contains("exit 0"),
            "the message says why it matters: {err}"
        );
        // A file is not a directory either, and is the likelier mistake of the two.
        assert!(require_dir("the root", Path::new("/etc/hostname")).is_err());
        require_dir("the root", Path::new("/tmp")).expect("a real directory passes");
    }

    /// A host path may contain `=`, so the split is at the first separator and not the last. A
    /// rightmost split would mount `/opt/a` under the tag `data=/opt` and look like it worked.
    #[test]
    fn a_share_splits_at_the_first_separator() {
        let (tag, path) = split_share("data=/opt/a=b").expect("a well-formed share");
        assert_eq!(tag, "data");
        assert_eq!(path, Path::new("/opt/a=b"));
    }

    /// Half a share is refused rather than mounted as something else.
    #[test]
    fn a_share_missing_either_half_is_refused() {
        assert!(split_share("data").is_none(), "no separator");
        assert!(split_share("=/opt").is_none(), "no tag");
        assert!(split_share("data=").is_none(), "no path");
    }

    /// A vsock spec is a port and a socket path; half of one, or a port that is not a number, is
    /// refused rather than mapped as something else.
    #[test]
    fn a_vsock_spec_parses_its_port_and_survives_equals_in_the_path() {
        let (port, path) = split_vsock("1024=/run/a=b.sock").expect("well-formed");
        assert_eq!(port, 1024);
        assert_eq!(path, Path::new("/run/a=b.sock"));
        assert!(split_vsock("notaport=/run/x").is_none());
        assert!(split_vsock("1024=").is_none());
        assert!(split_vsock("1024").is_none());
    }

    /// An env entry without a `=` is refused rather than handed to the guest as a string no libc
    /// would parse back out of environ. An empty *value* stays legal, because `FOO=` is ordinary.
    #[test]
    fn an_env_entry_that_is_not_key_value_is_refused() {
        assert!(well_formed_env("KEY=value"));
        assert!(well_formed_env("KEY="), "an empty value is a real entry");
        assert!(well_formed_env("KEY=a=b"), "values may carry their own =");
        assert!(!well_formed_env("KEY"), "no separator");
        assert!(!well_formed_env("=value"), "no key");
        assert!(!well_formed_env(""), "empty");
    }

    /// Every flag the supervisor will write has to parse back into the field it meant. Exercised
    /// through the real parser rather than by reading the `#[arg]` attributes, and including a
    /// share whose host path contains `=`, which is the case a rightmost split would corrupt.
    ///
    /// The writing half is the supervisor's (2.4). Two spellings with no dependency edge between
    /// them is exactly what `xtask`'s lints are for, and that pin lands with the writer.
    #[test]
    fn every_helper_flag_parses_into_the_field_it_names() {
        use clap::Parser;

        let argv = [
            "bsx",
            HELPER_SUBCOMMAND,
            "--root",
            "/srv/root",
            "--vcpus",
            "2",
            "--mem",
            "1024",
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
            "--vsock",
            "1024=/run/agent.sock",
        ];
        let parsed = Cli::parse_from(argv);
        let Cmd::Vmm(got) = parsed.cmd else {
            panic!("the helper subcommand parses as itself");
        };

        assert_eq!(got.root, Path::new("/srv/root"));
        assert_eq!(got.exec, Path::new("/bin/sh"));
        assert_eq!(got.workdir.as_deref(), Some(Path::new("/work")));
        assert_eq!(got.vcpus.get(), 2);
        assert_eq!(got.mem.get(), 1024);
        assert_eq!(got.args, vec!["-c".to_string(), "echo hi".to_string()]);
        assert_eq!(got.env, vec!["KEY=value".to_string()]);
        let (tag, path) = split_share(&got.shares[0]).expect("the share parses");
        assert_eq!((tag, path), ("data", Path::new("/opt/a=b")));
        let (port, sock) =
            split_vsock(got.vsock.as_deref().expect("the vsock spec parses")).expect("well-formed");
        assert_eq!((port, sock), (1024, Path::new("/run/agent.sock")));
    }
}
