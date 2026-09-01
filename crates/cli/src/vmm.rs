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
    /// A host directory made read-write at a guest path, as `GUESTDIR=HOSTDIR` (the same
    /// guest-thing=host-thing direction as `--share`). Repeatable. Mounting needs `/bin/sh` and
    /// `mount` in the guest image, because the workload is wrapped in a mount preamble.
    #[arg(long = "mount", value_name = "GUESTDIR=HOSTDIR")]
    pub(crate) mounts: Vec<String>,
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

/// A `GUESTDIR=HOSTDIR` mount spec split at its **first** `=`, so a host path containing `=`
/// survives. The guest path must be absolute (it names a mount point inside the guest, and a
/// relative one would mean "relative to wherever init happens to be") and must not be `/`
/// itself: mounting over the guest root mid-boot shadows the running system, which is never
/// what a project mount meant.
pub(crate) fn split_mount(spec: &str) -> Option<(&Path, &Path)> {
    let (guest, host) = spec.split_once('=')?;
    if !guest.starts_with('/') || guest == "/" || host.is_empty() {
        return None;
    }
    Some((Path::new(guest), Path::new(host)))
}

/// `s` as a single-quoted shell word, safe to splice into the mount preamble: the one byte a
/// single-quoted string cannot carry is `'`, which becomes `'\''`.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The virtiofs tag for mount `i`. Ours by construction, so it needs no quoting or validation
/// beyond staying under virtio's 36-byte tag limit, which the 8-byte prefix plus even a 20-digit
/// index stays inside.
fn mount_tag(i: usize) -> String {
    format!("bsx-mnt-{i}")
}

/// The `sh -c` script that creates every `--mount`'s guest directory, mounts its tag there, and
/// then becomes the real workload, with the command spliced in as single-quoted words so its
/// exit code and PATH resolution match the unwrapped exec. A failed step stops the boot loudly
/// (exit 2 on the console) rather than running the command with a directory silently missing.
///
/// **The script's grammar is dictated by the transport, not by taste.** It travels as one argv
/// entry on the kernel command line, whose codec was measured (2026-09-01, libkrun 1.19.4)
/// corrupting a space inside a double-quoted span (`a "b c" d` arrives as `a "bc" d"`) while
/// carrying single-quoted spans intact. So: one line, no double quote anywhere, every path and
/// command word through [`sh_quote`], and the usual `exec "$0" "$@"` tail replaced by splicing.
///
/// `mkdir -p` writes the mount point through the root virtiofs, so an empty directory lands in
/// the shared image tree on the host and survives the VM; `build-rootfs --verify` reads that as
/// drift, which is the honest report. `krun_fs_add_overlay_dir` was the way to avoid it and is
/// unusable: against libkrun 1.19.4 a configuration it accepted aborts the VMM inside
/// `krun_start_enter` (`InvalidAscii`, `src/vmm/src/builder.rs:1073`), measured 2026-09-01 with
/// `KRUN_FEATURE_INIT_BLOB` present.
fn mount_preamble(mounts: &[(&Path, &Path)], exec: &Path, args: &[String]) -> String {
    let mut script = String::new();
    for (i, (guest, _)) in mounts.iter().enumerate() {
        let dir = sh_quote(&guest.to_string_lossy());
        script.push_str(&format!(
            "mkdir -p {dir} && mount -t virtiofs {tag} {dir} || {{ echo 'bsx: mounting' {dir} \
             'failed' >&2; exit 2; }}; ",
            tag = mount_tag(i),
        ));
    }
    script.push_str("exec ");
    script.push_str(&sh_quote(&exec.to_string_lossy()));
    for arg in args {
        script.push(' ');
        script.push_str(&sh_quote(arg));
    }
    script
}

/// Whether `s` can ride the kernel command line, which is how libkrun hands the guest its
/// workload: **printable ASCII only**. Not a style choice: a byte outside this range aborts the
/// whole VMM inside `krun_start_enter` (`InvalidAscii`, unwrapped in libkrun's builder; measured
/// 2026-09-01 against 1.19.4 with `echo é`, a newline argument, and a non-ASCII `--env` value),
/// so the helper refuses here, where it can still be a typed error naming the byte.
fn cmdline_safe(s: &OsStr) -> bool {
    s.as_encoded_bytes()
        .iter()
        .all(|b| (0x20..=0x7e).contains(b))
}

/// Whether `s` survives the codec unchanged: the same measurement found a space inside a
/// double-quoted span silently corrupted (`a "b c" d` arrives as `a "bc" d"`), which is worse
/// than an abort because the guest runs a command nobody wrote. Refusing every entry that mixes
/// `"` with a space is deliberately wider than the observed corruption, because the codec's
/// exact grammar is libkrun's private business and a guess that under-refuses corrupts silently.
fn codec_safe(s: &OsStr) -> bool {
    let bytes = s.as_encoded_bytes();
    !(bytes.contains(&b'"') && bytes.contains(&b' '))
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
    /// A `--mount` that is not `GUESTDIR=HOSTDIR` with an absolute guest path.
    Mount(String),
    /// An exec path, argument, or environment entry with a byte the kernel command line cannot
    /// carry. Refused here because libkrun aborts the VMM on it instead of erroring.
    CmdlineByte {
        /// Which input carried it.
        what: &'static str,
        /// The offending input, lossily rendered.
        input: String,
    },
    /// More guest RAM than the host physically has. libkrun accepts it (guest RAM faults in
    /// lazily) and the guest then believes in memory no host can back, which surfaces later as
    /// the host OOMing instead of now as an error.
    MemCeiling {
        /// What the caller asked for, in MiB.
        asked_mib: u32,
        /// What the host has, in MiB.
        host_mib: u32,
    },
    /// An entry mixing `"` with a space, which libkrun's command-line codec was measured
    /// corrupting silently. Refused because a corrupted argv runs a command nobody wrote.
    CmdlineQuote {
        /// Which input carried it.
        what: &'static str,
        /// The offending input, lossily rendered.
        input: String,
    },
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
            Self::Mount(m) => write!(
                f,
                "--mount {m:?} is not GUESTDIR=HOSTDIR with an absolute guest path"
            ),
            Self::CmdlineByte { what, input } => write!(
                f,
                "{what} {input:?} carries a byte outside printable ASCII; libkrun passes the \
                 workload's argv and environment on the kernel command line and aborts on such \
                 a byte instead of reporting it"
            ),
            Self::MemCeiling {
                asked_mib,
                host_mib,
            } => write!(
                f,
                "--mem {asked_mib} asks for more RAM than this host has ({host_mib} MiB); \
                 libkrun would boot a guest believing in memory nothing can back, and the \
                 failure would arrive later as the host running out"
            ),
            Self::CmdlineQuote { what, input } => write!(
                f,
                "{what} {input:?} mixes a double quote with a space, which libkrun's \
                 command-line codec corrupts silently; rewrite it with single quotes"
            ),
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
    require_backable_mem(args.mem.get())?;
    if args.vcpus.get() > MEASURED_VCPU_CLAMP {
        eprintln!(
            "bsx __vmm: warning: libkrun was measured silently clamping vCPU counts above \
             {MEASURED_VCPU_CLAMP}; the guest may see fewer than the {} asked for",
            args.vcpus
        );
    }
    let mut mounts = Vec::with_capacity(args.mounts.len());
    for spec in &args.mounts {
        let (guest, host) = split_mount(spec).ok_or_else(|| HelperError::Mount(spec.clone()))?;
        require_dir("a mount", host)?;
        mounts.push((guest, host));
    }

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
    for (i, (_, host)) in mounts.iter().enumerate() {
        // The device carrying the host directory; the guest path is the preamble's business.
        machine = machine.share(&mount_tag(i), host)?;
    }
    if let Some((port, path)) = vsock {
        // `listen = true` per the header: the guest listens on the port and connections are
        // initiated from the host side, which is the agent-channel direction.
        machine = machine.vsock_port(port, path, true)?;
    }
    if let Some(dir) = &args.workdir {
        machine = machine.workdir(dir)?;
    }

    let env: Vec<&OsStr> = args.env.iter().map(OsStr::new).collect();
    require_cmdline_safe("the exec path", args.exec.as_os_str())?;
    for arg in &args.args {
        require_cmdline_safe("a guest argument", OsStr::new(arg))?;
    }
    for entry in &env {
        require_cmdline_safe("a guest environment entry", entry)?;
    }
    machine = if mounts.is_empty() {
        let argv: Vec<&OsStr> = args.args.iter().map(OsStr::new).collect();
        machine.exec(&args.exec, &argv, &env)?
    } else {
        // The workload becomes `sh -c '<mounts>; exec <command, quoted>'`: the mounts land
        // before anything of the caller's runs, and the `exec` hands the process over with the
        // exit code and PATH resolution the unwrapped form had.
        let script = mount_preamble(&mounts, &args.exec, &args.args);
        // Covers the guest mount paths, which are spliced into the script.
        require_cmdline_safe("the mount preamble", OsStr::new(&script))?;
        let argv: Vec<&OsStr> = vec![OsStr::new("-c"), OsStr::new(&script)];
        machine.exec(Path::new("/bin/sh"), &argv, &env)?
    };

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

/// libkrun was **measured** (2026-09-01, 1.19.4, an 8-CPU host) silently clamping the vCPU count
/// above this: 16 boots as 16, 17 and 24 boot as 16, and the config never learns. Above it the
/// helper warns rather than refuses, because the bound may be different libkrun code or other
/// hardware, and a warning stays true either way.
const MEASURED_VCPU_CLAMP: u8 = 16;

/// Host `MemTotal` in MiB, where the host exposes it. A host without a readable `/proc/meminfo`
/// is left unchecked rather than guessed at: this is a capability probe, not a platform branch.
fn host_mem_mib() -> Option<u32> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let kib: u64 = meminfo
        .lines()
        .find(|l| l.starts_with("MemTotal:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    u32::try_from(kib / 1024).ok()
}

/// Refuses a `--mem` this host cannot physically back. Overcommit *across* VMs stays legal
/// (guest RAM faults in lazily, which is what lets a cohort of idle VMs share a laptop); what is
/// refused is a single machine larger than the host, which can never be honest.
fn require_backable_mem(asked_mib: u32) -> Result<(), HelperError> {
    match host_mem_mib() {
        Some(host_mib) if asked_mib > host_mib => Err(HelperError::MemCeiling {
            asked_mib,
            host_mib,
        }),
        _ => Ok(()),
    }
}

/// Refuses an input the kernel command line cannot carry. See [`cmdline_safe`] for why this is a
/// crash guard rather than a style rule.
fn require_cmdline_safe(what: &'static str, s: &OsStr) -> Result<(), HelperError> {
    if !cmdline_safe(s) {
        return Err(HelperError::CmdlineByte {
            what,
            input: s.to_string_lossy().into_owned(),
        });
    }
    if !codec_safe(s) {
        return Err(HelperError::CmdlineQuote {
            what,
            input: s.to_string_lossy().into_owned(),
        });
    }
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

    /// The preamble is what runs before the caller's command: one line, no double quote anywhere
    /// (the two constraints the cmdline codec was measured breaking), every mount and every
    /// command word single-quoted, and the tail an `exec` into the caller's command.
    #[test]
    fn the_mount_preamble_mounts_each_tag_then_becomes_the_workload() {
        let mounts = vec![
            (Path::new("/project"), Path::new("/srv/a")),
            (Path::new("/it's here"), Path::new("/srv/b")),
        ];
        // The command's own words go through `sh_quote` like the paths, so a word with spaces
        // or quotes is data. (A word mixing `"` with a space never reaches here: the codec
        // guard refuses it for every workload, wrapped or not.)
        let script = mount_preamble(
            &mounts,
            Path::new("sh"),
            &["-c".to_string(), "echo 'x y'".to_string()],
        );
        assert!(
            !script.contains('\n'),
            "one line, or the cmdline aborts: {script}"
        );
        assert!(
            !script.contains('"'),
            "no double quote, or the codec corrupts it: {script}"
        );
        assert!(script.contains("mkdir -p '/project' && mount -t virtiofs bsx-mnt-0 '/project'"));
        assert!(
            script.contains("'/it'\\''s here'"),
            "a quote in a guest path is escaped, not spliced: {script}"
        );
        assert!(
            script.ends_with(r#"exec 'sh' '-c' 'echo '\''x y'\'''"#),
            "the command is spliced in quoted, so its own quotes are data: {script}"
        );
    }

    /// A mount spec is guest=host with an absolute guest path; anything else is refused.
    #[test]
    fn a_mount_spec_requires_an_absolute_guest_path() {
        let (guest, host) = split_mount("/project=/srv/a=b").expect("well-formed");
        assert_eq!(guest, Path::new("/project"));
        assert_eq!(host, Path::new("/srv/a=b"));
        assert!(split_mount("project=/srv/a").is_none(), "relative guest");
        assert!(
            split_mount("/=/srv/a").is_none(),
            "mounting over the guest root is refused"
        );
        assert!(split_mount("/project=").is_none(), "no host");
        assert!(split_mount("/project").is_none(), "no separator");
    }

    /// A machine larger than the host is refused with both numbers, because the alternative is
    /// a guest that believes in RAM nothing can back and a failure that arrives as the host
    /// OOMing later. Driven with a fabricated host size, since the check itself reads the real
    /// one.
    #[test]
    fn a_mem_ask_beyond_the_host_is_refused_with_both_numbers() {
        if let Some(host) = host_mem_mib() {
            let err = require_backable_mem(host.saturating_add(1))
                .expect_err("one MiB past the host must refuse");
            let msg = err.to_string();
            assert!(
                msg.contains(&host.to_string()),
                "names the host size: {msg}"
            );
            require_backable_mem(host).expect("exactly the host size passes");
            require_backable_mem(1).expect("a small machine passes");
        } else {
            println!(
                "SKIPPED a_mem_ask_beyond_the_host_is_refused_with_both_numbers: this host \
                 exposes no readable MemTotal, so the ceiling is not checked here"
            );
        }
    }

    /// The crash guard: a byte outside printable ASCII in the workload's argv aborts the whole
    /// VMM inside libkrun, so it must be refused before entering, with the input named.
    #[test]
    fn a_byte_the_cmdline_cannot_carry_is_refused_not_aborted_on() {
        for ok in ["echo", "hi there", "a=\"b\"; $x | { y; }"] {
            assert!(cmdline_safe(OsStr::new(ok)), "{ok:?} should pass");
        }
        for bad in ["\u{e9}", "a\nb", "tab\the", "nul\0"] {
            assert!(!cmdline_safe(OsStr::new(bad)), "{bad:?} must be refused");
        }
        let err = require_cmdline_safe("a guest argument", OsStr::new("\u{e9}"))
            .expect_err("must refuse");
        let msg = err.to_string();
        assert!(msg.contains("kernel command line"), "says why: {msg}");
        assert!(msg.contains("aborts"), "names the stake: {msg}");
    }

    /// The codec guard: a space inside a double-quoted span was measured arriving corrupted
    /// (`a "b c" d` as `a "bc" d"`), so anything mixing `"` with a space is refused with the
    /// rewrite named. Wider than the observed corruption on purpose.
    #[test]
    fn an_entry_the_codec_would_corrupt_is_refused_with_the_rewrite_named() {
        assert!(codec_safe(OsStr::new("a\"b")), "a quote alone is fine");
        assert!(codec_safe(OsStr::new("a b c")), "spaces alone are fine");
        assert!(
            codec_safe(OsStr::new("echo 'x y'")),
            "single quotes carry spaces"
        );
        assert!(
            !codec_safe(OsStr::new("a \"b c\" d")),
            "the measured corruption"
        );
        let err = require_cmdline_safe("a guest argument", OsStr::new("echo \"x y\""))
            .expect_err("must refuse");
        assert!(err.to_string().contains("single quotes"), "{err}");
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
