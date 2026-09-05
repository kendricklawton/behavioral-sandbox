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
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex, OnceLock};

use clap::Args;

#[cfg(test)]
use crate::{Cli, Cmd};

/// The scanout a display's lease and window show: libkrun numbers them from zero and one
/// display makes one.
const SCANOUT: u32 = 0;

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
    /// The network posture: `none` (default), or `tsi` for libkrun's transparent host-socket
    /// proxying. Off by default, because libkrun's own default (an implicit vsock with TSI
    /// hijacking) is not.
    #[arg(long, value_name = "POSTURE", default_value = "none")]
    pub(crate) net: NetPosture,
    /// What the guest may do to the image tree it boots from: `read-only` (default) or
    /// `writable`. The tree is shared by every sandbox on this host, so a writable root is a
    /// guest editing what the next guest starts from.
    #[arg(long, value_name = "POSTURE", default_value = "read-only")]
    pub(crate) rootfs: RootFsPosture,
    /// A display as `WIDTHxHEIGHT[@HZ]`, shown in a window this process opens, whose keyboard and
    /// pointer reach the guest as two input devices. Without a display server the display still
    /// runs and the window is skipped.
    #[arg(long, value_name = "WIDTHxHEIGHT[@HZ]")]
    pub(crate) display: Option<String>,
    /// Keep this file holding the display's latest frame as a binary PPM. Needs `--display`.
    #[arg(long, value_name = "PATH")]
    pub(crate) screenshot: Option<PathBuf>,
    /// Append one `frame_id<TAB>nanoseconds` line to this file per frame the display thread
    /// sees. Needs `--display`.
    #[arg(long, value_name = "PATH")]
    pub(crate) frame_log: Option<PathBuf>,
    /// Give the guest a virtio-snd sound card, backed by the host's audio server. Off by default:
    /// audio is a two-way hole (the guest plays to your output and can capture from your input),
    /// so it is opened only when asked. Refused before boot if this libkrun has no snd feature.
    #[arg(long)]
    pub(crate) sound: bool,
    /// Give the guest's virtio-gpu the 3D path (virgl + Venus) into the host renderer, with or
    /// without --display. Off by default: guest-issued GPU commands are a wider hole than a
    /// display's pixel path. Refused before boot if this libkrun has no gpu feature.
    #[arg(long)]
    pub(crate) gpu: bool,
}

/// What the guest may do to its root filesystem, [`ReadOnly`](RootFsPosture::ReadOnly) by default
/// because one image tree boots every sandbox. Enforced by the virtiofs device, so the guest can
/// neither undo nor see it: `/proc/mounts` still reports the root `rw`.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) enum RootFsPosture {
    /// Guest writes to the root fail with `EROFS`. Writable state comes from a `--mount`.
    #[default]
    ReadOnly,
    /// Guest writes go through to the shared image tree and outlive the VM.
    Writable,
}

/// What the guest's network reaches. The default is [`None`](NetPosture::None) because libkrun's
/// default is not: it adds an implicit vsock whose TSI hijacking proxies the guest's sockets onto
/// the host, so "say nothing" means "the guest can reach the host's network" unless this says no.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) enum NetPosture {
    /// No network: the implicit vsock is replaced by an explicit one with no TSI hijacking, so
    /// the guest has loopback and nothing else.
    #[default]
    None,
    /// libkrun's transparent socket impersonation (`KRUN_TSI_HIJACK_INET`): the guest's inet
    /// socket calls are proxied through the host, so it reaches whatever the host can, including
    /// host loopback. Opt-in and named, not a silent default.
    Tsi,
}

impl NetPosture {
    /// The supervisor's spelling of this posture, for the control socket's answer.
    fn into_net(self) -> bsx_supervisor::Net {
        match self {
            Self::None => bsx_supervisor::Net::None,
            Self::Tsi => bsx_supervisor::Net::Tsi,
        }
    }
}

impl RootFsPosture {
    /// The supervisor's spelling of this posture, for the control socket's answer.
    fn into_rootfs(self) -> bsx_supervisor::RootFs {
        match self {
            Self::ReadOnly => bsx_supervisor::RootFs::ReadOnly,
            Self::Writable => bsx_supervisor::RootFs::Writable,
        }
    }

    /// The virtiofs device flag this posture is.
    fn into_access(self) -> bsx_krun::FsAccess {
        match self {
            Self::ReadOnly => bsx_krun::FsAccess::ReadOnly,
            Self::Writable => bsx_krun::FsAccess::ReadWrite,
        }
    }
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

/// A `WIDTHxHEIGHT` or `WIDTHxHEIGHT@HZ` display spec as `(width, height, refresh)`, or `None`
/// for anything whose numbers are not all non-zero.
pub(crate) fn split_display(spec: &str) -> Option<(NonZeroU32, NonZeroU32, Option<NonZeroU32>)> {
    let mode = bsx_record::DisplayMode::parse(spec)?;
    Some((mode.width, mode.height, mode.refresh))
}

/// A `GUESTDIR=HOSTDIR` mount spec split at its **first** `=`, so a host path containing `=`
/// survives. The guest path must be absolute, must not be `/`, and must carry no `..`, since
/// [`mount_point_in_image`] resolves it against the host's image tree.
pub(crate) fn split_mount(spec: &str) -> Option<(&Path, &Path)> {
    let (guest, host) = spec.split_once('=')?;
    if !guest.starts_with('/') || guest == "/" || host.is_empty() {
        return None;
    }
    let guest = Path::new(guest);
    if guest
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        return None;
    }
    Some((guest, Path::new(host)))
}

/// Where a `--mount`'s guest path lands in the host's image tree, which is the same tree the VM
/// serves as the guest's root. Used to check the mount point exists before boot; the guest path
/// is absolute and `..`-free by [`split_mount`], so this stays inside `root`.
fn mount_point_in_image(root: &Path, guest: &Path) -> PathBuf {
    root.join(guest.strip_prefix("/").unwrap_or(guest))
}

/// `s` as a single-quoted shell word, safe to splice into the mount preamble: the one byte a
/// single-quoted string cannot carry is `'`, which becomes `'\''`.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The prefix every tag this helper invents carries, and which a caller's `--share` may not use.
///
/// **The tag is what the guest mounts by**, so two devices sharing one leave the kernel matching
/// whichever it saw first, silently.
const RESERVED_TAG_PREFIX: &str = "bsx-";

/// The virtiofs tag for mount `i`. Ours by construction, since [`RESERVED_TAG_PREFIX`] is refused
/// to callers, so it needs no quoting or validation beyond staying under virtio's 36-byte tag
/// limit, which the prefix plus even a 20-digit index stays inside.
fn mount_tag(i: usize) -> String {
    format!("{RESERVED_TAG_PREFIX}mnt-{i}")
}

/// The `sh -c` script that mounts every `--mount` tag and becomes the workload, exiting 2 on a
/// failed step. **The grammar is the transport's**: one argv entry whose codec corrupts a space
/// inside a double-quoted span, so one line, no double quote, every word through [`sh_quote`].
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

/// Whether `s` can ride the kernel command line: **printable ASCII only**, because a byte outside
/// that range aborts the VMM inside `krun_start_enter`. Refused here, where it is a typed error.
fn cmdline_safe(s: &OsStr) -> bool {
    s.as_encoded_bytes()
        .iter()
        .all(|b| (0x20..=0x7e).contains(b))
}

/// Whether `s` survives the codec unchanged: a space inside a double-quoted span is corrupted
/// silently, so the guest would run a command nobody wrote. Refusing every `"`-with-space entry
/// is wider than the observed corruption, because under-refusing is silent.
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

/// Which input a refusal is about, so a message names it and a caller cannot misspell it.
///
/// The words are the message's, not an identifier's: they land mid-sentence in [`HelperError`]'s
/// `Display`, which is why they carry their own article.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Subject {
    Root,
    Share,
    Mount,
    ExecPath,
    GuestArgument,
    GuestEnv,
    MountPreamble,
}

impl Subject {
    /// How a message names this input.
    fn as_words(self) -> &'static str {
        match self {
            Self::Root => "the root",
            Self::Share => "a share",
            Self::Mount => "a mount",
            Self::ExecPath => "the exec path",
            Self::GuestArgument => "a guest argument",
            Self::GuestEnv => "a guest environment entry",
            Self::MountPreamble => "the mount preamble",
        }
    }
}

impl std::fmt::Display for Subject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_words())
    }
}

/// The failure this helper can report: a bad argument it refuses, or libkrun declining to start.
#[derive(Debug)]
enum HelperError {
    /// A host path that is not a directory. Checked here because libkrun would accept it and boot
    /// an empty machine that exits 0, which a supervisor reads as success.
    NotADirectory {
        /// Which argument named it, so the message says whether it was the root or a share.
        what: Subject,
        /// The path as given.
        path: PathBuf,
    },
    /// A `--share` that is not `TAG=HOSTPATH`.
    Share(String),
    /// A `--share` whose tag is one this helper invents for itself, which would leave the guest
    /// mounting whichever device the kernel matched first.
    ReservedTag(String),
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
        what: Subject,
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
        what: Subject,
        /// The offending input, lossily rendered.
        input: String,
    },
    /// A `--mount` whose guest path is not a directory in the image, under a read-only root the
    /// guest cannot create it on. Refused before boot so the report names the fix, rather than
    /// arriving as the preamble's exit 2 on a console.
    MountPointMissing {
        /// The guest path asked for.
        guest: PathBuf,
        /// Where that lands in the host's image tree.
        in_image: PathBuf,
    },
    /// A `--display` that is not `WIDTHxHEIGHT[@HZ]`.
    Display(String),
    /// A `--screenshot` with no display to take one of.
    ScreenshotNeedsDisplay,
    /// A `--frame-log` with no display to log frames of.
    FrameLogNeedsDisplay,
    /// The display's window thread could not be started.
    Window(std::io::Error),
    /// The input replay thread could not be started.
    Input(std::io::Error),
    /// `--gpu` on a libkrun built without the gpu feature.
    GpuUnsupported,
    /// `--sound` on a libkrun built without the snd feature.
    SoundUnsupported,
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
            Self::ReservedTag(tag) => write!(
                f,
                "--share tag {tag:?} starts with {RESERVED_TAG_PREFIX:?}, which is reserved for \
                 the devices --mount adds: two virtiofs devices under one tag leave the guest \
                 mounting whichever the kernel matches first, so one of them silently serves the \
                 other's directory. Pick a tag that does not start with {RESERVED_TAG_PREFIX:?}."
            ),
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
            Self::MountPointMissing { guest, in_image } => write!(
                f,
                "--mount needs {} to be a directory in the guest image ({}), and the root is \
                 read-only, so the guest cannot create it: mount at a directory the image has \
                 (/mnt is empty and unused), or pass --rootfs writable and let the guest write \
                 the mount point into the shared tree",
                guest.display(),
                in_image.display()
            ),
            Self::Display(d) => write!(
                f,
                "--display {d:?} is not WIDTHxHEIGHT or WIDTHxHEIGHT@HZ, all non-zero"
            ),
            Self::ScreenshotNeedsDisplay => {
                write!(f, "--screenshot needs a --display to take a frame from")
            }
            Self::FrameLogNeedsDisplay => {
                write!(f, "--frame-log needs a --display to log frames of")
            }
            Self::Window(e) => write!(f, "the display window: {e}"),
            Self::Input(e) => write!(f, "the input replay: {e}"),
            Self::GpuUnsupported => write!(
                f,
                "--gpu needs a libkrun built with the gpu feature, which this one lacks"
            ),
            Self::SoundUnsupported => write!(
                f,
                "--sound needs a libkrun built with the snd feature, which this one lacks"
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
    // Checked before the socket is bound, so a refusal leaves no file for a VM that never was.
    require_dir(Subject::Root, &args.root)?;
    let mut shares = Vec::with_capacity(args.shares.len());
    for spec in &args.shares {
        let (tag, path) = split_share(spec).ok_or_else(|| HelperError::Share(spec.clone()))?;
        if tag.starts_with(RESERVED_TAG_PREFIX) {
            return Err(HelperError::ReservedTag(tag.to_string()));
        }
        require_dir(Subject::Share, path)?;
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
    let display = args
        .display
        .as_deref()
        .map(|spec| split_display(spec).ok_or_else(|| HelperError::Display(spec.to_string())))
        .transpose()?;
    if args.screenshot.is_some() && display.is_none() {
        return Err(HelperError::ScreenshotNeedsDisplay);
    }
    if args.frame_log.is_some() && display.is_none() {
        return Err(HelperError::FrameLogNeedsDisplay);
    }
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
        require_dir(Subject::Mount, host)?;
        // `mkdir -p` cannot create a mount point through a read-only root, and a failed mount in
        // the guest is an exit 2 on a console nobody reads.
        if args.rootfs == RootFsPosture::ReadOnly {
            let in_image = mount_point_in_image(&args.root, guest);
            if !in_image.is_dir() {
                return Err(HelperError::MountPointMissing {
                    guest: guest.to_path_buf(),
                    in_image,
                });
            }
        }
        mounts.push((guest, host));
    }

    // The framebuffer does not exist when the socket is bound, but the control thread has to
    // answer a lease from it once it does: these slots are filled below.
    let display_share: DisplayShare = Arc::new(OnceLock::new());
    let input_share: InputShare = Arc::new(OnceLock::new());
    if let Some(name) = args.name.as_deref() {
        bind_control_socket(
            name,
            control_info(args),
            Arc::clone(&display_share),
            Arc::clone(&input_share),
        )?;
    }

    let mut machine = bsx_krun::Context::new()?
        .root(&args.root, args.rootfs.into_access())?
        .vm_config(args.vcpus, args.mem)?;

    for (tag, path) in shares {
        machine = machine.share(tag, path)?;
    }
    for (i, (_, host)) in mounts.iter().enumerate() {
        // The device carrying the host directory; the guest path is the preamble's business.
        machine = machine.share(&mount_tag(i), host)?;
    }
    // Before any port mapping, which attaches to the vsock device libkrun allows only one of.
    // `None` replaces libkrun's TSI-hijacking implicit device; `Tsi` keeps it but names it.
    let tsi = match args.net {
        NetPosture::None => 0,
        NetPosture::Tsi => bsx_krun::KRUN_TSI_HIJACK_INET,
    };
    machine = machine.vsock(tsi)?;
    if let Some((port, path)) = vsock {
        // `listen = true` per the header: the guest listens on the port and connections are
        // initiated from the host side, which is the agent-channel direction.
        machine = machine.vsock_port(port, path, bsx_krun::VsockInitiator::Host)?;
        restrict_when_bound(path);
    }
    // Rule 3: the guest issuing GPU commands is a named hole. Probed like sound, because a
    // build without gpu exports the symbol and adds no device.
    if args.gpu && !bsx_krun::has_feature(bsx_krun::KRUN_FEATURE_GPU)? {
        return Err(HelperError::GpuUnsupported);
    }
    // libkrun takes one gpu-options call per context, so --gpu and --display merge into it here.
    if args.gpu {
        machine = machine.gpu_device(bsx_krun::GpuMode::Accelerated)?;
    } else if display.is_some() {
        machine = machine.gpu_device(bsx_krun::GpuMode::Display)?;
    }
    // The window runs on its own thread from here, this one being about to become the guest.
    if let Some((width, height, refresh)) = display {
        let (mut with_display, display_id) = machine.add_display(width.get(), height.get())?;
        // The rate the guest paces its flips to; libkrun's own default otherwise. Host-side
        // nothing changes: frames arrive when the guest flushes them, at whatever rate that is.
        if let Some(hz) = refresh {
            with_display = with_display.display_set_refresh_rate(display_id, hz.get())?;
        }
        // Shared, not heap: the slots live in a memfd so a `display` lease over the control
        // socket can hand them to another process without a copy (4.9).
        let (with_backend, framebuffer) =
            with_display.display_backend(bsx_krun::MemoryFramebuffer::shared())?;
        let _ = display_share.set(Arc::clone(&framebuffer));
        let (with_keyboard, keyboard) = with_backend.input_device(bsx_input::keyboard())?;
        let (with_pointer, pointer) = with_keyboard.input_device(bsx_input::pointer())?;
        machine = with_pointer;
        let inputs = crate::input::Inputs { keyboard, pointer };
        let _ = input_share.set(inputs.clone());
        if let Some(path) = std::env::var_os(crate::input::REPLAY_ENV) {
            crate::input::replay(PathBuf::from(path), inputs.clone())
                .map_err(HelperError::Input)?;
        }
        crate::window::spawn(
            framebuffer,
            (width, height),
            args.name.as_deref().unwrap_or("sandbox"),
            args.screenshot.clone(),
            args.frame_log.clone(),
            inputs,
        )
        .map_err(HelperError::Window)?;
    }
    // Off unless asked (rule 3): a two-way path to the host's sound server is a named hole.
    // Probed, because a build without snd exports the symbol and adds no device.
    if args.sound {
        if !bsx_krun::has_feature(bsx_krun::KRUN_FEATURE_SND)? {
            return Err(HelperError::SoundUnsupported);
        }
        machine = machine.sound_device()?;
    }
    if let Some(dir) = &args.workdir {
        machine = machine.workdir(dir)?;
    }

    let env: Vec<&OsStr> = args.env.iter().map(OsStr::new).collect();
    require_cmdline_safe(Subject::ExecPath, args.exec.as_os_str())?;
    for arg in &args.args {
        require_cmdline_safe(Subject::GuestArgument, OsStr::new(arg))?;
    }
    for entry in &env {
        require_cmdline_safe(Subject::GuestEnv, entry)?;
    }
    machine = if mounts.is_empty() {
        let argv: Vec<&OsStr> = args.args.iter().map(OsStr::new).collect();
        machine.exec(&args.exec, &argv, &env)?
    } else {
        // `sh -c '<mounts>; exec <command>'`: the `exec` keeps the unwrapped exit code and
        // PATH resolution.
        let script = mount_preamble(&mounts, &args.exec, &args.args);
        // Covers the guest mount paths, which are spliced into the script.
        require_cmdline_safe(Subject::MountPreamble, OsStr::new(&script))?;
        let argv: Vec<&OsStr> = vec![OsStr::new("-c"), OsStr::new(&script)];
        machine.exec(Path::new("/bin/sh"), &argv, &env)?
    };

    // Past here the process either becomes the guest or reports why it could not.
    Err(HelperError::Krun(machine.enter()))
}

/// What this VM answers `bsx ls` with: its shape as configured, and whether an agent is reachable.
///
/// Read off the arguments, because libkrun reports nothing back and clamps some of them (see
/// [`MEASURED_VCPU_CLAMP`]). This is the ask, which is what `ps` shows too.
fn control_info(args: &VmmArgs) -> bsx_supervisor::control::Info {
    use bsx_supervisor::control::{Channel, Info};
    Info::new(
        std::process::id(),
        args.vcpus,
        args.mem,
        args.net.into_net(),
        args.rootfs.into_rootfs(),
        if args.vsock.is_some() {
            Channel::Present
        } else {
            Channel::Absent
        },
    )
}

/// Binds this VM's control socket and serves it from a background thread.
///
/// How a caller that did not start this VM reaches it, and what discovery reads: a VM is listed
/// for exactly as long as it can answer.
type DisplayShare = Arc<OnceLock<Arc<Mutex<bsx_krun::MemoryFramebuffer>>>>;
/// The device senders an `input` session feeds, filled beside the framebuffer.
type InputShare = Arc<OnceLock<crate::input::Inputs>>;

fn bind_control_socket(
    name: &str,
    info: bsx_supervisor::control::Info,
    display: DisplayShare,
    inputs: InputShare,
) -> Result<(), HelperError> {
    let path = bsx_supervisor::socket::path_for(name).map_err(HelperError::Socket)?;
    // A leftover from a previous helper with this name would make `bind` fail with EADDRINUSE. Only
    // cleared when nothing is listening, so a name genuinely in use still refuses.
    bsx_supervisor::socket::clear_if_stale(&path).map_err(HelperError::Socket)?;
    let listener = std::os::unix::net::UnixListener::bind(&path).map_err(HelperError::Socket)?;
    // `bind` applies the umask, commonly leaving the socket world-connectable. The `0700`
    // runtime directory is the first lock; this is the second.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(HelperError::Socket)?;

    std::thread::Builder::new()
        .name(format!("bsx-ctl-{name}"))
        .spawn(move || serve_control(&listener, &info, &display, &inputs))
        .map_err(HelperError::Socket)?;
    Ok(())
}

/// Deadline on each control exchange, so a caller that connects and then says nothing cannot park
/// the one thread that answers for this VM.
const CONTROL_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Answers on this VM's control socket until the VM ends, which for a stop request is here.
///
/// Errors are dropped rather than reported: once the main thread is inside libkrun this thread has
/// nowhere to report to, and a panic would take a running VM down over one failed accept.
fn serve_control(
    listener: &std::os::unix::net::UnixListener,
    info: &bsx_supervisor::control::Info,
    display: &DisplayShare,
    inputs: &InputShare,
) {
    use bsx_supervisor::control::{Request, read_request, write_answer};

    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let deadline = Some(CONTROL_IO_TIMEOUT);
        if stream.set_read_timeout(deadline).is_err() || stream.set_write_timeout(deadline).is_err()
        {
            continue;
        }
        let Ok(request) = read_request(&mut stream) else {
            continue;
        };
        if request == Some(Request::Display) {
            lease_display(stream, display.get());
            continue;
        }
        if request == Some(Request::Input) {
            serve_input(stream, inputs.get());
            continue;
        }
        if write_answer(&mut stream, request, info).is_err() {
            continue;
        }
        if request == Some(Request::Stop) {
            // Closed after the request is read: unread data in the queue sends an RST, which
            // would discard the `ok`.
            drop(stream);
            stop_this_vm();
        }
    }
}

/// Answers an input session: `ok`, then the connection goes to a thread that feeds its lines
/// to the devices until the client hangs up. No read deadline from here on, because a key may
/// be any time away.
fn serve_input(mut stream: std::os::unix::net::UnixStream, inputs: Option<&crate::input::Inputs>) {
    use std::io::Write;

    use bsx_supervisor::control::write_refusal;
    let Some(inputs) = inputs else {
        let _ = write_refusal(&mut stream, "this VM has no display");
        return;
    };
    if writeln!(stream, "ok").is_err() || stream.set_read_timeout(None).is_err() {
        return;
    }
    let _ = crate::input::serve(stream, inputs.clone());
}

/// Answers a display lease: the memfd and layout now, then a record per present until the client
/// goes or the scanout is resized. Written from libkrun's gpu thread under the lock, non-blocking,
/// so a client that cannot take it is dropped rather than waited for.
fn lease_display(
    stream: std::os::unix::net::UnixStream,
    framebuffer: Option<&Arc<Mutex<bsx_krun::MemoryFramebuffer>>>,
) {
    use bsx_supervisor::control::{
        Damage, RECONFIGURED_SLOT, Scanout, write_display_answer, write_present, write_refusal,
    };
    let mut stream = stream;
    let Some(framebuffer) = framebuffer else {
        let _ = write_refusal(&mut stream, "this VM has no display");
        return;
    };
    let mut guard = framebuffer
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let shared = match guard.share(SCANOUT) {
        Ok(Some(shared)) => shared,
        Ok(None) => {
            let _ = write_refusal(&mut stream, bsx_supervisor::control::NOT_READY);
            return;
        }
        Err(e) => {
            let _ = write_refusal(&mut stream, &format!("the display cannot be shared: {e}"));
            return;
        }
    };
    let (memfd, layout) = shared;
    let scanout = Scanout::new(
        layout.width,
        layout.height,
        layout.format.to_raw(),
        layout.stride,
        layout.slots,
        layout.slot_bytes,
        layout.generation,
    );
    // Answered under the lock, so no present can slip between the layout and the first record.
    if write_display_answer(&stream, memfd.as_fd(), &scanout).is_err() {
        return;
    }
    if stream.set_nonblocking(true).is_err() {
        return;
    }
    let generation = layout.generation;
    let whole = Damage::new(0, 0, layout.width, layout.height);
    guard.watch(move |event| match *event {
        bsx_krun::Event::Presented {
            scanout_id: SCANOUT,
            frame_id,
            slot,
            damage,
        } => {
            let damage = damage.map_or(whole, |r| Damage::new(r.x, r.y, r.width, r.height));
            write_present(&mut &stream, frame_id, slot, damage).is_ok()
        }
        bsx_krun::Event::Reconfigured {
            scanout_id: SCANOUT,
            generation: now,
        } if now != generation => {
            let _ = write_present(&mut &stream, 0, RECONFIGURED_SLOT, whole);
            false
        }
        bsx_krun::Event::Disabled {
            scanout_id: SCANOUT,
        } => {
            let _ = write_present(&mut &stream, 0, RECONFIGURED_SLOT, whole);
            false
        }
        _ => true,
    });
}

/// Ends this process, which is what ending a VM is: `krun_start_enter` never returns.
///
/// SIGKILL to itself, not `exit`, which would run libkrun's atexit handlers off the VMM's thread.
/// By pid, safe only because the process asking cannot have been reaped.
pub(crate) fn stop_this_vm() {
    let _ = rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::KILL);
}

/// How long the mode fixer waits for libkrun to bind the channel socket, and how often it looks.
/// Generous against a slow boot and bounded so the thread cannot outlive its usefulness; the
/// socket appears inside `krun_start_enter`, which is milliseconds after this is spawned.
const BIND_WAIT: std::time::Duration = std::time::Duration::from_secs(10);
const BIND_POLL: std::time::Duration = std::time::Duration::from_millis(5);

/// Tightens the agent channel socket to `0600` once libkrun has bound it.
///
/// **The channel runs commands in the sandbox**, and libkrun binds it under the caller's umask
/// with no call to set a mode. The `0700` runtime directory holds the window between.
fn restrict_when_bound(path: &Path) {
    let path = path.to_path_buf();
    // Best-effort by construction: a VM whose socket could not be tightened still runs, and a
    // failure here has nowhere to be reported once the main thread is inside libkrun.
    let _ = std::thread::Builder::new()
        .name("bsx-chan-mode".to_string())
        .spawn(move || {
            let deadline = std::time::Instant::now() + BIND_WAIT;
            while std::time::Instant::now() < deadline {
                if path.exists() {
                    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
                    return;
                }
                std::thread::sleep(BIND_POLL);
            }
        });
}

/// libkrun silently clamps the vCPU count above this, and the config never learns. A warning
/// rather than a refusal, since the bound may differ with other libkrun code or hardware.
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
fn require_cmdline_safe(what: Subject, s: &OsStr) -> Result<(), HelperError> {
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
fn require_dir(what: Subject, path: &Path) -> Result<(), HelperError> {
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
        let err = require_dir(Subject::Root, missing).expect_err("a missing root cannot boot");
        assert!(
            matches!(&err, HelperError::NotADirectory { what, path }
                if *what == Subject::Root && path == missing),
            "got {err:?}"
        );
        assert!(
            err.to_string().contains("exit 0"),
            "the message says why it matters: {err}"
        );
        // `what` is a `Subject` now, so the words it renders as are pinned here rather than by
        // the match above: they are what tells a reader which argument was wrong.
        assert!(
            err.to_string()
                .starts_with("the root /nonexistent-bsx-root"),
            "the message names which argument: {err}"
        );
        // A file is not a directory either, and is the likelier mistake of the two.
        assert!(require_dir(Subject::Root, Path::new("/etc/hostname")).is_err());
        require_dir(Subject::Root, Path::new("/tmp")).expect("a real directory passes");
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

    /// A caller's `--share` may not take a tag this helper invents, because the guest mounts by
    /// tag: the duplicate would put one device's directory where the other's was asked for, and
    /// nothing downstream could tell.
    #[test]
    fn a_share_tag_cannot_shadow_the_device_a_mount_adds() {
        for i in [0usize, 1, 42] {
            assert!(
                mount_tag(i).starts_with(RESERVED_TAG_PREFIX),
                "every invented tag must be inside the reserved namespace"
            );
        }
        let (tag, _) = split_share("bsx-mnt-0=/tmp").expect("it parses; the refusal is separate");
        assert!(tag.starts_with(RESERVED_TAG_PREFIX));
        assert!(
            !split_share("data=/tmp")
                .expect("a plain tag parses")
                .0
                .starts_with(RESERVED_TAG_PREFIX),
            "an ordinary tag is untouched by the rule"
        );
    }

    /// A display is two non-zero numbers; anything else is refused where it can still be named.
    #[test]
    fn a_display_spec_is_two_non_zero_numbers() {
        let (w, h, hz) = split_display("800x600").expect("well-formed");
        assert_eq!(hz, None);
        let (_, _, hz) = split_display("800x600@120").expect("with a rate");
        assert_eq!(hz.map(NonZeroU32::get), Some(120));
        assert_eq!((w.get(), h.get()), (800, 600));
        for bad in [
            "800",
            "800x",
            "x600",
            "0x600",
            "800x0",
            "800 x 600",
            "800X600",
            "-8x6",
        ] {
            assert!(split_display(bad).is_none(), "{bad:?} must be refused");
        }
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
        // The command's words go through `sh_quote` too, so one with spaces or quotes is data.
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

    /// A machine larger than the host is refused with both numbers, the alternative being a
    /// guest believing in RAM nothing can back. Driven with a fabricated host size.
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
        let err = require_cmdline_safe(Subject::GuestArgument, OsStr::new("\u{e9}"))
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
        let err = require_cmdline_safe(Subject::GuestArgument, OsStr::new("echo \"x y\""))
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

    /// Every flag the supervisor writes parses back into the field it meant, through the real
    /// parser, including a share whose host path contains `=`.
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
            "--rootfs",
            "writable",
            "--display",
            "800x600",
            "--screenshot",
            "/tmp/frame.ppm",
            "--frame-log",
            "/tmp/frames.tsv",
            "--sound",
            "--gpu",
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
        assert_eq!(got.rootfs, RootFsPosture::Writable);
        assert_eq!(got.display.as_deref(), Some("800x600"));
        assert_eq!(got.screenshot.as_deref(), Some(Path::new("/tmp/frame.ppm")));
        assert!(got.sound, "--sound parses as the sound flag");
        assert!(got.gpu, "--gpu parses as the gpu flag");
        assert_eq!(got.frame_log.as_deref(), Some(Path::new("/tmp/frames.tsv")));
    }

    /// Saying nothing about the filesystem asks for a root the guest cannot write, which is the
    /// whole of 3.7: the shared image tree is not something a sandbox edits by default.
    #[test]
    fn a_helper_told_nothing_about_the_filesystem_asks_for_a_read_only_root() {
        use clap::Parser;

        let parsed = Cli::parse_from([
            "bsx",
            HELPER_SUBCOMMAND,
            "--root",
            "/srv/root",
            "--exec",
            "/bin/true",
        ]);
        let Cmd::Vmm(got) = parsed.cmd else {
            panic!("the helper subcommand parses as itself");
        };
        assert_eq!(got.rootfs, RootFsPosture::ReadOnly);
    }

    /// A mount point is looked for in the same tree the VM will serve as the guest's root, and a
    /// guest path that tried to climb out of it is not a mount spec at all.
    #[test]
    fn a_mount_point_resolves_inside_the_image_and_cannot_climb_out() {
        assert_eq!(
            mount_point_in_image(Path::new("/srv/root"), Path::new("/mnt")),
            Path::new("/srv/root/mnt")
        );
        assert_eq!(
            mount_point_in_image(Path::new("/srv/root"), Path::new("/a/b")),
            Path::new("/srv/root/a/b")
        );
        assert!(
            split_mount("/../escape=/tmp").is_none(),
            "a .. component would resolve outside the image tree"
        );
        assert!(
            split_mount("/ok/../escape=/tmp").is_none(),
            "a .. anywhere in the path, not only at the front"
        );
    }
}
