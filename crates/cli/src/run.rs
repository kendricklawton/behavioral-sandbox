//! `bsx run`: boot a sandbox, run one command in it, exit with the command's status.
//!
//! The whole verb is a thin shape over the supervisor: build a [`bsx_supervisor::VmConfig`], spawn
//! the helper that becomes the VM, wait, and translate how the helper ended into this process's
//! exit code. The guest's output is this process's output because the helper inherits stdio, so
//! `bsx run -- make test 2>/dev/null` behaves like the command it wraps.
//!
//! **Every `run` is a cold boot** (~300 ms on the development laptop, `scratch/ROADMAP.md` 2.9):
//! libkrun has no snapshot surface, so there is no warm path to hide it. A sequence of commands
//! against one VM is 3.9's long-lived mode, not this verb.

use std::ffi::OsString;
use std::num::{NonZeroU8, NonZeroU32};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;

use bsx_record::{End, Posture, RESULTS_GUEST_PATH, Record, Store, Verb};
use bsx_supervisor::{Console, Display, Exit, Net, RootFs, Vm, VmConfig};

use crate::EXIT_OPERATIONAL;

/// The network posture flag, shared by `run` and `shell`. A CLI-side mirror of
/// [`bsx_supervisor::Net`], because clap's `ValueEnum` cannot derive on a type in another crate;
/// [`into`](NetArg::into) is the single crossing point and the only place the two can drift.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) enum NetArg {
    /// No network beyond loopback. The default, because libkrun's implicit TSI vsock is not.
    #[default]
    None,
    /// libkrun's transparent socket impersonation: the guest reaches what the host can. Opt-in.
    Tsi,
}

impl NetArg {
    pub(crate) fn into_net(self) -> Net {
        match self {
            Self::None => Net::None,
            Self::Tsi => Net::Tsi,
        }
    }
}

/// The filesystem-posture flag, shared by `run` and `shell`. A CLI-side mirror of
/// [`bsx_supervisor::RootFs`], for [`NetArg`]'s reason, with [`into_rootfs`](Self::into_rootfs)
/// as the single crossing point.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) enum RootFsArg {
    /// The guest cannot write its root. The default: one image tree boots every sandbox.
    #[default]
    ReadOnly,
    /// The guest writes through to the shared image tree, and its edits outlive the VM.
    Writable,
}

impl RootFsArg {
    pub(crate) fn into_rootfs(self) -> RootFs {
        match self {
            Self::ReadOnly => RootFs::ReadOnly,
            Self::Writable => RootFs::Writable,
        }
    }
}

/// Run one command in a fresh sandbox.
#[derive(Args, Debug)]
pub(crate) struct RunArgs {
    /// The guest root directory (a tree from `cargo xtask build-rootfs`). Falls back to
    /// `$BSX_GUEST_ROOT`, then `~/.local/share/bsx/rootfs`.
    #[arg(long, value_name = "DIR")]
    pub(crate) root: Option<PathBuf>,
    /// vCPUs for this sandbox. Falls back to `$BSX_VCPUS`, then 1.
    #[arg(long, value_name = "N")]
    pub(crate) vcpus: Option<NonZeroU8>,
    /// Guest RAM in MiB. Falls back to `$BSX_MEM_MIB`, then 512.
    #[arg(long, value_name = "MIB")]
    pub(crate) mem: Option<NonZeroU32>,
    /// The guest working directory.
    #[arg(long, value_name = "DIR")]
    pub(crate) workdir: Option<PathBuf>,
    /// A host directory made read-write at a guest path, as `GUESTDIR=HOSTDIR`: the project
    /// case, where edits land on the host. Repeatable.
    #[arg(long = "mount", value_name = "GUESTDIR=HOSTDIR")]
    pub(crate) mounts: Vec<String>,
    /// An extra virtiofs device, as `TAG=HOSTPATH`, for a guest that mounts by tag itself.
    /// Repeatable; `--mount` is the one that also mounts.
    #[arg(long = "share", value_name = "TAG=HOSTPATH")]
    pub(crate) shares: Vec<String>,
    /// The network posture: `none` (default) or `tsi`. See [`NetArg`].
    #[arg(long, value_name = "POSTURE", default_value = "none")]
    pub(crate) net: NetArg,
    /// What the guest may do to its root: `read-only` (default) or `writable`. See [`RootFsArg`].
    #[arg(long, value_name = "POSTURE", default_value = "read-only")]
    pub(crate) rootfs: RootFsArg,
    /// A `KEY=VALUE` entry for the guest environment. Repeatable.
    #[arg(long = "env", value_name = "KEY=VALUE")]
    pub(crate) env: Vec<String>,
    /// The VM's name while it runs, visible to discovery. Defaults to `run-<pid>`.
    #[arg(long, value_name = "NAME")]
    pub(crate) name: Option<String>,
    /// Print what this sandbox would share and exit, without booting anything.
    #[arg(long)]
    pub(crate) dry_run: bool,
    /// Give the guest a display of `WIDTHxHEIGHT`, shown in a window for as long as the sandbox
    /// runs; `WIDTHxHEIGHT@HZ` also tells the guest its refresh rate. Closing the window stops
    /// the sandbox.
    #[arg(long, value_name = "WIDTHxHEIGHT[@HZ]")]
    pub(crate) display: Option<String>,
    /// Keep PATH holding the display's latest frame as a binary PPM. Needs `--display`.
    #[arg(long, value_name = "PATH")]
    pub(crate) screenshot: Option<PathBuf>,
    /// Append one `frame_id<TAB>nanoseconds` line to PATH per frame the display thread sees, for
    /// measuring the frame path. Needs `--display`.
    #[arg(long, value_name = "PATH")]
    pub(crate) frame_log: Option<PathBuf>,
    /// Give the guest a virtio-snd sound card, backed by the host's audio server. Off by default:
    /// audio is a two-way hole, so the guest playing to your speakers and capturing from your
    /// microphone is opened only when asked.
    #[arg(long)]
    pub(crate) sound: bool,
    /// Do not mount the run's results directory at `/results` in the guest. Every run gets one
    /// by default: the record's own empty directory, where the guest's results land.
    #[arg(long)]
    pub(crate) no_results: bool,
    /// The command, after `--`. The first word is resolved by the guest (its `PATH`, not the
    /// host's), so `echo` runs the guest's `echo`.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub(crate) command: Vec<String>,
}

pub(crate) fn run(args: &RunArgs) -> ExitCode {
    match execute(args) {
        Ok(code) => ExitCode::from(code),
        Err(msg) => {
            eprintln!("bsx run: {msg}");
            ExitCode::from(EXIT_OPERATIONAL)
        }
    }
}

/// The verb's fallible body, one error path, one printer: the same shape as `shell`'s `session`.
fn execute(args: &RunArgs) -> Result<u8, String> {
    let root = resolve_root(args.root.as_deref())?;
    let mut cfg = to_config(args, root)?;
    let name = args
        .name
        .clone()
        .unwrap_or_else(|| format!("run-{}", std::process::id()));
    crate::check_name(&name)?;
    let results = !args.no_results;

    if args.dry_run {
        print_posture(&name, &cfg, results, &mut std::io::stdout()).map_err(|e| e.to_string())?;
        return Ok(0);
    }
    // The record first, so the results directory exists to mount; the output goes through this
    // process on its way to the record, and the caller's stdout still gets every byte.
    let store = Store::open().map_err(|e| e.to_string())?;
    let mut record = Record::begin(
        &name,
        Verb::Run,
        args.command.clone(),
        posture_of(&cfg, results),
    );
    let run = store.create(&record).map_err(|e| e.to_string())?;
    if results {
        cfg.mounts
            .push((PathBuf::from(RESULTS_GUEST_PATH), run.results()));
    }
    cfg.console = Console::Piped;
    let mut vm = Vm::spawn(name, &cfg).map_err(|e| e.to_string())?;
    record.pid = Some(vm.pid());
    store.save(&record).map_err(|e| e.to_string())?;
    let out = tee(
        vm.take_stdout(),
        std::io::stdout(),
        run.append(&run.stdout()).map_err(|e| e.to_string())?,
    );
    let err = tee(
        vm.take_stderr(),
        std::io::stderr(),
        run.append(&run.stderr()).map_err(|e| e.to_string())?,
    );
    let waited = vm.wait();
    let _ = out.join();
    let _ = err.join();
    let exit = match waited {
        Ok(exit) => exit,
        Err(e) => {
            record.finish(End::Failed);
            let _ = store.save(&record);
            return Err(e.to_string());
        }
    };
    record.finish(match exit {
        Exit::Code(code) => End::Exit(code),
        Exit::Signal(sig) => End::Signal(sig),
        _ => End::Failed,
    });
    store.save(&record).map_err(|e| e.to_string())?;
    Ok(exit_code_of(exit))
}

/// Copies `from` to `to` and to `keep` on a thread of its own, until `from` ends. `from` being
/// `None` is a VM whose console was not piped, which copies nothing.
fn tee(
    from: Option<impl std::io::Read + Send + 'static>,
    mut to: impl std::io::Write + Send + 'static,
    mut keep: bsx_record::Capped,
) -> std::thread::JoinHandle<()> {
    use std::io::Write;
    std::thread::spawn(move || {
        let Some(mut from) = from else { return };
        let mut buf = [0u8; 8192];
        loop {
            let n = match from.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let _ = keep.write_all(&buf[..n]);
            if to.write_all(&buf[..n]).is_err() || to.flush().is_err() {
                break;
            }
        }
    })
}

/// The record's posture for `cfg`: the same facts [`print_posture`] prints, in the record's
/// shape.
pub(crate) fn posture_of(cfg: &VmConfig, results: bool) -> Posture {
    let mut p = Posture::new(cfg.root.clone(), cfg.vcpus.get(), cfg.mem_mib.get());
    p.rootfs = cfg.rootfs.as_flag().to_string();
    p.mounts = cfg.mounts.clone();
    p.shares = cfg.shares.clone();
    p.network = cfg.net.as_flag().to_string();
    p.display = cfg.display.map(|d| d.as_spec());
    p.sound = cfg.sound;
    p.results = results;
    p
}

/// Writes what this sandbox shares, one element to a line, in the order the guest meets them.
///
/// Design rule 3 says the set of virtiofs tags and the network backend are settled before the VM
/// starts and are visible to the person starting it; this is the second half. To stdout, because
/// it is a run's structured result, and the terse `key value...` shape is for `grep`.
pub(crate) fn print_posture(
    name: &str,
    cfg: &VmConfig,
    results: bool,
    out: &mut impl std::io::Write,
) -> std::io::Result<()> {
    writeln!(out, "name     {name}")?;
    writeln!(
        out,
        "root     {} {}",
        cfg.root.display(),
        cfg.rootfs.as_flag()
    )?;
    for (guest, host) in &cfg.mounts {
        writeln!(
            out,
            "mount    {} <- {} writable",
            guest.display(),
            host.display()
        )?;
    }
    for (tag, host) in &cfg.shares {
        writeln!(out, "share    {tag} <- {} writable", host.display())?;
    }
    if results {
        writeln!(
            out,
            "results  {RESULTS_GUEST_PATH} <- the run's own record directory, writable"
        )?;
    }
    if let Some((port, path)) = &cfg.vsock {
        writeln!(out, "channel  guest vsock {port} <- {}", path.display())?;
    }
    if let Some(display) = cfg.display {
        writeln!(out, "display  {} in a window", display.as_spec())?;
    }
    if let Some(path) = &cfg.screenshot {
        writeln!(out, "screenshot {}", path.display())?;
    }
    if let Some(path) = &cfg.frame_log {
        writeln!(out, "frame-log {}", path.display())?;
    }
    if cfg.sound {
        writeln!(
            out,
            "sound    a virtio-snd card to the host audio server (play and capture)"
        )?;
    }
    writeln!(out, "network  {}", cfg.net.as_flag())?;
    writeln!(
        out,
        "limits   {} vcpu, {} MiB",
        cfg.vcpus.get(),
        cfg.mem_mib.get()
    )?;
    writeln!(out, "exec     {}", cfg.exec.display())
}

/// The guest root: the flag, else `$BSX_GUEST_ROOT`, else the per-user data directory. The same
/// order as every other layered knob here (flag, then env, then default), with the config file
/// layer deliberately absent until phase 3's config work decides its shape.
pub(crate) fn resolve_root(flag: Option<&Path>) -> Result<PathBuf, String> {
    resolve_root_from(
        flag.map(Path::to_path_buf),
        std::env::var_os("BSX_GUEST_ROOT"),
        std::env::var_os("XDG_DATA_HOME"),
        std::env::var_os("HOME"),
    )
}

/// [`resolve_root`] with the environment reads lifted out, so the precedence is a pure decision a
/// test can drive without mutating the test process's environment (which is `unsafe` in this
/// edition).
fn resolve_root_from(
    flag: Option<PathBuf>,
    env_root: Option<OsString>,
    xdg_data: Option<OsString>,
    home: Option<OsString>,
) -> Result<PathBuf, String> {
    let root = flag
        .or(env_root.map(PathBuf::from))
        .or_else(|| data_dir(xdg_data, home).map(|d| d.join("bsx/rootfs")));
    let Some(root) = root else {
        return Err(
            "no guest root: pass --root, set BSX_GUEST_ROOT, or install a tree at \
             ~/.local/share/bsx/rootfs (a checkout builds one with `cargo xtask build-rootfs`, \
             at artifacts/rootfs-guest)"
                .to_string(),
        );
    };
    if !root.is_dir() {
        return Err(format!(
            "the guest root {} is not a directory (a checkout builds one with \
             `cargo xtask build-rootfs`)",
            root.display()
        ));
    }
    Ok(root)
}

/// A resource limit from its flag, else its `BSX_*` variable, else `None` (the supervisor's
/// default). The same flag-then-env order as the guest root, with the config-file layer still
/// deferred with it.
pub(crate) fn resolve_limit<T: std::str::FromStr>(
    flag: Option<T>,
    var: &'static str,
) -> Result<Option<T>, String> {
    resolve_limit_from(flag, var, std::env::var_os(var))
}

/// [`resolve_limit`] with the environment read lifted out, for [`resolve_root_from`]'s reason.
/// A variable that is set but does not parse is refused loudly rather than ignored: a typo'd
/// limit that silently falls back is a config that lies about what it configured.
fn resolve_limit_from<T: std::str::FromStr>(
    flag: Option<T>,
    var: &'static str,
    env: Option<OsString>,
) -> Result<Option<T>, String> {
    if flag.is_some() {
        return Ok(flag);
    }
    let Some(raw) = env else {
        return Ok(None);
    };
    let Some(text) = raw.to_str() else {
        return Err(format!("{var} is set but is not valid UTF-8"));
    };
    text.parse().map(Some).map_err(|_| {
        format!("{var}={text:?} is not a usable limit (a non-zero number that fits the knob)")
    })
}

/// `$XDG_DATA_HOME`, else `$HOME/.local/share`, else nothing to derive a default from.
fn data_dir(xdg_data: Option<OsString>, home: Option<OsString>) -> Option<PathBuf> {
    xdg_data
        .map(PathBuf::from)
        .or(home.map(|h| PathBuf::from(h).join(".local/share")))
}

/// Puts a `--display`, `--screenshot` and `--frame-log` on `cfg`, refusing the spellings the
/// helper would. Shared by every verb that boots, so the refusal is one message.
pub(crate) fn apply_display(
    cfg: &mut VmConfig,
    display: Option<&str>,
    screenshot: Option<&Path>,
    frame_log: Option<&Path>,
) -> Result<(), String> {
    if let Some(spec) = display {
        let Some((width, height, refresh)) = crate::vmm::split_display(spec) else {
            return Err(format!(
                "--display {spec:?} is not WIDTHxHEIGHT or WIDTHxHEIGHT@HZ, all non-zero"
            ));
        };
        let mut d = Display::new(width, height);
        if let Some(hz) = refresh {
            d = d.with_refresh(hz);
        }
        cfg.display = Some(d);
    }
    if cfg.display.is_none() {
        if screenshot.is_some() {
            return Err("--screenshot needs a --display to take a frame from".to_string());
        }
        if frame_log.is_some() {
            return Err("--frame-log needs a --display to log frames of".to_string());
        }
    }
    cfg.screenshot = screenshot.map(Path::to_path_buf);
    cfg.frame_log = frame_log.map(Path::to_path_buf);
    Ok(())
}

/// The [`VmConfig`] for `args`, against `root`. Split from [`run`] so the flag-to-field mapping is
/// testable without booting anything.
fn to_config(args: &RunArgs, root: PathBuf) -> Result<VmConfig, String> {
    let Some((program, rest)) = args.command.split_first() else {
        return Err("no command after `--`".to_string());
    };
    let mut cfg = VmConfig::new(root, program);
    cfg.net = args.net.into_net();
    cfg.rootfs = args.rootfs.into_rootfs();
    cfg.sound = args.sound;
    apply_display(
        &mut cfg,
        args.display.as_deref(),
        args.screenshot.as_deref(),
        args.frame_log.as_deref(),
    )?;
    if let Some(v) = resolve_limit(args.vcpus, "BSX_VCPUS")? {
        cfg.vcpus = v;
    }
    if let Some(m) = resolve_limit(args.mem, "BSX_MEM_MIB")? {
        cfg.mem_mib = m;
    }
    cfg.workdir = args.workdir.clone();
    cfg.args = rest.iter().map(OsString::from).collect();
    cfg.env = args.env.iter().map(OsString::from).collect();
    for spec in &args.shares {
        let Some((tag, path)) = crate::vmm::split_share(spec) else {
            return Err(format!("--share {spec:?} is not TAG=HOSTPATH"));
        };
        cfg.shares.push((tag.to_string(), path.to_path_buf()));
    }
    for spec in &args.mounts {
        let Some((guest, host)) = crate::vmm::split_mount(spec) else {
            return Err(format!(
                "--mount {spec:?} is not GUESTDIR=HOSTDIR with an absolute guest path"
            ));
        };
        cfg.mounts.push((guest.to_path_buf(), host.to_path_buf()));
    }
    Ok(cfg)
}

/// This process's exit code for how the helper ended. The guest's own code passes through; a
/// signalled VM reports as `128 + signal`, the shell convention, so a stopped sandbox and a
/// command that returned that number are at least spelled the same way everywhere else.
fn exit_code_of(exit: Exit) -> u8 {
    match exit {
        Exit::Code(code) => guest_code(code),
        Exit::Signal(sig) => 128u8.saturating_add(u8::try_from(sig).unwrap_or(u8::MAX)),
        // `Exit` is `#[non_exhaustive]`: a variant this build does not know is an operational
        // failure to report, not a guest answer to invent.
        _ => EXIT_OPERATIONAL,
    }
}

/// A guest's `i32` exit code as this process's `u8` one, shared by both verbs. Out-of-range
/// values cannot come from a Unix wait status, but a lossy cast that quietly wrapped one would
/// report a wrong code as a right one, so they saturate loudly instead.
pub(crate) fn guest_code(code: i32) -> u8 {
    u8::try_from(code).unwrap_or(u8::MAX)
}

#[cfg(test)]
mod tests {
    // `panic!` is the assertion in the let-else arms below; the tree-wide deny is for the host
    // path, and this module is not on it.
    #![allow(clippy::panic)]

    use std::path::Path;

    use clap::Parser;

    use super::*;
    use crate::{Cli, Cmd};

    /// The roadmap's own example, `bsx run -- echo hello`, must parse with the command intact and
    /// hyphens in the command untouched, since everything after `--` belongs to the guest.
    #[test]
    fn the_command_after_the_separator_is_taken_verbatim() {
        let cli = Cli::parse_from(["bsx", "run", "--", "sh", "-c", "echo hi"]);
        let Cmd::Run(args) = cli.cmd else {
            panic!("run must parse");
        };
        assert_eq!(args.command, ["sh", "-c", "echo hi"]);
        assert!(args.root.is_none());
    }

    /// Precedence is flag, then env, then the data-dir default, and the error path names all
    /// three sources rather than reporting an empty hand.
    #[test]
    fn the_root_resolves_flag_then_env_then_data_dir() {
        let flag = Some(PathBuf::from("/tmp"));
        let env = Some(OsString::from("/nonexistent-env-root"));
        let got = resolve_root_from(flag, env.clone(), None, None).expect("the flag wins");
        assert_eq!(got, Path::new("/tmp"));
        let got = resolve_root(Some(Path::new("/tmp"))).expect("the borrowed form agrees");
        assert_eq!(got, Path::new("/tmp"));

        let err = resolve_root_from(None, env, None, None)
            .expect_err("an env root that is not a directory is refused");
        assert!(err.contains("/nonexistent-env-root"), "{err}");

        let err = resolve_root_from(None, None, None, None)
            .expect_err("nothing to resolve from is an error, not a guess");
        assert!(err.contains("--root"), "{err}");
        assert!(err.contains("BSX_GUEST_ROOT"), "{err}");

        let home = Some(OsString::from("/nonexistent-home"));
        let err = resolve_root_from(None, None, None, home)
            .expect_err("the derived default is still checked for existence");
        assert!(err.contains(".local/share/bsx/rootfs"), "{err}");
    }

    /// Every flag lands in the config field it names, and the command splits into the guest
    /// program and its arguments.
    #[test]
    fn the_flags_land_in_the_config_fields_they_name() {
        let cli = Cli::parse_from([
            "bsx",
            "run",
            "--vcpus",
            "2",
            "--mem",
            "1024",
            "--workdir",
            "/w",
            "--share",
            "data=/tmp",
            "--env",
            "K=v",
            "--mount",
            "/project=/srv/code",
            "--",
            "prog",
            "-x",
        ]);
        let Cmd::Run(args) = cli.cmd else {
            panic!("run must parse");
        };
        let cfg = to_config(&args, PathBuf::from("/root-tree")).expect("a well-formed config");
        assert_eq!(cfg.root, Path::new("/root-tree"));
        assert_eq!(cfg.exec, Path::new("prog"));
        assert_eq!(cfg.args, [OsString::from("-x")]);
        assert_eq!(cfg.vcpus.get(), 2);
        assert_eq!(cfg.mem_mib.get(), 1024);
        assert_eq!(cfg.workdir.as_deref(), Some(Path::new("/w")));
        assert_eq!(cfg.env, [OsString::from("K=v")]);
        assert_eq!(cfg.shares, [("data".to_string(), PathBuf::from("/tmp"))]);
        assert_eq!(
            cfg.mounts,
            [(PathBuf::from("/project"), PathBuf::from("/srv/code"))]
        );
    }

    /// A limit resolves flag first, then its variable, and a variable that does not parse is a
    /// loud refusal naming it, never a silent fall-back to the default.
    #[test]
    fn a_limit_resolves_flag_then_env_and_refuses_a_typo() {
        let flag = NonZeroU8::new(4);
        let env = Some(OsString::from("2"));
        assert_eq!(
            resolve_limit_from(flag, "BSX_VCPUS", env.clone()).expect("the flag wins"),
            flag
        );
        assert_eq!(
            resolve_limit_from::<NonZeroU8>(None, "BSX_VCPUS", env).expect("the env fills in"),
            NonZeroU8::new(2)
        );
        assert_eq!(
            resolve_limit_from::<NonZeroU8>(None, "BSX_VCPUS", None).expect("unset means unset"),
            None
        );
        for bad in ["zero-is-not-a-machine", "0", "-1", ""] {
            let err = resolve_limit_from::<NonZeroU8>(None, "BSX_VCPUS", Some(OsString::from(bad)))
                .expect_err("a set-but-broken limit must refuse");
            assert!(err.contains("BSX_VCPUS"), "names the variable: {err}");
        }
    }

    /// The CLI's posture enum maps onto the supervisor's, and the default is `None`: the whole
    /// point of the task is that "say nothing" means no network, against libkrun's own default.
    #[test]
    fn the_net_posture_defaults_to_none_and_maps_across() {
        assert_eq!(NetArg::default(), NetArg::None);
        assert_eq!(NetArg::None.into_net(), Net::None);
        assert_eq!(NetArg::Tsi.into_net(), Net::Tsi);
        let cli = Cli::parse_from(["bsx", "run", "--", "true"]);
        let Cmd::Run(args) = cli.cmd else {
            panic!("run must parse");
        };
        assert_eq!(args.net, NetArg::None, "no --net means no network");
    }

    /// The CLI's filesystem posture maps onto the supervisor's, and the default is read-only:
    /// one image tree boots every sandbox on the host, so "say nothing" must not mean "edit it".
    #[test]
    fn the_root_posture_defaults_to_read_only_and_maps_across() {
        assert_eq!(RootFsArg::default(), RootFsArg::ReadOnly);
        assert_eq!(RootFsArg::ReadOnly.into_rootfs(), RootFs::ReadOnly);
        assert_eq!(RootFsArg::Writable.into_rootfs(), RootFs::Writable);
        let cli = Cli::parse_from(["bsx", "run", "--", "true"]);
        let Cmd::Run(args) = cli.cmd else {
            panic!("run must parse");
        };
        assert_eq!(args.rootfs, RootFsArg::ReadOnly);
        let cfg = to_config(&args, PathBuf::from("/r")).expect("a well-formed config");
        assert_eq!(cfg.rootfs, RootFs::ReadOnly);
    }

    /// The posture print names every way into and out of the sandbox, each with its direction,
    /// and the root line carries the posture rather than only the path: a reader must be able to
    /// tell a writable image tree from a read-only one without booting it.
    #[test]
    fn the_posture_print_names_every_shared_thing_and_its_direction() {
        let cli = Cli::parse_from([
            "bsx",
            "run",
            "--rootfs",
            "writable",
            "--mount",
            "/mnt=/srv/code",
            "--share",
            "data=/srv/data",
            "--net",
            "tsi",
            "--",
            "true",
        ]);
        let Cmd::Run(args) = cli.cmd else {
            panic!("run must parse");
        };
        let cfg = to_config(&args, PathBuf::from("/root-tree")).expect("a well-formed config");
        let mut out = Vec::new();
        print_posture("vm-under-test", &cfg, false, &mut out).expect("a Vec never fails to write");
        let text = String::from_utf8(out).expect("the printer writes UTF-8");
        for line in [
            "name     vm-under-test",
            "root     /root-tree writable",
            "mount    /mnt <- /srv/code writable",
            "share    data <- /srv/data writable",
            "network  tsi",
            "limits   1 vcpu, 512 MiB",
            "exec     true",
        ] {
            assert!(text.contains(line), "{line:?} missing from:\n{text}");
        }
    }

    /// A display lands in the config as two non-zero numbers, a screenshot needs one, and the
    /// posture print names both: a window is a way out of the sandbox a reader should see.
    #[test]
    fn a_display_and_screenshot_land_in_the_config_and_the_posture() {
        let mut cfg = VmConfig::new("/r", "true");
        let err = apply_display(&mut cfg, None, Some(Path::new("/tmp/f.ppm")), None)
            .expect_err("a screenshot with no display");
        assert!(err.contains("--display"), "{err}");
        let err =
            apply_display(&mut cfg, Some("0x600"), None, None).expect_err("zero is not a display");
        assert!(err.contains("0x600"), "{err}");
        apply_display(
            &mut cfg,
            Some("800x600"),
            Some(Path::new("/tmp/f.ppm")),
            None,
        )
        .expect("both");
        assert_eq!(
            cfg.display.map(|d| d.as_spec()),
            Some("800x600".to_string())
        );
        assert_eq!(cfg.screenshot.as_deref(), Some(Path::new("/tmp/f.ppm")));
        let err = apply_display(
            &mut VmConfig::new("/r", "true"),
            None,
            None,
            Some(Path::new("/l")),
        )
        .expect_err("a frame log needs a display");
        assert!(err.contains("--frame-log"), "{err}");
        let mut rated = VmConfig::new("/r", "true");
        apply_display(
            &mut rated,
            Some("800x600@120"),
            None,
            Some(Path::new("/tmp/frames.tsv")),
        )
        .expect("a rate and a log");
        assert_eq!(
            rated.display.map(|d| d.as_spec()).as_deref(),
            Some("800x600@120")
        );
        assert_eq!(
            rated.frame_log.as_deref(),
            Some(Path::new("/tmp/frames.tsv"))
        );
        let mut out = Vec::new();
        print_posture("vm", &cfg, true, &mut out).expect("a Vec never fails");
        let text = String::from_utf8(out).expect("UTF-8");
        assert!(text.contains("display  800x600 in a window"), "{text}");
        assert!(text.contains("screenshot /tmp/f.ppm"), "{text}");
    }

    /// A malformed share is refused here, before a VM is spawned to die on it.
    #[test]
    fn a_malformed_share_is_refused_before_spawn() {
        let cli = Cli::parse_from(["bsx", "run", "--share", "nopath", "--", "true"]);
        let Cmd::Run(args) = cli.cmd else {
            panic!("run must parse");
        };
        let err = to_config(&args, PathBuf::from("/r")).expect_err("half a share is refused");
        assert!(err.contains("nopath"), "{err}");
    }

    /// The guest's code passes through; a signalled VM is `128 + signal`, so the two never
    /// collide silently with each other's range unannounced.
    #[test]
    fn the_exit_code_carries_the_guests_answer() {
        assert_eq!(exit_code_of(Exit::Code(0)), 0);
        assert_eq!(exit_code_of(Exit::Code(7)), 7);
        assert_eq!(exit_code_of(Exit::Signal(9)), 137);
        assert_eq!(
            exit_code_of(Exit::Code(-1)),
            u8::MAX,
            "impossible, but loud"
        );
    }
}
