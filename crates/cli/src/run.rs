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
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;

use bsx_supervisor::{Exit, Vm, VmConfig};

/// Run one command in a fresh sandbox.
#[derive(Args, Debug)]
pub(crate) struct RunArgs {
    /// The guest root directory (a tree from `cargo xtask build-rootfs`). Falls back to
    /// `$BSX_GUEST_ROOT`, then `~/.local/share/bsx/rootfs`.
    #[arg(long, value_name = "DIR")]
    pub(crate) root: Option<PathBuf>,
    /// vCPUs for this sandbox.
    #[arg(long, value_name = "N")]
    pub(crate) vcpus: Option<NonZeroU8>,
    /// Guest RAM in MiB.
    #[arg(long, value_name = "MIB")]
    pub(crate) mem: Option<NonZeroU32>,
    /// The guest working directory.
    #[arg(long, value_name = "DIR")]
    pub(crate) workdir: Option<PathBuf>,
    /// An extra read-write virtiofs share, as `TAG=HOSTPATH`. Repeatable.
    #[arg(long = "share", value_name = "TAG=HOSTPATH")]
    pub(crate) shares: Vec<String>,
    /// A `KEY=VALUE` entry for the guest environment. Repeatable.
    #[arg(long = "env", value_name = "KEY=VALUE")]
    pub(crate) env: Vec<String>,
    /// The VM's name while it runs, visible to discovery. Defaults to `run-<pid>`.
    #[arg(long, value_name = "NAME")]
    pub(crate) name: Option<String>,
    /// The command, after `--`. The first word is resolved by the guest (its `PATH`, not the
    /// host's), so `echo` runs the guest's `echo`.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub(crate) command: Vec<String>,
}

/// Exit code for an operational failure, re-exported for the message sites here.
use crate::EXIT_OPERATIONAL;

pub(crate) fn run(args: &RunArgs) -> ExitCode {
    let root = match resolve_root(args.root.clone()) {
        Ok(root) => root,
        Err(msg) => {
            eprintln!("bsx run: {msg}");
            return ExitCode::from(EXIT_OPERATIONAL);
        }
    };
    let cfg = match to_config(args, root) {
        Ok(cfg) => cfg,
        Err(msg) => {
            eprintln!("bsx run: {msg}");
            return ExitCode::from(EXIT_OPERATIONAL);
        }
    };
    let name = args
        .name
        .clone()
        .unwrap_or_else(|| format!("run-{}", std::process::id()));

    let vm = match Vm::spawn(name, &cfg) {
        Ok(vm) => vm,
        Err(e) => {
            eprintln!("bsx run: {e}");
            return ExitCode::from(EXIT_OPERATIONAL);
        }
    };
    match vm.wait() {
        Ok(exit) => ExitCode::from(exit_code_of(exit)),
        Err(e) => {
            eprintln!("bsx run: {e}");
            ExitCode::from(EXIT_OPERATIONAL)
        }
    }
}

/// The guest root: the flag, else `$BSX_GUEST_ROOT`, else the per-user data directory. The same
/// order as every other layered knob here (flag, then env, then default), with the config file
/// layer deliberately absent until phase 3's config work decides its shape.
pub(crate) fn resolve_root(flag: Option<PathBuf>) -> Result<PathBuf, String> {
    resolve_root_from(
        flag,
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

/// `$XDG_DATA_HOME`, else `$HOME/.local/share`, else nothing to derive a default from.
fn data_dir(xdg_data: Option<OsString>, home: Option<OsString>) -> Option<PathBuf> {
    xdg_data
        .map(PathBuf::from)
        .or(home.map(|h| PathBuf::from(h).join(".local/share")))
}

/// The [`VmConfig`] for `args`, against `root`. Split from [`run`] so the flag-to-field mapping is
/// testable without booting anything.
fn to_config(args: &RunArgs, root: PathBuf) -> Result<VmConfig, String> {
    let Some((program, rest)) = args.command.split_first() else {
        return Err("no command after `--`".to_string());
    };
    let mut cfg = VmConfig::new(root, program);
    if let Some(v) = args.vcpus {
        cfg.vcpus = v;
    }
    if let Some(m) = args.mem {
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
    Ok(cfg)
}

/// This process's exit code for how the helper ended. The guest's own code passes through; a
/// signalled VM reports as `128 + signal`, the shell convention, so a stopped sandbox and a
/// command that returned that number are at least spelled the same way everywhere else.
fn exit_code_of(exit: Exit) -> u8 {
    match exit {
        // Out-of-range codes cannot come from a Unix wait status, but a lossy cast that quietly
        // wrapped one would report a wrong code as a right one.
        Exit::Code(code) => u8::try_from(code).unwrap_or(u8::MAX),
        Exit::Signal(sig) => 128u8.saturating_add(u8::try_from(sig).unwrap_or(u8::MAX)),
        // `Exit` is `#[non_exhaustive]`: a variant this build does not know is an operational
        // failure to report, not a guest answer to invent.
        _ => EXIT_OPERATIONAL,
    }
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
