//! `bsx shell`: an interactive shell (or any command) on a pseudo-terminal inside a fresh sandbox.
//!
//! The console cannot do this: libkrun wires the workload's stdio through pipes, so a guest
//! command never sees a tty there no matter what the host side is (measured, `scratch/ROADMAP.md`
//! 3.1). The pty therefore lives **in the guest**, allocated by the agent, and this verb is the
//! host half of that session:
//!
//! - Boot a VM whose workload *is* the agent, listening on vsock; reach it through the unix
//!   socket the helper maps (`--vsock`), and ask for a [`Request::ExecPty`].
//! - Put the host terminal in **raw mode** for the session, so every byte (including `^C`, which
//!   must reach the guest's foreground job, not this process) passes through; the guest pty's
//!   line discipline is the one that interprets them. Restored on every exit path by a drop guard.
//! - Follow the host terminal's size: polled, and a change becomes a [`Request::Resize`]. Polling
//!   rather than `SIGWINCH` keeps signal handling (and its `unsafe`) out of the crate for the
//!   price of a 250 ms lag on a resize.
//! - The guest console is detached ([`Console::Detached`]): an attached one *reads this
//!   process's stdin into the guest console*, stealing the session's keystrokes (watched happen),
//!   and its output would interleave boot noise into a raw terminal.
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;

use bsx_channel::{GUEST_AGENT_PATH, GUEST_DEFAULT_PATH, VSOCK_PORT};
use bsx_supervisor::{Console, Vm, VmConfig};

use crate::EXIT_OPERATIONAL;

/// Open an interactive shell in a fresh sandbox.
#[derive(Args, Debug)]
pub(crate) struct ShellArgs {
    /// The guest root directory. Falls back like `bsx run`'s.
    #[arg(long, value_name = "DIR")]
    pub(crate) root: Option<PathBuf>,
    /// vCPUs for this sandbox. Falls back to `$BSX_VCPUS`, then 1.
    #[arg(long, value_name = "N")]
    pub(crate) vcpus: Option<std::num::NonZeroU8>,
    /// Guest RAM in MiB. Falls back to `$BSX_MEM_MIB`, then 512.
    #[arg(long, value_name = "MIB")]
    pub(crate) mem: Option<std::num::NonZeroU32>,
    /// A host directory made read-write at a guest path, as `GUESTDIR=HOSTDIR`: the project
    /// case, where edits land on the host. Repeatable.
    #[arg(long = "mount", value_name = "GUESTDIR=HOSTDIR")]
    pub(crate) mounts: Vec<String>,
    /// An extra virtiofs device, as `TAG=HOSTPATH`, for a guest that mounts by tag itself.
    /// Repeatable; `--mount` is the one that also mounts.
    #[arg(long = "share", value_name = "TAG=HOSTPATH")]
    pub(crate) shares: Vec<String>,
    /// A `KEY=VALUE` entry for the shell's guest environment. Repeatable.
    #[arg(long = "env", value_name = "KEY=VALUE")]
    pub(crate) env: Vec<String>,
    /// The network posture: `none` (default) or `tsi`.
    #[arg(long, value_name = "POSTURE", default_value = "none")]
    pub(crate) net: crate::run::NetArg,
    /// What the guest may do to its root: `read-only` (default) or `writable`.
    #[arg(long, value_name = "POSTURE", default_value = "read-only")]
    pub(crate) rootfs: crate::run::RootFsArg,
    /// The VM's name while it runs. Defaults to `shell-<pid>`.
    #[arg(long, value_name = "NAME")]
    pub(crate) name: Option<String>,
    /// Print what this sandbox would share and exit, without booting anything.
    #[arg(long)]
    pub(crate) dry_run: bool,
    /// Give the guest a display of `WIDTHxHEIGHT`, shown in a window for as long as the sandbox
    /// runs; `WIDTHxHEIGHT@HZ` also tells the guest its refresh rate. Closing the window stops
    /// the sandbox.
    #[arg(long, value_name = "WIDTHxHEIGHT[@HZ]", value_parser = crate::run::parse_display)]
    pub(crate) display: Option<bsx_supervisor::Display>,
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
    /// Let the guest use the host GPU for its own rendering: a 3D-capable virtio-gpu (virgl +
    /// Venus) into the host renderer, with or without --display. Off by default: what the guest
    /// submits, the host renderer executes. The default image ships no driver to use it.
    #[arg(long)]
    pub(crate) gpu: bool,
    /// Do not mount the session's results directory at `/results` in the guest.
    #[arg(long)]
    pub(crate) no_results: bool,
    /// The command to run on the pty, after `--`. Defaults to `/bin/sh`.
    #[arg(last = true, value_name = "COMMAND")]
    pub(crate) command: Vec<String>,
}

pub(crate) fn run(args: &ShellArgs) -> ExitCode {
    match session(args) {
        Ok(code) => ExitCode::from(code),
        Err(msg) => {
            eprintln!("bsx shell: {msg}");
            ExitCode::from(EXIT_OPERATIONAL)
        }
    }
}

fn session(args: &ShellArgs) -> Result<u8, String> {
    let root = crate::run::resolve_root(args.root.as_deref())?;
    for entry in &args.env {
        if !crate::vmm::well_formed_env(entry) {
            return Err(format!("--env {entry:?} is not KEY=VALUE"));
        }
    }

    // A private directory for the channel socket, owned (and removed) by this process: unlike a
    // VM's control socket, this one's lifetime is exactly this session's.
    let dir = SessionDir::create()?;
    let channel_sock = dir.path.join("agent.sock");

    let mut cfg = VmConfig::new(root, GUEST_AGENT_PATH);
    cfg.args = vec![format!("vsock:{VSOCK_PORT}").into()];
    // `warn`, because the agent's stderr is the guest console. A `PATH` because libkrun exports
    // none, so a bare program name resolves nowhere in the guest.
    cfg.env = vec![
        "BSX_LOG=warn".into(),
        format!("PATH={GUEST_DEFAULT_PATH}").into(),
    ];
    cfg.vsock = Some((VSOCK_PORT, channel_sock.clone()));
    cfg.console = Console::Detached;
    cfg.net = args.net.into_net();
    cfg.rootfs = args.rootfs.into_rootfs();
    cfg.sound = args.sound;
    cfg.gpu = args.gpu;
    crate::run::apply_display(
        &mut cfg,
        args.display,
        args.screenshot.as_deref(),
        args.frame_log.as_deref(),
    )?;
    if let Some(v) = crate::run::resolve_limit(args.vcpus, "BSX_VCPUS")? {
        cfg.vcpus = v;
    }
    if let Some(m) = crate::run::resolve_limit(args.mem, "BSX_MEM_MIB")? {
        cfg.mem_mib = m;
    }
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
    let name = args
        .name
        .clone()
        .unwrap_or_else(|| format!("shell-{}", std::process::id()));
    crate::check_name(&name)?;
    let results = !args.no_results;

    if args.dry_run {
        crate::run::print_posture(&name, &cfg, results, &mut std::io::stdout())
            .map_err(|e| e.to_string())?;
        return Ok(0);
    }
    let mut command: Vec<String> = args.command.clone();
    if command.is_empty() {
        command = vec!["/bin/sh".to_string()];
    }
    let store = bsx_record::Store::open().map_err(|e| e.to_string())?;
    let mut record = bsx_record::Record::begin(
        &name,
        bsx_record::Verb::Shell,
        command.clone(),
        crate::run::posture_of(&cfg, results),
    );
    let run = store.create(&record).map_err(|e| e.to_string())?;
    if results {
        cfg.mounts
            .push((PathBuf::from(bsx_record::RESULTS_GUEST_PATH), run.results()));
    }
    let mut log = run.append(&run.shell_log()).map_err(|e| e.to_string())?;
    let outcome = attach(
        args,
        &cfg,
        &channel_sock,
        name,
        command,
        &mut log,
        &mut record,
        &store,
    );
    record.finish(match &outcome {
        Ok(code) => bsx_record::End::Exit(i32::from(*code)),
        Err(_) => bsx_record::End::Failed,
    });
    store.save(&record).map_err(|e| e.to_string())?;
    outcome
}

/// Boots the VM and runs the session on it, the terminal's bytes copied to `log` on the way to
/// the terminal.
#[allow(clippy::too_many_arguments)]
fn attach(
    args: &ShellArgs,
    cfg: &VmConfig,
    channel_sock: &Path,
    name: String,
    command: Vec<String>,
    log: &mut bsx_record::Capped,
    record: &mut bsx_record::Record,
    store: &bsx_record::Store,
) -> Result<u8, String> {
    let mut vm = Vm::spawn(name, cfg).map_err(|e| e.to_string())?;
    record.pid = Some(vm.pid());
    store.save(record).map_err(|e| e.to_string())?;
    // The console is discarded, a raw terminal being about to own it, so there is no report to
    // point at: an image with no agent is the likeliest cause.
    let (reader, stream) = crate::agent::dial(channel_sock, &mut vm).map_err(|e| {
        format!("{e}; is the guest image one with the agent baked in? (`cargo xtask build-rootfs`)")
    })?;

    // What the guest echoes is what the record keeps; the keystrokes themselves are not.
    let env: Vec<(String, String)> = args
        .env
        .iter()
        .filter_map(|e| {
            e.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect();
    crate::pty::session(reader, stream, command, env, log)
}

/// A private 0700 directory for this session's channel socket, removed on drop.
struct SessionDir {
    path: PathBuf,
}

impl SessionDir {
    fn create() -> Result<Self, String> {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(format!("bsx-shell-{}", std::process::id()));
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        b.mode(0o700);
        b.create(&path)
            .map_err(|e| format!("create {}: {e}", path.display()))?;
        Ok(Self { path })
    }
}

impl Drop for SessionDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use clap::Parser;

    use crate::{Cli, Cmd};

    /// No command means `/bin/sh`, and a command after `--` arrives verbatim, hyphens and all.
    #[test]
    fn the_shell_command_defaults_to_sh_and_passes_verbatim() {
        let cli = Cli::parse_from(["bsx", "shell"]);
        let Cmd::Shell(args) = cli.cmd else {
            panic!("shell must parse");
        };
        assert!(args.command.is_empty(), "empty means the default shell");

        let cli = Cli::parse_from(["bsx", "shell", "--", "top", "-d", "1"]);
        let Cmd::Shell(args) = cli.cmd else {
            panic!("shell must parse");
        };
        assert_eq!(args.command, ["top", "-d", "1"]);
    }
}
