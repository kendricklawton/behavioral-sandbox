//! `bsx up`: start a sandbox that outlives the command that started it.
//!
//! Every `bsx run` is a cold boot, because libkrun has no snapshot surface: ~300 ms before the
//! guest runs anything, paid again for each command (`scratch/ROADMAP.md` 2.9). A VM started here
//! is booted once and then used by `bsx exec` until `bsx stop`, which is the only way to amortise
//! that on a library with no snapshots.
//!
//! - **The workload is the agent**, so there is something to exec into, reached over the socket
//!   the helper maps beside the VM's control socket. Both live in the runtime directory, because
//!   a VM nobody holds a handle to has to be findable by name.
//! - **Readiness is the handshake, not the spawn.** This verb does not return until the agent has
//!   answered, so a `bsx exec` typed straight after it meets a VM that is ready.
//! - **Detaching is deliberate and singular.** [`Vm::detach`] is the one path in the supervisor
//!   that leaves a helper running; everything else exists to make that impossible by accident.

use std::process::ExitCode;

use clap::Args;

use bsx_channel::{GUEST_AGENT_PATH, GUEST_DEFAULT_PATH, VSOCK_PORT};
use bsx_supervisor::{Console, Vm, VmConfig, socket};

use crate::EXIT_OPERATIONAL;

/// Start a long-lived sandbox and print its name.
#[derive(Args, Debug)]
pub(crate) struct UpArgs {
    /// The VM's name, which is how `exec`, `ls` and `stop` reach it. Defaults to `vm-<pid>`.
    #[arg(long, value_name = "NAME")]
    pub(crate) name: Option<String>,
    /// The guest root directory. Falls back like `bsx run`'s.
    #[arg(long, value_name = "DIR")]
    pub(crate) root: Option<std::path::PathBuf>,
    /// vCPUs for this sandbox. Falls back to `$BSX_VCPUS`, then 1.
    #[arg(long, value_name = "N")]
    pub(crate) vcpus: Option<std::num::NonZeroU8>,
    /// Guest RAM in MiB. Falls back to `$BSX_MEM_MIB`, then 512.
    #[arg(long, value_name = "MIB")]
    pub(crate) mem: Option<std::num::NonZeroU32>,
    /// A host directory made read-write at a guest path, as `GUESTDIR=HOSTDIR`. Repeatable.
    #[arg(long = "mount", value_name = "GUESTDIR=HOSTDIR")]
    pub(crate) mounts: Vec<String>,
    /// An extra virtiofs device, as `TAG=HOSTPATH`. Repeatable.
    #[arg(long = "share", value_name = "TAG=HOSTPATH")]
    pub(crate) shares: Vec<String>,
    /// The network posture: `none` (default) or `tsi`.
    #[arg(long, value_name = "POSTURE", default_value = "none")]
    pub(crate) net: crate::run::NetArg,
    /// What the guest may do to its root: `read-only` (default) or `writable`.
    #[arg(long, value_name = "POSTURE", default_value = "read-only")]
    pub(crate) rootfs: crate::run::RootFsArg,
    /// Print what this sandbox would share and exit, without booting anything.
    #[arg(long)]
    pub(crate) dry_run: bool,
    /// Give the guest a display of `WIDTHxHEIGHT`, shown in a window for as long as the sandbox
    /// runs. Closing the window stops the sandbox.
    #[arg(long, value_name = "WIDTHxHEIGHT")]
    pub(crate) display: Option<String>,
    /// Keep PATH holding the display's latest frame as a binary PPM. Needs `--display`.
    #[arg(long, value_name = "PATH")]
    pub(crate) screenshot: Option<std::path::PathBuf>,
    /// Give the guest a virtio-snd sound card, backed by the host's audio server. Off by default:
    /// audio is a two-way hole, so the guest playing to your speakers and capturing from your
    /// microphone is opened only when asked.
    #[arg(long)]
    pub(crate) sound: bool,
}

/// What `start` did, so the printer cannot report the name of a VM that was never booted: a dry
/// run has no name to give, and an empty one printed as a name is a blank line a caller reads as
/// one.
enum Outcome {
    /// A VM is running under this name.
    Running(String),
    /// The posture was printed and nothing was booted.
    Described,
}

pub(crate) fn run(args: &UpArgs) -> ExitCode {
    match start(args) {
        Ok(Outcome::Running(name)) => {
            // The name is this verb's whole result, and it is what the next command needs.
            println!("{name}");
            ExitCode::SUCCESS
        }
        Ok(Outcome::Described) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("bsx up: {msg}");
            ExitCode::from(EXIT_OPERATIONAL)
        }
    }
}

fn start(args: &UpArgs) -> Result<Outcome, String> {
    let root = crate::run::resolve_root(args.root.as_deref())?;
    let name = args
        .name
        .clone()
        .unwrap_or_else(|| format!("vm-{}", std::process::id()));
    let control = socket::path_for(&name).map_err(|e| e.to_string())?;
    let channel = socket::agent_path_for(&name).map_err(|e| e.to_string())?;
    let log = socket::log_path_for(&name).map_err(|e| e.to_string())?;
    if socket::is_live(&control) {
        return Err(format!(
            "a VM named {name:?} is already running; `bsx ls` lists it and `bsx stop {name}` ends it"
        ));
    }
    // Both sockets are this name's, and this name has no live VM, so a leftover from a previous
    // one is ours to clear. The helper would otherwise fail to bind either.
    socket::clear_if_stale(&control).map_err(|e| e.to_string())?;
    socket::clear_if_stale(&channel).map_err(|e| e.to_string())?;

    let mut cfg = VmConfig::new(root, GUEST_AGENT_PATH);
    cfg.args = vec![format!("vsock:{VSOCK_PORT}").into()];
    // A `PATH` for the agent and for everything it runs: libkrun exports none, so
    // without this a bare program name resolves nowhere inside the guest.
    cfg.env = vec![
        "BSX_LOG=warn".into(),
        format!("PATH={GUEST_DEFAULT_PATH}").into(),
    ];
    cfg.vsock = Some((VSOCK_PORT, channel.clone()));
    // Nothing is waiting on this VM's console once this command returns, and an attached one
    // would read the caller's stdin into the guest.
    cfg.console = Console::Detached;
    // Not the caller's stderr: this VM outlives this command, and an inherited pipe would be one
    // it holds open after the caller has gone.
    cfg.log = Some(log.clone());
    cfg.net = args.net.into_net();
    cfg.rootfs = args.rootfs.into_rootfs();
    cfg.sound = args.sound;
    crate::run::apply_display(
        &mut cfg,
        args.display.as_deref(),
        args.screenshot.as_deref(),
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

    if args.dry_run {
        crate::run::print_posture(&name, &cfg, &mut std::io::stdout())
            .map_err(|e| e.to_string())?;
        return Ok(Outcome::Described);
    }

    let mut vm = Vm::spawn(name.clone(), &cfg).map_err(|e| e.to_string())?;
    // Held only until the agent answers. Until this returns, the `Vm` still owns the helper, so a
    // guest that never comes up is torn down by the `?` below rather than left running.
    // The dial says what it saw; what the VM did wrong is in the VM's own account of itself,
    // which is why that file exists and why this names it instead of guessing.
    let dialed = crate::agent::dial(&channel, &mut vm)
        .map_err(|e| format!("{e}; its own report is in {}", log.display()))?;
    drop(dialed);
    vm.detach().map_err(|e| e.to_string())?;
    Ok(Outcome::Running(name))
}
