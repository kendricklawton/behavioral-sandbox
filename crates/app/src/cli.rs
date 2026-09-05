//! The `bsx` binary as the app runs it: starting a run, stopping one, and a shell in the
//! operator's terminal. The app has no verb of its own, so this is the whole bridge.
//!
//! - **Which `bsx`.** `$BSX_CLI` if set, else the `bsx` beside this binary, else the one on
//!   `PATH`, so a packaged pair and a `target/` pair both find each other.
//! - **A started run is not this process's.** `bsx run` is spawned detached with its stdio on
//!   `/dev/null` (the record has the output), and a thread reaps it so nothing is left a zombie;
//!   `bsx up` returns at once with the name.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::Form;

/// Where the CLI is.
pub(crate) fn bsx_path() -> PathBuf {
    if let Some(path) = std::env::var_os("BSX_CLI") {
        return PathBuf::from(path);
    }
    if let Ok(me) = std::env::current_exe()
        && let Some(dir) = me.parent()
    {
        let beside = dir.join("bsx");
        if beside.is_file() {
            return beside;
        }
    }
    PathBuf::from("bsx")
}

/// The guest root the CLI would default to, for the form's first value.
pub(crate) fn default_root() -> Option<PathBuf> {
    if let Some(root) = std::env::var_os("BSX_GUEST_ROOT") {
        return Some(PathBuf::from(root));
    }
    let data = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))?;
    Some(data.join("bsx/rootfs"))
}

/// What the menu's status line reports: where `bsx` and the guest root are, if anywhere.
#[derive(Debug, Default)]
pub(crate) struct Platform {
    pub(crate) bsx: Option<PathBuf>,
    pub(crate) root: GuestRoot,
}

/// The default guest root as the menu judges it, so "a path with nothing there yet" cannot be
/// confused with "nothing to point at".
#[derive(Debug, Default)]
pub(crate) enum GuestRoot {
    Present(PathBuf),
    Absent(PathBuf),
    #[default]
    Unset,
}

/// Stats what the two chains name; nothing here spawns, so a tick cannot hang on it.
pub(crate) fn probe() -> Platform {
    let root = match default_root() {
        Some(path) if path.is_dir() => GuestRoot::Present(path),
        Some(path) => GuestRoot::Absent(path),
        None => GuestRoot::Unset,
    };
    Platform {
        bsx: find_bsx(),
        root,
    }
}

/// The `bsx` that [`bsx_path`] names, when it would actually spawn: the path itself when it is
/// an executable file, or the first executable match on `PATH` for a bare name.
fn find_bsx() -> Option<PathBuf> {
    let named = bsx_path();
    if named
        .parent()
        .is_some_and(|dir| !dir.as_os_str().is_empty())
    {
        return is_executable(&named).then_some(named);
    }
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|dir| dir.join(&named))
        .find(|candidate| is_executable(candidate))
}

/// A file this user could run: regular, with any execute bit set.
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.is_file() && std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
}

/// The CLI arguments a form's posture becomes, without the verb and the command.
pub(crate) fn posture_args(form: &Form, name: &str) -> Result<Vec<String>, String> {
    let mut args = vec!["--name".to_string(), name.to_string()];
    if form.root.trim().is_empty() {
        return Err("a guest root is needed".to_string());
    }
    args.extend(["--root".to_string(), form.root.trim().to_string()]);
    args.extend([
        "--rootfs".to_string(),
        if form.writable_root {
            "writable"
        } else {
            "read-only"
        }
        .to_string(),
    ]);
    args.extend([
        "--net".to_string(),
        if form.network { "tsi" } else { "none" }.to_string(),
    ]);
    for mount in form.mounts.split_whitespace() {
        if !mount.contains('=') {
            return Err(format!("mount {mount:?} is not GUESTDIR=HOSTDIR"));
        }
        args.extend(["--mount".to_string(), mount.to_string()]);
    }
    for share in form.shares.split_whitespace() {
        if !share.contains('=') {
            return Err(format!("share {share:?} is not TAG=HOSTPATH"));
        }
        args.extend(["--share".to_string(), share.to_string()]);
    }
    if form.display {
        args.extend([
            "--display".to_string(),
            form.display_size.trim().to_string(),
        ]);
    }
    if form.sound {
        args.push("--sound".to_string());
    }
    if form.gpu {
        args.push("--gpu".to_string());
    }
    if !form.results {
        args.push("--no-results".to_string());
    }
    let vcpus: u8 = form
        .vcpus
        .trim()
        .parse()
        .map_err(|_| format!("vcpus {:?} is not a number", form.vcpus))?;
    let mem: u32 = form
        .mem_mib
        .trim()
        .parse()
        .map_err(|_| format!("memory {:?} is not a number of MiB", form.mem_mib))?;
    args.extend(["--vcpus".to_string(), vcpus.to_string()]);
    args.extend(["--mem".to_string(), mem.to_string()]);
    Ok(args)
}

/// Starts the run the form describes and returns its name: `bsx run` for a command, detached,
/// or `bsx up` for a sandbox with none.
pub(crate) fn start(bsx: &Path, form: &Form) -> Result<crate::RunName, String> {
    let name = if form.name.trim().is_empty() {
        format!("app-{}", bsx_record::now_ms())
    } else {
        form.name.trim().to_string()
    };
    let args = posture_args(form, &name)?;
    let command: Vec<&str> = form.command.split_whitespace().collect();
    if command.is_empty() {
        let out = Command::new(bsx)
            .arg("up")
            .args(&args)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("run {}: {e}", bsx.display()))?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
        return Ok(crate::RunName::started(name));
    }
    let child = Command::new(bsx)
        .arg("run")
        .args(&args)
        .arg("--")
        .args(&command)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("run {}: {e}", bsx.display()))?;
    reap(child);
    // The record is written before the VM boots, so a short wait is all the list needs.
    std::thread::sleep(std::time::Duration::from_millis(300));
    Ok(crate::RunName::started(name))
}

/// Stops the run named `name`.
pub(crate) fn stop(bsx: &Path, name: &str) -> Result<String, String> {
    let out = Command::new(bsx)
        .args(["stop", name])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("run bsx: {e}"))?;
    if out.status.success() {
        Ok(format!("stopped {name}"))
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// Opens the operator's terminal on a shell in the run named `name`: `bsx exec --tty`.
pub(crate) fn open_shell(bsx: &Path, name: &str) -> Result<String, String> {
    let terminal = terminal().ok_or_else(no_terminal)?;
    let shown = terminal.shown();
    let mut cmd = terminal.command(bsx, name)?;
    let child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("run {shown}: {e}"))?;
    reap(child);
    Ok(format!("a shell in {name}, in {shown}"))
}

/// What to suggest when nothing was found, in the names this platform's users would recognise.
fn no_terminal() -> String {
    let known = KNOWN_TERMINALS
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(", ");
    format!("no terminal found: set $TERMINAL, or install one of {known}")
}

/// How to get a terminal to run one command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Terminal {
    /// A terminal that takes the command as arguments, after `before`.
    Direct {
        program: PathBuf,
        before: &'static [&'static str],
    },
    /// macOS's stock Terminal, which opens a *file* rather than taking a command, so the command
    /// is written to a script and that is what is opened.
    TerminalApp,
}

impl Terminal {
    /// How this terminal names itself in a message.
    fn shown(&self) -> String {
        match self {
            Self::Direct { program, .. } => program.display().to_string(),
            Self::TerminalApp => "Terminal.app".to_string(),
        }
    }

    /// The command that opens a shell on `name`.
    fn command(&self, bsx: &Path, name: &str) -> Result<Command, String> {
        match self {
            Self::Direct { program, before } => {
                let mut cmd = Command::new(program);
                cmd.args(*before);
                cmd.arg(bsx).args(["exec", "--tty", name, "--", "/bin/sh"]);
                Ok(cmd)
            }
            // `open -a Terminal <file>` is the only route that needs no AppleScript, and
            // AppleScript would mean quoting a command into a second language. The script removes
            // itself first thing, so a launch that never happens leaves the OS to clean one file
            // out of its own temporary directory rather than leaving one behind on every click.
            Self::TerminalApp => {
                let script = std::env::temp_dir().join(format!("bsx-shell-{name}.command"));
                let body = format!(
                    "#!/bin/sh\nrm -f -- \"$0\"\nexec {} exec --tty {} -- /bin/sh\n",
                    shell_quote(&bsx.display().to_string()),
                    shell_quote(name)
                );
                std::fs::write(&script, body).map_err(|e| format!("write {script:?}: {e}"))?;
                set_executable(&script)?;
                let mut cmd = Command::new("open");
                cmd.args(["-a", "Terminal"]).arg(&script);
                Ok(cmd)
            }
        }
    }
}

/// A single-quoted shell word, so a path with a space in it survives the script.
fn shell_quote(raw: &str) -> String {
    format!("'{}'", raw.replace('\'', r"'\''"))
}

/// Marks `path` executable, which `open -a Terminal` needs of a `.command` file.
fn set_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("make {path:?} executable: {e}"))
}

/// Terminals this knows how to hand a command to, and the arguments that make each do it.
///
/// Ordered by how likely a person is to want the one they installed over the one that came with
/// the machine, which is why `Terminal.app` is not in here: it is the fallback below, and it is
/// also the only one that cannot take a command as arguments.
const KNOWN_TERMINALS: [(&str, &[&str]); 8] = [
    ("ghostty", &["-e"]),
    ("wezterm", &["start", "--"]),
    ("alacritty", &["-e"]),
    ("kitty", &["-e"]),
    ("foot", &["-e"]),
    ("gnome-terminal", &["--"]),
    ("konsole", &["-e"]),
    ("xterm", &["-e"]),
];

/// The terminal to open: `$TERMINAL` first, then a known one on `PATH`, then a known one inside a
/// macOS application bundle, then macOS's stock Terminal.
///
/// The bundle step is why a Mac is not simply "none of these are on `PATH`": a terminal installed
/// by dragging it to `/Applications` puts no binary there, and every one of these ships its
/// executable at the same place inside its own bundle.
fn terminal() -> Option<Terminal> {
    if let Some(term) = std::env::var_os("TERMINAL") {
        return Some(Terminal::Direct {
            program: PathBuf::from(term),
            before: &["-e"],
        });
    }
    let on_path = std::env::var_os("PATH").and_then(|path| {
        KNOWN_TERMINALS.iter().find_map(|(name, before)| {
            std::env::split_paths(&path)
                .map(|dir| dir.join(name))
                .find(|candidate| candidate.is_file())
                .map(|program| Terminal::Direct { program, before })
        })
    });
    if let Some(found) = on_path {
        return Some(found);
    }
    if cfg!(target_os = "macos") {
        if let Some(found) = in_app_bundle() {
            return Some(found);
        }
        // Every Mac has this one, so the button is never dead here.
        return Some(Terminal::TerminalApp);
    }
    None
}

/// A known terminal's executable inside an application bundle, which is where macOS keeps one.
fn in_app_bundle() -> Option<Terminal> {
    let roots = [
        PathBuf::from("/Applications"),
        std::env::var_os("HOME").map_or_else(
            || PathBuf::from("/Applications"),
            |home| PathBuf::from(home).join("Applications"),
        ),
    ];
    KNOWN_TERMINALS.iter().find_map(|(name, before)| {
        roots.iter().find_map(|root| {
            let bundle = root.join(format!("{}.app", bundle_name(name)));
            let program = bundle.join("Contents/MacOS").join(name);
            program
                .is_file()
                .then_some(Terminal::Direct { program, before })
        })
    })
}

/// The bundle a terminal ships as, which is its name capitalised except where it is not.
fn bundle_name(binary: &str) -> &str {
    match binary {
        "ghostty" => "Ghostty",
        "wezterm" => "WezTerm",
        "alacritty" => "Alacritty",
        "kitty" => "kitty",
        other => other,
    }
}

/// Waits for `child` on a thread of its own, so a detached `bsx` is reaped when it ends.
fn reap(mut child: std::process::Child) {
    std::thread::spawn(move || {
        let _ = child.wait();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only a regular file with an execute bit counts as a found `bsx`.
    #[test]
    fn only_an_executable_file_counts_as_found() {
        let dir = bsx_test_support::ScratchDir::created("app-probe");
        let plain = dir.path().join("plain");
        std::fs::write(&plain, b"#!/bin/sh\n").expect("written");
        std::fs::set_permissions(&plain, PermissionsExt::from_mode(0o644)).expect("chmod");
        assert!(!is_executable(&plain), "0644 is not runnable");
        std::fs::set_permissions(&plain, PermissionsExt::from_mode(0o755)).expect("chmod");
        assert!(is_executable(&plain));
        assert!(!is_executable(dir.path()), "a directory is not a binary");
    }

    use std::os::unix::fs::PermissionsExt;

    /// A direct terminal is handed the command as arguments, after whatever that terminal needs
    /// first, and the shell is the last word: `wezterm start -- bsx exec --tty NAME -- /bin/sh`.
    #[test]
    fn a_direct_terminal_is_handed_the_command() {
        let term = Terminal::Direct {
            program: PathBuf::from("/opt/homebrew/bin/wezterm"),
            before: &["start", "--"],
        };
        let cmd = term
            .command(Path::new("/usr/local/bin/bsx"), "vm1")
            .expect("built");
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            [
                "start",
                "--",
                "/usr/local/bin/bsx",
                "exec",
                "--tty",
                "vm1",
                "--",
                "/bin/sh"
            ]
        );
        assert!(term.shown().ends_with("wezterm"), "{}", term.shown());
    }

    /// Terminal.app takes a *file*, not a command, so what it is opened on is a script that runs
    /// the shell. Written, executable, and removing itself before it execs.
    #[cfg(target_os = "macos")]
    #[test]
    fn terminal_app_is_opened_on_a_script_that_runs_the_shell() {
        let cmd = Terminal::TerminalApp
            .command(Path::new("/usr/local/bin/bsx"), "vm-two")
            .expect("built");
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(cmd.get_program(), "open");
        assert_eq!(args[..2], ["-a".to_string(), "Terminal".to_string()]);

        let script = PathBuf::from(&args[2]);
        let body = std::fs::read_to_string(&script).expect("the script was written");
        assert!(body.contains("exec --tty 'vm-two'"), "{body}");
        assert!(body.contains("rm -f -- \"$0\""), "removes itself: {body}");
        let mode = std::fs::metadata(&script)
            .expect("staged")
            .permissions()
            .mode();
        assert_eq!(mode & 0o111, 0o100, "must be executable: {mode:o}");
        let _ = std::fs::remove_file(&script);
    }

    /// A path with a space survives into the script, because a shell would otherwise read it as
    /// two words and run the wrong program.
    #[test]
    fn a_quoted_word_survives_a_space_and_a_quote() {
        assert_eq!(
            shell_quote("/Volumes/My Disk/bsx"),
            "'/Volumes/My Disk/bsx'"
        );
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }

    /// The refusal names terminals this platform's user could plausibly install, and every name it
    /// offers is one the launcher actually knows how to drive.
    #[test]
    fn the_refusal_only_suggests_terminals_it_can_drive() {
        let why = no_terminal();
        assert!(why.contains("$TERMINAL"), "{why}");
        for (name, _) in KNOWN_TERMINALS {
            assert!(
                why.contains(name),
                "{name} is driveable but unmentioned: {why}"
            );
        }
    }

    /// macOS always has an answer, so the shell button is never dead there: with no known terminal
    /// on `PATH` and none in a bundle, the stock Terminal is what is left.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_always_has_a_terminal_to_fall_back_to() {
        assert!(terminal().is_some(), "a Mac always has Terminal.app");
    }

    /// The form's posture becomes the CLI's flags, one to one, and a field the CLI would refuse
    /// is refused here with its name.
    #[test]
    fn the_form_becomes_the_clis_flags() {
        let mut form = Form {
            root: "/img".to_string(),
            vcpus: "2".to_string(),
            mem_mib: "768".to_string(),
            results: true,
            ..Form::default()
        };
        let args = posture_args(&form, "x").expect("valid");
        assert_eq!(
            args,
            [
                "--name",
                "x",
                "--root",
                "/img",
                "--rootfs",
                "read-only",
                "--net",
                "none",
                "--vcpus",
                "2",
                "--mem",
                "768"
            ]
        );
        form.writable_root = true;
        form.network = true;
        form.display = true;
        form.display_size = "800x600".to_string();
        form.sound = true;
        form.gpu = true;
        form.results = false;
        form.mounts = "/mnt=/home/x/out".to_string();
        form.shares = "src=/home/x/src".to_string();
        let args = posture_args(&form, "x").expect("valid");
        assert!(args.windows(2).any(|w| w == ["--rootfs", "writable"]));
        assert!(args.windows(2).any(|w| w == ["--net", "tsi"]));
        assert!(
            args.windows(2)
                .any(|w| w == ["--mount", "/mnt=/home/x/out"])
        );
        assert!(args.windows(2).any(|w| w == ["--share", "src=/home/x/src"]));
        assert!(args.windows(2).any(|w| w == ["--display", "800x600"]));
        assert!(args.contains(&"--sound".to_string()));
        assert!(args.contains(&"--gpu".to_string()));
        assert!(args.contains(&"--no-results".to_string()));
        form.mounts = "nonsense".to_string();
        assert!(
            posture_args(&form, "x")
                .expect_err("refused")
                .contains("nonsense")
        );
        form.mounts.clear();
        form.vcpus = "many".to_string();
        assert!(
            posture_args(&form, "x")
                .expect_err("refused")
                .contains("vcpus")
        );
        form.vcpus = "1".to_string();
        form.root.clear();
        assert!(posture_args(&form, "x").is_err());
    }

    /// The bridge starts a run through the built `bsx` and the record appears under the runs
    /// directory it was given, then stops it and the record ends `stopped`. Needs /dev/kvm and
    /// the guest tree, and skips with the reason otherwise.
    #[test]
    fn the_bridge_starts_and_stops_a_run_the_record_shows() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("the workspace")
            .to_path_buf();
        let bsx = root.join("target/debug/bsx");
        let guest = root.join("artifacts/rootfs-guest");
        if let Some(why) = bsx_test_support::hypervisor_unusable() {
            println!("SKIPPED the_bridge_starts_and_stops_a_run_the_record_shows: {why}");
            return;
        }
        if !bsx.is_file() || !guest.is_dir() {
            println!(
                "SKIPPED the_bridge_starts_and_stops_a_run_the_record_shows: no {} or {}",
                bsx.display(),
                guest.display()
            );
            return;
        }
        let dir = bsx_test_support::ScratchDir::created("app-bridge");
        let runs = dir.path().join("runs");
        let rt = dir.path().join("rt");
        std::fs::create_dir(&rt).expect("a runtime dir");
        std::fs::set_permissions(&rt, std::fs::Permissions::from_mode(0o700)).expect("private");
        // The CLI reads the runs directory and the runtime directory from the environment, which
        // a test must not set for its own process: a wrapper script sets them for `bsx` alone.
        let wrapper = dir.path().join("bsx");
        std::fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\nexport BSX_RUNS_DIR={}\nexport XDG_RUNTIME_DIR={}\nunset DISPLAY WAYLAND_DISPLAY\nexec {} \"$@\"\n",
                runs.display(),
                rt.display(),
                bsx.display()
            ),
        )
        .expect("the wrapper");
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).expect("exec");
        let form = Form {
            name: "bridged".to_string(),
            root: guest.display().to_string(),
            vcpus: "1".to_string(),
            mem_mib: "512".to_string(),
            results: true,
            ..Form::default()
        };
        let name = start(&wrapper, &form).expect("started");
        assert_eq!(name.as_str(), "bridged");
        let store = bsx_record::Store::at(runs.clone()).expect("the store");
        let open = store
            .open_run("bridged")
            .expect("read")
            .expect("an open record");
        assert_eq!(open.verb, bsx_record::Verb::Up);
        stop(&wrapper, "bridged").expect("stopped");
        let ended = store.find("bridged").expect("read").expect("still there");
        assert_eq!(ended.end, Some(bsx_record::End::Stopped));
    }
}
