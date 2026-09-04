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
pub(crate) fn start(bsx: &Path, form: &Form) -> Result<String, String> {
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
        return Ok(name);
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
    Ok(name)
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
    let (terminal, how) = terminal().ok_or_else(|| {
        "no terminal found: set $TERMINAL, or install foot, alacritty, kitty, wezterm, \
         gnome-terminal, konsole or xterm"
            .to_string()
    })?;
    let mut cmd = Command::new(&terminal);
    cmd.args(how);
    cmd.arg(bsx)
        .args(["exec", "--tty", name, "--", "/bin/sh"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = cmd
        .spawn()
        .map_err(|e| format!("run {}: {e}", terminal.display()))?;
    reap(child);
    Ok(format!("a shell in {name}, in {}", terminal.display()))
}

/// The terminal to open and the arguments that make it run a command: `$TERMINAL` first, then
/// the first of a known few on `PATH`.
fn terminal() -> Option<(PathBuf, &'static [&'static str])> {
    if let Some(term) = std::env::var_os("TERMINAL") {
        return Some((PathBuf::from(term), &["-e"]));
    }
    const KNOWN: [(&str, &[&str]); 7] = [
        ("foot", &["-e"]),
        ("alacritty", &["-e"]),
        ("kitty", &["-e"]),
        ("wezterm", &["start", "--"]),
        ("gnome-terminal", &["--"]),
        ("konsole", &["-e"]),
        ("xterm", &["-e"]),
    ];
    let path = std::env::var_os("PATH")?;
    for (name, how) in KNOWN {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some((candidate, how));
            }
        }
    }
    None
}

/// Waits for `child` on a thread of its own, so a detached `bsx` is reaped when it ends.
fn reap(mut child: std::process::Child) {
    std::thread::spawn(move || {
        let _ = child.wait();
    });
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

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
        assert_eq!(name, "bridged");
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
