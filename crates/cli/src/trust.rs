//! Whether the user config file's author is this user.
//!
//! **The threat.** `~/.bsx.toml` names the binary this host executes, the images it boots, the key
//! it signs records with, and the ids a VMM drops to. On a shared host, another local user who can
//! write that file, or replace it by owning the directory it sits in, chooses those for you.
//!
//! **What is checked**, in the order [`judge`] reports it: the link's own owner if the path is a
//! symlink, then the file's owner, then its write bits, then the containing directory's owner and
//! write bits. Refusing is a hard failure, matching the file layer's existing posture that a config
//! the operator got wrong fails loudly rather than silently not applying.
//!
//! **What is deliberately not checked.** Read bits: this file gates integrity, not secrecy, and its
//! contents (paths, ceilings, postures) are already visible in `ps` and in the audit record. That is
//! the divergence from `bsx_record`'s signing-key gate, which refuses any group or world bit because
//! a *secret* leaks by being read. Refusing mode `0o644` here would refuse what every editor writes
//! under the default umask, teaching a `chmod` that buys nothing. Also not checked: ancestors above
//! the immediate parent (given the owner check, an attacker-writable grandparent buys a denial of
//! service, not a substitution), and the hard-link count (creating one needs the writable parent
//! this already refuses).
//!
//! **Who counts as the author** is [`HostIds::trusts`], shared with the signing-key gate that reads
//! the file this one names. Its module header carries the `SUDO_UID` reasoning.

use std::fs::File;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use crate::ids::HostIds;

/// Who this process would name as the config's expected owner, for a refusal message.
fn expected(ids: HostIds) -> String {
    match (ids.effective(), ids.sudo_invoker()) {
        (0, Some(u)) => format!("root or uid {u} (SUDO_UID)"),
        (0, None) => "root".to_string(),
        (e, _) => format!("uid {e} or root"),
    }
}

/// The uid a refusal should tell the reader to `chown` to.
fn primary(ids: HostIds) -> u32 {
    ids.sudo_invoker().unwrap_or_else(|| ids.effective())
}

/// The facts about one config file that decide whether it is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileFacts {
    uid: u32,
    mode: u32,
    /// The owner of the symlink itself, when the path is one.
    link_uid: Option<u32>,
    dir_uid: u32,
    dir_mode: u32,
}

/// Why a config file was not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    LinkOwner(u32),
    Owner(u32),
    Mode(u32),
    DirOwner(u32),
    DirMode(u32),
}

/// Judge `facts` against this process's identity.
///
/// The order is fixed so a file wrong on two axes reports the same reason every time: what was
/// opened (the link, then the file), then whether it can be rewritten, then whether its container
/// lets someone swap it.
fn judge(facts: &FileFacts, ids: HostIds) -> Result<(), Refusal> {
    // A symlink's own owner chooses which file gets read, so it needs the same trust as the target.
    // Its permission bits are always `0o777` on Linux and carry nothing.
    if let Some(link_uid) = facts.link_uid
        && !ids.trusts(link_uid)
    {
        return Err(Refusal::LinkOwner(link_uid));
    }
    if !ids.trusts(facts.uid) {
        return Err(Refusal::Owner(facts.uid));
    }
    if facts.mode & 0o022 != 0 {
        return Err(Refusal::Mode(facts.mode));
    }
    if !ids.trusts(facts.dir_uid) {
        return Err(Refusal::DirOwner(facts.dir_uid));
    }
    if !ids.trusts_dir(facts.dir_uid, facts.dir_mode) {
        return Err(Refusal::DirMode(facts.dir_mode));
    }
    Ok(())
}

/// The operator-facing sentence for a [`Refusal`]: what was found, what it lets another user do,
/// and the one command that fixes it.
fn refusal_message(refusal: &Refusal, path: &Path, dir: &Path, ids: HostIds) -> String {
    let p = path.display();
    match refusal {
        Refusal::LinkOwner(uid) => format!(
            "config file {p} is a symlink owned by uid {uid}: the link's owner chooses which file \
             this reads; replace it with a link you own, or remove it"
        ),
        Refusal::Owner(uid) => format!(
            "config file {p} is owned by uid {uid}, not {}: a config another local user owns sets \
             this run's kernel, rootfs, and signing key; `chown {}` it or remove it",
            expected(ids),
            primary(ids)
        ),
        Refusal::Mode(mode) => format!(
            "config file {p} is mode {mode:03o}: group/world write lets another local user rewrite \
             it between runs; `chmod go-w` it"
        ),
        Refusal::DirOwner(uid) => format!(
            "config file {p} sits in {}, owned by uid {uid}: that uid can replace the file at any \
             time; move the config into a directory you own",
            dir.display()
        ),
        Refusal::DirMode(mode) => format!(
            "config file {p} sits in {}, mode {mode:04o}: a group/world-writable directory without \
             the sticky bit lets another local user replace the file; `chmod go-w` the directory, \
             or move the config into one you own",
            dir.display()
        ),
    }
}

/// Open `path` if this user's own config, `Ok(None)` if there is nothing there to read.
///
/// The `metadata` call before `File::open` is load-bearing: without it a planted FIFO named
/// `.bsx.toml` would block the open forever, which is a hang on the host path. The owner and mode
/// are then taken from the **open descriptor**, so the file judged is the file parsed.
///
/// # Errors
/// The operator-facing refusal, when the file is there but another local user could have authored
/// or replaced it.
pub(crate) fn open_trusted(path: &Path) -> Result<Option<File>, String> {
    let Ok(link) = std::fs::symlink_metadata(path) else {
        return Ok(None); // nothing there is nothing to refuse
    };
    let link_uid = link.file_type().is_symlink().then(|| link.uid());

    // Refusing without an identity would be worse than not checking: the check would depend on a
    // read that can fail. `sweep_orphans` takes the same line for the same reason.
    let ids = HostIds::current().ok_or_else(|| {
        format!(
            "cannot read /proc/self/status to check who owns {}; refusing to read it",
            path.display()
        )
    })?;

    let dir = path.parent().unwrap_or(Path::new("/"));
    let dir_meta = std::fs::metadata(dir)
        .map_err(|e| format!("stat {} to check who can write it: {e}", dir.display()))?;

    match std::fs::metadata(path) {
        Ok(m) if m.is_file() => {}
        // A directory, a dangling link, or a device named `.bsx.toml` is not a config file: skipped
        // rather than refused, since a config that is not there does not apply.
        _ => return Ok(None),
    }

    let file = File::open(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("stat the open {}: {e}", path.display()))?;
    let facts = FileFacts {
        uid: meta.uid(),
        mode: meta.mode() & 0o7777,
        link_uid,
        dir_uid: dir_meta.uid(),
        dir_mode: dir_meta.mode() & 0o7777,
    };
    match judge(&facts, ids) {
        Ok(()) => Ok(Some(file)),
        Err(r) => Err(refusal_message(&r, path, dir, ids)),
    }
}

#[cfg(test)]
mod tests {
    /// This euid, for the tests that can only run as real root.
    fn own_euid() -> Option<u32> {
        HostIds::current().map(HostIds::effective)
    }

    use bsx_test_support::ScratchDir;

    use super::*;

    fn ids(effective: u32, real: u32, sudo: Option<u32>) -> HostIds {
        HostIds::from_parts(real, effective, sudo)
    }

    fn facts(uid: u32, mode: u32) -> FileFacts {
        FileFacts {
            uid,
            mode,
            link_uid: None,
            dir_uid: uid,
            dir_mode: 0o755,
        }
    }

    #[test]
    fn a_writable_config_is_refused_and_a_readable_one_is_not() {
        let me = ids(1000, 1000, None);
        for (mode, ok) in [
            (0o600, true),
            (0o644, true), // what every editor writes under the default umask
            (0o444, true),
            (0o664, false),
            (0o666, false),
            (0o620, false),
            (0o602, false),
        ] {
            let judged = judge(&facts(1000, mode), me);
            assert_eq!(
                judged.is_ok(),
                ok,
                "mode {mode:03o} should {}be admitted, got {judged:?}",
                if ok { "" } else { "not " }
            );
        }
    }

    #[test]
    fn a_shared_directory_is_refused_unless_it_is_sticky() {
        let me = ids(1000, 1000, None);
        for (dir_uid, dir_mode, ok, why) in [
            (1000, 0o755, true, "our own directory"),
            (0, 0o1777, true, "/tmp: sticky, so no one can swap our file"),
            (0, 0o777, false, "world-writable without sticky"),
            (1001, 0o755, false, "another user can chmod it at will"),
            (1000, 0o775, false, "group-writable, no sticky"),
            (1000, 0o1775, true, "group-writable but sticky"),
        ] {
            let f = FileFacts {
                uid: 1000,
                mode: 0o600,
                link_uid: None,
                dir_uid,
                dir_mode,
            };
            assert_eq!(
                judge(&f, me).is_ok(),
                ok,
                "dir {dir_uid}/{dir_mode:04o}: {why}"
            );
        }
    }

    #[test]
    fn each_refusal_names_the_file_the_fault_and_the_fix() {
        let me = ids(1000, 1000, None);
        let path = Path::new("/home/you/.bsx.toml");
        let dir = Path::new("/home/you");
        for (refusal, needle, fix) in [
            (Refusal::LinkOwner(1001), "1001", "remove"),
            (Refusal::Owner(1001), "1001", "chown"),
            (Refusal::Mode(0o666), "666", "chmod"),
            (Refusal::DirOwner(1001), "1001", "move"),
            (Refusal::DirMode(0o0777), "0777", "chmod"),
        ] {
            let msg = refusal_message(&refusal, path, dir, me);
            assert!(msg.contains("/home/you/.bsx.toml"), "names the file: {msg}");
            assert!(msg.contains(needle), "names what was found: {msg}");
            assert!(msg.contains(fix), "names the fix: {msg}");
        }
    }

    #[test]
    fn the_judgement_order_is_fixed_so_a_doubly_wrong_file_reads_the_same_every_time() {
        // Wrong on every axis at once: the identity of what was opened is reported first.
        let f = FileFacts {
            uid: 1001,
            mode: 0o666,
            link_uid: Some(1002),
            dir_uid: 1003,
            dir_mode: 0o777,
        };
        assert_eq!(
            judge(&f, ids(1000, 1000, None)),
            Err(Refusal::LinkOwner(1002))
        );
    }

    #[test]
    fn a_world_writable_config_is_refused_by_the_open() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = ScratchDir::created("trust-mode");
        let p = dir.path().join(".bsx.toml");
        std::fs::write(&p, "vcpus = 1\n").expect("write");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666)).expect("chmod");

        let err = open_trusted(&p).expect_err("a world-writable config must be refused");
        assert!(err.contains("666") && err.contains("chmod"), "{err}");

        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(
            open_trusted(&p)
                .expect("a 0644 config is ordinary")
                .is_some(),
            "the default umask's mode is still admitted"
        );
    }

    #[test]
    fn a_symlinked_config_is_honored_when_the_link_is_ours() {
        // The dotfile-manager layout (`~/.bsx.toml -> ~/dotfiles/bsx.toml`) must keep working.
        let dir = ScratchDir::created("trust-link");
        let target = dir.path().join("real.toml");
        std::fs::write(&target, "vcpus = 1\n").expect("write");
        let link = dir.path().join(".bsx.toml");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        assert!(
            open_trusted(&link).expect("our own link is fine").is_some(),
            "a link this user created points at a file this user owns"
        );
    }

    #[test]
    fn an_absent_or_non_file_config_is_nothing_to_read_rather_than_a_refusal() {
        let dir = ScratchDir::created("trust-absent");
        assert!(
            open_trusted(&dir.path().join(".bsx.toml"))
                .expect("absent is not an error")
                .is_none()
        );
        // A directory by that name is skipped, not refused.
        std::fs::create_dir(dir.path().join(".bsx.toml")).expect("mkdir");
        assert!(
            open_trusted(&dir.path().join(".bsx.toml"))
                .expect("a directory is not a config file")
                .is_none()
        );
    }

    #[test]
    #[ignore = "chowns a file to another uid; needs real root (run via `cargo xtask ci-privileged`)"]
    fn a_config_owned_by_another_uid_is_refused() {
        // The one fact an unprivileged process cannot fabricate. Mode stays `0o600` so ownership is
        // the only thing wrong, and the refusal must therefore be the owner clause.
        if own_euid() != Some(0) {
            eprintln!("skipping a_config_owned_by_another_uid_is_refused: needs real root");
            return;
        }
        let dir = ScratchDir::created("trust-foreign");
        let p = dir.path().join(".bsx.toml");
        std::fs::write(&p, "vcpus = 1\n").expect("write");
        std::os::unix::fs::chown(&p, Some(65534), Some(65534)).expect("chown to nobody");

        let err = open_trusted(&p).expect_err("another uid's config must be refused");
        assert!(
            err.contains("65534") && err.contains("owned by uid"),
            "the refusal names the foreign owner: {err}"
        );
    }
}
