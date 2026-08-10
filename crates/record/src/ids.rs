//! Which local uids this host trusts to have authored a file it reads.
//!
//! **The threat.** Two files decide what a run does and how its record is signed: the user config
//! (`~/.bsx.toml`, which names the binary, the images, the key, and the ids a VMM drops to) and the
//! signing key itself. On a shared host, another local user who can write either one, or replace it
//! by owning the directory it sits in, chooses those for you. Both gates ask the same question of a
//! file's owner, so both ask it here.
//!
//! **Who is trusted.** The effective uid, root, and the `sudo` invoker. Root is admitted because it
//! can already replace the binary being configured, so a root-authored file grants nothing new; this
//! is OpenSSH `StrictModes`'s rule.
//!
//! **Where `SUDO_UID` stops being sound.** It is consulted only when the real *and* effective uid
//! are both 0, which is the state `sudo` produces. A setuid-root `bsx` would leave the real uid at
//! the caller's, so an unprivileged attacker could otherwise set `SUDO_UID` themselves and have
//! their own file trusted. `su -` clears the environment and `doas` sets a name rather than a uid,
//! so a root shell obtained either way reads a user-owned file as untrusted: a refusal naming a fix,
//! not a silent acceptance.

/// This process's uids, plus the invoking uid when it is running under `sudo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostIds {
    real: u32,
    effective: u32,
    sudo: Option<u32>,
}

impl HostIds {
    /// Read from `/proc/self/status` and the environment, or `None` if `/proc` is unreadable.
    #[must_use]
    pub fn current() -> Option<Self> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let (real, effective) = uids(&status)?;
        // An unparseable value is not a claim, so it extends trust to nobody rather than refusing.
        let sudo = std::env::var("SUDO_UID").ok().and_then(|v| v.parse().ok());
        Some(Self {
            real,
            effective,
            sudo,
        })
    }

    /// Builds an identity from its parts, for a test that needs a uid combination this process
    /// cannot be.
    #[must_use]
    pub fn from_parts(real: u32, effective: u32, sudo: Option<u32>) -> Self {
        Self {
            real,
            effective,
            sudo,
        }
    }

    /// This process's effective uid.
    #[must_use]
    pub fn effective(self) -> u32 {
        self.effective
    }

    /// The invoking uid, but only in the state `sudo` produces. See the module header.
    #[must_use]
    pub fn sudo_invoker(self) -> Option<u32> {
        if self.effective == 0 && self.real == 0 {
            self.sudo
        } else {
            None
        }
    }

    /// Whether a file owned by `uid` was written by someone this process trusts to have authored it.
    #[must_use]
    pub fn trusts(self, uid: u32) -> bool {
        uid == self.effective || uid == 0 || self.sudo_invoker() == Some(uid)
    }
}

/// The `(real, effective)` uids from a `/proc/self/status` body.
///
/// `strip_prefix` consumes the `Uid:` token, so the remaining whitespace fields are
/// `[real, effective, saved, fs]`. (A `starts_with` split would leave `Uid:` as field 0 and shift
/// both indices by one, which is why the sibling helpers in this workspace differ.)
fn uids(status: &str) -> Option<(u32, u32)> {
    let line = status.lines().find_map(|l| l.strip_prefix("Uid:"))?;
    let mut fields = line.split_whitespace();
    let real = fields.next()?.parse().ok()?;
    let effective = fields.next()?.parse().ok()?;
    Some((real, effective))
}

#[cfg(test)]
mod tests {
    use bsx_test_support::ScratchDir;

    use super::*;

    fn ids(effective: u32, real: u32, sudo: Option<u32>) -> HostIds {
        HostIds::from_parts(real, effective, sudo)
    }

    #[test]
    fn a_file_owner_is_the_euid_root_or_the_sudo_invoker() {
        // (euid, ruid, SUDO_UID, file uid, trusted)
        let cases = [
            (1000, 1000, None, 1000, true, "our own file"),
            (1000, 1000, None, 0, true, "a root-authored operator file"),
            (1000, 1000, None, 1001, false, "another local user's"),
            (0, 0, Some(1000), 1000, true, "the sudo workflow"),
            (
                0,
                0,
                Some(1000),
                1001,
                false,
                "sudo widens by exactly one uid",
            ),
            (
                0,
                1001,
                Some(1000),
                1000,
                false,
                "setuid-root: the real uid is not 0, so SUDO_UID is the attacker's to set",
            ),
            (
                1000,
                1000,
                Some(1001),
                1001,
                false,
                "SUDO_UID is inert below root",
            ),
        ];
        for (euid, ruid, sudo, file_uid, want, why) in cases {
            assert_eq!(
                ids(euid, ruid, sudo).trusts(file_uid),
                want,
                "euid {euid}, ruid {ruid}, SUDO_UID {sudo:?}, file uid {file_uid}: {why}"
            );
        }
    }

    #[test]
    fn the_uid_line_parse_reads_the_real_and_effective_fields() {
        // A setuid-shaped line on purpose: a live `/proc` read cannot tell `nth(1)` from `nth(2)`,
        // because an ordinary process's four uid fields are all equal.
        let status = "Name:\tbsx\nUid:\t1000\t0\t0\t0\nGid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(uids(status), Some((1000, 0)));
        assert_eq!(uids("Name:\tbsx\n"), None, "no Uid: line");
        assert_eq!(uids("Uid:\tnotanumber\t0\n"), None);
    }

    #[test]
    fn the_effective_uid_matches_the_owner_of_a_file_this_process_creates() {
        // The kernel's own answer, cross-checking the `/proc` read's *format*. The field index is
        // guarded by `the_uid_line_parse_reads_the_real_and_effective_fields`, which this cannot do.
        let dir = ScratchDir::created("ids-euid");
        let p = dir.path().join("owned");
        std::fs::write(&p, b"x").expect("write");
        let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&p).expect("stat"));
        assert_eq!(HostIds::current().map(HostIds::effective), Some(uid));
    }
}
