//! One walk over `/proc/self/mountinfo`, for the three questions the driver asks of it: the mount
//! points under a dir (`sweep`, detaching a crashed run's binds), whether a path's mount is shared
//! (`jail`), and that mount's `nodev`/`noexec` flags (`doctor`).
//!
//! - **The mount point is decoded here** ([`unescape_octal`]): the kernel writes space, tab,
//!   newline and backslash as octal escapes, so a raw comparison misses a path containing one.
//! - **One selection rule.** [`covering`] answers "which mount holds this path" once, so `jail` and
//!   `doctor` judge the same mount; `sweep` keeps its own walk for a different question.
//! - **Pure and `/proc`-free.** The callers read the file, this reads the text, so every selection
//!   rule is unit-tested against a fixture.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt as _;
use std::path::{Path, PathBuf};

/// One mountinfo line, reduced to the fields the driver asks about: a line is
/// `id parent major:minor root MOUNT_POINT OPTIONS <optional…> - fstype src super`, so mount point
/// and options sit at fixed indices before the *variable-length* optional tags, and the propagation
/// tag has to be resolved here rather than handed back as a slice.
pub(crate) struct Mount<'a> {
    /// Field 5, with its octal escapes decoded.
    pub(crate) point: PathBuf,
    /// Field 6, the comma-separated per-mount VFS options (`nodev`, `noexec`, `relatime`, …).
    pub(crate) options: &'a str,
    /// Whether an optional tag marks this mount **shared** (`shared:N`), the one propagation type
    /// that carries a bind made under it into another namespace (the jailer's slave one).
    pub(crate) shared: bool,
    /// The filesystem type, the first field after the `-` separator. `tmpfs` here means a write
    /// charged to host RAM rather than to a disk, which is why a benchmark records it. Read by the
    /// consumers that compile this module in by `#[path]` rather than by the driver, so the driver's
    /// own build sees it unused.
    #[allow(dead_code)]
    pub(crate) fstype: &'a str,
}

/// Every parseable line of `mountinfo`. A line too short to carry a mount point and its options is
/// skipped rather than failing the walk, so a truncated table degrades to "fewer mounts" and each
/// caller's own default (copy rather than bind, assume fine, detach nothing) decides the rest.
pub(crate) fn mounts(mountinfo: &str) -> impl Iterator<Item = Mount<'_>> {
    mountinfo.lines().filter_map(parse_line)
}

/// The mount that holds `target`: the deepest mount point that is a path-prefix of it. `None` when
/// no line covers `target` (an absolute path is always covered by `/`, so only on malformed input).
pub(crate) fn covering<'a>(mountinfo: &'a str, target: &Path) -> Option<Mount<'a>> {
    let mut best: Option<(usize, Mount<'a>)> = None;
    for mount in mounts(mountinfo) {
        if !target.starts_with(&mount.point) {
            continue;
        }
        let depth = mount.point.components().count();
        // `>=`, not `>`: on an *overmount* (two mounts at the same point, so equal depth) the
        // topmost, the **last** mountinfo line, is the visible filesystem, and it decides both what
        // a later mount there inherits and the flags a file there feels.
        if best.as_ref().is_none_or(|(d, _)| depth >= *d) {
            best = Some((depth, mount));
        }
    }
    best.map(|(_, mount)| mount)
}

/// This process's own mount table, or `None` when `/proc/self/mountinfo` is unreadable.
pub(crate) fn self_text() -> Option<String> {
    std::fs::read_to_string("/proc/self/mountinfo").ok()
}

fn parse_line(line: &str) -> Option<Mount<'_>> {
    let mut fields = line.split(' ');
    let point = fields.nth(4).map(unescape_octal)?;
    let options = fields.next()?;
    // The optional tags run from here to a standalone `-`; everything past it is the fstype triple,
    // where a `shared:` substring would be a device name, not a propagation tag. Scanned to the
    // separator rather than short-circuited on the first match, so `fields` is left positioned on
    // the fstype whether or not a propagation tag was found.
    let mut shared = false;
    for field in fields.by_ref() {
        if field == "-" {
            break;
        }
        shared |= field.starts_with("shared:");
    }
    let fstype = fields.next()?;
    Some(Mount {
        point,
        options,
        shared,
        fstype,
    })
}

/// Decode a mountinfo path's octal escapes (`\040` space, `\011` tab, `\012` newline, `\134`
/// backslash) so a mount point with a space still prefix-matches correctly.
fn unescape_octal(s: &str) -> PathBuf {
    if !s.contains('\\') {
        return PathBuf::from(s);
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 4], 8)
        {
            out.push(byte);
            i += 4;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    PathBuf::from(OsString::from_vec(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// A slice with one escaped mount point, one private mount, one shared, and one that only
    /// *receives* propagation (`master:`, which is not `shared:`).
    const MOUNTINFO: &str = "\
21 1 0:20 / / rw,relatime shared:1 - ext4 /dev/root rw
30 21 0:24 / /tmp rw,nosuid,nodev shared:128 - tmpfs tmpfs rw
40 21 0:30 / /mnt/my\\040scratch rw,noexec - ext4 /dev/sdb rw
50 21 0:31 / /mnt/slave rw,relatime master:9 - ext4 /dev/sdc rw
";

    #[test]
    fn a_line_yields_its_point_options_and_propagation() {
        let all: Vec<Mount<'_>> = mounts(MOUNTINFO).collect();
        assert_eq!(all.len(), 4, "every line parses");

        assert_eq!(all[0].point, Path::new("/"));
        assert!(all[0].shared);
        assert!(all[1].options.split(',').any(|o| o == "nodev"));

        // The escaped point is decoded, which is the whole reason this walk exists: a raw
        // comparison against `/mnt/my scratch` would miss it.
        assert_eq!(all[2].point, Path::new("/mnt/my scratch"));
        assert!(all[2].options.split(',').any(|o| o == "noexec"));
        assert!(!all[2].shared, "no optional tag at all");

        // `master:` receives propagation; it does not send it.
        assert!(!all[3].shared, "master: is not shared:");
    }

    #[test]
    fn the_covering_mount_is_the_deepest_and_on_a_tie_the_last_line() {
        // `/scratch` is overmounted: the fs at 0:25 is the visible one. Under it, `/scratch/deep`
        // is a strictly deeper point that beats both same-point lines.
        let mi = "\
21 1 0:20 / / rw shared:1 - ext4 /dev/root rw
30 21 0:24 / /scratch rw,nodev shared:128 - tmpfs a rw
31 21 0:25 / /scratch rw - tmpfs b rw
32 31 0:26 / /scratch/deep rw,noexec shared:9 - tmpfs c rw
";
        let top = covering(mi, Path::new("/scratch/x")).expect("`/` always covers");
        assert!(!top.shared, "the last same-point line wins the tie");
        assert!(!top.options.contains("nodev"), "and its options answer");
        // The reverse order must flip the answer, or the tie-break is dead code.
        let flipped = mi.replace("0:24 / /scratch rw,nodev shared:128", "0:24 / /scratch rw");
        let flipped = flipped.replace("0:25 / /scratch rw ", "0:25 / /scratch rw shared:128 ");
        assert!(
            covering(&flipped, Path::new("/scratch/x"))
                .expect("`/` always covers")
                .shared,
            "shared-last reads shared"
        );
        let deep = covering(mi, Path::new("/scratch/deep/file")).expect("`/` always covers");
        assert!(
            deep.shared,
            "a strictly deeper point beats the overmount pair"
        );
        assert!(deep.options.contains("noexec"));
        assert!(
            covering("", Path::new("/anything")).is_none(),
            "no line, no mount"
        );
    }

    #[test]
    fn a_short_line_is_skipped_not_a_panic() {
        // Five fields: a mount point but no options field. The walk drops it, so a truncated table
        // is fewer mounts rather than a wrong answer about the ones it did read.
        assert_eq!(mounts("garbage line with too few").count(), 0);
        assert_eq!(mounts("").count(), 0);
        assert_eq!(mounts("\n\n").count(), 0);
    }

    /// The fstype sits past the variable-length optional tags, so it can only be read by scanning
    /// to the `-` separator. A scan that short-circuits on a propagation tag leaves the iterator
    /// mid-tags and reads one of them as the filesystem.
    #[test]
    fn the_fstype_is_read_past_the_optional_tags() {
        let plain = "40 21 0:30 / /mnt rw,noexec - ext4 /dev/sdb rw";
        assert_eq!(parse_line(plain).expect("parses").fstype, "ext4");

        let tagged = "41 21 0:31 / /scratch rw shared:22 master:7 - tmpfs tmpfs rw,size=1G";
        let mount = parse_line(tagged).expect("parses");
        assert_eq!(mount.fstype, "tmpfs", "not a propagation tag");
        assert!(mount.shared, "and the tag is still seen");

        // No fields past the separator is a truncated line, skipped like any other short one.
        assert!(parse_line("40 21 0:30 / /mnt rw -").is_none());
    }

    #[test]
    fn a_shared_token_past_the_separator_is_a_device_name_not_a_tag() {
        // The optional-tag field ends at the standalone `-`. Anything after it belongs to the
        // fstype triple, where `shared:9` is a source path a caller must not read as propagation.
        let line = "21 1 0:20 / / rw,relatime - ext4 shared:9 rw";
        let m = mounts(line).next().expect("the line parses");
        assert!(!m.shared, "the token sits past the separator");
    }

    #[test]
    fn an_unescaped_point_costs_no_allocation_path() {
        // The common case has no backslash and returns early; this pins that the early return and
        // the decoder agree.
        assert_eq!(unescape_octal("/mnt/plain"), Path::new("/mnt/plain"));
        assert_eq!(unescape_octal("/a\\040b\\011c"), Path::new("/a b\tc"));
        // A trailing backslash cannot be a complete escape, so it survives as itself.
        assert_eq!(unescape_octal("/a\\"), Path::new("/a\\"));
    }
}
