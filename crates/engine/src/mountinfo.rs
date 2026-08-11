//! One walk over `/proc/self/mountinfo`, for the three questions the driver asks of it.
//!
//! - **`sweep`** wants the mount points under a dir, to detach a crashed run's binds before
//!   reclaiming it.
//! - **`jail`** wants whether the mount holding a path is *shared*, since only a shared mount
//!   propagates a bind into the jailer's slave namespace.
//! - **`doctor`** wants the `nodev`/`noexec` flags of the mount holding the scratch dir.
//!
//! Three questions, one line format, and one place that knows it. The mount point is **decoded**
//! here ([`unescape_octal`]), because the kernel writes space, tab, newline and backslash as octal
//! escapes and a raw comparison silently fails to match a path containing one. Each caller keeps
//! its own selection rule (deepest-first, longest-ancestor, the overmount tie-break); only the
//! parse is shared.
//!
//! Pure and `/proc`-free: the callers read the file, this reads the text, so every selection rule is
//! unit-tested against a fixture.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt as _;
use std::path::PathBuf;

/// One mountinfo line, reduced to the fields the driver asks about.
///
/// A line is `id parent major:minor root MOUNT_POINT OPTIONS <optional…> - fstype src super`. Mount
/// point and options sit at fixed indices before the *variable-length* optional tags, which is why
/// those two are slices and the propagation tag is resolved here instead.
pub(crate) struct Mount<'a> {
    /// Field 5, with its octal escapes decoded.
    pub(crate) point: PathBuf,
    /// Field 6, the comma-separated per-mount VFS options (`nodev`, `noexec`, `relatime`, …).
    pub(crate) options: &'a str,
    /// Whether an optional tag marks this mount **shared** (`shared:N`), the propagation type that
    /// decides whether a bind made under it reaches another namespace.
    pub(crate) shared: bool,
}

/// Every parseable line of `mountinfo`. A line too short to carry a mount point and its options is
/// skipped rather than failing the walk, so a truncated table degrades to "fewer mounts" and each
/// caller's own default (copy rather than bind, assume fine, detach nothing) decides what that
/// means.
pub(crate) fn mounts(mountinfo: &str) -> impl Iterator<Item = Mount<'_>> {
    mountinfo.lines().filter_map(parse_line)
}

fn parse_line(line: &str) -> Option<Mount<'_>> {
    let mut fields = line.split(' ');
    let point = fields.nth(4).map(unescape_octal)?;
    let options = fields.next()?;
    // The optional tags run from here to a standalone `-`; everything past it is the fstype triple,
    // where a `shared:` substring would be a device name, not a propagation tag.
    let shared = fields
        .take_while(|f| *f != "-")
        .any(|f| f.starts_with("shared:"));
    Some(Mount {
        point,
        options,
        shared,
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
    fn a_short_line_is_skipped_not_a_panic() {
        // Five fields: a mount point but no options field. The walk drops it, so a truncated table
        // is fewer mounts rather than a wrong answer about the ones it did read.
        assert_eq!(mounts("garbage line with too few").count(), 0);
        assert_eq!(mounts("").count(), 0);
        assert_eq!(mounts("\n\n").count(), 0);
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
