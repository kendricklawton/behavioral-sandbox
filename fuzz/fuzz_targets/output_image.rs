//! Fuzz the bulk-output image reader: the ext4 parser the driver points at a filesystem whose every
//! byte the guest chose. `ext4-view` states that invalid data should never crash, panic, or fail to
//! terminate; this target is what holds that claim to the bytes a sandbox can actually produce.
//! Loading and a full tree walk are both in scope, since the walk is what follows extents, directory
//! htrees and symlink targets, and the loader alone touches little more than the superblock.

#![no_main]

use ext4_view::{Ext4, FileType, PathBuf};
use libfuzzer_sys::fuzz_target;

/// Bound the walk the same way the engine's own readback does, so a corpus entry that encodes a
/// directory cycle ends the iteration instead of the run.
const MAX_DEPTH: u32 = 8;
const MAX_ENTRIES: u32 = 4096;

// `&[u8]`, not `Vec<u8>`: the `Arbitrary` impl for a vector takes its length from the input and
// truncates, so a seed image would reach the parser as a fragment of itself.
fuzz_target!(|data: &[u8]| {
    let Ok(fs) = Ext4::load(Box::new(data.to_vec())) else {
        return;
    };
    let Ok(root) = PathBuf::try_from("/") else {
        return;
    };
    let mut budget = MAX_ENTRIES;
    walk(&fs, &root, 0, &mut budget);
});

fn walk(fs: &Ext4, dir: &PathBuf, depth: u32, budget: &mut u32) {
    if depth > MAX_DEPTH {
        return;
    }
    let Ok(entries) = fs.read_dir(dir) else {
        return;
    };
    for entry in entries {
        if *budget == 0 {
            return;
        }
        *budget -= 1;
        let Ok(entry) = entry else { return };
        let name = entry.file_name();
        if name == "." || name == ".." {
            continue;
        }
        let _ = name.as_str();
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        match meta.file_type() {
            FileType::Directory => walk(fs, &path, depth + 1, budget),
            // `read` pulls the file's extents and data blocks, which is the deepest the parser goes
            // on attacker bytes. The engine copies in chunks; whole-file is the same surface here.
            FileType::Regular => {
                let _ = fs.read(&path);
            }
            FileType::Symlink => {
                let _ = fs.read_link(&path);
            }
            _ => {}
        }
    }
}
