//! Fuzz the bulk-output image reader: the ext4 parser the driver points at a filesystem whose every
//! byte the guest chose.
//!
//! **This target mirrors `collect_output_image` and must keep mirroring it.** It applies the same
//! pre-parse bound (`bsx_engine::fuzz::superblock_admits_parsing`, the engine's own function, not a
//! copy) and then catches unwinds exactly where the readback catches them. A target that validated
//! more than production would go green while production kept the bug, which is the failure this
//! shape exists to prevent.
//!
//! What the bound cannot cover, and this target therefore still finds: a panic is caught and
//! reported, but an **allocation** the parser sizes from attacker bytes aborts the process, and no
//! `catch_unwind` reaches an abort. Anything reaching one here is a real readback crash.

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
    // The readback's first act, on the same bytes and the same length it would see on disk.
    let offset = bsx_engine::fuzz::SUPERBLOCK_OFFSET as usize;
    let end = offset + bsx_engine::fuzz::SUPERBLOCK_LEN;
    if data.len() < end {
        return; // Too small to hold a superblock; the readback passes these straight to the parser.
    }
    if !bsx_engine::fuzz::superblock_admits_parsing(&data[offset..end], data.len() as u64) {
        return;
    }

    let Ok(Ok(fs)) = catch(|| Ext4::load(Box::new(data.to_vec()))) else {
        return;
    };
    let Ok(root) = PathBuf::try_from("/") else {
        return;
    };
    let mut budget = MAX_ENTRIES;
    let _ = catch(|| walk(&fs, &root, 0, &mut budget));
});

/// Run `f`, swallowing an unwind, which is what `collect_output_image` does around both the load and
/// the walk. The panic hook is silenced only for the call, so libFuzzer's own output stays readable
/// on the failures that matter (an abort, which this cannot catch and must not appear to).
fn catch<T>(f: impl FnOnce() -> T) -> Result<T, ()> {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    std::panic::set_hook(prev);
    out.map_err(|_| ())
}

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
            // Chunked, like the engine's copy loop: reading into a fixed buffer exercises the extent
            // walk without letting an inode's claimed size drive a whole-file allocation here.
            FileType::Regular => {
                if let Ok(mut src) = fs.open(&path) {
                    let mut buf = [0u8; 8192];
                    let _ = std::io::Read::read(&mut src, &mut buf);
                }
            }
            // The walk's own per-inode bound: `read_link` allocates from the inode's claimed
            // size, and the readback refuses a claim longer than a path can be. Applying it here
            // too is what keeps this target reporting only crashes production can reach.
            FileType::Symlink if meta.len() <= bsx_engine::fuzz::MAX_SYMLINK_TARGET => {
                let _ = fs.read_link(&path);
            }
            _ => {}
        }
    }
}
