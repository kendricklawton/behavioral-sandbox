//! The privileged half of the fixture suite: these mount a real tmpfs, so they need root and run
//! under `cargo xtask ci-privileged` (whose preflight guarantees they cannot skip there).
#![allow(clippy::panic)]

use bsx_test_support::{SmallFs, have_real_root};

/// `fill_leaving(h)` promises the actual remaining space is exactly `h`. The seed file makes the
/// free space a non-multiple of the fill chunk, so the last write fails partway through: a fill
/// that counts what the loop wrote rather than what the filesystem took undercounts there, and
/// its truncate hands back space the caller was promised is gone.
#[test]
#[ignore = "mounts a tmpfs (needs root; run via `cargo xtask ci-privileged`)"]
fn fill_leaving_leaves_exactly_the_headroom() {
    if !have_real_root() {
        eprintln!("skipping fill_leaving_leaves_exactly_the_headroom: not root");
        return;
    }
    for headroom in [0u64, 32 * 1024] {
        let Some(fs) = SmallFs::create(1, "fill-exact") else {
            eprintln!("skipping fill_leaving_leaves_exactly_the_headroom: tmpfs would not mount");
            return;
        };
        std::fs::write(fs.path().join("seed"), vec![0u8; 100]).expect("seed an odd-sized file");
        fs.fill_leaving(headroom);
        let (_, avail) = fs.size_bytes().expect("df reads the fixture back");
        assert_eq!(
            avail,
            headroom,
            "fill_leaving({headroom}) must leave exactly that much free ({})",
            fs.state()
        );
    }
}
