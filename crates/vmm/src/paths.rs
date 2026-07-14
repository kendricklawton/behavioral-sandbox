//! Small shared path/file helpers used across the driver — the boot machine ([`crate::spawn`]),
//! restore ([`crate::snapshot`]), block devices ([`crate::drives`]), and the jailer
//! ([`crate::jail`]). Kept out of `vm.rs` so that module stays the public surface (`BootConfig`,
//! `Vm`, `RunningVm`, `Snapshot`) rather than the home for crate-internal plumbing. Pure,
//! `unsafe`-free, and every failure is a typed [`VmmError`].

use std::path::{Path, PathBuf};

use crate::VmmError;

/// A path as `&str`, or a typed error — Firecracker's JSON API can't carry non-UTF-8 paths.
pub(crate) fn path_str(p: &Path) -> Result<&str, VmmError> {
    p.to_str()
        .ok_or_else(|| VmmError::Vmm(format!("path is not valid UTF-8: {}", p.display())))
}

/// Resolve `p` to an absolute path against the **driver's** cwd (where a relative artifact path is
/// meant to resolve). Every *file* path handed to Firecracker must be absolute, because each VMM runs
/// with its scratch dir as cwd (so a relative vsock socket resolves per-VM — see `spawn_fc`); a
/// relative file path would otherwise resolve against that scratch dir instead. Lexical only (no
/// symlink resolution, no existence requirement), so it's safe on a path that doesn't exist yet.
pub(crate) fn absolute(p: &Path) -> Result<PathBuf, VmmError> {
    if p.is_absolute() {
        Ok(p.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(p))
            .map_err(|e| VmmError::Vmm(format!("resolve {}: {e}", p.display())))
    }
}

/// Require a file to exist, mapping absence to a clear [`VmmError::Artifact`]. Callers pass it their
/// inputs (kernel, rootfs, a snapshot bundle's files) to fail early with an actionable message.
pub(crate) fn require_file(path: &Path, what: &str) -> Result<(), VmmError> {
    if path.is_file() {
        Ok(())
    } else {
        Err(VmmError::Artifact(format!(
            "{what} not found at {} (run `cargo xtask fetch-artifacts`)",
            path.display()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_artifact_is_typed_error() {
        let err = require_file(Path::new("/no/such/vmlinux"), "kernel image").unwrap_err();
        assert!(matches!(err, VmmError::Artifact(_)));
    }
}
