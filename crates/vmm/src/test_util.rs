//! Shared unit-test helpers (compiled only under `cfg(test)`).

use std::path::{Path, PathBuf};

/// A test scratch dir that is removed even when an assertion fails first.
pub(crate) struct TestDir(PathBuf);
impl TestDir {
    pub(crate) fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("test scratch dir");
        Self(dir)
    }
    /// Own an existing dir (e.g. one `create_workdir` made) so it's reclaimed on drop.
    pub(crate) fn adopt(dir: PathBuf) -> Self {
        Self(dir)
    }
    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
