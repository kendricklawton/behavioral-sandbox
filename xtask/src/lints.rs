//! The cross-file lint the compiler cannot express.
//!
//! A workflow names repo paths as bare shell text, and the prose-drift lint reads `.rs` and `.md`
//! only, so a rename lands green here and fails days later on a scheduled job.
//!
//! It runs under `cargo xtask ci` like any other test. The twins this module also held (the two
//! `Uid:` parses, the backoff pair, the cgroup-limit mirror) each had one of their two sites inside
//! the deleted Firecracker engine, so they went with it rather than becoming a lint on a single
//! site.

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::workspace_root;

    /// Workflows name repo files as bare shell text: a parser's target, or an error message telling a
    /// human which file to edit. The prose-drift lint reads `.rs` and `.md` only, and even there it wants
    /// a backticked span, so without this a rename lands green and the weekly job fails days later on a
    /// path that no longer exists.
    ///
    /// Scoped to the `crates/` and `xtask/` prefixes, which are ours. A workflow also fetches a
    /// path out of upstream Firecracker's repo by URL, and `dist/` is build output; neither is a
    /// file this tree can be asked to hold.
    #[test]
    fn workflow_repo_paths_exist() {
        let repo = workspace_root();
        let mut checked = 0usize;
        let mut missing: Vec<String> = Vec::new();
        for (wf, text) in workflow_texts(repo) {
            for (idx, line) in text.lines().enumerate() {
                for token in line.split(|c: char| c.is_ascii_whitespace() || "\"'`(),".contains(c))
                {
                    if !(token.starts_with("crates/") || token.starts_with("xtask/")) {
                        continue;
                    }
                    // `crates/engine/**` is a path *filter*, not a file: check the dir it roots.
                    // Trailing sentence punctuation is not part of the path either.
                    let target = token
                        .trim_end_matches("/**")
                        .trim_end_matches(['.', ':', ';']);
                    checked += 1;
                    if !repo.join(target).exists() {
                        missing.push(format!("{wf}:{}: {target}", idx + 1));
                    }
                }
            }
        }
        // Without this, a workflow rename (or a move to composite actions) leaves the scan
        // matching nothing and passing green, which is the failure mode this whole test exists
        // to prevent.
        assert!(
            checked > 0,
            "no crates/ or xtask/ path reference matched in .github/workflows: the workflows no \
             longer name repo files the way this scan looks for, so it is asserting nothing"
        );
        assert!(
            missing.is_empty(),
            "workflow(s) reference repo paths that no longer exist:\n  {}",
            missing.join("\n  ")
        );
    }

    /// Every workflow file with its text, in name order: discovered by reading the directory
    /// rather than a hardcoded list, because a list silently exempts whatever it omits. Both
    /// GitHub spellings, since a `.yaml` file GitHub runs but a scan skipped would be a silent
    /// hole in exactly the coverage the callers claim; an empty directory fails here rather than
    /// leaving every caller's scan vacuously green.
    fn workflow_texts(repo: &Path) -> Vec<(String, String)> {
        let dir = repo.join(".github/workflows");
        let mut paths: Vec<_> = std::fs::read_dir(&dir)
            .expect(".github/workflows")
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| matches!(p.extension().and_then(|e| e.to_str()), Some("yml" | "yaml")))
            .collect();
        paths.sort();
        assert!(!paths.is_empty(), "no workflows found in {}", dir.display());
        paths
            .into_iter()
            .map(|p| {
                let wf = p
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let text = std::fs::read_to_string(&p).expect("read workflow");
                (wf, text)
            })
            .collect()
    }
}
