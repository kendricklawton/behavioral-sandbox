//! The prose-drift lint (part of `cargo xtask ci`): comments and docs make claims nothing else
//! compiles or tests, and three kinds are mechanically checkable, so this pass checks them:
//!
//! 1. **Repo paths in backticks.** A comment naming `` `crates/vmm/src/lib.rs` `` must point at
//!    something in the tree; a rename otherwise leaves the comment lying about where things live.
//! 2. **Relative links in Markdown.** A `[text](./file.md)` target must exist on disk; `mdbook`
//!    silently *creates* missing `SUMMARY.md` chapters as empty stubs, so a deleted page would
//!    otherwise ship as a blank one.
//! 3. **Cargo package names.** A `cargo … -p <name>` handed to a reader must name a workspace
//!    package. A crate's directory is not always its package (`crates/cli` builds `ekvm-cli`), so
//!    this is invisible to check 1: the path resolves while the command it appears in does not run.
//!    Unlike checks 1 and 2 this one reads **every** tracked text file, not just `.rs` and `.md`:
//!    a copy-pasteable command is a command wherever it is printed, and two dead `-p cli`
//!    invocations sat in `.env.example` precisely because the check skipped the file.
//!
//! This lint checks that pointers point at something, not that the prose around them is still
//! *true*; the meaning half stays with review, and the standing rule is to promote a checkable
//! prose promise into a type or test.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{bail, Context, Result};

/// One broken reference, kept as a rendered line so the report stays a plain sorted list.
type Violation = String;

pub fn check(root: &Path) -> Result<()> {
    let tracked = tracked_files(root)?;
    let anchors = path_anchors(&tracked);
    let packages = package_names(root, &tracked)?;

    let mut violations: Vec<Violation> = Vec::new();
    let mut path_refs = 0usize;
    let mut links = 0usize;
    let mut pkg_refs = 0usize;

    for rel in &tracked {
        let is_rs = rel.ends_with(".rs");
        let is_md = rel.ends_with(".md");
        // Prose lives in `.rs` (comments) and `.md` (docs, incl. the `AGENTS.md` operating manual).
        // A `cargo … -p` command is read out of any tracked text file, so the read is unconditional
        // and the *prose* checks below are the ones gated on the extension.
        let Ok(text) = std::fs::read_to_string(root.join(rel)) else {
            // A tracked-but-unreadable prose file (for example deleted in the working tree) is
            // itself drift: the tree no longer matches what git says it holds. Anything else that
            // does not decode as UTF-8 is a binary fixture (`fuzz/seeds/`), not a claim.
            if is_rs || is_md {
                violations.push(format!(
                    "{rel}: tracked but missing/unreadable in the working tree"
                ));
            }
            continue;
        };

        // A `cargo … -p <name>` a reader is told to run must name a real workspace package. The
        // directory and the package name are allowed to differ here (`crates/cli` builds
        // `ekvm-cli`), which is how five copies of a `-p cli` invocation came to be printed at
        // people, in the docs, in two test headers, and in xtask's own output. Every one errored
        // with "package(s) not found in workspace". Scoping this to `.rs`/`.md` is what let two
        // more of them survive in `.env.example`, so it runs over every tracked text file.
        for (line_no, pkg) in cargo_package_refs(&text) {
            pkg_refs += 1;
            if !packages.contains(&pkg) {
                violations.push(format!(
                    "{rel}:{line_no}: `cargo … -p {pkg}`, which is not a workspace package \
                     (a crate's directory name is not always its package name)"
                ));
            }
        }
        if !is_rs && !is_md {
            continue;
        }
        // Backticked repo-path claims are checked in every prose file, `.rs` and `.md`
        // (a rename rots a `docs/*.md` path just as it does a comment's).
        for (line_no, cand) in path_candidates(&text, &anchors) {
            path_refs += 1;
            if !path_exists(&tracked, &cand) {
                violations.push(format!(
                    "{rel}:{line_no}: references `{cand}`, which matches nothing in the tree"
                ));
            }
        }
        if is_md {
            let dir = Path::new(rel).parent().unwrap_or(Path::new(""));
            for (line_no, target) in markdown_links(&text) {
                links += 1;
                if !root.join(dir).join(&target).exists() {
                    violations.push(format!("{rel}:{line_no}: links to missing file {target}"));
                }
            }
        }
    }

    if !violations.is_empty() {
        violations.sort();
        for v in &violations {
            eprintln!("prose drift: {v}");
        }
        bail!("prose drift: {} broken reference(s)", violations.len());
    }
    println!(
        "· prose drift: {path_refs} path reference(s), {links} markdown link(s), \
         {pkg_refs} cargo package reference(s) all resolve"
    );
    Ok(())
}

/// Every package name in the workspace, read from the tracked `Cargo.toml` files rather than from
/// directory names: the two differ (`crates/cli` builds `ekvm-cli`), and it is the name `-p` takes.
fn package_names(root: &Path, tracked: &BTreeSet<String>) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for rel in tracked.iter().filter(|p| p.ends_with("Cargo.toml")) {
        let Ok(text) = std::fs::read_to_string(root.join(rel)) else {
            continue;
        };
        // The first `name = "..."` after a `[package]` header. Later `[[bin]]`/`[lib]` sections
        // carry their own `name`, which `-p` does not accept.
        let mut in_package = false;
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('[') {
                in_package = line == "[package]";
                continue;
            }
            if in_package {
                if let Some(name) = line
                    .strip_prefix("name")
                    .and_then(|r| r.trim_start().strip_prefix('='))
                    .and_then(|r| r.trim().strip_prefix('"'))
                    .and_then(|r| r.split('"').next())
                {
                    names.insert(name.to_string());
                    in_package = false;
                }
            }
        }
    }
    if names.is_empty() {
        bail!("no workspace package names found: the Cargo.toml parse in drift.rs has gone stale");
    }
    Ok(names)
}

/// `-p <name>` arguments on lines that invoke `cargo`, with their 1-based line. Scoped to `cargo`
/// lines so an unrelated `-p` (`mkdir -p`, `install -p`) is never read as a package; a line that
/// does both would be reported, which is the safe direction for a lint.
fn cargo_package_refs(text: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        if !line.contains("cargo ") {
            continue;
        }
        let mut tokens = line.split_ascii_whitespace();
        while let Some(token) = tokens.next() {
            if token != "-p" {
                continue;
            }
            let Some(pkg) = tokens.next() else { continue };
            // A placeholder or a shell interpolation names no package this lint can resolve, and it
            // must not guess: `-p <name>` in a doc comment, `-p {pkg}` in a format string, `-p $PKG`
            // in a script. Checked before trimming, since trimming is what would hide them.
            if pkg.starts_with(['<', '{', '$', '"']) {
                continue;
            }
            // Trailing shell/prose punctuation (`-p ekvm,` `-p ekvm`.) is not part of the name.
            let pkg =
                pkg.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_');
            if pkg.is_empty() || pkg.starts_with('-') {
                continue;
            }
            found.push((idx + 1, pkg.to_string()));
        }
    }
    found
}

/// The tracked file list (`git ls-files`), the definition of "in the tree". Requires a git
/// checkout; the gate always runs in one.
fn tracked_files(root: &Path) -> Result<BTreeSet<String>> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z"])
        .output()
        .context("running `git ls-files` (the prose-drift lint needs a git checkout)")?;
    if !out.status.success() {
        bail!("`git ls-files` failed; the prose-drift lint needs a git checkout");
    }
    let listing = String::from_utf8(out.stdout).context("`git ls-files` output was not UTF-8")?;
    Ok(listing
        .split('\0')
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect())
}

/// Backticked tokens in the text that look like repo paths, with their 1-based line. Deliberately
/// conservative: a token must be slash-separated with a path-safe charset and its first segment
/// must be a known anchor (a top-level source dir or a crate's dir name, so crate-relative
/// references like `guest-agent/src/lib.rs` still count). Everything else, `stdout/stderr`,
/// `10.200.0.1/30`, guest-rootfs paths like `sbin/apk.static`, illustrative paths like
/// `out/x.txt`, never matches. Build outputs (`target/`, `artifacts/`) exist only after a build,
/// so they are not checkable and never anchor.
fn path_candidates(text: &str, anchors: &BTreeSet<String>) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    // Skip fenced code blocks: a `.md` example (or a shown command) may name a path that
    // needn't exist. A ```` ``` ```` fence toggles at a line's start; in `.rs` the doc-comment
    // fences are prefixed (`//! ```), so this never triggers there, leaving `.rs` behavior unchanged.
    let mut in_fence = false;
    for (idx, line) in text.lines().enumerate() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        let mut parts = line.split('`');
        let _outside = parts.next();
        while let (Some(inside), Some(_)) = (parts.next(), parts.next()) {
            if is_path_candidate(inside, anchors) {
                found.push((idx + 1, inside.to_owned()));
            }
        }
    }
    found
}

fn is_path_candidate(tok: &str, anchors: &BTreeSet<String>) -> bool {
    if !tok.contains('/')
        || tok.starts_with('/')
        || tok.contains("target/")
        || !tok
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'/' | b'-'))
    {
        return false;
    }
    let first = tok.split('/').next().unwrap_or("");
    anchors.contains(first)
}

/// The first-segment anchors that make a backticked token a repo-path claim: the top-level source
/// dirs plus every crate's dir name, derived from the tracked list so a new crate anchors itself.
fn path_anchors(tracked: &BTreeSet<String>) -> BTreeSet<String> {
    let mut anchors: BTreeSet<String> = ["crates", "docs", "xtask", ".github"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    for t in tracked {
        if let Some(rest) = t.strip_prefix("crates/") {
            if let Some((name, _)) = rest.split_once('/') {
                anchors.insert(name.to_owned());
            }
        }
    }
    anchors
}

/// Whether a referenced path names something tracked: an exact file, a directory of tracked
/// files, or (for un-anchored references like `guest-agent/src/lib.rs`) a suffix of one.
fn path_exists(tracked: &BTreeSet<String>, cand: &str) -> bool {
    let cand = cand.strip_suffix('/').unwrap_or(cand);
    tracked.contains(cand)
        || tracked.iter().any(|t| {
            t.starts_with(cand) && t.as_bytes().get(cand.len()) == Some(&b'/')
                || t.ends_with(cand) && t.as_bytes()[..t.len() - cand.len()].ends_with(b"/")
        })
}

/// Relative link targets in Markdown (`[text](target)`), with their 1-based line. External
/// (`http`, `mailto:`), in-page (`#anchor`), and fenced-code-block content are skipped; a
/// `path#anchor` target is checked as `path`.
/// Blank out inline code spans (backtick-delimited) in one line, so link syntax shown *as code*
/// isn't scanned as a live link. Backticks toggle in/out of a span; an unbalanced backtick drops the
/// rest of the line (conservative: a lint skips rather than false-positives). Only the surviving
/// text matters to the caller (it reports line numbers, not columns), so spans are dropped outright.
fn strip_inline_code(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut in_code = false;
    for c in line.chars() {
        if c == '`' {
            in_code = !in_code;
        } else if !in_code {
            out.push(c);
        }
    }
    out
}

fn markdown_links(text: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let mut in_fence = false;
    for (idx, line) in text.lines().enumerate() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        // Blank out inline code spans first: a `[text](x.md)` *shown as code* (the link syntax
        // itself, e.g. in a doc about Markdown) is not a live link and its target needn't exist.
        let stripped = strip_inline_code(line);
        let mut rest = stripped.as_str();
        while let Some(pos) = rest.find("](") {
            rest = &rest[pos + 2..];
            let Some(end) = rest.find(')') else { break };
            let target = &rest[..end];
            rest = &rest[end..];
            let target = target.split('#').next().unwrap_or("");
            if target.is_empty()
                || target.contains("://")
                || target.starts_with("mailto:")
                || target.contains(char::is_whitespace)
            {
                continue;
            }
            found.push((idx + 1, target.to_owned()));
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The engine targets kernels, not distributions (`docs/architecture.md`, decision 8): a host
    /// difference is probed as a capability, never read off the host's identity papers. This is
    /// the enforcer for that sentence. It scans every tracked source file in the shipped crates
    /// (plus `install.sh`, which runs before the engine exists to probe anything) for the files
    /// and commands that answer "which distro is this": if one appears outside a comment, either
    /// a capability probe exists that should replace it, or this test's list is teaching you what
    /// it is. The `Containerfile` is exempt: package manager use *inside* the image is that
    /// image's own pinned userspace, not host detection.
    #[test]
    fn shipped_code_probes_capabilities_never_distro_identity() {
        let root = crate::workspace_root();
        let tracked = tracked_files(root).expect("a git checkout");
        let needles = [
            "os-release",
            "lsb_release",
            "lsb-release",
            "/etc/debian_version",
            "/etc/redhat-release",
            "/etc/arch-release",
            "/etc/fedora-release",
            "/etc/SuSE-release",
            "ID_LIKE",
        ];

        let mut hits = Vec::new();
        for rel in tracked
            .iter()
            .filter(|p| (p.starts_with("crates/") && p.ends_with(".rs")) || *p == "install.sh")
        {
            let text = std::fs::read_to_string(root.join(rel)).unwrap_or_default();
            for (i, line) in text.lines().enumerate() {
                let code = line.trim_start();
                // A comment may *say* "no /etc/os-release parsing"; only code may not do it.
                if code.starts_with("//") || code.starts_with('#') {
                    continue;
                }
                for needle in needles {
                    if code.contains(needle) {
                        hits.push(format!("{rel}:{}: {needle}", i + 1));
                    }
                }
            }
        }
        assert!(
            hits.is_empty(),
            "shipped code reads distro identity instead of probing a capability:\n{}",
            hits.join("\n")
        );
    }

    #[test]
    fn path_candidates_skip_fenced_code_blocks() {
        let anchors = path_anchors(&BTreeSet::new());
        // A backticked path outside a fence is a candidate; the same inside a ``` fence is skipped
        // (an illustrative example that needn't exist).
        let text = "real `crates/vmm/src/lib.rs` here.\n\
                    ```\n`docs/made-up-example.md`\n```\n";
        let got = path_candidates(text, &anchors);
        assert_eq!(
            got,
            vec![(1, "crates/vmm/src/lib.rs".to_string())],
            "{got:?}"
        );
    }

    #[test]
    fn path_candidates_match_anchored_paths_not_prose_slashes() {
        let tracked: BTreeSet<String> = ["crates/vmm/src/lib.rs", "crates/guest-agent/src/lib.rs"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let anchors = path_anchors(&tracked);
        for good in [
            "crates/vmm/src/lib.rs",
            "docs/probes.md",
            "crates/probes",
            "crates/guest-agent/src/lib.rs",
        ] {
            assert!(is_path_candidate(good, &anchors), "{good}");
        }
        for bad in [
            "stdout/stderr",
            "10.200.0.1/30",
            "x86_64/aarch64",
            "/dev/kvm",
            "crates/probes/target/bpfel-unknown-none/release/probes",
            "--allow 10.200.0.1:9000/udp",
            "cargo xtask ci",
            "out/x.txt",             // an illustrative artifact path, not a repo claim
            "sbin/apk.static",       // a path inside the guest rootfs
            "artifacts/rootfs.ext4", // build output, exists only after a fetch/build
            "src/lib.rs",            // un-anchored: ambiguous, so not a checkable claim
        ] {
            assert!(!is_path_candidate(bad, &anchors), "{bad}");
        }
    }

    #[test]
    fn path_exists_matches_exact_dir_and_suffix() {
        let tracked: BTreeSet<String> = ["crates/vmm/src/lib.rs", "crates/vmm/Cargo.toml"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        assert!(path_exists(&tracked, "crates/vmm/src/lib.rs"));
        assert!(path_exists(&tracked, "crates/vmm"));
        assert!(path_exists(&tracked, "vmm/src/lib.rs"));
        assert!(path_exists(&tracked, "crates/vmm/"));
        assert!(!path_exists(&tracked, "crates/vmm/src/gone.rs"));
        assert!(
            !path_exists(&tracked, "mm/src/lib.rs"),
            "not a path segment"
        );
    }

    #[test]
    fn markdown_links_skip_external_anchor_and_fenced() {
        let text = "[a](./quickstart.md) [b](https://x.y/z) [c](#local)\n\
                    ```\n[d](inside-a-fence.md)\n```\n[e](embedding.md#api)";
        let got = markdown_links(text);
        assert_eq!(
            got,
            vec![(1, "./quickstart.md".into()), (5, "embedding.md".into())],
            "{got:?}"
        );
    }

    #[test]
    fn markdown_links_skip_inline_code_spans() {
        // Link syntax shown as code (documenting Markdown itself) is not a live link; a real link
        // on the same line still resolves.
        let text = "the form `[text](x.md)` is a link; see [real](embedding.md) for one";
        let got = markdown_links(text);
        assert_eq!(got, vec![(1, "embedding.md".into())], "{got:?}");
    }
}
