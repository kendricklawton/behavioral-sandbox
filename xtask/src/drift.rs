//! The prose-drift lint (part of `cargo xtask ci`): comments and docs make claims nothing else
//! compiles or tests, and three kinds are mechanically checkable, so this pass checks them:
//!
//! 1. **ADR citations.** `ADR NNN` or `decision NNN` (both spellings cite the same log) in any
//!    tracked `.rs`/`.md` prose must name an ADR that exists under `docs/adr/` (a
//!    `NNN-*.md` file). A renumbered or deleted ADR otherwise turns every citation into a pointer
//!    at the wrong rationale.
//! 2. **Repo paths in backticks.** A comment naming `` `crates/vmm/src/lib.rs` `` must point at
//!    something in the tree; a rename otherwise leaves the comment lying about where things live.
//! 3. **Relative links in Markdown.** A `[text](./file.md)` target must exist on disk; `mdbook`
//!    silently *creates* missing `SUMMARY.md` chapters as empty stubs, so a deleted page would
//!    otherwise ship as a blank one.
//!
//! This lint checks that pointers point at something, not that the prose around them is still
//! *true*; the meaning half stays with review, and the standing rule is to promote a checkable
//! prose promise into a type or test.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{bail, Context, Result};

/// The decision log: the ADR folder, one `NNN-*.md` file per decision. The set of numbers those
/// filenames carry is the single source of "which decisions exist".
const ADR_DIR: &str = "docs/adr";

/// One broken reference, kept as a rendered line so the report stays a plain sorted list.
type Violation = String;

pub fn check(root: &Path) -> Result<()> {
    let tracked = tracked_files(root)?;
    let defined = defined_decisions(root)?;
    let anchors = path_anchors(&tracked);

    let mut violations: Vec<Violation> = Vec::new();
    let mut citations = 0usize;
    let mut path_refs = 0usize;
    let mut links = 0usize;

    for rel in &tracked {
        let is_rs = rel.ends_with(".rs");
        let is_md = rel.ends_with(".md");
        // Prose lives in `.rs` (comments) and `.md` (docs, incl. the `AGENTS.md` operating manual).
        if !is_rs && !is_md {
            continue;
        }
        // A tracked-but-unreadable file (for example deleted in the working tree) is itself
        // drift: the tree no longer matches what git says it holds.
        let Ok(text) = std::fs::read_to_string(root.join(rel)) else {
            violations.push(format!(
                "{rel}: tracked but missing/unreadable in the working tree"
            ));
            continue;
        };

        for (line_no, n) in cited_decisions(&text) {
            citations += 1;
            if !defined.contains(&n) {
                violations.push(format!(
                    "{rel}:{line_no}: cites decision {n:03}, no `{n:03}-*.md` ADR in {ADR_DIR}"
                ));
            }
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
        "· prose drift: {citations} ADR citation(s), {path_refs} path reference(s), \
         {links} markdown link(s) all resolve"
    );
    Ok(())
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

/// The set of decision numbers the ADR folder defines: one number per `NNN-*.md` filename (the
/// index `README.md` and any non-`NNN` file are ignored).
fn defined_decisions(root: &Path) -> Result<BTreeSet<u32>> {
    let dir = root.join(ADR_DIR);
    let mut defined = BTreeSet::new();
    let entries = std::fs::read_dir(&dir).with_context(|| format!("reading {ADR_DIR}"))?;
    for entry in entries {
        let name = entry?.file_name();
        let name = name.to_string_lossy();
        if !name.ends_with(".md") {
            continue;
        }
        if let Some(n) = leading_number(&name) {
            if !defined.insert(n) {
                bail!("{ADR_DIR} defines decision {n:03} twice");
            }
        }
    }
    if defined.is_empty() {
        bail!("{ADR_DIR} holds no `NNN-*.md` ADRs; the lint would pass vacuously");
    }
    Ok(defined)
}

/// Every ADR number the text cites, with its 1-based line. Two interchangeable spellings are
/// scanned, `ADR 010` (crate comments) and `decision 010` (docs/ROADMAP/AGENTS.md), each in singular,
/// plural, and joined forms: `Decision 010`, `decision 010/011`, `decisions 021, 026`,
/// `ADRs 021 and 026`.
///
/// Scans a **line-joined** view (each source line separated by a single space) so a citation
/// wrapped across a line break (`decision\n029`, as several live docs do) still parses as one token;
/// a per-offset line map keeps best-effort attribution (the line the keyword sits on).
fn cited_decisions(text: &str) -> Vec<(usize, u32)> {
    // Join lines with one space; record where each source line begins so an offset maps back to a
    // line. `to_ascii_lowercase` preserves byte length, so offsets in `lower` == offsets in `joined`.
    let mut joined = String::with_capacity(text.len());
    let mut line_starts = Vec::new();
    for line in text.lines() {
        line_starts.push(joined.len());
        joined.push_str(line);
        joined.push(' ');
    }
    let line_of = |offset: usize| -> usize {
        match line_starts.binary_search(&offset) {
            Ok(i) => i + 1, // offset is the first byte of line i (0-based)
            Err(i) => i,    // line_starts[i-1] <= offset < line_starts[i] ⇒ line i-1 (0-based)
        }
    };
    let lower = joined.to_ascii_lowercase();

    // Both keywords cite the same ADR log, so both are scanned; neither is a substring of the
    // other, so the two passes never double-count one citation.
    let mut found = Vec::new();
    for keyword in ["decision", "adr"] {
        let mut from = 0;
        while let Some(pos) = lower[from..].find(keyword) {
            let at = from + pos;
            // A word start: "predecision"/"quadratic" is not a citation.
            let word_start = at == 0 || !lower.as_bytes()[at - 1].is_ascii_alphanumeric();
            let mut rest = &lower[at + keyword.len()..];
            rest = rest.strip_prefix('s').unwrap_or(rest);
            if word_start {
                while let Some(n) = {
                    let trimmed = rest.trim_start();
                    let n = leading_number(trimmed);
                    if n.is_some() {
                        rest = &trimmed[3..];
                    }
                    n
                } {
                    found.push((line_of(at), n));
                    // A joined continuation ("/014", ", 026", " and 026") cites more numbers.
                    let after = rest.trim_start();
                    rest = match after
                        .strip_prefix('/')
                        .or_else(|| after.strip_prefix(','))
                        .or_else(|| after.strip_prefix("and "))
                    {
                        Some(next) => next,
                        None => break,
                    };
                }
            }
            from = at + keyword.len();
        }
    }
    found
}

/// A three-digit number at the start of `s`, not followed by a fourth digit.
fn leading_number(s: &str) -> Option<u32> {
    let b = s.as_bytes();
    if b.len() >= 3
        && b[..3].iter().all(u8::is_ascii_digit)
        && !b.get(3).is_some_and(u8::is_ascii_digit)
    {
        s[..3].parse().ok()
    } else {
        None
    }
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

    #[test]
    fn citations_parse_single_joined_and_plural_forms() {
        let text = "per decision 010.\nDecisions 021 and 026 agree; decision 010/011 too.\n\
                    predecision 999 is not a citation, nor is decision 12 or 1234.";
        let got = cited_decisions(text);
        assert_eq!(
            got,
            vec![(1, 10), (2, 21), (2, 26), (2, 10), (2, 11)],
            "{got:?}"
        );
    }

    #[test]
    fn adr_spelling_is_cited_like_decision() {
        // `ADR NNN` cites the same log as `decision NNN`; both spellings and their plural/joined
        // forms parse, and a word that merely contains "adr" (quadratic) is not a citation.
        let text = "see ADR 010 and ADRs 021/023.\nquadratic 999 is not one; ADR013 is.";
        let got = cited_decisions(text);
        assert_eq!(got, vec![(1, 10), (1, 21), (1, 23), (2, 13)], "{got:?}");
    }

    #[test]
    fn citations_wrapped_across_a_line_break_are_caught() {
        // The word "decision" ending a line with its number on the next is still one citation
        // (attributed to the line the word sits on), the live-doc drift the line-joined scan closes.
        let text = "see decision\n029 for why, and decisions 021,\n026 too.";
        let got = cited_decisions(text);
        assert_eq!(got, vec![(1, 29), (2, 21), (2, 26)], "{got:?}");
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
            "guest-agent/src/lib.rs",
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
