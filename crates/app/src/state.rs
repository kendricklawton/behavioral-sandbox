//! What the notebook remembers between launches: one `key value` file beside the runs
//! directory, written whole to a temporary file and renamed, read leniently (an unknown key is
//! a later build's; a file this build cannot read is nothing saved).

use std::io;
use std::path::{Path, PathBuf};

/// The state format's version, the first line of the file.
const FORMAT: u32 = 1;

/// The file's name, a sibling of the runs directory.
const FILE: &str = "app-state";

/// The state file's path: beside the runs directory, or inside it when there is no beside.
fn beside(runs: &Path) -> PathBuf {
    runs.parent()
        .map_or_else(|| runs.join(FILE), |parent| parent.join(FILE))
}

/// The saved theme name, or `None` for a file that is absent, unreadable or a later format.
pub(crate) fn load() -> Option<String> {
    let runs = bsx_record::runs_dir().ok()?;
    let text = std::fs::read_to_string(beside(&runs)).ok()?;
    parse(&text)
}

/// Saves the picked theme, whole: the temporary is renamed over the file, never left.
pub(crate) fn save(theme: &iced::Theme) -> io::Result<()> {
    save_at(&beside(&bsx_record::runs_dir()?), theme)
}

fn save_at(path: &Path, theme: &iced::Theme) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, render(theme))?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

fn render(theme: &iced::Theme) -> String {
    format!("state {FORMAT}\ntheme {theme}\n")
}

fn parse(text: &str) -> Option<String> {
    let mut lines = text.lines();
    if lines.next()? != format!("state {FORMAT}") {
        return None;
    }
    lines.find_map(|line| line.strip_prefix("theme ").map(str::to_owned))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `save` writes parses back; a later format, garbage, or a missing format line is
    /// nothing saved; a key this build does not know is passed over.
    #[test]
    fn the_state_file_round_trips_and_a_file_this_build_cannot_read_is_nothing_saved() {
        assert_eq!(
            parse(&render(&iced::Theme::Nord)).as_deref(),
            Some("Nord"),
            "its own text parses"
        );
        assert_eq!(parse("state 2\ntheme Nord\n"), None, "a later format");
        assert_eq!(parse("theme Nord\n"), None, "no format line");
        assert_eq!(parse("not even lines"), None);
        assert_eq!(
            parse("state 1\nfuture x\ntheme Nord\n").as_deref(),
            Some("Nord"),
            "an unknown key is passed over"
        );
    }

    /// The file sits beside the runs directory, so `$BSX_RUNS_DIR` isolation carries over.
    #[test]
    fn the_state_file_sits_beside_the_runs_directory() {
        assert_eq!(
            beside(Path::new("/x/bsx/runs")),
            Path::new("/x/bsx/app-state")
        );
        assert_eq!(
            beside(Path::new("/")),
            Path::new("/app-state"),
            "no beside falls inside"
        );
    }

    /// A pick lands whole under the final name, with no temporary left.
    #[test]
    fn a_pick_is_saved_whole_with_no_tmp_left() {
        let dir = bsx_test_support::ScratchDir::created("app-state");
        let path = dir.path().join(FILE);
        save_at(&path, &iced::Theme::Dracula).expect("saved");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "state 1\ntheme Dracula\n"
        );
        assert!(!path.with_extension("tmp").exists(), "no temporary stays");
        let blocked = dir.path().join("a-directory");
        std::fs::create_dir(&blocked).expect("a directory in the way");
        save_at(&blocked, &iced::Theme::Nord).expect_err("cannot rename over a directory");
        assert!(
            !blocked.with_extension("tmp").exists(),
            "a failed rename does not leave its temporary"
        );
    }
}
