//! Which palette the notebook draws in.
//!
//! - **A theme is a choice, not a restyling.** Every colour in `screens` comes from a semantic role
//!   on the theme's extended palette (`success.base`, `background.strong.text`) and never from a
//!   literal, so every theme the toolkit ships already works.
//! - **The list is the toolkit's plus one.** [`all`] puts the app's own New York palette ahead
//!   of `iced::Theme::ALL`, read from the toolkit, so a theme iced adds or drops cannot leave a
//!   copy behind to drift.
//! - **A name is refused, never guessed at.** A typo that silently fell back to the default would
//!   read as "that theme looks like the old one".

use std::fmt::Write as _;

/// What the notebook draws in when nothing asks otherwise.
pub(crate) fn default_theme() -> iced::Theme {
    new_york()
}

/// The app's own palette: near-black, near-white, and color kept for meaning.
fn new_york() -> iced::Theme {
    iced::Theme::custom(
        "New York",
        iced::theme::Palette {
            background: iced::Color::from_rgb8(0x09, 0x09, 0x0B),
            text: iced::Color::from_rgb8(0xFA, 0xFA, 0xFA),
            primary: iced::Color::from_rgb8(0xFA, 0xFA, 0xFA),
            success: iced::Color::from_rgb8(0x22, 0xC5, 0x5E),
            warning: iced::Color::from_rgb8(0xF5, 0x9E, 0x0B),
            danger: iced::Color::from_rgb8(0xEF, 0x44, 0x44),
        },
    )
}

/// Every theme the picker offers: the app's own first, then everything the toolkit ships.
pub(crate) fn all() -> Vec<iced::Theme> {
    std::iter::once(new_york())
        .chain(iced::Theme::ALL.iter().cloned())
        .collect()
}

/// The environment variable a theme can be named in, below the flag and above the default.
pub(crate) const ENV: &str = "BSX_THEME";

/// The theme `asked` names, or [`default_theme`] when nothing asked.
///
/// Matching ignores case and anything that is not a letter or digit, so `Tokyo Night Storm`,
/// `TokyoNightStorm` and `tokyo-night-storm` are one name.
pub(crate) fn resolve(asked: Option<&str>) -> Result<iced::Theme, String> {
    let Some(asked) = asked else {
        return Ok(default_theme());
    };
    let wanted = normalise(asked);
    if wanted.is_empty() {
        return Err(refusal(asked));
    }
    all()
        .into_iter()
        .find(|theme| normalise(&theme.to_string()) == wanted)
        .ok_or_else(|| refusal(asked))
}

/// The theme to open in, and a note when a saved name had to be let go.
///
/// An explicit ask (flag or env) is refused when unknown, as [`resolve`] refuses it; a stale
/// *saved* name only degrades to [`default_theme`], because a launch should not be blocked by
/// a file.
pub(crate) fn startup(
    asked: Option<&str>,
    saved: Option<&str>,
) -> Result<(iced::Theme, Option<String>), String> {
    if asked.is_some() {
        return resolve(asked).map(|theme| (theme, None));
    }
    let Some(saved) = saved else {
        return Ok((default_theme(), None));
    };
    match resolve(Some(saved)) {
        Ok(theme) => Ok((theme, None)),
        Err(_) => Ok((
            default_theme(),
            Some(format!(
                "the saved theme {saved:?} is not in this build; drawing in {}",
                default_theme()
            )),
        )),
    }
}

/// The theme named on the command line, else in the environment, else none.
///
/// Takes the environment's value rather than reading it, so the precedence is a pure function and
/// its test needs neither `unsafe` nor a process-global the other tests race against.
pub(crate) fn asked_for(flag: Option<&str>, env: Option<String>) -> Option<String> {
    flag.map(str::to_owned)
        .or_else(|| env.filter(|v| !v.trim().is_empty()))
}

/// What the environment asks for, if anything.
pub(crate) fn from_env() -> Option<String> {
    std::env::var(ENV).ok()
}

/// A refusal that quotes every name it would have accepted, since the set is short and fixed.
fn refusal(asked: &str) -> String {
    let mut message = format!("no theme named {asked:?}. The ones there are:");
    for theme in all() {
        let _ = write!(message, "\n  {theme}");
    }
    message
}

/// A name reduced to what distinguishes it: lowercase letters and digits.
fn normalise(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every theme the picker offers can be asked for by the name it prints, the app's own New
    /// York among them, or the list is a promise the app does not keep.
    #[test]
    fn every_theme_in_the_picker_can_be_named() {
        assert!(
            iced::Theme::ALL.len() >= 20,
            "iced ships {} themes, which is fewer than this app was written against",
            iced::Theme::ALL.len()
        );
        for theme in all() {
            let by_display = resolve(Some(&theme.to_string())).expect("its own printed name");
            assert_eq!(by_display, theme);
        }
        assert_eq!(
            resolve(Some("new-york")).expect("the app's own palette"),
            default_theme()
        );
        assert_eq!(resolve(None).expect("nothing asked"), default_theme());
    }

    /// The spelling a person actually types is accepted: the printed name, the enum's own casing,
    /// and the kebab form a shell history tends to carry.
    #[test]
    fn a_name_is_matched_however_it_is_spaced_and_cased() {
        for spelling in [
            "Tokyo Night Storm",
            "TokyoNightStorm",
            "tokyo-night-storm",
            "  tokyo night storm  ",
            "TOKYO_NIGHT_STORM",
        ] {
            assert_eq!(
                resolve(Some(spelling)).expect("one theme, five spellings"),
                iced::Theme::TokyoNightStorm,
                "{spelling:?}"
            );
        }
    }

    /// An unknown name is refused with the list, never quietly defaulted: a theme that silently
    /// did not change reads as a theme that looks like the old one.
    #[test]
    fn an_unknown_name_is_refused_and_says_what_would_have_worked() {
        let why = resolve(Some("dracola")).expect_err("a typo is not a theme");
        assert!(why.contains("dracola"), "names what was asked: {why}");
        assert!(why.contains("Dracula"), "and what was meant: {why}");
        assert!(
            resolve(Some("")).is_err(),
            "an empty name is not the default"
        );
        assert_eq!(resolve(None).expect("nothing asked"), default_theme());
    }

    /// The flag outranks the environment, which outranks the default: the order the CLI's other
    /// knobs already use. An environment set to blanks is nothing asked, not a theme named "".
    #[test]
    fn the_flag_outranks_the_environment() {
        let env = || Some("Nord".to_string());
        assert_eq!(
            asked_for(Some("Dracula"), env()).as_deref(),
            Some("Dracula")
        );
        assert_eq!(asked_for(None, env()).as_deref(), Some("Nord"));
        assert_eq!(asked_for(None, None), None);
        assert_eq!(asked_for(None, Some("   ".to_string())), None);
    }

    /// A saved theme is used; a stale one degrades to the default with a note; an explicit
    /// flag or env ask is still refused when unknown, and outranks whatever was saved.
    #[test]
    fn a_saved_theme_is_used_and_a_stale_one_degrades_with_a_note() {
        assert_eq!(
            startup(None, Some("Nord")).expect("a saved theme"),
            (iced::Theme::Nord, None)
        );
        let (theme, note) = startup(None, Some("dracola")).expect("a stale name still opens");
        assert_eq!(theme, default_theme());
        let note = note.expect("with a note");
        assert!(note.contains("dracola"), "{note}");
        startup(Some("dracola"), Some("Nord")).expect_err("an explicit ask is refused");
        assert_eq!(
            startup(Some("Nord"), Some("Dracula")).expect("the ask outranks the saved"),
            (iced::Theme::Nord, None)
        );
        assert_eq!(
            startup(None, None).expect("nothing asked"),
            (default_theme(), None)
        );
    }
}
