//! `bsx doctor`: the operator-facing host-readiness report. Renders the shared engine-runtime
//! checks ([`bsx_engine::doctor`]) plus the eBPF-observability capability row (owned by the probe
//! loader, out of `bsx-engine`), so a fresh host reads exactly what will work, degrade, or refuse
//! *before* the first sandbox. `cargo xtask setup` renders the same shared checks, one source of
//! truth for "ready", two entry points.

use std::io::{IsTerminal, Write};
use std::process::ExitCode;

use bsx_engine::BootConfig;
use bsx_engine::doctor::{self, Check, CheckStatus};

/// Whether to emit ANSI colour on a stream.
///
/// Gated on the stream actually being a terminal, because this report is a **stdout result** and
/// stdout stays pipe-clean: escape sequences must never reach `bsx doctor | …` or a file. On top of
/// that, `NO_COLOR` (any value, per the informal standard) and `TERM=dumb` both turn it off.
fn colour_enabled(is_tty: bool, no_color: bool, term: Option<&str>) -> bool {
    is_tty && !no_color && term != Some("dumb")
}

/// Colour for one stream, resolved once so every write agrees.
#[derive(Clone, Copy)]
struct Paint(bool);

impl Paint {
    /// Resolve from the process environment for a stream's TTY-ness.
    fn for_stream(is_tty: bool) -> Self {
        Self(colour_enabled(
            is_tty,
            std::env::var_os("NO_COLOR").is_some(),
            std::env::var("TERM").ok().as_deref(),
        ))
    }

    /// Wrap `s` in the SGR `code`, or return it untouched when colour is off. Only the status word
    /// is wrapped, never the surrounding brackets, so the columns still line up and a `grep` for
    /// `[warn]` on a *piped* run keeps matching.
    fn wrap(self, code: &str, s: &str) -> String {
        if self.0 {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
}

/// Flags for `bsx doctor`.
#[derive(clap::Args)]
pub struct DoctorArgs {
    /// Also print what each missing item means at runtime.
    ///
    /// The full fail-open-vs-hard-error matrix: which gaps degrade a run, which refuse it outright.
    /// Off by default so the report stays a scannable list of rows plus a verdict; the rows that
    /// aren't `ok` already carry their own fix.
    #[arg(long)]
    pub explain: bool,

    /// Emit the report as JSON instead of the human table.
    ///
    /// Exists so a host you do not own can report back: an operator runs one command and sends the
    /// output, and you have exactly what their kernel offers instead of a screenshot. The exit code
    /// is unchanged, so `bsx doctor --json && …` still gates.
    #[arg(long, conflicts_with = "explain")]
    pub json: bool,
}

/// Render `checks` as a JSON object: the verdict, then one entry per row.
///
/// Hand-rolled rather than derived, so `bsx-engine`'s `Check` carries no `Serialize` impl for one
/// caller's diagnostic rendering. The only values interpolated are this binary's own labels and
/// notes, so [`json_escape`] covers the quoting.
fn checks_as_json(checks: &[Check]) -> String {
    let rows: Vec<String> = checks
        .iter()
        .map(|c| {
            let status = match c.status {
                CheckStatus::Ok => "ok",
                CheckStatus::Warn => "warn",
                CheckStatus::Fail => "fail",
            };
            let note = c
                .note
                .as_ref()
                .map_or_else(|| "null".to_string(), |n| format!("\"{}\"", json_escape(n)));
            format!(
                "    {{\"label\": \"{}\", \"status\": \"{status}\", \"note\": {note}}}",
                json_escape(&c.label)
            )
        })
        .collect();
    format!(
        "{{\n  \"schema\": 1,\n  \"can_boot\": {},\n  \"jailed_run_available\": {},\n  \"checks\": [\n{}\n  ]\n}}",
        doctor::can_boot(checks),
        doctor::jailed_run_available(),
        rows.join(",\n")
    )
}

/// Escape a string for a JSON double-quoted scalar. Control characters go to `\uXXXX` rather than
/// through, so a note carrying an escape sequence cannot break the document a recipient parses.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Print the readiness report for `config` (resolved `flags`-free, i.e. `env > file > defaults`, so
/// the artifact paths checked are the ones a run would boot). Returns the process exit code: success
/// when the engine can boot *something* (every hard prerequisite met), a failure code when a hard
/// requirement is missing, so `bsx doctor && bsx run …` gates correctly.
#[must_use]
pub fn report(
    config: &BootConfig,
    args: &DoctorArgs,
    sources: &crate::config::Sources,
) -> ExitCode {
    let mut out = std::io::stdout();

    let mut checks = doctor::checks(config);
    checks.push(ebpf_check());
    checks.push(config_check(sources));

    // The JSON form is the whole stdout result, so it returns before any human framing is written.
    if args.json {
        let _ = writeln!(out, "{}", checks_as_json(&checks));
        return if doctor::can_boot(&checks) {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        };
    }

    let paint = Paint::for_stream(out.is_terminal());
    let _ = writeln!(out, "{}\n", paint.wrap("1", "bsx doctor: host readiness"));

    for c in &checks {
        // The rows a reader must act on are the ones that aren't `ok`, so those carry the colour;
        // green on `ok` is what makes them scannable at a glance in a long list.
        let mark = match c.status {
            CheckStatus::Ok => paint.wrap("32", "ok  "),
            CheckStatus::Warn => paint.wrap("33", "warn"),
            CheckStatus::Fail => paint.wrap("1;31", "FAIL"),
        };
        let _ = writeln!(out, "  [{mark}] {}", c.label);
        if let Some(note) = &c.note {
            let _ = writeln!(out, "         {note}");
        }
    }
    let _ = writeln!(out, "\n  {}", tally(&checks, paint));

    if args.explain {
        let _ = writeln!(out, "\nWhat a missing item means at runtime:");
        for line in doctor::matrix() {
            let _ = writeln!(out, "  {line}");
        }
    } else if checks.iter().any(|c| !matches!(c.status, CheckStatus::Ok)) {
        let _ = writeln!(
            out,
            "  What a missing item means at runtime: `bsx doctor --explain`"
        );
    }

    if doctor::can_boot(&checks) {
        let _ = writeln!(
            out,
            "\n{}",
            paint.wrap("1;32", "Ready: this host can boot a sandbox.")
        );
        // Name a first command that works *here*: the jailed default needs real root plus the jailer, so
        // suggesting it unconditionally would hand a fresh operator a failing command, and the unjailed
        // form works in the very shell reading this. The sudo form re-injects the caller's PATH via `env`,
        // because sudoers `secure_path` overrides PATH even under `-E` and would hide both a user-local
        // `bsx` and the binaries the engine resolves.
        if doctor::jailed_run_available() {
            let _ = writeln!(out, "\nTry it:\n  bsx run -- echo hello");
        } else {
            let _ = writeln!(
                out,
                "\nTry it (the default jails the VMM, which needs real root):\
                 \n  bsx run --unjailed -- echo hello                 # no root needed: still behind KVM, VMM unconfined\
                 \n  sudo -E env \"PATH=$PATH\" bsx run -- echo hello   # jailed, the supported posture"
            );
        }
        ExitCode::SUCCESS
    } else {
        // A hard prerequisite is missing, say so on stderr (the report itself is the stdout result),
        // and exit non-zero so a script can gate on it. stderr gets its own TTY check: the two
        // streams are redirected independently, so stdout's answer says nothing about this one.
        let err = std::io::stderr();
        let err_paint = Paint::for_stream(err.is_terminal());
        let _ = writeln!(
            &err,
            "{}",
            err_paint.wrap(
                "1;31",
                "bsx: not ready, a hard prerequisite above is missing (see the FAIL rows above, \
                 each names its fix), then re-run `bsx doctor`"
            )
        );
        ExitCode::from(2)
    }
}

/// One line summarising the rows above, so a reader knows whether anything needs acting on without
/// re-scanning a list that is mostly `ok`. Clean categories are dropped rather than printed as
/// zeroes, so an all-green host reads as a single short count.
fn tally(checks: &[Check], paint: Paint) -> String {
    let count = |want: fn(&CheckStatus) -> bool| checks.iter().filter(|c| want(&c.status)).count();
    let ok = count(|s| matches!(s, CheckStatus::Ok));
    let warn = count(|s| matches!(s, CheckStatus::Warn));
    let fail = count(|s| matches!(s, CheckStatus::Fail));

    let mut parts = vec![paint.wrap("32", &format!("{ok} ok"))];
    if warn > 0 {
        parts.push(paint.wrap("33", &format!("{warn} degraded")));
    }
    if fail > 0 {
        parts.push(paint.wrap("1;31", &format!("{fail} missing")));
    }
    parts.join(", ")
}

/// The eBPF-observability capability row, from the probe loader's own support check (`CAP_BPF` +
/// `CAP_PERFMON` + kernel BTF). A degradation, not hard: without it, `--trace`/`--watch` still run
/// (recording a coverage gap) and only `--allow` *enforcement* refuses.
fn ebpf_check() -> Check {
    match bsx_probes_loader::check_support() {
        Ok(()) => Check {
            label: "eBPF observability (CAP_BPF + CAP_PERFMON + kernel BTF)".to_string(),
            status: CheckStatus::Ok,
            note: None,
        },
        Err(e) => Check {
            label: "eBPF observability (CAP_BPF + CAP_PERFMON + kernel BTF)".to_string(),
            status: CheckStatus::Warn,
            note: Some(format!(
                "--trace/--watch degrade to a coverage gap and --allow enforcement refuses: {e}"
            )),
        },
    }
}

/// Which `.bsx.toml` layers this run read. Always `Ok`: a project file reaching for a user-only key
/// is refused before dispatch, so this row cannot observe that case, and a host that uses no config
/// file at all is a normal host rather than a degraded one. The row exists to explain where the
/// artifact paths in the rows above came from, and it travels in `--json` for a host you do not own.
fn config_check(sources: &crate::config::Sources) -> Check {
    let user = match sources.user_path() {
        Some(p) if p.is_file() => format!("user {}", p.display()),
        Some(p) => format!("no user file at {}", p.display()),
        None => "$HOME does not resolve, so there is no user file".to_string(),
    };
    let project = match sources.project_path() {
        Some(p) => format!(
            "project {} (house defaults, ceilings, and postures)",
            p.display()
        ),
        None => "no project file above the working directory".to_string(),
    };
    Check {
        label: "config (user file, project file)".to_string(),
        status: CheckStatus::Ok,
        note: Some(format!("{user}, {project}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colour_is_off_unless_a_terminal_wants_it() {
        // The load-bearing case: the report is a stdout result, so a redirected or piped run must
        // stay byte-clean. Everything else is a courtesy on top of that.
        assert!(
            !colour_enabled(false, false, Some("xterm-256color")),
            "piped or redirected output never carries escapes"
        );
        assert!(colour_enabled(true, false, Some("xterm-256color")));

        // NO_COLOR (any value) and TERM=dumb both opt out even on a terminal.
        assert!(!colour_enabled(true, true, Some("xterm-256color")));
        assert!(!colour_enabled(true, false, Some("dumb")));

        // An unset TERM is not "dumb"; a terminal that says nothing still gets colour.
        assert!(colour_enabled(true, false, None));
    }

    #[test]
    fn a_clean_host_tallies_without_zero_rows() {
        let row = |status| Check {
            label: String::new(),
            status,
            note: None,
        };
        let plain = Paint(false);

        // The point of dropping empty categories: an all-ok host must not read as if it had
        // findings worth scanning for.
        assert_eq!(
            tally(&[row(CheckStatus::Ok), row(CheckStatus::Ok)], plain),
            "2 ok"
        );
        assert_eq!(
            tally(
                &[
                    row(CheckStatus::Ok),
                    row(CheckStatus::Warn),
                    row(CheckStatus::Fail)
                ],
                plain
            ),
            "1 ok, 1 degraded, 1 missing"
        );
    }

    /// The point of the JSON form is that a recipient can parse it, so a note carrying a quote or
    /// a control character must not break the document.
    #[test]
    fn json_escapes_what_would_otherwise_break_the_document() {
        assert_eq!(json_escape(r#"a "quoted" path"#), r#"a \"quoted\" path"#);
        assert_eq!(json_escape("back\\slash"), "back\\\\slash");
        assert_eq!(json_escape("two\nlines"), "two\\nlines");
        // An ANSI escape in a note (a guest-influenced string can reach one) becomes , not a
        // raw control byte in someone else's parser.
        assert_eq!(json_escape("\x1b[31mred"), "\\u001b[31mred");
    }

    #[test]
    fn json_reports_every_row_with_its_status() {
        let rows = [
            Check {
                label: "kvm".to_string(),
                status: CheckStatus::Ok,
                note: None,
            },
            Check {
                label: "jailer".to_string(),
                status: CheckStatus::Warn,
                note: Some("needs \"root\"".to_string()),
            },
            Check {
                label: "arch".to_string(),
                status: CheckStatus::Fail,
                note: Some("unsupported".to_string()),
            },
        ];
        let json = checks_as_json(&rows);

        assert!(json.contains(r#""schema": 1"#));
        assert!(
            json.contains(r#""can_boot": false"#),
            "a Fail row blocks boot"
        );
        assert!(json.contains(r#"{"label": "kvm", "status": "ok", "note": null}"#));
        assert!(json.contains(r#""status": "warn", "note": "needs \"root\"""#));
        assert!(json.contains(r#""label": "arch", "status": "fail""#));
        // One entry per row, no more: the separator count pins it.
        assert_eq!(json.matches(r#""label":"#).count(), 3);
    }

    #[test]
    fn wrap_is_the_identity_when_colour_is_off() {
        assert_eq!(Paint(false).wrap("32", "ok  "), "ok  ");
        assert_eq!(Paint(true).wrap("32", "ok  "), "\x1b[32mok  \x1b[0m");
    }
}
