//! `agent doctor`: the operator-facing host-readiness report. Renders the shared engine-runtime
//! checks ([`agent_vmm::doctor`]) plus the eBPF-observability capability row (owned by the probe
//! loader, out of `agent-vmm`), so a fresh host reads exactly what will work, degrade, or refuse
//! *before* the first sandbox. `cargo xtask setup` renders the same shared checks, one source of
//! truth for "ready", two entry points.

use std::io::{IsTerminal, Write};
use std::process::ExitCode;

use agent_vmm::doctor::{self, Check, CheckStatus};
use agent_vmm::BootConfig;

/// Whether to emit ANSI colour on a stream.
///
/// Gated on the stream actually being a terminal, because this report is a **stdout result** and
/// stdout stays pipe-clean: escape sequences must never reach `agent doctor | …` or a file. On top of
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

/// Flags for `agent doctor`.
#[derive(clap::Args)]
pub struct DoctorArgs {
    /// Also print what each missing item means at runtime.
    ///
    /// The full fail-open-vs-hard-error matrix: which gaps degrade a run, which refuse it outright.
    /// Off by default so the report stays a scannable list of rows plus a verdict; the rows that
    /// aren't `ok` already carry their own fix.
    #[arg(long)]
    pub explain: bool,
}

/// Print the readiness report for `config` (resolved `flags`-free, i.e. `env > file > defaults`, so
/// the artifact paths checked are the ones a run would boot). Returns the process exit code: success
/// when the engine can boot *something* (every hard prerequisite met), a failure code when a hard
/// requirement is missing, so `agent doctor && agent run …` gates correctly.
#[must_use]
pub fn report(config: &BootConfig, args: &DoctorArgs) -> ExitCode {
    let mut out = std::io::stdout();
    let paint = Paint::for_stream(out.is_terminal());
    let _ = writeln!(out, "{}\n", paint.wrap("1", "agent doctor: host readiness"));

    let mut checks = doctor::checks(config);
    checks.push(ebpf_check());

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
            "  What a missing item means at runtime: `agent doctor --explain`"
        );
    }

    if doctor::can_boot(&checks) {
        let _ = writeln!(
            out,
            "\n{}",
            paint.wrap("1;32", "Ready: this host can boot a sandbox.")
        );
        // Name a first command that works *here*: the jailed default needs real root plus the
        // jailer, so suggesting it unconditionally would hand a fresh operator a failing command.
        if doctor::jailed_run_available() {
            let _ = writeln!(out, "\nTry it:\n  agent run -- echo hello");
        } else {
            let _ = writeln!(
                out,
                "\nTry it (the default jails the VMM, which needs real root):\
                 \n  sudo -E agent run -- echo hello       # jailed, the supported posture\
                 \n  agent run --unjailed -- echo hello    # no root: still behind KVM, VMM unconfined"
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
                "agent: not ready, a hard prerequisite above is missing (see the FAIL rows above, \
                 each names its fix), then re-run `agent doctor`"
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
    match agent_probes_loader::check_support() {
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

    #[test]
    fn wrap_is_the_identity_when_colour_is_off() {
        assert_eq!(Paint(false).wrap("32", "ok  "), "ok  ");
        assert_eq!(Paint(true).wrap("32", "ok  "), "\x1b[32mok  \x1b[0m");
    }
}
