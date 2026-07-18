//! `agent doctor`: the operator-facing host-readiness report. Renders the shared engine-runtime
//! checks ([`agent_vmm::doctor`]) plus the eBPF-observability capability row (owned by the probe
//! loader, out of `agent-vmm`), so a fresh host reads exactly what will work, degrade, or refuse
//! *before* the first sandbox. `cargo xtask setup` renders the same shared checks, one source of
//! truth for "ready", two entry points.

use std::io::Write;
use std::process::ExitCode;

use agent_vmm::doctor::{self, Check, CheckStatus};
use agent_vmm::BootConfig;

/// Print the readiness report for `config` (resolved `flags`-free, i.e. `env > file > defaults`, so
/// the artifact paths checked are the ones a run would boot). Returns the process exit code: success
/// when the engine can boot *something* (every hard prerequisite met), a failure code when a hard
/// requirement is missing, so `agent doctor && agent run …` gates correctly.
#[must_use]
pub fn report(config: &BootConfig) -> ExitCode {
    let mut out = std::io::stdout();
    let _ = writeln!(out, "agent doctor — host readiness\n");

    let mut checks = doctor::checks(config);
    checks.push(ebpf_check());

    for c in &checks {
        let mark = match c.status {
            CheckStatus::Ok => "ok  ",
            CheckStatus::Warn => "warn",
            CheckStatus::Fail => "FAIL",
        };
        let _ = writeln!(out, "  [{mark}] {}", c.label);
        if let Some(note) = &c.note {
            let _ = writeln!(out, "         {note}");
        }
    }

    let _ = writeln!(out, "\nWhat a missing item means at runtime:");
    for line in doctor::matrix() {
        let _ = writeln!(out, "  {line}");
    }

    if doctor::can_boot(&checks) {
        let _ = writeln!(out, "\nReady: this host can boot a sandbox.");
        ExitCode::SUCCESS
    } else {
        // A hard prerequisite is missing, say so on stderr (the report itself is the stdout result),
        // and exit non-zero so a script can gate on it.
        let _ = writeln!(
            std::io::stderr(),
            "agent: not ready — a hard prerequisite above is missing (see the FAIL rows)"
        );
        ExitCode::from(2)
    }
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
