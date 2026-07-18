# 029. The observability face: the CLI carries the audit surface on flags, the live view draws on stderr *(2026-07-17)*

**Decision.** What a run did becomes *legible* at the CLI, on three composable `run` flags over one
mechanism: `--trace` (the human-readable trail, on **stdout** after the run), `--record FILE` (the
deterministic JSON record, the machine surface), and `--watch` (a live full-screen view, on
**stderr**, while the command runs). A fourth flag, `--net`, boots the sandbox with its NIC so
there is a tap to observe (deny-by-default unchanged: no allowance means nothing past the host /30).
Any of the three audit flags triggers the same launch sequence decision 028 defined, load the
shared tracer + meter, boot, `SandboxProbes::attach` by plain values, exec, `collect` while the
sandbox is alive, composed **in the CLI**, never in `agent-vmm` (decisions 024/026 hold: the two
tracks still bridge only by `vmm_pid`/`netns`/`tap_name`).

**Stream discipline decides where each face lives.** The house rule is "stderr carries diagnostics,
stdout carries the run's result, so a pipeline stays clean". So: the live TUI is *interactive
diagnostics* → it draws on **stderr** (ratatui over a stderr backend; stdout still relays the
guest's output afterwards, `--watch --json` composes). The trail and the record are *requested run
output* → stdout / a file. `--trace` conflicts with `--json` (two formats interleaved on one stream
helps no one); machine consumers combine `--json --record FILE` instead. The pretty trail makes
**no stability promise**, the byte-stable contract is `RunRecord::to_json` alone (decision 028),
and the trail says so in the docs rather than growing a second frozen format.

**The live view is a reader, and the record stays authoritative.** `--watch` polls a new
non-destructive `SandboxProbes::snapshot` (`LiveSnapshot`: the tap's flows/denials now, the meter's
summary now, a *finished clone* of the syscall fold-so-far) while the exec runs on a worker thread
that owns the `Sandbox`, so watching can never disturb the fold, the maps, or the final `collect`,
and closing the view (`q`) never cancels the run. The timeline panel is derived by *diffing
successive snapshots* (new flow / denial delta / new notable syscall), pure and host-safe-tested;
terminal state is restored by a drop guard on every exit path, and a broken TUI degrades to a
headless run (logged), never a failed one, the no-panic discipline extended to the screen.

**Fail-open extends to the CLI.** A host without BTF/caps/the object still runs `--trace`: the
shared probes load fail-open and an unattached run yields the honest empty record with every absent
axis explained in coverage, a working command with a thin record, never a refused run.

**`--net` lands here, policy projection stays later.** The live view and the drill-down are about
the *network* above all, so the NIC flag could not wait for the fuller CLI-completeness phase; it
boots observe-only (no `EgressPolicy`, so the denial trail is structurally empty until `--allow`
lands with the policy projection). That later phase inherits `--net` already shipped.

**Alternative rejected.** A structured *stream* (NDJSON events during the run) instead of a TUI:
less code, pipeable, but it is a second machine surface to freeze prematurely, and the phase's
point is the *demo you show people*. The record file already serves machines; a stream can join the
daemon later if embedders want push-style events.
