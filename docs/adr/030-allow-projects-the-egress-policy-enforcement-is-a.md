# 030. `--allow` projects the egress policy: enforcement is a typed refusal, never a degradation *(2026-07-17)*

**Decision.** `agent run --allow IP[/CIDR][:PORT][/PROTO]` (repeatable, `requires` `--net`) projects
the `EgressPolicy` onto the CLI, completing the network half decision 029 pulled forward observe-only.
Each value parses into one validated allow-rule (`parse_allow`, right-to-left so the numeric CIDR
prefix and the `/tcp`|`/udp` suffix can't be confused); the rules fold into a deny-by-default policy
(`build_egress`, capped at `MAX_POLICY_RULES` with a typed refusal), which the audit-bundle launch
sequence hands to `SandboxProbes::attach` as `Some(policy)`, so it is armed on the tap *before* the
tc programs go live (the no-unpoliced-window property, decision 025). Every allowance is explicit on
the command line (guardrail 3's greppable audit line), and what the policy drops lands in the record's
denials.

**Enforcement does not fail open.** Observation degrades to a recorded coverage gap on a capless host
(a `--trace` run still works, decision 029). A *policy* can't: a run that asked to enforce one and
couldn't arm the tap would silently ignore the operator's allow-list, so it is a **typed refusal**
instead. Two layers realize this: a cheap pre-boot `check_support()` when `--allow` is present (catches
the missing-BTF/`CAP_BPF`/`CAP_PERFMON` case before paying a boot), and a post-attach check in the CLI's
`Observability::attach` that refuses if the *network* axis gapped (the residual `CAP_NET_ADMIN`/tc-attach
case the pre-flight can't see). `--allow` without `--net` is refused by clap. The split is deliberate:
the enforcement check keys on the network axis alone, so a poisoned syscall/CPU probe still degrades
observation to a gap without blocking a policed run.

**Scope.** This closes the network projection of the CLI-completeness interphase; the config-file layer,
`agent doctor`, and the JSON schema version remain. `--allow` is `run`-only, where `--net` lives (the
interactive `shell` has no network face).
