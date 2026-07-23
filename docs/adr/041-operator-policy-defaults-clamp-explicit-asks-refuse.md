# 041. Operator policy: defaults clamp, explicit asks are refused *(2026-07-22)*

**Context.** The config surface had the split backwards for an engine whose job is running untrusted
code. `.agent.toml` covered **where things live** (`kernel`, `rootfs`, `firecracker`, `scratch_dir`),
logging, and two postures (`require_limits`, the signing keys), while every **containment** knob was
caller-controlled with a default compiled into the binary: `--vcpus`, `--mem`, `--wall`,
`--output-cap`, `--unjailed`, `--net`. An operator could not set the house profile, could not lower
`MAX_VCPUS` (a `const`), and could not withdraw the `--unjailed` opt-out. The daemon made this
concrete: the wire `open` carries client-supplied `vcpus`/`mem_mib` (decision 030), so a client on the
socket could ask for 32 vCPUs on someone else's host.

Adding config keys alone would not have fixed it. The layering is **flags > env > file**
(decision 027), so a file value is *a default the caller overrides*. That is exactly right for a
default and exactly wrong for a ceiling, whose entire purpose is to bound what the caller may ask for.
A "ceiling" that the bounded party can edit is not a ceiling.

**Decision.** Add an operator policy with two kinds of knob and two different composition rules, in
one shared resolver (`crates/cli/src/policy.rs`) that both entry points call.

- **Defaults** (`vcpus`, `mem_mib`, `wall_secs`, `output_cap`) compose the ordinary way: the caller's
  value, else the operator's, else the engine's.
- **Ceilings** (`max_vcpus`, `max_mem_mib`, `max_wall_secs`, `max_output_cap`) do **not** participate
  in that precedence. They bound the result, and what happens on exceeding one depends on whether a
  caller actually asked:
  - **An explicit request above a ceiling is refused**, a typed error naming the knob, the ask, and
    the bound. Silently serving less is the degradation decision 026 forbids.
  - **A default above a ceiling is clamped.** Nobody asked for it, so there is no caller intent to
    contradict. This is not a softening: without it, setting only `max_wall_secs = 10` would refuse
    every bare run, because the *engine's* own 30s default exceeds it. A self-inconsistent policy (a
    default above its own ceiling) likewise resolves to the ceiling, the operator's stronger
    statement.
- **Postures** are monotone, a caller may tighten and never loosen: `require_jail` withdraws the
  `--unjailed` opt-out (decision 012's escape hatch, closed), `allow_net = false` refuses `--net`
  outright (it does not alter the deny-by-default egress a NIC still gets, decision 008).

**Where it binds, and where it is only a guardrail.** This asymmetry is the point, and it is recorded
rather than left implicit:

- **The daemon is the boundary.** `agent serve`'s clients arrive over a socket and control neither its
  environment nor its config, so bounding a client's `open` is real enforcement. Its policy comes from
  **explicit flags** (`--max-vcpus` and friends), never a discovered `.agent.toml`: a daemon must not
  read a security control out of whatever directory it happened to be started in. Jail and networking
  are already daemon-wide and client-immutable there, so only the ceilings travel to the session.
- **The CLI is a guardrail.** A local caller owns the config file and the environment, and
  `docs/security.md` already declares them trusted ("the caller harming the caller" is not a security
  bug). Policy there keeps a host's runs consistent; it is not a boundary, and claiming otherwise
  would be theatre.

**Alternatives considered.**
- **Just add more `.agent.toml` keys.** Rejected: under flags > env > file, a caller overrides every
  one of them, so the ceilings would read as enforcement while enforcing nothing, which is worse than
  not having them.
- **Clamp everything silently, refuse nothing.** Friendlier, and rejected for explicit asks: a caller
  who asks for 32 vCPUs and silently receives 4 has been lied to, and will debug the wrong thing. The
  split above keeps the friendliness exactly where no one is being contradicted.
- **Refuse everything over a ceiling, including defaults.** This was the first implementation, and a
  test killed it: with `max_wall_secs = 10` every bare run was refused, because the engine default is
  30s. Refusing a request the caller never made is absurd.
- **Put policy in `agent-vmm`.** Rejected: an embedder constructs `Limits` directly and *is* the
  operator, so there is no second party to bound. Policy belongs at the CLI/daemon edge, which also
  keeps the pinned engine API untouched (non-`api:`).

**Consequences and notes.**
- **Two vocabularies, deliberately.** The CLI reads `.agent.toml`; the daemon takes flags. Documented,
  because the alternative (a daemon inheriting cwd-discovered policy) is a footgun in a security
  control.
- **Absent policy changes nothing.** Every field is optional, and the default `Policy` resolves to
  exactly today's `Limits`, so no existing host's behavior moves.
- **Not covered here, and deliberately boxed separately:** an allow-list *ceiling* on `--allow` (set
  containment over egress rules, not a scalar clamp, and it lands on the egress path of decisions
  022/026) and `require_record` (which touches the record pipeline and needs a records-directory
  design). Both are their own roadmap boxes rather than being smuggled in under this mechanism.

**As shipped.** `crates/cli/src/policy.rs` holds the resolver and its table-driven tests; the daemon
enforces at `open_limits` in `crates/cli/src/session.rs` (the seam where a client's request becomes
`Limits`), with `--max-vcpus`/`--max-mem-mib`/`--max-wall-secs`/`--max-output-cap` on `agent serve`;
the CLI resolves the same way from `.agent.toml` in `crates/cli/src/main.rs`, plus `require_jail` and
`allow_net`.
