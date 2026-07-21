# 016. The VM is the session: one persistent in-guest working directory per agent process *(2026-07-15)*

**Context.** A stateful session, install a package, write a file, use both three execs later, needs
somewhere for state to live and a rule for when it dies. The guest filesystem already persists for
the VM's lifetime (the overlay), so the substrate is there; what the design has to pin down is where
each exec's working directory sits and how long it lasts. Two forces pull on that choice. First, the
composition users reach for first (`echo hi > x`, then `cat x`, or a file injected once and read
later) has to work at the layer they touch first, so per-exec state that evaporates after the exec it
rode in on is the wrong default. Second, isolation between sessions is a security property, so it must
rest on the hardware boundary, not on agent-side bookkeeping (core property 2): the agent is exec/IO
convenience, never a boundary, so any session concept it enforced would put isolation in the wrong
place.

**Decision.** **Session identity is VM identity.** The in-VM agent serves every connection from one
persistent per-process working directory (`serve_session(stream, dir)`, called by the in-VM binary
with a single fixed dir for its whole life): injected files, written files, and artifacts all share
it across execs. No session ids, no session protocol messages, no per-session dirs inside one VM,
an embedder that wants two isolated sessions boots two VMs (which is exactly the isolation story the
engine sells; the two-concurrent-sessions test exercises it as two VMs). State's lifetime is the
VM's: teardown discards the overlay, so nothing outlives the session, and a snapshot clone gets a
copy-on-write view of the source's accumulated state (N clones of one pre-warmed session diverge
independently, that falls out of the existing snapshot machinery, nothing new). The library-level
`serve` keeps the fresh-dir one-shot semantics: host-side unit tests run many serves in one process
and must not share (or race on) a dir; the session default is the *in-VM binary's* choice, where one
process = one VM = one tenant.

Alternatives considered:
- **Per-exec fresh dirs, state only via absolute guest paths.** Rejected: it makes the obvious
  composition fail and forces every SDK to warn "your files vanish unless you `cd /somewhere`".
- **A session id in the protocol** (per-session dirs, host-managed lifecycle). Rejected: it invents
  a second session concept inside the one the VM already provides, adds protocol surface, and its
  isolation between sessions would be agent-enforced, the agent is exec/IO convenience, never a
  boundary (core property 2). Hardware-isolated sessions are VMs.
- **Reuse one connection for many execs** instead of one-command-per-connection. Rejected here:
  orthogonal transport churn; sessions are about *state*, not connection count.

"The VM is the session" keeps the trust story unchanged (isolation between sessions is KVM, not
agent bookkeeping), costs zero new protocol, and gives the pre-warmed-pool path its natural meaning:
a pooled clone *is* a pre-warmed session.

**Consequences.**
- The two-concurrent-sessions test is two VMs, by construction.
- A future "reset the session without rebooting" (wipe the dir) would be a new agent request type,
  additive (a new tag), not a redesign.
- The session dir lives on the overlay like everything else, so a `read_only_root` boot bounds
  session state by the overlay's size (`overlay_size` ≈ half guest RAM), bulk data still belongs on
  the block-device paths.
