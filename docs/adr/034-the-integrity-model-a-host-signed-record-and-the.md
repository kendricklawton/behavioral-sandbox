# 034. The integrity model: a host-signed record, and the boundary a signature does not cross *(2026-07-21)*

**Context.** The engine's headline is a **tamper-evident** audit record, and today that word holds in
exactly one sense: the record is **host-observed**, so the *guest* cannot forge or alter it (decision
029, the trust boundary). But a finalized record is a plain JSON artifact, and the party that
*consumes* it, a supervising caller (decision 031) or a hoster deciding whether to trust a run, reads
it **after** it has left the producing host. Nothing today lets that consumer **detect** post-hoc
alteration by a compromised host process, an operator, or a transport in between. "Tamper-evident"
is therefore true against the guest and merely asserted against everyone downstream of the host. This
decision fixes the integrity model that makes the adjective literal, and, just as importantly, draws
the line the model does **not** cross, before any signing code is written.

**Decision.** Each finalized `RunRecord` is **signed on the host** with a key the guest never sees,
and the engine ships a **verify** path, so any alteration of the stored or transmitted record is
detectable by anyone holding the trusted public key, without their having to trust the host, operator,
or transport that relayed it to them.

- **The primitive.** An `ed25519` **detached** signature over the **canonical record bytes**, where
  "canonical" is the deterministic-JSON serialization already fixed by decision 024. Verification
  re-canonicalizes the record and checks the signature; because the byte form is deterministic, a
  round-trip is exact, and a single flipped byte fails. The signature travels in an envelope
  (`schema` + `key_id` + `signature`, plus `prev` when chained) *alongside* the record, embedded as
  an escaped JSON string so its signed bytes survive re-serialization; the record stays plaintext,
  never encrypted.
- **What the signature protects:** post-hoc alteration. Once a host has signed a record, no party that
  later stores, forwards, or serves it can change a byte, drop a field, or swap it for another host's
  record without the change being detectable at verify time. The trust root is the **host signing
  key**.
- **What it explicitly does *not* protect:** a **fully-compromised producing host**. A host that owns
  the signing key at signing time can sign a record that is internally consistent and verifies cleanly
  yet describes a run that never happened that way. The signature authenticates *"this host attests to
  these exact bytes,"* not *"these bytes are true."* This is not a gap to be closed later; it is the
  same trust root decision 029 already fixed (trust the host, not the guest), now made **verifiable
  off-host** rather than a new anchor. Moving the signing key anywhere the guest can reach would
  contradict 029 by construction.
- **Key custody is the hoster's.** The engine generates a host key on first use and loads it at
  startup (path via the layered config), and it signs. It does **not** manage tenant identities,
  per-tenant keys, a KMS, key distribution, or revocation infrastructure. Those are tenancy, and
  tenancy is the hoster's, not something the engine grows (guardrail 4, decision 013). The engine's
  whole contribution to key management is a **`key_id`** on every record and a `verify` path that
  accepts a *set* of trusted keys, so a hoster can rotate a key without invalidating records already
  signed under the old one.

**Why this shape.** `ed25519` is the right primitive here: a small (64-byte) detached signature, a
signing cost expected sub-millisecond over already-canonical bytes (off the boot path, measured like
everything else, "measured, not marketed"), deterministic signatures with no per-record nonce state to
manage, and a widely-audited implementation. Signing the **canonical** bytes rather than a re-encoding
means verify has one unambiguous thing to reconstruct, and reuses the determinism decision 024 already
pays for. Rooting trust in a **host** key adds no new trusted party: decision 029 already places the
host inside the boundary and the guest outside, so a host-held key simply lets a remote consumer check
what the host already vouched for. The honest framing is the whole point: integrity extends from
"the guest can't forge the record" to "no party downstream of the producing host can alter it
undetected," and it stops exactly at the producing host, which was trusted all along.

**Consequences (residual, stated so the claim can't overreach).** The signature is **not** proof the
run occurred as described if the producing host was compromised at signing time; a lying host signs a
consistent lie, and detecting *that* is outside this engine (it is the hoster's key custody and host
hardening). It is **not** confidentiality: a detached signature is not encryption, and the record
stays plaintext for anyone who can read it. It is **not** a PKI or identity system: there are no
tenant keys, no certificate chains, and no revocation beyond a trusted-key set plus `key_id` for
rotation. And it is **not** guest-verifiable: the guest never holds the key, consistent with 029. Each
of these is a deliberate boundary, not an unfinished edge.

**Relationship to prior decisions.** This extends decision 029: same trust root, now checkable away
from the host that produced the record. It rides decision 024's canonical bytes as the thing signed
and re-derived at verify. It serves the consumer decision 031 named (the supervising caller, a reader
of the record) and the hoster of decision 013 / guardrail 4 (custody, rotation, and distribution are
theirs). Any future change that puts the signing key inside the guest, or that grows tenant key
management into the engine, contradicts this decision.
