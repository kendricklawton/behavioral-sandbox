# 032. Supported platforms: two architectures, a security-maintained host-kernel floor, and pinned upstream versions *(2026-07-17)*

**Context.** The engine runs untrusted code, and its isolation rests on the host: KVM is the trust
boundary (decision 029). That makes the supported platform a *security* property, not a convenience
list, and two forces shape it. First, an end-of-life host kernel carries unpatched KVM CVEs, so "it
booted" is the wrong bar: the substrate the isolation-and-audit thesis stands on (an architecture the
engine builds for, and a patched kernel) has to be a stated, auditable line, with the security-relevant
parts **hard** (a refusal), not a fail-open degradation. Second, the pinned upstream inputs move:
Firecracker periodically **drops guest-kernel support** (it retired 4.14; the supported set is now
~5.10/6.1), so a pinned guest kernel that falls off their list would silently stop restoring on a
Firecracker bump. The floor is the substrate; the fail-open items around it are features (a missing tap
tool only fails `--net` runs).

**Decision.** Fix the supported platform, and split its checks into *refuse* vs *degrade* on the same
principle the rest of the engine uses: the isolation boundary is never a degradation.

- **Architectures: `x86_64` and `aarch64`**, Firecracker's two, and the only targets the engine builds
  (the eBPF object, the guest rootfs, the binaries). Any other arch is a **hard** refusal. For a shipped
  binary this is settled at compile time; the `doctor` check names an unsupported cross-compile rather
  than letting it fail obscurely at first boot. ***(Narrowed, 2026-07-21: supported is `x86_64`
  only. aarch64 was never privileged-tested (no arm64 KVM hardware or CI lane, and the pinned boot
  artifacts were x86_64-only), and an untested isolation boundary must not be claimed as supported,
  so the aarch64 CI matrix leg and the dormant self-hosted lane were dropped with the claim.
  Re-widening takes a tested contribution: arm64 KVM hardware, pinned arm artifacts, and a
  privileged CI lane, at which point `doctor`'s `SUPPORTED_ARCHES` and this note move together.)***
- **Host kernel: a security-maintained LTS floor, `MIN_KERNEL` (currently 5.15)**, a **hard** floor, not
  a degradation. 5.15 is a maintained LTS (so it still receives KVM security fixes) and subsumes the
  `cgroup.kill` requirement (decision 011); it does not exclude common fleets (Ubuntu 22.04 ships 5.15).
  The floor is one constant, bumped to tighten (e.g. to 6.1) as older LTSes reach end of life. **Not
  boot-enforced:** `doctor` is the enforcement surface (it exits non-zero and names the miss), but a boot
  does not hard-refuse on a version *string*, distro backports make the number an unreliable proxy, and
  the real boundary (KVM) is already hard. The policy is stated and operator-checkable; it is not a
  brittle runtime string-compare in the hot path.
- **Firecracker: pinned v1.9 (decision 001), a degradation off-pin**, a different version boots with a
  warning (API bodies may not match), because it often works; the *tested* version is v1.9, stated here.
- **Guest kernel: pinned to a Firecracker-supported version**, built into the rootfs by `xtask`. This is
  the one that tracks Firecracker's support list: when Firecracker drops a guest-kernel version, the
  pinned build must move to one they still support (the same maintenance discipline as the sha-pinned
  upstream inputs). Recorded so the coupling is not discovered as a broken restore.
- **cgroup v2 controller delegation stays a *degradation*** (decision 010): resource caps are fairness
  hygiene, not the isolation boundary, so their absence warns and runs uncapped rather than refusing.
  This is deliberately *not* promoted to the hard floor, doing so would contradict decision 010.
- **eBPF observability/enforcement stays fail-open for observation, hard-refuse for enforcement**
  (decisions 022/029): no BTF/caps degrades `--trace`/`--watch` to a coverage gap, but `--allow`
  enforcement refuses rather than running unenforced. Unchanged; restated here as part of the matrix.

**Why a floor at all, when so much fails open.** The fail-open items are *features*: a missing tap tool
only fails `--net` runs. The platform floor is the *substrate*: architecture and a patched kernel are
what the isolation-and-audit thesis rests on, so they sit with `/dev/kvm` and the boot artifacts on the
hard side of the line. Running untrusted code on an unsupported arch or an EOL kernel is a threat-model
hole, and the engine should say so, not shrug and boot.

**Relationship to prior decisions.** This adds an explicit floor to the host-check surface and the
degradation matrix, and names the maintenance coupling for the guest kernel: the un-vendored upstream
inputs move underneath a pin. It respects decision 010 (caps fail open) and decision 029 (KVM and the
host kernel are trusted-*assumed-sound*; this floor is how "assumed sound" is kept honest over time). The
reader-facing statement is the *Supported platforms* section of `docs/cli-install.md`; the two are kept
in sync.
