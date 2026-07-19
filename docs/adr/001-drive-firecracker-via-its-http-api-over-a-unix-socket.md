# 001. Drive Firecracker via its HTTP API over a unix socket *(2026-07-10)*

**Context.** The `vmm` driver has to control a Firecracker microVM across its whole lifecycle, not
just get one VM off the ground: boot, then pause/snapshot/restore, then clean shutdown. Two forces
shape how it talks to Firecracker. First, the trust boundary is hardware, and the host path stays
`#![forbid(unsafe_code)]`, so anything that pulls substantial `unsafe` into our process is off the
table. Second, the control surface has to carry the entire lifecycle, not only a first boot, and it
has to do so without a heavy dependency stack. Firecracker exposes exactly one surface that is stable,
documented, and covers all of that: its API socket. The alternatives each give up one of those forces.

**Alternatives considered.**
- **`firecracker --config-file`** (boot the whole VM from one JSON file, zero API calls), simpler
  for a first boot, but there's no handle to *drive* the running VM, and pause/snapshot/restore
  and clean shutdown need the socket regardless. Kept as a manual bring-up smoke test,
  not the mechanism.
- **Embedding `rust-vmm` crates** (build our own VMM), maximal control, but pulls substantial
  `unsafe` into our process and reimplements what Firecracker already hardened. Rejected: it
  violates *isolation is hardware / no-unsafe-on-the-host-path* for no first-boot gain.

**Decision.** The `vmm` driver spawns a `firecracker` child with `--api-sock` and configures the
boot over that socket's **HTTP/1.1 REST API**, `PUT /boot-source`, `/drives/{id}`,
`/machine-config`, then `/actions {InstanceStart}`. We speak HTTP with a small **hand-rolled
client over `std::os::unix::net::UnixStream`** (serde for the JSON bodies): one fresh connection
per request, `Content-Length`-framed responses, read/write timeouts. No async runtime, no HTTP
crate; the driver's only new deps are `serde`/`serde_json`/`tracing`, and the host path stays
`#![forbid(unsafe_code)]`. Hand-rolling the sliver of HTTP those ~5 calls require keeps us
dependency-light and `unsafe`-free, and the raw request/response framing stays small.

**Consequences and notes.**
- **Pinned to Firecracker v1.9's API schema.** Field names (`vcpu_count`, `mem_size_mib`,
  `is_root_device`, …) have drifted across releases; a version bump means re-checking the request
  bodies in `crates/vmm/src/firecracker.rs`.
- **Serial-console-on-stdout is an unjailed convenience.** We read the guest console from the
  `firecracker` child's stdout. The jailer changes that wiring later, so console capture sits
  behind a small internal boundary to swap out then.
- **`SendCtrlAltDel` graceful shutdown is x86-only** (i8042); the guaranteed teardown is
  `kill()` + scratch-dir removal, so no leak depends on the guest cooperating.
