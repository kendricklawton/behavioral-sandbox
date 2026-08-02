//! A tiny HTTP/1.1 client for Firecracker's API, spoken over its unix socket.
//!
//! Firecracker exposes a REST API on a unix domain socket (`--api-sock`); we drive a boot with a
//! handful of `PUT`s. Rather than pull in an async runtime or an HTTP crate, we hand-roll the
//! sliver of HTTP/1.1 those calls need, it keeps the driver dependency-light and `unsafe`-free,
//! and the raw request/response framing stays small.
//!
//! Framing rules that matter (a naive client hangs on each):
//! - **One fresh connection per request.** HTTP/1.1 defaults to keep-alive, so "read to EOF"
//!   never returns; we frame the response by `Content-Length` and send `Connection: close`.
//! - **Success is `204 No Content`** with an empty body; errors are `4xx` carrying a JSON
//!   `{"fault_message": "..."}`. We surface that message as a typed error.
//! - Read/write **timeouts** bound every call so a wedged VMM is a typed error, never a hang.

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::VmmError;

/// Per-call socket timeout for the ordinary API calls, which answer instantly; this only bounds a
/// wedged VMM. The exception is `/snapshot/create` and `/snapshot/load`, whose reply is withheld
/// until Firecracker synchronously writes or reads the whole guest memory file: those use
/// [`snapshot_api_timeout`] instead, scaled by guest RAM.
const API_TIMEOUT: Duration = Duration::from_secs(5);

/// Assumed floor throughput (MiB/s) for the guest memory file during `/snapshot/create` (write) and
/// `/snapshot/load` (read). Real storage is far faster (NVMe in GB/s, network-backed volumes
/// ~100+ MB/s), so this deliberately-low floor is pure headroom: it keeps a slow disk and a
/// multi-GiB guest from making a *valid* snapshot spuriously time out, while still bounding a
/// genuinely wedged VMM.
const SNAPSHOT_FLOOR_MIB_PER_S: u32 = 32;

/// The socket timeout for a snapshot create/load call. Unlike the instant-reply calls, this one
/// blocks until Firecracker moves the entire `mem_mib`-sized memory file, so the bound is
/// [`API_TIMEOUT`] (the base reply latency) plus the time that file takes at
/// [`SNAPSHOT_FLOOR_MIB_PER_S`]. Integer division floors the per-MiB term; the base covers the
/// remainder.
pub(crate) fn snapshot_api_timeout(mem_mib: u32) -> Duration {
    API_TIMEOUT + Duration::from_secs(u64::from(mem_mib / SNAPSHOT_FLOOR_MIB_PER_S))
}

/// Cap on a response body. Firecracker's replies are at most a small JSON object; a huge
/// `Content-Length` is a broken peer and must be a typed error, not a huge upfront allocation.
const MAX_BODY: usize = 1 << 20; // 1 MiB

/// Cap on the whole response (status line + headers + body): `read_line` grows unboundedly on a
/// newline-free stream, so the reader is clamped before any line is read.
const MAX_RESPONSE: u64 = MAX_BODY as u64 + 8 * 1024;

/// A client bound to one Firecracker API socket. Cheap to clone; opens a fresh connection per call.
#[derive(Debug, Clone)]
pub(crate) struct ApiClient {
    socket: PathBuf,
}

impl ApiClient {
    pub(crate) fn new(socket: PathBuf) -> Self {
        Self { socket }
    }

    /// The socket path, so callers can poll it for readiness with `UnixStream::connect`.
    pub(crate) fn socket(&self) -> &Path {
        &self.socket
    }

    /// `PUT <path>` with a JSON body, expecting a `2xx`. A `4xx` fault becomes a typed error.
    pub(crate) fn put<B: Serialize>(&self, path: &str, body: &B) -> Result<(), VmmError> {
        self.send("PUT", path, body, API_TIMEOUT)
    }

    /// `PUT <path>` with an explicit socket timeout instead of the instant-reply [`API_TIMEOUT`],
    /// for `/snapshot/create` and `/snapshot/load`, whose reply is withheld until Firecracker moves
    /// the whole guest memory file (see [`snapshot_api_timeout`]). Framing is otherwise identical.
    pub(crate) fn put_with_timeout<B: Serialize>(
        &self,
        path: &str,
        body: &B,
        timeout: Duration,
    ) -> Result<(), VmmError> {
        self.send("PUT", path, body, timeout)
    }

    /// `PATCH <path>` with a JSON body, expecting a `2xx`. Firecracker uses `PATCH` for in-place
    /// changes to an already-configured VM, its run state (`/vm`) and a drive's backing path, so
    /// the snapshot/restore flow needs it alongside `put`. Framing is identical.
    pub(crate) fn patch<B: Serialize>(&self, path: &str, body: &B) -> Result<(), VmmError> {
        self.send("PATCH", path, body, API_TIMEOUT)
    }

    /// Serialize `body`, send `method path`, and expect a `2xx`; a `4xx` fault becomes a typed error.
    fn send<B: Serialize>(
        &self,
        method: &str,
        path: &str,
        body: &B,
        timeout: Duration,
    ) -> Result<(), VmmError> {
        let json = serde_json::to_vec(body)
            .map_err(|e| VmmError::Vmm(format!("serialize {path}: {e}")))?;
        let (status, resp) = self.request(method, path, &json, timeout)?;
        if (200..300).contains(&status) {
            return Ok(());
        }
        let detail = fault_message(&resp).unwrap_or_else(|| format!("HTTP {status}"));
        Err(VmmError::Vmm(format!("{method} {path}: {detail}")))
    }

    /// Write the request and read the framed response: `(status_code, body_bytes)`.
    fn request(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        timeout: Duration,
    ) -> Result<(u16, Vec<u8>), VmmError> {
        let ctx = || format!("api {method} {path}");
        // `connect_with_timeout` bounds the connection step so a wedged VMM API thread is a typed timeout.
        let stream = connect_with_timeout(&self.socket, timeout).map_err(|e| io_err(&ctx(), &e))?;
        // `timeout` bounds the **whole** response, not each read. A per-read `SO_RCVTIMEO` is reset by
        // every byte that arrives, so a compromised VMM (the jail's stated threat) dripping one byte
        // just inside the timeout would hold this call open indefinitely. The write is one small
        // `write_all` Firecracker drains promptly, so a per-write timeout suffices there; the read
        // side is re-armed to the *remaining* budget before every read by [`DeadlineReader`].
        let deadline = crate::spawn::deadline_after(timeout);
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|e| io_err(&ctx(), &e))?;

        // One `write_all`: request line, headers, blank line, then the body.
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\n\
             Host: localhost\r\n\
             Accept: application/json\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        req.extend_from_slice(body);
        (&stream).write_all(&req).map_err(|e| io_err(&ctx(), &e))?;
        (&stream).flush().map_err(|e| io_err(&ctx(), &e))?;

        read_response(
            BufReader::new(DeadlineReader::new(&stream, deadline)),
            &ctx(),
        )
    }
}

/// A `Read` adapter that bounds the **whole** response by one `deadline`, not each syscall. The
/// socket's own `SO_RCVTIMEO` is reset by every byte that arrives, so a peer dripping bytes slower
/// than the timeout but never pausing a full timeout's worth would never trip it. Re-arming the read
/// timeout to the *remaining* budget before each underlying read (including those `BufReader` makes
/// inside `read_line`/`read_exact`) makes the sum of all reads honor one deadline.
struct DeadlineReader<'a> {
    stream: &'a UnixStream,
    deadline: Instant,
}

impl<'a> DeadlineReader<'a> {
    fn new(stream: &'a UnixStream, deadline: Instant) -> Self {
        Self { stream, deadline }
    }
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // A blown deadline: fail now rather than arm a zero timeout, which `set_read_timeout` treats
        // as "block forever", the very hang this guards against.
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                ErrorKind::TimedOut,
                "firecracker API response exceeded its deadline",
            ));
        }
        self.stream.set_read_timeout(Some(remaining))?;
        let mut s = self.stream;
        s.read(buf)
    }
}

/// Parse `HTTP/1.1 <code> ...\r\n`, the headers, then exactly `Content-Length` body bytes.
fn read_response<R: BufRead>(reader: R, ctx: &str) -> Result<(u16, Vec<u8>), VmmError> {
    // Clamp everything we will ever read for one response, so no line/body can grow past it.
    let mut reader = reader.take(MAX_RESPONSE);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .map_err(|e| io_err(ctx, &e))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| VmmError::Vmm(format!("{ctx}: bad status line {status_line:?}")))?;

    let mut content_length = 0usize;
    let mut chunked = false;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).map_err(|e| io_err(ctx, &e))?;
        if n == 0 {
            // EOF *before* the blank line that terminates HTTP headers: the VMM closed mid-response
            // (e.g. killed after writing the status line). A truncated reply must be a typed error,
            // never the `Ok` we'd otherwise return, wrongly reporting a PUT the VMM may never have
            // applied as having succeeded.
            return Err(VmmError::Vmm(format!(
                "{ctx}: connection closed mid-headers (truncated response)"
            )));
        }
        if line.trim_end().is_empty() {
            break; // the blank line: end of headers
        }
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v
                .trim()
                .parse()
                .map_err(|_| VmmError::Vmm(format!("{ctx}: bad content-length {v:?}")))?;
        } else if let Some(v) = lower.strip_prefix("transfer-encoding:") {
            chunked = v.contains("chunked");
        }
    }
    if chunked {
        return Err(VmmError::Vmm(format!("{ctx}: unexpected chunked response")));
    }
    if content_length > MAX_BODY {
        return Err(VmmError::Vmm(format!(
            "{ctx}: content-length {content_length} exceeds the {MAX_BODY}-byte cap"
        )));
    }

    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).map_err(|e| io_err(ctx, &e))?;
    Ok((status, body))
}

/// Firecracker's error bodies are `{"fault_message": "..."}`; pull the message out if present.
fn fault_message(body: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct Fault {
        fault_message: String,
    }
    serde_json::from_slice::<Fault>(body)
        .ok()
        .map(|f| f.fault_message)
}

/// A read/write timeout is a bounded-wait expiry (typed `Timeout`); anything else is `Vmm`.
fn io_err(ctx: &str, e: &std::io::Error) -> VmmError {
    match e.kind() {
        ErrorKind::WouldBlock | ErrorKind::TimedOut => VmmError::Timeout(format!("{ctx}: {e}")),
        _ => VmmError::Vmm(format!("{ctx}: {e}")),
    }
}

// ---- API request bodies (serialized to the JSON Firecracker expects) --------------------------
// Field names and shapes are written against the pinned release's `swagger/firecracker.yaml`
// (see `spawn::PINNED_FC_VERSION`). The schema drifts across releases and fields get deprecated
// before they are removed, so a version bump means re-reading that file, not just the changelog:
// `mem_file_path` on load and `vsock_id` on the vsock device are both deprecated-but-accepted
// today, and nothing here uses either.

/// `PUT /boot-source`, the guest kernel and its command line.
#[derive(Serialize)]
pub(crate) struct BootSource<'a> {
    pub kernel_image_path: &'a str,
    pub boot_args: &'a str,
}

/// `PUT /drives/{drive_id}`, a virtio-block device. The root device becomes `/dev/vda`.
#[derive(Serialize)]
pub(crate) struct Drive<'a> {
    pub drive_id: &'a str,
    pub path_on_host: &'a str,
    pub is_root_device: bool,
    pub is_read_only: bool,
    /// The guest's IO bandwidth bound for this device (`None` omits it, an unthrottled drive). The
    /// driver sets a derived default ([`RateLimiter::default_guest_io`]); it is not a `Limits` knob.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limiter: Option<RateLimiter>,
}

/// A [Firecracker rate-limiter token bucket](https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md):
/// `size` tokens available, refilled in full every `refill_time` **milliseconds**, so the sustained
/// rate is `size / refill_time`. `one_time_burst` is extra tokens spent *before* the steady-state
/// bucket engages, so an initial burst runs unthrottled.
#[derive(Serialize)]
pub(crate) struct TokenBucket {
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub one_time_burst: Option<u64>,
    pub refill_time: u64,
}

/// A drive's `rate_limiter`: a `bandwidth` (bytes/s) and/or `ops` (IO/s) token bucket bounding the
/// guest's IO to that virtio-block device. The engine uses a bandwidth bound only (see
/// [`default_guest_io`](RateLimiter::default_guest_io)).
#[derive(Serialize)]
pub(crate) struct RateLimiter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bandwidth: Option<TokenBucket>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ops: Option<TokenBucket>,
}

/// The derived per-drive **bandwidth** cap (bytes/second): 256 MiB/s. Defense in depth against a
/// disk-thrashing guest starving a co-resident run, it sits well under a typical NVMe's throughput
/// (so a co-resident run keeps the bulk of it) yet is ample for one sandbox's normal IO.
const GUEST_IO_BANDWIDTH_BYTES_PER_S: u64 = 256 * 1024 * 1024;
/// The one-time burst (bytes) that runs unthrottled before the steady-state cap engages: 1 GiB, past
/// any rootfs the engine ships, so a cold boot's rootfs read fits inside the burst and runs
/// unthrottled *by construction*; only *sustained* thrashing beyond the burst is throttled. A
/// privileged test proves both halves live (sustained rewrites pin to the cap, boot stays
/// unthrottled): `crates/engine/tests/io_throttle.rs`.
const GUEST_IO_ONE_TIME_BURST_BYTES: u64 = 1024 * 1024 * 1024;

impl RateLimiter {
    /// The driver's derived default drive bound: a bandwidth cap with a boot-sized burst, no ops cap.
    /// An **internal derived default**, so the public contract is unchanged; surfacing it as a `Limits` field later
    /// would be an additive, `api:`-marked change.
    pub(crate) fn default_guest_io() -> Self {
        RateLimiter {
            bandwidth: Some(TokenBucket {
                size: GUEST_IO_BANDWIDTH_BYTES_PER_S,
                one_time_burst: Some(GUEST_IO_ONE_TIME_BURST_BYTES),
                refill_time: 1000,
            }),
            ops: None,
        }
    }
}

/// `PUT /machine-config`, the vCPU and memory budget.
#[derive(Serialize)]
pub(crate) struct MachineConfig {
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
}

/// `PUT /actions`, an instance action. The closed set of actions the driver issues, modelled as an
/// enum so the wire discriminant can't be mistyped; serializes to `{"action_type": "<PascalCase>"}`,
/// matching Firecracker's schema (mirrors how `ekvm-channel` centralizes its `TAG_*` wire discriminants).
#[derive(Serialize)]
#[serde(tag = "action_type")]
pub(crate) enum Action {
    InstanceStart,
    SendCtrlAltDel,
}

/// `PUT /vsock`, a virtio-vsock device. The host reaches a guest-listening port by connecting to
/// `uds_path` and sending `CONNECT <port>\n`; the guest sees it on context id `guest_cid`.
#[derive(Serialize)]
pub(crate) struct Vsock<'a> {
    pub guest_cid: u32,
    pub uds_path: &'a str,
}

/// `PUT /network-interfaces/{iface_id}`, a virtio-net device backed by a host tap. Firecracker does
/// not create the tap; the host makes it first and names it here via `host_dev_name`. Rate limiters
/// are optional and omitted (deny-by-default; no shaping in this engine).
#[derive(Serialize)]
pub(crate) struct NetworkInterface<'a> {
    pub iface_id: &'a str,
    pub host_dev_name: &'a str,
    pub guest_mac: &'a str,
}

/// `PATCH /vm`, move a running VM between run states. `Paused` freezes the vCPUs (the prerequisite
/// for a consistent snapshot); `Resumed` continues them. Serializes to `{"state": "Paused"}` /
/// `{"state": "Resumed"}` (a serde unit variant serializes as its PascalCase name, matching the
/// wire schema, the same closed-set-as-enum discipline as [`Action`]).
#[derive(Serialize)]
pub(crate) struct VmState {
    pub state: VmStateKind,
}

#[derive(Serialize)]
pub(crate) enum VmStateKind {
    Paused,
    Resumed,
}

/// `PUT /snapshot/create`, write a snapshot of a **paused** VM: `snapshot_path` receives the vCPU
/// and device state, `mem_file_path` the full guest memory. Only a `Full` snapshot is taken today;
/// diff snapshots ride the prewarmed pool later.
#[derive(Serialize)]
pub(crate) struct SnapshotCreate<'a> {
    pub snapshot_type: SnapshotType,
    pub snapshot_path: &'a str,
    pub mem_file_path: &'a str,
}

#[derive(Serialize)]
pub(crate) enum SnapshotType {
    Full,
}

/// `PUT /snapshot/load`, rebuild a VM from a snapshot on a fresh VMM and (with `resume_vm`) resume
/// it. `mem_backend` names the memory file (the older `mem_file_path` is deprecated).
///
/// The load body is where the pin's *capabilities* show up, so what is deliberately **not** sent
/// matters as much as what is:
/// - `network_overrides` (rename the host tap at load) exists on the pin, but the per-VM netns
///   already makes every clone's baked-in tap name correct in its own namespace, so there is
///   nothing to rename. See `net.rs`.
/// - `vsock_override` (rebind the vsock UDS at load) exists on the pin; the driver instead bakes a
///   **relative** socket path and gives each VMM its own cwd, which achieves the same per-clone
///   socket without the field.
/// - There is **no** drive-path override at any version, which is why Firecracker reopens each
///   block device at the path baked into the snapshot and why `stage_restore_disk` exists.
#[derive(Serialize)]
pub(crate) struct SnapshotLoad<'a> {
    pub snapshot_path: &'a str,
    pub mem_backend: MemBackend<'a>,
    pub resume_vm: bool,
    /// Advance the guest's kvmclock by the wall-clock time elapsed since the snapshot was taken,
    /// instead of resuming it frozen at the instant of the snapshot (`KVM_CLOCK_REALTIME` on the
    /// restore's `KVM_SET_CLOCK`). Without it a clone wakes believing no time passed, so its
    /// monotonic clock stalls by the snapshot's age: for a **prewarmed pool**, whose whole point is
    /// that a clone may sit minutes between snapshot and take, that skew is the common case rather
    /// than the exception. x86_64-only upstream, which is this engine's only target anyway.
    ///
    /// **`None` omits the key**, which is load-bearing rather than tidy: the field only exists from
    /// v1.16, Firecracker rejects unknown fields outright, and sending it unconditionally therefore
    /// broke restore on every older release, including ones upstream still patches. Set from the
    /// probed version (`spawn::clock_realtime_arg`), so an older-but-supported binary gets a body it
    /// accepts and only loses the clock fix-up.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clock_realtime: Option<bool>,
}

#[derive(Serialize)]
pub(crate) struct MemBackend<'a> {
    pub backend_type: MemBackendType,
    pub backend_path: &'a str,
}

#[derive(Serialize)]
pub(crate) enum MemBackendType {
    File,
}

/// Connect to a Unix domain socket with a deadline, so a wedged listener is a typed timeout rather
/// than a parked host thread.
///
/// **Thread-free by construction.** `std`'s `UnixStream::connect` blocks, so bounding it used to
/// mean handing the connect to a throwaway thread and abandoning it on timeout: one detached,
/// never-joined thread per dial (and this is called for *every* Firecracker API request and every
/// exec dial), each stuck in `connect` for as long as the peer stayed wedged, holding its fd. A
/// non-blocking socket needs no thread at all.
///
/// The retry loop is the AF_UNIX shape: for a unix socket, `connect` either completes or fails
/// **immediately** (`ECONNREFUSED` with no listener, so the callers' "nothing is accepting"
/// classification is unchanged), except when the listener's backlog is full, which a non-blocking
/// socket reports as `EAGAIN` where a blocking one would have parked. That is precisely the
/// wedged-peer case the deadline exists for, so it is retried until the deadline, then reported as
/// a timeout. Each attempt uses a fresh socket: after a failed `connect` the socket's state is
/// unspecified, so reusing it would be undefined-ish territory for the sake of one syscall.
pub(crate) fn connect_with_timeout(path: &Path, timeout: Duration) -> std::io::Result<UnixStream> {
    use nix::errno::Errno;
    use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, UnixAddr};
    use std::os::fd::AsRawFd as _;

    let addr = UnixAddr::new(path)?;
    // `deadline_after`, never a bare `+`: `timeout` flows from `Limits::wall`, where
    // `Duration::MAX` is a supported "no limit" and the bare add panics on overflow.
    let deadline = crate::spawn::deadline_after(timeout);
    let mut backoff = crate::spawn::PollBackoff::new();
    loop {
        // `SOCK_CLOEXEC` matches what `UnixStream::connect` sets: without it every socket would
        // leak into the Firecracker/jailer children this driver spawns.
        let fd = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
            None,
        )?;
        match connect(fd.as_raw_fd(), &addr) {
            Ok(()) => {
                let stream = UnixStream::from(fd);
                // The callers drive blocking reads/writes under their own `SO_RCVTIMEO`, so hand
                // back a blocking stream: non-blocking was an implementation detail of the dial.
                stream.set_nonblocking(false)?;
                return Ok(stream);
            }
            // Backlog full (the wedged peer) or an interrupted call: both retryable within the
            // deadline. Any other errno is the peer's real answer, surfaced immediately.
            Err(Errno::EAGAIN | Errno::EINPROGRESS | Errno::EINTR) => {}
            Err(e) => return Err(e.into()),
        }
        drop(fd);
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "unix connect timed out",
            ));
        }
        backoff.sleep();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_no_limit_dial_timeout_is_clamped_not_a_panic() {
        // `Limits::wall = Duration::MAX` ("no limit") reaches this dial through the exec path,
        // and the bare `Instant + Duration` add panicked before the first connect attempt, so
        // surviving to the typed error IS the assertion.
        let missing = Path::new("/nonexistent/ekvm-no-such-dir/agent.sock");
        let err = connect_with_timeout(missing, Duration::MAX).expect_err("nothing listens there");
        assert_ne!(
            err.kind(),
            std::io::ErrorKind::TimedOut,
            "a dead path fails at connect, immediately, not by burning the clamped deadline"
        );
    }

    /// This process's thread count, the axis the boot soak's leak check asserts on.
    fn process_threads() -> usize {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("Threads:"))?
                    .split_whitespace()
                    .nth(1)?
                    .parse()
                    .ok()
            })
            .unwrap_or(0)
    }

    #[test]
    fn a_refused_dial_keeps_its_errno_and_a_wedged_peer_times_out() {
        use nix::sys::socket::{
            bind, listen, socket, AddressFamily, Backlog, SockFlag, SockType, UnixAddr,
        };
        use std::os::fd::AsRawFd as _;
        let dir = ekvm_test_support::ScratchDir::created("fc-connect-wedged");

        // No listener at all: callers classify `ConnectionRefused` as "nothing is accepting", so
        // the non-blocking dial must still surface exactly that, not a timeout.
        let missing = dir.path().join("absent.sock");
        let err = connect_with_timeout(&missing, Duration::from_secs(1))
            .expect_err("a missing socket must fail");
        assert!(
            matches!(
                err.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
            ),
            "the peer's own errno survives: {err} ({:?})",
            err.kind()
        );

        // A listener that never accepts, with a 1-deep backlog: once it fills, further dials are
        // the wedged-peer case, and the deadline (not a parked thread) is what ends them.
        let wedged = dir.path().join("wedged.sock");
        let addr = UnixAddr::new(&wedged).expect("addr");
        let server = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )
        .expect("server socket");
        bind(server.as_raw_fd(), &addr).expect("bind");
        listen(&server, Backlog::new(1).expect("backlog")).expect("listen");

        // Hold every successful dial open so the backlog stays full.
        let mut held = Vec::new();
        let mut timed_out = None;
        for _ in 0..64 {
            match connect_with_timeout(&wedged, Duration::from_millis(150)) {
                Ok(s) => held.push(s),
                Err(e) => {
                    timed_out = Some(e);
                    break;
                }
            }
        }
        let err = timed_out.expect("a never-accepting listener must eventually refuse a dial");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::TimedOut,
            "a full backlog is the deadline's case, not an error passthrough: {err}"
        );

        // The leak this function was rewritten to close: the old implementation abandoned a
        // thread parked in `connect` on every timeout, so a wedged peer (a hung Firecracker API
        // socket) stranded one thread *and its fd* per dial, forever, with nothing to reap them.
        // The backlog is full now, so each of these dials is that case. A few threads of drift
        // from the parallel test harness are tolerable; sixteen are the bug.
        const WEDGED_DIALS: usize = 16;
        let threads_before = process_threads();
        for _ in 0..WEDGED_DIALS {
            assert!(
                connect_with_timeout(&wedged, Duration::from_millis(20)).is_err(),
                "the backlog is full; every further dial must time out"
            );
        }
        let grew = process_threads().saturating_sub(threads_before);
        assert!(
            grew < WEDGED_DIALS / 2,
            "timed-out dials stranded {grew} threads (of {WEDGED_DIALS} dials): a wedged peer \
             must cost no threads"
        );
        drop(held);
    }

    #[test]
    fn snapshot_timeout_scales_with_guest_ram_and_floors_at_the_base() {
        // A tiny guest still gets at least the base reply latency.
        assert_eq!(snapshot_api_timeout(1), API_TIMEOUT);
        // 256 MiB at the 32 MiB/s floor: base + 8s.
        assert_eq!(
            snapshot_api_timeout(256),
            API_TIMEOUT + Duration::from_secs(8)
        );
        // A multi-GiB guest gets a bound far past the old fixed 5s (the bug: a valid snapshot that
        // takes ~tens of seconds to write must not spuriously time out).
        assert_eq!(
            snapshot_api_timeout(4096),
            API_TIMEOUT + Duration::from_secs(128)
        );
        assert!(snapshot_api_timeout(4096) > Duration::from_secs(60));
        // The largest plausible guest still yields a finite, non-panicking bound.
        assert!(snapshot_api_timeout(u32::MAX) > API_TIMEOUT);
    }

    #[test]
    fn a_drip_feeding_peer_trips_the_whole_response_deadline() {
        // The finding: a per-read `SO_RCVTIMEO` is reset by every byte, so a peer dripping bytes
        // faster than the timeout but never completing the response would never trip it and would
        // hold `request` open indefinitely. `DeadlineReader` bounds the *sum* of reads by one
        // deadline, so a drip that never finishes still fails, at the deadline, regardless of the
        // per-byte interval. Prove it: a peer sends a byte every 20 ms forever (never a full
        // response), against a 200 ms deadline. A per-read scheme would never fire (each byte lands
        // well inside any per-read window); the deadline scheme must.
        use std::io::Write;
        use std::os::unix::net::UnixStream;
        let (client, mut server) = UnixStream::pair().expect("socketpair");
        let feeder = std::thread::spawn(move || {
            // Non-newline bytes so `read_line` never completes a status line; drip past the deadline.
            for _ in 0..100 {
                if server.write_all(b"a").is_err() {
                    break; // reader hung up at its deadline
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let started = Instant::now();
        let deadline = started + Duration::from_millis(200);
        let err = read_response(
            BufReader::new(DeadlineReader::new(&client, deadline)),
            "drip test",
        )
        .expect_err("a never-completing drip must trip the deadline");
        assert!(
            matches!(err, VmmError::Timeout(_)),
            "expected a typed Timeout, got {err:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "must fail at the ~200ms deadline, not keep reading the drip: {:?}",
            started.elapsed()
        );
        drop(client); // unblock the feeder's next write
        let _ = feeder.join();
    }

    #[test]
    fn parses_204_no_content() {
        let raw =
            b"HTTP/1.1 204 No Content\r\nServer: Firecracker API\r\nContent-Length: 0\r\n\r\n";
        let (status, body) = read_response(&raw[..], "test").unwrap();
        assert_eq!(status, 204);
        assert!(body.is_empty());
    }

    #[test]
    fn parses_204_without_content_length_header() {
        // Some responses omit Content-Length entirely on an empty body, must not hang.
        let raw = b"HTTP/1.1 204 No Content\r\n\r\n";
        let (status, body) = read_response(&raw[..], "test").unwrap();
        assert_eq!(status, 204);
        assert!(body.is_empty());
    }

    #[test]
    fn truncated_headers_before_the_blank_line_is_an_error() {
        // A VMM killed after the status line (no terminating blank line, connection closes) must be
        // a typed error, not the `Ok((204, empty))` an EOF-as-end-of-headers reading would return,
        // wrongly reporting an unapplied PUT as success.
        let raw = b"HTTP/1.1 204 No Content\r\n";
        let err = read_response(&raw[..], "test").expect_err("a truncated response must error");
        assert!(
            matches!(err, VmmError::Vmm(ref m) if m.contains("mid-headers")),
            "got {err:?}"
        );
    }

    #[test]
    fn reads_exactly_content_length_bytes() {
        // The JSON body is exactly 27 bytes; the trailing `xxx` must be left on the wire, not
        // read into the body (which would make it invalid JSON).
        let raw = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 27\r\n\r\n\
                    {\"fault_message\": \"boom!!\"}xxx";
        let (status, body) = read_response(&raw[..], "test").unwrap();
        assert_eq!(status, 400);
        assert_eq!(body.len(), 27);
        assert_eq!(fault_message(&body).as_deref(), Some("boom!!"));
    }

    #[test]
    fn header_matching_is_case_insensitive() {
        let raw = b"HTTP/1.1 200 OK\r\ncOnTeNt-LeNgTh: 2\r\n\r\nhi";
        let (status, body) = read_response(&raw[..], "test").unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"hi");
    }

    #[test]
    fn chunked_is_rejected_not_misframed() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n";
        let err = read_response(&raw[..], "test").unwrap_err();
        assert!(matches!(err, VmmError::Vmm(_)));
    }

    #[test]
    fn timeouts_classify_as_timeout_other_io_as_vmm() {
        let e = io_err("test", &std::io::Error::from(ErrorKind::WouldBlock));
        assert!(matches!(e, VmmError::Timeout(_)));
        let e = io_err("test", &std::io::Error::from(ErrorKind::TimedOut));
        assert!(matches!(e, VmmError::Timeout(_)));
        let e = io_err("test", &std::io::Error::from(ErrorKind::ConnectionRefused));
        assert!(matches!(e, VmmError::Vmm(_)));
    }

    #[test]
    fn newline_free_stream_is_bounded_not_unbounded_memory() {
        // A peer that never sends `\n` must hit the response cap and fail typed, the status
        // line's String must not grow with the stream.
        let raw = vec![b'a'; MAX_RESPONSE as usize + 1024];
        assert!(read_response(&raw[..], "test").is_err());
    }

    #[test]
    fn truncated_body_is_typed_error() {
        // EOF before Content-Length bytes arrive: read_exact must surface, not hang or misframe.
        let raw = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 50\r\n\r\nshort";
        assert!(read_response(&raw[..], "test").is_err());
    }

    #[test]
    fn fault_message_on_non_json_body_is_none() {
        // `put` then falls back to the "HTTP <status>" detail.
        assert_eq!(fault_message(b"<html>oops</html>"), None);
        assert_eq!(fault_message(b""), None);
    }

    #[test]
    fn oversized_content_length_is_rejected_before_allocating() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\n";
        assert!(matches!(
            read_response(&raw[..], "test"),
            Err(VmmError::Vmm(_))
        ));
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n";
        assert!(matches!(
            read_response(&raw[..], "test"),
            Err(VmmError::Vmm(_))
        ));
    }

    #[test]
    fn bad_status_line_is_typed_error() {
        let raw = b"garbage\r\n\r\n";
        assert!(read_response(&raw[..], "test").is_err());
    }

    #[test]
    fn boot_source_serializes_to_expected_fields() {
        let json = serde_json::to_value(BootSource {
            kernel_image_path: "/k/vmlinux",
            boot_args: "console=ttyS0",
        })
        .unwrap();
        assert_eq!(json["kernel_image_path"], "/k/vmlinux");
        assert_eq!(json["boot_args"], "console=ttyS0");
    }

    #[test]
    fn root_drive_serializes_to_expected_fields() {
        let json = serde_json::to_value(Drive {
            drive_id: "rootfs",
            path_on_host: "/w/rootfs.ext4",
            is_root_device: true,
            is_read_only: false,
            rate_limiter: None,
        })
        .unwrap();
        assert_eq!(json["drive_id"], "rootfs");
        assert_eq!(json["is_root_device"], true);
        assert_eq!(json["is_read_only"], false);
        // A `None` rate limiter is omitted entirely, an unthrottled drive, not `"rate_limiter":null`.
        assert!(
            json.get("rate_limiter").is_none(),
            "an absent rate limiter must not serialize a key: {json}"
        );
    }

    #[test]
    fn default_guest_io_rate_limiter_matches_firecrackers_schema() {
        // The derived IO bound: a bandwidth token bucket (256 MiB/s, 1 GiB burst), no ops bucket. The
        // shape must be exactly what Firecracker's `PUT /drives` expects, and the ops key must be
        // omitted (not null), so this pins both the numbers and the wire shape.
        let json = serde_json::to_value(Drive {
            drive_id: "rootfs",
            path_on_host: "/w/rootfs.ext4",
            is_root_device: true,
            is_read_only: false,
            rate_limiter: Some(RateLimiter::default_guest_io()),
        })
        .unwrap();
        let bw = &json["rate_limiter"]["bandwidth"];
        assert_eq!(bw["size"], 256 * 1024 * 1024);
        assert_eq!(bw["one_time_burst"], 1024 * 1024 * 1024_u64);
        assert_eq!(bw["refill_time"], 1000);
        assert!(
            json["rate_limiter"].get("ops").is_none(),
            "the engine sets no ops bound, so the key must be absent: {json}"
        );
    }

    #[test]
    fn vsock_serializes_to_expected_fields() {
        let json = serde_json::to_value(Vsock {
            guest_cid: 3,
            uds_path: "/tmp/ekvm-1-0/v.sock",
        })
        .unwrap();
        assert_eq!(json["guest_cid"], 3);
        assert_eq!(json["uds_path"], "/tmp/ekvm-1-0/v.sock");
    }

    #[test]
    fn network_interface_serializes_to_expected_fields() {
        let json = serde_json::to_value(NetworkInterface {
            iface_id: "eth0",
            host_dev_name: "fc0",
            guest_mac: "02:00:00:00:00:01",
        })
        .unwrap();
        assert_eq!(json["iface_id"], "eth0");
        assert_eq!(json["host_dev_name"], "fc0");
        assert_eq!(json["guest_mac"], "02:00:00:00:00:01");
    }

    #[test]
    fn vm_state_serializes_to_the_wire_states() {
        let paused = serde_json::to_value(VmState {
            state: VmStateKind::Paused,
        })
        .unwrap();
        assert_eq!(paused["state"], "Paused");
        let resumed = serde_json::to_value(VmState {
            state: VmStateKind::Resumed,
        })
        .unwrap();
        assert_eq!(resumed["state"], "Resumed");
    }

    #[test]
    fn snapshot_create_serializes_to_expected_fields() {
        let json = serde_json::to_value(SnapshotCreate {
            snapshot_type: SnapshotType::Full,
            snapshot_path: "/b/snapshot.state",
            mem_file_path: "/b/snapshot.mem",
        })
        .unwrap();
        assert_eq!(json["snapshot_type"], "Full");
        assert_eq!(json["snapshot_path"], "/b/snapshot.state");
        assert_eq!(json["mem_file_path"], "/b/snapshot.mem");
    }

    #[test]
    fn snapshot_load_serializes_with_nested_mem_backend() {
        let json = serde_json::to_value(SnapshotLoad {
            snapshot_path: "/b/snapshot.state",
            mem_backend: MemBackend {
                backend_type: MemBackendType::File,
                backend_path: "/b/snapshot.mem",
            },
            resume_vm: true,
            clock_realtime: Some(true),
        })
        .unwrap();
        assert_eq!(json["snapshot_path"], "/b/snapshot.state");
        assert_eq!(json["mem_backend"]["backend_type"], "File");
        assert_eq!(json["mem_backend"]["backend_path"], "/b/snapshot.mem");
        assert_eq!(json["resume_vm"], true);
        // The clock fix-up rides the load body, so a restored clone's monotonic clock advances by
        // the snapshot's age instead of resuming frozen. The key must be spelled exactly this way:
        // Firecracker rejects an unknown field outright, so a typo fails every restore.
        assert_eq!(json["clock_realtime"], true);
        // The three fields the driver deliberately does not send. `network_overrides` and
        // `vsock_override` exist on the pin but are unnecessary under the netns + relative-socket
        // model, and no drive-path override exists at any version; an accidental `Some`-typed field
        // creeping in here would change restore semantics silently.
        for absent in ["network_overrides", "vsock_override", "mem_file_path"] {
            assert!(
                json.get(absent).is_none(),
                "the load body must not carry {absent}: {json}"
            );
        }
    }

    #[test]
    fn an_older_supported_firecracker_gets_a_load_body_without_the_clock_key() {
        // The defect this shape exists to prevent: `clock_realtime` only exists from v1.16, and
        // Firecracker rejects an *unknown field* rather than ignoring it, so a body carrying the key
        // fails the whole restore on v1.14/v1.15, both of which upstream still patches. `None` must
        // therefore omit the key entirely, not serialize `"clock_realtime": null` (which is still an
        // unknown field to a release that has never heard of it).
        let json = serde_json::to_value(SnapshotLoad {
            snapshot_path: "/b/snapshot.state",
            mem_backend: MemBackend {
                backend_type: MemBackendType::File,
                backend_path: "/b/snapshot.mem",
            },
            resume_vm: true,
            clock_realtime: None,
        })
        .unwrap();
        assert!(
            json.get("clock_realtime").is_none(),
            "an omitted clock fix-up must not appear as a key at all: {json}"
        );
        // The rest of the body is unchanged, so an older release loses the clock advance and nothing
        // else: still a real restore, still resumed.
        assert_eq!(json["snapshot_path"], "/b/snapshot.state");
        assert_eq!(json["mem_backend"]["backend_path"], "/b/snapshot.mem");
        assert_eq!(json["resume_vm"], true);
    }
}
