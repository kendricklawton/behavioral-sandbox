//! A tiny HTTP/1.1 client for Firecracker's API, spoken over its unix socket.
//!
//! Firecracker exposes a REST API on a unix domain socket (`--api-sock`); we drive a boot with a
//! handful of `PUT`s. Rather than pull in an async runtime or an HTTP crate, we hand-roll the
//! sliver of HTTP/1.1 those calls need — it keeps the driver dependency-light and `unsafe`-free,
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
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::VmmError;

/// Per-call socket timeout. The API itself answers instantly; this only bounds a wedged VMM.
const API_TIMEOUT: Duration = Duration::from_secs(5);

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
        self.send("PUT", path, body)
    }

    /// `PATCH <path>` with a JSON body, expecting a `2xx`. Firecracker uses `PATCH` for in-place
    /// changes to an already-configured VM — its run state (`/vm`) and a drive's backing path — so
    /// the snapshot/restore flow needs it alongside `put`. Framing is identical.
    pub(crate) fn patch<B: Serialize>(&self, path: &str, body: &B) -> Result<(), VmmError> {
        self.send("PATCH", path, body)
    }

    /// Serialize `body`, send `method path`, and expect a `2xx`; a `4xx` fault becomes a typed error.
    fn send<B: Serialize>(&self, method: &str, path: &str, body: &B) -> Result<(), VmmError> {
        let json = serde_json::to_vec(body)
            .map_err(|e| VmmError::Vmm(format!("serialize {path}: {e}")))?;
        let (status, resp) = self.request(method, path, &json)?;
        if (200..300).contains(&status) {
            return Ok(());
        }
        let detail = fault_message(&resp).unwrap_or_else(|| format!("HTTP {status}"));
        Err(VmmError::Vmm(format!("{method} {path}: {detail}")))
    }

    /// Write the request and read the framed response: `(status_code, body_bytes)`.
    fn request(&self, method: &str, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), VmmError> {
        let ctx = || format!("api {method} {path}");
        let stream = UnixStream::connect(&self.socket).map_err(|e| io_err(&ctx(), &e))?;
        stream
            .set_read_timeout(Some(API_TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(API_TIMEOUT)))
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

        read_response(BufReader::new(&stream), &ctx())
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
        if n == 0 || line.trim_end().is_empty() {
            break; // end of headers (or EOF)
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
// Field names and shapes are pinned to Firecracker v1.9 (see docs/architecture.md, decision 001); the API
// schema has drifted across versions, so a version bump means re-checking these.

/// `PUT /boot-source` — the guest kernel and its command line.
#[derive(Serialize)]
pub(crate) struct BootSource<'a> {
    pub kernel_image_path: &'a str,
    pub boot_args: &'a str,
}

/// `PUT /drives/{drive_id}` — a virtio-block device. The root device becomes `/dev/vda`.
#[derive(Serialize)]
pub(crate) struct Drive<'a> {
    pub drive_id: &'a str,
    pub path_on_host: &'a str,
    pub is_root_device: bool,
    pub is_read_only: bool,
}

/// `PUT /machine-config` — the vCPU and memory budget.
#[derive(Serialize)]
pub(crate) struct MachineConfig {
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
}

/// `PUT /actions` — an instance action. The closed set of actions the driver issues, modelled as an
/// enum so the wire discriminant can't be mistyped; serializes to `{"action_type": "<PascalCase>"}`,
/// matching Firecracker's schema (mirrors how `channel` centralizes its `TAG_*` wire discriminants).
#[derive(Serialize)]
#[serde(tag = "action_type")]
pub(crate) enum Action {
    InstanceStart,
    SendCtrlAltDel,
}

/// `PUT /vsock` — a virtio-vsock device. The host reaches a guest-listening port by connecting to
/// `uds_path` and sending `CONNECT <port>\n`; the guest sees it on context id `guest_cid`.
#[derive(Serialize)]
pub(crate) struct Vsock<'a> {
    pub guest_cid: u32,
    pub uds_path: &'a str,
}

/// `PUT /network-interfaces/{iface_id}` — a virtio-net device backed by a host tap. Firecracker does
/// not create the tap; the host makes it first and names it here via `host_dev_name`. Rate limiters
/// are optional and omitted (deny-by-default; no shaping in this engine).
#[derive(Serialize)]
pub(crate) struct NetworkInterface<'a> {
    pub iface_id: &'a str,
    pub host_dev_name: &'a str,
    pub guest_mac: &'a str,
}

/// `PATCH /vm` — move a running VM between run states. `Paused` freezes the vCPUs (the prerequisite
/// for a consistent snapshot); `Resumed` continues them. Serializes to `{"state": "Paused"}` /
/// `{"state": "Resumed"}` (a serde unit variant serializes as its PascalCase name, matching the
/// wire schema — the same closed-set-as-enum discipline as [`Action`]).
#[derive(Serialize)]
pub(crate) struct VmState {
    pub state: VmStateKind,
}

#[derive(Serialize)]
pub(crate) enum VmStateKind {
    Paused,
    Resumed,
}

/// `PUT /snapshot/create` — write a snapshot of a **paused** VM: `snapshot_path` receives the vCPU
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

/// `PUT /snapshot/load` — rebuild a VM from a snapshot on a fresh VMM and (with `resume_vm`) resume
/// it. `mem_backend` names the memory file. Firecracker opens each block device's backing file **at
/// load**, at the path baked into the snapshot, so the driver stages the bundle's disk copy there
/// before calling this (see `Vm::restore`).
#[derive(Serialize)]
pub(crate) struct SnapshotLoad<'a> {
    pub snapshot_path: &'a str,
    pub mem_backend: MemBackend<'a>,
    pub resume_vm: bool,
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

#[cfg(test)]
mod tests {
    use super::*;

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
        // Some responses omit Content-Length entirely on an empty body — must not hang.
        let raw = b"HTTP/1.1 204 No Content\r\n\r\n";
        let (status, body) = read_response(&raw[..], "test").unwrap();
        assert_eq!(status, 204);
        assert!(body.is_empty());
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
        // A peer that never sends `\n` must hit the response cap and fail typed — the status
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
        })
        .unwrap();
        assert_eq!(json["drive_id"], "rootfs");
        assert_eq!(json["is_root_device"], true);
        assert_eq!(json["is_read_only"], false);
    }

    #[test]
    fn vsock_serializes_to_expected_fields() {
        let json = serde_json::to_value(Vsock {
            guest_cid: 3,
            uds_path: "/tmp/agent-1-0/v.sock",
        })
        .unwrap();
        assert_eq!(json["guest_cid"], 3);
        assert_eq!(json["uds_path"], "/tmp/agent-1-0/v.sock");
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
        })
        .unwrap();
        assert_eq!(json["snapshot_path"], "/b/snapshot.state");
        assert_eq!(json["mem_backend"]["backend_type"], "File");
        assert_eq!(json["mem_backend"]["backend_path"], "/b/snapshot.mem");
        assert_eq!(json["resume_vm"], true);
    }
}
