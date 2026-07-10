//! A tiny HTTP/1.1 client for Firecracker's API, spoken over its unix socket.
//!
//! Firecracker exposes a REST API on a unix domain socket (`--api-sock`); we drive a boot with a
//! handful of `PUT`s. Rather than pull in an async runtime or an HTTP crate, we hand-roll the
//! sliver of HTTP/1.1 those calls need — it keeps the driver dependency-light and `unsafe`-free,
//! and the raw request/response framing is itself the lesson.
//!
//! Framing rules that matter (a naive client hangs on each):
//! - **One fresh connection per request.** HTTP/1.1 defaults to keep-alive, so "read to EOF"
//!   never returns; we frame the response by `Content-Length` and send `Connection: close`.
//! - **Success is `204 No Content`** with an empty body; errors are `4xx` carrying a JSON
//!   `{"fault_message": "..."}`. We surface that message as a typed error.
//! - Read/write **timeouts** bound every call so a wedged VMM is a typed error, never a hang.

use std::io::{BufRead, BufReader, ErrorKind, Write};
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
        let json = serde_json::to_vec(body)
            .map_err(|e| VmmError::Vmm(format!("serialize {path}: {e}")))?;
        let (status, resp) = self.request(path, &json)?;
        if (200..300).contains(&status) {
            return Ok(());
        }
        let detail = fault_message(&resp).unwrap_or_else(|| format!("HTTP {status}"));
        Err(VmmError::Vmm(format!("PUT {path}: {detail}")))
    }

    /// Write the request and read the framed response: `(status_code, body_bytes)`.
    fn request(&self, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), VmmError> {
        let ctx = || format!("api PUT {path}");
        let stream = UnixStream::connect(&self.socket).map_err(|e| io_err(&ctx(), &e))?;
        stream
            .set_read_timeout(Some(API_TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(API_TIMEOUT)))
            .map_err(|e| io_err(&ctx(), &e))?;

        // One `write_all`: request line, headers, blank line, then the body.
        let mut req = format!(
            "PUT {path} HTTP/1.1\r\n\
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
fn read_response<R: BufRead>(mut reader: R, ctx: &str) -> Result<(u16, Vec<u8>), VmmError> {
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
// Field names and shapes are pinned to Firecracker v1.9 (see ARCHITECTURE.md, P1.1); the API
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

/// `PUT /actions` — an instance action (`InstanceStart`, `SendCtrlAltDel`).
#[derive(Serialize)]
pub(crate) struct Action<'a> {
    pub action_type: &'a str,
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
}
