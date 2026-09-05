# Control socket and host/guest IPC

Behavioral Sandbox (BSX) uses a two-tier IPC design for host management and host↔guest communication: a host control socket for local process discovery and display leasing, and a virtio-vsock wire protocol for in-guest command execution.

## Host control socket

There is no background daemon. A running sandbox is a helper process (`bsx __vmm`) listening on a Unix domain socket under the user's runtime directory.

### Socket resolution and discovery

Sockets live in `$XDG_RUNTIME_DIR/bsx/<name>.sock` (falling back to `$TMPDIR/bsx/<name>.sock` or `/tmp/bsx/<name>.sock`). The directory is created with `0700` permissions and checked at runtime for correct ownership and permissions to prevent multi-user socket hijacking under shared temporary directories.

The socket directory acts as the VM registry:
- **Discovery**: `bsx ls` scans the socket directory for files ending in `.sock`.
- **Liveness probe**: Rather than relying on file existence, `socket::is_live` attempts a non-blocking `UnixStream::connect`. A socket file whose process has died is cleaned up via `socket::clear_if_stale`.
- **Sidecar paths**: The agent socket sits at `<name>.agent` and the detached log file sits at `<name>.log`.

### Control protocol commands

The control socket speaks line-delimited JSON for management requests:
- `LEASE_DISPLAY`: Leases a virtio-gpu display scanout from a running VM. The helper passes a sealed shared memory file descriptor (`memfd_create`) over the Unix socket via `SCM_RIGHTS`.
- `INPUT_SESSION`: Opens an input stream to feed keyboard and pointer events directly into the helper's virtio-input devices using the `kbd|ptr TYPE CODE VALUE` line protocol.
- `STOP`: Sends a termination request to the VMM helper process.

## Host↔guest wire framing (`bsx-channel`)

Command execution inside a guest goes through `bsx-channel`, a length-prefixed wire protocol operating over AF_VSOCK (port 1024) or a Unix socket fallback.

### Handshake and framing

Every session begins with a 4-byte magic header (`AGCH`) and a 2-byte protocol version (`u16` = 3):
1. Both host (`ClientConnection`) and guest (`ServerConnection`) exchange magic and version headers.
2. Version mismatches reject immediately.
3. Subsequent messages use length-prefixed framing: `tag(u8) · len(u32-le) · payload`.

To prevent memory exhaustion attacks, `len` is validated against `MAX_PAYLOAD` (1 MiB) before memory allocation.

### Message tags

The wire protocol defines discrete frame discriminants:

| Tag | Name | Direction | Payload |
|---|---|---|---|
| 1 | `Exec` | Host → Guest | Command string, arguments, working directory, and environment key-value pairs. |
| 2 | `Stdout` | Guest → Host | Binary output stream from the command's stdout. |
| 3 | `Stderr` | Guest → Host | Binary output stream from the command's stderr. |
| 4 | `Exit` | Guest → Host | Command exit code (`i32`). |
| 5 | `Error` | Guest → Host | Agent error message string (sanitized). |
| 6 | `PutFile` | Host → Guest | Injected file path and binary content. |
| 7 | `File` | Guest → Host | Extracted file content from guest `/results`. |
| 8 | `TimedOut` | Guest → Host | Indicates command execution exceeded the configured deadline. |
| 9 | `ExecPty` | Host → Guest | Interactive shell request with PTY window dimensions (`cols`, `rows`). |
| 10 | `Stdin` | Host → Guest | Binary input stream for stdin or PTY interactive sessions. |
| 11 | `Resize` | Host → Guest | Updated PTY window dimensions (`cols`, `rows`). |

### Security and sanitization

- **Secret wiping**: Sensitive environment variables and payload buffers implement `zeroize` to wipe secret memory upon drop.
- **Error sanitization**: Guest error messages are capped at 4 KiB (`ERROR_MSG_CAP`) and sanitized to escape ASCII control characters and Unicode bidirectional control code points (`Bidi_Control`), preventing terminal injection and Trojan Source exploits.

## In-guest agent (`bsx-guest-agent`)

The guest agent is a statically linked Rust binary (`guest-agent`, compiled against `x86_64-unknown-linux-musl` or `aarch64-unknown-linux-musl`) baked into the guest image at `/usr/local/bin/guest-agent`.

- **Role**: Serves command execution requests (`Exec`/`ExecPty`), manages process lifecycles, attaches pseudo-terminals (PTYs), and handles file reads/writes in `/results`.
- **Trust boundary**: The agent runs inside the guest kernel space and is **not** part of the host isolation boundary. A compromised guest agent cannot escape the virtual machine.
