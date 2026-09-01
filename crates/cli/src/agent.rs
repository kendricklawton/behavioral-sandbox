//! Reaching the agent inside a VM, over the unix socket the helper maps onto its vsock port.
//!
//! Shared by every verb that talks to a guest: `shell` opens a pty session on a VM it just
//! started, `up` uses the same exchange as its readiness probe, and `exec` reaches a VM it did
//! not start at all.
//!
//! - **A completed `connect` proves nothing.** libkrun accepts on the unix socket before the
//!   guest is listening on the vsock port inside, and resets when the forward fails (watched
//!   happen), so the **protocol handshake is the readiness probe** and a dial retries through it.
//! - **A dial that runs out of grace is not the same failure as a VM that died.** [`Error`] keeps
//!   the two apart, because a VM that ended before answering usually means the image carries no
//!   agent, and one that is still there and silent means something else entirely.

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use bsx_channel::ClientConnection;
use bsx_supervisor::Vm;

/// How long the agent is given to answer. Cold boot is ~300 ms on the development laptop; this is
/// headroom, not a tuned value.
pub(crate) const DIAL_GRACE: Duration = Duration::from_secs(10);

/// Between attempts. Short enough that a boot is not padded by the poll, long enough that a
/// wedged guest is not spun on.
const RETRY: Duration = Duration::from_millis(25);

/// Bound on the handshake itself, so a guest that accepts and then says nothing cannot hold the
/// dial loop past its grace.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

/// A handshaken connection: the read half, plus the raw stream a caller can `resume` for the
/// other direction of a session that needs both.
pub(crate) type Dialed = (ClientConnection<UnixStream>, UnixStream);

/// Why the agent could not be reached, kept apart so a caller can say the right thing: a VM that
/// died is a different report from one that is simply busy.
pub(crate) enum Error {
    /// The VM ended before the agent answered.
    VmEnded(String),
    /// The grace ran out. The VM is still there, so it is booting slowly or already busy.
    Silent {
        /// The socket dialled, named because a caller may have derived it from a VM name.
        socket: std::path::PathBuf,
        /// The last attempt's failure, which is usually the more specific half.
        last: String,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VmEnded(how) => write!(
                f,
                "the VM ended ({how}) before the agent answered: is the guest image one with the \
                 agent baked in? (`cargo xtask build-rootfs`)"
            ),
            Self::Silent { socket, last } => write!(
                f,
                "the agent on {} did not answer within {DIAL_GRACE:?}, and the VM is still \
                 running (last attempt: {last})",
                socket.display()
            ),
        }
    }
}

/// Dials the agent of a VM this process started, failing fast if the helper dies on the way.
pub(crate) fn dial(sock: &Path, vm: &mut Vm) -> Result<Dialed, Error> {
    let deadline = Instant::now() + DIAL_GRACE;
    loop {
        // A `try_wait` that fails says nothing about the guest, so only a reported exit ends the
        // loop early and the grace ends it otherwise.
        if let Ok(Some(exit)) = vm.try_wait() {
            return Err(Error::VmEnded(format!("{exit:?}")));
        }
        let last = match try_dial(sock) {
            Ok(pair) => return Ok(pair),
            Err(e) => e,
        };
        if Instant::now() >= deadline {
            return Err(Error::Silent {
                socket: sock.to_path_buf(),
                last,
            });
        }
        std::thread::sleep(RETRY);
    }
}

/// One attempt: connect, complete the handshake under a deadline, and hand back both halves with
/// the deadline cleared, since a session idles for as long as its command runs.
fn try_dial(sock: &Path) -> Result<Dialed, String> {
    let stream = UnixStream::connect(sock).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|e| e.to_string())?;
    let conn = ClientConnection::connect(stream.try_clone().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    stream.set_read_timeout(None).map_err(|e| e.to_string())?;
    Ok((conn, stream))
}
