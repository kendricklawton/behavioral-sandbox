//! The captured serial console: a bounded, background-drained copy of the VMM's stdout that the
//! boot loop scans for the guest's userspace marker (and `abort` mines for diagnostics).

use std::io::Read;
use std::process::ChildStdout;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crate::VmmError;

/// Cap on the captured console (the most recent bytes are kept). A guest that floods its serial
/// port must not grow host memory without bound — a hostile guest never causes a leak. Boot output
/// is tens of KiB, so the userspace marker is never dropped while it still matters.
const CONSOLE_CAP: usize = 1 << 20; // 1 MiB
/// The captured serial console: a background thread appends the child's stdout into a shared
/// buffer that the boot loop scans for the userspace marker.
#[derive(Debug, Default)]
pub(crate) struct Console {
    buf: Arc<Mutex<Vec<u8>>>,
    reader: Option<JoinHandle<()>>,
}

impl Console {
    /// Start draining `stdout` immediately (before `InstanceStart`): the OS pipe buffer is ~64 KiB
    /// and a chatty boot would deadlock the guest if we only read after starting it.
    ///
    /// # Errors
    /// [`VmmError::Vmm`] if the OS refuses a new thread (`thread::spawn` would *panic* on that —
    /// EAGAIN is a real state under many-sandbox load, so it must stay a typed error).
    pub(crate) fn spawn(stdout: Option<ChildStdout>) -> Result<Self, VmmError> {
        let buf: Arc<Mutex<Vec<u8>>> = Arc::default();
        let reader = match stdout {
            None => None,
            Some(mut out) => {
                let sink = Arc::clone(&buf);
                let handle = std::thread::Builder::new()
                    .name("agent-console".into())
                    .spawn(move || {
                        let mut chunk = [0u8; 4096];
                        loop {
                            match out.read(&mut chunk) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if let Ok(mut g) = sink.lock() {
                                        append_capped(&mut g, &chunk[..n]);
                                    }
                                }
                            }
                        }
                    })
                    .map_err(|e| VmmError::Vmm(format!("spawn console reader: {e}")))?;
                Some(handle)
            }
        };
        Ok(Self { buf, reader })
    }

    /// Whether the console captured so far contains `marker`.
    pub(crate) fn contains(&self, marker: &str) -> bool {
        self.buf
            .lock()
            .map(|g| find(&g, marker.as_bytes()))
            .unwrap_or(false)
    }

    /// A UTF-8-lossy snapshot of the console captured so far.
    pub(crate) fn snapshot(&self) -> String {
        self.buf
            .lock()
            .map(|g| String::from_utf8_lossy(&g).into_owned())
            .unwrap_or_default()
    }

    /// Join the reader thread; it exits on its own once the child's stdout closes.
    pub(crate) fn join(&mut self) {
        if let Some(handle) = self.reader.take() {
            let _ = handle.join();
        }
    }
}

/// The last `n` non-empty lines of `text`, oldest first, joined with ` | ` — `None` if there are
/// none. Diagnostic tails for error enrichment.
pub(crate) fn last_lines(text: &str, n: usize) -> Option<String> {
    let tail: Vec<&str> = text
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.is_empty())
        .rev()
        .take(n)
        .collect();
    if tail.is_empty() {
        return None;
    }
    Some(tail.into_iter().rev().collect::<Vec<_>>().join(" | "))
}

/// Append a console chunk, dropping the oldest bytes once the buffer exceeds [`CONSOLE_CAP`].
fn append_capped(buf: &mut Vec<u8>, chunk: &[u8]) {
    buf.extend_from_slice(chunk);
    if buf.len() > CONSOLE_CAP {
        let excess = buf.len() - CONSOLE_CAP;
        buf.drain(..excess);
    }
}

/// Whether `haystack` contains the contiguous byte sequence `needle`.
pub(crate) fn find(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_locates_substring() {
        assert!(find(b"ubuntu-fc-uvm login: root", b"login:"));
        assert!(!find(b"Reached target Login Prompts", b"login:"));
        assert!(find(b"anything", b""));
        assert!(!find(b"hi", b"longer-than-haystack"));
    }

    #[test]
    fn console_captures_and_scans() {
        // No stdout: the buffer stays empty but the API works.
        let console = Console::spawn(None).expect("no thread needed");
        assert!(!console.contains("login:"));
        assert_eq!(console.snapshot(), "");
    }

    #[test]
    fn console_buffer_is_capped_keeping_the_tail() {
        let mut buf = vec![b'a'; CONSOLE_CAP];
        append_capped(&mut buf, b"login:");
        assert_eq!(buf.len(), CONSOLE_CAP, "buffer must not grow past the cap");
        assert!(
            find(&buf, b"login:"),
            "the newest bytes (where the marker lands) must be kept"
        );
        assert_eq!(&buf[..1], b"a", "only the oldest bytes are dropped");
    }
}
