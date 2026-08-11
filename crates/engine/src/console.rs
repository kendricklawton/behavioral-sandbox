//! The captured serial console: a bounded, background-drained copy of the VMM's stdout that the
//! boot loop scans for the guest's userspace marker (and `abort` mines for diagnostics).

use std::io::Read;
use std::process::ChildStdout;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crate::VmmError;

/// Cap on the captured console (the most recent bytes are kept). A guest that floods its serial
/// port would otherwise grow host memory without bound, so the buffer is capped rather than
/// trusted to stay small: the compaction below holds it at `CONSOLE_CAP + CONSOLE_SLACK`. Boot
/// output is tens of KiB, three orders of magnitude inside the cap, so the userspace marker is
/// still in the buffer when the boot path looks for it.
const CONSOLE_CAP: usize = 1 << 20; // 1 MiB
/// Slack the buffer may overshoot [`CONSOLE_CAP`] before it compacts. Draining on every 4 KiB chunk
/// once at the cap memmoves the whole buffer per chunk (O(n) per chunk, ~256x write amplification
/// under a flooding guest, the exact hostile case); overshooting by a cap's worth and compacting in
/// one bulk drop amortizes that to O(1) per byte. Memory stays strictly bounded at `CONSOLE_CAP +
/// CONSOLE_SLACK`.
const CONSOLE_SLACK: usize = CONSOLE_CAP;
/// The captured serial console: a background thread appends the child's stdout into a shared
/// buffer that the boot loop scans for the userspace marker.
#[derive(Debug, Default)]
pub(crate) struct Console {
    buf: Arc<Mutex<Capture>>,
    reader: Option<JoinHandle<()>>,
}

/// The captured bytes and the marker scan's place in them, under one lock so a compaction that drops
/// bytes off the front can move the scan position with them.
#[derive(Debug, Default)]
struct Capture {
    buf: Vec<u8>,
    /// The marker [`scanned`](Self::scanned) and [`found`](Self::found) describe. A different one
    /// resets both, so incremental state can never answer for a marker it did not scan for.
    needle: Vec<u8>,
    /// How far into `buf` the marker scan has already looked.
    scanned: usize,
    /// Latched once the marker is seen: the scan only ever moves forward, so without this a second
    /// call would look at the bytes *after* the match and report it gone.
    found: bool,
}

impl Console {
    /// Start draining `stdout` immediately (before `InstanceStart`): the OS pipe buffer is ~64 KiB
    /// and a chatty boot would deadlock the guest if we only read after starting it.
    ///
    /// # Errors
    /// [`VmmError::Vmm`] if the OS refuses a new thread (`thread::spawn` would *panic* on that,
    /// EAGAIN is a real state under many-sandbox load, so it must stay a typed error).
    pub(crate) fn spawn(stdout: Option<ChildStdout>) -> Result<Self, VmmError> {
        let buf: Arc<Mutex<Capture>> = Arc::default();
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
    ///
    /// **Scans only what is new.** The boot loop calls this every few milliseconds until the marker
    /// appears, so rescanning the whole buffer each time would make the wait cost
    /// `buffer × polls` rather than the bytes the guest actually wrote, and the buffer is capped at
    /// 2 MiB. The resume point backs up by `needle.len() - 1`, so a marker straddling two appends is
    /// still found.
    pub(crate) fn contains(&self, marker: &str) -> bool {
        let needle = marker.as_bytes();
        let Ok(mut cap) = self.buf.lock() else {
            return false;
        };
        if cap.needle != needle {
            cap.needle = needle.to_vec();
            cap.scanned = 0;
            cap.found = false;
        }
        if cap.found {
            return true;
        }
        let from = cap.scanned.saturating_sub(needle.len().saturating_sub(1));
        cap.found = find(&cap.buf[from..], needle);
        cap.scanned = cap.buf.len();
        cap.found
    }

    /// A UTF-8-lossy snapshot of the console captured so far.
    pub(crate) fn snapshot(&self) -> String {
        self.buf
            .lock()
            .map(|g| String::from_utf8_lossy(&g.buf).into_owned())
            .unwrap_or_default()
    }

    /// Join the reader thread; it exits on its own once the child's stdout closes.
    pub(crate) fn join(&mut self) {
        if let Some(handle) = self.reader.take() {
            let _ = handle.join();
        }
    }
}

/// The 12 Unicode `Bidi_Control` code points, which reorder how the text around them renders.
/// [`char::is_control`] is category `Cc` only and returns `false` for every one of them. The twin of
/// `bsx_channel`'s and `bsx-cli`'s predicates of the same name, one per surface that renders a
/// guest-authored string to a terminal; `the_terminal_escapers_agree_on_the_bidi_controls` pins the
/// set across all three.
fn is_bidi_control(c: char) -> bool {
    matches!(c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// The last `n` non-empty lines of `text`, oldest first, joined with ` | `, `None` if there are
/// none: diagnostic tails for error enrichment, made safe to print.
///
/// Escaping happens **here** rather than at the call sites because every caller folds the result into
/// a [`VmmError`](crate::VmmError) the CLI prints to a terminal, and the console half is bytes the
/// guest chose: an unescaped tail lets it forge lines or reorder the operator's display around it.
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
    let joined = tail.into_iter().rev().collect::<Vec<_>>().join(" | ");
    let mut out = String::with_capacity(joined.len() + 8);
    for c in joined.chars() {
        if c.is_control() || is_bidi_control(c) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    Some(out)
}

/// Append a console chunk, dropping the oldest bytes in one bulk compaction once the buffer
/// overshoots [`CONSOLE_CAP`] by [`CONSOLE_SLACK`] (so the front-drain memmove is amortized, not
/// paid per chunk).
fn append_capped(cap: &mut Capture, chunk: &[u8]) {
    cap.buf.extend_from_slice(chunk);
    if cap.buf.len() > CONSOLE_CAP + CONSOLE_SLACK {
        let excess = cap.buf.len() - CONSOLE_CAP;
        cap.buf.drain(..excess);
        // The scan position is an index into `buf`, so it moves with the bytes the drain removed.
        // Saturating rather than wrapping: a compaction can drop past everything scanned so far,
        // which just means the next scan starts at the new front.
        cap.scanned = cap.scanned.saturating_sub(excess);
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
        // Push past the compaction trigger (cap + slack) so one bulk drop fires.
        let mut cap = Capture {
            buf: vec![b'a'; CONSOLE_CAP + CONSOLE_SLACK],
            ..Capture::default()
        };
        append_capped(&mut cap, b"login:");
        let buf = &cap.buf;
        assert!(
            buf.len() <= CONSOLE_CAP + CONSOLE_SLACK,
            "buffer stays within the cap plus its compaction slack"
        );
        assert!(
            find(buf, b"login:"),
            "the newest bytes (where the marker lands) must be kept"
        );
        assert_eq!(
            &buf[buf.len() - 6..],
            b"login:",
            "the freshest tail is preserved after compaction"
        );
        assert_eq!(&buf[..1], b"a", "only the oldest bytes are dropped");
    }

    #[test]
    fn console_buffer_overshoots_by_at_most_the_slack_before_compacting() {
        // Below the trigger the buffer is left intact (no per-chunk memmove).
        let mut cap = Capture {
            buf: vec![b'a'; CONSOLE_CAP],
            ..Capture::default()
        };
        append_capped(&mut cap, b"x");
        assert_eq!(
            cap.buf.len(),
            CONSOLE_CAP + 1,
            "no compaction until cap + slack"
        );
    }

    /// The three ways an incremental scan can be wrong, each of which a whole-buffer rescan could
    /// never be: a marker split across two appends, a marker whose bytes the compaction moved, and a
    /// second call after the match.
    #[test]
    fn the_marker_scan_resumes_without_losing_a_marker() {
        // Straddle: the resume point must back up by `needle.len() - 1`, or the halves are never
        // seen together.
        let console = Console::spawn(None).expect("no thread needed");
        {
            let mut cap = console.buf.lock().expect("lock");
            append_capped(&mut cap, b"boot ...GUEST-");
        }
        assert!(!console.contains("GUEST-READY"), "only half has arrived");
        {
            let mut cap = console.buf.lock().expect("lock");
            append_capped(&mut cap, b"READY\n");
        }
        assert!(
            console.contains("GUEST-READY"),
            "a marker split across two appends is still found"
        );

        // Latched: the scan only moves forward, so a second call must not report it gone.
        assert!(
            console.contains("GUEST-READY"),
            "the answer must not change once the marker has been seen"
        );

        // A different needle resets the state, so it cannot inherit the first one's answer.
        assert!(!console.contains("login:"), "a new needle scans afresh");
    }

    #[test]
    fn a_compaction_moves_the_scan_position_with_the_bytes() {
        // The scan position is an index into a buffer the compaction shifts. If it were not moved
        // down with the drain, it would point past bytes never scanned and the marker would be lost.
        let console = Console::spawn(None).expect("no thread needed");
        {
            let mut cap = console.buf.lock().expect("lock");
            append_capped(&mut cap, &vec![b'a'; CONSOLE_CAP + CONSOLE_SLACK]);
        }
        assert!(!console.contains("GUEST-READY"), "not there yet");
        {
            // This append trips the compaction, dropping bytes off the front *and* landing the
            // marker in the tail.
            let mut cap = console.buf.lock().expect("lock");
            append_capped(&mut cap, b"GUEST-READY\n");
            assert!(
                cap.buf.len() <= CONSOLE_CAP + CONSOLE_SLACK,
                "the compaction must have fired for this test to mean anything"
            );
        }
        assert!(
            console.contains("GUEST-READY"),
            "the marker survives a compaction that moved the scan position"
        );
    }

    #[test]
    fn a_console_tail_cannot_forge_or_reorder_the_line_it_lands_in() {
        // `abort` folds this tail into a `VmmError` the CLI prints, and the console is bytes the guest
        // chose, so the diagnostic must not carry a terminal's control or bidi vocabulary.
        let forged =
            last_lines("boot ok\nowned\x1b]0;pwned\x07 \x1b[2J", 2).expect("two non-empty lines");
        assert!(
            !forged.contains('\x1b'),
            "ESC must be escaped, not printed: {forged:?}"
        );
        assert!(
            forged.contains("\\u{1b}") && forged.contains("boot ok"),
            "the text survives, escaped: {forged:?}"
        );

        // Bidi controls are category `Cf`, so an `is_control`-only guard passes them straight through.
        let reordered = last_lines("start\u{202E}dne", 1).expect("one non-empty line");
        assert!(
            !reordered.contains('\u{202E}') && reordered.contains("\\u{202e}"),
            "the RTL override is escaped: {reordered:?}"
        );

        // A carriage return can retype a line over itself on a terminal, so it is control too.
        let retyped = last_lines("real line\rfake line", 1).expect("one non-empty line");
        assert!(!retyped.contains('\r'), "CR must be escaped: {retyped:?}");
    }
}
