//! Cross-machine clipboard sync — Stage A: the local monitor/apply backend.
//!
//! A single [`arboard::Clipboard`] is owned by one dedicated task: clipboard
//! handles are not safely shareable across threads on every platform, so all
//! access (both the change-detection poll and applying inbound content) happens
//! on that one task, mirroring the capture/emulation task pattern. The task is
//! driven on the service's `LocalSet` via `spawn_local`.
//!
//! Detection is poll-based (arboard exposes no change notification): every
//! [`POLL_INTERVAL`] we read the text and compare against the last value we
//! either observed or set. Comparing against the value we *set* is also the loop
//! guard — content we just applied from the peer reads back identical, so it is
//! never echoed.
//!
//! Wired into the service: local changes are broadcast to peers over dedicated
//! ephemeral clipboard QUIC streams, and inbound payloads are applied via
//! [`Clipboard::apply`].

use local_channel::mpsc::{Receiver, Sender, channel};
use std::time::Duration;
use tokio::task::{JoinHandle, spawn_local};
use tokio::time::{MissedTickBehavior, interval};

/// How often the local clipboard is polled for changes. 500 ms is well below
/// human copy→switch-window→paste latency while costing one cheap read/sec.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// A change observed on the *local* clipboard, to be forwarded to the peer.
pub(crate) enum ClipboardEvent {
    /// The local clipboard's text contents changed.
    Changed(String),
}

/// A request to the clipboard task.
enum ClipboardRequest {
    /// Apply text received from the peer to the local clipboard.
    Set(String),
}

/// Handle to the clipboard-sync backend. Dropping it stops the task.
pub(crate) struct Clipboard {
    request_tx: Sender<ClipboardRequest>,
    event_rx: Receiver<ClipboardEvent>,
    _task: JoinHandle<()>,
}

impl Clipboard {
    /// Spawns the clipboard task on the current `LocalSet`. If a clipboard
    /// handle cannot be opened, the task logs and exits — sync is simply
    /// inactive, the rest of the service is unaffected.
    pub(crate) fn new() -> Self {
        let (request_tx, mut request_rx) = channel::<ClipboardRequest>();
        let (event_tx, event_rx) = channel::<ClipboardEvent>();

        let task = spawn_local(async move {
            let mut clipboard = match arboard::Clipboard::new() {
                Ok(c) => c,
                Err(e) => {
                    log::warn!("clipboard sync disabled (could not open clipboard): {e}");
                    return;
                }
            };

            // The text we last know the clipboard holds — whether we read it on
            // a poll or wrote it from the peer. Seeded with the current contents
            // so the existing clipboard is not broadcast on startup.
            let mut last: Option<String> = clipboard.get_text().ok();

            let mut poll = interval(POLL_INTERVAL);
            poll.set_missed_tick_behavior(MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = poll.tick() => {
                        match clipboard.get_text() {
                            Ok(text) => {
                                if last.as_deref() != Some(text.as_str()) {
                                    last = Some(text.clone());
                                    // Receiver gone => service shutting down.
                                    if event_tx.send(ClipboardEvent::Changed(text)).is_err() {
                                        break;
                                    }
                                }
                            }
                            // Empty or non-text (image/files) clipboard. Clear
                            // the baseline so re-copying the SAME text after an
                            // intervening empty/non-text state is still seen as a
                            // change (leaving `last` set would suppress it).
                            Err(_) => last = None,
                        }
                    }
                    req = request_rx.recv() => {
                        let Some(req) = req else { break };
                        match req {
                            ClipboardRequest::Set(text) => {
                                // Update `last` only on a SUCCESSFUL write. Poll
                                // and set run on the same task (never concurrent),
                                // so there is no race to guard against — and
                                // recording before a write that then fails would
                                // make the unchanged clipboard look like a fresh
                                // local change next poll and echo stale content
                                // back to the peer.
                                match clipboard.set_text(text.clone()) {
                                    Ok(()) => last = Some(text),
                                    Err(e) => {
                                        log::warn!("failed to set local clipboard: {e}")
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        Self {
            request_tx,
            event_rx,
            _task: task,
        }
    }

    /// Awaits the next local clipboard change to forward to the peer. Returns
    /// `None` once the task has stopped.
    pub(crate) async fn changed(&mut self) -> Option<ClipboardEvent> {
        self.event_rx.recv().await
    }

    /// Applies clipboard text received from the peer to the local clipboard.
    /// Best-effort: a dropped task silently no-ops.
    pub(crate) fn apply(&self, text: String) {
        let _ = self.request_tx.send(ClipboardRequest::Set(text));
    }
}

#[cfg(test)]
mod tests {
    /// Smoke test: confirm arboard can open the clipboard and read text at
    /// runtime in a *non-GUI* process (the macOS service has no NSApplication).
    /// Read-only and never logs contents, so it does not disturb or leak the
    /// user's clipboard. Tolerant of a headless host (no clipboard) so it is
    /// safe as a permanent test.
    #[test]
    fn opens_and_reads_clipboard() {
        let mut cb = match arboard::Clipboard::new() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[clipboard] unavailable (headless?): {e}");
                return;
            }
        };
        match cb.get_text() {
            Ok(t) => eprintln!("[clipboard] open + read OK ({} chars)", t.len()),
            Err(e) => eprintln!("[clipboard] opened; no text present (acceptable): {e}"),
        }
    }
}
