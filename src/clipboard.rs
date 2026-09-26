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
//! Wired into the service: local changes are broadcast over dedicated
//! ephemeral clipboard QUIC streams to the peers the pairing shares them with,
//! and inbound payloads the pairing takes pass [`ClipboardInbox`] before
//! [`Clipboard::apply`] (#182, #186).

use local_channel::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

use crate::transport::{PeerClipboard, Trust};
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

/// Clipboard text from peers, on its way to being applied here.
///
/// The transports check the pairing when a transfer arrives and when it
/// completes. This is the last check, at the moment of applying: text queued
/// before its sender was removed must not land after it. Holding the receiver
/// privately makes this the only way from the network to [`Clipboard::apply`].
pub(crate) struct ClipboardInbox {
    rx: Receiver<PeerClipboard>,
    trust: Trust,
}

impl ClipboardInbox {
    pub(crate) fn new(rx: Receiver<PeerClipboard>, trust: Trust) -> Self {
        Self { rx, trust }
    }

    /// The next text a peer sent whose pairing still takes clipboard from it.
    /// `None` once every transport has gone.
    pub(crate) async fn next(&mut self) -> Option<String> {
        loop {
            let received = self.rx.recv().await?;
            if self
                .trust
                .read()
                .expect("lock")
                .clipboard_from(&received.from)
            {
                return Some(received.text);
            }
            log::info!(
                "clipboard text dropped: the pairing stopped taking clipboard from its \
                 sender before it was applied"
            );
        }
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

#[cfg(test)]
mod clipboard_follows_the_pairing {
    //! Clipboard text moves only where the pairing grants it (#182, #186):
    //! sent to a peer whose lease carries `clipboard-to`, taken from a peer
    //! whose lease carries `clipboard-from`, and neither once the peer is
    //! removed. Both machines here are the production transports over
    //! loopback; only the system clipboard at each end is left out.

    use std::net::SocketAddr;

    use futures::StreamExt;
    use local_channel::mpsc::{Receiver, channel};

    use crate::listen::{LanMouseListener, ListenEvent};
    use crate::test_harness::{
        ARRIVES_WITHIN, Machine, NEVER_WITHIN, applied_within, clipboard_pair, heard_within,
        machine, raw_client_config, run_local, trust,
    };
    use crate::transport::{self, PeerClipboard, Trust};
    use crate::trust::{Caps, TrustStore};

    use super::ClipboardInbox;

    /// `me`'s store, granting `peer` exactly `caps`.
    fn store(me: &Machine, peer: &Machine, caps: Caps) -> TrustStore {
        let mut store = TrustStore::new(&me.fingerprint, 0).expect("ours");
        store.issue(&peer.fingerprint, "peer", caps).expect("issue");
        store
    }

    fn text(heard: Option<(String, String)>) -> Option<String> {
        heard.map(|(text, _)| text)
    }

    // LEDGER T1862 | class B | 6 struct state: peer's inbound queue; ClipboardSender::broadcast, ClipboardSenderListen::broadcast
    #[test]
    fn a_removed_machine_is_not_sent_the_clipboard() {
        run_local(async {
            // The driver removes the machine it drives, and the link is still up.
            let (driven, driver) = (machine(), machine());
            let (on_driven, on_driver) = (
                store(&driven, &driver, Caps::INBOUND),
                store(&driver, &driven, Caps::OUTBOUND),
            );
            let mut pair = clipboard_pair(driven, on_driven, driver, on_driver).await;
            pair.driver_sends.broadcast("before".into()).await;
            assert_eq!(
                heard_within(&mut pair.driven_heard, ARRIVES_WITHIN).await,
                Some(("before".into(), pair.driver.fingerprint.clone())),
                "the driven machine never got text its pairing grants, under \
                 the sender's own fingerprint"
            );
            let gone = pair.driven.fingerprint.clone();
            pair.driver_trust.write().expect("lock").revoke(&gone);
            pair.driver_sends.broadcast("after".into()).await;
            assert_eq!(
                text(heard_within(&mut pair.driven_heard, NEVER_WITHIN).await),
                None,
                "text copied on this machine went to a machine it had removed, \
                 over a link that was still open"
            );

            // The driven machine removes its driver, on a pairing that shares
            // the clipboard both ways.
            let (driven, driver) = (machine(), machine());
            let both = Caps::INBOUND | Caps::OUTBOUND;
            let (on_driven, on_driver) =
                (store(&driven, &driver, both), store(&driver, &driven, both));
            let mut pair = clipboard_pair(driven, on_driven, driver, on_driver).await;
            pair.driven_sends.broadcast("before".into()).await;
            assert_eq!(
                heard_within(&mut pair.dialer.notices.clipboard, ARRIVES_WITHIN).await,
                Some(("before".into(), pair.driven.fingerprint.clone())),
                "the driver never got text a both-ways pairing grants"
            );
            let gone = pair.driver.fingerprint.clone();
            pair.driven_trust.write().expect("lock").revoke(&gone);
            pair.driven_sends.broadcast("after".into()).await;
            assert_eq!(
                text(heard_within(&mut pair.dialer.notices.clipboard, NEVER_WITHIN).await),
                None,
                "text copied on this machine went to a machine it had removed, \
                 over the link that machine opened to it"
            );
        });
    }

    // LEDGER T1866 | class B | 6 struct state: inbound queue; transport::clipboard_accept_loop via LanMouseListener and LanMouseConnection
    #[test]
    fn a_machine_refuses_clipboard_its_pairing_does_not_take_from_that_peer() {
        run_local(async {
            // The driven machine's lease lets the driver drive it and nothing
            // more, while the driver's lease says it may share.
            let (driven, driver) = (machine(), machine());
            let (on_driven, on_driver) = (
                store(&driven, &driver, Caps::DRIVE_ME),
                store(&driver, &driven, Caps::OUTBOUND),
            );
            let mut pair = clipboard_pair(driven, on_driven, driver, on_driver).await;
            pair.driver_sends.broadcast("unasked".into()).await;
            assert_eq!(
                text(heard_within(&mut pair.driven_heard, NEVER_WITHIN).await),
                None,
                "the driven machine took clipboard text from a peer its pairing \
                 takes none from"
            );

            // The driver's lease takes nothing from the machine it drives,
            // while that machine's lease says it may share.
            let (driven, driver) = (machine(), machine());
            let (on_driven, on_driver) = (
                store(&driven, &driver, Caps::INBOUND | Caps::CLIPBOARD_TO),
                store(&driver, &driven, Caps::OUTBOUND),
            );
            let mut pair = clipboard_pair(driven, on_driven, driver, on_driver).await;
            pair.driven_sends.broadcast("unasked".into()).await;
            assert_eq!(
                text(heard_within(&mut pair.dialer.notices.clipboard, NEVER_WITHIN).await),
                None,
                "the driver took clipboard text from a machine its pairing takes \
                 none from"
            );
        });
    }

    /// A raw peer dialled into the production listener, its input stream open.
    struct RawDriver {
        _listener: LanMouseListener,
        driven_trust: Trust,
        driver: Machine,
        heard: Receiver<PeerClipboard>,
        _endpoint: quinn::Endpoint,
        _input: quinn::SendStream,
        conn: quinn::Connection,
    }

    async fn raw_driver(caps_on_driven: Caps) -> RawDriver {
        let (driven, driver) = (machine(), machine());
        let driven_trust = trust(&driven, &[&driver], caps_on_driven);
        let (heard_tx, heard) = channel();
        let (mut listener, port) = LanMouseListener::bind_loopback(
            driven.identity.clone(),
            driven_trust.clone(),
            heard_tx,
        )
        .await
        .expect("listener");
        let mut endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().expect("loopback")).expect("endpoint");
        endpoint.set_default_client_config(raw_client_config(
            &driver,
            trust(&driver, &[&driven], Caps::OUTBOUND),
            1 << 20,
        ));
        let conn = endpoint
            .connect(
                SocketAddr::new("127.0.0.1".parse().expect("loopback"), port),
                "grabbr",
            )
            .expect("dial")
            .await
            .expect("handshake");
        let mut input = conn.open_uni().await.expect("input stream");
        transport::write_frame(&mut input, hops_proto::ProtoEvent::Ping)
            .await
            .expect("ping");
        // The input stream is the first the listener takes; clipboard streams
        // are the ones after it.
        let seen = tokio::time::timeout(ARRIVES_WITHIN, async {
            while let Some(event) = listener.next().await {
                if let ListenEvent::Msg { .. } = event {
                    return true;
                }
            }
            false
        })
        .await;
        assert!(
            matches!(seen, Ok(true)),
            "the listener never read the input stream"
        );
        RawDriver {
            _listener: listener,
            driven_trust,
            driver,
            heard,
            _endpoint: endpoint,
            _input: input,
            conn,
        }
    }

    // LEDGER T1864 | class B | 6 struct state: queue filled by LanMouseListener's transport::clipboard_accept_loop
    #[test]
    fn a_transfer_in_flight_at_removal_is_not_applied() {
        run_local(async {
            let mut raw = raw_driver(Caps::INBOUND).await;
            let mut send = raw.conn.open_uni().await.expect("clipboard stream");
            send.write_all(b"half of ").await.expect("write");
            // Long enough on loopback for the listener to take the stream while
            // the pairing still grants it.
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            let gone = raw.driver.fingerprint.clone();
            raw.driven_trust.write().expect("lock").revoke(&gone);
            send.write_all(b"the text").await.expect("write");
            send.finish().expect("finish");
            assert_eq!(
                text(heard_within(&mut raw.heard, NEVER_WITHIN).await),
                None,
                "text from a peer removed while it was still arriving was handed \
                 on to be applied; the grant has to be checked when the transfer \
                 completes, not only when it starts"
            );
        });
    }

    // LEDGER T1865 | class B | 1 return value: ClipboardInbox::next
    #[test]
    fn a_transfer_queued_at_removal_is_not_applied() {
        run_local(async {
            let (me, peer) = (machine(), machine());
            let trust = trust(&me, &[&peer], Caps::INBOUND);
            let (queue, rx) = channel();
            let mut inbox = ClipboardInbox::new(rx, trust.clone());
            let from_peer = |text: &str| PeerClipboard {
                from: peer.fingerprint.clone(),
                text: text.to_string(),
            };
            queue.send(from_peer("before")).expect("queue");
            assert_eq!(
                applied_within(&mut inbox, ARRIVES_WITHIN).await.as_deref(),
                Some("before"),
                "text from a peer the pairing takes clipboard from was not applied"
            );
            // Passed the transport's checks and waiting to be applied when the
            // peer is removed: the service's loop can take the removal first.
            queue
                .send(from_peer("queued, then removed"))
                .expect("queue");
            trust.write().expect("lock").revoke(&peer.fingerprint);
            assert_eq!(
                applied_within(&mut inbox, NEVER_WITHIN).await,
                None,
                "text queued before its sender was removed was applied after it"
            );
        });
    }

    // LEDGER T1867 | class B | 2 stream state: SendStream::stopped code, produced by transport::clipboard_accept_loop
    #[test]
    fn a_peer_the_pairing_takes_no_clipboard_from_is_stopped_before_it_sends() {
        run_local(async {
            let raw = raw_driver(Caps::DRIVE_ME).await;
            let mut send = raw.conn.open_uni().await.expect("clipboard stream");
            send.write_all(b"the start of something long")
                .await
                .expect("write");
            let stopped = tokio::time::timeout(ARRIVES_WITHIN, send.stopped()).await;
            assert_eq!(
                stopped.ok().and_then(|r| r.ok()).flatten(),
                Some(quinn::VarInt::from_u32(transport::CLIPBOARD_REFUSED)),
                "a peer the pairing takes no clipboard from was left sending \
                 into a stream this machine would never use"
            );
        });
    }
}
