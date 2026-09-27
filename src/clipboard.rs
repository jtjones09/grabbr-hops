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

use crate::client::ClientManager;
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
            // A daemon a test runs in-process leaves the user's clipboard
            // alone, as one on a system without a clipboard does. AppKit's
            // cannot be read from tests running side by side either.
            if cfg!(test) {
                log::info!("clipboard sync disabled (a test's daemon)");
                return;
            }
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

const SWITCHED_OFF_LOG_DEBOUNCE: Duration = Duration::from_secs(60);
thread_local! {
    static PREV_SWITCHED_OFF_LOG: std::cell::Cell<Option<std::time::Instant>> =
        const { std::cell::Cell::new(None) };
}

/// Clipboard text from peers, on its way to being applied here.
///
/// The transports check the pairing when a transfer arrives and when it
/// completes. This is the last check, at the moment of applying: text queued
/// before its sender was removed must not land after it. Holding the receiver
/// privately makes this the only way from the network to [`Clipboard::apply`].
///
/// It is also the only check of the device switch on text coming in: a
/// machine switched off here has none of its text applied, whichever of the
/// two machines opened the link it came over (#218).
pub(crate) struct ClipboardInbox {
    rx: Receiver<PeerClipboard>,
    trust: Trust,
    clients: ClientManager,
}

impl ClipboardInbox {
    pub(crate) fn new(rx: Receiver<PeerClipboard>, trust: Trust, clients: ClientManager) -> Self {
        Self { rx, trust, clients }
    }

    /// The next text a peer sent whose pairing still takes clipboard from it,
    /// from a machine not switched off here. `None` once every transport has
    /// gone.
    pub(crate) async fn next(&mut self) -> Option<String> {
        loop {
            let received = self.rx.recv().await?;
            if !self
                .clients
                .switch_allows_clipboard(&received.from, received.dialled_for)
            {
                // Debounced: a paired machine keeps sending on every copy.
                crate::debounce!(
                    PREV_SWITCHED_OFF_LOG,
                    SWITCHED_OFF_LOG_DEBOUNCE,
                    log::info!(
                        "clipboard text dropped: its sender is switched off on this machine"
                    )
                );
                continue;
            }
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
        store
            .issue_confirmed(&peer.fingerprint, "peer", caps)
            .expect("issue");
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
            let mut inbox = ClipboardInbox::new(rx, trust.clone(), Default::default());
            let from_peer = |text: &str| PeerClipboard {
                from: peer.fingerprint.clone(),
                dialled_for: None,
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

#[cfg(test)]
mod clipboard_follows_the_switch {
    //! Off means off (#218): no clipboard text moves to or from a machine
    //! whose device is switched off here, over the link this machine dialled
    //! to it or the one it opened to this machine, and switching it back on
    //! restores both. The machines are the production transports over
    //! loopback; only the system clipboard at each end is left out.

    use std::collections::HashSet;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    use futures::StreamExt;
    use hops_ipc::{ClientHandle, Position};
    use hops_proto::ProtoEvent;
    use local_channel::mpsc::channel;

    use crate::client::ClientManager;
    use crate::config::ConfigClient;
    use crate::listen::{ClipboardSenderListen, LanMouseListener, ListenEvent};
    use crate::test_harness::{
        ARRIVES_WITHIN, Dialer, Machine, NEVER_WITHIN, applied_within, clipboard_pair, dialer,
        heard_within, machine, run_local, trust, wait_until,
    };
    use crate::transport::Trust;
    use crate::trust::{Caps, TrustStore};

    use super::ClipboardInbox;

    const LINK_UP_WITHIN: Duration = Duration::from_secs(10);

    fn both_ways(me: &Machine, peer: &Machine) -> TrustStore {
        let mut store = TrustStore::new(&me.fingerprint, 0).expect("ours");
        store
            .issue_confirmed(&peer.fingerprint, "peer", Caps::KNOWN)
            .expect("issue");
        store
    }

    async fn heard(rx: &mut Dialer, within: Duration) -> Option<String> {
        heard_within(&mut rx.notices.clipboard, within)
            .await
            .map(|(text, _)| text)
    }

    // LEDGER T2181 | class B | 1 return value: ClipboardInbox::next on each machine, after ClipboardSender::broadcast and ClipboardSenderListen::broadcast; OutboundRevoker::close_device, LanMouseConnection::send
    #[test]
    fn a_device_switched_off_is_sent_no_clipboard_over_the_link_dialled_to_it_and_none_of_its_is_applied()
     {
        run_local(async {
            // This machine dialled the peer, as its first crossing does.
            let (peer, me) = (machine(), machine());
            let (on_peer, on_me) = (both_ways(&peer, &me), both_ways(&me, &peer));
            let mut pair = clipboard_pair(peer, on_peer, me, on_me).await;
            let (mut peer_applies, mut here_applies) = pair.inboxes();
            let (switch, device) = (pair.dialer.clients.clone(), pair.dialer.handle);

            pair.driver_sends.broadcast("switched on".into()).await;
            pair.driven_sends.broadcast("its, switched on".into()).await;
            assert_eq!(
                (
                    applied_within(&mut peer_applies, ARRIVES_WITHIN).await,
                    applied_within(&mut here_applies, ARRIVES_WITHIN).await,
                ),
                (Some("switched on".into()), Some("its, switched on".into())),
                "(there, here): clipboard did not flow both ways with the device on"
            );

            // Only the switch changes: the link stays up, as a link racing
            // the switch would.
            assert!(switch.deactivate_client(device), "precondition");
            pair.driver_sends.broadcast("switched off".into()).await;
            assert_eq!(
                applied_within(&mut peer_applies, NEVER_WITHIN).await,
                None,
                "text copied here went to a device switched off here, over the \
                 link this machine dialled to it"
            );
            pair.driven_sends
                .broadcast("its, switched off".into())
                .await;
            assert_eq!(
                applied_within(&mut here_applies, NEVER_WITHIN).await,
                None,
                "text from a device switched off here was applied here"
            );

            assert!(switch.activate_client(device), "precondition");
            pair.driver_sends.broadcast("back on".into()).await;
            pair.driven_sends.broadcast("its, back on".into()).await;
            assert_eq!(
                (
                    applied_within(&mut peer_applies, ARRIVES_WITHIN).await,
                    applied_within(&mut here_applies, ARRIVES_WITHIN).await,
                ),
                (Some("back on".into()), Some("its, back on".into())),
                "(there, here): switching the device back on left its clipboard \
                 stopped"
            );

            // What switching it off does to the link, as the service does it:
            // closed. Switched back on, it is dialled at the next crossing, as
            // any device that is on is.
            assert!(switch.deactivate_client(device), "precondition");
            let pin = switch.peer_fingerprint(device);
            assert_eq!(
                pin.as_deref(),
                Some(pair.driven.fingerprint.as_str()),
                "precondition: pinned to the machine it dialled"
            );
            assert_eq!(
                pair.dialer
                    .conn
                    .revoker()
                    .close_device(device, pin.as_deref())
                    .await,
                1,
                "precondition: the link was up"
            );
            assert!(switch.activate_client(device), "precondition");
            let _ = pair.dialer.conn.send(ProtoEvent::Ping, device).await;
            wait_until(
                "the device switched back on to be dialled again",
                LINK_UP_WITHIN,
                || pair.dialer.conn.active_addr(device).is_some(),
            )
            .await;
            pair.driver_sends.broadcast("dialled again".into()).await;
            assert_eq!(
                applied_within(&mut peer_applies, ARRIVES_WITHIN).await,
                Some("dialled again".into()),
                "a device switched off and on again was not sent clipboard over \
                 its new link"
            );
        });
    }

    // LEDGER T2185 | class B | 1 return value: ClipboardInbox::next on each machine after ClipboardSender::broadcast, OutboundRevoker::close_device; 6 struct state: LanMouseConnection::active_addr after LanMouseConnection::send
    #[test]
    fn a_device_edited_while_connected_and_then_switched_off_gets_no_clipboard_and_its_link_closes()
    {
        run_local(async {
            let (peer, me) = (machine(), machine());
            let (on_peer, on_me) = (both_ways(&peer, &me), both_ways(&me, &peer));
            let mut pair = clipboard_pair(peer, on_peer, me, on_me).await;
            let (mut peer_applies, mut here_applies) = pair.inboxes();
            let (switch, device) = (pair.dialer.clients.clone(), pair.dialer.handle);

            // Each edit leaves the device pinned to its machine (#99) and
            // its link up: a rename from the app, and a change of address.
            type Edit = fn(&ClientManager, ClientHandle);
            let edits: [(&str, Edit); 2] = [
                ("renamed", |m, h| {
                    m.set_hostname(h, Some("desk mac".into()));
                }),
                ("re-addressed", |m, h| {
                    m.set_fix_ips(
                        h,
                        vec![Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()],
                    )
                }),
            ];
            for (edit, apply) in edits {
                assert!(
                    switch.peer_fingerprint(device).is_some(),
                    "precondition: the device is pinned to the machine it dialled"
                );
                apply(&switch, device);
                assert_eq!(
                    switch.peer_fingerprint(device).as_deref(),
                    Some(pair.driven.fingerprint.as_str()),
                    "precondition: the {edit} device kept its pin"
                );

                assert!(switch.deactivate_client(device), "precondition");
                pair.driver_sends.broadcast(format!("{edit}, off")).await;
                assert_eq!(
                    applied_within(&mut peer_applies, NEVER_WITHIN).await,
                    None,
                    "text copied here went to a device {edit} and then switched off \
                     here, over the link this machine dialled to it"
                );
                pair.driven_sends
                    .broadcast(format!("its, {edit}, off"))
                    .await;
                assert_eq!(
                    applied_within(&mut here_applies, NEVER_WITHIN).await,
                    None,
                    "text from a device {edit} and then switched off here was applied \
                     here"
                );

                // What switching it off does to the link, as the service does
                // it: closed.
                let pin = switch.peer_fingerprint(device);
                assert_eq!(
                    pair.dialer
                        .conn
                        .revoker()
                        .close_device(device, pin.as_deref())
                        .await,
                    1,
                    "switching off a device {edit} while connected closed no link"
                );

                // Switched back on, it is dialled and pinned again.
                assert!(switch.activate_client(device), "precondition");
                let _ = pair.dialer.conn.send(ProtoEvent::Ping, device).await;
                wait_until(
                    "the device switched back on to be dialled again",
                    LINK_UP_WITHIN,
                    || pair.dialer.conn.active_addr(device).is_some(),
                )
                .await;
                pair.driver_sends
                    .broadcast(format!("{edit}, back on"))
                    .await;
                assert_eq!(
                    applied_within(&mut peer_applies, ARRIVES_WITHIN).await,
                    Some(format!("{edit}, back on")),
                    "a device {edit}, switched off and on again was not sent \
                     clipboard over its new link"
                );
            }
        });
    }

    /// This machine's listener, with what the service puts around it for
    /// clipboard: the device list, the broadcast to the machines that dialled
    /// in, and the check made before their text is applied.
    struct DialledInto {
        me: Machine,
        trust: Trust,
        clients: ClientManager,
        listener: LanMouseListener,
        port: u16,
        sends: ClipboardSenderListen,
        applies: ClipboardInbox,
    }

    async fn dialled_into() -> DialledInto {
        let me = machine();
        let trust = trust(&me, &[], Caps::KNOWN);
        listening_as(me, trust, ClientManager::default()).await
    }

    /// `me` listening, with this trust and device list.
    async fn listening_as(me: Machine, trust: Trust, clients: ClientManager) -> DialledInto {
        let (heard_tx, heard) = channel();
        let (listener, port) =
            LanMouseListener::bind_loopback(me.identity.clone(), trust.clone(), heard_tx)
                .await
                .expect("listener");
        let sends = listener.clipboard_sender(clients.clone());
        let applies = ClipboardInbox::new(heard, trust.clone(), clients.clone());
        DialledInto {
            me,
            trust,
            clients,
            listener,
            port,
            sends,
            applies,
        }
    }

    impl DialledInto {
        /// A device here for `peer`, switched on, pinned to it and sharing
        /// the clipboard both ways, and its link to this machine up.
        async fn device_dialling_in(&mut self, peer: &Machine) -> (Dialer, ClientHandle) {
            self.trust
                .write()
                .expect("lock")
                .issue_confirmed(&peer.fingerprint, "peer", Caps::KNOWN)
                .expect("issue");
            let device = self.entry_for(peer);
            let d = self
                .dialled_by(peer, trust(peer, &[&self.me], Caps::KNOWN))
                .await;
            (d, device)
        }

        /// `peer`, trusting this machine as `peer_trust` says, dials it, and
        /// its link is up.
        async fn dialled_by(&mut self, peer: &Machine, peer_trust: Trust) -> Dialer {
            let d = dialer(peer, peer_trust, self.port, Position::Left);
            d.conn.dial(d.handle).await;
            let accepted = tokio::time::timeout(LINK_UP_WITHIN, async {
                while let Some(event) = self.listener.next().await {
                    if let ListenEvent::Accept { fingerprint, .. } = event {
                        if fingerprint == peer.fingerprint {
                            return true;
                        }
                    }
                }
                false
            })
            .await;
            assert!(
                matches!(accepted, Ok(true)),
                "this machine never accepted the peer's link"
            );
            wait_until("the peer to hold its link", LINK_UP_WITHIN, || {
                d.conn.active_addr(d.handle).is_some()
            })
            .await;
            d
        }

        /// Another entry here pinned to `peer`, switched on.
        fn entry_for(&self, peer: &Machine) -> ClientHandle {
            self.clients.add_with_config(ConfigClient {
                label: None,
                ips: HashSet::new(),
                hostname: None,
                port: hops_ipc::DEFAULT_PORT,
                pos: Position::Right,
                active: true,
                enter_hook: None,
                fingerprint: Some(peer.fingerprint.clone()),
            })
        }
    }

    // LEDGER T2182 | class B | 1 return value: ClipboardInbox::next; 6 struct state: each peer's transport queue after ClipboardSenderListen::broadcast
    #[test]
    fn a_device_switched_off_is_sent_no_clipboard_over_the_link_it_opened_and_the_others_still_are()
    {
        run_local(async {
            let mut here = dialled_into().await;
            let (switched, other) = (machine(), machine());
            let (mut switched_peer, device) = here.device_dialling_in(&switched).await;
            let (mut other_peer, _) = here.device_dialling_in(&other).await;
            let (switched_sends, other_sends) = (
                switched_peer.conn.clipboard_sender(),
                other_peer.conn.clipboard_sender(),
            );

            here.sends.broadcast("all on".into()).await;
            assert_eq!(
                (
                    heard(&mut switched_peer, ARRIVES_WITHIN).await,
                    heard(&mut other_peer, ARRIVES_WITHIN).await,
                ),
                (Some("all on".into()), Some("all on".into())),
                "clipboard did not reach two devices that are on"
            );
            switched_sends.broadcast("its, on".into()).await;
            assert_eq!(
                applied_within(&mut here.applies, ARRIVES_WITHIN).await,
                Some("its, on".into()),
                "text from a device that is on was not applied"
            );

            assert!(here.clients.deactivate_client(device), "precondition");
            here.sends.broadcast("one off".into()).await;
            assert_eq!(
                heard(&mut other_peer, ARRIVES_WITHIN).await,
                Some("one off".into()),
                "switching one device off stopped clipboard to another"
            );
            assert_eq!(
                heard(&mut switched_peer, NEVER_WITHIN).await,
                None,
                "text copied here went to a device switched off here, over the \
                 link it opened to this machine"
            );
            switched_sends.broadcast("its, off".into()).await;
            assert_eq!(
                applied_within(&mut here.applies, NEVER_WITHIN).await,
                None,
                "text from a device switched off here was applied, over the link \
                 it opened to this machine"
            );
            other_sends.broadcast("the other's".into()).await;
            assert_eq!(
                applied_within(&mut here.applies, ARRIVES_WITHIN).await,
                Some("the other's".into()),
                "switching one device off stopped clipboard from another"
            );

            // A second entry for the same machine, switched on, does not
            // reopen it.
            here.entry_for(&switched);
            here.sends.broadcast("another entry on".into()).await;
            assert_eq!(
                heard(&mut other_peer, ARRIVES_WITHIN).await,
                Some("another entry on".into()),
                "precondition: the other device still gets text"
            );
            assert_eq!(
                heard(&mut switched_peer, NEVER_WITHIN).await,
                None,
                "one entry for a machine is off and another is on, and text went \
                 to it: off has to fail closed"
            );

            assert!(here.clients.activate_client(device), "precondition");
            here.sends.broadcast("back on".into()).await;
            assert_eq!(
                heard(&mut switched_peer, ARRIVES_WITHIN).await,
                Some("back on".into()),
                "switching the device back on left clipboard to it stopped"
            );
            switched_sends.broadcast("its, back on".into()).await;
            assert_eq!(
                applied_within(&mut here.applies, ARRIVES_WITHIN).await,
                Some("its, back on".into()),
                "switching the device back on left clipboard from it stopped"
            );
        });
    }

    // LEDGER T2187 | class B | 1 return value: ClipboardInbox::next; 6 struct state: the peer's transport queue after ClipboardSenderListen::broadcast
    #[test]
    fn a_device_edited_and_switched_off_is_sent_no_clipboard_over_the_link_it_opened() {
        run_local(async {
            let mut here = dialled_into().await;
            let peer = machine();
            let (mut peer_link, mut device) = here.device_dialling_in(&peer).await;
            let peer_sends = peer_link.conn.clipboard_sender();

            // A rename keeps the pin (#99). The switch has to keep naming the
            // machine whether the rename comes before it or after it. Each
            // case takes a fresh entry for the machine, pinned to it.
            type Step = fn(&ClientManager, ClientHandle);
            let rename: Step = |m, h| {
                m.set_hostname(h, Some("desk mac".into()));
            };
            let off: Step = |m, h| assert!(m.deactivate_client(h), "precondition");
            let cases: [(&str, [Step; 2]); 2] = [
                ("renamed and then switched off", [rename, off]),
                ("switched off and then renamed", [off, rename]),
            ];
            for (case, steps) in cases {
                here.sends.broadcast(format!("on, before {case}")).await;
                peer_sends
                    .broadcast(format!("its, on, before {case}"))
                    .await;
                assert_eq!(
                    (
                        heard(&mut peer_link, ARRIVES_WITHIN).await,
                        applied_within(&mut here.applies, ARRIVES_WITHIN).await,
                    ),
                    (
                        Some(format!("on, before {case}")),
                        Some(format!("its, on, before {case}"))
                    ),
                    "(there, here): precondition: clipboard flows both ways with the \
                     device on"
                );

                for step in steps {
                    step(&here.clients, device);
                }
                assert_eq!(
                    here.clients.peer_fingerprint(device).as_deref(),
                    Some(peer.fingerprint.as_str()),
                    "precondition: the rename kept the pin"
                );
                here.sends.broadcast(case.to_string()).await;
                assert_eq!(
                    heard(&mut peer_link, NEVER_WITHIN).await,
                    None,
                    "text copied here went to a device {case} here, over the link it \
                     opened to this machine"
                );
                peer_sends.broadcast(format!("its, {case}")).await;
                assert_eq!(
                    applied_within(&mut here.applies, NEVER_WITHIN).await,
                    None,
                    "text from a device {case} here was applied, over the link it \
                     opened to this machine"
                );

                assert!(here.clients.activate_client(device), "precondition");
                here.sends.broadcast(format!("{case}, back on")).await;
                peer_sends.broadcast(format!("its, {case}, back on")).await;
                assert_eq!(
                    (
                        heard(&mut peer_link, ARRIVES_WITHIN).await,
                        applied_within(&mut here.applies, ARRIVES_WITHIN).await,
                    ),
                    (
                        Some(format!("{case}, back on")),
                        Some(format!("its, {case}, back on"))
                    ),
                    "(there, here): switching the device back on left its clipboard \
                     stopped"
                );
                device = here.entry_for(&peer);
            }
        });
    }

    // LEDGER T2188 | class B | 1 return value: ClipboardInbox::next; 6 struct state: the peer's transport queue after ClipboardSenderListen::broadcast; OutboundRevoker::close_device, LanMouseConnection::send
    #[test]
    fn a_device_edited_while_linked_both_ways_and_switched_off_is_sent_no_clipboard_over_the_link_it_opened()
     {
        run_local(async {
            let (peer, me) = (machine(), machine());
            let (on_peer, on_me) = (both_ways(&peer, &me), both_ways(&me, &peer));
            // This machine dialled the peer, and that dial pinned its device...
            let pair = clipboard_pair(peer, on_peer, me, on_me).await;
            let (switch, device) = (pair.dialer.clients.clone(), pair.dialer.handle);
            // ...and the peer opened a link to this machine as well.
            let me = Machine {
                identity: pair.driver.identity.clone(),
                fingerprint: pair.driver.fingerprint.clone(),
            };
            let mut here = listening_as(me, pair.driver_trust.clone(), switch.clone()).await;
            let mut peer_link = here
                .dialled_by(&pair.driven, pair.driven_trust.clone())
                .await;
            let peer_sends = peer_link.conn.clipboard_sender();
            here.sends.broadcast("on".into()).await;
            peer_sends.broadcast("its, on".into()).await;
            assert_eq!(
                (
                    heard(&mut peer_link, ARRIVES_WITHIN).await,
                    applied_within(&mut here.applies, ARRIVES_WITHIN).await,
                ),
                (Some("on".into()), Some("its, on".into())),
                "(there, here): precondition: clipboard flows both ways over the \
                 link the peer opened"
            );

            type Edit = fn(&ClientManager, ClientHandle);
            let edits: [(&str, Edit); 2] = [
                ("renamed", |m, h| {
                    m.set_hostname(h, Some("desk mac".into()));
                }),
                ("re-addressed", |m, h| {
                    m.set_fix_ips(
                        h,
                        vec![Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()],
                    )
                }),
            ];
            for (edit, apply) in edits {
                assert_eq!(
                    switch.peer_fingerprint(device).as_deref(),
                    Some(pair.driven.fingerprint.as_str()),
                    "precondition: the device is pinned by this machine's own dial"
                );
                apply(&switch, device);
                assert!(switch.deactivate_client(device), "precondition");

                here.sends.broadcast(format!("{edit}, off")).await;
                assert_eq!(
                    heard(&mut peer_link, NEVER_WITHIN).await,
                    None,
                    "text copied here went to a device {edit} and then switched off \
                     here, over the link it opened to this machine"
                );
                peer_sends.broadcast(format!("its, {edit}, off")).await;
                assert_eq!(
                    applied_within(&mut here.applies, NEVER_WITHIN).await,
                    None,
                    "text from a device {edit} and then switched off here was applied, \
                     over the link it opened to this machine"
                );

                // As the service switches it off: its own link closes. Back
                // on, it is dialled and pinned again, and clipboard over the
                // peer's link resumes.
                let pin = switch.peer_fingerprint(device);
                assert_eq!(
                    pair.dialer
                        .conn
                        .revoker()
                        .close_device(device, pin.as_deref())
                        .await,
                    1,
                    "precondition: this machine's link to it was up"
                );
                assert!(switch.activate_client(device), "precondition");
                let _ = pair.dialer.conn.send(ProtoEvent::Ping, device).await;
                wait_until(
                    "the device switched back on to be dialled again",
                    LINK_UP_WITHIN,
                    || pair.dialer.conn.active_addr(device).is_some(),
                )
                .await;
                here.sends.broadcast(format!("{edit}, back on")).await;
                peer_sends.broadcast(format!("its, {edit}, back on")).await;
                assert_eq!(
                    (
                        heard(&mut peer_link, ARRIVES_WITHIN).await,
                        applied_within(&mut here.applies, ARRIVES_WITHIN).await,
                    ),
                    (
                        Some(format!("{edit}, back on")),
                        Some(format!("its, {edit}, back on"))
                    ),
                    "(there, here): a device {edit}, switched off and on again, had \
                     its clipboard stopped over the link the peer opened"
                );
            }
        });
    }
}
