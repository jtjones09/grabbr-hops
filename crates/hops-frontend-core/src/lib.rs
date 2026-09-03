//! Shared frontend core for hops UIs (Ratatui TUI + Slint GUI).
//!
//! Owns a typed, auto-reconnecting async IPC client over
//! [`hops_ipc::connect_async`], an observable [`AppModel`] reduced from the
//! daemon's [`FrontendEvent`] stream, and a change-notification so a TUI redraw
//! or a Slint property bridge can subscribe. Front-ends depend on this crate +
//! `hops-ipc`; they contain no protocol logic of their own.

use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use futures::StreamExt;
use tokio::sync::{Notify, mpsc};

pub use hops_ipc::{
    AttemptOrigin, ClientConfig, ClientHandle, ClientState, DiscoveredDevice, FrontendEvent,
    FrontendRequest, Position, RevokedEntry, Status, connect_async,
};

pub mod prefs;
pub mod theme;

/// How many transient event/error lines to keep for the UI log pane.
const MAX_MESSAGES: usize = 50;

/// Reduced, UI-facing snapshot of daemon state. Cloned cheaply for rendering.
#[derive(Debug, Default, Clone)]
pub struct AppModel {
    /// True while the IPC socket is connected.
    pub connected: bool,
    /// Configured clients, keyed + ordered by handle.
    pub clients: BTreeMap<ClientHandle, (ClientConfig, ClientState)>,
    /// Local input-capture status.
    pub capture: Status,
    /// Local input-emulation status.
    pub emulation: Status,
    /// This device's public-key fingerprint.
    pub fingerprint: Option<String>,
    /// This device's own shareable pairing code (encoded), or `None` if it has no
    /// shareable LAN address. Sent by the daemon on sync; the UI reveals it so the
    /// user can hand it to another machine to pair across a subnet.
    pub local_pairing_code: Option<String>,
    /// Trusted peer fingerprints -> description.
    pub authorized: HashMap<String, String>,
    /// Fingerprints the user deliberately revoked. Kept so a returning peer is
    /// shown as EXPELLED rather than as a stranger, and so re-trusting it is a
    /// distinct, user-initiated act.
    pub revoked: HashMap<String, RevokedEntry>,
    /// The daemon's listen port.
    pub port: Option<u16>,
    /// Recent transient events / errors (newest last), capped at [`MAX_MESSAGES`].
    pub messages: VecDeque<String>,
    /// Monotonic counter, bumped on every message. Lets a polling frontend tell a
    /// NEW notice from the same one still on screen, so a dismissed banner stays
    /// dismissed but a fresh failure re-raises it.
    pub message_seq: u64,
    /// Fingerprints of peers currently connected *in*, as known from live
    /// connect/disconnect events while this client is attached. CAVEAT: a peer
    /// that connected before we attached is not reflected until the daemon
    /// reports current connections on `Sync` (a planned additive event).
    pub connected_peers: HashSet<String>,
    /// Machines seen on the local network that are not already configured or
    /// trusted — the "click a name instead of typing an address" list (#136).
    ///
    /// NOT trusted and NOT identified. `claimed_fingerprint` is an assertion by
    /// whatever is on the LAN. Selecting one of these dials it and goes through
    /// the ordinary approval prompt exactly as a typed address does; it must
    /// never shortcut that.
    pub discovered: Vec<DiscoveredDevice>,
    /// Whether hops is actually looking for machines on the network.
    ///
    /// Needed because an empty `discovered` is ambiguous — off, still looking,
    /// or genuinely nothing there. Rendering the same silence for all three is
    /// how a working feature looks broken (#141).
    pub discovery_active: bool,
    /// An untrusted peer's fingerprint awaiting the user's pairing approval. Set
    /// on `ConnectionAttempt`; cleared once it becomes authorized or the daemon
    /// link drops. The UI surfaces this as an approve/deny prompt.
    pub pending_pairing: Option<String>,
    /// How the pending attempt arrived. `OutboundDial` means WE dialled and
    /// found an untrusted receiver — which a console verb can cause, so the UI
    /// must not present it as a peer knocking (#61).
    pub pending_pairing_origin: Option<AttemptOrigin>,
    /// The address that answered, for an `OutboundDial` attempt. The user typed
    /// an address; this is the one that actually replied, and the two are not
    /// always the same machine (#93).
    pub pending_pairing_addr: Option<std::net::SocketAddr>,
    /// When `pending_pairing` was last (re)asserted by a `ConnectionAttempt`.
    /// A front-end can treat the prompt as stale (the peer gave up) once this is
    /// older than a small TTL, since the daemon emits no retraction event.
    pub pending_pairing_since: Option<Instant>,
    /// Maps a connected peer's socket address -> fingerprint, so the addr-only
    /// `IncomingDisconnected` event can be correlated back to a fingerprint.
    peer_addrs: HashMap<SocketAddr, String>,
}

impl Device {
    /// Should this device occupy a row in the device list?
    ///
    /// Excludes ONLY a bare inbound pairing request, which lives in the pairing
    /// banner instead. A revoked device MUST be listable — being visible as
    /// expelled is the entire point of persisting revocation, and it has neither
    /// a send facet nor `receive`, so any "send or receive" test silently drops
    /// it and the restore UI can never render.
    pub fn is_listable(&self) -> bool {
        self.send.is_some() || self.receive || self.trust == TrustState::Revoked
    }
}

impl AppModel {
    /// Fold one daemon event into the model.
    pub fn apply(&mut self, event: FrontendEvent) {
        match event {
            FrontendEvent::Enumerate(list) => {
                self.clients = list.into_iter().map(|(h, c, s)| (h, (c, s))).collect();
            }
            FrontendEvent::Created(h, c, s) | FrontendEvent::State(h, c, s) => {
                self.clients.insert(h, (c, s));
            }
            FrontendEvent::Deleted(h) => {
                self.clients.remove(&h);
            }
            FrontendEvent::CaptureStatus(s) => self.capture = s,
            FrontendEvent::EmulationStatus(s) => self.emulation = s,
            FrontendEvent::PublicKeyFingerprint(fp) => self.fingerprint = Some(fp),
            FrontendEvent::PairingCode(code) => {
                self.local_pairing_code = (!code.is_empty()).then_some(code);
            }
            FrontendEvent::RevokedUpdated(map) => self.revoked = map,
            FrontendEvent::AuthorizedUpdated(map) => {
                self.authorized = map;
                // a pending request that just became trusted is resolved
                if let Some(fp) = self.pending_pairing.clone() {
                    if self.authorized.contains_key(&fp) {
                        self.pending_pairing = None;
                        self.pending_pairing_since = None;
                    }
                }
            }
            FrontendEvent::PortChanged(port, err) => {
                self.port = Some(port);
                if let Some(e) = err {
                    self.push_message(format!("port change failed: {e}"));
                }
            }
            FrontendEvent::Error(e) => self.push_message(format!("error: {e}")),
            FrontendEvent::DeviceConnected { addr, fingerprint } => {
                self.register_peer(addr, fingerprint);
                self.push_message(format!("device connected: {addr}"));
            }
            FrontendEvent::DeviceEntered {
                addr,
                pos,
                fingerprint,
            } => {
                self.register_peer(addr, fingerprint);
                self.push_message(format!("cursor entered from {addr} ({pos})"));
            }
            FrontendEvent::IncomingDisconnected(addr) => {
                if let Some(fp) = self.peer_addrs.remove(&addr) {
                    self.forget_if_last_addr(&fp);
                }
                self.push_message(format!("incoming disconnected: {addr}"));
            }
            FrontendEvent::ConnectionAttempt {
                fingerprint,
                origin,
                addr,
            } => {
                self.push_message(match origin {
                    AttemptOrigin::Inbound => format!("pairing request: {fingerprint}"),
                    AttemptOrigin::OutboundDial => match addr {
                        Some(a) => format!("{a} answered our dial, untrusted: {fingerprint}"),
                        None => format!("we dialled an untrusted receiver: {fingerprint}"),
                    },
                });
                if !self.authorized.contains_key(&fingerprint) {
                    self.pending_pairing = Some(fingerprint);
                    self.pending_pairing_origin = Some(origin);
                    self.pending_pairing_addr = addr;
                    self.pending_pairing_since = Some(Instant::now());
                }
            }
            FrontendEvent::Discovered { active, peers } => {
                self.discovery_active = active;
                self.discovered = peers;
            }
            FrontendEvent::NoSuchClient(_) => {}
        }
    }

    /// Record a peer as connected, dropping any stale fingerprint previously
    /// mapped to the same socket address — prevents a permanently "connected"
    /// ghost when an addr reconnects under a different fingerprint.
    fn register_peer(&mut self, addr: SocketAddr, fingerprint: String) {
        if let Some(old) = self.peer_addrs.insert(addr, fingerprint.clone()) {
            if old != fingerprint {
                self.forget_if_last_addr(&old);
            }
        }
        self.connected_peers.insert(fingerprint);
    }

    /// Drop a fingerprint from `connected_peers` ONLY when no live address still
    /// maps to it.
    ///
    /// A peer that reconnects on a new source port produces DeviceConnected(new)
    /// followed by IncomingDisconnected(old). Removing unconditionally let the
    /// OLD address's late disconnect erase the connection the NEW one had just
    /// established, so a connected peer rendered as "offline".
    fn forget_if_last_addr(&mut self, fingerprint: &str) {
        if !self.peer_addrs.values().any(|f| f == fingerprint) {
            self.connected_peers.remove(fingerprint);
        }
    }

    fn push_message(&mut self, msg: String) {
        if self.messages.len() >= MAX_MESSAGES {
            self.messages.pop_front();
        }
        self.messages.push_back(msg);
        self.message_seq += 1;
    }

    /// The most recent notice, if any. The daemon's only channel for telling the
    /// user something went wrong; before this was rendered, every failure —
    /// unresolvable name, refused trust change, failed config write, rejected
    /// IPC token — reached the user as silence.
    pub fn latest_message(&self) -> Option<&str> {
        self.messages.back().map(|s| s.as_str())
    }
}

/// The trust status of a [`Device`] in the unified view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustState {
    /// An outgoing client we have never completed a handshake with, so its
    /// identity (fingerprint) is unknown/unpinned — trust is not established.
    Provisional,
    /// The peer's fingerprint is in the authorized allowlist.
    Trusted,
    /// An un-authorized peer awaiting the user's pairing approval.
    PendingApproval,
    /// The user deliberately expelled this peer. Distinct from `Provisional` on
    /// purpose: the whole point of persisting revocation is that "a device you
    /// threw out" must never render like "a device you have not met".
    Revoked,
}

/// The outgoing ("send input to this device") facet of a [`Device`], present
/// iff this machine has a configured client for it.
#[derive(Debug, Clone)]
pub struct DeviceSend {
    pub handle: ClientHandle,
    pub config: ClientConfig,
    pub state: ClientState,
}

/// One physical peer, unifying the two disjoint namespaces — the outgoing
/// `clients` list (address-shaped) and the `authorized_fingerprints` allowlist
/// (identity-shaped) — into a single record joined by the TLS leaf-cert
/// fingerprint. Built by [`AppModel::devices`]. See `DEVICE-MODEL-DISCOVERY.md`.
#[derive(Debug, Clone)]
pub struct Device {
    /// The peer's leaf-cert fingerprint — the identity + join key. `None` for a
    /// provisional outgoing client that has never connected (no fp learned yet).
    pub fingerprint: Option<String>,
    /// Display label: the send-side hostname, else the trusted description,
    /// else a short fingerprint.
    pub label: String,
    pub trust: TrustState,
    /// A peer with this fingerprint is currently connected *in*.
    pub online: bool,
    /// Present iff this machine dials the device (a configured client).
    pub send: Option<DeviceSend>,
    /// True iff the device's fingerprint is in the authorized allowlist
    /// (trusted to connect *in*).
    pub receive: bool,
}

impl AppModel {
    /// The six digits to display beside a pending pairing prompt.
    ///
    /// Derived from **this machine's** fingerprint and the peer's, so the other
    /// machine's prompt shows the same number. The user's job is to check they
    /// match; a compromised console cannot make the far screen show a number of
    /// its choosing, which is the property nothing else in the pairing flow has
    /// (#61, #136).
    ///
    /// `None` until both fingerprints are known — better to show nothing than a
    /// number that cannot be compared.
    pub fn pending_verification_code(&self) -> Option<String> {
        let ours = self.fingerprint.as_deref()?;
        let theirs = self.pending_pairing.as_deref()?;
        hops_ipc::pairing::verification_code(ours, theirs)
    }
}

/// The hostname to store for a machine picked off the network list.
///
/// mDNS advertises a host as `<instance>.local.`, and a bare `ScornMBP23` does
/// not resolve while `ScornMBP23.local` does — through the OS name stack
/// (Bonjour on macOS, Avahi via nsswitch on Linux), which `src/dns.rs` uses
/// deliberately for exactly this.
///
/// This is what makes a discovered device **self-healing**. The addresses
/// pinned at add-time are a snapshot: if the peer's DHCP lease changes, they go
/// stale. hops dials the union of pinned and freshly-resolved addresses on
/// every reconnect, so a resolvable `.local` name keeps the device working
/// after every address it was added with has changed.
///
/// A label that already contains a dot is left alone — it is either already
/// qualified or something the user typed.
pub fn discovered_hostname(label: &str) -> String {
    let label = label.trim();
    if label.is_empty() || label.contains('.') {
        label.to_string()
    } else {
        format!("{label}.local")
    }
}

impl Device {
    /// This machine is configured to drive the device, capture is routed to it,
    /// and the device has told us on the wire that its emulation is **off** —
    /// so `connect.rs` will refuse every event with `TargetEmulationDisabled`
    /// before writing a frame.
    ///
    /// Kept here rather than in each front-end because both of them used to
    /// compute `online || alive`, which OR's this away: a peer that connects
    /// *in* sets `online`, and the dot went green while the same machine
    /// silently refused everything sent to it. `online` and `alive` are
    /// different facts about different directions (#92).
    pub fn refuses_our_input(&self) -> bool {
        self.send.as_ref().is_some_and(|s| {
            // `active_addr` is Some only while an outbound link is actually up
            // (set on a successful dial, cleared by `disconnect`). Without it
            // this predicate fired for a device that is merely OFFLINE, because
            // `alive` is false until the first Pong arrives and stays false if
            // no connection is ever made.
            //
            // That reintroduced the exact conflation #92 existed to remove:
            // "up and refusing" and "not reachable" need different fixes from
            // the user, and telling them the wrong one is worse than saying
            // nothing. Reported from the rig within minutes of the build
            // landing — every configured device read "not accepting input"
            // before anything had crossed.
            s.state.active && s.state.active_addr.is_some() && !s.state.alive
        })
    }
}

/// A compact, human-comparable rendering of a colon-separated fingerprint
/// (first three groups, e.g. `1e:19:1b`) for use as a fallback label.
fn short_fingerprint(fp: &str) -> String {
    fp.split(':').take(3).collect::<Vec<_>>().join(":")
}

/// What to call a peer the user approved without typing a name.
///
/// Shared so the frontends agree: the GUI used the literal `"device"` and the
/// TUI used a truncated fingerprint, so the same peer, approved the same way,
/// came out with two different names depending on which interface was open —
/// and `"device"` is worse than useless once there are two of them. A short
/// fingerprint is at least the peer's own identity, and it is what the device
/// projection already falls back to.
pub fn fallback_label(fp: &str) -> String {
    if fp.is_empty() {
        return "unnamed device".to_string();
    }
    short_fingerprint(fp)
}

/// Pick a display label, preferring the user-typed send-side hostname, then the
/// trusted description, then a short fingerprint, then a placeholder.
fn display_label(hostname: Option<&str>, description: Option<&str>, fp: &str) -> String {
    if let Some(h) = hostname.filter(|h| !h.is_empty()) {
        return h.to_string();
    }
    if let Some(d) = description.filter(|d| !d.is_empty()) {
        return d.to_string();
    }
    if !fp.is_empty() {
        return short_fingerprint(fp);
    }
    "unnamed device".to_string()
}

impl AppModel {
    /// Project the two disjoint namespaces — outgoing `clients` and `authorized`
    /// fingerprints — into one [`Device`] per physical peer, joined by the peer
    /// fingerprint (stamped onto `ClientState` at handshake). An outgoing client
    /// that has never connected (no `peer_fingerprint`) stays its own
    /// provisional card; a trusted fingerprint with no outgoing client is a
    /// receive-only card. One approval keyed by fingerprint therefore surfaces
    /// as one device in both directions — the end of double-entry.
    pub fn devices(&self) -> Vec<Device> {
        let is_self = |fp: &str| self.fingerprint.as_deref() == Some(fp);
        let mut by_fp: HashMap<String, Device> = HashMap::new();
        // provisional (never-connected) send cards have no fingerprint to key on
        let mut provisional: Vec<Device> = Vec::new();

        // 1. authorized fingerprints -> trusted / receive-capable devices
        for (fp, desc) in &self.authorized {
            if is_self(fp) {
                continue; // never list ourselves
            }
            by_fp.insert(
                fp.clone(),
                Device {
                    fingerprint: Some(fp.clone()),
                    label: display_label(None, Some(desc), fp),
                    trust: TrustState::Trusted,
                    online: self.connected_peers.contains(fp),
                    send: None,
                    receive: true,
                },
            );
        }

        // 2. outgoing clients -> attach a send facet, joining by peer_fingerprint
        for (&handle, (config, state)) in &self.clients {
            let send = DeviceSend {
                handle,
                config: config.clone(),
                state: state.clone(),
            };
            match state.peer_fingerprint.as_deref() {
                Some(fp) if !is_self(fp) => {
                    let device = by_fp.entry(fp.to_string()).or_insert_with(|| Device {
                        fingerprint: Some(fp.to_string()),
                        label: display_label(config.hostname.as_deref(), None, fp),
                        trust: if self.pending_pairing.as_deref() == Some(fp) {
                            TrustState::PendingApproval
                        } else {
                            TrustState::Provisional
                        },
                        online: self.connected_peers.contains(fp),
                        send: None,
                        receive: false,
                    });
                    // A user-typed send-side hostname is the preferred label --
                    // EXCEPT when it is a bare IP literal. Adding a device by
                    // address puts the IP in the name field, and an address is a
                    // worse name than the peer's own advertised description.
                    if let Some(host) = config
                        .hostname
                        .as_deref()
                        .filter(|h| !h.is_empty())
                        .filter(|h| h.parse::<std::net::IpAddr>().is_err())
                    {
                        device.label = host.to_string();
                    }
                    device.send = Some(send);
                }
                // never connected (or our own fp somehow) -> own provisional card
                _ => provisional.push(Device {
                    fingerprint: None,
                    label: display_label(config.hostname.as_deref(), None, ""),
                    trust: TrustState::Provisional,
                    online: false,
                    send: Some(send),
                    receive: false,
                }),
            }
        }

        // 3. revoked devices — shown, not forgotten, so re-trust is something the
        //    user initiates from a row they can see rather than something a
        //    reconnecting peer provokes with a prompt.
        for (fp, entry) in &self.revoked {
            // Revoked OUTRANKS authorized, deliberately. The daemon refuses to
            // re-authorize an expelled fingerprint, so both tables naming one
            // means the config was hand-edited — and the safe reading of that is
            // "expelled", never "trusted".
            if is_self(fp) {
                continue;
            }
            let device = by_fp.entry(fp.clone()).or_insert_with(|| Device {
                fingerprint: Some(fp.clone()),
                label: display_label(None, Some(&entry.label), fp),
                trust: TrustState::Revoked,
                online: false,
                send: None,
                receive: false,
            });
            // a client may still be configured to dial it; the card stays revoked
            device.trust = TrustState::Revoked;
            device.receive = false;
            if device.label.is_empty() {
                device.label = display_label(None, Some(&entry.label), fp);
            }
        }

        // 4. a bare inbound pairing request not already represented above
        if let Some(fp) = self.pending_pairing.as_deref() {
            if !self.authorized.contains_key(fp) && !is_self(fp) && !self.revoked.contains_key(fp) {
                by_fp.entry(fp.to_string()).or_insert_with(|| Device {
                    fingerprint: Some(fp.to_string()),
                    label: short_fingerprint(fp),
                    trust: TrustState::PendingApproval,
                    online: self.connected_peers.contains(fp),
                    send: None,
                    receive: false,
                });
            }
        }

        // send-facet devices first (ordered by handle), then receive-only (by label)
        let mut out: Vec<Device> = by_fp.into_values().chain(provisional).collect();
        out.sort_by(|a, b| {
            match (
                a.send.as_ref().map(|s| s.handle),
                b.send.as_ref().map(|s| s.handle),
            ) {
                (Some(x), Some(y)) => x.cmp(&y),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                // tie-break on fingerprint: `by_fp` is a HashMap, so equal labels
                // would otherwise fall through to its nondeterministic iteration
                // order and the rows would swap on every refresh.
                (None, None) => a
                    .label
                    .to_lowercase()
                    .cmp(&b.label.to_lowercase())
                    .then_with(|| a.fingerprint.cmp(&b.fingerprint)),
            }
        });
        out
    }
}

/// Handle to the running IPC client: a shared observable [`AppModel`], a change
/// signal, and a request sink. Clone it freely; spawn it inside a `LocalSet`.
#[derive(Clone)]
pub struct FrontendClient {
    model: Arc<Mutex<AppModel>>,
    changed: Arc<Notify>,
    requests: mpsc::UnboundedSender<FrontendRequest>,
}

impl FrontendClient {
    /// Spawn the auto-reconnecting connection task and return a handle. Must be
    /// called within a tokio `LocalSet` (it uses `spawn_local`).
    pub fn spawn() -> Self {
        let model = Arc::new(Mutex::new(AppModel::default()));
        let changed = Arc::new(Notify::new());
        let (requests, request_rx) = mpsc::unbounded_channel();
        tokio::task::spawn_local(connection_loop(model.clone(), changed.clone(), request_rx));
        Self {
            model,
            changed,
            requests,
        }
    }

    /// A cheap clone of the current model, for rendering.
    pub fn snapshot(&self) -> AppModel {
        self.model.lock().expect("model lock poisoned").clone()
    }

    /// Resolves the next time the model changes (coalesced — multiple changes
    /// while not awaiting collapse into a single wake).
    pub async fn changed(&self) {
        self.changed.notified().await;
    }

    /// Send a request to the daemon (fire-and-forget).
    pub fn request(&self, request: FrontendRequest) {
        let _ = self.requests.send(request);
    }
}

/// Connect, sync, fold events into the model, forward requests; reconnect on drop.
async fn connection_loop(
    model: Arc<Mutex<AppModel>>,
    changed: Arc<Notify>,
    mut request_rx: mpsc::UnboundedReceiver<FrontendRequest>,
) {
    loop {
        let (mut events, mut writer) = match connect_async(None).await {
            Ok(conn) => conn,
            Err(e) => {
                log::warn!("frontend: could not connect to daemon: {e}");
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
        };
        model.lock().expect("model lock poisoned").connected = true;
        changed.notify_one();
        // pull full initial state
        let _ = writer.request(FrontendRequest::Sync).await;

        loop {
            tokio::select! {
                event = events.next() => match event {
                    Some(Ok(event)) => {
                        model.lock().expect("model lock poisoned").apply(event);
                        changed.notify_one();
                    }
                    // forward-compat: skip an event line we can't decode, keep the connection
                    Some(Err(hops_ipc::IpcError::Json(e))) => {
                        log::debug!("frontend: skipping undecodable event: {e}");
                    }
                    // EOF or io error -> reconnect
                    _ => break,
                },
                request = request_rx.recv() => match request {
                    Some(request) => {
                        if let Err(e) = writer.request(request).await {
                            log::warn!("frontend: request failed: {e}");
                            break;
                        }
                    }
                    None => return, // the FrontendClient was dropped
                },
            }
        }

        {
            let mut m = model.lock().expect("model lock poisoned");
            m.connected = false;
            // we lose live connect/disconnect tracking when the daemon link
            // drops; clear it so we don't show a stale "connected" peer.
            m.connected_peers.clear();
            m.peer_addrs.clear();
            m.pending_pairing = None;
            m.pending_pairing_since = None;
        }
        changed.notify_one();
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[cfg(test)]
mod attempt_origin {
    //! A prompt we caused by dialling out must not reach the user looking like a
    //! peer knocking (#61). The daemon knows which it was; the model has to
    //! carry that, because the UI cannot re-derive it.
    use super::{AppModel, AttemptOrigin, FrontendEvent};
    use std::net::SocketAddr;

    fn attempt(origin: AttemptOrigin) -> AppModel {
        attempt_from(origin, None)
    }

    fn attempt_from(origin: AttemptOrigin, addr: Option<SocketAddr>) -> AppModel {
        let mut m = AppModel::default();
        m.apply(FrontendEvent::ConnectionAttempt {
            fingerprint: "AA:BB".into(),
            origin,
            addr,
        });
        m
    }

    /// The address that answered has to reach the user. They typed one address;
    /// a different machine can be the one that replies (a typo, a recycled DHCP
    /// lease, a machine that took the address while the intended one slept), and
    /// the fingerprint alone gives them nothing to compare against (#93).
    #[test]
    fn the_answering_address_reaches_the_user() {
        let a: SocketAddr = "10.0.0.5:4242".parse().unwrap();
        let m = attempt_from(AttemptOrigin::OutboundDial, Some(a));
        assert_eq!(m.pending_pairing_addr, Some(a));
        assert!(
            m.messages.back().unwrap().contains("10.0.0.5:4242"),
            "the log line must name the address that answered, got {:?}",
            m.messages.back()
        );
    }

    #[test]
    fn the_origin_reaches_the_model() {
        assert_eq!(
            attempt(AttemptOrigin::Inbound).pending_pairing_origin,
            Some(AttemptOrigin::Inbound)
        );
        assert_eq!(
            attempt(AttemptOrigin::OutboundDial).pending_pairing_origin,
            Some(AttemptOrigin::OutboundDial)
        );
    }

    /// Both still raise a prompt — a console-caused dial is not silently
    /// swallowed. It is *labelled*, not suppressed. Suppressing it would break
    /// the outbound pairing flow, which is how a device is actually paired.
    #[test]
    fn both_origins_still_prompt() {
        for o in [AttemptOrigin::Inbound, AttemptOrigin::OutboundDial] {
            assert_eq!(
                attempt(o).pending_pairing.as_deref(),
                Some("AA:BB"),
                "{o:?} must still raise a prompt"
            );
        }
    }

    /// And the user-visible sentence differs. If these ever converge, the whole
    /// point of carrying the provenance is lost.
    #[test]
    fn the_two_read_differently() {
        let inbound = attempt(AttemptOrigin::Inbound).messages.pop_back().unwrap();
        let dialled = attempt(AttemptOrigin::OutboundDial)
            .messages
            .pop_back()
            .unwrap();
        assert_ne!(
            inbound, dialled,
            "a prompt we summoned by dialling out reads identically to a peer \
             knocking — that is the #61 defect, and it is what makes a forged \
             provenance invisible"
        );
    }
}

#[cfg(test)]
mod refusal_is_not_maskable {
    //! A device that will refuse our input must not read as healthy (#92).
    //!
    //! `Pong(bool)` carries the receiver's own "is my emulation active" bit,
    //! `connect.rs` fail-closes on it before writing a frame, and both
    //! front-ends rendered `online || alive` — so a peer that connects *in*
    //! (setting `online`) masked a false `alive`, and the dot stayed green while
    //! every event sent to that machine was refused. The user's only symptom was
    //! the cursor snapping back at the edge.
    //!
    //! `online` and `alive` are facts about opposite directions. ORing them
    //! together is the defect.
    use super::*;

    /// Connected by default — the interesting new axis is what happens when we
    /// are NOT.
    fn dev(online: bool, active: bool, alive: bool) -> Device {
        dev_conn(online, active, alive, true)
    }

    fn dev_conn(online: bool, active: bool, alive: bool, connected: bool) -> Device {
        Device {
            fingerprint: Some("aa:bb".into()),
            label: "peer".into(),
            trust: TrustState::Trusted,
            online,
            send: Some(DeviceSend {
                handle: 0,
                config: ClientConfig::default(),
                state: ClientState {
                    active,
                    alive,
                    active_addr: connected.then(|| "10.0.0.5:4242".parse().unwrap()),
                    ..Default::default()
                },
            }),
            receive: true,
        }
    }

    /// The exact scenario in the issue: B's emulation died, B still dials us so
    /// `online` is true, and we are actively pushing input at it.
    #[test]
    fn an_inbound_connection_does_not_mask_a_dead_receiver() {
        assert!(
            dev(true, true, false).refuses_our_input(),
            "online must not mask a receiver that told us its emulation is off — \
             every event we send is refused before it is written"
        );
    }

    #[test]
    fn a_healthy_peer_is_not_flagged() {
        assert!(!dev(true, true, true).refuses_our_input());
    }

    /// If capture is not routed there we are not sending, so `alive` says
    /// nothing the user needs to act on. Flagging it would cry wolf on every
    /// switched-off device.
    #[test]
    fn an_inactive_device_is_not_flagged() {
        assert!(!dev(true, false, false).refuses_our_input());
    }

    /// Reported from the rig minutes after the build landed: every configured
    /// device read "not accepting input" before anything had crossed. `alive`
    /// is false until the first Pong, and stays false while OFFLINE — so a
    /// predicate that ignores whether a link exists calls "unreachable"
    /// "refusing", which is the exact conflation #92 existed to remove.
    #[test]
    fn an_offline_device_is_not_refusing_it_is_offline() {
        assert!(
            !dev_conn(false, true, false, false).refuses_our_input(),
            "a device with no live link is OFFLINE, not refusing. Those need \
             different fixes from the user: one is 'go turn hops on over there', \
             the other is 'go grant it permission'."
        );
    }

    /// And the real case still fires: link up, peer says emulation is off.
    #[test]
    fn a_connected_peer_that_says_no_is_still_flagged() {
        assert!(dev_conn(true, true, false, true).refuses_our_input());
    }

    /// A receive-only peer has no send facet and therefore nothing to refuse.
    #[test]
    fn a_receive_only_peer_is_not_flagged() {
        let mut d = dev(true, true, false);
        d.send = None;
        assert!(!d.refuses_our_input());
    }
}

#[cfg(test)]
mod discovered_hostnames {
    //! A discovered device must survive its addresses changing.
    //!
    //! Jeremy's case, and the reason this matters: *"if my switch goes down, it
    //! could still connect to my wifi without having to redo the connection,
    //! which I have run into with Synergy."* hops already races every known
    //! address and keys trust on the fingerprint rather than the address, so a
    //! path change is not a new device. The remaining gap was that addresses
    //! pinned at add-time are a snapshot — a `.local` name closes it, because
    //! the resolved set is refreshed on every reconnect.
    use super::discovered_hostname;

    #[test]
    fn a_bare_mdns_label_becomes_resolvable() {
        assert_eq!(discovered_hostname("ScornMBP23"), "ScornMBP23.local");
    }

    /// Already-qualified names are left alone rather than becoming
    /// `host.local.local`, which resolves to nothing.
    #[test]
    fn an_already_qualified_name_is_untouched() {
        for n in ["ScornMBP23.local", "box.lan", "10.110.20.99"] {
            assert_eq!(discovered_hostname(n), n, "{n:?} must not be re-suffixed");
        }
    }

    #[test]
    fn whitespace_and_empty_are_handled() {
        assert_eq!(discovered_hostname("  rig  "), "rig.local");
        assert_eq!(discovered_hostname("   "), "");
    }
}

#[cfg(test)]
mod verification_code_reaches_the_prompt {
    //! The number is worthless unless it is on the screen next to the decision.
    //!
    //! `hops_ipc::pairing::verification_code` can be perfect and the ceremony
    //! still not exist — that is the shape of #92, where a correct fact was
    //! discarded at the render step. So the model-level wiring gets its own
    //! test, and the render site gets one in hops-slint.
    use super::*;

    const OURS: &str = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:\
aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99";
    const THEIRS: &str = "11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:\
11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00";

    fn model(ours: Option<&str>, pending: Option<&str>) -> AppModel {
        let mut m = AppModel::default();
        m.fingerprint = ours.map(String::from);
        m.pending_pairing = pending.map(String::from);
        m
    }

    #[test]
    fn a_pending_prompt_has_a_code() {
        let c = model(Some(OURS), Some(THEIRS))
            .pending_verification_code()
            .expect("both fingerprints known");
        assert_eq!(c.len(), 6);
    }

    /// Both machines must show the SAME digits, which is the entire ceremony.
    /// Here that means: swapping which fingerprint is "ours" changes nothing.
    #[test]
    fn the_other_machine_computes_the_same_number() {
        assert_eq!(
            model(Some(OURS), Some(THEIRS)).pending_verification_code(),
            model(Some(THEIRS), Some(OURS)).pending_verification_code(),
            "the peer's screen must show what ours does, or the user is told to \
             reject a valid pairing"
        );
    }

    /// Better nothing than a number that cannot be compared.
    #[test]
    fn no_code_until_both_ends_are_known() {
        assert!(
            model(None, Some(THEIRS))
                .pending_verification_code()
                .is_none()
        );
        assert!(
            model(Some(OURS), None)
                .pending_verification_code()
                .is_none()
        );
        assert!(
            model(Some(OURS), Some("garbage"))
                .pending_verification_code()
                .is_none()
        );
    }
}
