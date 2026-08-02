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
use tokio::sync::{mpsc, Notify};

pub use hops_ipc::{
    connect_async, ClientConfig, ClientHandle, ClientState, FrontendEvent, FrontendRequest,
    Position, Status,
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
    /// The daemon's listen port.
    pub port: Option<u16>,
    /// Recent transient events / errors (newest last), capped at [`MAX_MESSAGES`].
    pub messages: VecDeque<String>,
    /// Fingerprints of peers currently connected *in*, as known from live
    /// connect/disconnect events while this client is attached. CAVEAT: a peer
    /// that connected before we attached is not reflected until the daemon
    /// reports current connections on `Sync` (a planned additive event).
    pub connected_peers: HashSet<String>,
    /// An untrusted peer's fingerprint awaiting the user's pairing approval. Set
    /// on `ConnectionAttempt`; cleared once it becomes authorized or the daemon
    /// link drops. The UI surfaces this as an approve/deny prompt.
    pub pending_pairing: Option<String>,
    /// When `pending_pairing` was last (re)asserted by a `ConnectionAttempt`.
    /// A front-end can treat the prompt as stale (the peer gave up) once this is
    /// older than a small TTL, since the daemon emits no retraction event.
    pub pending_pairing_since: Option<Instant>,
    /// Maps a connected peer's socket address -> fingerprint, so the addr-only
    /// `IncomingDisconnected` event can be correlated back to a fingerprint.
    peer_addrs: HashMap<SocketAddr, String>,
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
                    self.connected_peers.remove(&fp);
                }
                self.push_message(format!("incoming disconnected: {addr}"));
            }
            FrontendEvent::ConnectionAttempt { fingerprint } => {
                self.push_message(format!("pairing request: {fingerprint}"));
                if !self.authorized.contains_key(&fingerprint) {
                    self.pending_pairing = Some(fingerprint);
                    self.pending_pairing_since = Some(Instant::now());
                }
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
                self.connected_peers.remove(&old);
            }
        }
        self.connected_peers.insert(fingerprint);
    }

    fn push_message(&mut self, msg: String) {
        if self.messages.len() >= MAX_MESSAGES {
            self.messages.pop_front();
        }
        self.messages.push_back(msg);
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

/// A compact, human-comparable rendering of a colon-separated fingerprint
/// (first three groups, e.g. `1e:19:1b`) for use as a fallback label.
fn short_fingerprint(fp: &str) -> String {
    fp.split(':').take(3).collect::<Vec<_>>().join(":")
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

        // 3. a bare inbound pairing request not already represented above
        if let Some(fp) = self.pending_pairing.as_deref() {
            if !self.authorized.contains_key(fp) && !is_self(fp) {
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
mod tests {
    use super::{AppModel, ClientConfig, ClientState, TrustState};

    fn client(hostname: Option<&str>, peer_fp: Option<&str>) -> (ClientConfig, ClientState) {
        let config = ClientConfig {
            hostname: hostname.map(String::from),
            ..Default::default()
        };
        let state = ClientState {
            peer_fingerprint: peer_fp.map(String::from),
            ..Default::default()
        };
        (config, state)
    }

    #[test]
    fn merges_client_and_authorized_by_fingerprint() {
        let mut m = AppModel::default();
        let fp = "aa:bb:cc:dd";
        m.clients.insert(0, client(Some("studio-mac"), Some(fp)));
        m.authorized.insert(fp.to_string(), "studio-mac".to_string());
        let devices = m.devices();
        assert_eq!(devices.len(), 1, "one machine must render as one card");
        let d = &devices[0];
        assert!(d.send.is_some(), "carries the outgoing facet");
        assert!(d.receive, "trusted to connect in");
        assert_eq!(d.trust, TrustState::Trusted);
        assert_eq!(d.fingerprint.as_deref(), Some(fp));
    }

    /// The rig case: both Mac receivers were added on Windows BY IP, so the
    /// name field holds an address. Once the fingerprint is learned the two
    /// rows must collapse into one card named by the peer, not by its IP.
    #[test]
    fn ip_named_client_merges_and_takes_the_peer_description() {
        let mut m = AppModel::default();
        let scorn = "73:90:2a:3c:9d:e5";
        let carrier = "2d:65:8f:e6:f8:2b";
        m.clients.insert(0, client(Some("10.110.20.99"), Some(scorn)));
        m.clients.insert(1, client(Some("10.110.21.46"), Some(carrier)));
        m.authorized.insert(scorn.to_string(), "ScornMBP23".to_string());
        m.authorized.insert(carrier.to_string(), "CarrierMBP".to_string());

        let devices = m.devices();
        assert_eq!(devices.len(), 2, "two machines, not four cards");
        let mut labels: Vec<&str> = devices.iter().map(|d| d.label.as_str()).collect();
        labels.sort();
        assert_eq!(labels, ["CarrierMBP", "ScornMBP23"], "named by peer, not by IP");
        for d in &devices {
            assert!(d.send.is_some(), "{} keeps its outgoing facet", d.label);
            assert!(d.receive, "{} stays trusted (revoke must render)", d.label);
        }
    }

    #[test]
    fn offline_client_and_unrelated_trust_stay_two_cards() {
        let mut m = AppModel::default();
        // an outgoing client that has never connected (no fingerprint yet)
        m.clients.insert(0, client(Some("studio-mac"), None));
        // an unrelated trusted sender (receive-only)
        m.authorized
            .insert("cc:dd:ee:ff".to_string(), "windows-box".to_string());
        let devices = m.devices();
        assert_eq!(devices.len(), 2, "no fingerprint to join on => two cards");
        assert!(devices
            .iter()
            .any(|d| d.fingerprint.is_none() && d.send.is_some()));
        assert!(devices.iter().any(|d| d.receive && d.send.is_none()));
    }

    #[test]
    fn excludes_this_device() {
        let mut m = AppModel::default();
        let me = "de:ad:be:ef";
        m.fingerprint = Some(me.to_string());
        m.authorized.insert(me.to_string(), "myself".to_string());
        assert!(m.devices().is_empty(), "never list ourselves");
    }

    #[test]
    fn bare_pairing_request_surfaces_as_pending() {
        let mut m = AppModel::default();
        let fp = "12:34:56:78";
        m.pending_pairing = Some(fp.to_string());
        let devices = m.devices();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].trust, TrustState::PendingApproval);
        assert_eq!(devices[0].fingerprint.as_deref(), Some(fp));
    }

    #[test]
    fn online_reflects_connected_peers() {
        let mut m = AppModel::default();
        let fp = "aa:bb:cc:dd";
        m.authorized.insert(fp.to_string(), "studio-mac".to_string());
        m.connected_peers.insert(fp.to_string());
        let devices = m.devices();
        assert_eq!(devices.len(), 1);
        assert!(devices[0].online);
    }
}
