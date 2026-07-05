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
