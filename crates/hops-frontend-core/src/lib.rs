//! Shared frontend core for hops UIs (Ratatui TUI + Slint GUI).
//!
//! Owns a typed, auto-reconnecting async IPC client over
//! [`hops_ipc::connect_async`], an observable [`AppModel`] reduced from the
//! daemon's [`FrontendEvent`] stream, and a change-notification so a TUI redraw
//! or a Slint property bridge can subscribe. Front-ends depend on this crate +
//! `hops-ipc`; they contain no protocol logic of their own.

use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    future::Future,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use futures::{Stream, StreamExt};
use hops_ipc::{AsyncFrontendRequestWriter, ConnectionError, IpcError};
use tokio::sync::{Notify, mpsc};

pub use hops_ipc::{
    AttemptOrigin, Build, ClientConfig, ClientHandle, ClientState, DiscoveredDevice, FrontendEvent,
    FrontendRequest, PeerTrust, Position, RevokedEntry, Status, connect_async,
};

pub mod prefs;
pub mod theme;

/// How many transient event/error lines to keep for the UI log pane.
const MAX_MESSAGES: usize = 50;

/// What the binary tells its frontend as the frontend opens.
#[derive(Debug, Clone, Default)]
pub struct Launch {
    /// This binary's own build, to compare with the daemon's. `None` compares
    /// nothing.
    pub build: Option<Build>,
    /// Why the service the app tried to start is not running, in words, with
    /// the file that says more. `None` when the app started nothing or the
    /// service came up.
    pub start_problem: Option<String>,
    /// That the app restarted a service running another build, in words, to
    /// show once as a notice. `None` when it restarted nothing.
    pub restarted: Option<String>,
    /// Why the app left a service of another build running, and what to do,
    /// shown with the mismatch in place of the general advice.
    pub left_running: Option<String>,
}

/// What the daemon on this connection said about its build.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ServiceBuild {
    /// Nothing yet on this connection.
    #[default]
    Unknown,
    /// It sent state without saying: a daemon older than the event.
    Unstated,
    /// It said which build it is.
    Is(Build),
}

/// Reduced, UI-facing snapshot of daemon state. Cloned cheaply for rendering.
#[derive(Debug, Default, Clone)]
pub struct AppModel {
    /// True while the IPC socket is connected.
    pub connected: bool,
    /// Which daemon connection this model describes, bumped each time one is
    /// lost. What a frontend keeps against a request, such as the name for a
    /// device it asked to create, belongs to the connection that took the
    /// request, and is void once that connection is gone (#34).
    pub link: u64,
    /// This binary's build, from [`Launch::build`].
    pub this_build: Option<Build>,
    /// The daemon's build, as it stated it on this connection.
    pub service_build: ServiceBuild,
    /// Why the service the app tried to start did not come up, from
    /// [`Launch::start_problem`]. Cleared once a daemon answers.
    pub start_problem: Option<String>,
    /// Why the app left a service of another build running, from
    /// [`Launch::left_running`].
    pub left_running: Option<String>,
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
    /// What the trust store grants each paired machine, by fingerprint. Read
    /// through [`AppModel::clipboard`]. Empty from a daemon older than
    /// `FrontendEvent::TrustUpdated`.
    pub trust: HashMap<String, PeerTrust>,
    /// The daemon's listen port.
    pub port: Option<u16>,
    /// Until when pairing prompts may appear on this machine, or `None` while
    /// the window is closed (#195).
    pub pairing_open_until: Option<Instant>,
    /// The activity log: recent events and errors alike (newest last), capped
    /// at [`MAX_MESSAGES`].
    pub messages: VecDeque<String>,
    /// Monotonic counter, bumped on every activity-log line.
    pub message_seq: u64,
    /// The latest thing that went wrong, or `None`.
    ///
    /// Kept apart from [`Self::messages`], which also records routine events
    /// such as a cursor entering. The GUI's error banner rendered the log's
    /// last line, so the most routine thing hops does appeared in red beside
    /// a dismiss button, and an error surface that cries wolf stops being
    /// read (#150).
    pub latest_error: Option<String>,
    /// Bumped on every error. Lets a polling frontend tell a NEW error from
    /// the same one still on screen, so a dismissed banner stays dismissed
    /// but a repeat of the same failure re-raises it.
    pub error_seq: u64,
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
    /// Every machine awaiting an answer, oldest first. `pending_pairing` is
    /// only the latest; the prompt is chosen from this, through
    /// [`PairingCard`], so another machine's request cannot replace the one on
    /// screen (#168).
    pub pairing_attempts: Vec<PairingAttempt>,
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
            FrontendEvent::DaemonBuild(build) => self.service_build = ServiceBuild::Is(build),
            FrontendEvent::Enumerate(list) => {
                // A daemon states its build before its state on every sync,
                // so state with nothing stated first is from one that never
                // does. A statement that arrives later still replaces this.
                if self.service_build == ServiceBuild::Unknown {
                    self.service_build = ServiceBuild::Unstated;
                }
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
            FrontendEvent::TrustUpdated(map) => self.trust = map,
            FrontendEvent::AuthorizedUpdated(map) => {
                self.authorized = map;
                let attempts = std::mem::take(&mut self.pairing_attempts);
                self.pairing_attempts = attempts
                    .into_iter()
                    .filter(|a| !self.arrival_permitted(&a.fingerprint, Some(a.origin)))
                    .collect();
                // a pending request whose direction just became permitted is
                // resolved
                if let Some(fp) = self.pending_pairing.clone() {
                    if self.arrival_permitted(&fp, self.pending_pairing_origin) {
                        self.pending_pairing = None;
                        self.pending_pairing_since = None;
                    }
                }
            }
            FrontendEvent::PortChanged(port, err) => {
                self.port = Some(port);
                if let Some(e) = err {
                    self.push_error(format!("port change failed: {e}"));
                }
            }
            FrontendEvent::Error(e) => self.push_error(e),
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
                    AttemptOrigin::Inbound => match addr {
                        Some(a) => format!("pairing request from {a}: {fingerprint}"),
                        None => format!("pairing request: {fingerprint}"),
                    },
                    AttemptOrigin::OutboundDial => match addr {
                        Some(a) => format!("{a} answered our dial, untrusted: {fingerprint}"),
                        None => format!("we dialled an untrusted receiver: {fingerprint}"),
                    },
                });
                if !self.arrival_permitted(&fingerprint, Some(origin)) {
                    let now = Instant::now();
                    self.note_attempt(PairingAttempt {
                        fingerprint: fingerprint.clone(),
                        origin,
                        addr,
                        since: now,
                    });
                    self.pending_pairing = Some(fingerprint);
                    self.pending_pairing_origin = Some(origin);
                    self.pending_pairing_addr = addr;
                    self.pending_pairing_since = Some(now);
                }
            }
            FrontendEvent::Discovered { active, peers } => {
                self.discovery_active = active;
                self.discovered = peers;
            }
            FrontendEvent::PairingOpen { seconds } => {
                self.pairing_open_until = (seconds > 0)
                    .then(|| Instant::now() + std::time::Duration::from_secs(seconds.into()));
            }
            FrontendEvent::NoSuchClient(_) => {}
        }
    }

    /// The pairing request to put in front of the user: the pending attempt,
    /// unless the direction it arrived in is already permitted. Freshness and
    /// the user's snooze are the front-end's.
    pub fn pairing_request(&self) -> Option<&str> {
        let fp = self.pending_pairing.as_deref()?;
        (!self.arrival_permitted(fp, self.pending_pairing_origin)).then_some(fp)
    }

    /// Is what an attempt from `fp`, arriving by `origin`, asks for already
    /// permitted?
    ///
    /// A peer that may drive this machine can still ask to be driven by it:
    /// one approval grants one direction, and a pair that works both ways is
    /// approved twice (#166). So being in `authorized` answers only the
    /// inbound question. Nothing here says whether this machine may drive a
    /// peer, and the daemon raises an attempt from its own dial only after its
    /// trust store said it may not, so that attempt is never already answered.
    fn arrival_permitted(&self, fp: &str, origin: Option<AttemptOrigin>) -> bool {
        match origin {
            Some(AttemptOrigin::OutboundDial) => false,
            Some(AttemptOrigin::Inbound) | None => self.authorized.contains_key(fp),
        }
    }

    /// The pin of device `handle` as this model has it: the fingerprint a
    /// delete or rename of it must carry (`None` if it has none, or no such
    /// device).
    pub fn pin_of(&self, handle: ClientHandle) -> Option<String> {
        self.clients
            .get(&handle)
            .and_then(|(_, s)| s.peer_fingerprint.clone())
    }

    /// Whether device `handle` is still here and still pinned to `pin`, as it
    /// was when a frontend armed a delete or opened a rename on it.
    ///
    /// A frontend drops an armed action once this is false. The daemon would
    /// refuse it anyway, but only after the user confirmed something the row
    /// no longer shows (#94).
    pub fn still_names(&self, handle: ClientHandle, pin: Option<&str>) -> bool {
        self.clients
            .get(&handle)
            .is_some_and(|(_, s)| s.peer_fingerprint.as_deref() == pin)
    }

    /// Add an attempt, or refresh the one already held for that machine in
    /// place, keeping its position in the queue.
    fn note_attempt(&mut self, attempt: PairingAttempt) {
        if let Some(held) = self
            .pairing_attempts
            .iter_mut()
            .find(|a| a.fingerprint == attempt.fingerprint)
        {
            *held = attempt;
            return;
        }
        // Anyone who can reach the daemon while add device is open can add
        // one, so the queue is bounded.
        if self.pairing_attempts.len() >= MAX_PAIRING_ATTEMPTS {
            self.pairing_attempts.remove(0);
        }
        self.pairing_attempts.push(attempt);
    }

    /// What is wrong with the service this app talks to, in words, or `None`.
    ///
    /// While nothing is connected: why the service the app started did not
    /// come up. Once connected: that the daemon runs another build than this
    /// app, which it keeps doing until it restarts.
    pub fn service_problem(&self) -> Option<String> {
        if !self.connected {
            return self.start_problem.clone();
        }
        let this = self.this_build.as_ref()?;
        let theirs = match &self.service_build {
            ServiceBuild::Unknown => return None,
            ServiceBuild::Is(build) if build == this => return None,
            ServiceBuild::Is(build) => format!("hops {build}"),
            ServiceBuild::Unstated => "an older build that does not say which".to_string(),
        };
        let advice = match &self.left_running {
            Some(why) => why.clone(),
            None => {
                let restart = if cfg!(target_os = "linux") {
                    "restart the computer"
                } else {
                    "log out and back in"
                };
                format!(
                    "The service keeps running its own version until it restarts: \
                     {restart} to run this one."
                )
            }
        };
        Some(format!(
            "This app is hops {this}, but the service it is connected to is {theirs}. \
             {advice}"
        ))
    }

    /// The model a frontend opens with: this build, and what the front door
    /// found. A service it restarted is told as a notice.
    pub fn launched(launch: Launch) -> Self {
        let mut model = AppModel {
            this_build: launch.build,
            start_problem: launch.start_problem,
            left_running: launch.left_running,
            ..AppModel::default()
        };
        if let Some(restarted) = launch.restarted {
            model.push_message(restarted);
        }
        model
    }

    /// Whole seconds left in the pairing window, or `None` when it is closed.
    pub fn pairing_seconds_left(&self, now: Instant) -> Option<u64> {
        let left = self.pairing_open_until?.checked_duration_since(now)?;
        // Rounded up, so the countdown reads 2:00 when it opens and never 0:00
        // while prompts are still allowed.
        Some(left.as_secs() + u64::from(left.subsec_nanos() > 0)).filter(|&s| s > 0)
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

    /// Record an error: in the activity log, and as the latest error.
    fn push_error(&mut self, error: String) {
        self.push_message(format!("error: {error}"));
        self.latest_error = Some(error);
        self.error_seq += 1;
    }

    /// The daemon connection is gone: drop every fact only a running daemon
    /// can vouch for, so nothing renders live while nothing is (#34). What
    /// the user configured stays, to be shown as it was last known.
    ///
    /// The connection loop calls this on the shared model; public so a
    /// frontend's tests can reach the state it leaves without a socket.
    pub fn daemon_gone(&mut self) {
        self.connected = false;
        self.link = self.link.wrapping_add(1);
        self.connected_peers.clear();
        self.peer_addrs.clear();
        self.pending_pairing = None;
        self.pending_pairing_origin = None;
        self.pending_pairing_addr = None;
        self.pending_pairing_since = None;
        self.pairing_attempts.clear();
        self.pairing_open_until = None;
        self.discovered.clear();
        self.discovery_active = false;
        self.capture = Status::Disabled;
        self.emulation = Status::Disabled;
        for (_, state) in self.clients.values_mut() {
            state.active_addr = None;
            state.alive = false;
            state.peer_commit = None;
            state.peer_caps = None;
            state.resolving = false;
            state.has_pressed_keys = false;
        }
    }

    /// The activity log's latest line, if any: an event or an error.
    pub fn latest_message(&self) -> Option<&str> {
        self.messages.back().map(|s| s.as_str())
    }

    /// The latest error, if any. The daemon's only channel for telling the
    /// user something went wrong; before this was rendered, every failure —
    /// unresolvable name, refused trust change, failed config write, rejected
    /// IPC token — reached the user as silence.
    pub fn latest_error(&self) -> Option<&str> {
        self.latest_error.as_deref()
    }
}

/// How many machines awaiting an answer the model holds at once.
const MAX_PAIRING_ATTEMPTS: usize = 16;

/// A machine waiting for an answer to a pairing prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingAttempt {
    pub fingerprint: String,
    /// Whether it knocked or we dialled it (#61).
    pub origin: AttemptOrigin,
    /// Where it came from, or the address that answered our dial (#83, #93).
    pub addr: Option<SocketAddr>,
    /// When the daemon last reported it.
    pub since: Instant,
}

/// Why an approval was not sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalRefused {
    /// The fingerprint is not the one on the card.
    NotOnScreen,
    /// The card switched to this machine too recently for the click to have
    /// been meant for it.
    JustChanged,
}

impl ApprovalRefused {
    /// What to tell the person who clicked.
    pub fn notice(self) -> &'static str {
        match self {
            ApprovalRefused::NotOnScreen => {
                "That pairing request is no longer on screen, so nothing was trusted."
            }
            ApprovalRefused::JustChanged => {
                "The pairing request changed just before you approved it, so nothing \
                 was trusted. Check which device it is now, then approve again."
            }
        }
    }
}

/// Which pairing request the prompt shows, and whether an approval of it
/// counts (#168).
///
/// The prompt used to show whichever machine asked last, so a second machine
/// dialling while someone read the card, or typed a name into it, replaced the
/// machine under the click: approving then trusted the second machine under
/// the name meant for the first. A card now keeps its machine for as long as
/// that machine's request is live, and a click is refused unless the card has
/// shown that machine for at least [`Self::ARM_AFTER`], so a click aimed at
/// the card before it changed does not land on the one after.
#[derive(Debug, Default)]
pub struct PairingCard {
    shown: Option<(String, Instant)>,
}

impl PairingCard {
    /// A request nobody has repeated for this long is taken as abandoned: the
    /// daemon sends no retraction.
    pub const STALE_AFTER: Duration = Duration::from_secs(12);

    /// How long a card must have shown a machine before approving it counts.
    pub const ARM_AFTER: Duration = Duration::from_secs(1);

    /// The request to show at `now`: the one already on screen while it is
    /// still live, otherwise the oldest live one. Live means the direction it
    /// asks for is not yet permitted (#166), repeated within
    /// [`Self::STALE_AFTER`], and not `snoozed` (denied).
    pub fn show<'m>(
        &mut self,
        model: &'m AppModel,
        now: Instant,
        snoozed: impl Fn(&str) -> bool,
    ) -> Option<&'m PairingAttempt> {
        let live = |a: &&PairingAttempt| {
            !model.arrival_permitted(&a.fingerprint, Some(a.origin))
                && now.saturating_duration_since(a.since) < Self::STALE_AFTER
                && !snoozed(&a.fingerprint)
        };
        let on_screen = self.shown.as_ref().map(|(fp, _)| fp.as_str());
        let pick = model
            .pairing_attempts
            .iter()
            .filter(live)
            .find(|a| Some(a.fingerprint.as_str()) == on_screen)
            .or_else(|| model.pairing_attempts.iter().find(live));
        match pick {
            Some(a) if Some(a.fingerprint.as_str()) != on_screen => {
                self.shown = Some((a.fingerprint.clone(), now));
            }
            Some(_) => {}
            None => self.shown = None,
        }
        pick
    }

    /// Whether approving `fingerprint` at `now` binds to the card on screen.
    pub fn approve(&self, fingerprint: &str, now: Instant) -> Result<(), ApprovalRefused> {
        match &self.shown {
            Some((fp, since)) if fp == fingerprint => {
                if now.saturating_duration_since(*since) >= Self::ARM_AFTER {
                    Ok(())
                } else {
                    Err(ApprovalRefused::JustChanged)
                }
            }
            _ => Err(ApprovalRefused::NotOnScreen),
        }
    }
}

/// This machine's clipboard with one paired device (#182).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Clipboard {
    /// Neither way. There is no way to turn it on from a frontend yet.
    Off,
    /// That device's clipboard arrives here, and nothing goes back.
    FromIt,
    /// This machine's clipboard goes there, and nothing comes back.
    ToIt,
    /// Both ways.
    BothWays,
}

impl Clipboard {
    /// A direction is on, so the off switch has something to turn off.
    pub fn is_on(self) -> bool {
        self != Clipboard::Off
    }

    /// Short words for a device row, the same in every frontend.
    pub fn describe(self) -> &'static str {
        match self {
            Clipboard::Off => "clipboard off",
            Clipboard::FromIt => "clipboard from it",
            Clipboard::ToIt => "clipboard to it",
            Clipboard::BothWays => "clipboard both ways",
        }
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

/// The hostname to store for a machine picked off the network list.
///
/// mDNS advertises a host as `<instance>.local.`, and a bare `desk-mac` does
/// not resolve while `desk-mac.local` does — through the OS name stack
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
    /// The clipboard with the paired device whose fingerprint is `fp`, or
    /// `None` when no pairing holds one, so there is nothing to show or to
    /// switch off.
    pub fn clipboard(&self, fp: &str) -> Option<Clipboard> {
        self.trust
            .get(fp)
            .map(|t| match (t.clipboard_from, t.clipboard_to) {
                (false, false) => Clipboard::Off,
                (true, false) => Clipboard::FromIt,
                (false, true) => Clipboard::ToIt,
                (true, true) => Clipboard::BothWays,
            })
    }

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

/// What a request made while no daemon is connected is answered with.
pub const NOT_CONNECTED: &str = "Not done: no connection to the hops service, so nothing changed.";

impl FrontendClient {
    /// Spawn the auto-reconnecting connection task and return a handle. Must be
    /// called within a tokio `LocalSet` (it uses `spawn_local`).
    pub fn spawn(launch: Launch) -> Self {
        let model = Arc::new(Mutex::new(AppModel::launched(launch)));
        let changed = Arc::new(Notify::new());
        let (requests, request_rx) = mpsc::unbounded_channel();
        tokio::task::spawn_local(connection_loop(
            model.clone(),
            changed.clone(),
            request_rx,
            || connect_async(None),
        ));
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

    /// Send a request to the daemon. Returns whether it was handed to a
    /// connected daemon.
    ///
    /// While no daemon is connected the request is dropped, and the model
    /// records [`NOT_CONNECTED`] as an error. It used to wait in the queue
    /// and replay into whichever daemon answered next, however much later
    /// and against whatever the device list had become (#34).
    pub fn request(&self, request: FrontendRequest) -> bool {
        self.request_on(request).is_some()
    }

    /// [`Self::request`], saying which connection took it: the
    /// [`AppModel::link`] it was queued on, or `None` when it was refused.
    pub fn request_on(&self, request: FrontendRequest) -> Option<u64> {
        // Under the model lock, which the connection loop also holds while it
        // marks the daemon gone and empties the queue, so a request is either
        // queued for a live connection or refused here, never left behind.
        let mut model = self.model.lock().expect("model lock poisoned");
        if model.connected && self.requests.send(request).is_ok() {
            return Some(model.link);
        }
        model.push_error(NOT_CONNECTED.to_string());
        drop(model);
        self.changed.notify_one();
        None
    }
}

/// Where the connection loop writes requests: the daemon's socket, or a test
/// double.
trait RequestSink {
    async fn send(&mut self, request: FrontendRequest) -> Result<(), IpcError>;
}

impl RequestSink for AsyncFrontendRequestWriter {
    async fn send(&mut self, request: FrontendRequest) -> Result<(), IpcError> {
        self.request(request).await
    }
}

/// Connect, sync, fold events into the model, forward requests; reconnect on
/// drop. `connect` waits for a daemon and opens a connection to it.
async fn connection_loop<C, F, E, W>(
    model: Arc<Mutex<AppModel>>,
    changed: Arc<Notify>,
    mut request_rx: mpsc::UnboundedReceiver<FrontendRequest>,
    mut connect: C,
) where
    C: FnMut() -> F,
    F: Future<Output = Result<(E, W), ConnectionError>>,
    E: Stream<Item = Result<FrontendEvent, IpcError>> + Unpin,
    W: RequestSink,
{
    loop {
        let (mut events, mut writer) = match connect().await {
            Ok(conn) => conn,
            Err(e) => {
                log::warn!("frontend: could not connect to daemon: {e}");
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
        };
        {
            let mut m = model.lock().expect("model lock poisoned");
            m.connected = true;
            // A daemon answers, so a failed start no longer describes it; and
            // it may be another build than the last one.
            m.start_problem = None;
            m.service_build = ServiceBuild::Unknown;
        }
        changed.notify_one();
        // pull full initial state
        let _ = writer.send(FrontendRequest::Sync).await;

        // Requests taken from the queue that did not reach the daemon.
        let lost = loop {
            tokio::select! {
                event = events.next() => match event {
                    Some(Ok(event)) => {
                        model.lock().expect("model lock poisoned").apply(event);
                        changed.notify_one();
                    }
                    // forward-compat: skip an event line we can't decode, keep the connection
                    Some(Err(IpcError::Json(e))) => {
                        log::debug!("frontend: skipping undecodable event: {e}");
                    }
                    // EOF or io error -> reconnect
                    _ => break 0,
                },
                request = request_rx.recv() => match request {
                    Some(request) => {
                        if let Err(e) = writer.send(request).await {
                            log::warn!("frontend: request failed: {e}");
                            break 1;
                        }
                    }
                    None => return, // the FrontendClient was dropped
                },
            }
        };

        {
            let mut m = model.lock().expect("model lock poisoned");
            m.daemon_gone();
            // What was queued for this daemon is not replayed into the next
            // one: by then the user has seen the list go stale, and a delete
            // or a trust change must not land minutes later unannounced.
            let mut dropped = lost;
            while request_rx.try_recv().is_ok() {
                dropped += 1;
            }
            // Said as a lost connection, not a stopped service: the daemon
            // also closes the connection of a frontend that stopped reading,
            // and keeps running (#95).
            if dropped > 0 {
                log::warn!(
                    "frontend: the daemon connection closed with {dropped} request(s) not sent"
                );
                m.push_error(format!(
                    "The connection to the hops service was lost before {} reached it, so {} not made.",
                    if dropped == 1 {
                        "your last change".to_string()
                    } else {
                        format!("your last {dropped} changes")
                    },
                    if dropped == 1 { "it was" } else { "they were" },
                ));
            }
        }
        changed.notify_one();
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[cfg(test)]
mod armed_actions {
    //! A frontend arms a delete or opens a rename on a row, and the user
    //! confirms later. By then the device can be gone, replaced by a reload,
    //! or pinned to another machine; the armed action must not survive that.

    use super::*;

    fn pinned(fp: Option<&str>) -> (ClientConfig, ClientState) {
        let state = ClientState {
            peer_fingerprint: fp.map(str::to_string),
            ..Default::default()
        };
        (ClientConfig::default(), state)
    }

    // LEDGER T14 | class B | 1 return value: AppModel::still_names after AppModel::apply
    #[test]
    fn an_armed_action_outlives_nothing_about_its_device() {
        let x = "aa:".repeat(31) + "aa";
        let y = "bb:".repeat(31) + "bb";
        let mut m = AppModel::default();
        let (c, s) = pinned(Some(&x));
        m.apply(FrontendEvent::Created(7, c, s));
        assert!(
            m.still_names(7, Some(&x)),
            "unchanged: still the device shown"
        );

        // The device learns another identity.
        let (c, s) = pinned(Some(&y));
        m.apply(FrontendEvent::State(7, c, s));
        assert!(
            !m.still_names(7, Some(&x)),
            "the device is now pinned to another machine, and a delete armed on \
             the old one would revoke this one"
        );

        // Or it is replaced by a reload: removed, and another added.
        let (c, s) = pinned(Some(&x));
        m.apply(FrontendEvent::Enumerate(vec![(8, c, s)]));
        assert!(
            !m.still_names(7, Some(&x)),
            "the device is gone; an action armed on it must go with it"
        );
        assert_eq!(m.pin_of(8), Some(x), "the pin a request for 8 carries");
    }
}

#[cfg(test)]
mod pairing_card {
    //! The approval a person gives binds to the machine the card showed them
    //! (#168).
    use super::{
        AppModel, ApprovalRefused, AttemptOrigin, FrontendEvent, PairingAttempt, PairingCard,
    };
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    const B: &str = "bb:bb:bb";
    const C: &str = "cc:cc:cc";

    fn knock(m: &mut AppModel, fp: &str) {
        m.apply(FrontendEvent::ConnectionAttempt {
            fingerprint: fp.into(),
            origin: AttemptOrigin::Inbound,
            addr: None,
        });
    }

    fn attempt(fp: &str, since: Instant) -> PairingAttempt {
        PairingAttempt {
            fingerprint: fp.into(),
            origin: AttemptOrigin::Inbound,
            addr: None,
            since,
        }
    }

    /// The #168 repro: B's card is on screen, C dials before the click.
    // LEDGER T9 | class B | 1 return value: PairingCard::show over AppModel::apply
    #[test]
    fn a_card_on_screen_keeps_its_machine_when_another_knocks() {
        let mut m = AppModel::default();
        let mut card = PairingCard::default();
        knock(&mut m, B);
        let now = Instant::now();
        assert_eq!(
            card.show(&m, now, |_| false)
                .map(|a| a.fingerprint.as_str()),
            Some(B)
        );
        knock(&mut m, C);
        assert_eq!(
            card.show(&m, now, |_| false)
                .map(|a| a.fingerprint.as_str()),
            Some(B),
            "a second machine's knock replaced the machine on the card"
        );
        assert_eq!(card.approve(B, now + PairingCard::ARM_AFTER), Ok(()));
        assert_eq!(
            card.approve(C, now + PairingCard::ARM_AFTER),
            Err(ApprovalRefused::NotOnScreen),
            "a machine that is not on the card was approved"
        );
        // Once B is answered, C's request is next.
        m.apply(FrontendEvent::AuthorizedUpdated(HashMap::from([(
            B.to_string(),
            "laptop".to_string(),
        )])));
        assert_eq!(
            card.show(&m, now, |_| false)
                .map(|a| a.fingerprint.as_str()),
            Some(C),
            "the waiting machine was lost when the first was answered"
        );
    }

    /// When the card does change machine, a click that lands in the next
    /// moment was aimed at the card before it.
    // LEDGER T10 | class B | 1 return value: PairingCard::approve
    #[test]
    fn an_approval_right_after_the_card_changed_machine_is_refused() {
        let mut m = AppModel::default();
        let mut card = PairingCard::default();
        let t0 = Instant::now();
        m.pairing_attempts = vec![attempt(B, t0)];
        card.show(&m, t0, |_| false);
        // B stops asking; C, which asked later, is still live.
        let t1 = t0 + PairingCard::STALE_AFTER + Duration::from_secs(1);
        m.pairing_attempts.push(attempt(C, t1));
        assert_eq!(
            card.show(&m, t1, |_| false).map(|a| a.fingerprint.as_str()),
            Some(C)
        );
        assert_eq!(
            card.approve(C, t1 + Duration::from_millis(200)),
            Err(ApprovalRefused::JustChanged),
            "a click 200 ms after the card switched machine was taken as approving \
             the new one"
        );
        assert_eq!(
            card.approve(B, t1 + PairingCard::ARM_AFTER),
            Err(ApprovalRefused::NotOnScreen),
            "the machine that left the card was approved"
        );
        assert_eq!(card.approve(C, t1 + PairingCard::ARM_AFTER), Ok(()));
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
    //! The case that motivates it: a machine whose wired link drops and comes
    //! back on wi-fi should still be the same device, not a new one to pair
    //! again — a failure people hit on comparable tools. hops races every known
    //! address and keys trust on the fingerprint rather than the address, so a
    //! path change is not a new device. The remaining gap was that addresses
    //! pinned at add-time are a snapshot — a `.local` name closes it, because
    //! the resolved set is refreshed on every reconnect.
    use super::discovered_hostname;

    #[test]
    fn a_bare_mdns_label_becomes_resolvable() {
        assert_eq!(discovered_hostname("desk-mac"), "desk-mac.local");
    }

    /// Already-qualified names are left alone rather than becoming
    /// `host.local.local`, which resolves to nothing.
    #[test]
    fn an_already_qualified_name_is_untouched() {
        for n in ["desk-mac.local", "box.lan", "192.0.2.99"] {
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
mod pairing_window {
    //! The daemon says how long pairing prompts may appear here; zero closes
    //! the window (#195).
    use super::*;

    #[test]
    fn the_pairing_window_follows_the_daemon() {
        let mut m = AppModel::default();
        assert_eq!(m.pairing_seconds_left(Instant::now()), None);
        m.apply(FrontendEvent::PairingOpen { seconds: 120 });
        let left = m.pairing_seconds_left(Instant::now()).expect("open");
        assert!((119..=120).contains(&left), "{left} s left, expected 120");
        m.apply(FrontendEvent::PairingOpen { seconds: 0 });
        assert_eq!(
            m.pairing_seconds_left(Instant::now()),
            None,
            "the daemon closed the window and the model kept it open"
        );
    }
}

#[cfg(test)]
mod second_direction {
    //! A machine already paired one way is asked about the other (#166). One
    //! approval grants one direction, so the card for the second one has to
    //! reach the user even though the peer is already in `authorized`.
    use super::*;

    const PEER: &str = "aa:bb";

    /// PEER may drive this machine, and this machine's dial just reached it.
    fn driven_by_peer_then_dialled_it() -> AppModel {
        let mut m = AppModel::default();
        m.apply(FrontendEvent::AuthorizedUpdated(HashMap::from([(
            PEER.to_owned(),
            "desk mac".to_owned(),
        )])));
        m.apply(FrontendEvent::ConnectionAttempt {
            fingerprint: PEER.into(),
            origin: AttemptOrigin::OutboundDial,
            addr: Some("10.0.0.5:4242".parse().expect("addr")),
        });
        m
    }

    // LEDGER T5 | class B | 6 struct state + 1 return value: AppModel::apply, AppModel::pairing_request
    #[test]
    fn a_second_direction_raises_a_card_for_an_authorized_peer() {
        let m = driven_by_peer_then_dialled_it();
        assert_eq!(
            m.pairing_request(),
            Some(PEER),
            "a peer that may drive this machine answered this machine's dial, \
             and no card asks whether this machine may drive it; pending {:?}",
            m.pending_pairing
        );
    }

    // LEDGER T6 | class B | 6 struct state + 1 return value: AppModel::apply, AppModel::pairing_request
    #[test]
    fn a_trust_update_does_not_retire_a_card_for_the_other_direction() {
        let mut m = driven_by_peer_then_dialled_it();
        m.apply(FrontendEvent::AuthorizedUpdated(HashMap::from([
            (PEER.to_owned(), "desk mac".to_owned()),
            ("cc:dd".to_owned(), "another machine".to_owned()),
        ])));
        assert_eq!(
            m.pairing_request(),
            Some(PEER),
            "a change to who may drive this machine withdrew the card asking \
             whether this machine may drive PEER"
        );
    }

    /// The same, through the queue the frontends render from (#168): the
    /// card is picked from `pairing_attempts`, so the update must not drop
    /// the other direction's attempt from it either.
    // LEDGER T6b | class B | 1 return value: AppModel::apply, PairingCard::show
    #[test]
    fn a_trust_update_keeps_the_other_direction_on_the_card() {
        let mut m = driven_by_peer_then_dialled_it();
        m.apply(FrontendEvent::AuthorizedUpdated(HashMap::from([
            (PEER.to_owned(), "desk mac".to_owned()),
            ("cc:dd".to_owned(), "another machine".to_owned()),
        ])));
        assert_eq!(
            PairingCard::default()
                .show(&m, Instant::now(), |_| false)
                .map(|a| a.fingerprint.as_str()),
            Some(PEER),
            "a change to who may drive this machine took the card asking \
             whether this machine may drive PEER off the screen"
        );
    }

    // LEDGER T7 | class B | 6 struct state + 1 return value: AppModel::apply, AppModel::pairing_request
    #[test]
    fn a_knock_from_a_peer_that_may_already_drive_us_raises_no_card() {
        let mut m = AppModel::default();
        m.apply(FrontendEvent::AuthorizedUpdated(HashMap::from([(
            PEER.to_owned(),
            "desk mac".to_owned(),
        )])));
        m.apply(FrontendEvent::ConnectionAttempt {
            fingerprint: PEER.into(),
            origin: AttemptOrigin::Inbound,
            addr: None,
        });
        assert_eq!(
            m.pairing_request(),
            None,
            "a card asks to let PEER drive this machine, which it already may"
        );
    }
}

#[cfg(test)]
mod a_closed_link_shows_down {
    //! What the daemon sends when a link closes has to take the device out of
    //! "connected" and "refusing" in the model the frontends render (#34).
    use super::*;

    const FP: &str = "aa:bb";

    fn device(m: &AppModel) -> Device {
        m.devices()
            .into_iter()
            .find(|d| d.fingerprint.as_deref() == Some(FP))
            .expect("the device is listed")
    }

    // LEDGER T68 | class B | 6 struct state: AppModel::apply + AppModel::devices()
    #[test]
    fn a_closed_link_takes_the_device_out_of_connected_and_refusing() {
        let addr: std::net::SocketAddr = "10.0.0.5:51000".parse().unwrap();
        let mut m = AppModel::default();
        m.apply(FrontendEvent::AuthorizedUpdated(HashMap::from([(
            FP.to_string(),
            "peer".to_string(),
        )])));
        m.apply(FrontendEvent::DeviceConnected {
            addr,
            fingerprint: FP.into(),
        });
        let refusing = ClientState {
            active: true,
            alive: false,
            active_addr: Some("10.0.0.5:4242".parse().unwrap()),
            peer_fingerprint: Some(FP.into()),
            ..Default::default()
        };
        m.apply(FrontendEvent::State(
            0,
            ClientConfig::default(),
            refusing.clone(),
        ));
        assert!(
            device(&m).online && device(&m).refuses_our_input(),
            "precondition: connected in, and refusing our input"
        );

        m.apply(FrontendEvent::IncomingDisconnected(addr));
        m.apply(FrontendEvent::State(
            0,
            ClientConfig::default(),
            ClientState {
                active_addr: None,
                ..refusing
            },
        ));

        let d = device(&m);
        assert!(
            !d.online,
            "the inbound link closed and the device still shows connected"
        );
        assert!(
            !d.refuses_our_input(),
            "the outbound link closed and the device still shows as up and refusing"
        );
    }
}

#[cfg(test)]
mod the_service_problem {
    //! What the app says about the service it talks to: a start that did not
    //! come up (#189), or a daemon of another build left running across an
    //! update.
    use super::*;

    fn build(version: &str, commit: &str) -> Build {
        Build {
            version: version.into(),
            commit: commit.into(),
        }
    }

    /// Connected, as this build, with the daemon's state still to come.
    fn attached() -> AppModel {
        AppModel {
            connected: true,
            this_build: Some(build("0.13.0", "abcd1234")),
            ..AppModel::default()
        }
    }

    // LEDGER T60 | class B | 6 struct state after AppModel::apply
    #[test]
    fn a_daemon_of_another_build_or_one_that_never_says_is_named() {
        let mut same = attached();
        same.apply(FrontendEvent::DaemonBuild(build("0.13.0", "abcd1234")));
        same.apply(FrontendEvent::Enumerate(vec![]));
        assert_eq!(same.service_problem(), None, "{:?}", same.service_build);

        let mut other = attached();
        other.apply(FrontendEvent::DaemonBuild(build("0.13.0", "ffff0000")));
        other.apply(FrontendEvent::Enumerate(vec![]));
        let said = other.service_problem().unwrap_or_default();
        assert!(
            said.contains("0.13.0 (abcd1234)") && said.contains("0.13.0 (ffff0000)"),
            "a daemon built from another commit was not named: {said:?}"
        );

        // A v0.12 daemon sends its state and never its build.
        let mut older = attached();
        older.apply(FrontendEvent::PortChanged(4242, None));
        assert_eq!(older.service_problem(), None, "nothing is known yet");
        older.apply(FrontendEvent::Enumerate(vec![]));
        let said = older.service_problem().unwrap_or_default();
        assert!(
            said.contains("older build"),
            "state with no build before it is from a daemon that predates the \
             statement, and the app said {said:?}"
        );

        // A state broadcast can reach a frontend before its own sync does;
        // the statement that follows still counts.
        older.apply(FrontendEvent::DaemonBuild(build("0.13.0", "abcd1234")));
        assert_eq!(older.service_problem(), None);
    }

    // LEDGER T61 | class B | 6 struct state
    #[test]
    fn a_failed_start_shows_until_a_daemon_answers() {
        let mut model = AppModel {
            start_problem: Some("The hops service started and stopped again.".into()),
            this_build: Some(build("0.13.0", "abcd1234")),
            ..AppModel::default()
        };
        assert_eq!(
            model.service_problem().as_deref(),
            Some("The hops service started and stopped again."),
            "the app would read \"connecting\" with nothing said"
        );
        // What the connection loop does once a daemon answers.
        model.connected = true;
        model.start_problem = None;
        model.apply(FrontendEvent::DaemonBuild(build("0.13.0", "abcd1234")));
        assert_eq!(model.service_problem(), None);
    }

    /// What the front door did about a service of another build reaches the
    /// screen (#222): a restart as a notice, and a service it left running
    /// with the reason in place of the general advice.
    // LEDGER T2230 | class B | 6 struct state after AppModel::launched and apply
    #[test]
    fn what_the_front_door_did_about_another_build_is_what_the_app_says() {
        let restarted = AppModel::launched(Launch {
            build: Some(build("0.13.0", "abcd1234")),
            restarted: Some(
                "hops restarted its service because it was running hops 0.12.0.".into(),
            ),
            ..Launch::default()
        });
        assert_eq!(
            restarted.latest_message(),
            Some("hops restarted its service because it was running hops 0.12.0."),
            "the app restarted the service and said nothing about it"
        );

        let why = "hops did not restart it, because it was started from a terminal. \
                   Stop it, then open hops again.";
        let mut left = AppModel::launched(Launch {
            build: Some(build("0.13.0", "abcd1234")),
            left_running: Some(why.into()),
            ..Launch::default()
        });
        left.connected = true;
        left.apply(FrontendEvent::DaemonBuild(build("0.12.0", "11111111")));
        let said = left.service_problem().unwrap_or_default();
        assert!(
            said.contains("0.12.0 (11111111)") && said.ends_with(why) && !said.contains("log out"),
            "the app left a daemon of another build running and must say why, not \
             tell the user to log out: {said:?}"
        );
        // Once the daemon is this build, nothing is said.
        left.apply(FrontendEvent::DaemonBuild(build("0.13.0", "abcd1234")));
        assert_eq!(left.service_problem(), None);
    }
}

#[cfg(test)]
mod projection {
    //! One card per physical peer, joined on the fingerprint across the
    //! outgoing clients and the trust tables, which is the projection both
    //! front-ends render.
    use super::{AppModel, ClientConfig, ClientState, FrontendEvent, TrustState, fallback_label};

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

    fn revoked(label: &str) -> super::RevokedEntry {
        super::RevokedEntry {
            label: label.to_string(),
            revoked_at: 1_754_000_000,
        }
    }

    // LEDGER T501 | class B | 6 struct state: AppModel::devices()
    #[test]
    fn merges_client_and_authorized_by_fingerprint() {
        let mut m = AppModel::default();
        let fp = "aa:bb:cc:dd";
        m.clients.insert(0, client(Some("studio-mac"), Some(fp)));
        m.authorized
            .insert(fp.to_string(), "studio-mac".to_string());
        let devices = m.devices();
        assert_eq!(devices.len(), 1, "one machine must render as one card");
        let d = &devices[0];
        assert!(d.send.is_some(), "carries the outgoing facet");
        assert!(d.receive, "may drive this machine");
        assert_eq!(d.trust, TrustState::Trusted);
        assert_eq!(d.fingerprint.as_deref(), Some(fp));
    }

    /// Two machines added by address: the name field holds an address. Once
    /// the fingerprint is learned, each collapses into one card named by the
    /// peer, not by its address.
    // LEDGER T502 | class B | 6 struct state: AppModel::devices()
    #[test]
    fn ip_named_client_merges_and_takes_the_peer_description() {
        let mut m = AppModel::default();
        let desk = "73:90:2a:3c:9d:e5";
        let laptop = "2d:65:8f:e6:f8:2b";
        m.clients.insert(0, client(Some("192.0.2.10"), Some(desk)));
        m.clients
            .insert(1, client(Some("192.0.2.11"), Some(laptop)));
        m.authorized
            .insert(desk.to_string(), "desk mac".to_string());
        m.authorized
            .insert(laptop.to_string(), "laptop".to_string());

        let devices = m.devices();
        assert_eq!(devices.len(), 2, "two machines, not four cards");
        let mut labels: Vec<&str> = devices.iter().map(|d| d.label.as_str()).collect();
        labels.sort();
        assert_eq!(labels, ["desk mac", "laptop"], "named by peer, not by IP");
        for d in &devices {
            assert!(d.send.is_some(), "{} keeps its outgoing facet", d.label);
            assert!(d.receive, "{} may still drive this machine", d.label);
        }
    }

    /// A denial the trust store still holds must never render like a device
    /// never met.
    // LEDGER T503 | class B | 6 struct state: AppModel::devices()
    #[test]
    fn a_revoked_device_is_shown_as_revoked_not_as_a_stranger() {
        let mut m = AppModel::default();
        let fp = "aa:bb:cc:dd";
        m.revoked.insert(fp.to_string(), revoked("old laptop"));
        let devices = m.devices();
        assert_eq!(devices.len(), 1, "the removed device stays visible");
        assert_eq!(devices[0].trust, TrustState::Revoked);
        assert_eq!(
            devices[0].label, "old laptop",
            "it keeps the name it was known by"
        );
        assert!(!devices[0].receive, "revoked means it may not drive us");
    }

    /// A revoked peer reconnecting must not surface as a pairing request.
    // LEDGER T504 | class B | 6 struct state: AppModel::devices()
    #[test]
    fn a_revoked_peer_cannot_appear_as_a_pending_approval() {
        let mut m = AppModel::default();
        let fp = "aa:bb:cc:dd";
        m.revoked.insert(fp.to_string(), revoked("old laptop"));
        m.pending_pairing = Some(fp.to_string());
        let devices = m.devices();
        assert_eq!(devices.len(), 1);
        assert_eq!(
            devices[0].trust,
            TrustState::Revoked,
            "a reconnecting revoked peer must not be offered as a new pairing"
        );
    }

    /// If both tables somehow name the same fingerprint, it must not render as
    /// trusted.
    // LEDGER T505 | class B | 6 struct state: AppModel::devices()
    #[test]
    fn authorized_wins_only_when_not_revoked() {
        let mut m = AppModel::default();
        let fp = "aa:bb:cc:dd";
        m.authorized.insert(fp.to_string(), "old laptop".into());
        let devices = m.devices();
        assert_eq!(
            devices[0].trust,
            TrustState::Trusted,
            "plain trusted device"
        );

        m.revoked.insert(fp.to_string(), revoked("old laptop"));
        let devices = m.devices();
        assert_eq!(devices.len(), 1, "still one card, not two");
        assert_eq!(
            devices[0].trust,
            TrustState::Revoked,
            "revoked outranks authorized: a denied identity cannot present as trusted"
        );
        assert!(!devices[0].receive, "and it may not drive us");
    }

    /// Filtering on `send.is_some() || receive` drops revoked devices, so the
    /// removed state never rendered in the real app.
    // LEDGER T506 | class B | 1 return value: Device::is_listable over AppModel::devices()
    #[test]
    fn a_revoked_device_survives_the_list_filter() {
        let mut m = AppModel::default();
        m.revoked
            .insert("aa:bb:cc:dd".into(), revoked("old laptop"));
        let devices = m.devices();
        assert_eq!(devices.len(), 1);
        assert!(
            devices[0].is_listable(),
            "a revoked device must reach the device list, or nothing says it was removed"
        );
        assert_eq!(
            devices.iter().filter(|d| d.is_listable()).count(),
            1,
            "exactly one listable row"
        );
    }

    /// The daemon's only channel for "that didn't work": each failure must
    /// be something a UI can tell is new. The banner reads the latest error
    /// and its sequence, not the activity log (#150).
    // LEDGER T507 | class B | 6 struct state: AppModel::apply, latest_error/error_seq
    #[test]
    fn errors_become_a_notice_the_ui_can_tell_is_new() {
        let mut m = AppModel::default();
        assert_eq!(m.latest_error(), None, "nothing to show at rest");
        assert_eq!(m.error_seq, 0);

        m.apply(FrontendEvent::Error("could not resolve studio-pc".into()));
        assert_eq!(m.latest_error(), Some("could not resolve studio-pc"));
        let first = m.error_seq;
        assert!(
            first > 0,
            "an error must bump the seq or the UI cannot raise it"
        );

        // A second, identical error must still be distinguishable, or a
        // dismissed banner would stay hidden through a repeat of the failure.
        m.apply(FrontendEvent::Error("could not resolve studio-pc".into()));
        assert!(
            m.error_seq > first,
            "a repeated failure must re-raise the banner"
        );
    }

    /// A peer that reconnects on a new source port must not be reported
    /// offline by the old address's late disconnect.
    // LEDGER T508 | class B | 6 struct state: AppModel::apply
    #[test]
    fn a_reconnect_on_a_new_port_stays_connected() {
        use std::net::SocketAddr;
        let fp = "aa:bb:cc:dd";
        let old: SocketAddr = "192.0.2.5:50001".parse().unwrap();
        let new: SocketAddr = "192.0.2.5:50002".parse().unwrap();

        let mut m = AppModel::default();
        m.apply(FrontendEvent::DeviceConnected {
            addr: old,
            fingerprint: fp.into(),
        });
        assert!(m.connected_peers.contains(fp));

        // The reconnect lands first, then the old socket's disconnect.
        m.apply(FrontendEvent::DeviceConnected {
            addr: new,
            fingerprint: fp.into(),
        });
        m.apply(FrontendEvent::IncomingDisconnected(old));
        assert!(
            m.connected_peers.contains(fp),
            "the peer is still connected on the new port; a late disconnect \
             for the old one must not mark it offline"
        );

        m.apply(FrontendEvent::IncomingDisconnected(new));
        assert!(
            !m.connected_peers.contains(fp),
            "the last address leaving means offline"
        );
    }

    // LEDGER T509 | class B | 6 struct state: AppModel::devices()
    #[test]
    fn offline_client_and_unrelated_trust_stay_two_cards() {
        let mut m = AppModel::default();
        // an outgoing client that has never connected (no fingerprint yet)
        m.clients.insert(0, client(Some("studio-mac"), None));
        // an unrelated peer that may drive us (receive-only)
        m.authorized
            .insert("cc:dd:ee:ff".to_string(), "windows-box".to_string());
        let devices = m.devices();
        assert_eq!(devices.len(), 2, "no fingerprint to join on => two cards");
        assert!(
            devices
                .iter()
                .any(|d| d.fingerprint.is_none() && d.send.is_some())
        );
        assert!(devices.iter().any(|d| d.receive && d.send.is_none()));
    }

    // LEDGER T510 | class B | 6 struct state: AppModel::devices()
    #[test]
    fn excludes_this_device() {
        let mut m = AppModel::default();
        let me = "de:ad:be:ef";
        m.fingerprint = Some(me.to_string());
        m.authorized.insert(me.to_string(), "myself".to_string());
        m.revoked.insert(me.to_string(), revoked("myself"));
        m.pending_pairing = Some(me.to_string());
        assert!(m.devices().is_empty(), "never list ourselves");
    }

    // LEDGER T511 | class B | 6 struct state: AppModel::devices()
    #[test]
    fn bare_pairing_request_surfaces_as_pending() {
        let mut m = AppModel::default();
        let fp = "12:34:56:78";
        m.pending_pairing = Some(fp.to_string());
        let devices = m.devices();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].trust, TrustState::PendingApproval);
        assert_eq!(devices[0].fingerprint.as_deref(), Some(fp));
        assert!(
            !devices[0].is_listable(),
            "a bare request lives on the pairing card, not in the list"
        );
    }

    // LEDGER T512 | class B | 6 struct state: AppModel::apply + AppModel::devices()
    #[test]
    fn online_reflects_connected_peers() {
        let mut m = AppModel::default();
        let fp = "aa:bb:cc:dd";
        m.authorized
            .insert(fp.to_string(), "studio-mac".to_string());
        m.apply(FrontendEvent::DeviceConnected {
            addr: "192.0.2.5:50001".parse().unwrap(),
            fingerprint: fp.into(),
        });
        let devices = m.devices();
        assert_eq!(devices.len(), 1);
        assert!(devices[0].online);
    }

    /// Approving a peer without typing a name must produce the same label
    /// the projection would have chosen, from either front-end.
    // LEDGER T513 | class B | 1 return value: fallback_label, 6 struct state: AppModel::devices()
    #[test]
    fn a_blank_approval_is_named_the_same_way_everywhere() {
        let fp = "1e:19:1b:2c:3d:4e:5f:60";
        let label = fallback_label(fp);
        assert_eq!(label, "1e:19:1b");

        let mut m = AppModel::default();
        m.authorized.insert(fp.to_string(), label.clone());
        let d = m.devices();
        assert_eq!(d.len(), 1);
        assert_eq!(
            d[0].label, label,
            "the stored fallback must match what the projection displays"
        );

        // an empty fingerprint must still yield something sayable
        assert_eq!(fallback_label(""), "unnamed device");
    }
}

#[cfg(test)]
mod errors_apart_from_activity {
    //! Errors and the activity log are two things (#150): the log keeps
    //! everything, and only what went wrong is an error.
    use super::*;

    // LEDGER T516 | class B | 6 struct state: AppModel::apply, latest_error/error_seq
    #[test]
    fn routine_events_reach_the_log_and_not_the_errors() {
        let addr: SocketAddr = "192.0.2.5:50001".parse().expect("addr");
        let mut m = AppModel::default();
        m.apply(FrontendEvent::DeviceConnected {
            addr,
            fingerprint: "aa:bb".into(),
        });
        m.apply(FrontendEvent::DeviceEntered {
            addr,
            pos: Position::Right,
            fingerprint: "aa:bb".into(),
        });
        m.apply(FrontendEvent::ConnectionAttempt {
            fingerprint: "cc:dd".into(),
            origin: AttemptOrigin::Inbound,
            addr: Some(addr),
        });
        m.apply(FrontendEvent::IncomingDisconnected(addr));
        m.apply(FrontendEvent::PortChanged(4242, None));
        assert_eq!(m.messages.len(), 4, "the activity log keeps every event");
        assert_eq!(
            (m.latest_error(), m.error_seq),
            (None, 0),
            "a routine event became an error"
        );

        m.apply(FrontendEvent::Error("could not resolve studio-pc".into()));
        m.apply(FrontendEvent::DeviceEntered {
            addr,
            pos: Position::Right,
            fingerprint: "aa:bb".into(),
        });
        assert_eq!(
            (m.latest_error(), m.error_seq),
            (Some("could not resolve studio-pc"), 1),
            "a cursor entering replaced or re-raised the error"
        );
        assert!(
            m.latest_message()
                .is_some_and(|l| l.starts_with("cursor entered")),
            "the log's latest line is the latest event"
        );

        m.apply(FrontendEvent::PortChanged(
            4243,
            Some("address in use".into()),
        ));
        assert_eq!(
            (m.latest_error(), m.error_seq),
            (Some("port change failed: address in use"), 2)
        );
    }
}

#[cfg(test)]
mod the_daemon_gone {
    //! While no daemon is connected nothing reads live, and nothing asked of
    //! the app is kept to replay into whichever daemon answers next (#34).
    //!
    //! Drives the real connection loop over in-memory connections.
    use super::*;
    use futures::channel::mpsc as fmpsc;
    use std::rc::Rc;

    type Events = fmpsc::UnboundedReceiver<Result<FrontendEvent, IpcError>>;

    /// The app's end of one connection: what the daemon writes to it goes
    /// through `Events`, what it writes to the daemon through this.
    struct Sink(mpsc::UnboundedSender<FrontendRequest>);

    impl RequestSink for Sink {
        async fn send(&mut self, request: FrontendRequest) -> Result<(), IpcError> {
            self.0
                .send(request)
                .map_err(|_| IpcError::Io(std::io::ErrorKind::BrokenPipe.into()))
        }
    }

    /// The daemon's end of one connection.
    struct Daemon {
        events: fmpsc::UnboundedSender<Result<FrontendEvent, IpcError>>,
        received: mpsc::UnboundedReceiver<FrontendRequest>,
    }

    fn connection() -> (Daemon, (Events, Sink)) {
        let (events, app_events) = fmpsc::unbounded();
        let (app_requests, received) = mpsc::unbounded_channel();
        (
            Daemon { events, received },
            (app_events, Sink(app_requests)),
        )
    }

    /// Wait until `cond` holds of the model, for at most 10 s.
    async fn until(client: &FrontendClient, what: &str, cond: impl Fn(&AppModel) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !cond(&client.snapshot()) {
            assert!(Instant::now() < deadline, "not within 10 s: {what}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// The next request `daemon` receives, within 10 s.
    async fn next(daemon: &mut Daemon) -> FrontendRequest {
        tokio::time::timeout(Duration::from_secs(10), daemon.received.recv())
            .await
            .expect("a request within 10 s")
            .expect("the connection is open")
    }

    const FP: &str = "aa:bb";

    // LEDGER T520 | class B | 6 struct state + requests written by connection_loop across a daemon restart
    #[tokio::test(flavor = "current_thread")]
    async fn a_lost_daemon_leaves_nothing_live_and_nothing_to_replay() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let model = Arc::new(Mutex::new(AppModel::default()));
                let changed = Arc::new(Notify::new());
                let (requests, request_rx) = mpsc::unbounded_channel();
                let client = FrontendClient {
                    model: model.clone(),
                    changed: changed.clone(),
                    requests,
                };
                let (dial, answers) = mpsc::unbounded_channel::<(Events, Sink)>();
                let answers = Rc::new(tokio::sync::Mutex::new(answers));
                tokio::task::spawn_local(connection_loop(model, changed, request_rx, move || {
                    let answers = answers.clone();
                    async move {
                        answers
                            .lock()
                            .await
                            .recv()
                            .await
                            .ok_or(ConnectionError::Timeout)
                    }
                }));

                let (mut first, conn) = connection();
                assert!(dial.send(conn).is_ok(), "the loop stopped");
                until(&client, "the first daemon answers", |m| m.connected).await;
                assert!(matches!(next(&mut first).await, FrontendRequest::Sync));
                let live = ClientState {
                    active: true,
                    alive: true,
                    active_addr: Some("192.0.2.5:4242".parse().expect("addr")),
                    peer_fingerprint: Some(FP.into()),
                    ..Default::default()
                };
                for event in [
                    FrontendEvent::Enumerate(vec![(0, ClientConfig::default(), live)]),
                    FrontendEvent::DeviceConnected {
                        addr: "192.0.2.5:50001".parse().expect("addr"),
                        fingerprint: FP.into(),
                    },
                    FrontendEvent::PairingOpen { seconds: 120 },
                    FrontendEvent::CaptureStatus(Status::Enabled),
                    FrontendEvent::ConnectionAttempt {
                        fingerprint: "cc:dd".into(),
                        origin: AttemptOrigin::Inbound,
                        addr: Some("192.0.2.9:50002".parse().expect("addr")),
                    },
                    FrontendEvent::Discovered {
                        active: true,
                        peers: vec![DiscoveredDevice {
                            label: "desk-laptop".into(),
                            claimed_fingerprint: None,
                            addrs: vec!["192.0.2.7:4242".parse().expect("addr")],
                        }],
                    },
                ] {
                    first.events.unbounded_send(Ok(event)).expect("open");
                }
                until(&client, "the device reads live", |m| {
                    m.devices()
                        .iter()
                        .any(|d| d.online && d.send.as_ref().is_some_and(|s| s.state.alive))
                        && m.pairing_open_until.is_some()
                        && m.pending_pairing.is_some()
                        && !m.pairing_attempts.is_empty()
                        && !m.discovered.is_empty()
                })
                .await;

                // The daemon stops taking requests with two queued: the first
                // fails to write, the second, an add, is still waiting.
                drop(first.received);
                assert!(client.request(FrontendRequest::RemoveAuthorizedKey(FP.into())));
                let add_on = client
                    .request_on(FrontendRequest::Create)
                    .expect("a daemon is connected");
                until(&client, "the loss is noticed", |m| !m.connected).await;
                let gone = client.snapshot();

                // While none is connected, a request is refused, not queued.
                let refused = !client.request(FrontendRequest::Delete {
                    handle: 0,
                    fingerprint: Some(FP.into()),
                });
                let said = client.snapshot().latest_error().map(str::to_owned);

                let (mut second, conn) = connection();
                assert!(dial.send(conn).is_ok(), "the loop stopped");
                until(&client, "the second daemon answers", |m| m.connected).await;
                assert!(client.request(FrontendRequest::SaveConfiguration));
                let mut sent = vec![];
                loop {
                    let request = next(&mut second).await;
                    let last = matches!(request, FrontendRequest::SaveConfiguration);
                    sent.push(request);
                    if last {
                        break;
                    }
                }

                assert!(
                    matches!(
                        sent.as_slice(),
                        [FrontendRequest::Sync, FrontendRequest::SaveConfiguration]
                    ),
                    "the next daemon was sent {sent:?}: what was asked of the last \
                     one, or while none was connected, was replayed into it"
                );
                let d = &gone.devices()[0];
                let s = d.send.as_ref().expect("the device is still listed");
                assert!(
                    !d.online && !s.state.alive && s.state.active_addr.is_none(),
                    "with no daemon the device still reads connected or up: \
                     online {} alive {} link {:?}",
                    d.online,
                    s.state.alive,
                    s.state.active_addr
                );
                assert!(
                    gone.pairing_seconds_left(Instant::now()).is_none()
                        && gone.capture == Status::Disabled,
                    "with no daemon the pairing window or capture still reads open"
                );
                assert!(
                    gone.pending_pairing.is_none() && gone.pairing_attempts.is_empty(),
                    "with no daemon a pairing request still waits for an answer \
                     nothing can deliver: {:?}",
                    gone.pairing_attempts
                );
                assert!(
                    gone.discovered.is_empty() && !gone.discovery_active,
                    "with no daemon machines still read as found on the network: {:?}",
                    gone.discovered
                );
                assert!(
                    gone.latest_error()
                        .is_some_and(|e| e.contains("your last 2 changes")),
                    "two requests the daemon never took were dropped without a word: {:?}",
                    gone.latest_error()
                );
                assert!(
                    gone.link != add_on,
                    "the add was dropped with its connection, but the link it was \
                     queued on still reads current: a frontend keeping its name \
                     and edge would give them to the next handle to appear"
                );
                assert!(
                    refused && said.as_deref() == Some(NOT_CONNECTED),
                    "a request with no daemon connected was accepted ({refused}) or \
                     went unanswered ({said:?})"
                );
            })
            .await;
    }
}
