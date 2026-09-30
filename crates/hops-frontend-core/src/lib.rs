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
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use futures::{Stream, StreamExt};
use hops_ipc::{AsyncFrontendRequestWriter, ConnectionError, IpcError};
use tokio::sync::{Notify, mpsc};

pub use hops_ipc::{
    AttemptOrigin, Build, CaptureFault, CaptureState, ClientConfig, ClientHandle, ClientState,
    Controller, CrossingRefusal, DiscoveredDevice, EmulationFault, EmulationState, FrontendEvent,
    FrontendRequest, NewDevice, PairingCheck, PeerTrust, Permission, Position, Status,
    connect_async,
};

pub mod connection;
pub mod prefs;
pub mod theme;

pub use connection::{Connection, Tone};

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
    /// Local input-capture status, and why it failed when it did.
    pub capture: CaptureState,
    /// Local input-emulation status, and why it failed when it did.
    pub emulation: EmulationState,
    /// This device's public-key fingerprint.
    pub fingerprint: Option<String>,
    /// Trusted peer fingerprints -> description.
    pub authorized: HashMap<String, String>,
    /// What the trust store grants each paired machine, by fingerprint. Read
    /// through [`AppModel::clipboard`]. Empty from a daemon older than
    /// `FrontendEvent::TrustUpdated`.
    pub trust: HashMap<String, PeerTrust>,
    /// The daemon's listen port.
    pub port: Option<u16>,
    /// The daemon listens on no port: it only dials out (#15), so
    /// [`Self::port`] is its configured port and not one anything can reach.
    /// False from a daemon that does not say, which always listened.
    pub dials_out_only: bool,
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
    /// Discovery has run a while and heard no other machine at all (#149).
    pub discovery_quiet: bool,
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
    /// Pairings whose number a person here must now compare, oldest first
    /// (#11, #167). Set on `PairingCheck`, cleared on `PairingEnded` or when
    /// the daemon link drops.
    pub pairing_checks: Vec<PairingCheckCard>,
    /// Maps a connected peer's socket address -> fingerprint, so the addr-only
    /// `IncomingDisconnected` event can be correlated back to a fingerprint.
    peer_addrs: HashMap<SocketAddr, String>,
    /// Switched-on devices whose last crossing found no link, until a link
    /// to them comes up or they are switched off: what makes a device read
    /// [`Connection::Unreachable`] rather than merely not connected.
    unreached: HashSet<ClientHandle>,
}

/// A pairing whose number a person here must compare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingCheckCard {
    pub fingerprint: String,
    /// Where the other machine is, when known.
    pub addr: Option<SocketAddr>,
    /// Show the number and confirm, or pick it from three.
    pub check: PairingCheck,
    /// The person here answered; waiting for the other machine.
    pub answered: bool,
}

impl PairingCheckCard {
    /// The request answering this card with `number` sends: the digits, as
    /// shown with or without the space [`spaced_number`] puts in.
    pub fn answer(&self, number: &str) -> FrontendRequest {
        FrontendRequest::ConfirmPairing {
            fingerprint: self.fingerprint.clone(),
            number: number.chars().filter(|c| !c.is_whitespace()).collect(),
        }
    }

    /// The request ending this card without pairing sends.
    pub fn cancel(&self) -> FrontendRequest {
        FrontendRequest::CancelPairing(self.fingerprint.clone())
    }

    /// Where the other machine is, in words, for the card's first line.
    pub fn from(&self) -> String {
        match self.addr {
            Some(a) => format!("{} at {a}", short_fingerprint(&self.fingerprint)),
            None => short_fingerprint(&self.fingerprint),
        }
    }
}

impl Device {
    /// Should this device occupy a row in the device list?
    ///
    /// Excludes ONLY a bare inbound pairing request, which lives in the pairing
    /// banner instead.
    pub fn is_listable(&self) -> bool {
        self.send.is_some() || self.receive || self.paired || self.pair_again
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
                let clients = &self.clients;
                self.unreached
                    .retain(|h| clients.get(h).is_some_and(|(_, s)| still_unreached(s)));
            }
            FrontendEvent::Created(h, c, s) | FrontendEvent::State(h, c, s) => {
                if !still_unreached(&s) {
                    self.unreached.remove(&h);
                }
                self.clients.insert(h, (c, s));
            }
            FrontendEvent::Deleted(h) => {
                self.clients.remove(&h);
                self.unreached.remove(&h);
            }
            FrontendEvent::CaptureStatus(s) => self.capture = s,
            FrontendEvent::EmulationStatus(s) => self.emulation = s,
            FrontendEvent::Listening(listening) => self.dials_out_only = !listening,
            FrontendEvent::PublicKeyFingerprint(fp) => self.fingerprint = Some(fp),
            FrontendEvent::TrustUpdated(map) => {
                self.trust = map;
                // An approval here answers its request: the machine is now
                // mid-pairing, and its number card takes over (#167).
                let attempts = std::mem::take(&mut self.pairing_attempts);
                self.pairing_attempts = attempts
                    .into_iter()
                    .filter(|a| !self.arrival_permitted(&a.fingerprint, Some(a.origin)))
                    .collect();
            }
            FrontendEvent::PairingCheck {
                fingerprint,
                addr,
                check,
                answered,
            } => {
                let card = PairingCheckCard {
                    fingerprint,
                    addr,
                    check,
                    answered,
                };
                match self
                    .pairing_checks
                    .iter_mut()
                    .find(|c| c.fingerprint == card.fingerprint)
                {
                    Some(held) => *held = card,
                    None => {
                        if self.pairing_checks.len() >= MAX_PAIRING_ATTEMPTS {
                            self.pairing_checks.remove(0);
                        }
                        self.pairing_checks.push(card);
                    }
                }
            }
            FrontendEvent::PairingEnded {
                fingerprint,
                paired,
            } => {
                self.pairing_checks.retain(|c| c.fingerprint != fingerprint);
                if paired {
                    self.push_message(format!("paired with {}", short_fingerprint(&fingerprint)));
                }
            }
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
            FrontendEvent::Activity(line) => self.push_message(line),
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
            FrontendEvent::Discovered {
                active,
                peers,
                quiet,
            } => {
                self.discovery_active = active;
                self.discovery_quiet = quiet;
                self.discovered = peers;
            }
            FrontendEvent::PairingOpen { seconds } => {
                self.pairing_open_until = (seconds > 0)
                    .then(|| Instant::now() + std::time::Duration::from_secs(seconds.into()));
            }
            FrontendEvent::NoSuchClient(_) => {}
            // Sent to every frontend, and meant for the one that asked.
            FrontendEvent::Barrier(_) => {}
            // The pointer stayed on this machine. That is "that didn't
            // work" to someone pushing at an edge, so it takes the banner.
            FrontendEvent::CrossingRefused { handle, reason } => {
                // No link, and a dial started: if it lands, the device's
                // state arrives with its link up and clears this. A link
                // that is up and not yet answered on is still connecting.
                if reason == CrossingRefusal::NotConnected
                    && self
                        .clients
                        .get(&handle)
                        .is_some_and(|(_, s)| still_unreached(s))
                {
                    self.unreached.insert(handle);
                }
                let device = self
                    .devices()
                    .into_iter()
                    .find(|d| d.send.as_ref().is_some_and(|s| s.handle == handle));
                let text = match device {
                    Some(d) => {
                        crossing_refused(&d.label, d.trust == TrustState::Provisional, reason)
                    }
                    None => crossing_refused("That device", false, reason),
                };
                self.push_error(text);
            }
        }
    }

    /// The devices added here that `attempt` reached, when it is this
    /// machine's own dial, each named as the person here knows it: its name,
    /// and where it is dialled (#93). The card for that dial names them, so
    /// it is read against a device being added, never as a machine knocking.
    /// Empty for a knock, and for a dial that matches no device listed.
    pub fn dialled(&self, attempt: &PairingAttempt) -> Vec<String> {
        let Some(addr) = attempt
            .addr
            .filter(|_| attempt.origin == AttemptOrigin::OutboundDial)
        else {
            return Vec::new();
        };
        self.clients
            .values()
            .filter(|(c, s)| c.port == addr.port() && s.ips.contains(&addr.ip()))
            .map(|(c, _)| {
                let host = c
                    .hostname
                    .clone()
                    .or_else(|| c.fix_ips.first().map(IpAddr::to_string))
                    .unwrap_or_else(|| addr.ip().to_string());
                let at = match host.parse::<IpAddr>() {
                    Ok(ip) => SocketAddr::new(ip, c.port).to_string(),
                    Err(_) => format!("{host}:{}", c.port),
                };
                match c.label.as_deref() {
                    Some(label) if label != host => format!("{label} ({at})"),
                    _ => at,
                }
            })
            .collect()
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
        // Approved here and mid-pairing, either way: the request was answered,
        // and what is left is the number (#167).
        if self.is_pairing(fp) {
            return true;
        }
        match origin {
            Some(AttemptOrigin::OutboundDial) => false,
            Some(AttemptOrigin::Inbound) | None => self.authorized.contains_key(fp),
        }
    }

    /// Whether `fp` was approved here and waits for the number to be
    /// confirmed on both machines (#167).
    pub fn is_pairing(&self, fp: &str) -> bool {
        self.trust.get(fp).is_some_and(|t| t.pending)
            || self.pairing_checks.iter().any(|c| c.fingerprint == fp)
    }

    /// The number card to put in front of the user: the oldest open check.
    pub fn pairing_check(&self) -> Option<&PairingCheckCard> {
        self.pairing_checks.first()
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

    /// Why capture, which should run, does not, for a frontend to show while
    /// it is so (#91); `None` while capture runs or is simply off.
    ///
    /// A missing permission is named with where to grant it, and with what
    /// it is for: a Mac that is only ever controlled never needs it.
    pub fn capture_problem(&self) -> Option<String> {
        let CaptureState::Failed(fault) = &self.capture else {
            return None;
        };
        Some(match fault {
            CaptureFault::Missing(missing) => {
                let names: Vec<String> = missing.iter().map(ToString::to_string).collect();
                let names = names.join(" and ");
                let where_ = if missing.len() > 1 {
                    format!(", in both {names}")
                } else {
                    format!(" → {names}")
                };
                format!(
                    "Input capture cannot run: macOS does not grant hops {names}, which \
                     this Mac needs to control other machines. Turn hops on under System \
                     Settings → Privacy & Security{where_}."
                )
            }
            CaptureFault::Backend(error) => format!("Input capture is not running: {error}"),
        })
    }

    /// Why emulation, which should run, does not, for a frontend to show
    /// while it is so; `None` while emulation runs or is simply off.
    ///
    /// A Mac that is only ever controlled needs Accessibility for this and
    /// for nothing else, and was told only that emulation was off.
    pub fn emulation_problem(&self) -> Option<String> {
        let EmulationState::Failed(fault) = &self.emulation else {
            return None;
        };
        Some(match fault {
            EmulationFault::Missing(missing) => {
                let names: Vec<String> = missing.iter().map(ToString::to_string).collect();
                let names = names.join(" and ");
                format!(
                    "Input emulation cannot run: macOS does not grant hops {names}, which \
                     this Mac needs to be controlled from other machines. Turn hops on \
                     under System Settings → Privacy & Security → {names}."
                )
            }
            EmulationFault::Backend(error) => format!("Input emulation is not running: {error}"),
        })
    }

    /// The port as a frontend shows it: the number, "dials out only" for a
    /// daemon that listens on none, or a dash before the daemon says.
    pub fn port_words(&self) -> String {
        match self.port {
            _ if self.dials_out_only => "dials out only".to_string(),
            Some(port) => port.to_string(),
            None => "—".to_string(),
        }
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
        self.unreached.clear();
        self.pending_pairing = None;
        self.pending_pairing_origin = None;
        self.pending_pairing_addr = None;
        self.pending_pairing_since = None;
        self.pairing_attempts.clear();
        self.pairing_checks.clear();
        self.pairing_open_until = None;
        self.discovered.clear();
        self.discovery_active = false;
        self.discovery_quiet = false;
        self.capture = CaptureState::Disabled;
        self.emulation = EmulationState::Disabled;
        self.dials_out_only = false;
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
    /// Nobody said which way control goes. There is no default (#220).
    NoController,
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
            ApprovalRefused::NoController => {
                "Choose which machine is in control first. Nothing was trusted."
            }
        }
    }
}

/// What the person approving a pairing answered on its card (#220, #182):
/// which way control goes, which has no default, and whether to share the
/// clipboard, which is no until they say yes.
///
/// Held for one machine. Answers given while the card showed another are
/// cleared when it changes, so they can never be sent for this one (#168).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PairingAnswers {
    fingerprint: Option<String>,
    /// Which machine is in control, once the person said.
    pub controller: Option<Controller>,
    /// Share the clipboard, in the directions control goes.
    pub clipboard: bool,
}

impl PairingAnswers {
    /// The answers for the card showing `fingerprint`: those given while it
    /// showed that machine, or none.
    pub fn for_card(&mut self, fingerprint: &str) -> &mut Self {
        if self.fingerprint.as_deref() != Some(fingerprint) {
            *self = PairingAnswers {
                fingerprint: Some(fingerprint.to_string()),
                ..Default::default()
            };
        }
        self
    }

    /// The approval of `fingerprint`, named `name`, with these answers, if
    /// they were given for that machine and say which way control goes.
    pub fn approval(
        &self,
        fingerprint: &str,
        name: &str,
    ) -> Result<FrontendRequest, ApprovalRefused> {
        if self.fingerprint.as_deref() != Some(fingerprint) {
            return Err(ApprovalRefused::NotOnScreen);
        }
        approval_request(fingerprint, name, self.controller, self.clipboard)
    }
}

/// The request approving `fingerprint` sends, named `name` or, left blank,
/// by [`fallback_label`], with the card's two answers. Refused while nobody
/// said which way control goes: that is never assumed (#220).
pub fn approval_request(
    fingerprint: &str,
    name: &str,
    controller: Option<Controller>,
    clipboard: bool,
) -> Result<FrontendRequest, ApprovalRefused> {
    let controller = controller.ok_or(ApprovalRefused::NoController)?;
    let label = if name.trim().is_empty() {
        fallback_label(fingerprint)
    } else {
        name.trim().to_string()
    };
    Ok(FrontendRequest::AuthorizeKey {
        label,
        fingerprint: fingerprint.to_string(),
        controller,
        clipboard,
    })
}

/// What the card for this machine's own dial says under its title (#61,
/// #93), naming the devices [`AppModel::dialled`] found. A knock is never
/// described with this: nobody here dialled it.
pub fn our_dial_words(dialled: &[String]) -> String {
    match dialled {
        [] => "This machine dialled out, and the machine that answered is not paired \
               with this one. Pair it only if you just added a device here; if you did \
               not, deny it."
            .to_string(),
        [one] => format!(
            "This machine dialled {one}, a device added here. The machine that \
             answered is not paired with this one: pair it only if you are adding \
             that device, and deny it if you are not."
        ),
        several => format!(
            "This machine dialled {}, devices added here. The machine that answered \
             is not paired with this one: pair it only if you are adding one of \
             them, and deny it if you are not.",
            several.join(" and ")
        ),
    }
}

/// The request adding a device sends (#32): the whole device, dialled at
/// `hostname` or at `fix_ips`, on `port`, at `pos`, in one request; or, when
/// it cannot be dialled, why, to say instead of sending anything.
pub fn new_device(
    hostname: &str,
    fix_ips: Vec<IpAddr>,
    port: u16,
    pos: Position,
) -> Result<FrontendRequest, &'static str> {
    let hostname = hostname.trim();
    let device = NewDevice {
        hostname: (!hostname.is_empty()).then(|| hostname.to_string()),
        fix_ips,
        port,
        pos,
    };
    match device.refusal() {
        Some(why) => Err(why),
        None => Ok(FrontendRequest::Create(device)),
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
    /// Neither way. `EnableClipboard` turns it back on, in the directions
    /// the pairing drives.
    Off,
    /// That device's clipboard arrives here, and nothing goes back.
    FromIt,
    /// This machine's clipboard goes there, and nothing comes back.
    ToIt,
    /// Both ways.
    BothWays,
}

impl Clipboard {
    /// A direction is on, so the switch offers to turn it off; otherwise it
    /// offers to turn it back on.
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
    /// Paired with a version of hops before the trust store, and not since:
    /// it grants nothing until it is paired again (#231).
    PairAgain,
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
    /// Where its connection stands: the one thing a frontend draws the dot
    /// and the status words from (#148).
    pub connection: Connection,
    /// Present iff this machine dials the device (a configured client).
    pub send: Option<DeviceSend>,
    /// True iff the device's fingerprint is in the authorized allowlist
    /// (trusted to connect *in*).
    pub receive: bool,
    /// This machine holds a pairing with it, whichever way control goes:
    /// what makes the card removable by fingerprint.
    pub paired: bool,
    /// Its pairing lets this machine control it.
    pub controls: bool,
    /// Paired with a version of hops before the trust store and not since
    /// (#231): it grants nothing, and the card offers to add it again or
    /// remove it by fingerprint.
    pub pair_again: bool,
}

/// The hostname to store for a machine picked off the network list.
///
/// mDNS advertises a host as `<instance>.local.`, and a bare `desk-mac` does
/// not resolve while `desk-mac.local` does — through the OS name stack
/// (Bonjour on macOS, Avahi via nsswitch on Linux), which `src/dns.rs` uses
/// deliberately for exactly this.
///
/// The addresses pinned at add-time are a snapshot: if the peer's DHCP lease
/// changes, they go stale. hops dials them together with the addresses the
/// name resolves to, looked up when the device is switched on or renamed and,
/// on a machine that dials out to be driven, again after every dial that
/// reaches nothing. A machine that dials to drive the peer does not look the
/// name up again by itself; switching the device off and on does.
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

/// A pairing number as a person reads it: six digits in two groups of three,
/// so "042917" is compared as "042 917", the same in every frontend.
pub fn spaced_number(n: &str) -> String {
    if n.len() == 6 && n.is_ascii() {
        format!("{} {}", &n[..3], &n[3..])
    } else {
        n.to_string()
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

/// What to say when the pointer crossed toward `label` and stayed here (#115).
///
/// The device and the reason lead, so the start says why wherever the text
/// is cut or wrapped. `never_paired` is a device this machine has never
/// completed a handshake with, which is what #115 met: added, never paired.
/// Such a device may be refused for want of a permission it was never given,
/// and "no longer" would be wrong for it.
pub fn crossing_refused(label: &str, never_paired: bool, reason: CrossingRefusal) -> String {
    match reason {
        CrossingRefusal::NotConnected | CrossingRefusal::NotPermitted if never_paired => format!(
            "{label} is not paired yet, so the pointer stayed here. Pair the two machines, \
             then try again."
        ),
        CrossingRefusal::NotConnected => format!(
            "{label} is not connected, so the pointer stayed here. Check that hops is \
             running on it."
        ),
        CrossingRefusal::NotAcceptingInput => format!(
            "{label} is not accepting input, so the pointer stayed here. hops on it may \
             be missing a permission."
        ),
        CrossingRefusal::NotPermitted => {
            format!("This machine may no longer control {label}, so the pointer stayed here.")
        }
        CrossingRefusal::Unanswered => {
            format!("{label} did not answer the crossing, so the pointer came back.")
        }
    }
}

/// The name the user gave a device we dial, apart from its address (#13).
fn given_name(config: &ClientConfig) -> Option<&str> {
    config.label.as_deref().filter(|l| !l.trim().is_empty())
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
    /// switch.
    pub fn clipboard(&self, fp: &str) -> Option<Clipboard> {
        self.trust
            .get(fp)
            // mid-pairing, or to pair again: nothing is shared, and there is
            // nothing to switch
            .filter(|t| !t.pending && !t.pair_again)
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
                    connection: Connection::ServiceGone,
                    send: None,
                    receive: true,
                    paired: true,
                    controls: false,
                    pair_again: false,
                },
            );
        }

        // 1b. every other pairing, whichever way control goes. The allowlist
        // above names only the machines that may drive this one, so a pairing
        // this machine only controls, with no device pinned to it yet, was on
        // no card, and nothing in the app could remove it. One mid-pairing is
        // on its number card instead.
        for (fp, t) in &self.trust {
            if is_self(fp) || t.pending {
                continue;
            }
            // Paired with an older version and not since (#231): one card,
            // to add again or remove, holding nothing.
            if t.pair_again {
                by_fp.entry(fp.clone()).or_insert_with(|| Device {
                    fingerprint: Some(fp.clone()),
                    label: display_label(None, Some(&t.label), fp),
                    trust: TrustState::PairAgain,
                    connection: Connection::ServiceGone,
                    send: None,
                    receive: false,
                    paired: false,
                    controls: false,
                    pair_again: true,
                });
                continue;
            }
            let device = by_fp.entry(fp.clone()).or_insert_with(|| Device {
                fingerprint: Some(fp.clone()),
                label: display_label(None, Some(&t.label), fp),
                trust: TrustState::Trusted,
                connection: Connection::ServiceGone,
                send: None,
                receive: false,
                paired: true,
                controls: false,
                pair_again: false,
            });
            device.controls = t.we_may_drive;
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
                        connection: Connection::ServiceGone,
                        send: None,
                        receive: false,
                        paired: false,
                        controls: false,
                        pair_again: false,
                    });
                    // One entry per card. Of two entries for one machine, the
                    // first added names the card and takes its buttons (#12):
                    // the name used to come from one and the buttons from the
                    // other. `clients` is ordered by handle, and the daemon
                    // dials the machine for that same entry only.
                    if device.send.is_some() {
                        continue;
                    }
                    // The name the user gave the device comes first (#13). Then
                    // a user-typed send-side hostname -- EXCEPT when it is a
                    // bare IP literal. Adding a device by address puts the IP
                    // in the name field, and an address is a worse name than
                    // the peer's own advertised description.
                    if let Some(name) = given_name(config) {
                        device.label = name.to_string();
                    } else if let Some(host) = config
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
                    label: given_name(config).map_or_else(
                        || display_label(config.hostname.as_deref(), None, ""),
                        str::to_string,
                    ),
                    trust: TrustState::Provisional,
                    connection: Connection::ServiceGone,
                    send: Some(send),
                    receive: false,
                    paired: false,
                    controls: false,
                    pair_again: false,
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
                    connection: Connection::ServiceGone,
                    send: None,
                    receive: false,
                    paired: false,
                    controls: false,
                    pair_again: false,
                });
            }
        }

        // send-facet devices first (ordered by handle), then receive-only (by label)
        let mut out: Vec<Device> = by_fp.into_values().chain(provisional).collect();
        // Every card's facets are joined now: derive its state from them.
        for device in &mut out {
            device.connection = Connection::of(self.facts(device));
        }
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

    /// What the model knows about `device`'s connection, for
    /// [`Connection::of`]. The only place those facts are read for the dot.
    fn facts(&self, device: &Device) -> connection::Facts {
        use connection::{Link, Number, SendFacet, Standing};
        let fp = device.fingerprint.as_deref();
        let standing = match fp {
            Some(fp) if self.is_pairing(fp) => Standing::Pairing(
                match self.pairing_checks.iter().find(|c| c.fingerprint == fp) {
                    None => Number::NotYet,
                    Some(c) if c.answered => Number::Answered,
                    Some(_) => Number::OnScreen,
                },
            ),
            Some(fp) if self.trust.get(fp).is_some_and(|t| t.pair_again) => Standing::PairAgain,
            Some(fp)
                if self.authorized.contains_key(fp)
                    || self.trust.get(fp).is_some_and(|t| !t.pending) =>
            {
                Standing::Paired
            }
            _ => Standing::NotPaired,
        };
        // `active_addr` is set only while the outbound link is up; `alive`
        // is false until the device first answers on it, so without a link
        // it says nothing, and a device with none is never "refusing" (#144).
        let send = match &device.send {
            None => SendFacet::None,
            Some(s) if !s.state.active => SendFacet::Off,
            Some(s) if s.state.active_addr.is_some() => SendFacet::On(Link::Up {
                accepting: s.state.alive,
            }),
            Some(s) => SendFacet::On(Link::Down {
                unanswered: self.unreached.contains(&s.handle),
            }),
        };
        connection::Facts {
            service: self.connected,
            standing,
            send,
            inbound: fp.is_some_and(|fp| self.connected_peers.contains(fp)),
            // The machine this one dials refused it as one it holds no
            // pairing with (#184). The daemon clears it once a link to that
            // machine is up again, and never sets it while adding it.
            removed_by_peer: device
                .send
                .as_ref()
                .is_some_and(|s| s.state.removed_by_peer),
            // The daemon says so for a device whose machine dials in to be
            // driven from here (#15).
            // With no device, a pairing this machine controls is reached
            // only by its own dial: nothing here has an address for it.
            dials_us: match &device.send {
                Some(s) => s.state.dials_us,
                None => device.controls,
            },
        }
    }
}

/// Whether a device in state `s` can still be unreached: switched on, with
/// no link up.
fn still_unreached(s: &ClientState) -> bool {
    s.active && s.active_addr.is_none()
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
mod adding_a_device {
    //! Adding a device is one request carrying all of it (#32), and the card
    //! for the dial it starts names it (#93).
    use super::{
        AppModel, AttemptOrigin, ClientConfig, ClientState, FrontendEvent, FrontendRequest,
        NewDevice, PairingAttempt, Position, new_device, our_dial_words,
    };
    use std::net::{IpAddr, SocketAddr};
    use std::time::Instant;

    // LEDGER T3 | class B | 1 return value: new_device
    /// What the add form says becomes one request holding the whole device,
    /// or the reason it cannot be added; never a device with nowhere to dial.
    #[test]
    fn the_add_form_becomes_one_whole_request_or_a_reason() {
        let ip: IpAddr = "192.0.2.7".parse().expect("ip");
        assert_eq!(
            new_device(" desk-mac.local ", vec![], 4300, Position::Top),
            Ok(FrontendRequest::Create(NewDevice {
                hostname: Some("desk-mac.local".into()),
                fix_ips: vec![],
                port: 4300,
                pos: Position::Top,
            }))
        );
        assert_eq!(
            new_device("", vec![ip], 4242, Position::Right),
            Ok(FrontendRequest::Create(NewDevice {
                hostname: None,
                fix_ips: vec![ip],
                port: 4242,
                pos: Position::Right,
            })),
            "a machine picked off the network list is added by its addresses"
        );
        for (hostname, ips, port) in [("  ", vec![], 4242), ("desk-mac.local", vec![], 0)] {
            assert!(
                new_device(hostname, ips, port, Position::Left).is_err(),
                "{hostname:?} on port {port} would add a device that can never be dialled"
            );
        }
    }

    fn with_device(label: Option<&str>, hostname: &str, ip: IpAddr, port: u16) -> AppModel {
        let mut m = AppModel::default();
        m.apply(FrontendEvent::Created(
            4,
            ClientConfig {
                label: label.map(str::to_owned),
                hostname: Some(hostname.into()),
                port,
                ..Default::default()
            },
            ClientState {
                active: true,
                ips: [ip].into(),
                ..Default::default()
            },
        ));
        m
    }

    fn attempt(origin: AttemptOrigin, addr: SocketAddr) -> PairingAttempt {
        PairingAttempt {
            fingerprint: "AA:BB".into(),
            origin,
            addr: Some(addr),
            since: Instant::now(),
        }
    }

    // LEDGER T5 | class B | 1 return value: AppModel::dialled, our_dial_words
    /// This machine's own dial is named by the device it dialled, as it was
    /// added here; a knock from the very same address names no device.
    #[test]
    fn our_dial_is_named_by_the_device_it_dialled_and_a_knock_by_none() {
        let answered: SocketAddr = "192.0.2.7:4242".parse().expect("addr");
        let m = with_device(Some("desk mac"), "desk-mac.local", answered.ip(), 4242);
        let named = m.dialled(&attempt(AttemptOrigin::OutboundDial, answered));
        assert_eq!(named, vec!["desk mac (desk-mac.local:4242)".to_string()]);
        assert!(our_dial_words(&named).contains("dialled desk mac (desk-mac.local:4242)"));
        assert!(
            m.dialled(&attempt(AttemptOrigin::Inbound, answered))
                .is_empty(),
            "a knock was named as a device this machine dialled"
        );
        let elsewhere: SocketAddr = "192.0.2.7:4300".parse().expect("addr");
        assert!(
            m.dialled(&attempt(AttemptOrigin::OutboundDial, elsewhere))
                .is_empty(),
            "a device on another port was named as the one that answered"
        );
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

    const FP: &str = "aa:bb";

    /// The state of a paired device this machine dials, as the model derives
    /// it from daemon events. Linked by default: the interesting new axis is
    /// what happens when it is NOT.
    fn dev(online: bool, active: bool, alive: bool) -> Connection {
        dev_conn(online, active, alive, true)
    }

    fn dev_conn(online: bool, active: bool, alive: bool, linked: bool) -> Connection {
        let mut m = AppModel {
            connected: true,
            ..AppModel::default()
        };
        m.apply(FrontendEvent::AuthorizedUpdated(HashMap::from([(
            FP.to_string(),
            "peer".to_string(),
        )])));
        m.apply(FrontendEvent::Enumerate(vec![(
            0,
            ClientConfig::default(),
            ClientState {
                active,
                alive,
                active_addr: linked.then(|| "192.0.2.5:4242".parse().unwrap()),
                peer_fingerprint: Some(FP.into()),
                ..Default::default()
            },
        )]));
        if online {
            m.apply(FrontendEvent::DeviceConnected {
                addr: "192.0.2.5:51000".parse().unwrap(),
                fingerprint: FP.into(),
            });
        }
        let devices = m.devices();
        assert_eq!(devices.len(), 1, "one machine, one card: {devices:?}");
        devices[0].connection
    }

    /// The exact scenario in the issue: B's emulation died, B still dials us so
    /// `online` is true, and we are actively pushing input at it.
    // LEDGER T148-4 | class B | 6 struct state: AppModel::apply + AppModel::devices()
    #[test]
    fn an_inbound_connection_does_not_mask_a_dead_receiver() {
        assert_eq!(
            dev(true, true, false),
            Connection::NotAcceptingInput,
            "online must not mask a receiver that told us its emulation is off — \
             every event we send is refused before it is written"
        );
    }

    #[test]
    fn a_healthy_peer_is_not_flagged() {
        assert_eq!(dev(true, true, true), Connection::Connected);
    }

    /// If capture is not routed there we are not sending, so `alive` says
    /// nothing the user needs to act on. Flagging it would cry wolf on every
    /// switched-off device.
    #[test]
    fn an_inactive_device_is_not_flagged() {
        assert_eq!(
            dev(true, false, false),
            Connection::Off,
            "switched off here and connected in: nothing this machine sends is \
             refused, and the switch is what the row must say"
        );
    }

    /// Reported from the rig minutes after the build landed: every configured
    /// device read "not accepting input" before anything had crossed. `alive`
    /// is false until the first Pong, and stays false while OFFLINE — so a
    /// predicate that ignores whether a link exists calls "unreachable"
    /// "refusing", which is the exact conflation #92 existed to remove.
    #[test]
    fn an_offline_device_is_not_refusing_it_is_offline() {
        assert_eq!(
            dev_conn(false, true, false, false),
            Connection::NotConnected,
            "a device with no live link is OFFLINE, not refusing. Those need \
             different fixes from the user: one is 'go turn hops on over there', \
             the other is 'go grant it permission'."
        );
    }

    /// And the real case still fires: link up, peer says emulation is off.
    #[test]
    fn a_connected_peer_that_says_no_is_still_flagged() {
        assert_eq!(
            dev_conn(true, true, false, true),
            Connection::NotAcceptingInput
        );
    }

    /// A receive-only peer has no send facet and therefore nothing to refuse.
    #[test]
    fn a_receive_only_peer_is_not_flagged() {
        let mut m = AppModel {
            connected: true,
            ..AppModel::default()
        };
        m.apply(FrontendEvent::AuthorizedUpdated(HashMap::from([(
            FP.to_string(),
            "peer".to_string(),
        )])));
        m.apply(FrontendEvent::DeviceConnected {
            addr: "192.0.2.5:51000".parse().unwrap(),
            fingerprint: FP.into(),
        });
        assert_eq!(m.devices()[0].connection, Connection::Connected);
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
    //! path change is not a new device. Addresses pinned at add-time are a
    //! snapshot; a `.local` name is looked up again when the device is
    //! switched on, and by a machine that dials out after a dial that
    //! reaches nothing.
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
        let mut m = AppModel {
            connected: true,
            ..AppModel::default()
        };
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
        assert_eq!(
            device(&m).connection,
            Connection::NotAcceptingInput,
            "precondition: connected in, and refusing our input"
        );

        // The outbound link closes; the inbound one is still up.
        m.apply(FrontendEvent::State(
            0,
            ClientConfig::default(),
            ClientState {
                active_addr: None,
                ..refusing
            },
        ));
        assert_eq!(
            device(&m).connection,
            Connection::Connected,
            "the outbound link closed and the device still shows as up and refusing"
        );

        m.apply(FrontendEvent::IncomingDisconnected(addr));
        assert_eq!(
            device(&m).connection,
            Connection::NotConnected,
            "the inbound link closed and the device still shows connected"
        );
    }

    /// A peer that connects in and never crosses is shown connected only
    /// while its link is up (#34).
    // LEDGER T148-5 | class B | 6 struct state: AppModel::apply + AppModel::devices()
    #[test]
    fn a_peer_that_never_crossed_reads_down_once_its_link_closes() {
        let addr: std::net::SocketAddr = "192.0.2.5:51000".parse().unwrap();
        let mut m = AppModel {
            connected: true,
            ..AppModel::default()
        };
        m.apply(FrontendEvent::AuthorizedUpdated(HashMap::from([(
            FP.to_string(),
            "peer".to_string(),
        )])));
        m.apply(FrontendEvent::DeviceConnected {
            addr,
            fingerprint: FP.into(),
        });
        assert_eq!(device(&m).connection, Connection::Connected);
        m.apply(FrontendEvent::IncomingDisconnected(addr));
        assert_eq!(device(&m).connection, Connection::NotConnected);
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

    /// The same machine added twice, once by name and once by address: one
    /// card, whose name and controls come from the same entry, the first
    /// added (#12). The name came from one entry and the handle every button
    /// acts on from the other.
    // LEDGER T9902 | class B | 6 struct state: AppModel::devices()
    #[test]
    fn a_machine_added_twice_is_one_card_named_and_driven_by_one_entry() {
        let desk = "73:90:2a:3c:9d:e5";
        for (first, second) in [
            (Some("desk-mac.local"), Some("192.0.2.10")),
            (Some("192.0.2.10"), Some("desk-mac.local")),
            (Some("desk-mac.local"), Some("den")),
        ] {
            let mut m = AppModel::default();
            m.clients.insert(3, client(first, Some(desk)));
            m.clients.insert(7, client(second, Some(desk)));
            m.authorized
                .insert(desk.to_string(), "desk mac".to_string());
            let devices = m.devices();
            let cards: Vec<(&str, Option<u64>, Option<&str>)> = devices
                .iter()
                .map(|d| {
                    let send = d.send.as_ref();
                    (
                        d.label.as_str(),
                        send.map(|s| s.handle),
                        send.and_then(|s| s.config.hostname.as_deref()),
                    )
                })
                .collect();
            let named = match first {
                Some(h) if h.parse::<std::net::IpAddr>().is_err() => h,
                _ => "desk mac",
            };
            assert_eq!(
                cards,
                [(named, Some(3), first)],
                "(name, the handle its buttons act on, that handle's hostname): \
                 {first:?} then {second:?}, both the desk. The card has to be the \
                 first entry's, name and buttons both"
            );
        }
    }

    /// A device the user named is shown by that name, whatever it is dialled
    /// at and whatever its pairing called it, connected or not (#13). The
    /// name used to be the hostname, so naming it changed where it dialled.
    // LEDGER T9906 | class B | 6 struct state: AppModel::devices()
    #[test]
    fn a_named_device_is_shown_by_its_name_and_not_its_address() {
        let desk = "73:90:2a:3c:9d:e5";
        let named = |host: &str, pin: Option<&str>| {
            let (mut config, state) = client(Some(host), pin);
            config.label = Some("den".to_string());
            (config, state)
        };
        let mut m = AppModel::default();
        m.clients.insert(0, named("desk-mac.local", Some(desk)));
        m.clients.insert(1, named("192.0.2.11", None));
        m.authorized
            .insert(desk.to_string(), "desk mac".to_string());
        let labels: Vec<(Option<u64>, String)> = m
            .devices()
            .into_iter()
            .map(|d| (d.send.map(|s| s.handle), d.label))
            .collect();
        assert_eq!(
            labels,
            [(Some(0), "den".to_string()), (Some(1), "den".to_string())],
            "a paired device and a device never connected, both named den, were \
             not shown as den"
        );
    }

    /// A device whose machine refused this one as unknown, because it
    /// removed this machine, keeps its card, says so, and keeps its send
    /// facet, which is what the remove button acts on (#184). Every other
    /// card does not say so.
    // LEDGER R184-5 | class B | 6 struct state: AppModel::apply, AppModel::devices, Device::connection
    #[test]
    fn a_device_whose_machine_removed_this_one_says_so_and_can_be_removed() {
        let fp = "aa:bb:cc:dd";
        let mut m = AppModel {
            connected: true,
            ..AppModel::default()
        };
        m.authorized.insert(fp.to_string(), "desk".into());
        let (config, mut state) = client(Some("desk"), Some(fp));
        state.active = true;
        m.apply(FrontendEvent::Created(3, config.clone(), state.clone()));
        let devices = m.devices();
        assert_eq!(
            devices[0].connection,
            super::Connection::NotConnected,
            "a card said its machine removed this one before it was told"
        );
        state.removed_by_peer = true;
        m.apply(FrontendEvent::State(3, config, state));
        let devices = m.devices();
        assert_eq!(devices.len(), 1, "still one card");
        assert_eq!(
            devices[0].connection,
            super::Connection::NoLongerTrusts,
            "the card does not say so"
        );
        assert!(devices[0].is_listable(), "the card left the list");
        assert_eq!(
            devices[0].send.as_ref().map(|s| s.handle),
            Some(3),
            "the card lost the handle its remove button acts on"
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
        let mut m = AppModel {
            connected: true,
            ..AppModel::default()
        };
        let fp = "aa:bb:cc:dd";
        m.authorized
            .insert(fp.to_string(), "studio-mac".to_string());
        m.apply(FrontendEvent::DeviceConnected {
            addr: "192.0.2.5:50001".parse().unwrap(),
            fingerprint: fp.into(),
        });
        let devices = m.devices();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].connection, super::Connection::Connected);
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

    /// A machine refused in the background is a line in the log. Anyone on
    /// the network can cause one, so it must never raise the error banner.
    // LEDGER T2372 | class B | 6 struct state: AppModel::apply, messages and latest_error
    #[test]
    fn a_background_refusal_is_activity_and_never_an_error() {
        let mut m = AppModel::default();
        let line = "Refused a connection from 192.0.2.7: it is not paired to control this \
                    machine, and add device is not open here.";
        m.apply(FrontendEvent::Activity(line.into()));
        assert_eq!(
            m.latest_message(),
            Some(line),
            "a background refusal must be the log's latest line, as it was sent"
        );
        assert_eq!(
            (m.latest_error(), m.error_seq),
            (None, 0),
            "a background refusal raised the error banner"
        );
    }

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
                    FrontendEvent::CaptureStatus(CaptureState::Enabled),
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
                        quiet: false,
                    },
                ] {
                    first.events.unbounded_send(Ok(event)).expect("open");
                }
                until(&client, "the device reads live", |m| {
                    m.connected_peers.contains(FP)
                        && m.devices()
                            .iter()
                            .any(|d| d.send.as_ref().is_some_and(|s| s.state.alive))
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
                    .request_on(
                        super::new_device("desk-mac.local", vec![], 4242, Position::Right)
                            .expect("a device that can be added"),
                    )
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
                // Nothing reported yet by the daemon now answering: a device
                // the last one saw connected in is not connected in to this
                // one until it says so.
                let fresh = client.snapshot();
                assert!(
                    fresh
                        .devices()
                        .iter()
                        .all(|d| d.connection != Connection::Connected),
                    "the next daemon has reported no peer, and a device still \
                     reads connected: {:?}",
                    fresh.devices()
                );
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
                    d.connection == Connection::ServiceGone
                        && !s.state.alive
                        && s.state.active_addr.is_none(),
                    "with no daemon the device still reads connected or up: \
                     {:?} alive {} link {:?}",
                    d.connection,
                    s.state.alive,
                    s.state.active_addr
                );
                assert!(
                    gone.pairing_seconds_left(Instant::now()).is_none()
                        && gone.capture == CaptureState::Disabled,
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

#[cfg(test)]
mod pick_the_number {
    //! The pairing cards across an approval (#11, #167): the approve card
    //! gives way once the pairing waits for its number, and the number card
    //! lives from the daemon's check until it says the check is over.

    use super::*;

    const FP: &str = "cd:cd:cd";

    fn pending() -> FrontendEvent {
        FrontendEvent::TrustUpdated(HashMap::from([(
            FP.to_string(),
            PeerTrust {
                pending: true,
                ..Default::default()
            },
        )]))
    }

    // LEDGER G-18 | class B | 1 return value: PairingCard::show after AppModel::apply
    /// Approving a machine answers its request, in either direction: the
    /// approve card goes once the pairing waits for its number, rather than
    /// staying on screen until the request goes stale.
    #[test]
    fn an_approval_retires_its_card_once_the_pairing_waits_for_the_number() {
        for origin in [AttemptOrigin::Inbound, AttemptOrigin::OutboundDial] {
            let mut m = AppModel::default();
            m.apply(FrontendEvent::ConnectionAttempt {
                fingerprint: FP.into(),
                origin,
                addr: None,
            });
            let mut card = PairingCard::default();
            let now = Instant::now();
            assert!(card.show(&m, now, |_| false).is_some(), "precondition");
            m.apply(pending());
            assert!(
                card.show(&m, now, |_| false).is_none(),
                "the {origin:?} request is still asking to be approved after its \
                 approval"
            );
            assert_eq!(
                m.clipboard(FP),
                None,
                "a pairing that grants nothing offers a clipboard switch"
            );
        }
    }

    // LEDGER G-19 | class B | 6 struct state: AppModel::pairing_check after AppModel::apply
    /// The number card shows the check the daemon sent, follows the answer
    /// given here, and goes when the daemon says the check is over or the
    /// daemon is gone.
    #[test]
    fn the_number_card_lives_from_its_check_to_its_end() {
        let mut m = AppModel::default();
        let check = |answered| FrontendEvent::PairingCheck {
            fingerprint: FP.into(),
            addr: None,
            check: PairingCheck::Pick(vec!["1".into(), "2".into(), "3".into()]),
            answered,
        };
        m.apply(check(false));
        let card = m.pairing_check().expect("a number card");
        assert_eq!(
            card.check,
            PairingCheck::Pick(vec!["1".into(), "2".into(), "3".into()])
        );
        assert_eq!(
            card.answer("2"),
            FrontendRequest::ConfirmPairing {
                fingerprint: FP.into(),
                number: "2".into()
            }
        );
        m.apply(check(true));
        assert_eq!(m.pairing_checks.len(), 1, "the answer made a second card");
        assert!(m.pairing_check().is_some_and(|c| c.answered));
        m.apply(FrontendEvent::PairingEnded {
            fingerprint: FP.into(),
            paired: true,
        });
        assert!(m.pairing_check().is_none(), "the card outlived its check");

        m.apply(check(false));
        m.daemon_gone();
        assert!(
            m.pairing_check().is_none(),
            "a number card outlived the daemon that asked"
        );
    }
}

#[cfg(test)]
mod capture_that_cannot_run {
    //! What a frontend says about a capture that failed (#91).

    use super::{AppModel, CaptureFault, CaptureState, FrontendEvent, Permission};

    fn said(state: CaptureState) -> Option<String> {
        let mut m = AppModel::default();
        m.apply(FrontendEvent::CaptureStatus(state));
        m.capture_problem()
    }

    // LEDGER T8 | class B | 1 return value: AppModel::apply then AppModel::capture_problem
    #[test]
    fn a_missing_permission_is_named_with_where_to_turn_it_on() {
        let missing = |p: &[Permission]| CaptureState::Failed(CaptureFault::Missing(p.to_vec()));
        assert_eq!(
            [
                said(missing(&[Permission::InputMonitoring])),
                said(missing(&[
                    Permission::Accessibility,
                    Permission::InputMonitoring
                ])),
                said(CaptureState::Failed(CaptureFault::Backend(
                    "no backend available".into()
                ))),
                said(CaptureState::Disabled),
                said(CaptureState::Enabled),
            ],
            [
                Some(
                    "Input capture cannot run: macOS does not grant hops Input Monitoring, \
                     which this Mac needs to control other machines. Turn hops on under \
                     System Settings → Privacy & Security → Input Monitoring."
                        .to_string()
                ),
                Some(
                    "Input capture cannot run: macOS does not grant hops Accessibility and \
                     Input Monitoring, which this Mac needs to control other machines. Turn \
                     hops on under System Settings → Privacy & Security, in both \
                     Accessibility and Input Monitoring."
                        .to_string()
                ),
                Some("Input capture is not running: no backend available".to_string()),
                None,
                None,
            ]
        );
    }
}

#[cfg(test)]
mod a_refused_crossing {
    //! A crossing that left the pointer on this machine is said in the
    //! banner, naming the device as its card does and saying why (#115).
    use super::*;

    fn device(hostname: &str, peer_fp: Option<&str>) -> (ClientConfig, ClientState) {
        let config = ClientConfig {
            hostname: Some(hostname.to_string()),
            ..Default::default()
        };
        let state = ClientState {
            peer_fingerprint: peer_fp.map(String::from),
            ..Default::default()
        };
        (config, state)
    }

    // LEDGER T115-8 | class B | 6 struct state: AppModel::apply, latest_error/error_seq
    #[test]
    fn a_refused_crossing_names_the_device_and_the_reason_in_the_banner() {
        let mut m = AppModel::default();
        m.apply(FrontendEvent::Created(
            3,
            device("studio-pc", None).0,
            device("studio-pc", None).1,
        ));
        let seq = m.error_seq;

        m.apply(FrontendEvent::CrossingRefused {
            handle: 3,
            reason: CrossingRefusal::NotConnected,
        });
        assert!(
            m.error_seq > seq,
            "a refused crossing must raise the banner"
        );
        assert_eq!(
            m.latest_error(),
            Some(
                "studio-pc is not paired yet, so the pointer stayed here. Pair the two \
                 machines, then try again."
            ),
            "a device added and never paired, as in #115"
        );

        // Paired, and its link down.
        let fp = "aa:bb:cc:dd";
        let (config, state) = device("desk-mac", Some(fp));
        m.apply(FrontendEvent::Created(4, config, state));
        m.authorized.insert(fp.to_string(), "desk-mac".to_string());
        m.apply(FrontendEvent::CrossingRefused {
            handle: 4,
            reason: CrossingRefusal::NotConnected,
        });
        assert!(
            m.latest_error()
                .is_some_and(|e| e.starts_with("desk-mac is not connected")),
            "a paired device that is not connected: {:?}",
            m.latest_error()
        );

        m.apply(FrontendEvent::CrossingRefused {
            handle: 4,
            reason: CrossingRefusal::Unanswered,
        });
        assert_eq!(
            m.latest_error(),
            Some("desk-mac did not answer the crossing, so the pointer came back.")
        );

        // Pinned to a machine this one was never given permission to drive:
        // not paired yet, not a permission it lost.
        let (config, state) = device("studio-mac", Some("ee:ff"));
        m.apply(FrontendEvent::Created(5, config, state));
        m.apply(FrontendEvent::CrossingRefused {
            handle: 5,
            reason: CrossingRefusal::NotPermitted,
        });
        assert!(
            m.latest_error()
                .is_some_and(|e| e.starts_with("studio-mac is not paired yet")),
            "a device never paired was said to be one this machine may no longer control: {:?}",
            m.latest_error()
        );
        m.apply(FrontendEvent::CrossingRefused {
            handle: 4,
            reason: CrossingRefusal::NotPermitted,
        });
        assert_eq!(
            m.latest_error(),
            Some("This machine may no longer control desk-mac, so the pointer stayed here.")
        );
    }
}

#[cfg(test)]
mod the_state_follows_the_events {
    //! What the model derives a device's state from, driven through the
    //! daemon events that carry it (#148).
    use super::*;

    const FP: &str = "aa:bb";
    const HANDLE: ClientHandle = 0;

    fn linked(active: bool, link: bool) -> ClientState {
        ClientState {
            active,
            alive: true,
            active_addr: link.then(|| "192.0.2.5:4242".parse().expect("addr")),
            peer_fingerprint: Some(FP.into()),
            ..Default::default()
        }
    }

    fn paired() -> AppModel {
        let mut m = AppModel {
            connected: true,
            ..AppModel::default()
        };
        m.apply(FrontendEvent::TrustUpdated(HashMap::from([(
            FP.to_string(),
            PeerTrust {
                clipboard_from: true,
                clipboard_to: true,
                pending: false,
                ..Default::default()
            },
        )])));
        m.apply(FrontendEvent::Enumerate(vec![(
            HANDLE,
            ClientConfig::default(),
            linked(true, false),
        )]));
        m
    }

    fn state(m: &AppModel) -> Connection {
        m.devices()[0].connection
    }

    fn refused(m: &mut AppModel) {
        m.apply(FrontendEvent::CrossingRefused {
            handle: HANDLE,
            reason: CrossingRefusal::NotConnected,
        });
    }

    fn set(m: &mut AppModel, s: ClientState) {
        m.apply(FrontendEvent::State(HANDLE, ClientConfig::default(), s));
    }

    // LEDGER T148-6 | class B | 6 struct state: AppModel::apply + AppModel::devices()
    #[test]
    fn a_crossing_that_found_no_link_reads_unreachable_until_one_comes_up() {
        let mut m = paired();
        assert_eq!(state(&m), Connection::NotConnected, "precondition");

        refused(&mut m);
        assert_eq!(state(&m), Connection::Unreachable);

        // The dial the crossing started lands.
        set(&mut m, linked(true, true));
        assert_eq!(state(&m), Connection::Connected);

        // It closes again: down, and nothing has failed since.
        set(&mut m, linked(true, false));
        assert_eq!(
            state(&m),
            Connection::NotConnected,
            "a crossing refused before the last link came up still reads"
        );

        // Switched off, and back on, forgets a refused crossing.
        refused(&mut m);
        set(&mut m, linked(false, false));
        assert_eq!(state(&m), Connection::Off);
        set(&mut m, linked(true, false));
        assert_eq!(
            state(&m),
            Connection::NotConnected,
            "survived switching off"
        );

        // As does a lost service.
        refused(&mut m);
        m.daemon_gone();
        assert_eq!(state(&m), Connection::ServiceGone);
        m.connected = true;
        assert_eq!(state(&m), Connection::NotConnected, "survived the service");
    }

    // LEDGER T13 | class B | 6 struct state: AppModel::apply + AppModel::devices()
    /// A device whose machine dials this one to be controlled from here
    /// (#15) reads "waiting for it to dial" while its link is down, and
    /// connected once the link it dialled is up. A crossing that finds it
    /// down does not call it unreachable: this machine never dials it.
    #[test]
    fn a_device_that_dials_in_is_waited_for_until_its_link_is_up() {
        let dials_us = |link: bool| ClientState {
            dials_us: true,
            ..linked(true, link)
        };
        let mut m = paired();
        set(&mut m, dials_us(false));
        assert_eq!(state(&m), Connection::AwaitingItsDial);
        assert_eq!(m.devices()[0].connection.words(), "waiting for it to dial");

        refused(&mut m);
        assert_eq!(
            state(&m),
            Connection::AwaitingItsDial,
            "a crossing called a device this machine never dials unreachable"
        );

        set(&mut m, dials_us(true));
        assert_eq!(state(&m), Connection::Connected);
        set(&mut m, dials_us(false));
        assert_eq!(state(&m), Connection::AwaitingItsDial);
    }

    fn connected_in(m: &mut AppModel) {
        m.apply(FrontendEvent::DeviceConnected {
            addr: "192.0.2.5:51000".parse().expect("addr"),
            fingerprint: FP.into(),
        });
    }

    /// The other machine's link in is a fact about its direction. It does
    /// not hide the switch here, a dial from here that failed, or a
    /// pairing in progress, which the terminal row is the only place to
    /// read.
    // LEDGER T148-12 | class B | 6 struct state: AppModel::apply + AppModel::devices()
    #[test]
    fn the_link_in_hides_neither_the_switch_nor_a_failed_dial() {
        let mut m = paired();
        connected_in(&mut m);
        assert_eq!(state(&m), Connection::Connected, "precondition");

        refused(&mut m);
        assert_eq!(
            state(&m),
            Connection::Unreachable,
            "a dial from here failed while the device was connected in"
        );

        set(&mut m, linked(false, false));
        assert_eq!(
            state(&m),
            Connection::Off,
            "switched off here while the device is connected in"
        );
        set(&mut m, linked(true, false));
        assert_eq!(state(&m), Connection::Connected, "on again, still in");

        m.apply(FrontendEvent::TrustUpdated(HashMap::from([(
            FP.to_string(),
            PeerTrust {
                pending: true,
                ..Default::default()
            },
        )])));
        m.apply(FrontendEvent::PairingCheck {
            fingerprint: FP.into(),
            addr: None,
            check: PairingCheck::Show("042917".into()),
            answered: false,
        });
        assert_eq!(
            state(&m),
            Connection::ComparingNumber,
            "a number to compare, with the device connected in"
        );
    }

    /// Only a crossing refused for want of a link says the device could not
    /// be reached. One refused because this machine may not drive it says
    /// nothing about the network.
    // LEDGER T148-13 | class B | 6 struct state: AppModel::apply + AppModel::devices()
    #[test]
    fn a_crossing_refused_for_another_reason_is_not_unreachable() {
        let mut m = paired();
        m.apply(FrontendEvent::CrossingRefused {
            handle: HANDLE,
            reason: CrossingRefusal::NotPermitted,
        });
        assert_eq!(
            state(&m),
            Connection::NotConnected,
            "a crossing this machine may not make reads as a network failure"
        );
    }

    /// The mark belongs to the device on its handle. A list that still has
    /// it down keeps it; one with its link up, or without it, drops it, and
    /// so does its removal, so a device that later gets the same handle
    /// starts clean.
    // LEDGER T148-14 | class B | 6 struct state: AppModel::apply + AppModel::devices()
    #[test]
    fn a_fresh_list_or_a_removal_settles_the_mark() {
        let list = |m: &mut AppModel, devices: Vec<ClientState>| {
            m.apply(FrontendEvent::Enumerate(
                devices
                    .into_iter()
                    .map(|s| (HANDLE, ClientConfig::default(), s))
                    .collect(),
            ));
        };
        let mut m = paired();
        refused(&mut m);
        list(&mut m, vec![linked(true, false)]);
        assert_eq!(
            state(&m),
            Connection::Unreachable,
            "still down, still failed"
        );

        list(&mut m, vec![linked(true, true)]);
        assert_eq!(state(&m), Connection::Connected, "precondition");
        list(&mut m, vec![linked(true, false)]);
        assert_eq!(
            state(&m),
            Connection::NotConnected,
            "a list with the link up did not clear the mark"
        );

        refused(&mut m);
        list(&mut m, vec![]);
        m.apply(FrontendEvent::Created(
            HANDLE,
            ClientConfig::default(),
            linked(true, false),
        ));
        assert_eq!(
            state(&m),
            Connection::NotConnected,
            "a list without the device did not clear the mark"
        );

        refused(&mut m);
        m.apply(FrontendEvent::Deleted(HANDLE));
        m.apply(FrontendEvent::Created(
            HANDLE,
            ClientConfig::default(),
            linked(true, false),
        ));
        assert_eq!(
            state(&m),
            Connection::NotConnected,
            "a new device on a removed one's handle inherited its mark"
        );
    }

    /// The machine this one dials removed it (#184). That machine refuses
    /// everything this one sends, so the row says so over a link reported
    /// up or refusing, over the switch here and over a failed crossing;
    /// once a link to it is up again the daemon clears it and the row reads
    /// its link.
    // LEDGER T148-16 | class B | 6 struct state: AppModel::apply + AppModel::devices()
    #[test]
    fn a_machine_that_removed_this_one_outranks_its_link_and_the_switch() {
        let removed = |s: ClientState| ClientState {
            removed_by_peer: true,
            ..s
        };
        let mut m = paired();
        let mut refusing = linked(true, true);
        refusing.alive = false;
        set(&mut m, refusing.clone());
        assert_eq!(state(&m), Connection::NotAcceptingInput, "precondition");
        set(&mut m, removed(refusing));
        assert_eq!(
            state(&m),
            Connection::NoLongerTrusts,
            "a refusing link hid that the machine removed this one"
        );
        set(&mut m, removed(linked(true, true)));
        assert_eq!(
            state(&m),
            Connection::NoLongerTrusts,
            "a link up hid that the machine removed this one"
        );

        connected_in(&mut m);
        set(&mut m, removed(linked(false, false)));
        assert_eq!(
            state(&m),
            Connection::NoLongerTrusts,
            "the switch here, or a link in, hid it"
        );
        set(&mut m, removed(linked(true, false)));
        refused(&mut m);
        assert_eq!(
            state(&m),
            Connection::NoLongerTrusts,
            "a failed crossing hid it"
        );

        set(&mut m, linked(true, true));
        assert_eq!(
            state(&m),
            Connection::Connected,
            "the machine answers again and the row still says it does not"
        );
    }

    // LEDGER T148-7 | class B | 6 struct state: AppModel::apply + AppModel::devices()
    #[test]
    fn a_crossing_refused_on_a_link_still_connecting_is_not_unreachable() {
        let mut m = paired();
        let mut up = linked(true, true);
        up.alive = false;
        set(&mut m, up.clone());
        refused(&mut m);
        set(
            &mut m,
            ClientState {
                active_addr: None,
                ..up
            },
        );
        assert_eq!(
            state(&m),
            Connection::NotConnected,
            "the crossing was refused while the link was up, so nothing about \
             reaching the device failed"
        );
    }

    // LEDGER T148-8 | class B | 6 struct state: AppModel::apply + AppModel::devices()
    #[test]
    fn a_pairing_reads_from_approval_to_the_number_and_back() {
        let mut m = AppModel {
            connected: true,
            ..AppModel::default()
        };
        m.apply(FrontendEvent::Enumerate(vec![(
            HANDLE,
            ClientConfig::default(),
            linked(true, false),
        )]));
        assert_eq!(state(&m), Connection::NotPaired, "precondition");

        m.apply(FrontendEvent::TrustUpdated(HashMap::from([(
            FP.to_string(),
            PeerTrust {
                pending: true,
                ..Default::default()
            },
        )])));
        assert_eq!(state(&m), Connection::AwaitingOtherMachine);

        let check = |answered| FrontendEvent::PairingCheck {
            fingerprint: FP.into(),
            addr: None,
            check: PairingCheck::Show("042917".into()),
            answered,
        };
        m.apply(check(false));
        assert_eq!(state(&m), Connection::ComparingNumber);
        m.apply(check(true));
        assert_eq!(state(&m), Connection::AwaitingOtherMachine);

        m.apply(FrontendEvent::PairingEnded {
            fingerprint: FP.into(),
            paired: true,
        });
        m.apply(FrontendEvent::TrustUpdated(HashMap::from([(
            FP.to_string(),
            PeerTrust::default(),
        )])));
        assert_eq!(state(&m), Connection::NotConnected);
        set(&mut m, linked(true, true));
        assert_eq!(state(&m), Connection::Connected);
    }
}
