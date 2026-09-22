use crate::config::{local_caps, local_commit};
use crate::listen::{LanMouseListener, ListenEvent, ListenerCreationError};
use futures::{FutureExt, StreamExt};
use hops_proto::{Position, ProtoEvent};
use input_emulation::{EmulationHandle, InputEmulation, InputEmulationError};
use input_event::{Event, PointerEvent};
use local_channel::mpsc::{Receiver, Sender, channel};
use std::{
    cell::Cell,
    collections::VecDeque,
    collections::{HashMap, HashSet},
    net::SocketAddr,
    rc::Rc,
    time::{Duration, Instant},
};
use tokio::{
    select,
    task::{JoinHandle, spawn_local},
};

/// emulation handling events received from a listener
pub(crate) struct Emulation {
    /// shared with the proxy: when a peer last injected input into this machine
    last_injected: Rc<Cell<Option<Instant>>>,
    task: JoinHandle<()>,
    request_tx: Sender<EmulationRequest>,
    event_rx: Receiver<EmulationEvent>,
}

pub(crate) enum EmulationEvent {
    /// Input emulation fell back to a backend that DISCARDS events. Raised so
    /// this reaches the user instead of being a log line they never see.
    BackendDegraded(String),
    Connected {
        addr: SocketAddr,
        fingerprint: String,
    },
    ConnectionAttempt {
        fingerprint: String,
    },
    /// new connection
    Entered {
        /// address of the connection
        addr: SocketAddr,
        /// position of the connection
        pos: hops_ipc::Position,
        /// certificate fingerprint of the connection
        fingerprint: String,
    },
    /// connection closed
    Disconnected {
        addr: SocketAddr,
    },
    /// the port of the listener has changed
    PortChanged(Result<u16, ListenerCreationError>),
    /// emulation was disabled
    EmulationDisabled,
    /// emulation was enabled
    EmulationEnabled,
    /// capture should be released
    ReleaseNotify,
    /// the remote-controlled cursor was deliberately pushed past a screen
    /// edge on this device (adaptive edge crossing, receiver side). The
    /// service decides whether that edge belongs to the controlling peer
    /// and, if so, hands the cursor back.
    EdgePushed {
        /// peer whose input pushed the edge
        addr: SocketAddr,
        /// which edge was pushed
        side: hops_ipc::Position,
    },
    /// peer sent us a Hello with its build commit hash. Used to
    /// populate `client_manager.peer_commit` from the listen side
    /// too — without this, peer-version visibility silently fails
    /// whenever the outgoing connection in the *other* direction is
    /// broken (one-way setups, asymmetric NAT, peer's TCP listener
    /// down). The connect-side path stays as the primary source;
    /// this is the defensive fallback.
    PeerHello {
        addr: SocketAddr,
        commit: [u8; 8],
    },
    /// peer sent us a Capability event advertising its supported
    /// features. Routed upward (mirroring `PeerHello`) so the service
    /// can record it via `client_manager.set_peer_caps` — the receiver
    /// side needs the sender's caps to gate the future Trueloop
    /// return-channel, just as the sender needs the receiver's.
    PeerCaps {
        addr: SocketAddr,
        flags: u32,
    },
}

enum EmulationRequest {
    Reenable,
    Release(SocketAddr),
    ChangePort(u16),
    Terminate,
}

impl Emulation {
    pub(crate) fn new(
        backend: Option<input_emulation::Backend>,
        listener: LanMouseListener,
        trust: crate::transport::Trust,
    ) -> Self {
        let emulation_proxy = EmulationProxy::new(backend, listener.pressure());
        let last_injected = emulation_proxy.last_injected.clone();
        let (request_tx, request_rx) = channel();
        let (event_tx, event_rx) = channel();
        let emulation_task = ListenTask {
            listener,
            emulation_proxy,
            request_rx,
            event_tx,
            trust,
            peer_of: HashMap::new(),
        };
        let task = spawn_local(emulation_task.run());
        Self {
            last_injected,
            task,
            request_tx,
            event_rx,
        }
    }

    /// True if a peer injected input into this machine within `window`.
    /// See `EmulationProxy::remotely_driven_within`.
    pub(crate) fn remotely_driven_within(&self, window: Duration) -> bool {
        self.last_injected
            .get()
            .is_some_and(|t| t.elapsed() < window)
    }

    pub(crate) fn send_leave_event(&self, addr: SocketAddr) {
        self.request_tx
            .send(EmulationRequest::Release(addr))
            .expect("channel closed");
    }

    pub(crate) fn reenable(&self) {
        self.request_tx
            .send(EmulationRequest::Reenable)
            .expect("channel closed");
    }

    pub(crate) fn request_port_change(&self, port: u16) {
        self.request_tx
            .send(EmulationRequest::ChangePort(port))
            .expect("channel closed")
    }

    pub(crate) async fn event(&mut self) -> EmulationEvent {
        self.event_rx.recv().await.expect("channel closed")
    }

    /// wait for termination
    pub(crate) async fn terminate(&mut self) {
        log::debug!("terminating emulation");
        self.request_tx
            .send(EmulationRequest::Terminate)
            .expect("channel closed");
        if let Err(e) = (&mut self.task).await {
            log::warn!("{e}");
        }
    }
}

/// Reconstructs per-event relative deltas from the cumulative absolute
/// displacement carried by [`ProtoEvent::PointerMotionAbsolute`] (Stage 2).
/// Each peer's displacement is anchored at (0,0) on Enter — matching the
/// sender resetting its cumulative displacement at each crossing — and the
/// reconstructed delta is `current − previous`. Absolute displacement is
/// self-correcting: a lost or reordered update just means the next delta
/// spans the gap, so no drift accumulates (unlike a relative-delta stream).
/// The reconstructed delta is fed to the UNCHANGED injection path (the clamp
/// + edge detector on the macOS side), so the crown-jewel motion arm is
///   untouched.
///
/// Contract PR-4's sender must uphold: motion is emitted ONLY after the Enter
/// is acked. hops's capture state machine already enforces this — every event
/// during `State::WaitingForAck` becomes an Enter re-send (`capture.rs`), and
/// `PointerMotionAbsolute` would be emitted only in `State::Sending`. So every
/// `anchor()` (one per Enter re-send) lands before the first motion, and the
/// last — at the WaitingForAck→Sending boundary — is the live anchor. If a
/// future sender ever emitted motion before the Ack, this baseline would be
/// wrong; it must not.
#[derive(Default)]
struct AbsMotionReconstructor {
    prev: HashMap<SocketAddr, (f32, f32)>,
}

impl AbsMotionReconstructor {
    /// Anchor this peer at the origin — call on Enter, matching the sender's
    /// reset of its cumulative displacement at each crossing.
    fn anchor(&mut self, addr: SocketAddr) {
        self.prev.insert(addr, (0.0, 0.0));
    }

    /// Reconstruct the relative delta (f64, for the injection path) from a
    /// cumulative (vx, vy) update. A never-seen peer defaults to the origin,
    /// so a stray update before Enter degrades to "delta == absolute" rather
    /// than a jump from stale state.
    fn delta(&mut self, addr: SocketAddr, vx: f32, vy: f32) -> (f64, f64) {
        let (px, py) = self.prev.get(&addr).copied().unwrap_or((0.0, 0.0));
        self.prev.insert(addr, (vx, vy));
        ((vx - px) as f64, (vy - py) as f64)
    }

    /// Drop this peer's state — call on Leave/disconnect.
    fn forget(&mut self, addr: SocketAddr) {
        self.prev.remove(&addr);
    }
}

struct ListenTask {
    listener: LanMouseListener,
    emulation_proxy: EmulationProxy,
    request_rx: Receiver<EmulationRequest>,
    event_tx: Sender<EmulationEvent>,
    /// The store, so an expiring lease is refused AT THE POINT OF INJECTION.
    ///
    /// The sweep on the service loop catches a lapse eventually, but a timer is
    /// something a busy thread can delay. This check cannot be delayed, because
    /// it rides the attacker's own code path: to keep injecting, they have to
    /// execute it. That is the difference between a lease and a label.
    ///
    /// No lease lapses in this release (#183), so today what this refuses is a
    /// removed device; the lapse half is kept for when a term returns (#185).
    trust: crate::transport::Trust,
    /// Which peer each admitted address belongs to. Populated on accept, so the
    /// per-event check is a map lookup rather than a certificate parse.
    peer_of: HashMap<SocketAddr, String>,
}

/// The per-event check: may the peer admitted at `addr` inject input right now?
///
/// Asked for every input event, against the store as it is at that moment, so
/// a removal bites between two events rather than at the next handshake.
pub(crate) fn input_permitted(
    peer_of: &HashMap<SocketAddr, String>,
    trust: &crate::transport::Trust,
    addr: SocketAddr,
) -> bool {
    peer_of
        .get(&addr)
        .is_some_and(|fp| trust.read().expect("lock").may_drive_us(fp))
}

/// Suppresses repeat approval prompts for a fingerprint that keeps dialling,
/// without letting the memory that does the suppressing grow without bound.
///
/// This was a bare `HashMap` local to the listen task, inserted into and never
/// removed from, so it lived for the life of the daemon. Anyone on the network
/// can add to it: dial with a self-signed certificate we do not know, get
/// rejected, and a fingerprint is recorded. A peer generating a fresh key per
/// dial produces a fresh entry per dial — measured at 120 distinct fingerprints
/// per second from one host, roughly 432,000 permanent entries an hour, in the
/// highest-privilege daemon on the machine.
///
/// Entries exist only to answer "did this exact fingerprint dial within the
/// suppression window", so an entry older than that window has no reader and is
/// simply dropped.
struct RecentRejections {
    seen: HashMap<String, Instant>,
}

impl RecentRejections {
    /// How long a fingerprint stays suppressed after it raises a prompt.
    const WINDOW: Duration = Duration::from_secs(2);

    /// Prune once the map is larger than a real fleet could explain. Chosen so
    /// pruning is rare in normal use and cheap when an attacker forces it.
    const PRUNE_AT: usize = 256;

    fn new() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }

    /// True if this rejection should raise a prompt.
    fn should_notify(&mut self, fingerprint: &str) -> bool {
        let now = Instant::now();

        if self.seen.len() >= Self::PRUNE_AT {
            self.seen
                .retain(|_, first_seen| now.duration_since(*first_seen) < Self::WINDOW);
            // Everything still here is inside the window, which means a flood of
            // distinct fingerprints rather than a fleet. Drop it: the cost is a
            // repeated prompt for a peer that dialled seconds ago, and the
            // alternative is unbounded growth driven by a stranger.
            if self.seen.len() >= Self::PRUNE_AT {
                self.seen.clear();
            }
        }

        match self.seen.insert(fingerprint.to_owned(), now) {
            None => true,
            Some(previous) => now.duration_since(previous) >= Self::WINDOW,
        }
    }
}

impl ListenTask {
    async fn run(mut self) {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        let mut last_response = HashMap::new();
        let mut rejected_connections = RecentRejections::new();
        let mut absmotion = AbsMotionReconstructor::default();
        // Peers released because the trust check refused them, until one of
        // their events is permitted again.
        let mut refused = HashSet::new();
        loop {
            select! {
                e = self.listener.next() => {match e {
                    Some(ListenEvent::Msg { event, addr }) => {
                        log::trace!("{event} <-<-<-<-<- {addr}");
                        last_response.insert(addr, Instant::now());
                        match event {
                            ProtoEvent::Enter(pos) => {
                                if let Some(fingerprint) = self.listener.get_certificate_fingerprint(addr).await {
                                    // per-wire-event (the sender re-sends Enter until the
                                    // Ack); the once-per-crossing "entered" line is logged by
                                    // the service via hop_log::Lifecycle::Entered.
                                    log::trace!("Enter received from {addr}");
                                    self.event_tx.send(EmulationEvent::ReleaseNotify).expect("channel closed");
                                    self.listener.reply(addr, ProtoEvent::Ack(0)).await;
                                    // Anchor absolute-motion reconstruction at this
                                    // crossing (the sender resets its cumulative
                                    // displacement to 0 on Enter). Idempotent across the
                                    // pre-Ack Enter re-sends; motion only arrives after.
                                    absmotion.anchor(addr);
                                    self.event_tx.send(EmulationEvent::Entered{addr, pos: to_ipc_pos(pos), fingerprint}).expect("channel closed");
                                }
                            }
                            ProtoEvent::Leave(_) => {
                                self.emulation_proxy.remove(addr);
                                absmotion.forget(addr);
                                self.listener.reply(addr, ProtoEvent::Ack(0)).await;
                            }
                            ProtoEvent::Input(event) => {
                                // Cheap and unstarvable. Roughly 20 ns against
                                // the ~100 µs blocking syscall that dominates
                                // an injected event, so it is not measurable on
                                // the path it protects.
                                if input_permitted(&self.peer_of, &self.trust, addr) {
                                    if !refused.is_empty() {
                                        refused.remove(&addr);
                                    }
                                    self.emulation_proxy.consume(event, addr);
                                } else if refused.insert(addr) {
                                    // The lease lapsed or was revoked while the
                                    // peer was driving. Its button- and key-ups
                                    // are refused from here on too, so whatever
                                    // it holds would stay down until the session
                                    // is cut and the watchdog notices, which
                                    // takes over a minute after a lapse.
                                    //
                                    // Once per refusal, not per event: absolute
                                    // motion is not refused yet (#156) and
                                    // re-creates the handle, so a release per
                                    // event tore it down and built it again
                                    // for every pair.
                                    log::warn!(
                                        "releasing held keys and buttons: \
                                         {addr} may no longer drive this machine"
                                    );
                                    self.emulation_proxy.remove(addr);
                                }
                            }
                            ProtoEvent::Ping => self.listener.reply(addr, ProtoEvent::Pong(self.emulation_proxy.emulation_active.get())).await,
                            // Peer's version handshake. Echo our own
                            // commit back so the peer's connect-side
                            // receive_loop populates its `peer_commit`,
                            // AND publish a PeerHello upward so our
                            // service can populate ours from the listen
                            // side too — the connect side is the primary
                            // path, but if the outbound direction is
                            // broken (one-way setup, NAT, peer's TCP
                            // listener down) the version display would
                            // otherwise silently say "unknown" while
                            // the peer is in fact happily talking to us.
                            ProtoEvent::Hello { commit } => {
                                self.listener.reply(addr, ProtoEvent::Hello { commit: local_commit() }).await;
                                // Advertise our own capabilities right after the Hello
                                // reply, on the same reply stream (so the peer sees Hello
                                // then Capability, in order). Unconditional: an older
                                // sender that predates the event skips the unknown type
                                // and keeps the connection alive.
                                self.listener.reply(addr, ProtoEvent::Capability { flags: local_caps() }).await;
                                self.event_tx.send(EmulationEvent::PeerHello { addr, commit }).expect("channel closed");
                            }
                            ProtoEvent::Capability { flags } => {
                                self.event_tx.send(EmulationEvent::PeerCaps { addr, flags }).expect("channel closed");
                            }
                            // Stage 2 absolute motion: reconstruct the per-event delta
                            // from the cumulative displacement and feed the UNCHANGED
                            // injection path (clamp + edge detector) as a relative
                            // Motion — the macOS motion arm stays untouched. `seq` is
                            // for the Stage 3 servo; unused here. Inert until a peer
                            // negotiates caps::ABSOLUTE_MOTION and emits these (PR-4).
                            ProtoEvent::PointerMotionAbsolute { seq: _, ts, vx, vy } => {
                                let (dx, dy) = absmotion.delta(addr, vx, vy);
                                self.emulation_proxy.consume(
                                    Event::Pointer(PointerEvent::Motion { time: ts, dx, dy }),
                                    addr,
                                );
                            }
                            _ => {}
                        }
                    }
                    Some(ListenEvent::Accept { addr, fingerprint }) => {
                        self.peer_of.insert(addr, fingerprint.clone());
                        self.event_tx.send(EmulationEvent::Connected { addr, fingerprint }).expect("channel closed");
                    }
                    Some(ListenEvent::Rejected { fingerprint }) => {
                        if rejected_connections.should_notify(&fingerprint) {
                            self.event_tx.send(EmulationEvent::ConnectionAttempt { fingerprint }).expect("channel closed");
                        }
                    }
                    None => break
                }}
                event = self.emulation_proxy.event() => {
                    self.event_tx.send(event).expect("channel closed");
                }
                request = self.request_rx.recv() => match request.expect("channel closed") {
                    // reenable emulation
                    EmulationRequest::Reenable => self.emulation_proxy.reenable(),
                    // notify the other end that we hit a barrier (should release capture)
                    EmulationRequest::Release(addr) => self.listener.reply(addr, ProtoEvent::Leave(0)).await,
                    EmulationRequest::ChangePort(port) => {
                        self.listener.request_port_change(port);
                        let result = self.listener.port_changed().await;
                        self.event_tx.send(EmulationEvent::PortChanged(result)).expect("channel closed");
                    }
                    EmulationRequest::Terminate => break,
                },
                _ = interval.tick() => {
                    last_response.retain(|&addr,instant| {
                        // QUIC keep-alive handles real liveness; only treat a
                        // peer as gone after a long quiet window so normal
                        // pauses / load don't falsely release keys mid-session.
                        if instant.elapsed() > Duration::from_secs(10) {
                            log::warn!("releasing held keys and buttons: {addr} not responding!");
                            self.emulation_proxy.remove(addr);
                            // Forgotten along with the peer.
                            refused.remove(&addr);
                            let _ = self.event_tx.send(EmulationEvent::Disconnected { addr });
                            false
                        } else {
                            true
                        }
                    });
                }
            }
        }
        self.listener.terminate().await;
        self.emulation_proxy.terminate().await;
    }
}

/// proxy handling the actual input emulation,
/// discarding events when it is disabled
pub(crate) struct EmulationProxy {
    /// When a peer last injected input INTO this machine. Read by the service to
    /// refuse trust GRANTS while the cursor is not ours — otherwise a peer that
    /// still holds control can drive the pointer onto an approval button and
    /// click it, manufacturing its own consent.
    last_injected: Rc<Cell<Option<Instant>>>,
    emulation_active: Rc<Cell<bool>>,
    exit_requested: Rc<Cell<bool>>,
    request_tx: Sender<ProxyRequest>,
    event_rx: Receiver<EmulationEvent>,
    metrics: Rc<QueueMetrics>,
    task: JoinHandle<()>,
}

/// How many events the injection loop may consume before handing the runtime
/// back to every other task on the thread.
///
/// The runtime is single-threaded. A peer driving input keeps `request_rx.recv()`
/// ready forever, so without an explicit yield the injection loop is the only
/// thing that runs and a revocation cannot be serviced until the flood stops.
///
/// 8 is measured, not chosen for looking round: yielding every event costs 12.9%
/// of injection throughput, every 8 costs 1.7%, and both bound revoke latency to
/// single-digit milliseconds against 1.811 s unbounded.
///
/// NOT UNIT-TESTED, deliberately. Three attempts to assert the scheduling effect
/// from inside the same runtime were all flaky: `LocalSet` may run several ticks
/// of a spawned task per poll of the outer future, so neither "how much drained
/// before another task ran" nor "was the backlog ever seen partly drained" is
/// deterministic. A flaky test that trains people to re-run until green is worse
/// than an honest gap. The effect is measured end to end instead — revoke
/// latency under a 20,000-event flood — and that belongs in a rig check, not in
/// `cargo test`.
const YIELD_EVERY_N_EVENTS: u32 = 8;

enum ProxyRequest {
    Input(Event, SocketAddr),
    Remove(SocketAddr),
    Terminate,
    Reenable,
}

/// Diagnostic counters for the network→injection queue: input events enqueued
/// (network side) vs injected (emulation side), and the peak backlog between
/// them. The runtime is single-threaded (`spawn_local` + `local_channel`), so a
/// shared `Rc<QueueMetrics>` with `Cell` is safe and lock-free. The emulation
/// task reports these once per second whenever there's input activity — this is
/// how we confirm whether the cursor lag under load is the queue backing up.
#[derive(Default)]
struct QueueMetrics {
    enqueued: Cell<u64>,
    injected: Cell<u64>,
    peak_backlog: Cell<u64>,
}

impl QueueMetrics {
    fn on_enqueue(&self) {
        let enqueued = self.enqueued.get() + 1;
        self.enqueued.set(enqueued);
        let backlog = enqueued.saturating_sub(self.injected.get());
        if backlog > self.peak_backlog.get() {
            self.peak_backlog.set(backlog);
        }
    }

    fn on_inject(&self) {
        self.injected.set(self.injected.get() + 1);
    }
}

impl EmulationProxy {
    fn new(
        backend: Option<input_emulation::Backend>,
        pressure: Rc<crate::listen::InputPressure>,
    ) -> Self {
        let (request_tx, request_rx) = channel();
        let (event_tx, event_rx) = channel();
        let emulation_active = Rc::new(Cell::new(false));
        let exit_requested = Rc::new(Cell::new(false));
        let metrics = Rc::new(QueueMetrics::default());
        let emulation_task = EmulationTask {
            backend,
            exit_requested: exit_requested.clone(),
            request_rx,
            event_tx,
            handles: Default::default(),
            next_id: 0,
            metrics: metrics.clone(),
            queued: Default::default(),
            pressure,
        };
        let task = spawn_local(emulation_task.run());
        Self {
            last_injected: Rc::new(Cell::new(None)),
            emulation_active,
            exit_requested,
            request_tx,
            task,
            event_rx,
            metrics,
        }
    }

    /// True if a peer injected input into this machine within `window`.
    ///
    /// Production reads this through `Emulation`, which shares the same cell;
    /// this exists so the test can drive `consume()` directly without standing up
    /// a listener, hence `cfg(test)` rather than an allow(dead_code).
    #[cfg(test)]
    pub(crate) fn remotely_driven_within(&self, window: Duration) -> bool {
        self.last_injected
            .get()
            .is_some_and(|t| t.elapsed() < window)
    }

    async fn event(&mut self) -> EmulationEvent {
        let event = self.event_rx.recv().await.expect("channel closed");
        if let EmulationEvent::EmulationEnabled = event {
            self.emulation_active.replace(true);
        }
        if let EmulationEvent::EmulationDisabled = event {
            self.emulation_active.replace(false);
        }
        event
    }

    fn consume(&self, event: Event, addr: SocketAddr) {
        // stamped before the enabled-check: what matters is that a REMOTE peer is
        // driving, not whether we happened to act on it
        self.last_injected.set(Some(Instant::now()));
        // ignore events if emulation is currently disabled
        if self.emulation_active.get() {
            self.request_tx
                .send(ProxyRequest::Input(event, addr))
                .expect("channel closed");
            self.metrics.on_enqueue();
        }
    }

    fn remove(&self, addr: SocketAddr) {
        self.request_tx
            .send(ProxyRequest::Remove(addr))
            .expect("channel closed");
    }

    fn reenable(&self) {
        self.request_tx
            .send(ProxyRequest::Reenable)
            .expect("channel closed");
    }

    async fn terminate(&mut self) {
        self.exit_requested.replace(true);
        self.request_tx
            .send(ProxyRequest::Terminate)
            .expect("channel closed");
        let _ = (&mut self.task).await;
    }
}

struct EmulationTask {
    backend: Option<input_emulation::Backend>,
    exit_requested: Rc<Cell<bool>>,
    request_rx: Receiver<ProxyRequest>,
    event_tx: Sender<EmulationEvent>,
    handles: HashMap<SocketAddr, EmulationHandle>,
    next_id: EmulationHandle,
    metrics: Rc<QueueMetrics>,
    /// What waits for injection, one queue per peer.
    queued: PeerQueues,
    /// Peers told to stop sending until their queue drains.
    pressure: Rc<crate::listen::InputPressure>,
}

/// How many requests may wait for one peer before its connection stops
/// reading. Relative motion merges, so an honest mouse never reaches this;
/// what does is a peer sending events that cannot merge faster than this
/// machine can inject them.
const PEER_QUEUE_LIMIT: usize = 256;

/// How many arrived requests are sorted into queues between two injections,
/// so a key from one peer joins its queue while another peer is flooding.
const SORT_BATCH: usize = 64;

/// What one peer has asked for and this machine has not done yet.
enum Queued {
    Input(Event),
    /// Tear the peer's handle down, after everything it sent before.
    Remove,
}

/// Every peer's queue, served in turn (#82).
///
/// Injection used to take requests from one queue in arrival order, so a peer
/// sending faster than this machine injects pushed every other peer's input
/// behind its whole backlog. Now each peer waits in its own queue and each
/// turn injects one request from the next peer that has one.
#[derive(Default)]
struct PeerQueues {
    /// Peers with something queued, in the order they are served.
    turn: VecDeque<SocketAddr>,
    queues: HashMap<SocketAddr, VecDeque<Queued>>,
}

impl PeerQueues {
    /// Queue `item` for `addr`. Consecutive relative motion merges into one
    /// event carrying the sum: the pointer ends up in the same place, and a
    /// fast mouse costs one queue slot, not hundreds. Returns whether it merged
    /// and how many requests now wait for `addr`.
    fn push(&mut self, addr: SocketAddr, item: Queued) -> (bool, usize) {
        let queue = self.queues.entry(addr).or_default();
        if queue.is_empty() {
            self.turn.push_back(addr);
        }
        if let (
            Some(Queued::Input(Event::Pointer(PointerEvent::Motion { time, dx, dy }))),
            Queued::Input(Event::Pointer(PointerEvent::Motion {
                time: later,
                dx: more_x,
                dy: more_y,
            })),
        ) = (queue.back_mut(), &item)
        {
            *dx += *more_x;
            *dy += *more_y;
            *time = *later;
            return (true, queue.len());
        }
        queue.push_back(item);
        (false, queue.len())
    }

    /// The next peer's next request, and how many of that peer's are left.
    fn pop(&mut self) -> Option<(SocketAddr, Queued, usize)> {
        let addr = self.turn.pop_front()?;
        let queue = self.queues.get_mut(&addr)?;
        let item = queue.pop_front()?;
        let left = queue.len();
        if left > 0 {
            self.turn.push_back(addr);
        } else {
            self.queues.remove(&addr);
        }
        Some((addr, item, left))
    }

    fn is_empty(&self) -> bool {
        self.turn.is_empty()
    }

    /// Drop everything, returning how many inputs were waiting.
    fn clear(&mut self) -> u64 {
        let inputs = self
            .queues
            .values()
            .flatten()
            .filter(|q| matches!(q, Queued::Input(_)))
            .count() as u64;
        self.turn.clear();
        self.queues.clear();
        inputs
    }
}

impl EmulationTask {
    async fn run(mut self) {
        loop {
            if let Err(e) = self.do_emulation().await {
                log::warn!("input emulation exited: {e}");
            }
            if self.exit_requested.get() {
                break;
            }
            // wait for reenable request
            loop {
                match self.request_rx.recv().await.expect("channel closed") {
                    ProxyRequest::Reenable => break,
                    ProxyRequest::Terminate => return,
                    // emulation inactive => drop, but keep the backlog counter honest
                    ProxyRequest::Input(..) => self.metrics.on_inject(),
                    ProxyRequest::Remove(..) => { /* emulation inactive => ignore */ }
                }
            }
        }
    }

    async fn do_emulation(&mut self) -> Result<(), InputEmulationError> {
        log::info!("creating input emulation ...");
        let mut emulation = tokio::select! {
            r = InputEmulation::new(self.backend) => r?,
            // allow termination event while requesting input emulation
            _ = wait_for_termination(&mut self.request_rx) => return Ok(()),
        };

        // A fallback to Dummy accepts every event and throws it away while the
        // UI still reports "connected" — this project lost hours to exactly that.
        //
        // Choosing dummy deliberately (config/CLI) is legitimate and stays
        // supported. FALLING INTO it is not: it means every real backend was
        // unavailable, and the honest response is to refuse rather than pretend.
        // The Linux release shipped exactly this for months (#47) — built with
        // no backend features at all, so selection had nowhere to go.
        if emulation.backend() == input_emulation::Backend::Dummy {
            let asked_for_dummy = self.backend == Some(input_emulation::Backend::Dummy);
            let overridden = std::env::var("HOPS_ALLOW_DUMMY").is_ok_and(|v| v != "0");
            let _ = self.event_tx.send(EmulationEvent::BackendDegraded(
                emulation.backend().to_string(),
            ));
            if !asked_for_dummy && !overridden {
                log::error!(
                    "input emulation fell back to `dummy` — all input would be silently \
                     discarded. Refusing. Set HOPS_ALLOW_DUMMY=1 to override."
                );
                return Err(InputEmulationError::NoUsableBackend);
            }
        }

        // used to send enabled and disabled events
        let _emulation_guard = DropGuard::new(
            self.event_tx.clone(),
            EmulationEvent::EmulationEnabled,
            EmulationEvent::EmulationDisabled,
        );

        // create active handles
        if let Err(e) = self.create_clients(&mut emulation).await {
            emulation.terminate().await;
            return Err(e);
        }

        let res = self.do_emulation_session(&mut emulation).await;
        // What was still waiting goes with the session. Its peers may read
        // again, and the backlog counter stays honest.
        let waiting: Vec<SocketAddr> = self.queued.queues.keys().copied().collect();
        for addr in waiting {
            self.pressure.release(addr);
        }
        for _ in 0..self.queued.clear() {
            self.metrics.on_inject();
        }
        // FIXME replace with async drop when stabilized
        emulation.terminate().await;
        res
    }

    async fn create_clients(
        &mut self,
        emulation: &mut InputEmulation,
    ) -> Result<(), InputEmulationError> {
        for handle in self.handles.values() {
            tokio::select! {
                _ = emulation.create(*handle) => {},
                _ = wait_for_termination(&mut self.request_rx) => return Ok(()),
            }
        }
        Ok(())
    }

    async fn do_emulation_session(
        &mut self,
        emulation: &mut InputEmulation,
    ) -> Result<(), InputEmulationError> {
        // 1 Hz diagnostic report of the injection queue (input rate + backlog).
        // Only logs on active seconds, so it's silent when idle.
        let mut report = tokio::time::interval(Duration::from_secs(1));
        report.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut prev_enqueued = self.metrics.enqueued.get();
        let mut injected_since_yield: u32 = 0;
        loop {
            // Sort what has already arrived into its peers' queues first, so a
            // key from one peer joins its queue while another peer floods.
            for _ in 0..SORT_BATCH {
                match self.request_rx.recv().now_or_never() {
                    Some(request) => {
                        if self.sort(request.expect("channel closed")) {
                            return Ok(());
                        }
                    }
                    None => break,
                }
            }
            tokio::select! {
                biased;
                _ = report.tick() => {
                    let enqueued = self.metrics.enqueued.get();
                    let rate = enqueued - prev_enqueued;
                    prev_enqueued = enqueued;
                    if rate > 0 {
                        let backlog = enqueued.saturating_sub(self.metrics.injected.get());
                        let peak = self.metrics.peak_backlog.get();
                        // debug, not info: this fires once per ACTIVE second
                        // with no rotation anywhere, and accounted for the bulk
                        // of a 71.9 MB daemon log over 57 days.
                        log::debug!(
                            "[motion-metrics] {rate} input/s | backlog now {backlog} | peak {peak}"
                        );
                        self.metrics.peak_backlog.set(backlog);
                    }
                }
                _ = std::future::ready(()), if !self.queued.is_empty() => {
                    let (addr, item, left) = self.queued.pop().expect("a peer has something queued");
                    if left < PEER_QUEUE_LIMIT / 2 {
                        self.pressure.release(addr);
                    }
                    match item {
                        Queued::Input(event) => {
                            let handle = match self.handles.get(&addr) {
                                Some(&handle) => handle,
                                None => {
                                    let handle = self.next_id;
                                    self.next_id += 1;
                                    emulation.create(handle).await;
                                    self.handles.insert(addr, handle);
                                    handle
                                }
                            };
                            emulation.consume(event, handle).await?;
                            self.metrics.on_inject();
                            // Hand the runtime back periodically. `local_channel`
                            // recv resolves immediately while the queue is
                            // non-empty, and the runtime is `new_current_thread`
                            // (main.rs:337) — so without this, a peer that floods
                            // input starves every other task on the thread,
                            // including the one that services a revocation. That is
                            // denial-of-revocation by injection: the single most
                            // likely thing an attacker does once discovered.
                            //
                            // Measured, 20,000-event backlog: revoke serviced after
                            // 1.811 s with no yield, ~2 ms yielding every 8, and the
                            // revoke was never serviced mid-flood at all. Yielding
                            // on EVERY event costs 12.9% injection throughput for
                            // 300 µs nobody can perceive; every 8 costs 1.7%.
                            injected_since_yield += 1;
                            if injected_since_yield >= YIELD_EVERY_N_EVENTS {
                                injected_since_yield = 0;
                                tokio::task::yield_now().await;
                            }
                            // adaptive edge: the backend may have concluded this
                            // event was a deliberate push past a screen edge
                            if let Some(side) = emulation.take_edge_push() {
                                self.event_tx
                                    .send(EmulationEvent::EdgePushed {
                                        addr,
                                        side: edge_to_ipc_pos(side),
                                    })
                                    .expect("channel closed");
                            }

                        }
                        Queued::Remove => {
                            if let Some(handle) = self.handles.remove(&addr) {
                                emulation.destroy(handle).await;
                            }
                        }
                    }
                }
                e = self.request_rx.recv() => {
                    if self.sort(e.expect("channel closed")) {
                        break Ok(());
                    }
                }
            }
        }
    }

    /// File one request into its peer's queue. True for `Terminate`.
    fn sort(&mut self, request: ProxyRequest) -> bool {
        match request {
            ProxyRequest::Input(event, addr) => {
                let (merged, waiting) = self.queued.push(addr, Queued::Input(event));
                if merged {
                    // Merged into an event already waiting: done, as far as the
                    // backlog counter is concerned.
                    self.metrics.on_inject();
                }
                if waiting >= PEER_QUEUE_LIMIT {
                    self.pressure.hold(addr);
                }
                false
            }
            ProxyRequest::Remove(addr) => {
                self.queued.push(addr, Queued::Remove);
                false
            }
            ProxyRequest::Terminate => true,
            ProxyRequest::Reenable => false,
        }
    }
}

fn to_ipc_pos(pos: Position) -> hops_ipc::Position {
    match pos {
        Position::Left => hops_ipc::Position::Left,
        Position::Right => hops_ipc::Position::Right,
        Position::Top => hops_ipc::Position::Top,
        Position::Bottom => hops_ipc::Position::Bottom,
    }
}

fn edge_to_ipc_pos(side: input_emulation::EdgeSide) -> hops_ipc::Position {
    match side {
        input_emulation::EdgeSide::Left => hops_ipc::Position::Left,
        input_emulation::EdgeSide::Right => hops_ipc::Position::Right,
        input_emulation::EdgeSide::Top => hops_ipc::Position::Top,
        input_emulation::EdgeSide::Bottom => hops_ipc::Position::Bottom,
    }
}

async fn wait_for_termination(rx: &mut Receiver<ProxyRequest>) {
    loop {
        match rx.recv().await.expect("channel closed") {
            ProxyRequest::Terminate => return,
            ProxyRequest::Input(_, _) => continue,
            ProxyRequest::Remove(_) => continue,
            ProxyRequest::Reenable => continue,
        }
    }
}

struct DropGuard<T> {
    tx: Sender<T>,
    on_drop: Option<T>,
}

impl<T> DropGuard<T> {
    fn new(tx: Sender<T>, on_new: T, on_drop: T) -> Self {
        tx.send(on_new).expect("channel closed");
        let on_drop = Some(on_drop);
        Self { tx, on_drop }
    }
}

impl<T> Drop for DropGuard<T> {
    fn drop(&mut self) {
        self.tx
            .send(self.on_drop.take().expect("item"))
            .expect("channel closed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u16) -> SocketAddr {
        format!("127.0.0.1:{n}").parse().unwrap()
    }

    /// Remote unauthenticated memory growth.
    ///
    /// The suppression map was insert-only and lived for the life of the
    /// daemon, so a peer generating a fresh self-signed certificate per dial
    /// added a permanent entry per dial — measured at 120 distinct fingerprints
    /// per second from one host. Remove the pruning in `should_notify` and this
    /// fails with one entry per distinct fingerprint offered.
    #[test]
    fn a_flood_of_unknown_fingerprints_cannot_grow_memory_without_bound() {
        let mut recent = RecentRejections::new();
        for i in 0..50_000u32 {
            // A fresh key per dial, which is what defeats a per-fingerprint
            // suppression window and what an attacker actually does.
            recent.should_notify(&format!("fp-{i:08x}"));
        }
        assert!(
            recent.seen.len() < RecentRejections::PRUNE_AT * 2,
            "50,000 distinct dials left {} entries resident — an unauthenticated \
             peer can still drive unbounded growth in the daemon holding the \
             private key",
            recent.seen.len()
        );
    }

    /// The bound must not cost the thing the map exists to do.
    #[test]
    fn a_peer_retrying_in_a_loop_still_raises_only_one_prompt() {
        let mut recent = RecentRejections::new();
        assert!(
            recent.should_notify("aa:bb:cc"),
            "the first sighting of a fingerprint must raise a prompt"
        );
        for _ in 0..10_000 {
            assert!(
                !recent.should_notify("aa:bb:cc"),
                "a peer retrying inside the window must not raise a second prompt"
            );
        }
    }

    /// The pointer is not proof of local presence on a KVM: a peer that still
    /// holds control can drive the cursor onto an approval button and click it.
    /// The daemon refuses trust GRANTS while this reads true.
    #[test]
    fn peer_input_marks_the_machine_as_remotely_driven() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            let proxy = EmulationProxy::new(None, Default::default());
            let window = Duration::from_secs(2);
            assert!(
                !proxy.remotely_driven_within(window),
                "a machine nobody has driven is not remotely driven"
            );

            proxy.consume(
                Event::Pointer(PointerEvent::Motion {
                    time: 0,
                    dx: 1.0,
                    dy: 0.0,
                }),
                addr(1),
            );
            assert!(
                proxy.remotely_driven_within(window),
                "peer input must mark the machine as remotely driven"
            );

            // and the window is a window, not a latch
            assert!(
                !proxy.remotely_driven_within(Duration::from_nanos(1)),
                "the check must expire, or trust changes would be blocked forever"
            );
        });
    }

    #[test]
    fn reconstructs_cumulative_to_per_event_deltas() {
        let mut r = AbsMotionReconstructor::default();
        let a = addr(1);
        r.anchor(a);
        // cumulative displacement from the anchor -> per-event delta
        assert_eq!(r.delta(a, 10.0, 5.0), (10.0, 5.0)); // first, from origin
        assert_eq!(r.delta(a, 15.0, 5.0), (5.0, 0.0));
        assert_eq!(r.delta(a, 15.0, 20.0), (0.0, 15.0));
        assert_eq!(r.delta(a, 12.0, 18.0), (-3.0, -2.0)); // deltas can be negative
    }

    #[test]
    fn anchor_resets_on_reentry() {
        let mut r = AbsMotionReconstructor::default();
        let a = addr(1);
        r.anchor(a);
        r.delta(a, 100.0, 100.0); // cursor traveled far this visit
        // re-enter: the sender resets its cumulative displacement to 0, so must we
        r.anchor(a);
        assert_eq!(r.delta(a, 3.0, 3.0), (3.0, 3.0)); // NOT (3 - 100)
    }

    #[test]
    fn unseen_peer_degrades_to_absolute_not_a_jump() {
        let mut r = AbsMotionReconstructor::default();
        // no anchor() first (stray update) -> prev defaults to the origin
        assert_eq!(r.delta(addr(9), 7.0, -4.0), (7.0, -4.0));
    }

    #[test]
    fn peers_are_independent_and_forget_clears() {
        let mut r = AbsMotionReconstructor::default();
        let (a, b) = (addr(1), addr(2));
        r.anchor(a);
        r.anchor(b);
        r.delta(a, 50.0, 0.0);
        assert_eq!(r.delta(b, 4.0, 4.0), (4.0, 4.0)); // b independent of a
        r.forget(a);
        // a forgotten -> its next delta is measured from the origin again
        assert_eq!(r.delta(a, 8.0, 8.0), (8.0, 8.0));
    }

    /// End-to-end contract (PR-4 sender ⇄ PR-3 receiver): the sender accumulates
    /// deltas in f64 and puts the cumulative on the wire as f32
    /// (`abs_vx as f32`); the receiver reconstructs per-event deltas. The sum of
    /// reconstructed deltas must equal the sender's intended total displacement,
    /// to within f32 precision — no drift across a visit.
    #[test]
    fn absolute_roundtrip_preserves_total_displacement() {
        let mut r = AbsMotionReconstructor::default();
        let a = addr(1);
        r.anchor(a);
        let deltas = [
            (10.0, 5.0),
            (3.5, -2.0),
            (0.0, 8.0),
            (-4.0, -4.0),
            (1234.5, -987.25),
        ];
        let (mut avx, mut avy) = (0.0f64, 0.0f64); // sender accumulator (f64)
        let (mut rx, mut ry) = (0.0f64, 0.0f64); // sum of reconstructed deltas
        for &(dx, dy) in &deltas {
            avx += dx;
            avy += dy;
            let (rdx, rdy) = r.delta(a, avx as f32, avy as f32); // wire is f32
            rx += rdx;
            ry += rdy;
        }
        let (wx, wy) = deltas
            .iter()
            .fold((0.0f64, 0.0f64), |acc, &(x, y)| (acc.0 + x, acc.1 + y));
        assert!((rx - wx).abs() < 0.01, "x total drift: {rx} vs {wx}");
        assert!((ry - wy).abs() < 0.01, "y total drift: {ry} vs {wy}");
    }
}

#[cfg(test)]
mod held_input_is_released {
    //! Every way a peer's session on this machine ends must let go of what the
    //! peer was holding: buttons as well as keys (#89).
    //!
    //! The release was keyboard-only. A peer that vanished mid-drag left the
    //! button down here, so the drag carried on under whatever the local mouse
    //! did next, and could drop a file somewhere nobody chose.
    //!
    //! These drive the production path end to end over loopback: real dialers,
    //! the real listener and emulation task, and a recording backend in place of
    //! the OS.

    use super::*;
    use crate::test_harness::{Dialer, dialer, machine, run_local, trust, wait_until};
    use crate::trust::Caps;
    use input_emulation::ButtonScope;
    use input_emulation::recording::{Recorded, Recording};
    use input_event::{BTN_LEFT, BTN_RIGHT, KeyboardEvent, scancode};

    const KEY_A: u32 = scancode::Linux::KeyA as u32;

    struct Session {
        recording: Recording,
        emulation: Emulation,
        /// One per peer, each already crossed onto this machine.
        peers: Vec<Dialer>,
        /// This machine's trust store, which the listener checks per event.
        trust: crate::transport::Trust,
        /// Each peer's fingerprint, in the order of `peers`.
        fingerprints: Vec<String>,
    }

    /// `n` senders that have crossed onto this machine and are ready to inject,
    /// into a backend whose handles share one device.
    async fn session_with(n: usize) -> Session {
        session_scoped(n, ButtonScope::Machine).await
    }

    /// [`session_with`], into a backend that counts buttons as `scope` says.
    async fn session_scoped(n: usize, scope: ButtonScope) -> Session {
        let receiver = machine();
        let senders: Vec<_> = (0..n).map(|_| machine()).collect();
        let receiver_trust = trust(
            &receiver,
            &senders.iter().collect::<Vec<_>>(),
            Caps::INBOUND,
        );
        let (clipboard_tx, _) = channel();
        let (listener, port) = LanMouseListener::bind_loopback(
            receiver.identity.clone(),
            receiver_trust.clone(),
            clipboard_tx,
        )
        .await
        .expect("listener");
        let recording = Recording::with_button_scope(scope);
        let emulation = Emulation::new(Some(recording.backend()), listener, receiver_trust.clone());
        let mut peers = vec![];
        for sender in &senders {
            let peer = dialer(
                sender,
                trust(sender, &[&receiver], Caps::OUTBOUND),
                port,
                hops_ipc::Position::Left,
            );
            peer.until_alive().await;
            peer.send(ProtoEvent::Enter(Position::Right)).await;
            peers.push(peer);
        }
        Session {
            recording,
            emulation,
            peers,
            trust: receiver_trust,
            fingerprints: senders.iter().map(|m| m.fingerprint.clone()).collect(),
        }
    }

    async fn session() -> Session {
        session_with(1).await
    }

    fn button(button: u32, state: u32) -> Event {
        Event::Pointer(PointerEvent::Button {
            time: 0,
            button,
            state,
        })
    }

    fn key(key: u32, state: u8) -> Event {
        Event::Keyboard(KeyboardEvent::Key {
            time: 0,
            key,
            state,
        })
    }

    impl Session {
        fn dialer(&self) -> &Dialer {
            &self.peers[0]
        }

        /// Send `event` from the first peer and wait until it reaches the
        /// backend. Returns the emulation handle it was injected under.
        async fn inject(&self, event: Event) -> EmulationHandle {
            self.inject_from(0, event).await
        }

        /// [`Self::inject`] from peer `from`.
        async fn inject_from(&self, from: usize, event: Event) -> EmulationHandle {
            let before = self.consumed(event).len();
            self.peers[from].send(ProtoEvent::Input(event)).await;
            wait_until(
                &format!("{event} to reach the backend"),
                Duration::from_secs(10),
                || self.consumed(event).len() > before,
            )
            .await;
            self.consumed(event)[before].1
        }

        /// Every time `event` reached the backend: where in the log, and for
        /// which handle.
        fn consumed(&self, event: Event) -> Vec<(usize, EmulationHandle)> {
            self.recording
                .calls()
                .iter()
                .enumerate()
                .filter_map(|(at, c)| match c {
                    Recorded::Consume(e, h) if *e == event => Some((at, *h)),
                    _ => None,
                })
                .collect()
        }

        fn position(&self, event: Event) -> Option<usize> {
            self.consumed(event).first().map(|&(at, _)| at)
        }

        /// The handle each time `event` reached the backend, in order.
        fn handles_of(&self, event: Event) -> Vec<EmulationHandle> {
            self.consumed(event).iter().map(|&(_, h)| h).collect()
        }

        /// Wait for `handle` to be destroyed, and say where in the log it was.
        async fn destroyed(&self, handle: EmulationHandle) -> usize {
            let at = || {
                self.recording
                    .calls()
                    .iter()
                    .position(|c| *c == Recorded::Destroy(handle))
            };
            wait_until(
                "the peer's emulation handle to be destroyed",
                Duration::from_secs(30),
                || at().is_some(),
            )
            .await;
            at().expect("destroyed")
        }

        /// Wait for `handle` to be destroyed, then say whether `event` reached
        /// the backend for it before that.
        async fn released_before_destroy(&self, handle: EmulationHandle, event: Event) -> bool {
            let destroyed = self.destroyed(handle).await;
            self.consumed(event)
                .iter()
                .any(|&(at, h)| h == handle && at < destroyed)
        }
    }

    // LEDGER T1 | class B | 6 struct state: Recording::calls() after the ListenTask watchdog
    /// The case in the issue: no Leave ever arrives. The link closes, the
    /// watchdog notices 10-15 s later, and whatever was held must come up then.
    #[test]
    fn a_peer_that_vanishes_mid_drag_leaves_no_button_held() {
        run_local(async {
            let s = session().await;
            let handle = s.inject(button(BTN_LEFT, 1)).await;
            s.inject(key(KEY_A, 1)).await;

            // Close without a Leave, as a killed process or a dropped link does.
            s.dialer()
                .conn
                .revoker()
                .close_handles(&[s.dialer().handle])
                .await;

            assert!(
                s.released_before_destroy(handle, button(BTN_LEFT, 0)).await,
                "the peer went away holding the left button and it was never \
                 released here: {:?}",
                s.recording.calls()
            );
            assert!(
                s.released_before_destroy(handle, key(KEY_A, 0)).await,
                "held keys must still be released: {:?}",
                s.recording.calls()
            );
        });
    }

    // LEDGER T2 | class B | 6 struct state: Recording::calls() after a Leave
    #[test]
    fn a_leave_releases_a_held_button_with_the_keys() {
        run_local(async {
            let s = session().await;
            let handle = s.inject(button(BTN_RIGHT, 1)).await;
            s.inject(key(KEY_A, 1)).await;

            s.dialer().send(ProtoEvent::Leave(0)).await;

            assert!(
                s.released_before_destroy(handle, button(BTN_RIGHT, 0))
                    .await,
                "a Leave while the right button was held left it down: {:?}",
                s.recording.calls()
            );
            assert!(
                s.released_before_destroy(handle, key(KEY_A, 0)).await,
                "a Leave must still release held keys: {:?}",
                s.recording.calls()
            );
        });
    }

    // LEDGER T3 | class B | 6 struct state: Recording::calls() after Emulation::terminate
    #[test]
    fn shutting_down_releases_a_held_button() {
        run_local(async {
            let mut s = session().await;
            s.inject(button(BTN_LEFT, 1)).await;

            s.emulation.terminate().await;

            let calls = s.recording.calls();
            let terminated = calls
                .iter()
                .position(|c| matches!(c, Recorded::Terminate))
                .expect("shutdown terminates the backend");
            assert!(
                s.position(button(BTN_LEFT, 0))
                    .is_some_and(|at| at < terminated),
                "shutting down while a peer held the left button left it down: {calls:?}"
            );
        });
    }

    // LEDGER T4 | class B | 6 struct state: Recording::calls() after a backend error
    /// A backend that fails ends the emulation session, which tears down every
    /// handle; that teardown must release too.
    #[test]
    fn a_backend_error_mid_drag_still_releases_the_button() {
        run_local(async {
            let s = session().await;
            let handle = s.inject(button(BTN_LEFT, 1)).await;

            let motion = Event::Pointer(PointerEvent::Motion {
                time: 0,
                dx: 1.0,
                dy: 0.0,
            });
            s.recording.fail_when(move |e| *e == motion);
            s.dialer().send(ProtoEvent::Input(motion)).await;

            assert!(
                s.released_before_destroy(handle, button(BTN_LEFT, 0)).await,
                "an emulation error mid-drag left the left button down: {:?}",
                s.recording.calls()
            );
        });
    }

    // LEDGER T5 | class B | 6 struct state: Recording::calls() after a failed release
    /// Returning at the first failed release left everything after it held.
    #[test]
    fn one_failed_release_does_not_strand_the_rest() {
        run_local(async {
            let s = session().await;
            let handle = s.inject(button(BTN_LEFT, 1)).await;
            s.inject(button(BTN_RIGHT, 1)).await;
            s.inject(key(KEY_A, 1)).await;

            let left_up = button(BTN_LEFT, 0);
            s.recording.fail_when(move |e| *e == left_up);
            s.dialer().send(ProtoEvent::Leave(0)).await;

            assert!(
                s.released_before_destroy(handle, left_up).await,
                "the failing release must still have been attempted: {:?}",
                s.recording.calls()
            );
            assert!(
                s.released_before_destroy(handle, button(BTN_RIGHT, 0))
                    .await,
                "one failed button release stranded another button: {:?}",
                s.recording.calls()
            );
            assert!(
                s.released_before_destroy(handle, key(KEY_A, 0)).await,
                "one failed button release stranded a held key: {:?}",
                s.recording.calls()
            );
        });
    }

    // LEDGER T6 | class B | 6 struct state: Recording::calls() after Leave from each of two peers
    /// Two peers can hold the same button at once. The machine has one left
    /// button, so the first to leave must not let go of it while the other
    /// still holds it; the last holder does. This covers teardown only; the
    /// two tests below cover a button-up arriving before a teardown.
    #[test]
    fn a_leaving_peer_keeps_a_button_another_peer_holds() {
        run_local(async {
            let s = session_with(2).await;
            let first = s.inject_from(0, button(BTN_LEFT, 1)).await;
            let second = s.inject_from(1, button(BTN_LEFT, 1)).await;
            assert_ne!(first, second, "precondition: one handle per peer");

            s.peers[0].send(ProtoEvent::Leave(0)).await;
            s.destroyed(first).await;
            assert!(
                s.position(button(BTN_LEFT, 0)).is_none(),
                "the first peer's Leave released the left button while the \
                 second peer still held it: {:?}",
                s.recording.calls()
            );

            s.peers[1].send(ProtoEvent::Leave(0)).await;
            assert!(
                s.released_before_destroy(second, button(BTN_LEFT, 0)).await,
                "the last peer holding the left button left and it stayed down: {:?}",
                s.recording.calls()
            );
        });
    }

    // LEDGER T10 | class B | 6 struct state: Recording::calls() after a button-up from another peer, then a Leave
    /// A sender that crossed back on a new connection while holding the button
    /// lets go of it there. That button-up comes from a peer that never pressed
    /// it, yet it releases the button for the machine; the old connection's
    /// teardown must not release it a second time.
    #[test]
    fn a_button_let_go_through_another_peer_is_not_released_again() {
        run_local(async {
            let s = session_with(2).await;
            let first = s.inject_from(0, button(BTN_LEFT, 1)).await;
            let second = s.inject_from(1, button(BTN_LEFT, 0)).await;
            assert_ne!(first, second, "precondition: one handle per peer");

            s.peers[0].send(ProtoEvent::Leave(0)).await;
            s.destroyed(first).await;

            assert_eq!(
                s.consumed(button(BTN_LEFT, 0)).len(),
                1,
                "the left button came up once, through the second peer, and the \
                 first peer's teardown injected another up: {:?}",
                s.recording.calls()
            );
        });
    }

    // LEDGER T11 | class B | 6 struct state: Recording::calls() after one of two holders clicks, then the other leaves
    /// The same when the new connection presses and releases the button itself
    /// before the old one is retired: its up releases the one machine button,
    /// so the old connection holds nothing any more.
    #[test]
    fn a_click_through_another_peer_leaves_nothing_to_release_again() {
        run_local(async {
            let s = session_with(2).await;
            let first = s.inject_from(0, button(BTN_LEFT, 1)).await;
            let second = s.inject_from(1, button(BTN_LEFT, 1)).await;
            assert_ne!(first, second, "precondition: one handle per peer");
            s.inject_from(1, button(BTN_LEFT, 0)).await;

            s.peers[0].send(ProtoEvent::Leave(0)).await;
            s.destroyed(first).await;

            assert_eq!(
                s.consumed(button(BTN_LEFT, 0)).len(),
                1,
                "the second peer clicked, which let go of the left button, and \
                 the first peer's teardown injected another up: {:?}",
                s.recording.calls()
            );
        });
    }

    // LEDGER T12 | class B | 6 struct state: Recording::calls() after a Leave, then the peer's own late up
    /// A link that stalls past the watchdog and then recovers delivers the
    /// peer's own button-up after this machine already released the button.
    /// Injected, that second up would end whatever holds the button by then.
    #[test]
    fn a_late_button_up_after_a_teardown_is_not_injected_again() {
        run_local(async {
            let s = session().await;
            let handle = s.inject(button(BTN_LEFT, 1)).await;
            s.dialer().send(ProtoEvent::Leave(0)).await;
            s.destroyed(handle).await;
            assert_eq!(
                s.consumed(button(BTN_LEFT, 0)).len(),
                1,
                "precondition: the Leave released the left button: {:?}",
                s.recording.calls()
            );

            // The up the peer sent before it knew, then something after it on
            // the same stream, so the up has been handled once that arrives.
            s.dialer()
                .send(ProtoEvent::Input(button(BTN_LEFT, 0)))
                .await;
            s.inject(key(KEY_A, 1)).await;

            assert_eq!(
                s.consumed(button(BTN_LEFT, 0)).len(),
                1,
                "the left button was released at the Leave, and the peer's late \
                 up was injected as a second one: {:?}",
                s.recording.calls()
            );
        });
    }

    /// A scroll, which the queues never merge: the flood in the fairness test
    /// has to be events that cannot be collapsed into one.
    fn scroll(value: f64) -> Event {
        Event::Pointer(PointerEvent::Axis {
            time: 0,
            axis: 0,
            value,
        })
    }

    fn motion(dx: f64) -> Event {
        Event::Pointer(PointerEvent::Motion {
            time: 0,
            dx,
            dy: 0.,
        })
    }

    /// How many events the backend took before `mark`, and whether it took it.
    fn injected_before(calls: &[Recorded], mark: Event) -> Option<usize> {
        let at = calls
            .iter()
            .position(|c| matches!(c, Recorded::Consume(e, _) if *e == mark))?;
        Some(
            calls[..at]
                .iter()
                .filter(|c| matches!(c, Recorded::Consume(..)))
                .count(),
        )
    }

    // LEDGER T27 | class B | 6 struct state: Recording::calls() order under a flood from another peer
    /// One machine sending faster than this one can inject must not hold up
    /// another machine's key.
    ///
    /// Every peer's input used to wait in one queue in arrival order, so a key
    /// from a second machine sat behind the whole backlog of the first (#82).
    /// Injection is made the slow step here, which is what a real backend is.
    #[test]
    fn a_flood_from_one_peer_does_not_delay_another_peers_key() {
        run_local(async {
            let s = session_with(2).await;
            const FLOOD: usize = 300;
            s.recording.consume_takes(Duration::from_millis(2));

            for _ in 0..FLOOD {
                s.peers[0].send(ProtoEvent::Input(scroll(1.))).await;
            }
            s.peers[1].send(ProtoEvent::Input(key(KEY_A, 1))).await;

            wait_until(
                "the second peer's key to be injected",
                Duration::from_secs(20),
                || !s.consumed(key(KEY_A, 1)).is_empty(),
            )
            .await;
            let waited =
                injected_before(&s.recording.calls(), key(KEY_A, 1)).expect("the key was injected");
            assert!(
                waited < FLOOD / 4,
                "the key waited behind {waited} of the flood's {FLOOD} events; \
                 each peer is supposed to be served in turn"
            );
        });
    }

    // LEDGER T28 | class B | 6 struct state: Recording::calls() after a high-rate mouse
    /// A fast mouse costs one queue slot, not hundreds, and the pointer still
    /// ends up where it was sent.
    ///
    /// Relative motion waiting behind an injection merges into the event
    /// already queued, carrying the sum (#82).
    #[test]
    fn a_high_rate_mouse_is_merged_and_still_lands_where_it_was_sent() {
        run_local(async {
            let s = session().await;
            const MOVES: usize = 400;
            s.recording.consume_takes(Duration::from_millis(2));

            for _ in 0..MOVES {
                s.dialer().send(ProtoEvent::Input(motion(1.))).await;
            }
            // A key after the motion: once it arrives, everything sent before
            // it has been dealt with.
            s.peers[0].send(ProtoEvent::Input(key(KEY_A, 1))).await;
            wait_until(
                "the key sent after the motion to be injected",
                Duration::from_secs(20),
                || !s.consumed(key(KEY_A, 1)).is_empty(),
            )
            .await;

            let moved: f64 = s
                .recording
                .calls()
                .iter()
                .filter_map(|c| match c {
                    Recorded::Consume(Event::Pointer(PointerEvent::Motion { dx, .. }), _) => {
                        Some(*dx)
                    }
                    _ => None,
                })
                .sum();
            let injections = s
                .recording
                .calls()
                .iter()
                .filter(|c| {
                    matches!(
                        c,
                        Recorded::Consume(Event::Pointer(PointerEvent::Motion { .. }), _)
                    )
                })
                .count();
            assert_eq!(
                moved, MOVES as f64,
                "the pointer moved {moved} of the {MOVES} it was sent"
            );
            assert!(
                injections < MOVES / 2,
                "{injections} injections for {MOVES} moves: motion waiting behind \
                 an injection is supposed to merge"
            );
        });
    }

    // LEDGER T13 | class B | 6 struct state: Recording::calls() after the per-event trust check refuses the peer
    /// Revoking or letting a lease lapse refuses the peer's events at the
    /// point of injection, its button- and key-ups included. What it held must
    /// come up then, not when the session is eventually cut.
    #[test]
    fn a_peer_refused_mid_drag_leaves_nothing_held() {
        run_local(async {
            let s = session().await;
            let handle = s.inject(button(BTN_LEFT, 1)).await;
            s.inject(key(KEY_A, 1)).await;

            s.trust
                .write()
                .expect("trust lock")
                .revoke(&s.fingerprints[0]);
            // Refused: the peer is no longer allowed to drive this machine.
            s.dialer()
                .send(ProtoEvent::Input(button(BTN_LEFT, 0)))
                .await;

            assert!(
                s.released_before_destroy(handle, button(BTN_LEFT, 0)).await,
                "the peer was refused while holding the left button and it was \
                 never released: {:?}",
                s.recording.calls()
            );
            assert!(
                s.released_before_destroy(handle, key(KEY_A, 0)).await,
                "the peer was refused while holding a key and it was never \
                 released: {:?}",
                s.recording.calls()
            );
            assert_eq!(
                s.consumed(button(BTN_LEFT, 0)).len(),
                1,
                "exactly one up: the release, not the refused event: {:?}",
                s.recording.calls()
            );
        });
    }

    // LEDGER T18 | class B | 6 struct state: Recording::calls() after refused Input events, synced by a Capability marker and a permitted peer's input
    /// A refusal releases the peer once. Absolute motion is not refused yet
    /// (#156) and re-creates the handle the refusal destroyed, so releasing on
    /// every refused event tore that handle down and built it again for each
    /// pair: on wlroots a new virtual pointer and keyboard every time.
    ///
    /// Nothing here needs that motion to be injected. Once #156 refuses it
    /// too, this still passes, but a release per event then has no handle to
    /// destroy, and only the repeated warning would show it.
    #[test]
    fn a_refused_peer_is_released_once_not_per_event() {
        run_local(async {
            let mut s = session_with(2).await;
            let handle = s.inject_from(0, button(BTN_LEFT, 1)).await;

            s.trust
                .write()
                .expect("trust lock")
                .revoke(&s.fingerprints[0]);
            let scroll = Event::Pointer(PointerEvent::Axis {
                time: 0,
                axis: 0,
                value: 1.0,
            });
            for seq in 1..=5u32 {
                s.peers[0]
                    .send(ProtoEvent::PointerMotionAbsolute {
                        seq,
                        ts: 0,
                        vx: seq as f32,
                        vy: 0.0,
                    })
                    .await;
                s.peers[0].send(ProtoEvent::Input(scroll)).await;
            }

            // Sent on the same stream after the events above and never
            // refused, so once the listener reports it, it has handled them
            // all and queued every release they asked for.
            const MARKER: u32 = 0x7e57_0018;
            s.peers[0]
                .send(ProtoEvent::Capability { flags: MARKER })
                .await;
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if let EmulationEvent::PeerCaps { flags: MARKER, .. } =
                        s.emulation.event().await
                    {
                        break;
                    }
                }
            })
            .await
            .expect("the listener handled the refused peer's events within 10s");
            // Queued behind those releases, so once it reaches the backend so
            // has every one of them.
            s.inject_from(1, key(KEY_A, 1)).await;

            let calls = s.recording.calls();
            assert!(
                calls.contains(&Recorded::Destroy(handle)),
                "precondition: the refusal released the peer: {calls:?}"
            );
            assert!(
                s.consumed(scroll).is_empty(),
                "precondition: the refused events were not injected: {calls:?}"
            );
            let destroyed = calls
                .iter()
                .filter(|c| matches!(c, Recorded::Destroy(_)))
                .count();
            assert_eq!(
                destroyed, 1,
                "five refused events each tore the refused peer's emulation \
                 handle down again: {calls:?}"
            );
        });
    }

    // LEDGER T21 | class B | 6 struct state: Recording::calls() after a refusal, a new grant, input, and a second refusal
    /// A peer granted again after a refusal can press a button again, and a
    /// second refusal must release that too.
    #[test]
    fn a_peer_refused_again_after_a_new_grant_is_released_again() {
        run_local(async {
            let s = session().await;
            let fingerprint = &s.fingerprints[0];
            let first = s.inject(button(BTN_LEFT, 1)).await;

            let lapse = || {
                s.trust
                    .write()
                    .expect("trust lock")
                    .drop_capabilities(fingerprint, Caps::DRIVE_ME);
            };
            lapse();
            s.dialer()
                .send(ProtoEvent::Input(button(BTN_LEFT, 0)))
                .await;
            assert!(
                s.released_before_destroy(first, button(BTN_LEFT, 0)).await,
                "precondition: the first refusal released the left button: {:?}",
                s.recording.calls()
            );

            s.trust
                .write()
                .expect("trust lock")
                .issue(fingerprint, "peer", Caps::INBOUND)
                .expect("grant again");
            let second = s.inject(button(BTN_RIGHT, 1)).await;
            assert_ne!(first, second, "precondition: a new handle");

            lapse();
            s.dialer()
                .send(ProtoEvent::Input(button(BTN_RIGHT, 0)))
                .await;
            assert!(
                s.released_before_destroy(second, button(BTN_RIGHT, 0))
                    .await,
                "the peer was granted again, pressed the right button, and was \
                 refused again, and the right button was never released: {:?}",
                s.recording.calls()
            );
        });
    }

    // LEDGER T23 | class B | 6 struct state: Recording::calls() after A holds, B presses and lets go, then A lets go (PerHandle)
    /// Where each peer has a device of its own and presses are counted across
    /// devices (wlroots 0.19 and later), the button comes up for applications
    /// only once every device that pressed it has let go. The first holder's
    /// own up must still go out, on its own device, after another peer's up.
    #[test]
    fn per_device_every_holder_lets_go_through_its_own_device() {
        run_local(async {
            let s = session_scoped(2, ButtonScope::PerHandle).await;
            let first = s.inject_from(0, button(BTN_LEFT, 1)).await;
            let second = s.inject_from(1, button(BTN_LEFT, 1)).await;
            assert_ne!(first, second, "precondition: one handle per peer");
            s.inject_from(1, button(BTN_LEFT, 0)).await;

            s.peers[0]
                .send(ProtoEvent::Input(button(BTN_LEFT, 0)))
                .await;
            // After the up on the same stream: once this is in, so is the up.
            s.inject_from(0, key(KEY_A, 1)).await;

            assert_eq!(
                s.handles_of(button(BTN_LEFT, 0)),
                vec![second, first],
                "each device pressed the left button once, so each must let go \
                 of it once; a counted press with no up keeps it held: {:?}",
                s.recording.calls()
            );
        });
    }

    // LEDGER T24 | class B | 6 struct state: Recording::calls() after A leaves while B holds, then B lets go (PerHandle)
    /// A peer that leaves while another still holds the same button releases
    /// its own device's press. The other device's press keeps the button
    /// down until that peer lets go.
    #[test]
    fn per_device_a_leaving_peer_releases_its_press_while_another_holds() {
        run_local(async {
            let s = session_scoped(2, ButtonScope::PerHandle).await;
            let first = s.inject_from(0, button(BTN_LEFT, 1)).await;
            let second = s.inject_from(1, button(BTN_LEFT, 1)).await;
            assert_ne!(first, second, "precondition: one handle per peer");

            s.peers[0].send(ProtoEvent::Leave(0)).await;
            assert!(
                s.released_before_destroy(first, button(BTN_LEFT, 0)).await,
                "the first peer left holding the left button on its own device \
                 and that press was never released: {:?}",
                s.recording.calls()
            );

            s.inject_from(1, button(BTN_LEFT, 0)).await;
            assert_eq!(
                s.handles_of(button(BTN_LEFT, 0)),
                vec![first, second],
                "one up per device that pressed: {:?}",
                s.recording.calls()
            );
        });
    }

    // LEDGER T25 | class B | 6 struct state: Recording::calls() after an up from a peer holding nothing, then the holder's Leave (PerHandle)
    /// A sender that crossed back on a new connection lets go there, while
    /// its old connection still holds the press. The up goes out on the
    /// device that pressed, and that device then has nothing left to release.
    #[test]
    fn per_device_an_up_from_another_peer_goes_out_on_the_pressing_device() {
        run_local(async {
            let s = session_scoped(2, ButtonScope::PerHandle).await;
            let first = s.inject_from(0, button(BTN_LEFT, 1)).await;

            s.peers[1]
                .send(ProtoEvent::Input(button(BTN_LEFT, 0)))
                .await;
            let second = s.inject_from(1, key(KEY_A, 1)).await;
            assert_ne!(first, second, "precondition: one handle per peer");
            assert_eq!(
                s.handles_of(button(BTN_LEFT, 0)),
                vec![first],
                "the up must go out on the device that pressed the button, or \
                 that device keeps its press: {:?}",
                s.recording.calls()
            );

            s.peers[0].send(ProtoEvent::Leave(0)).await;
            s.destroyed(first).await;
            assert_eq!(
                s.consumed(button(BTN_LEFT, 0)).len(),
                1,
                "the pressing device already let go, and its teardown injected \
                 another up: {:?}",
                s.recording.calls()
            );
        });
    }

    // LEDGER T26 | class B | 6 struct state: Recording::calls() after the same peer presses twice (PerHandle)
    /// A device holds a button once and releases it once. A second press from
    /// the same peer would be counted with no up ever to match it.
    #[test]
    fn per_device_a_repeated_press_from_the_holder_is_not_injected() {
        run_local(async {
            let s = session_scoped(1, ButtonScope::PerHandle).await;
            s.inject(button(BTN_LEFT, 1)).await;

            s.dialer()
                .send(ProtoEvent::Input(button(BTN_LEFT, 1)))
                .await;
            s.inject(key(KEY_A, 1)).await;

            assert_eq!(
                s.consumed(button(BTN_LEFT, 1)).len(),
                1,
                "a second press of a button the device already holds reached \
                 the backend: {:?}",
                s.recording.calls()
            );
        });
    }

    // LEDGER T27 | class B | 6 struct state: Recording::calls() after a Leave, then the peer's own late up (PerHandle)
    /// The late up of T12, where each peer has its own device: nothing holds
    /// the button any more, so the up is dropped here too.
    #[test]
    fn per_device_a_late_button_up_after_a_teardown_is_not_injected_again() {
        run_local(async {
            let s = session_scoped(1, ButtonScope::PerHandle).await;
            let handle = s.inject(button(BTN_LEFT, 1)).await;
            s.dialer().send(ProtoEvent::Leave(0)).await;
            s.destroyed(handle).await;

            s.dialer()
                .send(ProtoEvent::Input(button(BTN_LEFT, 0)))
                .await;
            s.inject(key(KEY_A, 1)).await;

            assert_eq!(
                s.consumed(button(BTN_LEFT, 0)).len(),
                1,
                "the left button was released at the Leave, and the peer's late \
                 up was injected as a second one: {:?}",
                s.recording.calls()
            );
        });
    }
}
