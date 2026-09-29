use std::collections::{HashMap, HashSet};
use std::{
    cell::{Cell, RefCell},
    net::SocketAddr,
    rc::Rc,
    time::{Duration, Instant},
};

use futures::StreamExt;
use hops_ipc::CrossingRefusal;
use hops_proto::{ProtoEvent, caps};
use input_capture::{
    CaptureError, CaptureEvent, CaptureHandle, InputCapture, InputCaptureError, Permission,
    Position,
};
use input_event::{Event, KeyboardEvent, PointerEvent, scancode};
use local_channel::mpsc::{Receiver, Sender, channel};
use tokio::task::{JoinHandle, spawn_local};
use tokio_util::sync::CancellationToken;

use crate::connect::{LanMouseConnection, LanMouseConnectionError};

pub(crate) struct Capture {
    cancellation_token: CancellationToken,
    request_tx: Sender<CaptureRequest>,
    task: JoinHandle<()>,
    event_rx: Receiver<ICaptureEvent>,
}

pub(crate) enum ICaptureEvent {
    /// a client was entered
    CaptureBegin(CaptureHandle),
    /// capture disabled
    CaptureDisabled,
    /// capture disabled
    CaptureEnabled,
    /// Capture could not start, or stopped, and why (#91). Sent after the
    /// `CaptureDisabled` a session that stopped ends with.
    CaptureFailed(hops_ipc::CaptureFault),
    /// A (new) client was entered.
    /// In contrast to [`ICaptureEvent::CaptureBegin`] this
    /// event is only triggered when the capture was
    /// explicitly released in the meantime by
    /// either the remote client leaving its device region,
    /// a new device entering the screen or the release bind.
    ClientEntered(u64),
    /// A crossing to `handle` left the pointer on this machine, for
    /// `reason`. Sent once per device and reason while the user keeps
    /// pushing at that edge (see [`Told`]).
    CrossingRefused {
        handle: CaptureHandle,
        reason: CrossingRefusal,
    },
}

/// How long a crossing waits for the peer's Ack before the pointer is given
/// back (#115). A peer on the LAN answers in milliseconds, and it answers
/// every Enter re-send; one that has not answered in a second is not going
/// to, and until then the user's pointer is frozen at the edge.
const ACK_DEADLINE: Duration = Duration::from_secs(1);

/// After a crossing a peer never acknowledged, how long crossings to it are
/// refused without taking the pointer at all. Without it, pushing at that
/// edge froze the pointer for [`ACK_DEADLINE`] out of every push.
const UNANSWERED_BACKOFF: Duration = Duration::from_secs(5);

/// How long a crossing waits, and for what: [`ACK_DEADLINE`] and
/// [`UNANSWERED_BACKOFF`] outside tests.
#[derive(Clone, Copy, Debug)]
struct Timing {
    ack_deadline: Duration,
    unanswered_backoff: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            ack_deadline: ACK_DEADLINE,
            unanswered_backoff: UNANSWERED_BACKOFF,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CaptureType {
    /// a normal input capture
    Default,
    /// A capture only interested in [`CaptureEvent::Begin`] events.
    /// The capture is released immediately, if there is no
    /// Default capture at the same position.
    EnterOnly,
}

#[derive(Clone, Debug)]
enum CaptureRequest {
    /// capture must release the mouse
    Release,
    /// add a capture client
    Create(CaptureHandle, Position, CaptureType),
    /// destory a capture client
    Destroy(CaptureHandle),
    /// reenable input capture
    Reenable,
    /// set release bind
    SetReleaseBind(Vec<scancode::Linux>),
    /// dial a client now, rather than when the pointer next crosses to it
    Dial(CaptureHandle),
}

impl Capture {
    pub(crate) fn new(
        backend: Option<input_capture::Backend>,
        conn: LanMouseConnection,
        release_bind: Vec<scancode::Linux>,
    ) -> Self {
        Self::with_timing(backend, conn, release_bind, Timing::default())
    }

    /// As [`Capture::new`], a crossing timed by `timing`.
    fn with_timing(
        backend: Option<input_capture::Backend>,
        conn: LanMouseConnection,
        release_bind: Vec<scancode::Linux>,
        timing: Timing,
    ) -> Self {
        let (request_tx, request_rx) = channel();
        let (event_tx, event_rx) = channel();
        let cancellation_token = CancellationToken::new();
        let capture_task = CaptureTask {
            held_lock_keys: Default::default(),
            buttons_down_on_peer: Default::default(),
            active_client: None,
            acked_at: None,
            acked_link: None,
            timing,
            awaiting_ack: None,
            unanswered: Default::default(),
            told: Default::default(),
            backend,
            cancellation_token: cancellation_token.clone(),
            captures: Default::default(),
            conn,
            event_tx,
            request_rx,
            release_bind: Rc::new(RefCell::new(release_bind)),
            state: Default::default(),
            // HOPS_COALESCE_MOTION=1 (or any value except "0"/"off") turns it on.
            coalesce_motion: std::env::var("HOPS_COALESCE_MOTION")
                .map(|v| v != "0" && !v.eq_ignore_ascii_case("off"))
                .unwrap_or(false),
            pending_motion: None,
            abs_vx: 0.0,
            abs_vy: 0.0,
            abs_seq: 0,
        };
        if capture_task.coalesce_motion {
            log::info!("motion coalescing ON (HOPS_COALESCE_MOTION) — flushing at ~240 Hz");
        }
        let task = spawn_local(capture_task.run());
        Self {
            cancellation_token,
            request_tx,
            task,
            event_rx,
        }
    }

    pub(crate) fn reenable(&self) {
        self.request_tx
            .send(CaptureRequest::Reenable)
            .expect("channel closed");
    }

    pub(crate) async fn terminate(&mut self) {
        self.cancellation_token.cancel();
        log::debug!("terminating capture");
        if let Err(e) = (&mut self.task).await {
            log::warn!("{e}");
        }
    }

    pub(crate) fn create(
        &self,
        handle: CaptureHandle,
        pos: hops_ipc::Position,
        capture_type: CaptureType,
    ) {
        let pos = to_capture_pos(pos);
        self.request_tx
            .send(CaptureRequest::Create(handle, pos, capture_type))
            .expect("channel closed");
    }

    pub(crate) fn destroy(&self, handle: CaptureHandle) {
        self.request_tx
            .send(CaptureRequest::Destroy(handle))
            .expect("channel closed");
    }

    /// Dial `handle` now if it has no connection, without waiting for the
    /// pointer to cross to it. For a device being added (#195).
    pub(crate) fn dial(&self, handle: CaptureHandle) {
        self.request_tx
            .send(CaptureRequest::Dial(handle))
            .expect("channel closed");
    }

    pub(crate) fn release(&self) {
        self.request_tx
            .send(CaptureRequest::Release)
            .expect("channel closed");
    }

    pub(crate) async fn event(&mut self) -> ICaptureEvent {
        self.event_rx.recv().await.expect("channel closed")
    }

    pub(crate) fn set_release_bind(&mut self, bind: Vec<scancode::Linux>) {
        let _ = self.request_tx.send(CaptureRequest::SetReleaseBind(bind));
    }
}

/// debounce a statement `$st`, i.e. the statement is executed only if the
/// time since the previous execution is at least `$dur`.
/// `$prev` is used to keep track of this timestamp
#[macro_export]
macro_rules! debounce {
    ($prev:ident, $dur:expr, $st:stmt) => {
        let exec = match $prev.get() {
            None => true,
            Some(instant) if instant.elapsed() > $dur => true,
            _ => false,
        };
        if exec {
            $prev.replace(Some(std::time::Instant::now()));
            $st
        }
    };
}

/// What to tell the user about a capture that ended with `e`: the settings
/// to change when a permission is missing, and the error otherwise.
fn fault_of(e: &InputCaptureError) -> hops_ipc::CaptureFault {
    match e.missing_permissions() {
        Some(missing) if !missing.is_empty() => hops_ipc::CaptureFault::Missing(
            missing
                .iter()
                .map(|p| match p {
                    Permission::Accessibility => hops_ipc::Permission::Accessibility,
                    Permission::InputMonitoring => hops_ipc::Permission::InputMonitoring,
                })
                .collect(),
        ),
        _ => hops_ipc::CaptureFault::Backend(e.to_string()),
    }
}

/// Caps / Num / Scroll Lock (evdev codes). These TOGGLE on each key-down, so an
/// OS auto-repeat must never be forwarded — unlike an ordinary key, where repeat
/// is the point.
fn is_lock_key(key: u32) -> bool {
    key == scancode::Linux::KeyCapsLock as u32
        || key == scancode::Linux::KeyNumlock as u32
        || key == scancode::Linux::KeyScrollLock as u32
}

struct CaptureTask {
    active_client: Option<CaptureHandle>,
    /// The client that acknowledged the crossing, and where its connection
    /// was then, so the frames that end the visit reach the peer holding its
    /// input. Removing a client, or reloading the config, drops it from the
    /// client list before capture hears of it; looking the handle up then
    /// finds nothing, or a new client not yet connected.
    acked_at: Option<(CaptureHandle, SocketAddr)>,
    /// The link the crossing was acknowledged on
    /// ([`LanMouseConnection::link_serial`]). The peer takes a crossing per
    /// link, so once its device is on another link, a machine that dialled
    /// again after its link dropped, the crossing is made again there.
    acked_link: Option<u64>,
    /// How long a crossing waits for the peer's Ack, and how long a peer
    /// that left one unanswered is refused crossings.
    timing: Timing,
    /// When the crossing to the active client is given up on if its Ack has
    /// not come. Set as the crossing starts; cleared by the Ack or by leaving.
    awaiting_ack: Option<tokio::time::Instant>,
    /// Clients that left a crossing unacknowledged, and when.
    unanswered: HashMap<CaptureHandle, Instant>,
    /// Refused crossings the service was told of.
    told: Told,
    backend: Option<input_capture::Backend>,
    cancellation_token: CancellationToken,
    captures: Vec<(CaptureHandle, Position, CaptureType)>,
    conn: LanMouseConnection,
    event_tx: Sender<ICaptureEvent>,
    release_bind: Rc<RefCell<Vec<scancode::Linux>>>,
    request_rx: Receiver<CaptureRequest>,
    state: State,
    /// Lock keys currently held down, so OS auto-repeat can be swallowed.
    ///
    /// Holding Caps Lock streams dozens of key-DOWNS per second (measured on the
    /// rig: 38 downs for one press, no ups between). For an ordinary key that
    /// repeat is meaningful — holding `a` should type `aaaa`. For a LOCK key it
    /// carries no information and is actively harmful, because every down
    /// toggles the lock: the user got dozens of toggles and, with Windows
    /// ToggleKeys on, a beep for each.
    ///
    /// b5834e0 fixed the receiver (macos.rs) so the Mac's lock stops flipping,
    /// but the SENDER still put every repeat on the wire. Filtering here rather
    /// than in a platform backend keeps it cross-platform and testable — there
    /// is no Windows target on the dev machine.
    held_lock_keys: HashSet<u32>,
    /// Buttons the active client was sent a down for and no up since: what it
    /// holds because of us, so leaving it can let go of exactly those (#89).
    ///
    /// Kept here, not in `InputCapture`, because only this task knows what
    /// went out. A button pressed before the peer's Ack goes out as an Enter,
    /// and an up for it would be one the peer never had a down for.
    buttons_down_on_peer: HashSet<u32>,
    /// Motion coalescing (opt-in via `HOPS_COALESCE_MOTION`). A high-polling mouse
    /// emits ~800 moves/sec; without this we send one Input per move, flooding the
    /// receiver's injection queue (lag) and burning sender CPU. When enabled,
    /// consecutive Motion deltas are summed into `pending_motion` (a depth-1 dirty
    /// slot) and flushed as ONE event at a capped cadence — total displacement is
    /// preserved, only redundant intermediate samples are dropped (what the OS does
    /// natively). Gated + default-off until A/B-validated against the adaptive edge
    /// crossing on the real rig.
    coalesce_motion: bool,
    pending_motion: Option<(f64, f64)>,
    /// Cumulative pointer displacement from the entry anchor, for Stage 2
    /// absolute motion — reset to 0 at each crossing (Enter), emitted as f32 in
    /// `PointerMotionAbsolute` when the peer negotiated `caps::ABSOLUTE_MOTION`.
    /// Accumulated in f64 (cast to f32 only on the wire) so rounding doesn't
    /// drift over a visit. `abs_seq` is a per-crossing sequence for the Stage 3
    /// servo; the receiver ignores it today.
    abs_vx: f64,
    abs_vy: f64,
    abs_seq: u32,
}

impl CaptureTask {
    fn add_capture(&mut self, handle: CaptureHandle, pos: Position, capture_type: CaptureType) {
        self.captures.push((handle, pos, capture_type));
    }

    fn remove_capture(&mut self, handle: CaptureHandle) {
        self.captures.retain(|&(h, ..)| handle != h);
    }

    fn is_default_capture_at(&self, pos: Position) -> bool {
        self.captures
            .iter()
            .any(|&(_, p, t)| p == pos && t == CaptureType::Default)
    }

    /// Position of a capture, or `Left` if the handle is unknown.
    ///
    /// Both of these used to `.expect()`. `InputCapture::destroy` did not purge
    /// already-queued events, so an event for a handle the consumer had already
    /// forgotten reached here and, with `panic = "abort"`, ended the process
    /// (#63). That hole is closed at the source in `input-capture`; these stay
    /// non-fatal because a lookup returning nothing must never be a reason for a
    /// KVM daemon to die — it strands every peer's held keys.
    fn get_pos(&self, handle: CaptureHandle) -> Position {
        match self.captures.iter().find(|(h, ..)| *h == handle) {
            Some(&(_, pos, _)) => pos,
            None => {
                log::warn!("get_pos: no capture {handle} — it was probably just destroyed");
                Position::Left
            }
        }
    }

    fn get_type(&self, handle: CaptureHandle) -> CaptureType {
        match self.captures.iter().find(|(h, ..)| *h == handle) {
            Some(&(_, _, ty)) => ty,
            None => {
                log::warn!("get_type: no capture {handle} — it was probably just destroyed");
                CaptureType::Default
            }
        }
    }

    async fn run(mut self) {
        loop {
            if let Err(e) = self.do_capture().await {
                log::warn!("input capture exited: {e}");
                // Declining the portal's request switches capture off. Any
                // other end is capture that should run and cannot, which
                // the user is told apart from off, with what to change.
                if !e.cancelled_by_user() {
                    let _ = self
                        .event_tx
                        .send(ICaptureEvent::CaptureFailed(fault_of(&e)));
                }
            }
            loop {
                tokio::select! {
                    r = self.request_rx.recv() => match r.expect("channel closed") {
                        CaptureRequest::Reenable => break,
                        CaptureRequest::Create(h, p, t) => self.add_capture(h, p, t),
                        CaptureRequest::Destroy(h) => self.remove_capture(h),
                        CaptureRequest::Release => { /* nothing to do */ }
                        CaptureRequest::SetReleaseBind(bind) => {
                            self.release_bind.borrow_mut().clone_from(&bind);
                        }
                        // Pairing does not need capture running.
                        CaptureRequest::Dial(h) => self.conn.dial(h).await,
                    },
                    _ = self.cancellation_token.cancelled() => return,
                }
            }
        }
    }

    async fn do_capture(&mut self) -> Result<(), InputCaptureError> {
        /* allow cancelling capture request */
        let mut capture = tokio::select! {
            r = InputCapture::new(self.backend) => r?,
            _ = self.cancellation_token.cancelled() => return Ok(()),
        };

        let _capture_guard = DropGuard::new(
            self.event_tx.clone(),
            ICaptureEvent::CaptureEnabled,
            ICaptureEvent::CaptureDisabled,
        );

        /* create barriers for active clients */
        let r = self.create_captures(&mut capture).await;
        if let Err(e) = r {
            capture.terminate().await?;
            return Err(e.into());
        }

        let r = self.do_capture_session(&mut capture).await;

        // However the session ended (a backend error, its stream closing, or
        // shutdown), the peer we crossed to is sent nothing more from here. Let
        // go of what it holds and say we left, or it keeps the button or key
        // down: while this daemon runs it keeps pinging the peer, so the peer's
        // watchdog never fires.
        self.leave_active_client(&mut capture).await;

        // FIXME replace with async drop when stabilized
        capture.terminate().await?;

        r
    }

    async fn create_captures(&mut self, capture: &mut InputCapture) -> Result<(), CaptureError> {
        let captures = self.captures.clone();
        for (handle, pos, _type) in captures {
            tokio::select! {
                r = capture.create(handle, pos) => r?,
                _ = self.cancellation_token.cancelled() => return Ok(()),
            }
        }
        Ok(())
    }

    async fn do_capture_session(
        &mut self,
        capture: &mut InputCapture,
    ) -> Result<(), InputCaptureError> {
        // ~240 Hz flush cadence for coalesced motion (see `coalesce_motion`); the
        // branch below is inert unless coalescing is on AND a delta is pending.
        let mut motion_flush = tokio::time::interval(Duration::from_millis(4));
        motion_flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = motion_flush.tick(), if self.coalesce_motion && self.pending_motion.is_some() => {
                    self.flush_pending_motion(capture).await?;
                }
                _ = until(self.awaiting_ack), if self.awaiting_ack.is_some() => {
                    self.give_up_on_crossing(capture).await?;
                }
                event = capture.next() => match event {
                    Some(event) => self.handle_capture_event(capture, event?).await?,
                    None => return Ok(()),
                },
                (handle, event, link) = self.conn.recv() => {
                    if let Some(active) = self.active_client {
                        if handle != active {
                            // we only care about events coming from the client we are currently connected to
                            // only `Ack` and `Leave` are relevant
                            continue
                        }
                    }

                    match event {
                        // connection acknowlegded => set state to Sending
                        ProtoEvent::Ack(_) => {
                            log::info!("client {handle} acknowledged the connection!");
                            self.state = State::Sending;
                            if self.active_client == Some(handle) {
                                // The crossing landed. An Ack with no crossing
                                // under way answers a Leave, and says nothing
                                // about whether this peer takes crossings: a
                                // late Ack for a crossing already given up on
                                // looks the same, and a peer that refuses
                                // crossings still Acks a Leave. So only this
                                // branch lifts the backoff.
                                self.awaiting_ack = None;
                                self.unanswered.remove(&handle);
                                self.told.forget(handle);
                                self.acked_at =
                                    self.conn.active_addr(handle).map(|addr| (handle, addr));
                                // The link the Ack came on, not the one the
                                // device is on now: a redial in between
                                // leaves the new link uncrossed.
                                self.acked_link = Some(link);
                            }
                        }
                        // client disconnected
                        ProtoEvent::Leave(_) => {
                            log::info!("releasing capture: left remote client device region");
                            self.release_capture(capture).await?;
                        },
                        _ => {}
                    }
                },
                e = self.request_rx.recv() => match e.expect("channel closed") {
                    CaptureRequest::Reenable => { /* already active */ },
                    CaptureRequest::Dial(h) => self.conn.dial(h).await,
                    CaptureRequest::Release => self.release_capture(capture).await?,
                    CaptureRequest::Create(h, p, t) => {
                        self.add_capture(h, p, t);
                        capture.create(h, p).await?;
                    }
                    CaptureRequest::Destroy(h) => {
                        // Switching off or removing the client we are on:
                        // nothing more reaches it, so let go first. A removed
                        // client is already gone from the client list, which
                        // is why leaving sends to `acked_at`.
                        let released = if self.active_client == Some(h) {
                            log::info!("releasing capture: client {h} was switched off or removed");
                            self.release_capture(capture).await
                        } else {
                            Ok(())
                        };
                        self.remove_capture(h);
                        self.unanswered.remove(&h);
                        self.told.forget(h);
                        released?;
                        capture.destroy(h).await?;
                    }
                    CaptureRequest::SetReleaseBind(bind) => {
                        self.release_bind.borrow_mut().clone_from(&bind);
                    }
                },
                _ = self.cancellation_token.cancelled() => break,
            }
        }
        Ok(())
    }

    /// Send any accumulated coalesced motion as a single Input event, then clear
    /// the slot. Callers flush BEFORE emitting a non-motion event so ordering
    /// holds (a click lands at the summed position). Mirrors the send + release
    /// error handling in `handle_capture_event`.
    async fn flush_pending_motion(
        &mut self,
        capture: &mut InputCapture,
    ) -> Result<(), CaptureError> {
        let Some((dx, dy)) = self.pending_motion.take() else {
            return Ok(());
        };
        if dx == 0.0 && dy == 0.0 {
            return Ok(());
        }
        let Some(handle) = self.active_client else {
            return Ok(());
        };
        if self.cross_again_if_relinked(handle).await {
            return Ok(());
        }
        self.send_motion(capture, handle, dx, dy).await
    }

    /// Whether the crossing to `handle` was acknowledged on a link that is
    /// no longer its link, and so must be made again. Its peer drops what
    /// arrives on a link no Enter crossed, so input sent there is lost
    /// while this machine holds the pointer. The crossing then waits for an
    /// Ack again, which the next event asks for with an Enter, and is given
    /// up on if none comes, as a new one is. Motion not sent yet belonged
    /// to the crossing on the old link and is dropped, and absolute motion
    /// starts again from the origin, where the peer anchors it on that
    /// Enter.
    async fn cross_again_if_relinked(&mut self, handle: CaptureHandle) -> bool {
        if self.state != State::Sending || self.active_client != Some(handle) {
            return false;
        }
        // A crossing with no link known to have taken it is made again.
        match self.conn.link_serial(handle).await {
            Some(now) if self.acked_link != Some(now) => {
                log::info!(
                    "client {handle} is on another link than the one it took the crossing on: \
                     crossing again"
                );
                self.state = State::WaitingForAck;
                self.awaiting_ack = Some(tokio::time::Instant::now() + self.timing.ack_deadline);
                self.acked_link = None;
                self.pending_motion = None;
                self.abs_vx = 0.0;
                self.abs_vy = 0.0;
                self.abs_seq = 0;
                true
            }
            _ => false,
        }
    }

    /// Emit a pointer-motion delta to `handle`. When the peer negotiated
    /// `caps::ABSOLUTE_MOTION`, send cumulative absolute displacement
    /// (`PointerMotionAbsolute`, Stage 2) — self-correcting under loss and the
    /// substrate for the Stage 3 servo; otherwise the classic relative
    /// `Input(Motion)`. Mirrors the send + release-on-error of its callers.
    /// Switching relative→absolute mid-visit is safe: `abs_v*` accumulates only
    /// absolute-path deltas from 0 and the receiver's anchor is 0, so the
    /// reconstructed total matches no matter when the negotiated caps land.
    async fn send_motion(
        &mut self,
        capture: &mut InputCapture,
        handle: CaptureHandle,
        dx: f64,
        dy: f64,
    ) -> Result<(), CaptureError> {
        let event = if self.conn.peer_supports(handle, caps::ABSOLUTE_MOTION) {
            self.abs_vx += dx;
            self.abs_vy += dy;
            self.abs_seq = self.abs_seq.wrapping_add(1);
            // Once-per-crossing confirmation that the peer negotiated absolute
            // motion (abs_seq == 1 is the first emit after a Begin reset). Makes
            // a two-machine A/B unambiguous: no line ⇒ relative fallback.
            if self.abs_seq == 1 {
                log::info!(
                    "absolute motion active for client {handle} (peer negotiated ABSOLUTE_MOTION)"
                );
            }
            ProtoEvent::PointerMotionAbsolute {
                seq: self.abs_seq,
                ts: 0,
                vx: self.abs_vx as f32,
                vy: self.abs_vy as f32,
            }
        } else {
            ProtoEvent::Input(Event::Pointer(PointerEvent::Motion { time: 0, dx, dy }))
        };
        if let Err(e) = self.conn.send(event, handle).await {
            // Debounced (shared with the generic send path): motion is the
            // highest-frequency event, so an undebounced warn floods at
            // ~motion-rate when a peer goes unreachable mid-visit.
            const DUR: Duration = Duration::from_millis(500);
            debounce!(PREV_LOG, DUR, log::warn!("releasing capture (motion): {e}"));
            self.release_capture(capture).await?;
        }
        Ok(())
    }

    async fn handle_capture_event(
        &mut self,
        capture: &mut InputCapture,
        event: (CaptureHandle, CaptureEvent),
    ) -> Result<(), CaptureError> {
        let (handle, event) = event;
        log::trace!("({handle}): {event:?}");

        if capture.keys_pressed(&self.release_bind.borrow()) {
            log::info!("releasing capture: release-bind pressed");
            return self.release_capture(capture).await;
        }

        self.cross_again_if_relinked(handle).await;

        // Motion coalescing: while Sending, sum consecutive Motion deltas into the
        // dirty slot and let the flush timer emit them as one event; any other
        // event flushes the accumulated motion first so it lands in order.
        if self.coalesce_motion {
            match &event {
                CaptureEvent::Input(Event::Pointer(PointerEvent::Motion { dx, dy, .. }))
                    if matches!(self.state, State::Sending)
                        && self.active_client == Some(handle) =>
                {
                    let (px, py) = self.pending_motion.unwrap_or((0.0, 0.0));
                    self.pending_motion = Some((px + dx, py + dy));
                    return Ok(());
                }
                _ => self.flush_pending_motion(capture).await?,
            }
        }

        if event == CaptureEvent::Begin {
            self.event_tx
                .send(ICaptureEvent::CaptureBegin(handle))
                .expect("channel closed");
        }

        // enter only capture (for incoming connections)
        if self.get_type(handle) == CaptureType::EnterOnly {
            // if there is no active outgoing connection at the current capture,
            // we release the capture
            if !self.is_default_capture_at(self.get_pos(handle)) {
                // per-event barrier probe (fires on every move at this edge); not a
                // lifecycle transition, so keep it at trace.
                log::trace!("releasing capture: no active client at this position");
                capture.release().await?;
            }
            // we dont care about events from incoming handles except for releasing the capture
            return Ok(());
        }

        // Re-anchor absolute motion on EVERY crossing (Begin past the
        // EnterOnly return above, i.e. one that actually sends an Enter), not
        // only when the active client changes: the receiver re-anchors its
        // reconstruction at 0 on that Enter, so our cumulative must reset in
        // lock-step. Otherwise the stale cumulative emits a huge first delta
        // and teleports the remote cursor. Begin fires once per crossing
        // (idempotent).
        if event == CaptureEvent::Begin {
            self.abs_vx = 0.0;
            self.abs_vy = 0.0;
            self.abs_seq = 0;
        }

        // activated a new client
        if event == CaptureEvent::Begin && Some(handle) != self.active_client {
            // Only a peer with a live link can take the pointer. Anything
            // else would be held at the edge for a crossing that cannot land
            // (#115), and would count as entering it.
            if let Some(reason) = self.cannot_cross(handle).await {
                self.refused(handle, reason);
                return self.release_capture(capture).await;
            }
            self.state = State::WaitingForAck;
            self.active_client.replace(handle);
            self.awaiting_ack = Some(tokio::time::Instant::now() + self.timing.ack_deadline);
            self.event_tx
                .send(ICaptureEvent::ClientEntered(handle))
                .expect("channel closed");
        }

        // Nothing reaches a peer outside a crossing to it that was let
        // through. An event queued behind a refused or ended crossing is the
        // local pointer's: sent, it went out as an Enter the gate had just
        // refused, or as input after the Leave.
        if self.active_client != Some(handle) {
            return Ok(());
        }

        // Sending motion routes through send_motion (absolute-aware). Only
        // reached when coalescing is OFF — the coalesce path above intercepts
        // Sending motion and flushes it via flush_pending_motion (also
        // absolute-aware). Matched by reference so `event` stays owned for the
        // generic path below (non-motion events + the Enter re-sends).
        if matches!(self.state, State::Sending) {
            if let CaptureEvent::Input(Event::Pointer(PointerEvent::Motion { dx, dy, .. })) = &event
            {
                return self.send_motion(capture, handle, *dx, *dy).await;
            }
        }

        // Lock-key auto-repeat carries no information and toggles the lock on
        // every down — drop it before it reaches the wire.
        if let CaptureEvent::Input(Event::Keyboard(KeyboardEvent::Key { key, state, .. })) = &event
        {
            if is_lock_key(*key) {
                if *state == 0 {
                    self.held_lock_keys.remove(key);
                } else if !self.held_lock_keys.insert(*key) {
                    log::trace!("swallowing a lock key's auto-repeat");
                    return Ok(());
                }
            }
        }

        let opposite_pos = to_proto_pos(self.get_pos(handle).opposite());

        let event = match event {
            CaptureEvent::Begin => ProtoEvent::Enter(opposite_pos),
            CaptureEvent::Input(e) => match self.state {
                // connection not acknowledged, repeat `Enter` event
                State::WaitingForAck => ProtoEvent::Enter(opposite_pos),
                State::Sending => ProtoEvent::Input(e),
            },
        };

        // A link that is up and not answered on yet is still connecting:
        // its peer has said nothing about its input, and a send there is
        // refused as if it had said it takes none. A crossing made again
        // after a redial meets one whenever the pointer moves before the
        // first Pong. The Enter waits for that answer, asked for again by
        // the next event, and the crossing is given up on at its deadline
        // if none comes, so the pointer is held no longer than any crossing.
        if matches!(event, ProtoEvent::Enter(_))
            && self.awaiting_ack.is_some()
            && self.conn.active_addr(handle).is_some()
            && !self.conn.peer_answered(handle)
        {
            log::debug!("client {handle}: its link is not answered yet; the Enter waits");
            return Ok(());
        }

        // Recorded before the send: a down whose send fails may still have
        // reached the peer, and an up it never needed is dropped there.
        if let ProtoEvent::Input(Event::Pointer(PointerEvent::Button { button, state, .. })) = event
        {
            if state == 0 {
                self.buttons_down_on_peer.remove(&button);
            } else {
                self.buttons_down_on_peer.insert(button);
            }
        }

        if let Err(e) = self.conn.send(event, handle).await {
            const DUR: Duration = Duration::from_millis(500);
            debounce!(PREV_LOG, DUR, log::warn!("releasing capture: {e}"));
            // The link failed before the peer took the crossing: it did not
            // land, and the user is told why.
            if self.state == State::WaitingForAck && self.active_client == Some(handle) {
                self.refused(handle, refusal(&e));
            }
            // Full release (not just capture.release()): also resets active_client
            // + state, so a re-entry to the SAME client re-arms the Enter->Ack
            // handshake (State::WaitingForAck) instead of silently skipping it and
            // sending Input the peer hasn't acknowledged.
            self.release_capture(capture).await?;
        }
        Ok(())
    }

    async fn release_capture(&mut self, capture: &mut InputCapture) -> Result<(), CaptureError> {
        self.leave_active_client(capture).await;
        capture.release().await
    }

    /// Why a crossing to `handle` cannot land now, if it cannot: a peer this
    /// machine may not drive, no link to its peer (a dial is started, as a
    /// crossing always has), a peer that has not answered a ping on its link
    /// yet or says it is not injecting, or one that left the last crossing
    /// unacknowledged a moment ago.
    async fn cannot_cross(&mut self, handle: CaptureHandle) -> Option<CrossingRefusal> {
        // First, and with no dial: a dial to it is refused after its
        // handshake, and the crossing would then be reported as a link that
        // is down rather than a permission this machine lacks.
        if self.conn.may_not_drive(handle).await {
            return Some(CrossingRefusal::NotPermitted);
        }
        // A link that is up and has not been answered on yet is still
        // connecting: its peer has said nothing about its input.
        if self.conn.active_addr(handle).is_none() || !self.conn.peer_answered(handle) {
            self.conn.dial(handle).await;
            return Some(CrossingRefusal::NotConnected);
        }
        if !self.conn.peer_alive(handle) {
            return Some(CrossingRefusal::NotAcceptingInput);
        }
        match self.unanswered.get(&handle) {
            Some(at) if at.elapsed() < self.timing.unanswered_backoff => {
                Some(CrossingRefusal::Unanswered)
            }
            _ => None,
        }
    }

    /// The crossing to `handle` did not land: tell the service why, once
    /// per device and reason while the user keeps pushing at the edge.
    fn refused(&mut self, handle: CaptureHandle, reason: CrossingRefusal) {
        if self.told.first(handle, reason, Instant::now()) {
            log::info!("crossing to client {handle} refused ({reason}); the pointer stays here");
            self.event_tx
                .send(ICaptureEvent::CrossingRefused { handle, reason })
                .expect("channel closed");
        } else {
            log::debug!("crossing to client {handle} refused ({reason})");
        }
    }

    /// The active client did not acknowledge its crossing in time: give the
    /// pointer back, and tell it the visit is over in case the Enter landed
    /// and only the Ack was lost.
    async fn give_up_on_crossing(
        &mut self,
        capture: &mut InputCapture,
    ) -> Result<(), CaptureError> {
        self.awaiting_ack = None;
        let Some(handle) = self.active_client else {
            return Ok(());
        };
        log::warn!(
            "releasing capture: client {handle} did not acknowledge the crossing within {:?}",
            self.timing.ack_deadline
        );
        self.unanswered.insert(handle, Instant::now());
        self.refused(handle, CrossingRefusal::Unanswered);
        self.release_capture(capture).await
    }

    /// Tell the active client we are leaving, after letting go of everything
    /// it was sent as held. Touches only the connection and the capture's own
    /// bookkeeping, never the capture backend, so it still works when that
    /// backend has just failed.
    async fn leave_active_client(&mut self, capture: &mut InputCapture) {
        // Drop any un-flushed coalesced motion — it's <=1 flush-interval old and
        // belongs to the visit we're leaving; sending it after Leave would be
        // out of order.
        self.pending_motion = None;
        self.awaiting_ack = None;
        let buttons = std::mem::take(&mut self.buttons_down_on_peer);
        let acked_at = self.acked_at.take();
        self.acked_link = None;
        // If we have an active client, notify them we're leaving
        if let Some(handle) = self.active_client.take() {
            let addr = acked_at
                .filter(|&(acked, _)| acked == handle)
                .map(|(_, addr)| addr);
            // Buttons first, for the same reason as the keys below: a release
            // bind pressed mid-drag leaves capture with the button down, and its
            // button-up then reaches this machine instead of the peer, which
            // keeps dragging (#89). First, because that is the order a person
            // lets go of a modifier-drag.
            for button in buttons {
                let button_up = ProtoEvent::Input(Event::Pointer(PointerEvent::Button {
                    time: 0,
                    button,
                    state: 0,
                }));
                if let Err(e) = self.send_leaving(button_up, handle, addr).await {
                    log::warn!("failed to send button-up to client {handle}: {e}");
                }
            }
            // Synthesize key-up events for every key still held in the
            // capture's pressed_keys set BEFORE sending Leave. Without
            // this, pressing the release-bind chord (typically all four
            // modifiers) leaves the peer with phantom held modifiers:
            // the down events were forwarded while capture was active,
            // but the matching up events arrive after the local tap
            // flips to passthrough and never reach the peer. The peer
            // then runs every subsequent keystroke through those held
            // mods until its watchdog times out (1+ s) or our Leave
            // arrives — and Leave can be lost over UDP/DTLS.
            for key in capture.take_pressed_keys() {
                let key_up = ProtoEvent::Input(Event::Keyboard(KeyboardEvent::Key {
                    time: 0,
                    key: key as u32,
                    state: 0,
                }));
                if let Err(e) = self.send_leaving(key_up, handle, addr).await {
                    log::warn!("failed to send key-up to client {handle}: {e}");
                }
            }
            // Reset the modifier mask too. The peer's input-emulation
            // layer keeps a separate XKB-style modifier state that's
            // updated by KeyboardEvent::Modifiers, distinct from the
            // pressed_keys set drained above. Without this, an
            // already-locked CapsLock would survive the release.
            let mods_zero = ProtoEvent::Input(Event::Keyboard(KeyboardEvent::Modifiers {
                depressed: 0,
                latched: 0,
                locked: 0,
                group: 0,
            }));
            if let Err(e) = self.send_leaving(mods_zero, handle, addr).await {
                log::warn!("failed to reset modifiers on client {handle}: {e}");
            }

            log::info!("sending Leave event to client {handle}");
            if let Err(e) = self.send_leaving(ProtoEvent::Leave(0), handle, addr).await {
                log::warn!("failed to send Leave to client {handle}: {e}");
            }
        }
    }

    /// Send one of the frames that end a visit: to the connection the peer
    /// acknowledged the crossing on when there was one, else as any input.
    async fn send_leaving(
        &self,
        event: ProtoEvent,
        handle: CaptureHandle,
        addr: Option<SocketAddr>,
    ) -> Result<(), LanMouseConnectionError> {
        match addr {
            Some(addr) => self.conn.send_to(event, handle, addr).await,
            None => self.conn.send(event, handle).await,
        }
    }
}

thread_local! {
    static PREV_LOG: Cell<Option<Instant>> = const { Cell::new(None) };
}

/// Resolves at `deadline`; never, without one.
async fn until(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// What a failed send says about a crossing that had not landed yet.
fn refusal(e: &LanMouseConnectionError) -> CrossingRefusal {
    match e {
        LanMouseConnectionError::NotPermitted => CrossingRefusal::NotPermitted,
        LanMouseConnectionError::TargetEmulationDisabled => CrossingRefusal::NotAcceptingInput,
        _ => CrossingRefusal::NotConnected,
    }
}

/// Which refused crossings the service was told of, and when.
///
/// A user pushing at the edge of a device that cannot take the pointer
/// makes a crossing per push. Saying why once is the point; saying it per
/// push floods the activity log and re-raises a banner just dismissed.
#[derive(Default)]
struct Told(HashMap<CaptureHandle, (CrossingRefusal, Instant)>);

impl Told {
    /// The same refusal is told again after this long.
    const AGAIN_AFTER: Duration = Duration::from_secs(10);

    /// Whether this refusal is news: a new reason for `handle`, or the same
    /// one told long enough ago. Records it if so.
    fn first(&mut self, handle: CaptureHandle, reason: CrossingRefusal, now: Instant) -> bool {
        match self.0.get(&handle) {
            Some(&(told, at))
                if told == reason && now.saturating_duration_since(at) < Self::AGAIN_AFTER =>
            {
                false
            }
            _ => {
                self.0.insert(handle, (reason, now));
                true
            }
        }
    }

    fn forget(&mut self, handle: CaptureHandle) {
        self.0.remove(&handle);
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum State {
    #[default]
    WaitingForAck,
    Sending,
}

fn to_capture_pos(pos: hops_ipc::Position) -> input_capture::Position {
    match pos {
        hops_ipc::Position::Left => input_capture::Position::Left,
        hops_ipc::Position::Right => input_capture::Position::Right,
        hops_ipc::Position::Top => input_capture::Position::Top,
        hops_ipc::Position::Bottom => input_capture::Position::Bottom,
    }
}

fn to_proto_pos(pos: input_capture::Position) -> hops_proto::Position {
    match pos {
        input_capture::Position::Left => hops_proto::Position::Left,
        input_capture::Position::Right => hops_proto::Position::Right,
        input_capture::Position::Top => hops_proto::Position::Top,
        input_capture::Position::Bottom => hops_proto::Position::Bottom,
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
    /// A receiver already gone has no one left to tell. Panicking here
    /// instead turns a capture task dropped after its owner (a test
    /// unwinding, a runtime shutting down) into a second panic, which
    /// aborts the process if it lands while the first is unwinding.
    fn drop(&mut self) {
        if let Some(on_drop) = self.on_drop.take() {
            let _ = self.tx.send(on_drop);
        }
    }
}

#[cfg(test)]
mod lock_key_tests {
    use super::is_lock_key;
    use input_event::scancode;

    /// Measured on the rig 2026-08-19: holding Caps Lock produced 38 consecutive
    /// key-DOWNS with no key-up between, each of which toggles the lock. With
    /// Windows ToggleKeys on, that is 38 beeps.
    #[test]
    fn only_lock_keys_are_repeat_filtered() {
        for k in [
            scancode::Linux::KeyCapsLock,
            scancode::Linux::KeyNumlock,
            scancode::Linux::KeyScrollLock,
        ] {
            assert!(
                is_lock_key(k as u32),
                "{k:?} toggles, so repeat must be dropped"
            );
        }
        // ordinary keys MUST keep their auto-repeat — holding `a` types `aaaa`,
        // and a filter that swallowed those would be a far worse bug
        for k in [
            scancode::Linux::KeyA,
            scancode::Linux::KeySpace,
            scancode::Linux::KeyLeftShift,
            scancode::Linux::KeyBackspace,
        ] {
            assert!(!is_lock_key(k as u32), "{k:?} must keep auto-repeat");
        }
    }
}

#[cfg(test)]
mod release_mid_drag {
    //! Leaving a peer mid-drag must hand it the button-up it will otherwise
    //! never see (#89), however the visit ends: the release bind, the capture
    //! backend failing, the client being switched off or removed, a config
    //! reload, or shutdown.
    //!
    //! Driven end to end over loopback: scripted capture feeds the real capture
    //! task, which sends through the real connection to a real listener. The
    //! assertion is on what arrives at that listener, because the receiver's own
    //! teardown now also releases held buttons and would hide a sender that
    //! forgot to.

    use super::*;
    use crate::listen::{LanMouseListener, ListenEvent};
    use crate::test_harness::{Dialer, Notices, dialer, machine, run_local, trust, wait_until};
    use crate::trust::Caps;
    use input_capture::scripted::Script;
    use input_event::{BTN_LEFT, BTN_RIGHT};

    const PATIENCE: Duration = Duration::from_secs(20);

    fn button(button: u32, state: u32) -> Event {
        Event::Pointer(PointerEvent::Button {
            time: 0,
            button,
            state,
        })
    }

    /// `ProtoEvent` has no `PartialEq`; these are the kinds the tests look for.
    fn same(a: &ProtoEvent, b: &ProtoEvent) -> bool {
        match (a, b) {
            (ProtoEvent::Input(a), ProtoEvent::Input(b)) => a == b,
            (ProtoEvent::Leave(_), ProtoEvent::Leave(_)) => true,
            (ProtoEvent::Enter(_), ProtoEvent::Enter(_)) => true,
            (ProtoEvent::Ping, ProtoEvent::Ping) => true,
            _ => false,
        }
    }

    fn key(key: scancode::Linux, state: u8) -> CaptureEvent {
        CaptureEvent::Input(Event::Keyboard(KeyboardEvent::Key {
            time: 0,
            key: key as u32,
            state,
        }))
    }

    pub(super) const MOTION: Event = Event::Pointer(PointerEvent::Motion {
        time: 0,
        dx: 1.0,
        dy: 0.0,
    });

    /// A sender's capture task, crossed onto a receiver that writes down every
    /// frame reaching it.
    pub(super) struct Visit {
        wire: Rc<RefCell<Vec<ProtoEvent>>>,
        pub(super) script: Script,
        pub(super) capture: Capture,
        handle: hops_ipc::ClientHandle,
        /// The sender's client list, which the service changes before it
        /// tells capture.
        clients: crate::client::ClientManager,
        /// What the sender's trust store grants the receiver.
        pub(super) trust: crate::transport::Trust,
        /// The receiver's fingerprint.
        pub(super) receiver: String,
        /// The sender's fingerprint.
        sender: String,
        /// Whether the receiver acknowledges a crossing, from now on.
        acks: Rc<std::cell::Cell<bool>>,
        /// The receiver's answer to a ping from now on, or `None` for none.
        pongs: Rc<std::cell::Cell<Option<bool>>>,
        /// Closes the receiver's end of a link.
        revoker: crate::listen::ConnRevoker,
        _notices: Notices,
    }

    /// Waits no loaded test run can reach, for the tests that are about
    /// something other than how long a crossing waits.
    pub(super) const PATIENT: Timing = Timing {
        ack_deadline: Duration::from_secs(3600),
        unanswered_backoff: Duration::from_secs(3600),
    };

    /// How the receiver answers the sender.
    #[derive(Clone, Copy)]
    pub(super) struct Answers {
        /// Its answer to every ping, or `None` to never answer one.
        pub(super) pong: Option<bool>,
        /// Whether it acknowledges a crossing.
        pub(super) ack: bool,
    }

    impl Visit {
        /// Cross onto a receiver that answers like a daemon. With `ack` false
        /// it never acknowledges the Enter, so the sender stays waiting for it.
        pub(super) async fn start(ack: bool) -> Visit {
            Self::start_with(ack, PATIENT).await
        }

        /// As [`Visit::start`], the crossing timed by `timing`.
        pub(super) async fn start_with(ack: bool, timing: Timing) -> Visit {
            let visit = Self::connect(
                Answers {
                    pong: Some(true),
                    ack,
                },
                timing,
            )
            .await;
            visit.cross(ack).await;
            visit
        }

        /// A sender linked to a receiver that answers as `answers` says,
        /// not crossed yet. Returns once the link is up and, if the receiver
        /// answers pings, once one was answered.
        pub(super) async fn connect(answers: Answers, timing: Timing) -> Visit {
            let receiver = machine();
            let sender = machine();
            let (clipboard_tx, _) = channel();
            let (mut listener, port) = LanMouseListener::bind_loopback(
                receiver.identity.clone(),
                trust(&receiver, &[&sender], Caps::INBOUND),
                clipboard_tx,
            )
            .await
            .expect("listener");
            let wire: Rc<RefCell<Vec<ProtoEvent>>> = Default::default();
            let received = wire.clone();
            let acks = Rc::new(std::cell::Cell::new(answers.ack));
            let acking = acks.clone();
            let pongs = Rc::new(std::cell::Cell::new(answers.pong));
            let ponging = pongs.clone();
            let revoker = listener.revoker();
            spawn_local(async move {
                while let Some(event) = listener.next().await {
                    let ListenEvent::Msg { event, addr } = event else {
                        continue;
                    };
                    received.borrow_mut().push(event);
                    match event {
                        ProtoEvent::Ping => {
                            if let Some(alive) = ponging.get() {
                                listener.reply(addr, ProtoEvent::Pong(alive)).await
                            }
                        }
                        ProtoEvent::Enter(_) if acking.get() => {
                            listener.reply(addr, ProtoEvent::Ack(0)).await
                        }
                        _ => {}
                    }
                }
            });

            let sender_trust = trust(&sender, &[&receiver], Caps::OUTBOUND);
            let Dialer {
                conn,
                handle,
                notices,
                clients,
            } = {
                let d = dialer(
                    &sender,
                    sender_trust.clone(),
                    port,
                    hops_ipc::Position::Left,
                );
                match answers.pong {
                    Some(true) => d.until_alive().await,
                    pong => {
                        d.conn.dial(d.handle).await;
                        wait_until("the link to come up", PATIENCE, || {
                            d.clients.active_addr(d.handle).is_some()
                        })
                        .await;
                        if pong.is_some() {
                            wait_until("the receiver to answer a ping", PATIENCE, || {
                                d.clients.answered(d.handle)
                            })
                            .await;
                        }
                    }
                }
                d
            };

            let script = Script::new();
            let bind = vec![scancode::Linux::KeyLeftCtrl, scancode::Linux::KeyLeftShift];
            let capture = Capture::with_timing(Some(script.backend()), conn, bind, timing);
            capture.create(handle, hops_ipc::Position::Left, CaptureType::Default);
            Visit {
                wire,
                script,
                capture,
                handle,
                clients,
                trust: sender_trust,
                receiver: receiver.fingerprint.clone(),
                sender: sender.fingerprint.clone(),
                acks,
                pongs,
                revoker,
                _notices: notices,
            }
        }

        /// Cross (again), and wait until the peer was sent an Enter for it.
        /// Only a Begin is pushed until then, so that Enter proves the capture
        /// task took the crossing: a Begin that lands before the capture exists
        /// is dropped. Acknowledged, then keep moving until motion is on the
        /// wire, since before the Ack input goes out as repeated Enters.
        pub(super) async fn cross(&self, ack: bool) {
            let after = self.count(&ProtoEvent::Leave(0));
            self.until(
                after,
                ProtoEvent::Enter(hops_proto::Position::Right),
                CaptureEvent::Begin,
            )
            .await;
            if ack {
                self.until(
                    after,
                    ProtoEvent::Input(MOTION),
                    CaptureEvent::Input(MOTION),
                )
                .await;
            }
        }

        /// Cross onto a receiver that acknowledges, and say how long it took
        /// until input reached it; `None` if the crossing was given up on
        /// first.
        pub(super) async fn cross_timed(&self) -> Option<Duration> {
            let started = tokio::time::Instant::now();
            let after = self.count(&ProtoEvent::Leave(0));
            self.until(
                after,
                ProtoEvent::Enter(hops_proto::Position::Right),
                CaptureEvent::Begin,
            )
            .await;
            while self.since_leave(after, &ProtoEvent::Input(MOTION)) == 0 {
                if self.count(&ProtoEvent::Leave(0)) > after || !self.script.held() {
                    return None;
                }
                assert!(started.elapsed() < PATIENCE, "never crossed");
                self.script
                    .push(Position::Left, CaptureEvent::Input(MOTION));
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Some(started.elapsed())
        }

        /// Push `event` until `want` has arrived after the `leaves`-th Leave.
        async fn until(&self, leaves: usize, want: ProtoEvent, event: CaptureEvent) {
            let started = tokio::time::Instant::now();
            while self.since_leave(leaves, &want) == 0 {
                assert!(started.elapsed() < PATIENCE, "never crossed");
                self.script.push(Position::Left, event);
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        /// The receiver closes the link and the sender dials it again,
        /// with no event captured in between. The receiver then acknowledges
        /// a crossing only if `acks`, and answers pings with `pong`. Returns
        /// once the new link is up and, if the receiver answers pings, once
        /// one was answered on it: until then the sender has not heard
        /// whether its peer takes input.
        pub(super) async fn relink(&self, acks: bool, pong: Option<bool>) {
            self.acks.set(acks);
            self.pongs.set(pong);
            assert_eq!(self.revoker.close_fingerprint(&self.sender).await, 1);
            wait_until("the link to drop", PATIENCE, || {
                self.clients.active_addr(self.handle).is_none()
            })
            .await;
            self.capture.dial(self.handle);
            wait_until("the link to be made again", PATIENCE, || {
                self.clients.active_addr(self.handle).is_some()
            })
            .await;
            if pong.is_some() {
                wait_until(
                    "the receiver to answer a ping on the new link",
                    PATIENCE,
                    || self.clients.answered(self.handle),
                )
                .await;
            }
        }

        /// The receiver answers pings with `pong` from now on.
        pub(super) fn pong(&self, pong: Option<bool>) {
            self.pongs.set(pong);
        }

        pub(super) fn frames(&self) -> Vec<ProtoEvent> {
            self.wire.borrow().clone()
        }

        pub(super) fn count(&self, want: &ProtoEvent) -> usize {
            self.wire.borrow().iter().filter(|e| same(e, want)).count()
        }

        /// How many `want` arrived after the first `from` frames.
        pub(super) fn since(&self, from: usize, want: &ProtoEvent) -> usize {
            let wire = self.wire.borrow();
            wire[from.min(wire.len())..]
                .iter()
                .filter(|e| same(e, want))
                .count()
        }

        /// How many `want` arrived after the `leaves`-th Leave.
        pub(super) fn since_leave(&self, leaves: usize, want: &ProtoEvent) -> usize {
            let wire = self.wire.borrow();
            let start = if leaves == 0 {
                0
            } else {
                wire.iter()
                    .enumerate()
                    .filter(|(_, e)| same(e, &ProtoEvent::Leave(0)))
                    .nth(leaves - 1)
                    .map_or(wire.len(), |(i, _)| i + 1)
            };
            wire[start..].iter().filter(|e| same(e, want)).count()
        }

        fn position(&self, want: &ProtoEvent) -> Option<usize> {
            self.wire.borrow().iter().position(|e| same(e, want))
        }

        /// Press `b` and wait until the peer has the button-down.
        pub(super) async fn press(&self, b: u32) {
            let down = ProtoEvent::Input(button(b, 1));
            let before = self.count(&down);
            self.script
                .push(Position::Left, CaptureEvent::Input(button(b, 1)));
            wait_until("the button-down to arrive", PATIENCE, || {
                self.count(&down) > before
            })
            .await;
        }

        /// Wait up to `limit` for `n` Leaves; say whether they arrived.
        pub(super) async fn leaves(&self, n: usize, limit: Duration) -> bool {
            let started = tokio::time::Instant::now();
            while self.count(&ProtoEvent::Leave(0)) < n {
                if started.elapsed() > limit {
                    return false;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            true
        }

        /// The peer was sent the left button-up after the down and before the
        /// first Leave.
        fn up_before_leave(&self) -> bool {
            let (Some(down), Some(leave)) = (
                self.position(&ProtoEvent::Input(button(BTN_LEFT, 1))),
                self.position(&ProtoEvent::Leave(0)),
            ) else {
                return false;
            };
            self.wire.borrow().iter().enumerate().any(|(i, e)| {
                i > down && i < leave && same(e, &ProtoEvent::Input(button(BTN_LEFT, 0)))
            })
        }

        pub(super) fn release_bind(&self) {
            self.script
                .push(Position::Left, key(scancode::Linux::KeyLeftCtrl, 1));
            self.script
                .push(Position::Left, key(scancode::Linux::KeyLeftShift, 1));
        }
    }

    // LEDGER T7 | class B | 2 frames received by listen::LanMouseListener
    /// Also: only a button still down is let go of, and only once. A click
    /// already finished gets no second up, and a second release sends nothing
    /// for a button the first one let go of.
    #[test]
    fn a_release_chord_mid_drag_sends_the_button_up() {
        run_local(async {
            let mut v = Visit::start(true).await;

            // A right click, finished before the drag.
            v.press(BTN_RIGHT).await;
            v.script
                .push(Position::Left, CaptureEvent::Input(button(BTN_RIGHT, 0)));
            // Press the left button, then the release bind while it is down.
            v.press(BTN_LEFT).await;
            v.release_bind();
            assert!(v.leaves(1, PATIENCE).await, "no Leave: {:?}", v.frames());

            assert!(
                v.up_before_leave(),
                "the release bind was pressed mid-drag and the peer was sent no \
                 button-up before Leave: {:?}",
                v.frames()
            );
            assert_eq!(
                v.count(&ProtoEvent::Input(button(BTN_RIGHT, 0))),
                1,
                "the right button was already let go of, and leaving sent it \
                 another up: {:?}",
                v.frames()
            );

            // Cross again and leave again, holding nothing.
            v.cross(true).await;
            v.release_bind();
            assert!(
                v.leaves(2, PATIENCE).await,
                "no second Leave: {:?}",
                v.frames()
            );
            assert_eq!(
                v.count(&ProtoEvent::Input(button(BTN_LEFT, 0))),
                1,
                "the second release sent another up for the left button the \
                 first one had already let go of: {:?}",
                v.frames()
            );

            v.capture.terminate().await;
        });
    }

    // LEDGER T14 | class B | 2 frames received by listen::LanMouseListener
    /// Before the peer's Ack every input goes out as an Enter, so a button
    /// pressed then was never down on the peer. An up for it would end
    /// whatever holds that button there.
    #[test]
    fn a_button_pressed_before_the_ack_gets_no_button_up() {
        run_local(async {
            let mut v = Visit::start(false).await;

            v.script
                .push(Position::Left, CaptureEvent::Input(button(BTN_LEFT, 1)));
            v.release_bind();
            assert!(v.leaves(1, PATIENCE).await, "no Leave: {:?}", v.frames());

            assert_eq!(
                v.count(&ProtoEvent::Input(button(BTN_LEFT, 0))),
                0,
                "the left button was pressed before the Ack, so the peer never \
                 had it down, and leaving sent it a button-up: {:?}",
                v.frames()
            );

            v.capture.terminate().await;
        });
    }

    // LEDGER T15 | class B | 2 frames received by listen::LanMouseListener
    /// The capture backend dying mid-drag ends the visit as surely as a
    /// release bind. The daemon keeps pinging the peer, so nothing else on the
    /// peer's side ever lets go.
    #[test]
    fn a_capture_backend_failing_mid_drag_sends_the_button_up() {
        run_local(async {
            let mut v = Visit::start(true).await;
            v.press(BTN_LEFT).await;

            v.script.fail();

            assert!(
                v.leaves(1, Duration::from_secs(10)).await && v.up_before_leave(),
                "the capture backend failed mid-drag and the peer was sent no \
                 button-up and Leave: {:?}",
                v.frames()
            );

            v.capture.terminate().await;
        });
    }

    // LEDGER T16 | class B | 2 frames received by listen::LanMouseListener
    /// Switching off the client the cursor is on: nothing more is sent to it,
    /// so it must be let go first. In the service's order: the client list
    /// first, then capture.
    #[test]
    fn switching_off_the_client_mid_drag_sends_the_button_up() {
        run_local(async {
            let mut v = Visit::start(true).await;
            v.press(BTN_LEFT).await;

            assert!(v.clients.deactivate_client(v.handle), "precondition");
            v.capture.destroy(v.handle);

            assert!(
                v.leaves(1, Duration::from_secs(10)).await && v.up_before_leave(),
                "the client was switched off mid-drag and was sent no button-up \
                 and Leave: {:?}",
                v.frames()
            );

            v.capture.terminate().await;
        });
    }

    // LEDGER T19 | class B | 2 frames received by listen::LanMouseListener
    /// Removing the client the cursor is on. The service drops it from the
    /// client list before capture hears of it, so its address can no longer
    /// be looked up. The peer still holds the button, and this daemon's pings
    /// keep its watchdog from ever firing.
    #[test]
    fn removing_the_client_mid_drag_sends_the_button_up() {
        run_local(async {
            let mut v = Visit::start(true).await;
            v.press(BTN_LEFT).await;

            assert!(v.clients.remove_client(v.handle).is_some(), "precondition");
            v.capture.destroy(v.handle);

            assert!(
                v.leaves(1, Duration::from_secs(10)).await && v.up_before_leave(),
                "the client was removed mid-drag and was sent no button-up and \
                 Leave: {:?}",
                v.frames()
            );

            v.capture.terminate().await;
        });
    }

    // LEDGER T20 | class B | 2 frames received by listen::LanMouseListener
    /// A config reload that edits the entry of the client the cursor is on
    /// removes that client and adds its replacement, under a new handle,
    /// before capture hears of either.
    #[test]
    fn reloading_the_config_mid_drag_sends_the_button_up() {
        run_local(async {
            let mut v = Visit::start(true).await;
            v.press(BTN_LEFT).await;

            // Service::handle_config_change, for the one client.
            let (config, state) = v.clients.remove_client(v.handle).expect("precondition");
            v.capture.destroy(v.handle);
            let handle = v.clients.add_with_config(crate::config::ConfigClient {
                label: None,
                ips: config.fix_ips.iter().copied().collect(),
                hostname: config.hostname,
                port: config.port,
                pos: config.pos,
                active: true,
                enter_hook: config.cmd,
                fingerprint: state.peer_fingerprint,
                geometry: None,
            });
            v.clients.deactivate_client(handle);
            assert!(v.clients.activate_client(handle), "precondition");
            v.capture
                .create(handle, hops_ipc::Position::Left, CaptureType::Default);

            assert!(
                v.leaves(1, Duration::from_secs(10)).await && v.up_before_leave(),
                "the config was reloaded mid-drag and the peer was sent no \
                 button-up and Leave: {:?}",
                v.frames()
            );

            v.capture.terminate().await;
        });
    }

    // LEDGER T17 | class B | 2 frames received by listen::LanMouseListener
    #[test]
    fn shutting_down_capture_mid_drag_sends_the_button_up() {
        run_local(async {
            let mut v = Visit::start(true).await;
            v.press(BTN_LEFT).await;

            v.capture.terminate().await;

            assert!(
                v.leaves(1, Duration::from_secs(10)).await && v.up_before_leave(),
                "capture shut down mid-drag and the peer was sent no button-up \
                 and Leave: {:?}",
                v.frames()
            );
        });
    }

    // LEDGER T117-2 | class B | 5 log line: Capture task and LanMouseConnection::send over loopback
    /// The sender's side of #117: every key it captures and sends is traced,
    /// and a held lock key's auto-repeat is traced as it is dropped. At trace,
    /// which a developer turns on to look at something else, none of those
    /// lines may say which key.
    #[test]
    fn keys_captured_and_sent_are_not_named_in_the_log() {
        const TYPED: scancode::Linux = scancode::Linux::KeyA;
        const LOCK: scancode::Linux = scancode::Linux::KeyCapsLock;
        run_local(async {
            let logs = crate::test_harness::logs::capture();
            let v = Visit::start(true).await;

            // Caps Lock held long enough to repeat: the repeat is dropped.
            v.script.push(Position::Left, key(LOCK, 1));
            v.script.push(Position::Left, key(LOCK, 1));
            v.script.push(Position::Left, key(LOCK, 0));
            v.script.push(Position::Left, key(TYPED, 1));
            v.script.push(Position::Left, key(TYPED, 0));
            let up = ProtoEvent::Input(Event::Keyboard(KeyboardEvent::Key {
                time: 0,
                key: TYPED as u32,
                state: 0,
            }));
            wait_until("the key-up to reach the peer", PATIENCE, || {
                v.count(&up) > 0
            })
            .await;

            let lines = logs.lines();
            let seen = |target: &str, needles: &[&str]| {
                lines.iter().any(|l| {
                    l.level == log::Level::Trace
                        && l.target == target
                        && needles.iter().all(|n| l.text.contains(n))
                })
            };
            // Without these, a capture that never saw the lines would pass.
            assert!(
                seen("hops::capture", &["Keyboard"]),
                "the capture task's trace line for a key never reached the capture: {lines:#?}"
            );
            assert!(
                seen("hops::connect", &[">->->->->-", "key("]),
                "the sender's trace line for a key on the wire never reached the capture: {lines:#?}"
            );
            assert!(
                seen("hops::capture", &["auto-repeat"]),
                "the trace line for the dropped lock-key repeat never reached the capture: {lines:#?}"
            );
            for held in [TYPED, LOCK] {
                let naming = logs.naming(held);
                assert!(
                    naming.is_empty(),
                    "the log names {held:?}. Raising the log level must not record \
                     what someone types: {naming:#?}"
                );
            }
        });
    }
}

#[cfg(test)]
mod a_refused_crossing {
    //! A crossing the other machine cannot take leaves the pointer on this
    //! one (#115). Before, a crossing the peer never acknowledged held the
    //! pointer until the release bind, and a crossing to a device with no
    //! link counted as entering it.
    //!
    //! Driven like `release_mid_drag`: scripted capture into the real capture
    //! task and connection. Whether the pointer is held is the scripted
    //! backend's own state, set by the `Begin` it yields and cleared by a
    //! release, as a real backend's grab is.

    use super::release_mid_drag::{Answers, MOTION, PATIENT, Visit};
    use super::*;
    use crate::test_harness::{dialer, machine, run_local, trust, wait_until};
    use crate::trust::Caps;
    use futures::FutureExt;
    use input_capture::scripted::Script;

    const PATIENCE: Duration = Duration::from_secs(20);

    /// The real Ack deadline, and a backoff no loaded run outlasts.
    const REAL_DEADLINE: Timing = Timing {
        ack_deadline: ACK_DEADLINE,
        unanswered_backoff: PATIENT.unanswered_backoff,
    };

    /// What the capture task has told the service so far.
    fn told(capture: &mut Capture) -> Vec<String> {
        let mut told = Vec::new();
        while let Some(event) = capture.event().now_or_never() {
            told.push(match event {
                ICaptureEvent::CaptureBegin(_) => "CaptureBegin".to_string(),
                ICaptureEvent::CaptureDisabled => "CaptureDisabled".to_string(),
                ICaptureEvent::CaptureEnabled => "CaptureEnabled".to_string(),
                ICaptureEvent::CaptureFailed(_) => "CaptureFailed".to_string(),
                ICaptureEvent::ClientEntered(_) => "ClientEntered".to_string(),
                ICaptureEvent::CrossingRefused { reason, .. } => {
                    format!("CrossingRefused({reason:?})")
                }
            });
        }
        told
    }

    fn entered(told: &[String]) -> bool {
        told.iter().any(|t| t == "ClientEntered")
    }

    fn refused(told: &[String], reason: CrossingRefusal) -> bool {
        told.contains(&format!("CrossingRefused({reason:?})"))
    }

    /// Cross until the backend has been told to let go more than `after`
    /// times. A Begin that lands before the capture exists is dropped.
    async fn cross_until_let_go(script: &Script, pos: Position, after: usize) {
        let started = tokio::time::Instant::now();
        while script.releases() <= after {
            assert!(
                started.elapsed() < PATIENCE,
                "the crossing was never let go"
            );
            script.push(pos, CaptureEvent::Begin);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    // LEDGER T115-1 | class B | 5 capture backend state: Script::held, crossing over loopback to a listener that never acks
    /// The peer is connected and answers pings, but never acknowledges the
    /// crossing. Nothing reaches it, and the pointer must not stay taken.
    #[test]
    fn a_crossing_the_peer_never_acknowledges_gives_the_pointer_back() {
        run_local(async {
            let mut v = Visit::start_with(false, REAL_DEADLINE).await;

            wait_until(
                "the pointer to be given back after a crossing the peer never acknowledged",
                PATIENCE,
                || !v.script.held(),
            )
            .await;
            assert!(
                v.leaves(1, PATIENCE).await,
                "the pointer was given back and the peer, which may have taken \
                 the Enter, was never told the visit ended: {:?}",
                v.frames()
            );

            assert!(
                refused(&told(&mut v.capture), CrossingRefusal::Unanswered),
                "the pointer was given back and the service was not told why"
            );

            v.capture.terminate().await;
        });
    }

    // LEDGER T115-13 | class B | 5 capture backend state + 2 frames received by listen::LanMouseListener
    /// The link drops while the pointer is across and is made again. The
    /// receiver took the crossing on the old link only, so it is made again
    /// on the new one; the receiver does not answer it, and the pointer is
    /// given back as after any unanswered crossing, rather than held with
    /// its input going where nothing takes it.
    #[test]
    fn a_crossing_made_again_on_a_new_link_and_never_answered_gives_the_pointer_back() {
        run_local(async {
            let mut v = Visit::start_with(true, REAL_DEADLINE).await;
            v.relink(false, Some(true)).await;
            assert!(
                v.script.held(),
                "precondition: the pointer was given back when the link dropped"
            );
            let enters = v.count(&ProtoEvent::Enter(hops_proto::Position::Right));
            let started = tokio::time::Instant::now();
            while v.script.held() {
                assert!(
                    started.elapsed() < PATIENCE,
                    "a crossing made again that the receiver never answered kept the \
                     pointer: {:?}",
                    v.frames()
                );
                v.script.push(Position::Left, CaptureEvent::Input(MOTION));
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(
                v.count(&ProtoEvent::Enter(hops_proto::Position::Right)) > enters,
                "the pointer was given back without the crossing being made again \
                 on the new link: {:?}",
                v.frames()
            );
            v.capture.terminate().await;
        });
    }

    // LEDGER TR-1 | class B | 5 capture backend state: Script::held + 2 frames received by listen::LanMouseListener
    /// The link drops while the pointer is across and is made again, and
    /// the pointer moves before the receiver has answered a ping on the new
    /// link. Until it has, the sender has not heard whether it takes input:
    /// the crossing waits, rather than being given back as refused by a
    /// receiver that takes no input, which it never said. Once it answers,
    /// the crossing is made on the new link and input lands there. Which
    /// comes first, the pointer or the answer, is up to the network, and
    /// must not decide whether the pointer stays or snaps back.
    #[test]
    fn a_crossing_made_again_waits_for_the_new_link_to_be_answered() {
        run_local(async {
            let mut v = Visit::start(true).await;
            v.relink(true, None).await;
            let relinked = v.frames().len();
            for _ in 0..15 {
                v.script.push(Position::Left, CaptureEvent::Input(MOTION));
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(
                v.script.held() && v.count(&ProtoEvent::Leave(0)) == 0,
                "the pointer was given back before the receiver said anything on \
                 the new link: {:?}",
                v.frames()
            );
            assert!(
                !refused(&told(&mut v.capture), CrossingRefusal::NotAcceptingInput),
                "the user was told the receiver takes no input, which it never said"
            );

            v.pong(Some(true));
            let started = tokio::time::Instant::now();
            while v.since(relinked, &ProtoEvent::Input(MOTION)) == 0 {
                assert!(
                    started.elapsed() < PATIENCE,
                    "input never landed on the new link: {:?}",
                    v.frames()
                );
                v.script.push(Position::Left, CaptureEvent::Input(MOTION));
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(
                v.since(relinked, &ProtoEvent::Enter(hops_proto::Position::Right)) > 0,
                "input went to the new link with no crossing made on it: {:?}",
                v.frames()
            );
            assert!(
                v.script.held() && v.count(&ProtoEvent::Leave(0)) == 0,
                "the crossing was made again and the pointer given back anyway: {:?}",
                v.frames()
            );
            v.capture.terminate().await;
        });
    }

    // LEDGER TR-2 | class B | 5 capture backend state: Script::held + events the capture task sends the service
    /// As above, and the receiver never answers on the new link. The
    /// crossing waits no longer than any crossing for its Ack, then the
    /// pointer is given back as unanswered and the receiver told the visit
    /// ended. It is not reported as a receiver that takes no input.
    #[test]
    fn a_crossing_made_again_on_a_link_never_answered_gives_the_pointer_back_as_unanswered() {
        run_local(async {
            let mut v = Visit::start_with(true, REAL_DEADLINE).await;
            v.relink(false, None).await;
            let leaves = v.count(&ProtoEvent::Leave(0));
            let started = tokio::time::Instant::now();
            while v.script.held() {
                assert!(
                    started.elapsed() < PATIENCE,
                    "a crossing made again on a link never answered kept the pointer: {:?}",
                    v.frames()
                );
                v.script.push(Position::Left, CaptureEvent::Input(MOTION));
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(
                started.elapsed() >= ACK_DEADLINE,
                "the pointer was given back after {:?}, before the crossing's deadline",
                started.elapsed()
            );
            assert!(
                v.leaves(leaves + 1, PATIENCE).await,
                "the receiver was never told the visit ended: {:?}",
                v.frames()
            );
            let told = told(&mut v.capture);
            assert!(
                refused(&told, CrossingRefusal::Unanswered)
                    && !refused(&told, CrossingRefusal::NotAcceptingInput),
                "the user was not told the crossing went unanswered: {told:?}"
            );
            v.capture.terminate().await;
        });
    }

    // LEDGER TR-3 | class B | 1 return value: the capture task's JoinHandle (DropGuard::drop in CaptureTask::do_capture)
    /// The capture task is torn down after the receiver of its events is
    /// gone, the order a runtime shutting down or a test unwinding drops
    /// them in. Saying capture stopped then has no one to tell and must not
    /// panic: under `panic = "abort"` that ends the process.
    #[test]
    fn a_capture_torn_down_after_its_owner_ends_without_a_panic() {
        run_local(async {
            let v = Visit::start(true).await;
            let Capture { task, event_rx, .. } = v.capture;
            drop(event_rx);
            task.abort();
            let ended = task.await;
            assert!(
                !ended.as_ref().is_err_and(|e| e.is_panic()),
                "the capture task panicked as it was torn down: {ended:?}"
            );
        });
    }

    // LEDGER T115-2 | class B | 5 capture backend state + events the capture task sends the service
    /// The device was added and never answered: no link. Crossing to it
    /// must not count as entering it (which runs its enter hook), and must
    /// let the pointer go.
    #[test]
    fn a_crossing_to_a_device_with_no_link_enters_nothing() {
        run_local(async {
            let sender = machine();
            let receiver = machine();
            // Bound and silent: a dial to it is never answered.
            let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("a silent port");
            let port = silent.local_addr().expect("its address").port();
            let crate::test_harness::Dialer {
                conn,
                handle,
                notices: _notices,
                ..
            } = dialer(
                &sender,
                trust(&sender, &[&receiver], Caps::OUTBOUND),
                port,
                hops_ipc::Position::Left,
            );
            let script = Script::new();
            let mut capture = Capture::new(
                Some(script.backend()),
                conn,
                vec![scancode::Linux::KeyLeftCtrl],
            );
            capture.create(handle, hops_ipc::Position::Left, CaptureType::Default);

            cross_until_let_go(&script, Position::Left, 0).await;
            let told = told(&mut capture);
            assert!(
                !entered(&told),
                "a crossing to a device with no link counted as entering it, \
                 which runs its enter hook: {told:?}"
            );
            // Nothing else here dials: the packet is the crossing's.
            silent.set_nonblocking(true).expect("nonblocking");
            let mut packet = [0u8; 2048];
            wait_until("the crossing to dial the device", PATIENCE, || {
                silent.recv(&mut packet).is_ok()
            })
            .await;
            assert!(
                refused(&told, CrossingRefusal::NotConnected),
                "the pointer stayed here and the service was not told it was \
                 because the device is not connected: {told:?}"
            );

            capture.terminate().await;
        });
    }

    // LEDGER T115-10 | class B | 5 capture backend state + events the capture task sends the service, no link
    /// The device is pinned to a receiver this machine may no longer drive,
    /// and there is no link: the lease lapsed while the link was down, as
    /// after the peer restarts. Every crossing says it is not permitted,
    /// enters nothing and dials nothing: the refusal comes from the pin, not
    /// from a link that is not there.
    #[test]
    fn a_crossing_to_a_pinned_receiver_this_machine_may_not_drive_dials_nothing() {
        run_local(async {
            let sender = machine();
            let receiver = machine();
            // Bound and silent: a dial to it would land here, and nothing
            // may dial it.
            let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("a silent port");
            let port = silent.local_addr().expect("its address").port();
            let store = trust(&sender, &[&receiver], Caps::OUTBOUND);
            let crate::test_harness::Dialer {
                conn,
                clients,
                handle,
                notices: _notices,
            } = dialer(&sender, store.clone(), port, hops_ipc::Position::Left);
            clients.set_peer_fingerprint(handle, Some(receiver.fingerprint.clone()));
            store
                .write()
                .expect("lock")
                .drop_capabilities(&receiver.fingerprint, Caps::OUTBOUND)
                .expect("the receiver's lease");
            let script = Script::new();
            let mut capture = Capture::new(
                Some(script.backend()),
                conn,
                vec![scancode::Linux::KeyLeftCtrl],
            );
            capture.create(handle, hops_ipc::Position::Left, CaptureType::Default);

            let mut told_since = Vec::new();
            for _ in 0..3 {
                let released = script.releases();
                cross_until_let_go(&script, Position::Left, released).await;
                told_since.extend(told(&mut capture));
            }
            assert!(
                !entered(&told_since),
                "a crossing to a receiver this machine may not drive counted as \
                 entering it: {told_since:?}"
            );
            let refusals: Vec<&String> = told_since
                .iter()
                .filter(|t| t.starts_with("CrossingRefused"))
                .collect();
            assert!(
                !refusals.is_empty()
                    && refusals
                        .iter()
                        .all(|t| **t
                            == format!("CrossingRefused({:?})", CrossingRefusal::NotPermitted)),
                "with no link, a crossing to a pinned receiver this machine may \
                 not drive gave another reason than the permission it lacks: \
                 {told_since:?}"
            );
            silent.set_nonblocking(true).expect("nonblocking");
            let mut packet = [0u8; 2048];
            assert!(
                silent.recv(&mut packet).is_err(),
                "a crossing dialled a receiver this machine may not drive"
            );

            capture.terminate().await;
        });
    }

    // LEDGER G-11 | class B | 5 capture backend state + events the capture task sends the service, no link
    /// The device is pinned to a receiver this machine approved, and that
    /// pairing still waits for its number (#167). Waiting is not paired:
    /// every crossing says it is not permitted, enters nothing and dials
    /// nothing, as for a receiver this machine was never allowed to drive.
    #[test]
    fn a_crossing_to_a_receiver_whose_pairing_waits_for_its_number_dials_nothing() {
        run_local(async {
            let sender = machine();
            let receiver = machine();
            // Bound and silent: a dial to it would land here, and nothing
            // may dial it.
            let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("a silent port");
            let port = silent.local_addr().expect("its address").port();
            let store = trust(&sender, &[], Caps::OUTBOUND);
            store
                .write()
                .expect("lock")
                .issue(&receiver.fingerprint, "receiver", Caps::OUTBOUND)
                .expect("approved here");
            assert!(
                store
                    .read()
                    .expect("lock")
                    .awaits(&receiver.fingerprint, Caps::I_MAY_DRIVE),
                "precondition: the approval waits for its number"
            );
            let crate::test_harness::Dialer {
                conn,
                clients,
                handle,
                notices: _notices,
            } = dialer(&sender, store.clone(), port, hops_ipc::Position::Left);
            clients.set_peer_fingerprint(handle, Some(receiver.fingerprint.clone()));
            let script = Script::new();
            let mut capture = Capture::new(
                Some(script.backend()),
                conn,
                vec![scancode::Linux::KeyLeftCtrl],
            );
            capture.create(handle, hops_ipc::Position::Left, CaptureType::Default);

            let mut told_since = Vec::new();
            for _ in 0..3 {
                let released = script.releases();
                cross_until_let_go(&script, Position::Left, released).await;
                told_since.extend(told(&mut capture));
            }
            assert!(
                !entered(&told_since),
                "a crossing to a receiver whose pairing waits for its number \
                 counted as entering it: {told_since:?}"
            );
            let refusals: Vec<&String> = told_since
                .iter()
                .filter(|t| t.starts_with("CrossingRefused"))
                .collect();
            assert!(
                !refusals.is_empty()
                    && refusals
                        .iter()
                        .all(|t| **t
                            == format!("CrossingRefused({:?})", CrossingRefusal::NotPermitted)),
                "a receiver whose pairing waits for its number was treated as \
                 paired: {told_since:?}"
            );
            silent.set_nonblocking(true).expect("nonblocking");
            let mut packet = [0u8; 2048];
            assert!(
                silent.recv(&mut packet).is_err(),
                "a crossing dialled a receiver whose pairing waits for its number"
            );

            capture.terminate().await;
        });
    }

    // LEDGER T115-4 | class B | 5 capture backend state + events the capture task sends the service, link up over loopback
    /// The link is up, and this machine may no longer drive the receiver.
    /// A crossing to it does not count as entering it (which runs its enter
    /// hook), and every push at that edge says the same thing: the link the
    /// refusal leaves behind, or its absence, is not the reason.
    #[test]
    fn a_crossing_to_a_receiver_this_machine_may_no_longer_drive_says_so() {
        run_local(async {
            let mut v = Visit::start(true).await;
            v.release_bind();
            assert!(v.leaves(1, PATIENCE).await, "no Leave: {:?}", v.frames());
            let before = told(&mut v.capture);
            assert!(
                !before.iter().any(|t| t.starts_with("CrossingRefused")),
                "{before:?}"
            );

            v.trust
                .write()
                .expect("lock")
                .drop_capabilities(&v.receiver, Caps::OUTBOUND)
                .expect("the receiver's lease");
            let mut told_since = Vec::new();
            for _ in 0..3 {
                let released = v.script.releases();
                cross_until_let_go(&v.script, Position::Left, released).await;
                told_since.extend(told(&mut v.capture));
            }

            assert!(
                !entered(&told_since),
                "a crossing to a receiver this machine may no longer drive \
                 counted as entering it, which runs its enter hook: {told_since:?}"
            );
            assert!(
                refused(&told_since, CrossingRefusal::NotPermitted),
                "a crossing to a receiver this machine may no longer drive was \
                 let go without saying why: {told_since:?}"
            );
            assert!(
                told_since
                    .iter()
                    .filter(|t| t.starts_with("CrossingRefused"))
                    .all(|t| *t == format!("CrossingRefused({:?})", CrossingRefusal::NotPermitted)),
                "a later push gave a reason other than the permission this \
                 machine lacks: {told_since:?}"
            );
            assert!(!v.script.held(), "the pointer is still held");

            v.capture.terminate().await;
        });
    }

    // LEDGER T115-9 | class B | 5 capture backend state + events the capture task sends the service, link up over loopback
    /// The receiver is connected and says its input emulation is off. A
    /// crossing to it lets the pointer go, says so, and enters nothing.
    #[test]
    fn a_crossing_to_a_peer_not_accepting_input_enters_nothing() {
        run_local(async {
            let answers = Answers {
                pong: Some(false),
                ack: true,
            };
            let mut v = Visit::connect(answers, PATIENT).await;

            cross_until_let_go(&v.script, Position::Left, 0).await;
            let told = told(&mut v.capture);
            assert!(
                !entered(&told),
                "a crossing to a peer not accepting input counted as entering \
                 it, which runs its enter hook: {told:?}"
            );
            assert!(
                refused(&told, CrossingRefusal::NotAcceptingInput),
                "the pointer stayed here and the service was not told the peer \
                 is not accepting input: {told:?}"
            );

            v.capture.terminate().await;
        });
    }

    // LEDGER T115-10 | class B | events the capture task sends the service, link up over loopback, no Pong yet
    /// The link is up and the receiver has not answered a ping yet. It has
    /// said nothing about its input, so a crossing then is not connected
    /// yet, not refused for a missing permission.
    #[test]
    fn a_crossing_before_the_first_pong_is_not_connected_yet() {
        run_local(async {
            let answers = Answers {
                pong: None,
                ack: true,
            };
            let mut v = Visit::connect(answers, PATIENT).await;

            cross_until_let_go(&v.script, Position::Left, 0).await;
            let told = told(&mut v.capture);
            assert!(!entered(&told), "{told:?}");
            assert!(
                refused(&told, CrossingRefusal::NotConnected)
                    && !refused(&told, CrossingRefusal::NotAcceptingInput),
                "a crossing before the receiver's first Pong was reported as \
                 anything but not connected yet: {told:?}"
            );

            v.capture.terminate().await;
        });
    }

    // LEDGER T115-11 | class B | events the capture task sends the service, after a crossing that landed
    /// A visit that a failed send ends was a crossing that landed: the
    /// pointer is given back, and nothing reports a refused crossing.
    #[test]
    fn a_visit_a_failed_send_ends_is_not_a_refused_crossing() {
        run_local(async {
            let mut v = Visit::start(true).await;
            let _ = told(&mut v.capture);

            v.trust
                .write()
                .expect("lock")
                .drop_capabilities(&v.receiver, Caps::OUTBOUND)
                .expect("the receiver's lease");
            // Not motion, which may be coalesced and sent another way: a
            // button-up for nothing held goes out as it is.
            let up = Event::Pointer(PointerEvent::Button {
                time: 0,
                button: input_event::BTN_LEFT,
                state: 0,
            });
            let started = tokio::time::Instant::now();
            while v.script.held() {
                assert!(
                    started.elapsed() < PATIENCE,
                    "a failed send never gave the pointer back"
                );
                v.script.push(Position::Left, CaptureEvent::Input(up));
                tokio::time::sleep(Duration::from_millis(20)).await;
            }

            let told = told(&mut v.capture);
            assert!(
                !told.iter().any(|t| t.starts_with("CrossingRefused")),
                "a visit that had landed was reported as a refused crossing: {told:?}"
            );

            v.capture.terminate().await;
        });
    }

    // LEDGER T115-5 | class B | 2 frames received by listen::LanMouseListener + 5 capture backend state
    /// A peer that left one crossing unanswered is not given the pointer
    /// again at once: pushing at its edge would freeze the pointer for the
    /// whole deadline on every push. The next crossing is let go without an
    /// Enter.
    #[test]
    fn after_an_unanswered_crossing_the_next_one_is_let_go_at_once() {
        run_local(async {
            let mut v = Visit::start_with(false, REAL_DEADLINE).await;
            wait_until("the first crossing to be given up on", PATIENCE, || {
                !v.script.held()
            })
            .await;
            let enters = v.count(&ProtoEvent::Enter(hops_proto::Position::Right));
            let released = v.script.releases();

            cross_until_let_go(&v.script, Position::Left, released).await;
            assert_eq!(
                v.count(&ProtoEvent::Enter(hops_proto::Position::Right)),
                enters,
                "a crossing to a peer that just left one unanswered took the \
                 pointer and sent it an Enter again: {:?}",
                v.frames()
            );
            assert!(!v.script.held(), "the pointer is still held");

            // Input queued behind the refused crossing is the local
            // pointer's. A Ping written after it on the same stream proves
            // anything sent for it has arrived.
            v.script.push(Position::Left, CaptureEvent::Input(MOTION));
            let released = v.script.releases();
            cross_until_let_go(&v.script, Position::Left, released).await;
            let pings = v.count(&ProtoEvent::Ping);
            wait_until("the next ping", PATIENCE, || {
                v.count(&ProtoEvent::Ping) > pings
            })
            .await;
            let after_leave = v.since_leave(1, &ProtoEvent::Enter(hops_proto::Position::Right))
                + v.since_leave(1, &ProtoEvent::Input(MOTION));
            assert_eq!(
                after_leave,
                0,
                "input outside a crossing reached the peer: {:?}",
                v.frames()
            );

            v.capture.terminate().await;
        });
    }

    // LEDGER T115-6 | class B | 5 capture backend state + 2 frames received by listen::LanMouseListener
    /// An acknowledged crossing is not given up on: the deadline is for the
    /// Ack, not for the visit. Judged only on a crossing whose Ack came well
    /// inside its deadline; a run too loaded for that tries a longer one.
    #[test]
    fn an_acknowledged_crossing_keeps_the_pointer_past_the_deadline() {
        run_local(async {
            let answers = Answers {
                pong: Some(true),
                ack: true,
            };
            for deadline in [1, 4, 16].map(Duration::from_secs) {
                let timing = Timing {
                    ack_deadline: deadline,
                    unanswered_backoff: PATIENT.unanswered_backoff,
                };
                let mut v = Visit::connect(answers, timing).await;
                match v.cross_timed().await {
                    Some(took) if took < deadline / 2 => {
                        // The deadline was armed before `took` ran out, so
                        // it has passed by now, with room to act on it.
                        tokio::time::sleep(deadline * 2).await;
                        assert!(
                            v.script.held() && v.count(&ProtoEvent::Leave(0)) == 0,
                            "an acknowledged crossing was given up on after the \
                             Ack deadline: {:?}",
                            v.frames()
                        );
                        v.capture.terminate().await;
                        return;
                    }
                    _ => {
                        let _ = told(&mut v.capture);
                        v.capture.terminate().await;
                    }
                }
            }
            panic!("no crossing was acknowledged well inside its deadline");
        });
    }

    // LEDGER T115-12 | class B | 2 frames received by listen::LanMouseListener
    /// The backoff after an unanswered crossing ends: the peer may have been
    /// busy, and the next crossing after it is tried again.
    #[test]
    fn after_the_backoff_a_crossing_is_tried_again() {
        run_local(async {
            let timing = Timing {
                ack_deadline: ACK_DEADLINE,
                unanswered_backoff: Duration::from_millis(200),
            };
            let mut v = Visit::start_with(false, timing).await;
            wait_until("the first crossing to be given up on", PATIENCE, || {
                !v.script.held()
            })
            .await;
            // Waits for an Enter after the give-up's Leave.
            v.cross(false).await;

            v.capture.terminate().await;
        });
    }

    // LEDGER T115-7 | class A | pure: Told::first
    /// Pushing at the edge of a device that cannot take the pointer makes a
    /// crossing per push; the user is told once, not per push.
    #[test]
    fn a_refusal_is_told_once_per_device_and_reason_until_it_is_old() {
        let mut told = Told::default();
        let t0 = Instant::now();
        let second = Duration::from_secs(1);
        assert!(
            told.first(1, CrossingRefusal::NotConnected, t0),
            "the first"
        );
        assert!(
            !told.first(1, CrossingRefusal::NotConnected, t0 + second),
            "the same refusal, a push later, was told again"
        );
        assert!(
            told.first(1, CrossingRefusal::Unanswered, t0 + second),
            "a new reason for the same device was not told"
        );
        assert!(
            told.first(2, CrossingRefusal::Unanswered, t0 + second),
            "the same reason for another device was not told"
        );
        assert!(
            told.first(
                1,
                CrossingRefusal::Unanswered,
                t0 + second + Told::AGAIN_AFTER
            ),
            "a refusal told long ago was not told again"
        );
    }
}
