use std::collections::HashSet;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    time::{Duration, Instant},
};

use futures::StreamExt;
use hops_proto::{ProtoEvent, caps};
use input_capture::{
    CaptureError, CaptureEvent, CaptureHandle, InputCapture, InputCaptureError, Position,
};
use input_event::{Event, KeyboardEvent, PointerEvent, scancode};
use local_channel::mpsc::{Receiver, Sender, channel};
use tokio::task::{JoinHandle, spawn_local};
use tokio_util::sync::CancellationToken;

use crate::connect::LanMouseConnection;

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
    /// A (new) client was entered.
    /// In contrast to [`ICaptureEvent::CaptureBegin`] this
    /// event is only triggered when the capture was
    /// explicitly released in the meantime by
    /// either the remote client leaving its device region,
    /// a new device entering the screen or the release bind.
    ClientEntered(u64),
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
}

impl Capture {
    pub(crate) fn new(
        backend: Option<input_capture::Backend>,
        conn: LanMouseConnection,
        release_bind: Vec<scancode::Linux>,
    ) -> Self {
        let (request_tx, request_rx) = channel();
        let (event_tx, event_rx) = channel();
        let cancellation_token = CancellationToken::new();
        let capture_task = CaptureTask {
            held_lock_keys: Default::default(),
            buttons_down_on_peer: Default::default(),
            active_client: None,
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
                event = capture.next() => match event {
                    Some(event) => self.handle_capture_event(capture, event?).await?,
                    None => return Ok(()),
                },
                (handle, event) = self.conn.recv() => {
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
                    CaptureRequest::Release => self.release_capture(capture).await?,
                    CaptureRequest::Create(h, p, t) => {
                        self.add_capture(h, p, t);
                        capture.create(h, p).await?;
                    }
                    CaptureRequest::Destroy(h) => {
                        // Switching off or removing the client we are on:
                        // nothing more reaches it, so let go first.
                        let released = if self.active_client == Some(h) {
                            log::info!("releasing capture: client {h} was switched off");
                            self.release_capture(capture).await
                        } else {
                            Ok(())
                        };
                        self.remove_capture(h);
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
        self.send_motion(capture, handle, dx, dy).await
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
        // and teleports
        // the remote cursor. Begin fires once per crossing (idempotent).
        if event == CaptureEvent::Begin {
            self.abs_vx = 0.0;
            self.abs_vy = 0.0;
            self.abs_seq = 0;
        }

        // activated a new client
        if event == CaptureEvent::Begin && Some(handle) != self.active_client {
            self.state = State::WaitingForAck;
            self.active_client.replace(handle);
            self.event_tx
                .send(ICaptureEvent::ClientEntered(handle))
                .expect("channel closed");
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
                    log::trace!("swallowing auto-repeat for lock key {key}");
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

    /// Tell the active client we are leaving, after letting go of everything
    /// it was sent as held. Touches only the connection and the capture's own
    /// bookkeeping, never the capture backend, so it still works when that
    /// backend has just failed.
    async fn leave_active_client(&mut self, capture: &mut InputCapture) {
        // Drop any un-flushed coalesced motion — it's <=1 flush-interval old and
        // belongs to the visit we're leaving; sending it after Leave would be
        // out of order.
        self.pending_motion = None;
        let buttons = std::mem::take(&mut self.buttons_down_on_peer);
        // If we have an active client, notify them we're leaving
        if let Some(handle) = self.active_client.take() {
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
                if let Err(e) = self.conn.send(button_up, handle).await {
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
                if let Err(e) = self.conn.send(key_up, handle).await {
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
            if let Err(e) = self.conn.send(mods_zero, handle).await {
                log::warn!("failed to reset modifiers on client {handle}: {e}");
            }

            log::info!("sending Leave event to client {handle}");
            if let Err(e) = self.conn.send(ProtoEvent::Leave(0), handle).await {
                log::warn!("failed to send Leave to client {handle}: {e}");
            }
        }
    }
}

thread_local! {
    static PREV_LOG: Cell<Option<Instant>> = const { Cell::new(None) };
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
    fn drop(&mut self) {
        self.tx
            .send(self.on_drop.take().expect("item"))
            .expect("channel closed");
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
    //! backend failing, the client being switched off, or shutdown.
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

    const MOTION: Event = Event::Pointer(PointerEvent::Motion {
        time: 0,
        dx: 1.0,
        dy: 0.0,
    });

    /// A sender's capture task, crossed onto a receiver that writes down every
    /// frame reaching it.
    struct Visit {
        wire: Rc<RefCell<Vec<ProtoEvent>>>,
        script: Script,
        capture: Capture,
        handle: hops_ipc::ClientHandle,
        _notices: Notices,
    }

    impl Visit {
        /// Cross onto a receiver that answers like a daemon. With `ack` false
        /// it never acknowledges the Enter, so the sender stays waiting for it.
        async fn start(ack: bool) -> Visit {
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
            spawn_local(async move {
                while let Some(event) = listener.next().await {
                    let ListenEvent::Msg { event, addr } = event else {
                        continue;
                    };
                    received.borrow_mut().push(event);
                    match event {
                        ProtoEvent::Ping => listener.reply(addr, ProtoEvent::Pong(true)).await,
                        ProtoEvent::Enter(_) if ack => {
                            listener.reply(addr, ProtoEvent::Ack(0)).await
                        }
                        _ => {}
                    }
                }
            });

            let Dialer {
                conn,
                handle,
                notices,
                ..
            } = {
                let d = dialer(
                    &sender,
                    trust(&sender, &[&receiver], Caps::OUTBOUND),
                    port,
                    hops_ipc::Position::Left,
                );
                d.until_alive().await;
                d
            };

            let script = Script::new();
            let bind = vec![scancode::Linux::KeyLeftCtrl, scancode::Linux::KeyLeftShift];
            let capture = Capture::new(Some(script.backend()), conn, bind);
            capture.create(handle, hops_ipc::Position::Left, CaptureType::Default);
            let visit = Visit {
                wire,
                script,
                capture,
                handle,
                _notices: notices,
            };
            visit.cross(ack).await;
            visit
        }

        /// Cross (again), and wait until the peer was sent an Enter for it.
        /// Only a Begin is pushed until then, so that Enter proves the capture
        /// task took the crossing: a Begin that lands before the capture exists
        /// is dropped. Acknowledged, then keep moving until motion is on the
        /// wire, since before the Ack input goes out as repeated Enters.
        async fn cross(&self, ack: bool) {
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

        /// Push `event` until `want` has arrived after the `leaves`-th Leave.
        async fn until(&self, leaves: usize, want: ProtoEvent, event: CaptureEvent) {
            let started = tokio::time::Instant::now();
            while self.since_leave(leaves, &want) == 0 {
                assert!(started.elapsed() < PATIENCE, "never crossed");
                self.script.push(Position::Left, event);
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        fn frames(&self) -> Vec<ProtoEvent> {
            self.wire.borrow().clone()
        }

        fn count(&self, want: &ProtoEvent) -> usize {
            self.wire.borrow().iter().filter(|e| same(e, want)).count()
        }

        /// How many `want` arrived after the `leaves`-th Leave.
        fn since_leave(&self, leaves: usize, want: &ProtoEvent) -> usize {
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
        async fn press(&self, b: u32) {
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
        async fn leaves(&self, n: usize, limit: Duration) -> bool {
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

        fn release_bind(&self) {
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
    /// Switching off, or removing, the client the cursor is on: nothing more
    /// is sent to it, so it must be let go first.
    #[test]
    fn switching_off_the_client_mid_drag_sends_the_button_up() {
        run_local(async {
            let mut v = Visit::start(true).await;
            v.press(BTN_LEFT).await;

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
}
