//! Input capture on macOS, through Quartz event taps.
//!
//! # Two taps, and why (#240)
//!
//! An *active* tap (`kCGEventTapOptionDefault`) sits in the event path: the
//! system waits on its callback for every event it is sent. Revoking
//! Accessibility from a process that holds one can hang input system-wide,
//! even with a callback that passes everything through, and only a forced
//! restart recovers it. A *listen-only* tap is told of events after the fact
//! and cannot hold them.
//!
//! So capture keeps a listen-only tap while the pointer is on this Mac, which
//! is all it takes to see the pointer reach an edge, and installs the active
//! tap only for a crossing: from the motion that reaches the edge until the
//! pointer comes back (release bind, the peer's Leave, the client going away,
//! or a fault). The user is necessarily on this Mac to switch the permission
//! off in System Settings, so a revocation there never meets an active tap.
//!
//! Both taps live on one thread with its own run loop. The crossing installs
//! the active tap synchronously in the listen tap's callback, ahead of it in
//! the chain, so the window in which a local event can slip past is the
//! callback's latency plus one `CGEventTapCreate` (logged at debug as "active
//! tap installed in"). Events in that window go to this Mac: motion is
//! harmless (the cursor is warped to the edge anyway); a key or click typed in
//! the same millisecond as the crossing lands here rather than on the peer.
//! Ending a crossing is a command to the tap thread, which removes the tap.
//!
//! # Never blocking in a callback
//!
//! The callbacks take no lock they wait for: the geometry shared with the
//! daemon side is a `std` mutex read with `try_lock` (a busy lock skips one
//! crossing check), everything else is owned by the tap thread. Events go out
//! on an unbounded channel: keys and buttons are never dropped; motion is
//! summed into one event once the daemon falls behind. A tap the system
//! disables is handled first, before anything else, by [`TapGuard`].

use super::{
    Capture, CaptureError, CaptureEvent, Permission, Position, error::MacosCaptureCreationError,
};
use async_trait::async_trait;
use bitflags::bitflags;
use core_foundation::{
    base::{CFRelease, TCFType, kCFAllocatorDefault},
    date::CFTimeInterval,
    mach_port::{CFMachPortInvalidate, CFMachPortRef},
    number::{CFBooleanRef, kCFBooleanTrue},
    runloop::{CFRunLoop, CFRunLoopSource, kCFRunLoopCommonModes},
    string::{CFStringCreateWithCString, CFStringRef, kCFStringEncodingUTF8},
};
use core_foundation_sys::runloop::{
    CFRunLoopSourceContext, CFRunLoopSourceCreate, CFRunLoopSourceInvalidate,
    CFRunLoopSourceSignal, CFRunLoopWakeUp,
};
use core_graphics::{
    base::{CGError, kCGErrorSuccess},
    display::{CGDisplay, CGPoint},
    event::{
        CGEvent, CGEventFlags, CGEventTap, CGEventTapLocation, CGEventTapOptions,
        CGEventTapPlacement, CGEventTapProxy, CGEventType, CallbackResult, EventField,
    },
    event_source::{CGEventSource, CGEventSourceStateID},
};
use futures_core::Stream;
use input_event::{
    BTN_BACK, BTN_FORWARD, BTN_LEFT, BTN_MIDDLE, BTN_RIGHT, Event, KeyboardEvent, PointerEvent,
};
use keycode::{KeyMap, KeyMapping};
use libc::c_void;
use std::{
    cell::RefCell,
    collections::{HashSet, VecDeque},
    ffi::{CString, c_char},
    pin::Pin,
    rc::{Rc, Weak},
    sync::{
        Arc, Mutex, MutexGuard, TryLockError,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    thread::{self},
    time::{Duration, Instant},
};
use tokio::sync::{
    mpsc::{self, Receiver, Sender, UnboundedReceiver, UnboundedSender},
    oneshot,
};

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Bounds {
    xmin: f64,
    xmax: f64,
    ymin: f64,
    ymax: f64,
}

/// What the tap thread and the daemon side share: written by the daemon side,
/// read by the listen tap's callback to see a crossing. Held only for copies.
#[derive(Debug, Default)]
struct Shared {
    /// active capture positions
    active_clients: HashSet<Position>,
    /// bounds of the input capture area
    bounds: Bounds,
}

impl Shared {
    fn crossed(&self, seen: &Seen) -> Option<Position> {
        for &position in self.active_clients.iter() {
            if (position == Position::Left && (seen.x + seen.dx) <= self.bounds.xmin)
                || (position == Position::Right && (seen.x + seen.dx) >= self.bounds.xmax)
                || (position == Position::Top && (seen.y + seen.dy) <= self.bounds.ymin)
                || (position == Position::Bottom && (seen.y + seen.dy) >= self.bounds.ymax)
            {
                log::debug!("Crossed barrier into position: {position:?}");
                return Some(position);
            }
        }
        None
    }

    /// Store new bounds if they differ (logging the change). No CG calls.
    fn store_bounds_if_changed(&mut self, bounds: Bounds) {
        if bounds != self.bounds {
            log::info!(
                "display geometry changed: {:?} -> {:?}",
                self.bounds,
                bounds
            );
            self.bounds = bounds;
        }
    }
}

/// Lock `shared` from the daemon side. The tap callbacks never wait for it,
/// so it is only ever held for a copy; a poisoned lock still holds valid data.
fn lock(shared: &Mutex<Shared>) -> MutexGuard<'_, Shared> {
    shared
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Enumerate active displays and compute their union bounds. Touches no
/// lock: call it OUTSIDE the shared lock. `None` = no displays.
///
/// Recompute from scratch each call: folding min/max into the existing
/// bounds let them only grow, so removing a display (lid close in clamshell)
/// left barrier edges at phantom coordinates.
fn compute_display_bounds() -> Result<Option<Bounds>, MacosCaptureCreationError> {
    let active_ids =
        CGDisplay::active_displays().map_err(MacosCaptureCreationError::ActiveDisplays)?;
    if active_ids.is_empty() {
        return Ok(None);
    }
    let mut bounds = Bounds {
        xmin: f64::MAX,
        xmax: f64::MIN,
        ymin: f64::MAX,
        ymax: f64::MIN,
    };
    for d in active_ids.iter() {
        let b = CGDisplay::new(*d).bounds();
        bounds.xmin = bounds.xmin.min(b.origin.x);
        bounds.xmax = bounds.xmax.max(b.origin.x + b.size.width);
        bounds.ymin = bounds.ymin.min(b.origin.y);
        bounds.ymax = bounds.ymax.max(b.origin.y + b.size.height);
    }
    Ok(Some(bounds))
}

/// Refresh the shared bounds: enumerate the displays first, then lock to store.
fn refresh_bounds(shared: &Mutex<Shared>) {
    match compute_display_bounds() {
        Ok(Some(bounds)) => lock(shared).store_bounds_if_changed(bounds),
        Ok(None) => log::warn!("no active displays reported; keeping previous bounds"),
        Err(e) => log::warn!("failed to refresh display bounds: {e}"),
    }
}

/// What the tap thread tells the daemon side.
#[derive(Debug)]
enum ProducerEvent {
    Create(Position),
    Destroy(Position),
    /// A crossing began: hide the cursor.
    Grab,
    /// The crossing ended: show the cursor.
    Released,
    DisplayReconfigured,
}

/// What the daemon side tells the tap thread.
#[derive(Debug)]
enum TapCommand {
    /// End the crossing, if one is under way.
    Release,
    /// The client at this position is gone; end a crossing to it.
    Destroy(Position),
    /// A permission is gone: remove every tap now. The fault is reported by
    /// whoever found it.
    Halt,
}

/// What the capture's stream carries: an event, or the fault that ends it.
type Item = Result<(Position, CaptureEvent), CaptureError>;

/// One tap event's fields, read once in the callback, so the logic that acts
/// on them can be driven without Core Graphics.
#[derive(Clone, Copy, Debug)]
struct Seen {
    ty: CGEventType,
    x: f64,
    y: f64,
    dx: f64,
    dy: f64,
    keycode: i64,
    flags: CGEventFlags,
    button: i64,
    continuous: bool,
    point_v: i64,
    point_h: i64,
    line_v: i64,
    line_h: i64,
}

impl Seen {
    fn new(ty: CGEventType) -> Self {
        Self {
            ty,
            x: 0.0,
            y: 0.0,
            dx: 0.0,
            dy: 0.0,
            keycode: 0,
            flags: CGEventFlags::empty(),
            button: 0,
            continuous: false,
            point_v: 0,
            point_h: 0,
            line_v: 0,
            line_h: 0,
        }
    }

    /// Read what this type of event carries. A disable notice carries
    /// nothing, and its event is not read.
    fn of(ty: CGEventType, ev: &CGEvent) -> Self {
        let mut seen = Self::new(ty);
        match ty {
            CGEventType::MouseMoved
            | CGEventType::LeftMouseDragged
            | CGEventType::RightMouseDragged
            | CGEventType::OtherMouseDragged => {
                let at = ev.location();
                seen.x = at.x;
                seen.y = at.y;
                seen.dx = ev.get_double_value_field(EventField::MOUSE_EVENT_DELTA_X);
                seen.dy = ev.get_double_value_field(EventField::MOUSE_EVENT_DELTA_Y);
            }
            CGEventType::KeyDown | CGEventType::KeyUp => {
                seen.keycode = ev.get_integer_value_field(EventField::KEYBOARD_EVENT_KEYCODE);
            }
            CGEventType::FlagsChanged => {
                seen.keycode = ev.get_integer_value_field(EventField::KEYBOARD_EVENT_KEYCODE);
                seen.flags = ev.get_flags();
            }
            CGEventType::OtherMouseDown | CGEventType::OtherMouseUp => {
                seen.button = ev.get_integer_value_field(EventField::MOUSE_EVENT_BUTTON_NUMBER);
            }
            CGEventType::ScrollWheel => {
                seen.continuous =
                    ev.get_integer_value_field(EventField::SCROLL_WHEEL_EVENT_IS_CONTINUOUS) != 0;
                seen.point_v =
                    ev.get_integer_value_field(EventField::SCROLL_WHEEL_EVENT_POINT_DELTA_AXIS_1);
                seen.point_h =
                    ev.get_integer_value_field(EventField::SCROLL_WHEEL_EVENT_POINT_DELTA_AXIS_2);
                seen.line_v =
                    ev.get_integer_value_field(EventField::SCROLL_WHEEL_EVENT_DELTA_AXIS_1);
                seen.line_h =
                    ev.get_integer_value_field(EventField::SCROLL_WHEEL_EVENT_DELTA_AXIS_2);
            }
            _ => {}
        }
        seen
    }

    /// Why the system disabled the tap, if this is its notice of that.
    fn disabled(&self) -> Option<Disabled> {
        match self.ty {
            CGEventType::TapDisabledByTimeout => Some(Disabled::Timeout),
            CGEventType::TapDisabledByUserInput => Some(Disabled::UserInput),
            _ => None,
        }
    }

    fn is_motion(&self) -> bool {
        matches!(
            self.ty,
            CGEventType::MouseMoved
                | CGEventType::LeftMouseDragged
                | CGEventType::RightMouseDragged
                | CGEventType::OtherMouseDragged
        )
    }
}

fn get_events(
    seen: &Seen,
    result: &mut Vec<CaptureEvent>,
    modifier_state: &mut XMods,
) -> Result<(), CaptureError> {
    fn motion(seen: &Seen) -> PointerEvent {
        PointerEvent::Motion {
            time: 0,
            dx: seen.dx,
            dy: seen.dy,
        }
    }

    fn map_key(code: i64) -> Result<u32, CaptureError> {
        match KeyMap::from_key_mapping(KeyMapping::Mac(code as u16)) {
            Ok(k) => Ok(k.evdev as u32),
            Err(()) => Err(CaptureError::KeyMapError(code)),
        }
    }

    fn button(button: u32, state: u32) -> CaptureEvent {
        CaptureEvent::Input(Event::Pointer(PointerEvent::Button {
            time: 0,
            button,
            state,
        }))
    }

    fn other_button(number: i64) -> u32 {
        match number {
            3 => BTN_BACK,
            4 => BTN_FORWARD,
            _ => BTN_MIDDLE,
        }
    }

    match seen.ty {
        CGEventType::KeyDown | CGEventType::KeyUp => {
            let key = map_key(seen.keycode)?;
            let state = matches!(seen.ty, CGEventType::KeyDown) as u8;
            result.push(CaptureEvent::Input(Event::Keyboard(KeyboardEvent::Key {
                time: 0,
                key,
                state,
            })));
        }
        CGEventType::FlagsChanged => {
            let mut depressed = XMods::empty();
            let mut mods_locked = XMods::empty();
            let cg_flags = seen.flags;

            if cg_flags.contains(CGEventFlags::CGEventFlagShift) {
                depressed |= XMods::ShiftMask;
            }
            if cg_flags.contains(CGEventFlags::CGEventFlagControl) {
                depressed |= XMods::ControlMask;
            }
            if cg_flags.contains(CGEventFlags::CGEventFlagAlternate) {
                depressed |= XMods::Mod1Mask;
            }
            if cg_flags.contains(CGEventFlags::CGEventFlagCommand) {
                depressed |= XMods::Mod4Mask;
            }
            if cg_flags.contains(CGEventFlags::CGEventFlagAlphaShift) {
                depressed |= XMods::LockMask;
                mods_locked |= XMods::LockMask;
            }

            // check if pressed or released
            let state = if depressed > *modifier_state { 1 } else { 0 };
            *modifier_state = depressed;

            if let Ok(key) = map_key(seen.keycode) {
                result.push(CaptureEvent::Input(Event::Keyboard(KeyboardEvent::Key {
                    time: 0,
                    key,
                    state,
                })));
            }

            result.push(CaptureEvent::Input(Event::Keyboard(
                KeyboardEvent::Modifiers {
                    depressed: depressed.bits(),
                    latched: 0,
                    locked: mods_locked.bits(),
                    group: 0,
                },
            )));
        }
        CGEventType::MouseMoved
        | CGEventType::LeftMouseDragged
        | CGEventType::RightMouseDragged
        | CGEventType::OtherMouseDragged => {
            result.push(CaptureEvent::Input(Event::Pointer(motion(seen))))
        }
        CGEventType::LeftMouseDown => result.push(button(BTN_LEFT, 1)),
        CGEventType::LeftMouseUp => result.push(button(BTN_LEFT, 0)),
        CGEventType::RightMouseDown => result.push(button(BTN_RIGHT, 1)),
        CGEventType::RightMouseUp => result.push(button(BTN_RIGHT, 0)),
        CGEventType::OtherMouseDown => result.push(button(other_button(seen.button), 1)),
        CGEventType::OtherMouseUp => result.push(button(other_button(seen.button), 0)),
        CGEventType::ScrollWheel => {
            if seen.continuous {
                if seen.point_v != 0 {
                    result.push(CaptureEvent::Input(Event::Pointer(PointerEvent::Axis {
                        time: 0,
                        axis: 0, // Vertical
                        value: seen.point_v as f64,
                    })));
                }
                if seen.point_h != 0 {
                    result.push(CaptureEvent::Input(Event::Pointer(PointerEvent::Axis {
                        time: 0,
                        axis: 1, // Horizontal
                        value: seen.point_h as f64,
                    })));
                }
            } else {
                // line based scrolling
                const LINES_PER_STEP: i32 = 3;
                const V120_STEPS_PER_LINE: i32 = 120 / LINES_PER_STEP;
                if seen.line_v != 0 {
                    result.push(CaptureEvent::Input(Event::Pointer(
                        PointerEvent::AxisDiscrete120 {
                            axis: 0, // Vertical
                            value: V120_STEPS_PER_LINE * seen.line_v as i32,
                        },
                    )));
                }
                if seen.line_h != 0 {
                    result.push(CaptureEvent::Input(Event::Pointer(
                        PointerEvent::AxisDiscrete120 {
                            axis: 1, // Horizontal
                            value: V120_STEPS_PER_LINE * seen.line_h as i32,
                        },
                    )));
                }
            }
        }
        _ => (),
    }
    Ok(())
}

/// Which of capture's two taps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TapKind {
    /// Listen-only, installed while capture runs: sees the pointer reach an
    /// edge. Cannot hold the system's input.
    Listen,
    /// The active filter, installed only while the pointer is on a peer:
    /// takes this Mac's input away from it.
    Active,
}

/// How each tap is created: listen-only unless it must take input away.
fn tap_options(kind: TapKind) -> CGEventTapOptions {
    match kind {
        TapKind::Listen => CGEventTapOptions::ListenOnly,
        TapKind::Active => CGEventTapOptions::Default,
    }
}

/// What each tap is sent. A crossing is seen on plain motion, so the listen
/// tap is sent nothing else: no key reaches hops while the pointer is here.
fn events_of_interest(kind: TapKind) -> Vec<CGEventType> {
    match kind {
        TapKind::Listen => vec![CGEventType::MouseMoved],
        TapKind::Active => vec![
            CGEventType::LeftMouseDown,
            CGEventType::LeftMouseUp,
            CGEventType::RightMouseDown,
            CGEventType::RightMouseUp,
            CGEventType::OtherMouseDown,
            CGEventType::OtherMouseUp,
            CGEventType::MouseMoved,
            CGEventType::LeftMouseDragged,
            CGEventType::RightMouseDragged,
            CGEventType::OtherMouseDragged,
            CGEventType::ScrollWheel,
            CGEventType::KeyDown,
            CGEventType::KeyUp,
            CGEventType::FlagsChanged,
        ],
    }
}

/// Why the system disabled a tap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disabled {
    /// Its callback took too long.
    Timeout,
    /// Secure input began: a password field, the lock screen, the screensaver.
    UserInput,
}

/// Why capture's taps were all removed.
#[derive(Clone, Debug, PartialEq, Eq)]
enum TearDownWhy {
    /// The last permission check found these missing.
    Revoked(Vec<Permission>),
    /// macOS refused the active tap at a crossing, which it does without
    /// Accessibility.
    Refused,
    /// Secure input disabled the active tap while the pointer was on a peer.
    SecureInput,
    /// A tap timed out more often than [`REENABLES`] in [`REENABLE_WINDOW`].
    Timeouts,
    /// The daemon side asked; it reports why itself.
    Halted,
}

impl TearDownWhy {
    /// The error that ends the capture's stream, if this end reports one.
    fn fault(&self) -> Option<CaptureError> {
        match self {
            Self::Revoked(missing) => Some(CaptureError::MissingPermissions(missing.clone())),
            Self::Refused => Some(CaptureError::MissingPermissions(vec![
                Permission::Accessibility,
            ])),
            Self::SecureInput => Some(CaptureError::Interrupted(
                "secure input disabled the event tap while the pointer was on another machine"
                    .to_string(),
            )),
            Self::Timeouts => Some(CaptureError::Interrupted(format!(
                "the event tap timed out more than {REENABLES} times in {} s",
                REENABLE_WINDOW.as_secs()
            ))),
            Self::Halted => None,
        }
    }
}

/// What to do with a tap the system disabled.
#[derive(Clone, Debug, PartialEq, Eq)]
enum OnDisabled {
    ReEnable,
    TearDown(TearDownWhy),
}

/// How many timeouts are re-enabled within [`REENABLE_WINDOW`]; one more
/// tears capture down.
const REENABLES: usize = 2;
const REENABLE_WINDOW: Duration = Duration::from_secs(30);

/// Decides, for each disable notice, whether to re-enable the tap or take
/// every tap down (#240). Pure: the caller supplies the time and what the
/// last permission check found.
///
/// - A permission check that found something missing: tear down. Re-enabling
///   then is what hung the system.
/// - Secure input disabling the *active* tap: tear down. The pointer comes
///   back to this Mac, where whatever asked for secure input is, the peer is
///   sent its Leave, and capture starts again shortly with only the
///   listen-only tap. Re-arming the active tap there would put it back in the
///   path of exactly the input the system is keeping from it.
/// - Secure input disabling the listen-only tap: re-enable. It cannot hold
///   input, and secure input comes and goes with every password field.
/// - A timeout: re-enable, at most [`REENABLES`] times in
///   [`REENABLE_WINDOW`]; past that, tear down rather than re-arm in a loop.
#[derive(Debug, Default)]
struct TapGuard {
    timeouts: VecDeque<Instant>,
}

impl TapGuard {
    fn on_disabled(
        &mut self,
        kind: TapKind,
        why: Disabled,
        now: Instant,
        missing: Option<&[Permission]>,
    ) -> OnDisabled {
        if let Some(missing) = missing.filter(|m| !m.is_empty()) {
            return OnDisabled::TearDown(TearDownWhy::Revoked(missing.to_vec()));
        }
        match (why, kind) {
            (Disabled::UserInput, TapKind::Active) => {
                OnDisabled::TearDown(TearDownWhy::SecureInput)
            }
            (Disabled::UserInput, TapKind::Listen) => OnDisabled::ReEnable,
            (Disabled::Timeout, _) => {
                while self
                    .timeouts
                    .front()
                    .is_some_and(|&t| now.saturating_duration_since(t) >= REENABLE_WINDOW)
                {
                    self.timeouts.pop_front();
                }
                if self.timeouts.len() >= REENABLES {
                    return OnDisabled::TearDown(TearDownWhy::Timeouts);
                }
                self.timeouts.push_back(now);
                OnDisabled::ReEnable
            }
        }
    }
}

/// What the last permission check found, for the tap callbacks, which must
/// not ask the system themselves.
#[derive(Debug, Default)]
struct Grants(AtomicU8);

const GRANTS_KNOWN: u8 = 0x80;

fn grant_bit(permission: Permission) -> u8 {
    match permission {
        Permission::Accessibility => 1,
        Permission::InputMonitoring => 2,
    }
}

impl Grants {
    fn record(&self, missing: &[Permission]) {
        let bits = missing
            .iter()
            .fold(GRANTS_KNOWN, |bits, &p| bits | grant_bit(p));
        self.0.store(bits, Ordering::SeqCst);
    }

    /// What the last check found missing; `None` before any check.
    fn missing(&self) -> Option<Vec<Permission>> {
        let bits = self.0.load(Ordering::SeqCst);
        (bits & GRANTS_KNOWN != 0).then(|| {
            [Permission::Accessibility, Permission::InputMonitoring]
                .into_iter()
                .filter(|&p| bits & grant_bit(p) != 0)
                .collect()
        })
    }
}

/// The sending end of the capture's stream, counting what is queued.
#[derive(Clone)]
struct StreamTx {
    tx: UnboundedSender<Item>,
    depth: Arc<AtomicUsize>,
}

impl StreamTx {
    fn send(&self, item: Item) {
        self.depth.fetch_add(1, Ordering::SeqCst);
        if self.tx.send(item).is_err() {
            // The capture was dropped: nothing reads the stream any more.
            self.depth.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn depth(&self) -> usize {
        self.depth.load(Ordering::SeqCst)
    }
}

/// Past this many queued items, motion is summed rather than queued.
const MOTION_BACKLOG: usize = 64;

/// The tap thread's end of the stream. Never blocks. Keys, buttons, scroll
/// and the crossing itself always go out, in order; once the daemon side has
/// fallen [`MOTION_BACKLOG`] items behind, motion is summed into one pending
/// event, sent ahead of whatever comes next, so no displacement is lost.
struct Events {
    tx: StreamTx,
    pending: Option<(Position, f64, f64)>,
}

impl Events {
    fn new(tx: StreamTx) -> Self {
        Self { tx, pending: None }
    }

    fn send(&mut self, pos: Position, event: CaptureEvent) {
        if let CaptureEvent::Input(Event::Pointer(PointerEvent::Motion { dx, dy, .. })) = event {
            let (sx, sy) = match self.pending.take() {
                Some((p, x, y)) if p == pos => (x + dx, y + dy),
                Some(other) => {
                    self.send_motion(other);
                    (dx, dy)
                }
                None => (dx, dy),
            };
            if self.tx.depth() >= MOTION_BACKLOG {
                self.pending = Some((pos, sx, sy));
            } else {
                self.send_motion((pos, sx, sy));
            }
            return;
        }
        if let Some(motion) = self.pending.take() {
            self.send_motion(motion);
        }
        self.tx.send(Ok((pos, event)));
    }

    fn send_motion(&self, (pos, dx, dy): (Position, f64, f64)) {
        self.tx.send(Ok((
            pos,
            CaptureEvent::Input(Event::Pointer(PointerEvent::Motion { time: 0, dx, dy })),
        )));
    }

    /// Motion not yet sent belongs to a crossing that ended.
    fn discard_pending(&mut self) {
        self.pending = None;
    }

    fn fault(&mut self, error: CaptureError) {
        self.pending = None;
        self.tx.send(Err(error));
    }
}

/// What the tap callbacks do to the taps and the cursor. The real one talks
/// to Quartz on the tap thread; tests use a fake.
trait Taps {
    /// Install the active tap. `false` if macOS refuses it.
    fn install_active(&mut self) -> bool;
    /// Remove the active tap, if installed.
    fn remove_active(&mut self);
    /// Re-enable a tap the system disabled.
    fn reenable(&mut self, kind: TapKind);
    /// Disable and remove every tap, and end the tap thread.
    fn tear_down(&mut self);
    /// Move the cursor.
    fn warp(&mut self, to: CGPoint);
}

/// What a tap callback answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    Keep,
    Drop,
}

/// The tap callbacks' logic, owned by the tap thread.
struct Core<T: Taps> {
    shared: Arc<Mutex<Shared>>,
    taps: T,
    events: Events,
    notify: UnboundedSender<ProducerEvent>,
    recheck: Sender<()>,
    grants: Arc<Grants>,
    guard: TapGuard,
    /// The position crossed to, while the active tap is installed.
    current_pos: Option<Position>,
    /// Where the hidden cursor is held while the pointer is on a peer.
    enter_position: Option<CGPoint>,
    modifier_state: XMods,
    /// Every tap is gone; nothing more is done.
    halted: bool,
}

impl<T: Taps> Core<T> {
    fn new(
        shared: Arc<Mutex<Shared>>,
        taps: T,
        stream: StreamTx,
        notify: UnboundedSender<ProducerEvent>,
        recheck: Sender<()>,
        grants: Arc<Grants>,
    ) -> Self {
        Self {
            shared,
            taps,
            events: Events::new(stream),
            notify,
            recheck,
            grants,
            guard: TapGuard::default(),
            current_pos: None,
            enter_position: None,
            modifier_state: XMods::empty(),
            halted: false,
        }
    }

    /// One event from the tap `kind`. Never waits for a lock.
    fn on_event(&mut self, kind: TapKind, seen: &Seen, now: Instant) -> Verdict {
        if self.halted {
            return Verdict::Keep;
        }
        // First, before anything that could take time: a disabled tap.
        if let Some(why) = seen.disabled() {
            self.on_disabled(kind, why, now);
            return Verdict::Keep;
        }
        match (self.current_pos, kind) {
            (Some(pos), TapKind::Active) => {
                self.forward(pos, seen);
                Verdict::Drop
            }
            // Slipped past the active tap at the crossing: it reached this
            // Mac, and sending it on too would deliver it twice.
            (Some(_), TapKind::Listen) => Verdict::Keep,
            (None, TapKind::Listen) => {
                if matches!(seen.ty, CGEventType::MouseMoved) {
                    self.check_crossing(seen);
                }
                Verdict::Keep
            }
            // Queued for an active tap that was just removed.
            (None, TapKind::Active) => Verdict::Keep,
        }
    }

    fn on_disabled(&mut self, kind: TapKind, why: Disabled, now: Instant) {
        let missing = self.grants.missing();
        match self.guard.on_disabled(kind, why, now, missing.as_deref()) {
            OnDisabled::ReEnable => {
                log::warn!("CGEventTap ({kind:?}) disabled ({why:?}) — re-enabling");
                self.taps.reenable(kind);
            }
            OnDisabled::TearDown(reason) => {
                log::warn!("CGEventTap ({kind:?}) disabled ({why:?}) — removing every tap");
                self.tear_down(reason);
            }
        }
        // Ask the permission watch to check now; one already asked covers it.
        let _ = self.recheck.try_send(());
    }

    fn forward(&mut self, pos: Position, seen: &Seen) {
        let mut out = Vec::new();
        get_events(seen, &mut out, &mut self.modifier_state)
            .unwrap_or_else(|e| log::error!("Failed to get events: {e}"));
        for event in out {
            self.events.send(pos, event);
        }
        // Keep the (hidden) cursor at the edge of the screen.
        if seen.is_motion() {
            if let Some(at) = self.enter_position {
                self.taps.warp(at);
            }
        }
    }

    fn check_crossing(&mut self, seen: &Seen) {
        // The daemon side holds this only for a copy; when it does, skip this
        // check, and the next motion makes it.
        let crossing = match self.shared.try_lock() {
            Ok(shared) => shared.crossed(seen).map(|pos| (pos, shared.bounds)),
            Err(TryLockError::Poisoned(shared)) => {
                let shared = shared.into_inner();
                shared.crossed(seen).map(|pos| (pos, shared.bounds))
            }
            Err(TryLockError::WouldBlock) => None,
        };
        if let Some((pos, bounds)) = crossing {
            self.begin(pos, seen, bounds);
        }
    }

    fn begin(&mut self, pos: Position, seen: &Seen, bounds: Bounds) {
        let started = Instant::now();
        if !self.taps.install_active() {
            log::warn!("macOS refused the active event tap for a crossing to {pos}");
            self.tear_down(TearDownWhy::Refused);
            return;
        }
        log::debug!("active tap installed in {:?}", started.elapsed());
        let edge_offset = 1.0;
        let mut at = CGPoint::new(seen.x, seen.y);
        match pos {
            Position::Left => at.x = bounds.xmin + edge_offset,
            Position::Right => at.x = bounds.xmax - edge_offset,
            Position::Top => at.y = bounds.ymin + edge_offset,
            Position::Bottom => at.y = bounds.ymax - edge_offset,
        };
        self.current_pos = Some(pos);
        self.enter_position = Some(at);
        self.taps.warp(at);
        self.events.send(pos, CaptureEvent::Begin);
        let _ = self.notify.send(ProducerEvent::Grab);
    }

    /// A command from the daemon side.
    fn command(&mut self, command: TapCommand) {
        match command {
            TapCommand::Release => self.end_capture(),
            TapCommand::Destroy(pos) => {
                if self.current_pos == Some(pos) {
                    self.end_capture();
                }
            }
            TapCommand::Halt => self.tear_down(TearDownWhy::Halted),
        }
    }

    /// The pointer comes back: remove the active tap.
    fn end_capture(&mut self) {
        if self.current_pos.take().is_some() {
            self.taps.remove_active();
            self.enter_position = None;
            self.events.discard_pending();
            let _ = self.notify.send(ProducerEvent::Released);
        }
    }

    fn tear_down(&mut self, why: TearDownWhy) {
        if self.halted {
            return;
        }
        self.halted = true;
        self.taps.tear_down();
        if self.current_pos.take().is_some() {
            self.enter_position = None;
            let _ = self.notify.send(ProducerEvent::Released);
        }
        if let Some(fault) = why.fault() {
            log::warn!("input capture stops: {fault}");
            self.events.fault(fault);
        }
    }
}

/// A tap on the run loop, with its source.
struct Installed {
    tap: CGEventTap<'static>,
    source: CFRunLoopSource,
}

impl Installed {
    fn port(&self) -> *mut c_void {
        self.tap.mach_port().as_concrete_TypeRef() as *mut c_void
    }

    /// Take it out of the event path and off the run loop. Its closure is
    /// freed later, never from inside its own callback.
    fn detach(&self, run_loop: &CFRunLoop) {
        unsafe {
            CGEventTapEnable(self.port(), false);
        }
        run_loop.remove_source(&self.source, unsafe { kCFRunLoopCommonModes });
        unsafe {
            CFMachPortInvalidate(self.tap.mach_port().as_concrete_TypeRef() as CFMachPortRef)
        };
    }
}

/// The real taps, on the tap thread.
struct RealTaps {
    run_loop: CFRunLoop,
    core: Weak<RefCell<Core<RealTaps>>>,
    listen: Option<Installed>,
    active: Option<Installed>,
    /// Detached taps, dropped where none of their callbacks can be running.
    graveyard: Vec<Installed>,
}

impl RealTaps {
    fn install(&mut self, kind: TapKind) -> Result<Installed, ()> {
        let core = self.core.clone();
        // SAFETY: the closure is 'static. It is not Send, so the tap must only
        // ever be serviced by this thread's run loop, where it is installed
        // below, and dropped on this thread, which `RealTaps` guarantees: it
        // lives in the tap thread's `Core` and never leaves it.
        let tap = unsafe {
            CGEventTap::new_unchecked(
                CGEventTapLocation::Session,
                CGEventTapPlacement::HeadInsertEventTap,
                tap_options(kind),
                events_of_interest(kind),
                move |_proxy: CGEventTapProxy, ty: CGEventType, ev: &CGEvent| {
                    tap_callback(&core, kind, ty, ev)
                },
            )
        }?;
        let source = tap.mach_port().create_runloop_source(0)?;
        self.run_loop
            .add_source(&source, unsafe { kCFRunLoopCommonModes });
        tap.enable();
        Ok(Installed { tap, source })
    }

    /// Free detached taps. Called only outside the active tap's callback.
    fn reap(&mut self) {
        self.graveyard.clear();
    }
}

impl Taps for RealTaps {
    fn install_active(&mut self) -> bool {
        // Called from the listen tap's callback: no active tap's is running.
        self.reap();
        if self.active.is_some() {
            return true;
        }
        match self.install(TapKind::Active) {
            Ok(tap) => {
                self.active = Some(tap);
                true
            }
            Err(()) => false,
        }
    }

    fn remove_active(&mut self) {
        if let Some(tap) = self.active.take() {
            tap.detach(&self.run_loop);
            self.graveyard.push(tap);
        }
    }

    fn reenable(&mut self, kind: TapKind) {
        let tap = match kind {
            TapKind::Listen => self.listen.as_ref(),
            TapKind::Active => self.active.as_ref(),
        };
        if let Some(tap) = tap {
            unsafe { CGEventTapEnable(tap.port(), true) };
        }
    }

    fn tear_down(&mut self) {
        for tap in [self.active.take(), self.listen.take()]
            .into_iter()
            .flatten()
        {
            tap.detach(&self.run_loop);
            self.graveyard.push(tap);
        }
        self.run_loop.stop();
    }

    fn warp(&mut self, to: CGPoint) {
        log::trace!("Resetting cursor position to: {}, {}", to.x, to.y);
        if let Err(e) = CGDisplay::warp_mouse_cursor_position(to) {
            log::warn!("{}", CaptureError::WarpCursor(e));
        }
    }
}

/// Every tap's callback. Never waits: a `Core` already in use (which nothing
/// here does) passes the event on.
fn tap_callback(
    core: &Weak<RefCell<Core<RealTaps>>>,
    kind: TapKind,
    ty: CGEventType,
    ev: &CGEvent,
) -> CallbackResult {
    log::trace!("Got event from {kind:?} tap: {ty:?}");
    let Some(core) = core.upgrade() else {
        return CallbackResult::Keep;
    };
    let Ok(mut core) = core.try_borrow_mut() else {
        return CallbackResult::Keep;
    };
    let seen = Seen::of(ty, ev);
    match core.on_event(kind, &seen, Instant::now()) {
        Verdict::Keep => CallbackResult::Keep,
        Verdict::Drop => {
            // Returning Drop should stop the event from being processed, but
            // core foundation still returns the event.
            ev.set_type(CGEventType::Null);
            CallbackResult::Drop
        }
    }
}

/// A run loop source, retained, handed to other threads to signal.
struct SignalSource(CFRunLoopSource);

// SAFETY: it is only signalled (CFRunLoopSourceSignal), retained and
// released from other threads, all of which Core Foundation documents as
// thread-safe.
unsafe impl Send for SignalSource {}
unsafe impl Sync for SignalSource {}

/// The daemon side's handle on the tap thread.
struct TapRemote {
    tx: std::sync::mpsc::Sender<TapCommand>,
    source: SignalSource,
    run_loop: CFRunLoop,
}

impl TapRemote {
    fn send(&self, command: TapCommand) {
        if self.tx.send(command).is_ok() {
            unsafe {
                CFRunLoopSourceSignal(self.source.0.as_concrete_TypeRef());
                CFRunLoopWakeUp(self.run_loop.as_concrete_TypeRef());
            }
        }
    }
}

type Perform = Box<dyn Fn()>;

extern "C" fn perform_commands(info: *const c_void) {
    // SAFETY: `info` is the `Box<Perform>` the tap thread owns, freed only
    // after the source is invalidated and the run loop has returned.
    let perform = unsafe { &*(info as *const Perform) };
    perform();
}

/// What the tap thread is given.
struct TapThread {
    shared: Arc<Mutex<Shared>>,
    stream: StreamTx,
    notify: UnboundedSender<ProducerEvent>,
    recheck: Sender<()>,
    grants: Arc<Grants>,
}

type Ready = Result<(CFRunLoop, TapRemote), MacosCaptureCreationError>;

fn event_tap_thread(
    args: TapThread,
    ready: std::sync::mpsc::Sender<Ready>,
    exit: oneshot::Sender<()>,
) {
    let run_loop = CFRunLoop::get_current();
    let display_notify_tx = args.notify.clone();
    let core: Rc<RefCell<Core<RealTaps>>> = Rc::new_cyclic(|me| {
        RefCell::new(Core::new(
            args.shared,
            RealTaps {
                run_loop: run_loop.clone(),
                core: me.clone(),
                listen: None,
                active: None,
                graveyard: Vec::new(),
            },
            args.stream,
            args.notify,
            args.recheck,
            args.grants,
        ))
    });

    // Capture starts with the listen-only tap alone.
    let listen = core.borrow_mut().taps.install(TapKind::Listen);
    match listen {
        Ok(tap) => core.borrow_mut().taps.listen = Some(tap),
        Err(()) => {
            let _ = ready.send(Err(MacosCaptureCreationError::EventTapCreation));
            return;
        }
    }

    // Commands from the daemon side, run on this thread between events.
    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<TapCommand>();
    let weak = Rc::downgrade(&core);
    let perform: Box<Perform> = Box::new(Box::new(move || {
        let Some(core) = weak.upgrade() else { return };
        let Ok(mut core) = core.try_borrow_mut() else {
            return;
        };
        core.taps.reap();
        while let Ok(command) = cmd_rx.try_recv() {
            core.command(command);
        }
    }));
    let info = Box::into_raw(perform);
    let mut context = CFRunLoopSourceContext {
        version: 0,
        info: info as *mut c_void,
        retain: None,
        release: None,
        copyDescription: None,
        equal: None,
        hash: None,
        schedule: None,
        cancel: None,
        perform: perform_commands,
    };
    let source_ref = unsafe { CFRunLoopSourceCreate(kCFAllocatorDefault, 0, &mut context) };
    if source_ref.is_null() {
        drop(unsafe { Box::from_raw(info) });
        let _ = ready.send(Err(MacosCaptureCreationError::EventTapCreation));
        return;
    }
    let source = unsafe { CFRunLoopSource::wrap_under_create_rule(source_ref) };
    run_loop.add_source(&source, unsafe { kCFRunLoopCommonModes });
    let remote = TapRemote {
        tx: cmd_tx,
        source: SignalSource(source.clone()),
        run_loop: run_loop.clone(),
    };
    if ready.send(Ok((run_loop.clone(), remote))).is_err() {
        unsafe { CFRunLoopSourceInvalidate(source.as_concrete_TypeRef()) };
        drop(core);
        drop(unsafe { Box::from_raw(info) });
        return;
    }

    // Refresh the capture bounds when a monitor is plugged in, the
    // resolution changes, or displays are rearranged. Box-leak the sender so
    // the C side has a stable pointer; reclaimed after the run loop exits.
    let display_user_info = Box::into_raw(Box::new(display_notify_tx)) as *mut c_void;
    unsafe {
        CGDisplayRegisterReconfigurationCallback(
            display_reconfiguration_callback,
            display_user_info,
        );
    }

    log::debug!("running CFRunLoop...");
    CFRunLoop::run_current();
    log::debug!("event tap thread exiting!...");

    unsafe {
        CFRunLoopSourceInvalidate(source.as_concrete_TypeRef());
        CGDisplayRemoveReconfigurationCallback(display_reconfiguration_callback, display_user_info);
        drop(Box::from_raw(
            display_user_info as *mut UnboundedSender<ProducerEvent>,
        ));
    }
    // Every tap goes with it, here, outside any of their callbacks.
    drop(core);
    drop(unsafe { Box::from_raw(info) });

    let _ = exit.send(());
}

/// Quartz display-reconfiguration callback. Fires twice per change: once
/// with `kCGDisplayBeginConfigurationFlag` set (BEFORE the change, bounds
/// still stale), then afterwards. Skip the begin phase; on the real
/// notification, kick the producer task to refresh bounds. Never blocks.
extern "C" fn display_reconfiguration_callback(_display: u32, flags: u32, user_info: *mut c_void) {
    const K_CG_DISPLAY_BEGIN_CONFIGURATION_FLAG: u32 = 1 << 0;
    if flags & K_CG_DISPLAY_BEGIN_CONFIGURATION_FLAG != 0 {
        return;
    }
    if user_info.is_null() {
        return;
    }
    // SAFETY: user_info is a Box::into_raw of UnboundedSender<ProducerEvent>
    // owned by `event_tap_thread`; the registration is removed before the box
    // is freed, and the callback only fires on that thread's run loop.
    let sender = unsafe { &*(user_info as *const UnboundedSender<ProducerEvent>) };
    if let Err(e) = sender.send(ProducerEvent::DisplayReconfigured) {
        log::warn!("failed to notify display reconfiguration: {e}");
    }
}

pub struct MacOSInputCapture {
    event_rx: UnboundedReceiver<Item>,
    depth: Arc<AtomicUsize>,
    notify_tx: UnboundedSender<ProducerEvent>,
    remote: Option<Rc<TapRemote>>,
    run_loop: CFRunLoop,
}

impl MacOSInputCapture {
    pub async fn new() -> Result<Self, MacosCaptureCreationError> {
        let probe: Probe = Arc::new(granted);
        let grants = Arc::new(Grants::default());
        let missing = missing_permissions(&probe);
        grants.record(&missing);
        if !missing.is_empty() {
            return Err(MacosCaptureCreationError::MissingPermissions(missing));
        }

        let mut shared = Shared::default();
        match compute_display_bounds()? {
            Some(bounds) => shared.store_bounds_if_changed(bounds),
            None => log::warn!("no active displays reported; keeping previous bounds"),
        }
        let shared = Arc::new(Mutex::new(shared));
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let depth = Arc::new(AtomicUsize::new(0));
        let stream = StreamTx {
            tx: event_tx,
            depth: depth.clone(),
        };
        let (notify_tx, mut notify_rx) = mpsc::unbounded_channel();
        let (recheck_tx, recheck_rx) = mpsc::channel(1);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (tap_exit_tx, mut tap_exit_rx) = oneshot::channel();

        unsafe {
            configure_cf_settings()?;
        }

        log::info!("Enabling CGEvent tap (listen-only until the pointer crosses)");
        let args = TapThread {
            shared: shared.clone(),
            stream: stream.clone(),
            notify: notify_tx.clone(),
            recheck: recheck_tx,
            grants: grants.clone(),
        };
        thread::spawn(move || event_tap_thread(args, ready_tx, tap_exit_tx));

        // wait for event tap creation result
        let (run_loop, remote) = ready_rx
            .recv()
            .map_err(|_| MacosCaptureCreationError::EventTapCreation)??;
        let remote = Rc::new(remote);

        let halt = {
            let remote = remote.clone();
            move || remote.send(TapCommand::Halt)
        };
        tokio::task::spawn_local(watch_grants(
            probe,
            GRANTS_EVERY,
            recheck_rx,
            stream,
            grants,
            halt,
        ));

        let _producer: tokio::task::JoinHandle<()> = tokio::task::spawn_local(async move {
            // Safety-net poll: the Quartz display-reconfiguration callback
            // doesn't reliably fire on lid open/close with some docks.
            let mut bounds_poll = tokio::time::interval(Duration::from_secs(1));
            bounds_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut hidden = false;
            loop {
                tokio::select! {
                    producer_event = notify_rx.recv() => {
                        let Some(producer_event) = producer_event else {
                            break;
                        };
                        log::debug!("handling event: {producer_event:?}");
                        // The shared lock is held only to change it; every
                        // WindowServer call is made outside it.
                        match producer_event {
                            ProducerEvent::Create(p) => {
                                lock(&shared).active_clients.insert(p);
                            }
                            ProducerEvent::Destroy(p) => {
                                lock(&shared).active_clients.remove(&p);
                            }
                            ProducerEvent::Grab => {
                                if !hidden {
                                    if let Err(e) = CGDisplay::hide_cursor(&CGDisplay::main()) {
                                        log::error!("failed to hide the cursor: {e}");
                                    }
                                    hidden = true;
                                }
                            }
                            ProducerEvent::Released => {
                                if hidden {
                                    if let Err(e) = CGDisplay::show_cursor(&CGDisplay::main()) {
                                        log::error!("failed to show the cursor: {e}");
                                    }
                                    hidden = false;
                                }
                            }
                            ProducerEvent::DisplayReconfigured => refresh_bounds(&shared),
                        }
                    }
                    _ = bounds_poll.tick() => refresh_bounds(&shared),
                    _ = &mut tap_exit_rx => break,
                }
            }
            // show cursor
            let _ = CGDisplay::show_cursor(&CGDisplay::main());
        });

        Ok(Self {
            event_rx,
            depth,
            notify_tx,
            remote: Some(remote),
            run_loop,
        })
    }

    fn command(&self, command: TapCommand) {
        if let Some(remote) = &self.remote {
            remote.send(command);
        }
    }
}

/// Asks whether macOS grants a permission.
type Probe = Arc<dyn Fn(Permission) -> bool + Send + Sync>;

/// Whether macOS grants this process `permission`. Silent: none of the checks
/// raises a prompt; the app asks instead (#169). Both are required: a tap
/// that starts without Input Monitoring may be sent no keys.
///
/// Accessibility is answered by [`active_tap_permitted`], not by
/// `AXIsProcessTrusted`, which can keep its first answer for the life of
/// the process on macOS 27, for a revocation and for a grant (#240). The
/// latter is still logged beside it, so a disagreement shows in the log.
fn granted(permission: Permission) -> bool {
    match permission {
        Permission::Accessibility => {
            let started = Instant::now();
            let tap = active_tap_permitted();
            let took = started.elapsed();
            // SAFETY: takes no arguments and only reads this process's grant.
            let ax = unsafe { AXIsProcessTrusted() } != 0;
            log::debug!(
                "Accessibility probe: active tap {} in {took:?}; AXIsProcessTrusted says {ax}",
                if tap { "permitted" } else { "refused" }
            );
            tap
        }
        // SAFETY: takes no arguments and only reads this process's grant.
        Permission::InputMonitoring => unsafe { CGPreflightListenEventAccess() },
    }
}

/// Whether macOS lets this process install an active event tap, which it
/// does only with Accessibility: creates one for key-down events at the tail
/// of the session's taps, disabled and invalidated at once. It is never
/// added to a run loop and never outlives this call.
pub fn active_tap_permitted() -> bool {
    extern "C" fn pass(
        _proxy: CGEventTapProxy,
        _ty: u32,
        event: *mut c_void,
        _info: *mut c_void,
    ) -> *mut c_void {
        event
    }
    const SESSION: u32 = 1; // kCGSessionEventTap
    const TAIL_APPEND: u32 = 1; // kCGTailAppendEventTap
    const ACTIVE: u32 = 0; // kCGEventTapOptionDefault
    const KEY_DOWN_MASK: u64 = 1 << 10; // CGEventMaskBit(kCGEventKeyDown)
    // SAFETY: creates a tap with a callback that never runs (the port is
    // never scheduled), then disables, invalidates and releases it.
    unsafe {
        let port = CGEventTapCreate(
            SESSION,
            TAIL_APPEND,
            ACTIVE,
            KEY_DOWN_MASK,
            pass,
            std::ptr::null_mut(),
        );
        if port.is_null() {
            return false;
        }
        CGEventTapEnable(port as *mut c_void, false);
        CFMachPortInvalidate(port);
        CFRelease(port as *const c_void);
        true
    }
}

/// Every permission capture needs that `probe` reports missing, so the user
/// is told all of them at once.
fn missing_permissions(probe: &Probe) -> Vec<Permission> {
    [Permission::Accessibility, Permission::InputMonitoring]
        .into_iter()
        .filter(|&p| !probe(p))
        .collect()
}

/// How often capture asks, while it runs, whether macOS still grants what it
/// needs. While the active tap is installed this is what bounds how long it
/// can outlive a revocation that sends no disable notice.
const GRANTS_EVERY: Duration = Duration::from_secs(2);

/// While capture runs, asks every `every`, and at once whenever a tap is
/// disabled, whether macOS still grants what capture needs (#79), and keeps
/// the answer in `grants` for the tap callbacks. Once one is gone, `halt`
/// removes every tap and the error goes on the capture's stream, which ends
/// the session and tells the daemon which setting to change. Ends then, or
/// once the capture is dropped.
///
/// The checks run on a blocking thread, so a slow answer from the system
/// never holds the daemon's loop.
async fn watch_grants(
    probe: Probe,
    every: Duration,
    mut recheck: Receiver<()>,
    faults: StreamTx,
    grants: Arc<Grants>,
    halt: impl Fn() + 'static,
) {
    let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        // The nudges close once the tap's thread has ended and dropped it.
        let tap_gone = tokio::select! {
            _ = ticks.tick() => false,
            nudge = recheck.recv() => nudge.is_none(),
            _ = faults.tx.closed() => return,
        };
        let probe = probe.clone();
        let missing = tokio::task::spawn_blocking(move || missing_permissions(&probe))
            .await
            .unwrap_or_default();
        log::debug!("capture permission check: missing {missing:?}");
        grants.record(&missing);
        if !missing.is_empty() {
            halt();
            let fault = CaptureError::MissingPermissions(missing);
            log::warn!("input capture stops: {fault}");
            faults.send(Err(fault));
            return;
        }
        // With the tap gone there is nothing left to watch. Holding a sender
        // would keep the stream open, and capture would read as running.
        if tap_gone {
            return;
        }
    }
}

impl Drop for MacOSInputCapture {
    fn drop(&mut self) {
        self.run_loop.stop();
    }
}

#[async_trait(?Send)]
impl Capture for MacOSInputCapture {
    async fn create(&mut self, pos: Position) -> Result<(), CaptureError> {
        log::debug!("creating capture, {pos}");
        let _ = self.notify_tx.send(ProducerEvent::Create(pos));
        Ok(())
    }

    async fn destroy(&mut self, pos: Position) -> Result<(), CaptureError> {
        log::debug!("destroying capture {pos}");
        let _ = self.notify_tx.send(ProducerEvent::Destroy(pos));
        self.command(TapCommand::Destroy(pos));
        Ok(())
    }

    async fn release(&mut self) -> Result<(), CaptureError> {
        log::debug!("notifying Release");
        self.command(TapCommand::Release);
        Ok(())
    }

    async fn terminate(&mut self) -> Result<(), CaptureError> {
        Ok(())
    }
}

impl Stream for MacOSInputCapture {
    type Item = Result<(Position, CaptureEvent), CaptureError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let polled = self.event_rx.poll_recv(cx);
        if let Poll::Ready(Some(_)) = &polled {
            self.depth.fetch_sub(1, Ordering::SeqCst);
        }
        polled
    }
}

type CGSConnectionID = u32;

#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    fn CGSSetConnectionProperty(
        cid: CGSConnectionID,
        targetCID: CGSConnectionID,
        key: CFStringRef,
        value: CFBooleanRef,
    ) -> CGError;
    fn _CGSDefaultConnection() -> CGSConnectionID;
}

extern "C" {
    fn CGEventSourceSetLocalEventsSuppressionInterval(
        event_source: CGEventSource,
        seconds: CFTimeInterval,
    );
    fn CGPreflightListenEventAccess() -> bool;
    /// Enable or disable an event tap. Thread-safe. The `tap` argument is a
    /// `CFMachPortRef`.
    fn CGEventTapEnable(tap: *mut c_void, enable: bool);

    /// Quartz Event Services. Declared here for the permission probe, which
    /// must not schedule the port the way `CGEventTap::new` lets it.
    fn CGEventTapCreate(
        tap: u32,
        place: u32,
        options: u32,
        events_of_interest: u64,
        callback: extern "C" fn(CGEventTapProxy, u32, *mut c_void, *mut c_void) -> *mut c_void,
        user_info: *mut c_void,
    ) -> CFMachPortRef;

    /// Register a callback invoked when the display configuration
    /// changes (monitor add/remove, resolution change, mirror,
    /// rearrange, etc). See Quartz Display Services Reference.
    fn CGDisplayRegisterReconfigurationCallback(
        callback: extern "C" fn(u32, u32, *mut c_void),
        user_info: *mut c_void,
    ) -> CGError;
    fn CGDisplayRemoveReconfigurationCallback(
        callback: extern "C" fn(u32, u32, *mut c_void),
        user_info: *mut c_void,
    ) -> CGError;
}

#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    // Apple declares this `Boolean` (u8), not C `_Bool`.
    fn AXIsProcessTrusted() -> u8;
}

unsafe fn configure_cf_settings() -> Result<(), MacosCaptureCreationError> {
    // When we warp the cursor using CGWarpMouseCursorPosition local events are suppressed for a short time
    // this leeds to the cursor not flowing when crossing back from a clinet, set this to to 0 stops the warp
    // from working, set a low value by trial and error, 0.05s seems good. 0.25s is the default
    let event_source = CGEventSource::new(CGEventSourceStateID::CombinedSessionState)
        .map_err(|_| MacosCaptureCreationError::EventSourceCreation)?;
    CGEventSourceSetLocalEventsSuppressionInterval(event_source, 0.05);
    // FIXME Memory Leak

    // This is a private settings that allows the cursor to be hidden while in the background.
    // It is used by Barrier and other apps.
    let key = CString::new("SetsCursorInBackground").unwrap();
    let cf_key = CFStringCreateWithCString(
        kCFAllocatorDefault,
        key.as_ptr() as *const c_char,
        kCFStringEncodingUTF8,
    );
    if CGSSetConnectionProperty(
        _CGSDefaultConnection(),
        _CGSDefaultConnection(),
        cf_key,
        kCFBooleanTrue,
    ) != kCGErrorSuccess
    {
        return Err(MacosCaptureCreationError::CGCursorProperty);
    }
    CFRelease(cf_key as *const c_void);
    Ok(())
}

// From X11/X.h
bitflags! {
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    struct XMods: u32 {
        const ShiftMask = (1<<0);
        const LockMask = (1<<1);
        const ControlMask = (1<<2);
        const Mod1Mask = (1<<3);
        const Mod2Mask = (1<<4);
        const Mod3Mask = (1<<5);
        const Mod4Mask = (1<<6);
        const Mod5Mask = (1<<7);
    }
}
#[cfg(test)]
mod a_permission_lost_while_capture_runs {
    //! What reaches the capture's stream once macOS takes a permission away
    //! while capture runs (#79). The grants are a stand-in and no event tap
    //! is created; the stream is the one the daemon reads.

    use super::{
        CaptureError, Grants, MacOSInputCapture, Permission, Probe, StreamTx, mpsc, watch_grants,
    };
    use core_foundation::runloop::CFRunLoop;
    use futures::StreamExt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    /// What must happen is waited for this long at most.
    const DEADLINE: Duration = Duration::from_secs(30);

    fn run_local<F: std::future::Future>(f: F) -> F::Output {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        tokio::task::LocalSet::new().block_on(&rt, f)
    }

    /// Grants Accessibility always, and Input Monitoring while `input` holds.
    fn system(input: &Arc<AtomicBool>) -> Probe {
        let input = input.clone();
        Arc::new(move |p| p == Permission::Accessibility || input.load(Ordering::SeqCst))
    }

    /// A capture whose stream the grants watch feeds, checking every
    /// `every`, and the sender that stands in for the tap's disable nudge.
    fn capture(probe: Probe, every: Duration) -> (MacOSInputCapture, mpsc::Sender<()>) {
        capture_halted_by(probe, every, || {})
    }

    /// As [`capture`], with `halt` standing in for removing the taps.
    fn capture_halted_by(
        probe: Probe,
        every: Duration,
        halt: impl Fn() + 'static,
    ) -> (MacOSInputCapture, mpsc::Sender<()>) {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let depth = Arc::new(AtomicUsize::new(0));
        let (notify_tx, _) = mpsc::unbounded_channel();
        let (recheck_tx, recheck_rx) = mpsc::channel(1);
        let faults = StreamTx {
            tx: event_tx,
            depth: depth.clone(),
        };
        tokio::task::spawn_local(watch_grants(
            probe,
            every,
            recheck_rx,
            faults,
            Arc::new(Grants::default()),
            halt,
        ));
        let capture = MacOSInputCapture {
            event_rx,
            depth,
            notify_tx,
            remote: None,
            run_loop: CFRunLoop::get_current(),
        };
        (capture, recheck_tx)
    }

    // LEDGER T5 | class B | 1 return value: MacOSInputCapture Stream::next fed by watch_grants
    #[test]
    fn a_permission_taken_away_ends_the_stream_with_an_error_naming_it() {
        run_local(async {
            let input = Arc::new(AtomicBool::new(true));
            let (mut capture, _nudge) = capture(system(&input), Duration::from_millis(20));
            tokio::time::sleep(Duration::from_millis(200)).await;
            input.store(false, Ordering::SeqCst);
            let next = tokio::time::timeout(DEADLINE, capture.next()).await;
            assert!(
                matches!(
                    &next,
                    Ok(Some(Err(CaptureError::MissingPermissions(missing))))
                        if missing == &[Permission::InputMonitoring]
                ),
                "Input Monitoring was taken away while capture ran. The capture's \
                 stream must yield the error naming it, which is how the daemon \
                 learns capture stopped and why; it yielded {next:?} (Err(Elapsed): \
                 nothing)"
            );
        });
    }

    // LEDGER T15 | class B | 1 return value: MacOSInputCapture Stream::next once the tap's nudge sender is dropped
    #[test]
    fn a_tap_that_is_gone_with_everything_granted_ends_the_stream() {
        run_local(async {
            let input = Arc::new(AtomicBool::new(true));
            let (mut capture, nudge) = capture(system(&input), Duration::from_secs(3600));
            // The tap's thread ends and drops what it holds; so does the
            // test's stand-in for the tap's own event sender.
            drop(nudge);
            let next = tokio::time::timeout(DEADLINE, capture.next()).await;
            assert!(
                matches!(next, Ok(None)),
                "the tap is gone and every permission is granted. The stream must end, \
                 as it did before the grants watch, or capture reads as running with \
                 no tap; it yielded {next:?} (Err(Elapsed): nothing)"
            );
        });
    }

    // LEDGER T6 | class B | 1 return value: MacOSInputCapture Stream::next after a watch_grants nudge
    #[test]
    fn a_disabled_tap_checks_the_grants_at_once() {
        run_local(async {
            let input = Arc::new(AtomicBool::new(true));
            // No tick falls inside the test: only the nudge can check.
            let (mut capture, nudge) = capture(system(&input), Duration::from_secs(3600));
            input.store(false, Ordering::SeqCst);
            nudge.send(()).await.expect("the watch runs");
            let next = tokio::time::timeout(DEADLINE, capture.next()).await;
            assert!(
                matches!(
                    &next,
                    Ok(Some(Err(CaptureError::MissingPermissions(missing))))
                        if missing == &[Permission::InputMonitoring]
                ),
                "macOS disabled the tap after taking Input Monitoring away. The tap \
                 is re-enabled in place, so the check its disable asks for is what \
                 ends capture; it yielded {next:?} (Err(Elapsed): nothing)"
            );
        });
    }

    // LEDGER T2411 | class B | 6 halt invoked by watch_grants
    #[test]
    fn a_permission_taken_away_removes_the_taps_before_the_stream_says_so() {
        run_local(async {
            let input = Arc::new(AtomicBool::new(true));
            let halted = Arc::new(AtomicBool::new(false));
            let halting = halted.clone();
            let (mut capture, _nudge) =
                capture_halted_by(system(&input), Duration::from_millis(20), move || {
                    halting.store(true, Ordering::SeqCst)
                });
            input.store(false, Ordering::SeqCst);
            let next = tokio::time::timeout(DEADLINE, capture.next()).await;
            assert!(
                matches!(next, Ok(Some(Err(CaptureError::MissingPermissions(_))))),
                "precondition: the stream names the missing permission; it yielded {next:?}"
            );
            assert!(
                halted.load(Ordering::SeqCst),
                "a permission was found gone and the stream said so, but the taps were \
                 not told to come down: an active tap would stay in the event path \
                 until the daemon got round to dropping the capture (#240)"
            );
        });
    }
}

#[cfg(test)]
mod a_disabled_tap {
    //! What [`TapGuard`] decides for each disable notice (#240). Pure: the
    //! clock and the last permission check are supplied.

    use super::{
        Disabled, OnDisabled, Permission, REENABLE_WINDOW, TapGuard, TapKind, TearDownWhy,
    };
    use std::time::{Duration, Instant};

    // LEDGER T2401 | class B | 1 return value: TapGuard::on_disabled
    #[test]
    fn a_third_timeout_within_the_window_tears_down_and_spaced_ones_do_not() {
        let start = Instant::now();
        let at = |s: u64| start + Duration::from_secs(s);
        let mut guard = TapGuard::default();
        let seen: Vec<OnDisabled> = [0, 5, 10]
            .into_iter()
            .map(|s| guard.on_disabled(TapKind::Active, Disabled::Timeout, at(s), Some(&[])))
            .collect();
        assert_eq!(
            seen,
            [
                OnDisabled::ReEnable,
                OnDisabled::ReEnable,
                OnDisabled::TearDown(TearDownWhy::Timeouts)
            ],
            "three timeouts in 10 s: the first two are re-enabled, the third must take \
             the taps down rather than re-arm an active tap in a loop"
        );

        let mut guard = TapGuard::default();
        let spaced = REENABLE_WINDOW.as_secs() + 1;
        let seen: Vec<OnDisabled> = (0..6)
            .map(|i| {
                guard.on_disabled(
                    TapKind::Active,
                    Disabled::Timeout,
                    at(i * spaced),
                    Some(&[]),
                )
            })
            .collect();
        assert!(
            seen.iter().all(|d| *d == OnDisabled::ReEnable),
            "timeouts further apart than the window are each re-enabled: {seen:?}"
        );
    }

    // LEDGER T2402 | class B | 1 return value: TapGuard::on_disabled
    #[test]
    fn a_permission_found_missing_tears_down_on_any_disable() {
        let missing = [Permission::Accessibility];
        for kind in [TapKind::Listen, TapKind::Active] {
            for why in [Disabled::Timeout, Disabled::UserInput] {
                let decided =
                    TapGuard::default().on_disabled(kind, why, Instant::now(), Some(&missing));
                assert_eq!(
                    decided,
                    OnDisabled::TearDown(TearDownWhy::Revoked(missing.to_vec())),
                    "{kind:?} tap disabled by {why:?} after the check found Accessibility \
                     gone: re-enabling then is what hung the system"
                );
            }
        }
    }

    // LEDGER T2403 | class B | 1 return value: TapGuard::on_disabled
    #[test]
    fn one_timeout_with_the_permission_present_or_unchecked_is_re_enabled() {
        for kind in [TapKind::Listen, TapKind::Active] {
            for missing in [Some(&[][..]), None] {
                let decided = TapGuard::default().on_disabled(
                    kind,
                    Disabled::Timeout,
                    Instant::now(),
                    missing,
                );
                assert_eq!(
                    decided,
                    OnDisabled::ReEnable,
                    "one timeout of the {kind:?} tap, permission check {missing:?}"
                );
            }
        }
    }

    // LEDGER T2404 | class B | 1 return value: TapGuard::on_disabled
    #[test]
    fn secure_input_takes_the_active_tap_down_and_re_enables_the_listening_one() {
        let now = Instant::now();
        assert_eq!(
            TapGuard::default().on_disabled(TapKind::Active, Disabled::UserInput, now, Some(&[])),
            OnDisabled::TearDown(TearDownWhy::SecureInput),
            "secure input disabled the active tap: the pointer comes home rather than \
             the active tap being put back in the way of input the system withholds"
        );
        let mut guard = TapGuard::default();
        for _ in 0..10 {
            assert_eq!(
                guard.on_disabled(TapKind::Listen, Disabled::UserInput, now, Some(&[])),
                OnDisabled::ReEnable,
                "secure input disabled the listen-only tap, which cannot hold input"
            );
        }
    }
}

#[cfg(test)]
mod the_tap_callbacks {
    //! The tap callbacks' logic ([`Core`]) driven with a fake for the taps
    //! and the cursor: no event tap is created and the cursor never moves.

    use super::{
        Bounds, CaptureError, CaptureEvent, Core, Disabled, Grants, Item, Permission, Position,
        ProducerEvent, Seen, Shared, StreamTx, TapCommand, TapKind, Taps, Verdict,
        events_of_interest, mpsc, tap_options,
    };
    use core_graphics::display::CGPoint;
    use core_graphics::event::{CGEventTapOptions, CGEventType};
    use input_event::{Event, KeyboardEvent, PointerEvent};
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tokio::sync::mpsc::{Receiver, UnboundedReceiver};

    /// The bound a callback must return within.
    const BOUND: Duration = Duration::from_millis(10);

    #[derive(Debug, Default)]
    struct TapState {
        listen: bool,
        active: bool,
        installs: usize,
        torn_down: bool,
        refuse: bool,
        reenabled: Vec<TapKind>,
        warps: Vec<(f64, f64)>,
    }

    #[derive(Clone, Default)]
    struct FakeTaps(Arc<Mutex<TapState>>);

    impl FakeTaps {
        fn state(&self) -> std::sync::MutexGuard<'_, TapState> {
            self.0.lock().expect("fake taps")
        }
    }

    impl Taps for FakeTaps {
        fn install_active(&mut self) -> bool {
            let mut s = self.state();
            if s.refuse {
                return false;
            }
            s.active = true;
            s.installs += 1;
            true
        }
        fn remove_active(&mut self) {
            self.state().active = false;
        }
        fn reenable(&mut self, kind: TapKind) {
            self.state().reenabled.push(kind);
        }
        fn tear_down(&mut self) {
            let mut s = self.state();
            s.listen = false;
            s.active = false;
            s.torn_down = true;
        }
        fn warp(&mut self, to: CGPoint) {
            self.state().warps.push((to.x, to.y));
        }
    }

    struct Rig {
        core: Core<FakeTaps>,
        taps: FakeTaps,
        tx: StreamTx,
        stream: UnboundedReceiver<Item>,
        notices: UnboundedReceiver<ProducerEvent>,
        shared: Arc<Mutex<Shared>>,
        grants: Arc<Grants>,
        _recheck: Receiver<()>,
    }

    /// A 1000x800 screen with a peer on its right, and the listen tap in.
    fn rig() -> Rig {
        let mut shared = Shared {
            bounds: Bounds {
                xmin: 0.0,
                xmax: 1000.0,
                ymin: 0.0,
                ymax: 800.0,
            },
            ..Default::default()
        };
        shared.active_clients.insert(Position::Right);
        let shared = Arc::new(Mutex::new(shared));
        let (event_tx, stream) = mpsc::unbounded_channel();
        let tx = StreamTx {
            tx: event_tx,
            depth: Arc::new(AtomicUsize::new(0)),
        };
        let (notify, notices) = mpsc::unbounded_channel();
        let (recheck, _recheck) = mpsc::channel(1);
        let taps = FakeTaps::default();
        taps.state().listen = true;
        let grants = Arc::new(Grants::default());
        let core = Core::new(
            shared.clone(),
            taps.clone(),
            tx.clone(),
            notify,
            recheck,
            grants.clone(),
        );
        Rig {
            core,
            taps,
            tx,
            stream,
            notices,
            shared,
            grants,
            _recheck,
        }
    }

    fn moved(x: f64, dx: f64) -> Seen {
        let mut seen = Seen::new(CGEventType::MouseMoved);
        seen.x = x;
        seen.y = 400.0;
        seen.dx = dx;
        seen
    }

    /// The motion that crosses to the peer on the right.
    fn crossing() -> Seen {
        moved(999.5, 1.0)
    }

    /// The A key (macOS key code 0, evdev 30).
    fn key_a(down: bool) -> Seen {
        let mut seen = Seen::new(if down {
            CGEventType::KeyDown
        } else {
            CGEventType::KeyUp
        });
        seen.keycode = 0;
        seen
    }

    fn disabled(why: Disabled) -> Seen {
        Seen::new(match why {
            Disabled::Timeout => CGEventType::TapDisabledByTimeout,
            Disabled::UserInput => CGEventType::TapDisabledByUserInput,
        })
    }

    fn drain<T>(rx: &mut UnboundedReceiver<T>) -> Vec<T> {
        let mut out = Vec::new();
        while let Ok(item) = rx.try_recv() {
            out.push(item);
        }
        out
    }

    impl Rig {
        fn on(&mut self, kind: TapKind, seen: Seen) -> Verdict {
            self.core.on_event(kind, &seen, Instant::now())
        }
    }

    // LEDGER T2405 | class B | 1 return value (timed): Core::on_event
    #[test]
    fn a_disable_notice_and_local_motion_return_at_once_while_the_lock_is_held() {
        let mut rig = rig();
        let shared = rig.shared.clone();
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let _held = shared.lock().expect("the lock");
            held_tx.send(()).expect("the test waits");
            std::thread::sleep(Duration::from_secs(1));
        });
        held_rx.recv().expect("the lock is held");

        let started = Instant::now();
        let verdict = rig.on(TapKind::Listen, disabled(Disabled::Timeout));
        let disable_took = started.elapsed();
        let started = Instant::now();
        rig.on(TapKind::Listen, crossing());
        let motion_took = started.elapsed();
        holder.join().expect("the holder");

        assert_eq!(verdict, Verdict::Keep);
        assert!(
            disable_took < BOUND && motion_took < BOUND,
            "another thread held the shared lock. A tap callback must not wait for it: \
             the system waits on an active tap's callback for every event. The disable \
             notice took {disable_took:?} and a motion {motion_took:?} (bound {BOUND:?})"
        );
        assert_eq!(
            rig.taps.state().reenabled,
            [TapKind::Listen],
            "the disable notice was acted on without the lock"
        );
    }

    // LEDGER T2406 | class B | 1 items on the stream Core::on_event writes
    #[test]
    fn a_key_while_the_stream_is_far_behind_returns_at_once_and_is_not_lost() {
        let mut rig = rig();
        rig.on(TapKind::Listen, crossing());
        // The daemon side has fallen 10 000 items behind.
        let still = CaptureEvent::Input(Event::Pointer(PointerEvent::Motion {
            time: 0,
            dx: 0.0,
            dy: 0.0,
        }));
        for _ in 0..10_000 {
            rig.tx.send(Ok((Position::Right, still)));
        }
        for _ in 0..100 {
            rig.on(TapKind::Active, moved(999.0, 1.0));
        }
        let started = Instant::now();
        let verdict = rig.on(TapKind::Active, key_a(true));
        let took = started.elapsed();

        assert_eq!(verdict, Verdict::Drop, "the key belongs to the peer");
        assert!(took < BOUND, "the key took {took:?} (bound {BOUND:?})");
        let items = drain(&mut rig.stream);
        let keys: Vec<_> = items
            .iter()
            .filter_map(|item| match item {
                Ok((
                    _,
                    CaptureEvent::Input(Event::Keyboard(KeyboardEvent::Key { key, state, .. })),
                )) => Some((*key, *state)),
                _ => None,
            })
            .collect();
        let moved: f64 = items
            .iter()
            .filter_map(|item| match item {
                Ok((_, CaptureEvent::Input(Event::Pointer(PointerEvent::Motion { dx, .. })))) => {
                    Some(*dx)
                }
                _ => None,
            })
            .sum();
        assert_eq!(
            keys,
            [(30, 1)],
            "the stream was far behind when A went down; the key must still reach it, \
             or the peer never sees it and the up that follows finds nothing held"
        );
        assert_eq!(
            moved, 100.0,
            "motion may be summed while the stream is behind, never lost"
        );
    }

    // LEDGER T2407 | class B | 6 struct state of the fake Taps after Core::on_event / Core::command
    #[test]
    fn the_active_tap_exists_only_from_a_crossing_until_the_pointer_comes_back() {
        let mut rig = rig();
        let active = |rig: &Rig| rig.taps.state().active;

        rig.on(TapKind::Listen, moved(500.0, 1.0));
        assert!(!active(&rig), "the pointer is here: no active tap");

        assert_eq!(rig.on(TapKind::Listen, crossing()), Verdict::Keep);
        assert!(
            active(&rig),
            "the pointer crossed: the active tap takes input"
        );
        assert!(matches!(
            drain(&mut rig.stream).as_slice(),
            [Ok((Position::Right, CaptureEvent::Begin))]
        ));
        assert_eq!(rig.on(TapKind::Active, moved(999.0, 3.0)), Verdict::Drop);
        assert_eq!(
            rig.taps.state().warps.last(),
            Some(&(999.0, 400.0)),
            "the hidden cursor is held at the edge it crossed"
        );

        rig.core.command(TapCommand::Release);
        assert!(!active(&rig), "released: the active tap is removed");
        assert_eq!(
            rig.on(TapKind::Active, moved(999.0, 3.0)),
            Verdict::Keep,
            "an event queued for the removed tap stays on this Mac"
        );

        rig.on(TapKind::Listen, crossing());
        rig.core.command(TapCommand::Destroy(Position::Left));
        assert!(
            active(&rig),
            "another client went away; this crossing goes on"
        );
        rig.core.command(TapCommand::Destroy(Position::Right));
        assert!(!active(&rig), "the client crossed to went away");

        rig.on(TapKind::Listen, crossing());
        assert!(active(&rig));
        drain(&mut rig.stream);
        for _ in 0..3 {
            rig.on(TapKind::Active, disabled(Disabled::Timeout));
        }
        let state = rig.taps.state();
        assert!(
            state.torn_down && !state.active && !state.listen,
            "a fault removes every tap: {state:?}"
        );
        drop(state);
        assert!(
            matches!(
                drain(&mut rig.stream).as_slice(),
                [Err(CaptureError::Interrupted(_))]
            ),
            "the fault ends the stream with an error capture starts again after"
        );
        let notices = drain(&mut rig.notices);
        let grabs = notices
            .iter()
            .filter(|n| matches!(n, ProducerEvent::Grab))
            .count();
        let releases = notices
            .iter()
            .filter(|n| matches!(n, ProducerEvent::Released))
            .count();
        assert_eq!(
            (grabs, releases),
            (3, 3),
            "each crossing hid the cursor once and each end showed it once: {notices:?}"
        );
    }

    // LEDGER T2408 | class B | 1 return value: tap_options, events_of_interest
    #[test]
    fn the_listening_tap_is_listen_only_and_sent_only_motion() {
        assert!(matches!(
            tap_options(TapKind::Listen),
            CGEventTapOptions::ListenOnly
        ));
        assert!(matches!(
            tap_options(TapKind::Active),
            CGEventTapOptions::Default
        ));
        assert!(matches!(
            events_of_interest(TapKind::Listen).as_slice(),
            [CGEventType::MouseMoved]
        ));
    }

    // LEDGER T2409 | class B | 1 items on the stream Core::on_event writes
    #[test]
    fn a_refused_active_tap_ends_capture_naming_accessibility() {
        let mut rig = rig();
        rig.taps.state().refuse = true;
        assert_eq!(rig.on(TapKind::Listen, crossing()), Verdict::Keep);
        let items = drain(&mut rig.stream);
        assert!(
            matches!(
                items.as_slice(),
                [Err(CaptureError::MissingPermissions(missing))]
                    if missing == &[Permission::Accessibility]
            ),
            "macOS refused the active tap at a crossing, which it does without \
             Accessibility: no crossing, and capture ends naming it; got {items:?}"
        );
        assert!(rig.taps.state().torn_down);
    }

    // LEDGER T2410 | class B | 6 fake Taps state + items on the stream via Core::on_event
    #[test]
    fn a_disable_after_the_check_found_accessibility_gone_removes_every_tap() {
        let mut rig = rig();
        rig.on(TapKind::Listen, crossing());
        drain(&mut rig.stream);
        rig.grants.record(&[Permission::Accessibility]);
        rig.on(TapKind::Active, disabled(Disabled::Timeout));
        let state = rig.taps.state();
        assert!(
            state.torn_down && !state.active && state.reenabled.is_empty(),
            "the last check found Accessibility gone: no tap may be re-enabled: {state:?}"
        );
        drop(state);
        let items = drain(&mut rig.stream);
        assert!(
            matches!(
                items.as_slice(),
                [Err(CaptureError::MissingPermissions(missing))]
                    if missing == &[Permission::Accessibility]
            ),
            "got {items:?}"
        );
    }
}
