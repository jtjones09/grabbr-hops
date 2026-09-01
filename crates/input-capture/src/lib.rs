use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt::Display,
    mem::swap,
    task::{Poll, ready},
};

use async_trait::async_trait;
use futures::StreamExt;
use futures_core::Stream;

use input_event::{Event, KeyboardEvent, scancode};

pub use error::{CaptureCreationError, CaptureError, InputCaptureError};

pub mod error;

#[cfg(libei)]
mod libei;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(layer_shell)]
mod layer_shell;

#[cfg(windows)]
mod windows;

#[cfg(x11)]
mod x11;

/// fallback input capture (does not produce events)
mod dummy;

pub type CaptureHandle = u64;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum CaptureEvent {
    /// capture on this capture handle is now active
    Begin,
    /// input event coming from capture handle
    Input(Event),
}

impl Display for CaptureEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaptureEvent::Begin => write!(f, "begin capture"),
            CaptureEvent::Input(e) => write!(f, "{e}"),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum Position {
    Left,
    Right,
    Top,
    Bottom,
}

impl Position {
    pub fn opposite(&self) -> Self {
        match self {
            Position::Left => Self::Right,
            Position::Right => Self::Left,
            Position::Top => Self::Bottom,
            Position::Bottom => Self::Top,
        }
    }
}

impl Display for Position {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pos = match self {
            Position::Left => "left",
            Position::Right => "right",
            Position::Top => "top",
            Position::Bottom => "bottom",
        };
        write!(f, "{pos}")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Backend {
    #[cfg(libei)]
    InputCapturePortal,
    #[cfg(layer_shell)]
    LayerShell,
    #[cfg(x11)]
    X11,
    #[cfg(windows)]
    Windows,
    #[cfg(target_os = "macos")]
    MacOs,
    Dummy,
}

impl Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(libei)]
            Backend::InputCapturePortal => write!(f, "input-capture-portal"),
            #[cfg(layer_shell)]
            Backend::LayerShell => write!(f, "layer-shell"),
            #[cfg(x11)]
            Backend::X11 => write!(f, "X11"),
            #[cfg(windows)]
            Backend::Windows => write!(f, "windows"),
            #[cfg(target_os = "macos")]
            Backend::MacOs => write!(f, "MacOS"),
            Backend::Dummy => write!(f, "dummy"),
        }
    }
}

pub struct InputCapture {
    /// capture backend
    capture: Box<dyn Capture>,
    /// keys pressed by active capture
    pressed_keys: HashSet<scancode::Linux>,
    /// map from position to ids
    position_map: HashMap<Position, Vec<CaptureHandle>>,
    /// map from id to position
    id_map: HashMap<CaptureHandle, Position>,
    /// pending events
    pending: VecDeque<(CaptureHandle, CaptureEvent)>,
}

impl InputCapture {
    /// create a new client with the given id
    pub async fn create(&mut self, id: CaptureHandle, pos: Position) -> Result<(), CaptureError> {
        assert!(!self.id_map.contains_key(&id));

        self.id_map.insert(id, pos);

        if let Some(v) = self.position_map.get_mut(&pos) {
            v.push(id);
            Ok(())
        } else {
            self.position_map.insert(pos, vec![id]);
            self.capture.create(pos).await
        }
    }

    /// destroy the client with the given id, if it exists
    pub async fn destroy(&mut self, id: CaptureHandle) -> Result<(), CaptureError> {
        // Drop anything already queued FOR THIS HANDLE. When two handles share a
        // position — the ordinary bidirectional setup, an outgoing client and an
        // inbound peer on the same edge — `poll_next` fans one backend event into
        // `pending`, one copy per handle, and `pending` is drained ahead of the
        // backend. Destroying only cleared `id_map` and `position_map`, so a copy
        // for a handle the consumer had ALREADY forgotten still came back out,
        // and the consumer looks handles up with `.expect()`. With
        // `panic = "abort"` that ended the process (#63).
        self.pending.retain(|&(queued, _)| queued != id);

        // A handle we do not know is not an error worth aborting over. It is the
        // shape of a double-destroy, and `update_incoming` does
        // remove-then-create back to back on the hot path.
        let Some(pos) = self.id_map.remove(&id) else {
            log::debug!("destroy: no capture {id} — already gone");
            return Ok(());
        };

        log::debug!("destroying capture {id} @ {pos}");
        let Some(remaining) = self.position_map.get_mut(&pos) else {
            log::debug!("destroy: no ids registered @ {pos}");
            return Ok(());
        };
        remaining.retain(|&i| i != id);

        log::debug!("remaining ids @ {pos}: {remaining:?}");
        if remaining.is_empty() {
            log::debug!("destroying capture @ {pos} - no remaining ids");
            self.position_map.remove(&pos);
            self.capture.destroy(pos).await?;
        }
        Ok(())
    }

    /// release mouse
    pub async fn release(&mut self) -> Result<(), CaptureError> {
        self.pressed_keys.clear();
        self.capture.release().await
    }

    /// Drain and return every key the capture has forwarded as
    /// down-but-not-up. The caller is expected to synthesize key-up
    /// events to the remote peer for each — otherwise the peer
    /// retains phantom-held keys after capture is released. The
    /// canonical case is the release-bind chord
    /// (Ctrl+Shift+Alt+Meta): the down events were sent while
    /// capture was active, but the matching up events arrive after
    /// the local tap has flipped to passthrough and never reach
    /// the peer.
    pub fn take_pressed_keys(&mut self) -> HashSet<scancode::Linux> {
        std::mem::take(&mut self.pressed_keys)
    }

    /// destroy the input capture
    pub async fn terminate(&mut self) -> Result<(), CaptureError> {
        self.capture.terminate().await
    }

    /// creates a new [`InputCapture`]
    pub async fn new(backend: Option<Backend>) -> Result<Self, CaptureCreationError> {
        let capture = create(backend).await?;
        Ok(Self {
            capture,
            id_map: Default::default(),
            pending: Default::default(),
            position_map: Default::default(),
            pressed_keys: HashSet::new(),
        })
    }

    /// check whether the given keys are pressed
    pub fn keys_pressed(&self, keys: &[scancode::Linux]) -> bool {
        keys.iter().all(|k| self.pressed_keys.contains(k))
    }

    fn update_pressed_keys(&mut self, key: u32, state: u8) {
        if let Ok(scancode) = scancode::Linux::try_from(key) {
            // NOT log::debug!. Key identity goes to its own opt-in, time-boxed
            // file so that raising the log level to look at something else does
            // not start recording what the user types (#117).
            input_event::keylog::key(key, state, &format!("{scancode:?}"));
            match state {
                1 => self.pressed_keys.insert(scancode),
                _ => self.pressed_keys.remove(&scancode),
            };
        }
    }
}

impl Stream for InputCapture {
    type Item = Result<(CaptureHandle, CaptureEvent), CaptureError>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        if let Some(e) = self.pending.pop_front() {
            return Poll::Ready(Some(Ok(e)));
        }

        // ready
        let event = ready!(self.capture.poll_next_unpin(cx));

        // stream closed
        let event = match event {
            Some(e) => e,
            None => return Poll::Ready(None),
        };

        // error occurred
        let (pos, event) = match event {
            Ok(e) => e,
            Err(e) => return Poll::Ready(Some(Err(e))),
        };

        // handle key presses
        if let CaptureEvent::Input(Event::Keyboard(KeyboardEvent::Key { key, state, .. })) = event {
            self.update_pressed_keys(key, state);
        }

        let len = self
            .position_map
            .get(&pos)
            .map(|ids| ids.len())
            .unwrap_or(0);

        match len {
            0 => Poll::Pending,
            1 => Poll::Ready(Some(Ok((
                self.position_map.get(&pos).expect("no id")[0],
                event,
            )))),
            _ => {
                let mut position_map = HashMap::new();
                swap(&mut self.position_map, &mut position_map);
                {
                    for &id in position_map.get(&pos).expect("position") {
                        self.pending.push_back((id, event));
                    }
                }
                swap(&mut self.position_map, &mut position_map);

                Poll::Ready(Some(Ok(self.pending.pop_front().expect("event"))))
            }
        }
    }
}

/// The `(?Send)` is load-bearing, not a style choice — do NOT "tidy" it back to
/// a bare `#[async_trait]`.
///
/// A bare `#[async_trait]` boxes every method as `Pin<Box<dyn Future + Send>>`.
/// `LayerShellInputCapture` cannot satisfy that: it transitively owns a
/// wayland `ReadEventsGuard`, which holds a `*mut wl_display` and is `!Send` on
/// purpose, because libwayland requires prepare_read/read to happen on one
/// thread. That made the DEFAULT feature set fail to compile on Linux — a bare
/// `cargo build` or `cargo install --git` — and nothing noticed for months
/// because no CI job compiled it (see #38, and #8 for the job that finally did).
///
/// The `Send` bound was never doing any work. `Box<dyn Capture>` below carries
/// no `+ Send`, so `InputCapture` is already `!Send`; the whole capture stack
/// runs on one current_thread runtime inside a `LocalSet` (src/main.rs), is
/// spawned with `spawn_local` (src/capture.rs), and several backends call
/// `spawn_local` in their own method bodies — which panics outside a LocalSet.
/// Single-threaded execution is a hard runtime requirement here; `?Send` just
/// makes the type system agree with what the code already demanded.
#[async_trait(?Send)]
trait Capture: Stream<Item = Result<(Position, CaptureEvent), CaptureError>> + Unpin {
    /// create a new client with the given id
    async fn create(&mut self, pos: Position) -> Result<(), CaptureError>;

    /// destroy the client with the given id, if it exists
    async fn destroy(&mut self, pos: Position) -> Result<(), CaptureError>;

    /// release mouse
    async fn release(&mut self) -> Result<(), CaptureError>;

    /// destroy the input capture
    async fn terminate(&mut self) -> Result<(), CaptureError>;
}

async fn create_backend(
    backend: Backend,
) -> Result<
    Box<dyn Capture<Item = Result<(Position, CaptureEvent), CaptureError>>>,
    CaptureCreationError,
> {
    match backend {
        #[cfg(libei)]
        Backend::InputCapturePortal => Ok(Box::new(libei::LibeiInputCapture::new().await?)),
        #[cfg(layer_shell)]
        Backend::LayerShell => Ok(Box::new(layer_shell::LayerShellInputCapture::new()?)),
        #[cfg(x11)]
        Backend::X11 => Ok(Box::new(x11::X11InputCapture::new()?)),
        #[cfg(windows)]
        Backend::Windows => Ok(Box::new(windows::WindowsInputCapture::new())),
        #[cfg(target_os = "macos")]
        Backend::MacOs => Ok(Box::new(macos::MacOSInputCapture::new().await?)),
        Backend::Dummy => Ok(Box::new(dummy::DummyInputCapture::new())),
    }
}

async fn create(
    backend: Option<Backend>,
) -> Result<
    Box<dyn Capture<Item = Result<(Position, CaptureEvent), CaptureError>>>,
    CaptureCreationError,
> {
    if let Some(backend) = backend {
        let b = create_backend(backend).await;
        if b.is_ok() {
            log::info!("using capture backend: {backend}");
        }
        return b;
    }

    for backend in [
        #[cfg(libei)]
        Backend::InputCapturePortal,
        #[cfg(layer_shell)]
        Backend::LayerShell,
        #[cfg(x11)]
        Backend::X11,
        #[cfg(windows)]
        Backend::Windows,
        #[cfg(target_os = "macos")]
        Backend::MacOs,
    ] {
        match create_backend(backend).await {
            Ok(b) => {
                log::info!("using capture backend: {backend}");
                return Ok(b);
            }
            Err(e) if e.cancelled_by_user() => return Err(e),
            Err(e) => log::warn!("{backend} input capture backend unavailable: {e}"),
        }
    }
    Err(CaptureCreationError::NoAvailableBackend)
}

#[cfg(test)]
mod destroy_purges_pending {
    //! `destroy` must forget a handle's QUEUED events, not just its registration.
    //!
    //! When two handles share a position — an outgoing client and an inbound
    //! peer on the same edge, the ordinary bidirectional setup — `poll_next`
    //! fans one backend event into `pending`, one copy per handle, and `pending`
    //! is drained ahead of the backend. `destroy` cleared `id_map` and
    //! `position_map` and left `pending` alone, so a copy for a handle the
    //! consumer had already forgotten still came back out of the stream. The
    //! consumer looks handles up by `.expect()`, and with `panic = "abort"` in
    //! the release profile that ended the process outright — stranding every
    //! key and button any peer was holding (#63).
    //!
    //! This is the first test in this crate. It is possible because
    //! `Backend::Dummy` needs no display, no compositor and no permissions.

    use super::*;

    async fn capture() -> InputCapture {
        InputCapture::new(Some(Backend::Dummy))
            .await
            .expect("the dummy backend needs no display")
    }

    #[tokio::test]
    async fn a_destroyed_handle_leaves_no_queued_events_behind() {
        let mut c = capture().await;
        c.create(1, Position::Left).await.expect("create 1");
        c.create(2, Position::Left).await.expect("create 2");

        // Exactly what the fan-out does when two handles share a position.
        c.pending.push_back((1, CaptureEvent::Begin));
        c.pending.push_back((2, CaptureEvent::Begin));

        c.destroy(2).await.expect("destroy 2");

        assert!(
            !c.id_map.contains_key(&2),
            "precondition: the handle is deregistered"
        );
        assert!(
            c.pending.iter().all(|&(h, _)| h != 2),
            "a destroyed handle must leave nothing queued — the consumer has already \
             forgotten it and looks handles up fallibly"
        );
        assert!(
            c.pending.iter().any(|&(h, _)| h == 1),
            "and the surviving handle's events must be untouched"
        );
    }

    #[tokio::test]
    async fn destroying_an_unknown_handle_is_not_fatal() {
        // `update_incoming` does remove-then-create back to back on the hot path,
        // so a double-destroy is a shape that actually occurs. It used to
        // `.expect("no position for this handle")`.
        let mut c = capture().await;
        c.create(1, Position::Left).await.expect("create");
        c.destroy(1).await.expect("first destroy");
        c.destroy(1)
            .await
            .expect("a second destroy must be a no-op, not an abort");
        c.destroy(99)
            .await
            .expect("an unknown handle must be a no-op, not an abort");
    }

    #[tokio::test]
    async fn destroying_one_of_two_leaves_the_position_alive() {
        let mut c = capture().await;
        c.create(1, Position::Right).await.expect("create 1");
        c.create(2, Position::Right).await.expect("create 2");
        c.destroy(1).await.expect("destroy 1");
        assert_eq!(
            c.position_map.get(&Position::Right).map(|v| v.as_slice()),
            Some([2].as_slice()),
            "the other handle keeps the position registered"
        );
    }
}
