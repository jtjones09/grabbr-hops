use async_trait::async_trait;
use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
};

use input_event::{Event, KeyboardEvent, PointerEvent};

pub use self::error::{EmulationCreationError, EmulationError, InputEmulationError};

#[cfg(windows)]
mod windows;

#[cfg(x11)]
mod x11;

#[cfg(wlroots)]
mod wlroots;

#[cfg(rdp)]
mod xdg_desktop_portal;

#[cfg(libei)]
mod libei;

#[cfg(target_os = "macos")]
mod macos;

/// fallback input emulation (logs events)
mod dummy;
mod error;

/// Records what would have been injected. Test builds only; see the feature.
#[cfg(feature = "recording")]
pub mod recording;

pub type EmulationHandle = u64;

/// A screen edge of the receiving desktop, as seen by input emulation.
/// Emitted by [`InputEmulation::take_edge_push`] when a backend's adaptive-edge
/// detector concludes the remote-controlled cursor was *deliberately pushed*
/// past that edge (accumulated blocked outward motion, not a position
/// tripwire — the injected cursor is clamped on-screen and can never actually
/// occupy the barrier coordinate).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EdgeSide {
    Left,
    Right,
    Top,
    Bottom,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Backend {
    #[cfg(wlroots)]
    Wlroots,
    #[cfg(libei)]
    Libei,
    #[cfg(rdp)]
    Xdp,
    #[cfg(x11)]
    X11,
    #[cfg(windows)]
    Windows,
    #[cfg(target_os = "macos")]
    MacOs,
    Dummy,
    /// Never picked by the fallback list and not nameable from a config file:
    /// only a test holding a [`recording::Recording`] can select it.
    #[cfg(feature = "recording")]
    Recording(recording::RecordingId),
}

impl Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(wlroots)]
            Backend::Wlroots => write!(f, "wlroots"),
            #[cfg(libei)]
            Backend::Libei => write!(f, "libei"),
            #[cfg(rdp)]
            Backend::Xdp => write!(f, "xdg-desktop-portal"),
            #[cfg(x11)]
            Backend::X11 => write!(f, "X11"),
            #[cfg(windows)]
            Backend::Windows => write!(f, "windows"),
            #[cfg(target_os = "macos")]
            Backend::MacOs => write!(f, "macos"),
            Backend::Dummy => write!(f, "dummy"),
            #[cfg(feature = "recording")]
            Backend::Recording(_) => write!(f, "recording"),
        }
    }
}

pub struct InputEmulation {
    /// The backend actually selected. `new()` falls back down a list, so this is
    /// NOT necessarily what was asked for — and a fallback to `Dummy` silently
    /// discards every event, which the caller must be able to notice.
    backend: Backend,
    emulation: Box<dyn Emulation>,
    handles: HashSet<EmulationHandle>,
    pressed_keys: HashMap<EmulationHandle, HashSet<u32>>,
    /// Buttons each handle pressed that no handle has released since, so
    /// teardown can release them. Without this a peer that dropped mid-drag
    /// left the button down on this machine (#89).
    pressed_buttons: HashMap<EmulationHandle, HashSet<u32>>,
}

impl InputEmulation {
    async fn with_backend(backend: Backend) -> Result<InputEmulation, EmulationCreationError> {
        let emulation: Box<dyn Emulation> = match backend {
            #[cfg(wlroots)]
            Backend::Wlroots => Box::new(wlroots::WlrootsEmulation::new()?),
            #[cfg(libei)]
            Backend::Libei => Box::new(libei::LibeiEmulation::new().await?),
            #[cfg(x11)]
            Backend::X11 => Box::new(x11::X11Emulation::new()?),
            #[cfg(rdp)]
            Backend::Xdp => Box::new(xdg_desktop_portal::DesktopPortalEmulation::new().await?),
            #[cfg(windows)]
            Backend::Windows => Box::new(windows::WindowsEmulation::new()?),
            #[cfg(target_os = "macos")]
            Backend::MacOs => Box::new(macos::MacOSEmulation::new()?),
            Backend::Dummy => Box::new(dummy::DummyEmulation::new()),
            #[cfg(feature = "recording")]
            Backend::Recording(id) => Box::new(recording::RecordingEmulation::new(id)?),
        };
        Ok(Self {
            backend,
            emulation,
            handles: HashSet::new(),
            pressed_keys: HashMap::new(),
            pressed_buttons: HashMap::new(),
        })
    }

    /// Which backend is actually in use. `Backend::Dummy` means input is being
    /// accepted and thrown away.
    pub fn backend(&self) -> Backend {
        self.backend
    }

    pub async fn new(backend: Option<Backend>) -> Result<InputEmulation, EmulationCreationError> {
        if let Some(backend) = backend {
            let b = Self::with_backend(backend).await;
            if b.is_ok() {
                log::info!("using emulation backend: {backend}");
            }
            return b;
        }

        for backend in [
            #[cfg(wlroots)]
            Backend::Wlroots,
            #[cfg(libei)]
            Backend::Libei,
            #[cfg(rdp)]
            Backend::Xdp,
            #[cfg(x11)]
            Backend::X11,
            #[cfg(windows)]
            Backend::Windows,
            #[cfg(target_os = "macos")]
            Backend::MacOs,
            Backend::Dummy,
        ] {
            match Self::with_backend(backend).await {
                Ok(b) => {
                    log::info!("using emulation backend: {backend}");
                    return Ok(b);
                }
                Err(e) if e.cancelled_by_user() => return Err(e),
                Err(e) => log::warn!("{e}"),
            }
        }

        Err(EmulationCreationError::NoAvailableBackend)
    }

    pub async fn consume(
        &mut self,
        event: Event,
        handle: EmulationHandle,
    ) -> Result<(), EmulationError> {
        match event {
            Event::Keyboard(KeyboardEvent::Key { key, state, .. }) => {
                // prevent double pressed / released keys
                if self.update_pressed_keys(handle, key, state) {
                    self.emulation.consume(event, handle).await?;
                }
                Ok(())
            }
            Event::Pointer(PointerEvent::Button { button, state, .. }) => {
                // Tracked, not filtered: every button event still reaches the
                // backend exactly as before. The sets only say what teardown
                // has to release.
                if state == 0 {
                    // The machine has one of each button, so this up lets go of
                    // it for every peer, not only the one that sent it. A peer
                    // still listed as holding it would inject a second up at its
                    // teardown, into whatever holds the button by then: another
                    // peer's drag or the local user's. That happens when a
                    // sender reconnects from a new port and lets go, or clicks,
                    // before the watchdog retires its old connection.
                    for pressed in self.pressed_buttons.values_mut() {
                        pressed.remove(&button);
                    }
                } else if let Some(pressed) = self.pressed_buttons.get_mut(&handle) {
                    pressed.insert(button);
                }
                self.emulation.consume(event, handle).await
            }
            _ => self.emulation.consume(event, handle).await,
        }
    }

    /// Take the pending adaptive-edge signal, if the backend detected one
    /// while consuming motion events: the remote-controlled cursor was
    /// deliberately pushed past the returned edge. Poll after [`Self::consume`];
    /// returns at most one signal, then resets.
    pub fn take_edge_push(&mut self) -> Option<EdgeSide> {
        self.emulation.take_edge_push()
    }

    pub async fn create(&mut self, handle: EmulationHandle) -> bool {
        if self.handles.insert(handle) {
            self.pressed_keys.insert(handle, HashSet::new());
            self.pressed_buttons.insert(handle, HashSet::new());
            self.emulation.create(handle).await;
            true
        } else {
            false
        }
    }

    pub async fn destroy(&mut self, handle: EmulationHandle) {
        let _ = self.release_held(handle).await;
        if self.handles.remove(&handle) {
            self.pressed_keys.remove(&handle);
            self.pressed_buttons.remove(&handle);
            self.emulation.destroy(handle).await
        }
    }

    pub async fn terminate(&mut self) {
        for handle in self.handles.iter().cloned().collect::<Vec<_>>() {
            self.destroy(handle).await
        }
        self.emulation.terminate().await
    }

    /// Release every button and key `handle` holds, then reset modifiers.
    ///
    /// Every teardown funnels through here via [`Self::destroy`]: a peer's
    /// Leave, the watchdog after a dropped link, shutdown, and the end of an
    /// emulation session. Buttons go first, which is the order a person lets
    /// go of a modifier-drag, so the drop keeps the modifiers it was made with.
    ///
    /// A release that fails does not stop the rest. Returning at the first
    /// error left everything after it held, which is the defect this exists to
    /// prevent. The first error is returned.
    pub async fn release_held(&mut self, handle: EmulationHandle) -> Result<(), EmulationError> {
        let mut first_error = None;

        let buttons = self
            .pressed_buttons
            .get_mut(&handle)
            .map(|b| b.drain().collect::<Vec<_>>())
            .unwrap_or_default();
        for button in buttons {
            // The machine has one left button however many peers press it. If
            // another peer still holds this one, letting go here would end that
            // peer's drag; its own button-up or teardown releases it instead.
            if self
                .pressed_buttons
                .iter()
                .any(|(other, held)| *other != handle && held.contains(&button))
            {
                log::debug!("not releasing mouse button {button:#x}: another peer holds it");
                continue;
            }
            log::warn!("releasing stuck mouse button: {button:#x}");
            let event = Event::Pointer(PointerEvent::Button {
                time: 0,
                button,
                state: 0,
            });
            if let Err(e) = self.emulation.consume(event, handle).await {
                first_error.get_or_insert(e);
            }
        }

        let keys = self
            .pressed_keys
            .get_mut(&handle)
            .map(|k| k.drain().collect::<Vec<_>>())
            .unwrap_or_default();
        for key in keys {
            let event = Event::Keyboard(KeyboardEvent::Key {
                time: 0,
                key,
                state: 0,
            });
            if let Err(e) = self.emulation.consume(event, handle).await {
                first_error.get_or_insert(e);
            }
            if let Ok(key) = input_event::scancode::Linux::try_from(key) {
                log::warn!("releasing stuck key: {key:?}");
            }
        }

        let event = Event::Keyboard(KeyboardEvent::Modifiers {
            depressed: 0,
            latched: 0,
            locked: 0,
            group: 0,
        });
        if let Err(e) = self.emulation.consume(event, handle).await {
            first_error.get_or_insert(e);
        }

        match first_error {
            None => Ok(()),
            Some(e) => Err(e),
        }
    }

    pub fn has_pressed_keys(&self, handle: EmulationHandle) -> bool {
        self.pressed_keys
            .get(&handle)
            .is_some_and(|p| !p.is_empty())
    }

    /// update the pressed_keys for the given handle
    /// returns whether the event should be processed
    fn update_pressed_keys(&mut self, handle: EmulationHandle, key: u32, state: u8) -> bool {
        let Some(pressed_keys) = self.pressed_keys.get_mut(&handle) else {
            return false;
        };

        if state == 0 {
            // currently pressed => can release
            pressed_keys.remove(&key)
        } else {
            // currently not pressed => can press
            pressed_keys.insert(key)
        }
    }
}

#[async_trait]
trait Emulation: Send {
    async fn consume(
        &mut self,
        event: Event,
        handle: EmulationHandle,
    ) -> Result<(), EmulationError>;
    async fn create(&mut self, handle: EmulationHandle);
    async fn destroy(&mut self, handle: EmulationHandle);
    async fn terminate(&mut self);
    /// Adaptive-edge signal (see [`InputEmulation::take_edge_push`]). Backends
    /// without a detector keep the default: never signals.
    fn take_edge_push(&mut self) -> Option<EdgeSide> {
        None
    }
}
