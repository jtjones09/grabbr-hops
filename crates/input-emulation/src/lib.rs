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

/// How the system behind a backend counts one button pressed through several
/// emulation handles. It depends on whether the backend gives each handle a
/// device of its own, so every backend states its own next to its injection
/// code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ButtonScope {
    /// Every handle injects through the same device, so a button is simply
    /// down or up. The first up lets go of it for every peer.
    Machine,
    /// Each handle injects through a device of its own, and presses are
    /// counted across devices: applications see the release only once every
    /// press has been matched by an up.
    PerHandle,
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
    /// Buttons each handle holds, so teardown can release them. Without this
    /// a peer that dropped mid-drag left the button down on this machine
    /// (#89). What counts as held, and which handle an up goes out on,
    /// follows `button_scope`; see `machine_button` and `per_handle_button`.
    ///
    /// This is bookkeeping, not what the OS saw: a release the backend
    /// accepted but did not deliver is not repeated when the peer's own up
    /// arrives later.
    pressed_buttons: HashMap<EmulationHandle, HashSet<u32>>,
    /// The backend's own answer, read once: it does not change.
    button_scope: ButtonScope,
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
            button_scope: emulation.button_scope(),
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
            Event::Pointer(PointerEvent::Button { button, state, .. }) => match self.button_scope {
                ButtonScope::Machine => self.machine_button(event, handle, button, state).await,
                ButtonScope::PerHandle => {
                    self.per_handle_button(event, handle, button, state).await
                }
            },
            _ => self.emulation.consume(event, handle).await,
        }
    }

    /// A button event where every handle shares one device.
    ///
    /// A down is recorded for the handle and passed on. An up is passed on
    /// only while some handle holds the button, and clears it for all of
    /// them, so a pressed button gets at most one up however many peers
    /// pressed it.
    async fn machine_button(
        &mut self,
        event: Event,
        handle: EmulationHandle,
        button: u32,
        state: u32,
    ) -> Result<(), EmulationError> {
        if state != 0 {
            if let Some(pressed) = self.pressed_buttons.get_mut(&handle) {
                pressed.insert(button);
            }
            return self.emulation.consume(event, handle).await;
        }
        // An up for a button no peer holds has nothing to let go of. This
        // machine already released it, at a teardown or through another
        // peer's up, or never had it pressed. A link that stalls past the
        // watchdog and then recovers delivers such an up. Passed on, it would
        // end whatever holds the button by then: another peer's drag or the
        // local user's.
        if !self.pressed_buttons.values().any(|p| p.contains(&button)) {
            log::debug!("dropping mouse button-up {button:#x}: no peer holds it");
            return Ok(());
        }
        // The device has one of each button, so this up lets go of it for
        // every peer, not only the one that sent it. A peer still listed as
        // holding it would inject a second up at its teardown. That happens
        // when a sender reconnects from a new port and lets go, or clicks,
        // before the watchdog retires its old connection.
        for pressed in self.pressed_buttons.values_mut() {
            pressed.remove(&button);
        }
        self.emulation.consume(event, handle).await
    }

    /// A button event where each handle has a device of its own and presses
    /// are counted across devices.
    ///
    /// Every down a handle's device received gets exactly one up through that
    /// same device: the peer's own up, or one at its teardown. Dropping an up
    /// because another peer already let go, as `machine_button` does, would
    /// leave the count above zero and the button held for applications.
    async fn per_handle_button(
        &mut self,
        event: Event,
        handle: EmulationHandle,
        button: u32,
        state: u32,
    ) -> Result<(), EmulationError> {
        if state != 0 {
            if let Some(pressed) = self.pressed_buttons.get_mut(&handle) {
                // A device holds a button once, and releases it once when it
                // is destroyed. A second down from it would be counted with
                // no up to match it.
                if !pressed.insert(button) {
                    log::debug!("dropping repeated mouse button-down {button:#x}");
                    return Ok(());
                }
            }
            return self.emulation.consume(event, handle).await;
        }
        // The up goes out on a device that holds the button: the sender's
        // own, or else the lowest-numbered handle that does. A sender that
        // reconnected from a new port lets go on the new connection while
        // its old one still holds the press.
        let holder = if self
            .pressed_buttons
            .get(&handle)
            .is_some_and(|p| p.contains(&button))
        {
            Some(handle)
        } else {
            self.pressed_buttons
                .iter()
                .filter(|(_, p)| p.contains(&button))
                .map(|(&h, _)| h)
                .min()
        };
        // As in `machine_button`: nothing holds it, so there is nothing to
        // let go of, and passing it on would end someone else's press.
        let Some(holder) = holder else {
            log::debug!("dropping mouse button-up {button:#x}: no peer holds it");
            return Ok(());
        };
        if let Some(pressed) = self.pressed_buttons.get_mut(&holder) {
            pressed.remove(&button);
        }
        self.emulation.consume(event, holder).await
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
            // Where every peer shares one device, it has one left button
            // however many peers press it. If another peer still holds this
            // one, letting go here would end that peer's drag; its own
            // button-up or teardown releases it instead. Where each peer has
            // its own device, this device's press is counted, so it is
            // released here whoever else holds the button.
            if self.button_scope == ButtonScope::Machine
                && self
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
    /// How the system behind this backend counts a button pressed through
    /// several handles. No default: a backend that gives handles their own
    /// devices and one that shares a device need opposite release rules, so
    /// each backend states which it is, with its reason, where it injects.
    fn button_scope(&self) -> ButtonScope;
    /// Adaptive-edge signal (see [`InputEmulation::take_edge_push`]). Backends
    /// without a detector keep the default: never signals.
    fn take_edge_push(&mut self) -> Option<EdgeSide> {
        None
    }
}
