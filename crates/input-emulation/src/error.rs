#[derive(Debug, Error)]
pub enum InputEmulationError {
    #[error("error creating input-emulation: `{0}`")]
    Create(#[from] EmulationCreationError),
    #[error("error emulating input: `{0}`")]
    Emulate(#[from] EmulationError),
    /// Every real backend failed and selection fell through to `Dummy`, which
    /// accepts every event and discards it. Refused rather than run, because a
    /// KVM that cannot move a cursor has no valid non-test use and the UI
    /// otherwise reports a healthy connection while nothing happens.
    #[error(
        "no usable input-emulation backend — every real backend was unavailable and \
         selection fell through to `dummy`, which discards all input. Refusing to run. \
         On Linux this usually means the binary was built without the backend features \
         (see release.yml). Set HOPS_ALLOW_DUMMY=1 to override for testing."
    )]
    NoUsableBackend,
    /// As [`Self::NoUsableBackend`], and the real backend that fell through
    /// failed because the system withholds these permissions. What the
    /// person can change, where a bare refusal named nothing.
    #[error(
        "input emulation cannot start: the system does not grant hops {}, and \
         selection fell through to `dummy`, which discards all input. Refusing to run. \
         Set HOPS_ALLOW_DUMMY=1 to override for testing.",
        .0.iter().map(ToString::to_string).collect::<Vec<_>>().join(" and ")
    )]
    Withheld(Vec<Permission>),
}

#[cfg(any(libei, rdp))]
use ashpd::{Error::Response, desktop::ResponseError};
use std::io;
use thiserror::Error;

#[cfg(wlroots)]
use wayland_client::{
    ConnectError, DispatchError,
    backend::WaylandError,
    globals::{BindError, GlobalError},
};

#[derive(Debug, Error)]
pub enum EmulationError {
    #[error("event stream closed")]
    EndOfStream,
    #[cfg(libei)]
    #[error("libei error: `{0}`")]
    Libei(#[from] reis::Error),
    #[cfg(wlroots)]
    #[error("wayland error: `{0}`")]
    Wayland(#[from] wayland_client::backend::WaylandError),
    #[cfg(any(rdp, libei))]
    #[error("xdg-desktop-portal: `{0}`")]
    Ashpd(#[from] ashpd::Error),
    #[error("io error: `{0}`")]
    Io(#[from] io::Error),
}

#[derive(Debug, Error)]
pub enum EmulationCreationError {
    #[cfg(wlroots)]
    #[error("wlroots backend: `{0}`")]
    Wlroots(#[from] WlrootsEmulationCreationError),
    #[cfg(libei)]
    #[error("libei backend: `{0}`")]
    Libei(#[from] LibeiEmulationCreationError),
    #[cfg(rdp)]
    #[error("xdg-desktop-portal: `{0}`")]
    Xdp(#[from] XdpEmulationCreationError),
    #[cfg(x11)]
    #[error("x11: `{0}`")]
    X11(#[from] X11EmulationCreationError),
    #[cfg(target_os = "macos")]
    #[error("macos: `{0}`")]
    MacOs(#[from] MacOSEmulationCreationError),
    #[cfg(windows)]
    #[error("windows: `{0}`")]
    Windows(#[from] WindowsEmulationCreationError),
    #[cfg(feature = "recording")]
    #[error("recording: `{0}`")]
    Recording(#[from] crate::recording::RecordingEmulationCreationError),
    #[error("capture error")]
    NoAvailableBackend,
}

/// A system permission emulation needs and was not granted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permission {
    /// macOS: Privacy & Security → Accessibility, which also grants posting
    /// input events.
    Accessibility,
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Accessibility => "Accessibility",
        })
    }
}

impl InputEmulationError {
    /// The permissions whose absence kept emulation from starting, when that
    /// is why.
    pub fn missing_permissions(&self) -> Option<&[Permission]> {
        match self {
            Self::Create(e) => e.missing_permissions(),
            Self::Withheld(missing) => Some(missing),
            _ => None,
        }
    }
}

impl EmulationCreationError {
    /// The permissions whose absence kept the backend from starting, when
    /// that is why.
    pub fn missing_permissions(&self) -> Option<&'static [Permission]> {
        #[cfg(target_os = "macos")]
        if let Self::MacOs(
            MacOSEmulationCreationError::AccessibilityPermission
            | MacOSEmulationCreationError::InputControlPermission,
        ) = self
        {
            return Some(&[Permission::Accessibility]);
        }
        #[cfg(feature = "recording")]
        if let Self::Recording(crate::recording::RecordingEmulationCreationError::Refused) = self {
            return Some(&[Permission::Accessibility]);
        }
        None
    }

    /// request was intentionally denied by the user
    pub(crate) fn cancelled_by_user(&self) -> bool {
        #[cfg(libei)]
        if matches!(
            self,
            EmulationCreationError::Libei(LibeiEmulationCreationError::Ashpd(Response(
                ResponseError::Cancelled,
            )))
        ) {
            return true;
        }
        #[cfg(rdp)]
        if matches!(
            self,
            EmulationCreationError::Xdp(XdpEmulationCreationError::Ashpd(Response(
                ResponseError::Cancelled,
            )))
        ) {
            return true;
        }
        false
    }
}

#[cfg(wlroots)]
#[derive(Debug, Error)]
pub enum WlrootsEmulationCreationError {
    #[error(transparent)]
    Connect(#[from] ConnectError),
    #[error(transparent)]
    Global(#[from] GlobalError),
    #[error(transparent)]
    Wayland(#[from] WaylandError),
    #[error(transparent)]
    Bind(#[from] WaylandBindError),
    #[error(transparent)]
    Dispatch(#[from] DispatchError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(wlroots)]
#[derive(Debug, Error)]
#[error("wayland protocol \"{protocol}\" not supported: {inner}")]
pub struct WaylandBindError {
    inner: BindError,
    protocol: &'static str,
}

#[cfg(wlroots)]
impl WaylandBindError {
    pub(crate) fn new(inner: BindError, protocol: &'static str) -> Self {
        Self { inner, protocol }
    }
}

#[cfg(libei)]
#[derive(Debug, Error)]
pub enum LibeiEmulationCreationError {
    #[error(transparent)]
    Ashpd(#[from] ashpd::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Reis(#[from] reis::Error),
}

#[cfg(rdp)]
#[derive(Debug, Error)]
pub enum XdpEmulationCreationError {
    #[error(transparent)]
    Ashpd(#[from] ashpd::Error),
}

#[cfg(x11)]
#[derive(Debug, Error)]
pub enum X11EmulationCreationError {
    #[error("could not open display")]
    OpenDisplay,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Error)]
pub enum MacOSEmulationCreationError {
    #[error("could not create event source")]
    EventSourceCreation,
    #[error("accessibility permission is required")]
    AccessibilityPermission,
    #[error("input control permission is required")]
    InputControlPermission,
}

#[cfg(windows)]
#[derive(Debug, Error)]
pub enum WindowsEmulationCreationError {}

#[cfg(all(test, target_os = "macos"))]
mod a_mac_refused_its_permission {
    use super::{EmulationCreationError, MacOSEmulationCreationError, Permission};

    // LEDGER G2-5 | class B | 1 return value: EmulationCreationError::missing_permissions
    /// Both ways macOS refuses to let hops post events are Accessibility in
    /// System Settings, so both are named as it; a backend that failed
    /// otherwise names nothing.
    #[test]
    fn both_refusals_name_accessibility() {
        let named =
            |e: MacOSEmulationCreationError| EmulationCreationError::MacOs(e).missing_permissions();
        assert_eq!(
            (
                named(MacOSEmulationCreationError::AccessibilityPermission),
                named(MacOSEmulationCreationError::InputControlPermission),
                named(MacOSEmulationCreationError::EventSourceCreation),
            ),
            (
                Some(&[Permission::Accessibility][..]),
                Some(&[Permission::Accessibility][..]),
                None,
            ),
            "(no Accessibility, no input control, no event source)"
        );
    }
}
