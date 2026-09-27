use thiserror::Error;

#[derive(Debug, Error)]
pub enum InputCaptureError {
    #[error("error creating input-capture: `{0}`")]
    Create(#[from] CaptureCreationError),
    #[error("error while capturing input: `{0}`")]
    Capture(#[from] CaptureError),
}

#[cfg(layer_shell)]
use std::io;
#[cfg(layer_shell)]
use wayland_client::{
    ConnectError, DispatchError,
    backend::WaylandError,
    globals::{BindError, GlobalError},
};

#[cfg(libei)]
use ashpd::desktop::ResponseError;

#[cfg(target_os = "macos")]
use core_graphics::base::CGError;

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("activation stream closed unexpectedly")]
    ActivationClosed,
    #[error("libei stream was closed")]
    EndOfStream,
    #[error("io error: `{0}`")]
    Io(#[from] std::io::Error),
    #[cfg(libei)]
    #[error("libei error: `{0}`")]
    Reis(#[from] reis::Error),
    #[cfg(libei)]
    #[error(transparent)]
    Portal(#[from] ashpd::Error),
    #[cfg(libei)]
    #[error("libei disconnected - reason: `{0}`")]
    Disconnected(String),
    #[cfg(target_os = "macos")]
    #[error("failed to warp mouse cursor: `{0}`")]
    WarpCursor(CGError),
    #[cfg(target_os = "macos")]
    #[error("reset_mouse_position called without a connected client")]
    ResetMouseWithoutClient,
    #[cfg(target_os = "macos")]
    #[error("core-graphics error: {0}")]
    CoreGraphics(CGError),
    #[cfg(target_os = "macos")]
    #[error("unable to map key event: {0}")]
    KeyMapError(i64),
    /// The OS took away a permission capture needs while it ran (#79).
    #[error("{}", Permission::sentence(.0))]
    MissingPermissions(Vec<Permission>),
}

/// An OS permission capture needs, named as macOS lists it under System
/// Settings → Privacy & Security. Only macOS has such permissions; a test's
/// scripted backend reports them anywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Permission {
    /// Accessibility (`AXIsProcessTrusted`).
    Accessibility,
    /// Input Monitoring (`CGPreflightListenEventAccess`).
    InputMonitoring,
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Accessibility => "Accessibility",
            Self::InputMonitoring => "Input Monitoring",
        })
    }
}

impl Permission {
    /// "macOS does not grant hops Accessibility and Input Monitoring".
    pub(crate) fn sentence(missing: &[Permission]) -> String {
        let names: Vec<String> = missing.iter().map(ToString::to_string).collect();
        format!("macOS does not grant hops {}", names.join(" and "))
    }
}

#[derive(Debug, Error)]
pub enum CaptureCreationError {
    #[error("no backend available")]
    NoAvailableBackend,
    #[cfg(feature = "scripted")]
    #[error("scripted: `{0}`")]
    Scripted(#[from] crate::scripted::ScriptedCaptureCreationError),
    #[cfg(libei)]
    #[error("error creating input-capture-portal backend: `{0}`")]
    Libei(#[from] LibeiCaptureCreationError),
    #[cfg(layer_shell)]
    #[error("error creating layer-shell capture backend: `{0}`")]
    LayerShell(#[from] LayerShellCaptureCreationError),
    #[cfg(x11)]
    #[error("error creating x11 capture backend: `{0}`")]
    X11(#[from] X11InputCaptureCreationError),
    #[cfg(windows)]
    #[error("error creating windows capture backend")]
    Windows,
    #[cfg(target_os = "macos")]
    #[error("error creating macos capture backend: `{0}`")]
    MacOS(#[from] MacosCaptureCreationError),
}

impl InputCaptureError {
    /// The permissions whose absence stopped capture, when that is why.
    pub fn missing_permissions(&self) -> Option<&[Permission]> {
        match self {
            Self::Create(e) => e.missing_permissions(),
            Self::Capture(e) => e.missing_permissions(),
        }
    }

    /// Whether the user declined to let capture start, which is switching
    /// it off rather than a failure.
    pub fn cancelled_by_user(&self) -> bool {
        matches!(self, Self::Create(e) if e.cancelled_by_user())
    }
}

impl CaptureError {
    /// The permissions taken away while capture ran, when that is why it
    /// stopped.
    pub fn missing_permissions(&self) -> Option<&[Permission]> {
        match self {
            Self::MissingPermissions(missing) => Some(missing),
            _ => None,
        }
    }
}

impl CaptureCreationError {
    /// The permissions whose absence kept the backend from starting, when
    /// that is why.
    pub fn missing_permissions(&self) -> Option<&[Permission]> {
        #[cfg(target_os = "macos")]
        if let Self::MacOS(MacosCaptureCreationError::MissingPermissions(missing)) = self {
            return Some(missing);
        }
        #[cfg(feature = "scripted")]
        if let Self::Scripted(crate::scripted::ScriptedCaptureCreationError::MissingPermissions(
            missing,
        )) = self
        {
            return Some(missing);
        }
        None
    }

    /// request was intentionally denied by the user
    #[cfg(libei)]
    pub fn cancelled_by_user(&self) -> bool {
        matches!(
            self,
            CaptureCreationError::Libei(LibeiCaptureCreationError::Ashpd(ashpd::Error::Response(
                ResponseError::Cancelled
            )))
        )
    }
    #[cfg(not(libei))]
    pub fn cancelled_by_user(&self) -> bool {
        false
    }
}

#[cfg(libei)]
#[derive(Debug, Error)]
pub enum LibeiCaptureCreationError {
    #[error("xdg-desktop-portal: `{0}`")]
    Ashpd(#[from] ashpd::Error),
}

#[cfg(layer_shell)]
#[derive(Debug, Error)]
#[error("{protocol} protocol not supported: {inner}")]
pub struct WaylandBindError {
    inner: BindError,
    protocol: &'static str,
}

#[cfg(layer_shell)]
impl WaylandBindError {
    pub(crate) fn new(inner: BindError, protocol: &'static str) -> Self {
        Self { inner, protocol }
    }
}

#[cfg(layer_shell)]
#[derive(Debug, Error)]
pub enum LayerShellCaptureCreationError {
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
    Io(#[from] io::Error),
}

#[cfg(x11)]
#[derive(Debug, Error)]
pub enum X11InputCaptureCreationError {
    #[error("X11 input capture is not yet implemented :(")]
    NotImplemented,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Error)]
pub enum MacosCaptureCreationError {
    #[error("event source creation failed!")]
    EventSourceCreation,
    #[cfg(target_os = "macos")]
    #[error("event tap creation failed")]
    EventTapCreation,
    /// Each permission macOS withholds, all of them, so the user is told
    /// every setting to change at once.
    #[error("{}", Permission::sentence(.0))]
    MissingPermissions(Vec<Permission>),
    #[error("failed to set CG Cursor property")]
    CGCursorProperty,
    #[cfg(target_os = "macos")]
    #[error("failed to get display ids: {0}")]
    ActiveDisplays(CGError),
}
