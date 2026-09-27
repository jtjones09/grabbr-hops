//! Asking macOS for what capture needs (#169).
//!
//! The daemon only checks its permissions, silently: it runs under launchd,
//! where a system prompt may never show. The app asks instead, when the user
//! turns capture on or opens the setting, never at launch: a Mac that is only
//! ever controlled needs neither permission, and is not asked for either.
//!
//! The app and the daemon are one signed binary with one identifier, so a
//! grant made through the app's prompt is the daemon's too; the daemon's
//! permission watch (#221) then starts capture with it. That the grant
//! reaches a launchd-started daemon this way is UNVERIFIED on hardware.
//!
//! Only macOS acts on it; elsewhere no capture fails for a permission.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use hops_frontend_core::{CaptureFault, CaptureState, Permission};

/// What the app does for a capture that failed for want of permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ask {
    /// Ask macOS for Input Monitoring. The first time, macOS shows its own
    /// prompt and lists hops under Input Monitoring, so there is a switch to
    /// turn on; after that the call only answers.
    pub(crate) input_monitoring: bool,
    /// The System Settings list to open: the first missing, Accessibility
    /// before Input Monitoring. The daemon names the next once it is granted.
    pub(crate) pane: Permission,
}

/// What to ask for while capture is in `capture`; `None` when no permission
/// is missing.
pub(crate) fn for_capture(capture: &CaptureState) -> Option<Ask> {
    let CaptureState::Failed(CaptureFault::Missing(missing)) = capture else {
        return None;
    };
    let pane = missing.iter().copied().min()?;
    Some(Ask {
        input_monitoring: missing.contains(&Permission::InputMonitoring),
        pane,
    })
}

/// The URL that opens `pane` in System Settings → Privacy & Security.
pub(crate) fn pane_url(pane: Permission) -> &'static str {
    match pane {
        Permission::Accessibility => {
            "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility"
        }
        Permission::InputMonitoring => {
            "x-apple.systempreferences:com.apple.preference.security?Privacy_ListenEvent"
        }
    }
}

/// Ask macOS for Input Monitoring, off the UI thread: whether the call waits
/// for the user's answer is not documented.
#[cfg(target_os = "macos")]
pub(crate) fn request_input_monitoring() {
    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGRequestListenEventAccess() -> bool;
    }
    std::thread::spawn(|| {
        // SAFETY: takes no arguments; asks for this process's own grant.
        let granted = unsafe { CGRequestListenEventAccess() };
        log::info!("asked macOS for Input Monitoring: granted {granted}");
    });
}

/// Open `pane` in System Settings.
#[cfg(target_os = "macos")]
pub(crate) fn open_pane(pane: Permission) {
    match std::process::Command::new("/usr/bin/open")
        .arg(pane_url(pane))
        .spawn()
    {
        // `open` hands the URL to System Settings and exits; reap it.
        Ok(mut child) => {
            std::thread::spawn(move || child.wait());
        }
        Err(e) => log::warn!("could not open System Settings: {e}"),
    }
}

/// Do what `ask` says: ask for Input Monitoring, and open the pane when
/// `open` is set.
#[cfg(target_os = "macos")]
pub(crate) fn act(ask: Ask, open: bool) {
    if ask.input_monitoring {
        request_input_monitoring();
    }
    if open {
        open_pane(ask.pane);
    }
}

#[cfg(test)]
mod what_the_app_asks_for {
    //! Which permission the app asks macOS for, and which list it opens, for
    //! each way capture can fail.

    use super::{Ask, for_capture, pane_url};
    use hops_frontend_core::{CaptureFault, CaptureState, Permission};

    fn missing(permissions: &[Permission]) -> CaptureState {
        CaptureState::Failed(CaptureFault::Missing(permissions.to_vec()))
    }

    // LEDGER T10 | class B | 1 return value: privacy::for_capture, privacy::pane_url
    #[test]
    fn input_monitoring_is_asked_for_only_when_it_is_what_is_missing() {
        assert_eq!(
            [
                for_capture(&missing(&[Permission::InputMonitoring])),
                for_capture(&missing(&[
                    Permission::InputMonitoring,
                    Permission::Accessibility
                ])),
                for_capture(&missing(&[Permission::Accessibility])),
                for_capture(&CaptureState::Failed(CaptureFault::Backend("x".into()))),
                for_capture(&CaptureState::Disabled),
            ],
            [
                Some(Ask {
                    input_monitoring: true,
                    pane: Permission::InputMonitoring
                }),
                Some(Ask {
                    input_monitoring: true,
                    pane: Permission::Accessibility
                }),
                Some(Ask {
                    input_monitoring: false,
                    pane: Permission::Accessibility
                }),
                None,
                None,
            ],
            "the app asks for Input Monitoring exactly when capture lacks it, opens \
             Accessibility first when both are missing, and asks for nothing when \
             no permission is missing"
        );
        assert!(
            pane_url(Permission::InputMonitoring).ends_with("?Privacy_ListenEvent")
                && pane_url(Permission::Accessibility).ends_with("?Privacy_Accessibility"),
            "each permission opens its own list"
        );
    }
}
