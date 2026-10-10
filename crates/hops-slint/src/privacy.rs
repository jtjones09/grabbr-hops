//! Asking macOS for what capture and emulation need (#169, #243).
//!
//! The daemon only checks its permissions, silently: it runs under launchd,
//! where macOS shows it no prompt, so a check that asks to prompt adds
//! nothing to the list (#243). The app asks instead, when the user clicks
//! enable input or a banner's open settings, never at launch.
//!
//! Capture needs Accessibility and Input Monitoring. Emulation, which a Mac
//! that is only ever controlled runs and nothing else, needs Accessibility,
//! which also grants posting input; it never needs Input Monitoring.
//!
//! Enable input first checks Accessibility itself with the probe tap, unless
//! the daemon already reports it missing or emulation runs. To ask for
//! Accessibility the app calls `AXIsProcessTrustedWithOptions` with the
//! prompt option and, when that answers untrusted, `CGRequestPostEventAccess`;
//! for Input Monitoring, `CGRequestListenEventAccess`. Each answer is logged,
//! and a burst of clicks asks once ([`Asking`]).
//! Which of them shows a prompt and adds hops to the list on macOS 27 is
//! UNVERIFIED on hardware.
//!
//! The app and the daemon are one signed binary with one identifier, so a
//! grant made through the app's prompt is the daemon's too; the daemon's
//! permission watch (#221) then starts capture with it. That the grant
//! reaches a launchd-started daemon this way is UNVERIFIED on hardware.
//!
//! Only macOS acts on it; elsewhere no capture fails for a permission.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use hops_frontend_core::{CaptureFault, CaptureState, EmulationFault, EmulationState, Permission};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// What the app asks macOS for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ask {
    /// Ask macOS for Accessibility: `AXIsProcessTrustedWithOptions` with
    /// the prompt option, then `CGRequestPostEventAccess` if that answers
    /// untrusted.
    pub(crate) accessibility: bool,
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
        accessibility: missing.contains(&Permission::Accessibility),
        input_monitoring: missing.contains(&Permission::InputMonitoring),
        pane,
    })
}

/// What to ask for while emulation is in `emulation`; `None` when no
/// permission is missing. Never Input Monitoring, which emulation does not
/// read.
pub(crate) fn for_emulation(emulation: &EmulationState) -> Option<Ask> {
    let EmulationState::Failed(EmulationFault::Missing(missing)) = emulation else {
        return None;
    };
    let pane = missing.iter().copied().min()?;
    Some(Ask {
        accessibility: missing.contains(&Permission::Accessibility),
        input_monitoring: false,
        pane,
    })
}

/// What enable input asks for: what capture and emulation report missing,
/// and Accessibility when `refused` says this process lacks it. The daemon
/// reports a permission only once a side has tried and failed, which on a
/// Mac that never granted hops can be after the first click, so the app
/// checks too. `refused` is called only when neither side already reports
/// Accessibility missing and emulation does not run: emulation that runs
/// has Accessibility, so nothing asks for it then.
pub(crate) fn for_enable_input(
    capture: &CaptureState,
    emulation: &EmulationState,
    refused: impl FnOnce() -> bool,
) -> Option<Ask> {
    let capture = for_capture(capture);
    let reported = capture.is_some_and(|a| a.accessibility)
        || for_emulation(emulation).is_some_and(|a| a.accessibility);
    let accessibility = !emulation.is_enabled() && (reported || refused());
    let input_monitoring = capture.is_some_and(|a| a.input_monitoring);
    let pane = match (accessibility, input_monitoring) {
        (true, _) => Permission::Accessibility,
        (false, true) => Permission::InputMonitoring,
        (false, false) => return None,
    };
    Some(Ask {
        accessibility,
        input_monitoring,
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

/// What the user did that may need macOS asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    /// Clicked enable input: asks, opens nothing.
    EnableInput,
    /// Clicked open settings on capture's banner.
    CaptureSettings,
    /// Clicked open settings on emulation's banner.
    EmulationSettings,
}

/// The calls through which the app asks macOS. [`System`] makes them.
pub(crate) trait Macos {
    /// Whether this process has Accessibility, by the probe tap
    /// ([`input_event::accessibility`]), which macOS answers afresh each
    /// time; `AXIsProcessTrusted` can keep its first answer for the life of
    /// the process (#240). No prompt.
    fn accessibility_permitted(&mut self) -> bool;
    /// `AXIsProcessTrustedWithOptions` with `kAXTrustedCheckOptionPrompt`
    /// true.
    fn prompt_accessibility(&mut self) -> bool;
    /// `CGRequestPostEventAccess`.
    fn request_post_events(&mut self) -> bool;
    /// `CGRequestListenEventAccess`.
    fn request_input_monitoring(&mut self) -> bool;
    /// Open `pane` in System Settings.
    fn open_pane(&mut self, pane: Permission);
}

/// Ask macOS, through `mac`, for what `action` needs while capture is in
/// `capture` and emulation in `emulation`. Accessibility is asked before
/// Input Monitoring and both before the pane opens, so a prompt can show
/// before System Settings takes the front.
pub(crate) fn act(
    action: Action,
    capture: &CaptureState,
    emulation: &EmulationState,
    mac: &mut impl Macos,
) {
    let (ask, open) = match action {
        Action::EnableInput => {
            let ask = for_enable_input(capture, emulation, || {
                let permitted = mac.accessibility_permitted();
                log::info!(
                    "checked Accessibility by the probe tap (no prompt): permitted {permitted}"
                );
                !permitted
            });
            (ask, false)
        }
        Action::CaptureSettings => (for_capture(capture), true),
        Action::EmulationSettings => (for_emulation(emulation), true),
    };
    let Some(mut ask) = ask else {
        return;
    };
    // Emulation that runs has Accessibility, whatever a stale report says.
    ask.accessibility &= !emulation.is_enabled();
    if ask.accessibility {
        let trusted = mac.prompt_accessibility();
        log::info!("asked macOS for Accessibility (AX prompt): trusted {trusted}");
        if !trusted {
            let granted = mac.request_post_events();
            log::info!("asked macOS for posting events: granted {granted}");
        }
    }
    if ask.input_monitoring {
        let granted = mac.request_input_monitoring();
        log::info!("asked macOS for Input Monitoring: granted {granted}");
    }
    if open {
        mac.open_pane(ask.pane);
    }
}

/// One ask at a time. A click while an ask is under way, or within
/// [`Asking::hold`] of its start, asks nothing, so a burst of clicks makes
/// one set of calls and at most one prompt each.
pub(crate) struct Asking {
    busy: AtomicBool,
    hold: Duration,
}

/// How long after an ask begins further clicks ask nothing.
const HOLD: Duration = Duration::from_secs(3);

static ASKING: Asking = Asking::new(HOLD);

impl Asking {
    pub(crate) const fn new(hold: Duration) -> Self {
        Self {
            busy: AtomicBool::new(false),
            hold,
        }
    }

    /// Ask macOS through `mac` for what `action` needs, on a thread of its
    /// own, off the UI thread: whether the request calls wait for the
    /// user's answer is not documented. `None`, asking nothing, while
    /// another ask holds.
    pub(crate) fn ask<M: Macos + Send + 'static>(
        &'static self,
        action: Action,
        capture: CaptureState,
        emulation: EmulationState,
        mut mac: M,
    ) -> Option<JoinHandle<()>> {
        if self.busy.swap(true, Ordering::AcqRel) {
            log::info!("{action:?}: already asking macOS; this click asks nothing");
            return None;
        }
        Some(std::thread::spawn(move || {
            let started = Instant::now();
            act(action, &capture, &emulation, &mut mac);
            std::thread::sleep(self.hold.saturating_sub(started.elapsed()));
            self.busy.store(false, Ordering::Release);
        }))
    }
}

/// Ask macOS for what `action` needs, one ask at a time. Does nothing off
/// macOS.
pub(crate) fn ask(action: Action, capture: CaptureState, emulation: EmulationState) {
    #[cfg(target_os = "macos")]
    let _ = ASKING.ask(action, capture, emulation, System);
    #[cfg(not(target_os = "macos"))]
    let _ = (action, capture, emulation, &ASKING);
}

/// The calls themselves.
#[cfg(target_os = "macos")]
pub(crate) struct System;

#[cfg(target_os = "macos")]
impl Macos for System {
    fn accessibility_permitted(&mut self) -> bool {
        input_event::accessibility::permitted_by(input_event::accessibility::create_active_tap)
    }

    fn prompt_accessibility(&mut self) -> bool {
        use core_foundation::base::TCFType;
        use core_foundation::boolean::CFBoolean;
        use core_foundation::dictionary::CFDictionary;
        use core_foundation::string::CFString;
        // kAXTrustedCheckOptionPrompt == CFSTR("AXTrustedCheckOptionPrompt")
        let key = CFString::from_static_string("AXTrustedCheckOptionPrompt");
        let options = CFDictionary::from_CFType_pairs(&[(
            key.as_CFType(),
            CFBoolean::true_value().as_CFType(),
        )]);
        // SAFETY: `options` outlives the synchronous call. The `Boolean`
        // (u8) result is normalized with != 0.
        unsafe { AXIsProcessTrustedWithOptions(options.as_concrete_TypeRef().cast()) != 0 }
    }

    fn request_post_events(&mut self) -> bool {
        // SAFETY: takes no arguments; asks for this process's own grant.
        unsafe { CGRequestPostEventAccess() }
    }

    fn request_input_monitoring(&mut self) -> bool {
        // SAFETY: takes no arguments; asks for this process's own grant.
        unsafe { CGRequestListenEventAccess() }
    }

    fn open_pane(&mut self, pane: Permission) {
        match std::process::Command::new("/usr/bin/open")
            .arg(pane_url(pane))
            .spawn()
        {
            // `open` hands the URL to System Settings and exits; reap it.
            Ok(mut child) => {
                let _ = child.wait();
            }
            Err(e) => log::warn!("could not open System Settings: {e}"),
        }
    }
}

#[cfg(target_os = "macos")]
#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    fn AXIsProcessTrustedWithOptions(options: *const std::ffi::c_void) -> u8;
}

#[cfg(target_os = "macos")]
#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGRequestPostEventAccess() -> bool;
    fn CGRequestListenEventAccess() -> bool;
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
                    accessibility: false,
                    input_monitoring: true,
                    pane: Permission::InputMonitoring
                }),
                Some(Ask {
                    accessibility: true,
                    input_monitoring: true,
                    pane: Permission::Accessibility
                }),
                Some(Ask {
                    accessibility: true,
                    input_monitoring: false,
                    pane: Permission::Accessibility
                }),
                None,
                None,
            ],
            "the app asks for each permission exactly when capture lacks it, opens \
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
