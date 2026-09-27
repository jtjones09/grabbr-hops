//! One GUI per session on Windows, and no other program able to stop it
//! opening (#176).
//!
//! A second launch finds the first and asks it to show its window, then
//! exits. The GUI used to decide that from whether anything accepted a
//! connection on a fixed loopback port, so any program that listened there,
//! run by any user, kept the GUI and its tray icon from ever appearing.
//!
//! Now the first launch creates a named event in the session's own `Local\`
//! namespace, named after the IPC token ([`crate::proof::gui_instance_name`])
//! and granting this user alone. A later launch exits only when it opened
//! that event and set it. When the name is held by anything else, an object
//! this user may not open or one of another kind, the launch opens a window
//! anyway and says why it could not check for another.

/// What a GUI launch found. Only [`Found::Running`] stops it opening.
#[derive(Debug)]
pub enum Found {
    /// No other GUI of this user runs in this session: open, holding this.
    First(First),
    /// Another GUI of this user runs in this session, and was asked to show
    /// its window.
    Running,
}

/// Held by the GUI that opened first, for as long as it runs.
#[derive(Debug)]
pub struct First {
    #[cfg(windows)]
    _event: Option<std::os::windows::io::OwnedHandle>,
}

/// What became of the name a launch tried to claim.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Claimed {
    /// This launch holds it.
    New,
    /// Another GUI of this user holds it, and was asked to show when
    /// `signalled`.
    Existing { signalled: bool },
    /// Something else holds it, or it could not be used.
    Refused,
}

/// Whether a launch that met `claimed` opens a window.
///
/// Every doubt resolves to opening one: a second window is a nuisance, a
/// GUI that never appears is a KVM the user cannot reach.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn opens(claimed: Claimed) -> bool {
    match claimed {
        Claimed::New | Claimed::Refused => true,
        Claimed::Existing { signalled } => !signalled,
    }
}

/// Claim this session's GUI, calling `on_show` whenever a later launch asks
/// this one to show its window.
#[cfg(windows)]
pub fn claim_gui(on_show: impl Fn() + Send + 'static) -> Found {
    match crate::token::load_or_create() {
        Ok(token) => claim_gui_named(&crate::proof::gui_instance_name(&token), on_show),
        Err(e) => {
            log::warn!(
                "could not read the IPC token that names the GUI's instance ({e}); \
                 opening without checking for another"
            );
            Found::First(First { _event: None })
        }
    }
}

/// [`claim_gui`] under the name `name`.
#[cfg(windows)]
pub fn claim_gui_named(name: &str, on_show: impl Fn() + Send + 'static) -> Found {
    use crate::windows::{GuiEvent, gui_event};
    let (claimed, event) = match gui_event(name, on_show) {
        GuiEvent::New(event) => (Claimed::New, Some(event)),
        GuiEvent::Existing { signalled } => {
            if !signalled {
                log::warn!(
                    "another hops window holds {name} but could not be asked to show; \
                     opening this one"
                );
            }
            (Claimed::Existing { signalled }, None)
        }
        GuiEvent::Refused(e) => {
            log::warn!(
                "{name} is held by something that is not a hops window ({e}); opening \
                 without checking for another"
            );
            (Claimed::Refused, None)
        }
    };
    if opens(claimed) {
        Found::First(First { _event: event })
    } else {
        Found::Running
    }
}

#[cfg(test)]
mod tests {
    use super::{Claimed, opens};

    /// Only a GUI that was found and asked to show keeps a launch from
    /// opening. A name held by anything else must not.
    // LEDGER T9610 | class B | 1 return value of instance::opens
    #[test]
    fn only_a_gui_that_was_asked_to_show_keeps_a_launch_closed() {
        assert_eq!(
            [
                Claimed::New,
                Claimed::Existing { signalled: true },
                Claimed::Existing { signalled: false },
                Claimed::Refused,
            ]
            .map(opens),
            [true, false, true, true],
            "(held it, found a GUI and asked it to show, found one that could not \
             be asked, the name held by something else). A launch that stays \
             closed without having surfaced a window leaves the user no GUI."
        );
    }
}

#[cfg(all(test, windows))]
mod on_windows {
    //! The event itself, on the system. One name per test, so tests running
    //! at once do not meet.

    use super::{Found, claim_gui_named};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    fn name(tag: &str) -> String {
        format!(r"Local\hops-gui-test-{tag}-{}", std::process::id())
    }

    /// A second launch finds the first, which is asked to show its window.
    // LEDGER T9611 | class B | 1 return value of instance::claim_gui_named + 6 flag set by the first's thread
    #[test]
    fn a_second_launch_surfaces_the_first_and_stays_closed() {
        let name = name("second");
        let shown = Arc::new(AtomicBool::new(false));
        let flag = shown.clone();
        let first = claim_gui_named(&name, move || flag.store(true, Ordering::SeqCst));
        let second = claim_gui_named(&name, || {});
        let deadline = Instant::now() + Duration::from_secs(10);
        while !shown.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            matches!(first, Found::First(_)) && matches!(second, Found::Running),
            "(first, second) = ({first:?}, {second:?})"
        );
        assert!(
            shown.load(Ordering::SeqCst),
            "the second launch stayed closed and the first was never asked to show"
        );
        drop(first);
    }

    /// A name held by something this user may not open, or by an object of
    /// another kind, does not keep the GUI closed.
    // LEDGER T9612 | class B | 1 return value of instance::claim_gui_named
    #[test]
    fn a_name_held_by_anything_else_does_not_keep_the_gui_closed() {
        let denied = name("denied");
        let other_kind = name("mutex");
        let _held = crate::windows::testing::event_no_one_may_open(&denied)
            .expect("an event no one may open");
        let _mutex = crate::windows::testing::mutex(&other_kind).expect("a mutex");
        let (a, b) = (
            claim_gui_named(&denied, || {}),
            claim_gui_named(&other_kind, || {}),
        );
        assert!(
            matches!(a, Found::First(_)) && matches!(b, Found::First(_)),
            "(an event this user may not open, a mutex) under the GUI's name kept \
             it closed: ({a:?}, {b:?}). Any program could stop the GUI appearing."
        );
    }
}
