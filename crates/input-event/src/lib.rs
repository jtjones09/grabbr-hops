pub mod keylog;
use std::fmt::{self, Display};

pub mod error;
pub mod scancode;

#[cfg(all(unix, feature = "libei", not(target_os = "macos")))]
mod libei;

// FIXME
pub const BTN_LEFT: u32 = 0x110;
pub const BTN_RIGHT: u32 = 0x111;
pub const BTN_MIDDLE: u32 = 0x112;
pub const BTN_BACK: u32 = 0x113;
pub const BTN_FORWARD: u32 = 0x114;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum PointerEvent {
    /// relative motion event
    Motion { time: u32, dx: f64, dy: f64 },
    /// mouse button event
    Button { time: u32, button: u32, state: u32 },
    /// axis event, scroll event for touchpads
    Axis { time: u32, axis: u8, value: f64 },
    /// discrete axis event, scroll event for mice - 120 = one scroll tick
    AxisDiscrete120 { axis: u8, value: i32 },
}

/// A key or a modifier change.
///
/// `Debug` and `Display` never print which key, nor which modifiers are
/// held: every log line that prints an input event goes through them, and
/// raising the log level must not record what someone types (#117). Key
/// identity goes to [`keylog`], which is compiled out of release builds.
#[derive(PartialEq, Clone, Copy)]
pub enum KeyboardEvent {
    /// a key press / release event
    Key { time: u32, key: u32, state: u8 },
    /// modifiers changed state
    Modifiers {
        depressed: u32,
        latched: u32,
        locked: u32,
        group: u32,
    },
}

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum Event {
    /// pointer event (motion / button / axis)
    Pointer(PointerEvent),
    /// keyboard events (key / modifiers)
    Keyboard(KeyboardEvent),
}

impl Display for PointerEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PointerEvent::Motion { time: _, dx, dy } => write!(f, "motion({dx},{dy})"),
            PointerEvent::Button {
                time: _,
                button,
                state,
            } => {
                let str = match *button {
                    BTN_LEFT => Some("left"),
                    BTN_RIGHT => Some("right"),
                    BTN_MIDDLE => Some("middle"),
                    BTN_FORWARD => Some("forward"),
                    BTN_BACK => Some("back"),
                    _ => None,
                };
                if let Some(button) = str {
                    write!(f, "button({button}, {state})")
                } else {
                    write!(f, "button({button}, {state}")
                }
            }
            PointerEvent::Axis {
                time: _,
                axis,
                value,
            } => write!(f, "scroll({axis}, {value})"),
            PointerEvent::AxisDiscrete120 { axis, value } => {
                write!(f, "scroll-120 ({axis}, {value})")
            }
        }
    }
}

/// Stands in for the key and the modifier masks when an event is printed.
const HIDDEN: &str = "<hidden>";

impl Display for KeyboardEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyboardEvent::Key { state, .. } => write!(f, "key({HIDDEN}, {state})"),
            KeyboardEvent::Modifiers { .. } => write!(f, "modifiers({HIDDEN})"),
        }
    }
}

impl fmt::Debug for KeyboardEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Hidden;
        impl fmt::Debug for Hidden {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(HIDDEN)
            }
        }
        match self {
            KeyboardEvent::Key { time, state, .. } => f
                .debug_struct("Key")
                .field("time", time)
                .field("key", &Hidden)
                .field("state", state)
                .finish(),
            KeyboardEvent::Modifiers { .. } => f.debug_struct("Modifiers").finish_non_exhaustive(),
        }
    }
}

impl Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::Pointer(p) => write!(f, "{p}"),
            Event::Keyboard(k) => write!(f, "{k}"),
        }
    }
}

#[cfg(test)]
mod no_key_identity {
    //! Every log line that prints an input event goes through these two
    //! impls: `Event`, `CaptureEvent` and `ProtoEvent` all print a keyboard
    //! event this way. Neither may say which key, nor which modifiers are
    //! held, since the modifier state beside each key gives away case (#117).

    use super::*;

    const MAPPED: u32 = scancode::Linux::KeyA as u32; // 30
    const UNMAPPED: u32 = 700;
    const MASKS: [u32; 4] = [0x11, 0x22, 0x44, 0x88];

    /// Every way the log can print a keyboard event.
    fn printed(event: KeyboardEvent) -> [String; 4] {
        [
            format!("{event}"),
            format!("{event:?}"),
            format!("{}", Event::Keyboard(event)),
            format!("{:?}", Event::Keyboard(event)),
        ]
    }

    // LEDGER T117-3 | class B | 1 return value: <KeyboardEvent as Display/Debug>::fmt
    #[test]
    fn a_key_event_prints_press_or_release_but_not_the_key() {
        assert!(
            scancode::Linux::try_from(UNMAPPED).is_err(),
            "{UNMAPPED} must have no scancode, or this does not cover the fallback"
        );
        for code in [MAPPED, UNMAPPED] {
            for state in [0u8, 1] {
                let event = KeyboardEvent::Key {
                    time: 0,
                    key: code,
                    state,
                };
                for text in printed(event) {
                    assert!(
                        !text.contains(&code.to_string()) && !text.contains("KeyA"),
                        "{text:?} names key {code}"
                    );
                    assert!(
                        text.contains(&state.to_string()),
                        "{text:?} must still say whether the key went down or up"
                    );
                }
            }
        }
    }

    // LEDGER T117-4 | class B | 1 return value: <KeyboardEvent as Display/Debug>::fmt
    #[test]
    fn a_modifiers_event_does_not_print_which_modifiers_are_held() {
        let [depressed, latched, locked, group] = MASKS;
        let event = KeyboardEvent::Modifiers {
            depressed,
            latched,
            locked,
            group,
        };
        for text in printed(event) {
            assert!(
                text.contains("odifiers"),
                "{text:?} is not a modifiers event"
            );
            for mask in MASKS {
                assert!(
                    !text.contains(&mask.to_string()) && !text.contains(&format!("{mask:x}")),
                    "{text:?} prints the modifier mask {mask:#x}"
                );
            }
        }
    }
}
