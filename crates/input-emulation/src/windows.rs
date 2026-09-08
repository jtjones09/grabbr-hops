use super::error::{EmulationError, WindowsEmulationCreationError};
use input_event::{
    BTN_BACK, BTN_FORWARD, BTN_LEFT, BTN_MIDDLE, BTN_RIGHT, Event, KeyboardEvent, PointerEvent,
    scancode,
};

use async_trait::async_trait;
use std::ops::BitOrAssign;
use std::time::Duration;
use tokio::task::AbortHandle;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    INPUT, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE,
    MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN,
    MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP,
    MOUSEEVENTF_WHEEL, MOUSEINPUT,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    INPUT_0, KEYEVENTF_EXTENDEDKEY, MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, SendInput,
};
use windows::Win32::UI::WindowsAndMessaging::{XBUTTON1, XBUTTON2};

use super::{Emulation, EmulationHandle};

const DEFAULT_REPEAT_DELAY: Duration = Duration::from_millis(500);
const DEFAULT_REPEAT_INTERVAL: Duration = Duration::from_millis(32);

pub(crate) struct WindowsEmulation {
    repeat_task: Option<AbortHandle>,
    /// Whether the input desktop is currently refusing our events, so the
    /// transition is logged once rather than at the rate a peer sends.
    desktop_refusing: bool,
}

impl WindowsEmulation {
    pub(crate) fn new() -> Result<Self, WindowsEmulationCreationError> {
        Ok(Self {
            repeat_task: None,
            desktop_refusing: false,
        })
    }
}

#[async_trait]
impl Emulation for WindowsEmulation {
    async fn consume(&mut self, event: Event, _: EmulationHandle) -> Result<(), EmulationError> {
        match event {
            Event::Pointer(pointer_event) => {
                let delivered = match pointer_event {
                    PointerEvent::Motion { time: _, dx, dy } => rel_mouse(dx as i32, dy as i32),
                    PointerEvent::Button {
                        time: _,
                        button,
                        state,
                    } => mouse_button(button, state),
                    PointerEvent::Axis {
                        time: _,
                        axis,
                        value,
                    } => scroll(axis, value as i32),
                    PointerEvent::AxisDiscrete120 { axis, value } => scroll(axis, value),
                };
                self.note_delivery(delivered);
            }
            Event::Keyboard(keyboard_event) => match keyboard_event {
                KeyboardEvent::Key {
                    time: _,
                    key,
                    state,
                } => {
                    match state {
                        // pressed
                        0 => self.kill_repeat_task(),
                        1 => self.spawn_repeat_task(key).await,
                        _ => {}
                    }
                    let delivered = key_event(key, state);
                    self.note_delivery(delivered);
                }
                KeyboardEvent::Modifiers { .. } => {}
            },
        }
        // FIXME
        Ok(())
    }

    async fn create(&mut self, _handle: EmulationHandle) {}

    async fn destroy(&mut self, _handle: EmulationHandle) {}

    async fn terminate(&mut self) {}
}

impl WindowsEmulation {
    /// Records whether the last event reached the input desktop.
    ///
    /// When it did not, the foreground desktop belongs to someone else — the
    /// Ctrl-Alt-Del secure desktop, a UAC prompt, the lock screen. Those are
    /// exactly the moments a peer must not be able to keep typing through, and
    /// the moments where the old unbounded retry loop hung the daemon. Stop the
    /// synthetic auto-repeat so a key held at that instant does not stay held.
    fn note_delivery(&mut self, delivered: bool) {
        let refusing = !delivered;
        if refusing == self.desktop_refusing {
            return;
        }
        self.desktop_refusing = refusing;
        if refusing {
            self.kill_repeat_task();
            log::info!(
                "input desktop is refusing events (secure desktop, UAC prompt or \
                 lock screen) — dropping injected input until it returns"
            );
        } else {
            log::info!("input desktop is accepting events again");
        }
    }

    async fn spawn_repeat_task(&mut self, key: u32) {
        // there can only be one repeating key and it's
        // always the last to be pressed
        self.kill_repeat_task();
        let repeat_task = tokio::task::spawn_local(async move {
            tokio::time::sleep(DEFAULT_REPEAT_DELAY).await;
            loop {
                // Stop repeating the moment the desktop refuses. Otherwise a key
                // held when the secure desktop appears keeps firing into it for
                // as long as it is up.
                if !key_event(key, 1) {
                    break;
                }
                tokio::time::sleep(DEFAULT_REPEAT_INTERVAL).await;
            }
        });
        self.repeat_task = Some(repeat_task.abort_handle());
    }
    fn kill_repeat_task(&mut self) {
        if let Some(task) = self.repeat_task.take() {
            task.abort();
        }
    }
}

/// How many times to re-offer one event before concluding the input desktop is
/// not ours.
///
/// This loop used to be unbounded. `SendInput` returns 0 whenever the foreground
/// desktop belongs to someone else — the Ctrl-Alt-Del secure desktop, a UAC
/// prompt, the lock screen — and it keeps returning 0 for as long as that
/// desktop is up. Measured on a real machine: 5000 of 5000 calls returned 0 with
/// ERROR_ACCESS_DENIED, at 209,130 futile calls per second, on the daemon's
/// single-threaded runtime. Pressing the one key sequence a peer provably cannot
/// synthesize therefore pinned a core at 100% and hung the daemon until it was
/// killed — turning the machine's own panic gesture into a denial of service.
///
/// A handful of retries still absorbs the transient failures the loop was
/// written for. Anything past that is a desktop we do not own, and the correct
/// response is to drop the event, not to spin.
const SEND_INPUT_MAX_ATTEMPTS: u32 = 8;

/// Submits one event. Returns false if the input desktop refused it.
///
/// A dropped event is not silent by choice — it is the least-bad outcome when
/// the alternative is a hung daemon. The caller stops any synthetic auto-repeat
/// so a held key does not keep firing into a desktop that is rejecting it.
#[must_use]
fn send_input_safe(input: INPUT) -> bool {
    unsafe {
        for _ in 0..SEND_INPUT_MAX_ATTEMPTS {
            /* retval = number of successfully submitted events */
            if SendInput(&[input], std::mem::size_of::<INPUT>() as i32) > 0 {
                return true;
            }
        }
    }
    false
}

fn send_mouse_input(mi: MOUSEINPUT) -> bool {
    send_input_safe(INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 { mi },
    })
}

fn send_keyboard_input(ki: KEYBDINPUT) -> bool {
    send_input_safe(INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 { ki },
    })
}
fn rel_mouse(dx: i32, dy: i32) -> bool {
    let mi = MOUSEINPUT {
        dx,
        dy,
        mouseData: 0,
        dwFlags: MOUSEEVENTF_MOVE,
        time: 0,
        dwExtraInfo: 0,
    };
    send_mouse_input(mi)
}

fn mouse_button(button: u32, state: u32) -> bool {
    let dw_flags = match state {
        0 => match button {
            BTN_LEFT => MOUSEEVENTF_LEFTUP,
            BTN_RIGHT => MOUSEEVENTF_RIGHTUP,
            BTN_MIDDLE => MOUSEEVENTF_MIDDLEUP,
            BTN_BACK => MOUSEEVENTF_XUP,
            BTN_FORWARD => MOUSEEVENTF_XUP,
            // An unmapped button is nothing to send, not a refusal.
            _ => return true,
        },
        1 => match button {
            BTN_LEFT => MOUSEEVENTF_LEFTDOWN,
            BTN_RIGHT => MOUSEEVENTF_RIGHTDOWN,
            BTN_MIDDLE => MOUSEEVENTF_MIDDLEDOWN,
            BTN_BACK => MOUSEEVENTF_XDOWN,
            BTN_FORWARD => MOUSEEVENTF_XDOWN,
            _ => return true,
        },
        _ => return true,
    };
    let mouse_data = match button {
        BTN_BACK => XBUTTON1 as u32,
        BTN_FORWARD => XBUTTON2 as u32,
        _ => 0,
    };
    let mi = MOUSEINPUT {
        dx: 0,
        dy: 0, // no movement
        mouseData: mouse_data,
        dwFlags: dw_flags,
        time: 0,
        dwExtraInfo: 0,
    };
    send_mouse_input(mi)
}

fn scroll(axis: u8, value: i32) -> bool {
    let event_type = match axis {
        0 => MOUSEEVENTF_WHEEL,
        1 => MOUSEEVENTF_HWHEEL,
        _ => return true,
    };
    let mi = MOUSEINPUT {
        dx: 0,
        dy: 0,
        mouseData: -value as u32,
        dwFlags: event_type,
        time: 0,
        dwExtraInfo: 0,
    };
    send_mouse_input(mi)
}

fn key_event(key: u32, state: u8) -> bool {
    let scancode = match linux_keycode_to_windows_scancode(key) {
        Some(code) => code,
        // linux_keycode_to_windows_scancode already logged it. Unmapped, not
        // refused — reporting it as a refusal would stop auto-repeat and log a
        // secure-desktop transition that never happened.
        None => return true,
    };
    let extended = scancode > 0xff;
    let scancode = scancode & 0xff;
    let mut flags = KEYEVENTF_SCANCODE;
    if extended {
        flags.bitor_assign(KEYEVENTF_EXTENDEDKEY);
    }
    if state == 0 {
        flags.bitor_assign(KEYEVENTF_KEYUP);
    }
    let ki = KEYBDINPUT {
        wVk: Default::default(),
        wScan: scancode,
        dwFlags: flags,
        time: 0,
        dwExtraInfo: 0,
    };
    send_keyboard_input(ki)
}

fn linux_keycode_to_windows_scancode(linux_keycode: u32) -> Option<u16> {
    let linux_scancode = match scancode::Linux::try_from(linux_keycode) {
        Ok(s) => s,
        Err(_) => {
            log::warn!("unknown keycode: {linux_keycode}");
            return None;
        }
    };
    // The sender's keystrokes, on a receiver. Same gate (#117).
    input_event::keylog::key(0, 0, &format!("linux:{linux_scancode:?}"));
    let windows_scancode = match scancode::Windows::try_from(linux_scancode) {
        Ok(s) => s,
        Err(_) => {
            log::warn!("failed to translate linux code into windows scancode: {linux_scancode:?}");
            return None;
        }
    };
    input_event::keylog::key(0, 0, &format!("windows:{windows_scancode:?}"));
    Some(windows_scancode as u16)
}
