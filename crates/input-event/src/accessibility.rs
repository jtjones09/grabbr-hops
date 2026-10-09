//! Whether macOS grants this process Accessibility, asked so that the answer
//! is current (#240).
//!
//! `AXIsProcessTrusted` and the `CGPreflight*` checks can keep their first
//! answer for the life of a running process on macOS 27, for a grant and
//! for a revocation alike. Whether macOS lets the process create an active
//! event tap is decided afresh each time, and it does only with
//! Accessibility; a listen-only tap is let through by Input Monitoring too,
//! so only an active one answers.
//!
//! The probe tap asks for no events at all. Measured on macOS 27.2: refused
//! without Accessibility and permitted with it, in 1 to 2 ms, the same
//! answers as a probe tap for key-down events. A tap that asks for no
//! events is sent none, so no event ever waits on it while it exists; a
//! key-down probe sat in the key-down path from its creation until it was
//! disabled, which is how an active tap holds input during a revocation.
//! That is what lets the check run every few seconds in every state,
//! including while the pointer is on this Mac and nothing is missing.
//!
//! Here because capture, emulation and the daemon all ask it.

/// The events the probe tap asks for: none (`CGEventMask` 0).
pub const PROBE_MASK: u64 = 0;

/// Whether `tap`, which creates an active event tap for the events in a
/// mask and reports whether macOS allowed it, is allowed the probe tap. The
/// one place the probe's mask is chosen, whoever creates the tap.
pub fn permitted_by(tap: impl FnOnce(u64) -> bool) -> bool {
    tap(PROBE_MASK)
}

/// Whether macOS grants this process Accessibility, by the probe tap.
/// Silent: raises no prompt.
#[cfg(target_os = "macos")]
pub fn active_tap_permitted() -> bool {
    permitted_by(create_active_tap)
}

/// Creates an active tap for the events in `mask` at the tail of the
/// session's taps, then disables, invalidates and releases it; whether
/// macOS allowed it. The tap is never added to a run loop, so its callback
/// never runs.
#[cfg(target_os = "macos")]
pub fn create_active_tap(mask: u64) -> bool {
    use std::ffi::c_void;

    extern "C" fn pass(
        _proxy: *mut c_void,
        _ty: u32,
        event: *mut c_void,
        _info: *mut c_void,
    ) -> *mut c_void {
        event
    }

    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGEventTapCreate(
            tap: u32,
            place: u32,
            options: u32,
            events_of_interest: u64,
            callback: extern "C" fn(*mut c_void, u32, *mut c_void, *mut c_void) -> *mut c_void,
            user_info: *mut c_void,
        ) -> *mut c_void;
        fn CGEventTapEnable(tap: *mut c_void, enable: bool);
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFMachPortInvalidate(port: *mut c_void);
        fn CFRelease(cf: *const c_void);
    }

    const SESSION: u32 = 1; // kCGSessionEventTap
    const TAIL_APPEND: u32 = 1; // kCGTailAppendEventTap
    const ACTIVE: u32 = 0; // kCGEventTapOptionDefault
    // SAFETY: creates a tap whose callback never runs (its port is never
    // scheduled), then disables, invalidates and releases the port it
    // returned, which this function alone holds.
    unsafe {
        let port = CGEventTapCreate(
            SESSION,
            TAIL_APPEND,
            ACTIVE,
            mask,
            pass,
            std::ptr::null_mut(),
        );
        if port.is_null() {
            return false;
        }
        CGEventTapEnable(port, false);
        CFMachPortInvalidate(port);
        CFRelease(port as *const c_void);
        true
    }
}

/// Remembers the last answer a check gave, so that it is logged when it
/// changes rather than on every check.
#[derive(Debug, Default)]
pub struct LastAnswer(std::sync::atomic::AtomicU8);

impl LastAnswer {
    pub const fn new() -> Self {
        Self(std::sync::atomic::AtomicU8::new(0))
    }

    /// Records `granted`; true when it differs from the answer recorded
    /// before, or is the first.
    pub fn changed(&self, granted: bool) -> bool {
        let now = if granted { 1 } else { 2 };
        self.0.swap(now, std::sync::atomic::Ordering::SeqCst) != now
    }
}

#[cfg(test)]
mod tests {
    use super::{LastAnswer, permitted_by};
    use std::cell::RefCell;

    // LEDGER T2430 | class B | 1 return value: permitted_by, with the masks asked recorded
    /// The probe asks for no events, so WindowServer never routes one
    /// through it. A key-down mask put the probe in the key-down path.
    #[test]
    fn the_probe_tap_asks_for_no_events() {
        let asked = RefCell::new(Vec::new());
        let answers: Vec<bool> = [true, false]
            .into_iter()
            .map(|allowed| {
                permitted_by(|mask| {
                    asked.borrow_mut().push(mask);
                    allowed
                })
            })
            .collect();
        assert_eq!(
            (answers, asked.into_inner()),
            (vec![true, false], vec![0, 0]),
            "(answers, masks asked): the probe must report what macOS answered and \
             ask for no events at all"
        );
    }

    // LEDGER T2431 | class B | 1 return value: LastAnswer::changed
    #[test]
    fn an_answer_is_new_only_when_it_changes() {
        let last = LastAnswer::new();
        let seen: Vec<bool> = [true, true, true, false, false, true]
            .into_iter()
            .map(|a| last.changed(a))
            .collect();
        assert_eq!(seen, [true, false, false, true, false, true]);
    }
}
