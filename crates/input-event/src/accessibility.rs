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
//!
//! No event tap is created until the [`Gate`] opens (#243). Measured on
//! macOS 27.2 after the permission was reset: a daemon that created the
//! probe tap at launch raised macOS's "would like to control this Mac"
//! dialog before the user had clicked anything, which #169 rules out.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// The events the probe tap asks for: none (`CGEventMask` 0).
pub const PROBE_MASK: u64 = 0;

/// How many probes in a row must be refused before a running capture or
/// emulation is stopped for a revocation. One refusal is not acted on, so a
/// single spurious one (a session switch, sleep and wake, WindowServer
/// starting again; whether any of these refuses is unverified) costs
/// nothing; a revocation is acted on one check later, within about 4 s at
/// one check every 2 s. A grant is acted on at once.
pub const REFUSALS_BEFORE_REVOKED: u32 = 2;

/// Whether `tap`, which creates an active event tap for the events in a
/// mask and reports whether macOS allowed it, is allowed the probe tap. The
/// one place the probe's mask is chosen, whoever creates the tap.
pub fn permitted_by(tap: impl FnOnce(u64) -> bool) -> bool {
    tap(PROBE_MASK)
}

/// Whether this process may create an event tap (#243, #169).
///
/// Closed as a process starts. While it is closed, Accessibility is
/// answered by `AXIsProcessTrusted` alone, which never prompts and is
/// accurate in a process that has just started; it can keep that first
/// answer for the life of the process (#240), which is why, once the gate
/// is open, the probe tap answers instead. The gate opens, for the rest of
/// the process's life, when that silent check says Accessibility is granted
/// or when the user asks for it by clicking enable input or open settings.
/// A revocation is then seen by the probe; a process that held the grant
/// raised no dialog when it was reset while it probed (measured 2026-10-09).
#[derive(Debug)]
pub struct Gate {
    state: AtomicU8,
    /// A probe has been permitted: later probes are routine.
    permitted: AtomicBool,
    /// The first refusal by the silent check has been logged.
    told: AtomicBool,
}

const CLOSED: u8 = 0;
const GRANTED: u8 = 1;
const CONSENTED: u8 = 2;

/// The gate of this process. Capture, emulation and the daemon's
/// permission watch all ask through it, and the daemon opens it when the
/// app says the user asked.
pub static GATE: Gate = Gate::new();

impl Default for Gate {
    fn default() -> Self {
        Self::new()
    }
}

impl Gate {
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(CLOSED),
            permitted: AtomicBool::new(false),
            told: AtomicBool::new(false),
        }
    }

    /// The user asked for the permission: event taps may be created from
    /// now on. True when this opened the gate.
    pub fn consent(&self) -> bool {
        let opened = self
            .state
            .compare_exchange(CLOSED, CONSENTED, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
        if opened {
            log::info!(
                "Accessibility gate: the user asked; event taps may be created from now on \
                 (consented)"
            );
        }
        opened
    }

    /// Whether an event tap may be created.
    pub fn is_open(&self) -> bool {
        self.state.load(Ordering::SeqCst) != CLOSED
    }

    /// Why a tap may be created, as logged beside each one: `None` while
    /// closed.
    pub fn reason(&self) -> Option<&'static str> {
        match self.state.load(Ordering::SeqCst) {
            CLOSED => None,
            _ if self.permitted.load(Ordering::SeqCst) => Some("routine"),
            GRANTED => Some("startup-granted"),
            _ => Some("consented"),
        }
    }

    /// Whether this process has Accessibility, for `who`. While the gate is
    /// closed `trusted` answers, and must not prompt (`AXIsProcessTrusted`
    /// without options); a yes opens the gate. Once it is open, the probe
    /// tap `tap` creates answers ([`permitted_by`]).
    pub fn accessibility(
        &self,
        who: &str,
        trusted: impl FnOnce() -> bool,
        tap: impl FnOnce(u64) -> bool,
    ) -> bool {
        if !self.is_open() {
            if !trusted() {
                if !self.told.swap(true, Ordering::SeqCst) {
                    log::info!(
                        "Accessibility gate: {who}: AXIsProcessTrusted says not granted; no \
                         event tap is created until the user clicks enable input or open \
                         settings"
                    );
                }
                return false;
            }
            if self
                .state
                .compare_exchange(CLOSED, GRANTED, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                log::info!(
                    "Accessibility gate: {who}: AXIsProcessTrusted says granted; event taps \
                     may be created from now on (startup-granted)"
                );
            }
        }
        let reason = self.reason().unwrap_or("closed");
        if reason == "routine" {
            log::trace!("Accessibility gate: {who}: creating the probe tap ({reason})");
        } else {
            log::debug!("Accessibility gate: {who}: creating the probe tap ({reason})");
        }
        let permitted = permitted_by(tap);
        if permitted && !self.permitted.swap(true, Ordering::SeqCst) {
            log::debug!("Accessibility gate: {who}: the probe tap was permitted");
        }
        permitted
    }
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
    use super::{Gate, LastAnswer, permitted_by};
    use std::cell::RefCell;

    // LEDGER T2450 | class B | 1 return value of Gate::accessibility + 6 taps it created, silent checks asked, Gate::reason
    /// A process the silent check says lacks Accessibility creates no tap
    /// until the user asks; then the probe decides. One the silent check
    /// says has it may probe at once (#243).
    #[test]
    fn no_tap_is_created_before_the_silent_check_or_the_user_allows_it() {
        let (taps, silent) = (RefCell::new(0), RefCell::new(0));
        let ask = |gate: &Gate, trusted: bool, permitted: bool| {
            gate.accessibility(
                "test",
                || {
                    *silent.borrow_mut() += 1;
                    trusted
                },
                |_| {
                    *taps.borrow_mut() += 1;
                    permitted
                },
            )
        };
        let missing = Gate::new();
        let before: Vec<bool> = (0..20).map(|_| ask(&missing, false, true)).collect();
        let untouched = (*taps.borrow(), *silent.borrow(), missing.reason());
        missing.consent();
        let after = [
            missing.reason(),
            Some(if ask(&missing, false, true) { "y" } else { "n" }),
            Some(if ask(&missing, false, false) {
                "y"
            } else {
                "n"
            }),
            missing.reason(),
        ];
        let granted = Gate::new();
        let fresh = [ask(&granted, true, true), ask(&granted, false, true)];
        assert_eq!(
            (
                before.iter().any(|&b| b),
                untouched,
                after,
                fresh,
                granted.reason(),
                *taps.borrow()
            ),
            (
                false,
                (0, 20, None),
                [Some("consented"), Some("y"), Some("n"), Some("routine")],
                [true, true],
                Some("routine"),
                4
            ),
            "(any yes before consent, (taps, silent checks, reason) before consent, \
             reason then answers after consent, a granted process's answers, its \
             reason, taps in all)"
        );
    }

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
