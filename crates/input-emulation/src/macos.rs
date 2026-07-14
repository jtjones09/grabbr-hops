use super::{EdgeSide, Emulation, EmulationHandle, error::EmulationError};
use async_trait::async_trait;
use bitflags::bitflags;
use core_graphics::base::CGFloat;
use core_graphics::display::{
    CGDirectDisplayID, CGDisplay, CGDisplayBounds, CGGetDisplaysWithRect, CGPoint, CGRect, CGSize,
};
use core_graphics::event::{
    CGEvent, CGEventFlags, CGEventTapLocation, CGEventType, CGKeyCode, CGMouseButton, EventField,
    ScrollEventUnit,
};
use core_graphics::event_source::{CGEventSource, CGEventSourceStateID};
use input_event::{
    BTN_BACK, BTN_FORWARD, BTN_LEFT, BTN_MIDDLE, BTN_RIGHT, Event, KeyboardEvent, PointerEvent,
    scancode,
};
use keycode::{KeyMap, KeyMapping};
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::os::raw::{c_char, c_void};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::{sync::Notify, task::JoinHandle};

use super::error::MacOSEmulationCreationError;

const DEFAULT_REPEAT_DELAY: Duration = Duration::from_millis(500);
const DEFAULT_REPEAT_INTERVAL: Duration = Duration::from_millis(32);
const DOUBLE_CLICK_INTERVAL: Duration = Duration::from_millis(500);

pub(crate) struct MacOSEmulation {
    /// global event source for all events
    event_source: CGEventSource,
    /// task handle for key repeats
    repeat_task: Option<JoinHandle<()>>,
    /// current state of the mouse buttons (tracked by evdev button code)
    pressed_buttons: HashSet<u32>,
    /// button previously pressed (evdev button code)
    previous_button: Option<u32>,
    /// timestamp of previous click (button down)
    previous_button_click: Option<Instant>,
    /// click state, i.e. number of clicks in quick succession
    button_click_state: i64,
    /// current modifier state
    modifier_state: Rc<Cell<XMods>>,
    /// notify to cancel key repeats
    notify_repeat_task: Arc<Notify>,
    /// last observed secure-input state, so we log only on the transition into it
    secure_input_prev: Cell<bool>,
    /// IOHIDSystem connection, opened once at startup. Used for media/consumer
    /// keys (NX_SYSDEFINED) always, and for the modifier path when `hid_modifiers`
    /// is set. None if the connection could not be opened (→ CGEvent only).
    hid_connect: Option<u32>,
    /// `LAN_MOUSE_HID_MODIFIERS`: route modifiers via IOHIDPostEvent on native
    /// focus (vs CGEvent device bits). Media keys are unaffected by this.
    hid_modifiers: bool,
    /// Cached "is the focused window a VM guest", short TTL, so the per-modifier
    /// window lookup stays cheap.
    vm_guest_cache: Cell<Option<(Instant, bool)>>,
    /// Last focused-window owner name we logged, so we log only on change.
    last_owner: RefCell<Option<String>>,
    /// IOPMAssertion id that keeps this Mac from idle-sleeping while it is the
    /// receiver (an asleep Mac is unreachable over the KVM). None if not held.
    power_assertion: Option<u32>,
    /// Reusable IOPMAssertionDeclareUserActivity id (0 = none yet) — wakes the
    /// display on incoming remote input (synthetic CGEvents alone don't wake it).
    user_activity_id: Cell<u32>,
    /// Throttle so we don't call DeclareUserActivity on every motion event.
    last_user_activity: Cell<Option<Instant>>,
    /// Adaptive edge crossing (intent detector) — integrates the outward motion
    /// the clamp discards at a screen edge; a deliberate push signals a
    /// cross-back. See [`EdgePressureDetector`].
    edge_pressure: EdgePressureDetector,
    /// Edge signalled by the detector, waiting to be collected via
    /// [`Emulation::take_edge_push`] after the current `consume`.
    pending_edge_push: Option<EdgeSide>,
    // --- Trueloop Phase A: passive divergence probe (HOPS_TRUELOOP_PROBE, default
    // off). Measures (integral of REQUESTED unclamped deltas) − get_mouse_location():
    // the accumulated clamp discard — how far the OS held the cursor from where we
    // asked. On a KVM receiver the host cursor IS the clamp result, so this is
    // nonzero *only* at a screen edge (guest-accel moves the guest cursor via the
    // delta field and is invisible to a host readback — out of scope for Phase A).
    // Receiver-only diagnostic; gates the Trueloop demo.
    probe_enabled: bool,
    probe_integral: Cell<Option<(f64, f64)>>, // running sum of unclamped requested deltas, anchored per visit
    probe_peak_offset: Cell<f64>,             // per-window max |divergence| (peak net clamp offset)
    probe_last_div: Cell<f64>,                // most-recent divergence magnitude
    probe_win_start_div: Cell<Option<f64>>,   // divergence at the start of the current window
    probe_report_at: Cell<Option<Instant>>,
    // per-window travel + speed — the mechanism fingerprint. If the OS accelerates
    // our injected motion, actual travel > requested travel (ratio > 1) and the
    // ratio rises with speed. Pure edge-clamp leaves ratio ~1 mid-screen.
    probe_req_travel: Cell<f64>,              // Σ|requested delta| this window
    probe_act_travel: Cell<f64>,              // Σ|actual cursor move| this window
    probe_prev_pos: Cell<Option<(f64, f64)>>, // last readback, for actual travel
    probe_peak_speed: Cell<f64>,              // max |delta|/dt this window (px/s)
    probe_last_evt: Cell<Option<Instant>>,    // last event time, for dt
}

/// Maps an evdev button code to the CGEventType used for drag events.
fn drag_event_type(button: u32) -> CGEventType {
    match button {
        BTN_LEFT => CGEventType::LeftMouseDragged,
        BTN_RIGHT => CGEventType::RightMouseDragged,
        // middle, back, forward, and any other button all use OtherMouseDragged
        _ => CGEventType::OtherMouseDragged,
    }
}

// SAFETY: MacOSEmulation runs entirely on one thread — the emulation task is
// driven via tokio's `spawn_local` inside a current-thread runtime / `LocalSet`
// (see src/main.rs), so the `!Sync` interior-mutability fields (Cell/RefCell/Rc)
// and the raw CG/IOKit handles are never accessed concurrently. The `Send` bound
// is required because `Emulation` is a `Send` supertrait stored as a boxed trait
// object; the value is constructed, used, and dropped on that single thread.
unsafe impl Send for MacOSEmulation {}

impl MacOSEmulation {
    pub(crate) fn new() -> Result<Self, MacOSEmulationCreationError> {
        request_macos_emulation_permissions()?;

        let event_source = CGEventSource::new(CGEventSourceStateID::CombinedSessionState)
            .map_err(|_| MacOSEmulationCreationError::EventSourceCreation)?;
        // The IOHIDSystem connection is needed for media/consumer keys
        // (NX_SYSDEFINED) regardless of mode, so open it once up front.
        // LAN_MOUSE_HID_MODIFIERS additionally routes *modifiers* via
        // IOHIDPostEvent on native focus (smoother, wakes the display); VM-guest
        // focus always uses the CGEvent device-bit path.
        let hid_connect = open_hid_connection();
        let hid_modifiers = std::env::var_os("LAN_MOUSE_HID_MODIFIERS").is_some();
        Ok(Self {
            event_source,
            pressed_buttons: HashSet::new(),
            previous_button: None,
            previous_button_click: None,
            button_click_state: 0,
            repeat_task: None,
            notify_repeat_task: Arc::new(Notify::new()),
            modifier_state: Rc::new(Cell::new(XMods::empty())),
            secure_input_prev: Cell::new(false),
            hid_connect,
            hid_modifiers,
            vm_guest_cache: Cell::new(None),
            last_owner: RefCell::new(None),
            power_assertion: create_power_assertion(),
            user_activity_id: Cell::new(0),
            last_user_activity: Cell::new(None),
            edge_pressure: EdgePressureDetector::from_env(),
            pending_edge_push: None,
            probe_enabled: std::env::var_os("HOPS_TRUELOOP_PROBE").is_some(),
            probe_integral: Cell::new(None),
            probe_peak_offset: Cell::new(0.0),
            probe_last_div: Cell::new(0.0),
            probe_win_start_div: Cell::new(None),
            probe_report_at: Cell::new(None),
            probe_req_travel: Cell::new(0.0),
            probe_act_travel: Cell::new(0.0),
            probe_prev_pos: Cell::new(None),
            probe_peak_speed: Cell::new(0.0),
            probe_last_evt: Cell::new(None),
        })
    }

    fn get_mouse_location(&self) -> Option<CGPoint> {
        let event: CGEvent = CGEvent::new(self.event_source.clone()).ok()?;
        Some(event.location())
    }

    /// Trueloop Phase A: log the probe once per active second. `peak-offset` = the
    /// per-window max |divergence| (px the OS held the cursor away from where we asked);
    /// `drift` = its rate of change (px/min, event-rate-independent). ~0 on open desktop,
    /// climbs into a screen edge, negative on pull-back, leaving a persistent residual.
    fn probe_flush(&self) {
        let now = Instant::now();
        let report_at = match self.probe_report_at.get() {
            Some(t) => t,
            None => {
                self.probe_report_at.set(Some(now));
                return;
            }
        };
        let elapsed = now.duration_since(report_at).as_secs_f64();
        if elapsed < 1.0 {
            return;
        }
        if let Some(win_start_div) = self.probe_win_start_div.get() {
            let drift = (self.probe_last_div.get() - win_start_div) / elapsed * 60.0;
            let req = self.probe_req_travel.get();
            // ratio = actual cursor travel / requested travel. ~1 => we command the
            // cursor 1:1; >1 => the OS amplifies our motion (acceleration).
            let ratio = if req > 1.0 { self.probe_act_travel.get() / req } else { 0.0 };
            log::info!(
                "[trueloop] peak-offset {:.1}px | drift {:+.1}px/min | ratio {:.3} (act/req) | peak-vel {:.0}px/s",
                self.probe_peak_offset.get(),
                drift,
                ratio,
                self.probe_peak_speed.get()
            );
        }
        // reset the window; peak carries the current divergence forward
        self.probe_peak_offset.set(self.probe_last_div.get());
        self.probe_win_start_div.set(None);
        self.probe_report_at.set(Some(now));
        self.probe_req_travel.set(0.0);
        self.probe_act_travel.set(0.0);
        self.probe_peak_speed.set(0.0);
    }

    /// Wake the display (and reset the idle-sleep timer) on incoming remote
    /// input. Synthetic CGEvents deliver input to the system but do NOT wake a
    /// sleeping display — only real HID activity or this assertion does. Throttled
    /// so we don't hammer IOKit on every motion event.
    fn declare_user_activity(&self) {
        let now = Instant::now();
        if let Some(last) = self.last_user_activity.get() {
            if now.duration_since(last).as_millis() < 500 {
                return;
            }
        }
        self.last_user_activity.set(Some(now));
        use core_foundation::base::TCFType;
        use core_foundation::string::CFString;
        let name = CFString::new("hops remote input");
        let mut id = self.user_activity_id.get();
        // SAFETY: `name` outlives the synchronous call; `id` is a valid in/out
        // pointer (0 on first call → creates; reused id later → extends).
        let r = unsafe {
            IOPMAssertionDeclareUserActivity(
                name.as_concrete_TypeRef(),
                0, // kIOPMUserActiveLocal
                &mut id,
            )
        };
        if r == 0 {
            self.user_activity_id.set(id);
        }
    }

    async fn spawn_repeat_task(&mut self, key: u16) {
        // there can only be one repeating key and it's
        // always the last to be pressed
        self.cancel_repeat_task().await;
        // initial key event
        key_event(self.event_source.clone(), key, 1, self.modifier_state.get());
        // repeat task
        let event_source = self.event_source.clone();
        let notify = self.notify_repeat_task.clone();
        let modifiers = self.modifier_state.clone();
        let repeat_task = tokio::task::spawn_local(async move {
            let stop = tokio::select! {
                _ = tokio::time::sleep(DEFAULT_REPEAT_DELAY) => false,
                _ = notify.notified() => true,
            };
            if !stop {
                loop {
                    key_event(event_source.clone(), key, 1, modifiers.get());
                    tokio::select! {
                        _ = tokio::time::sleep(DEFAULT_REPEAT_INTERVAL) => {},
                        _ = notify.notified() => break,
                    }
                }
            }
            // Always release the key with the correct CGKeyCode, regardless of
            // whether the repeat loop ran. This matches @feschber's review
            // request: "still release the key repeat task but with the correct
            // code."
            //
            // Do NOT call update_modifiers here: `key` is a Mac CGKeyCode but
            // update_modifiers expects a Linux evdev scancode, and the two
            // codespaces collide (e.g. Mac LeftShift=56 == Linux KeyLeftAlt=56,
            // Mac Down=125 == Linux KeyLeftMeta=125), corrupting modifier
            // state for chords like Shift+Option+X or Cmd+Down. Modifier state
            // is owned by the main consume() loop, which already calls
            // update_modifiers with the correct Linux scancode on the real key
            // release event from the client.
            key_event(event_source.clone(), key, 0, modifiers.get());
        });
        self.repeat_task = Some(repeat_task);
    }

    async fn cancel_repeat_task(&mut self) {
        if let Some(task) = self.repeat_task.take() {
            // notify_one (NOT notify_waiters): the repeat task spends most of its
            // time posting key events, not parked on `.notified()`. notify_waiters
            // only wakes a currently-parked waiter and drops the signal otherwise,
            // so a cancel that landed mid-keypress was silently lost and the repeat
            // loop ran forever (runaway key autorepeat / stuck key). notify_one
            // stores a permit, so the task sees the cancel at its next checkpoint
            // and always stops and releases the key.
            self.notify_repeat_task.notify_one();
            let _ = task.await;
        }
    }

    /// Diagnose (and, when `reconcile` is set, self-heal) modifier-state coherence.
    ///
    /// Compares the modifier state lan-mouse intends (`modifier_state`) with the
    /// flags the OS currently has applied (`CGEventSourceFlagsState`). A stuck
    /// modifier — a flag the OS still holds that we no longer intend — is the
    /// signature of the "ghosting" bug: it turns the next keystroke into a silent
    /// chord. When `reconcile` is set it re-asserts the intended state with a
    /// real-keycode `FlagsChanged`, healing the drift in one event. Only the
    /// stuck-ON direction is healed; the "missing" direction (common during
    /// VM-guest focus) is deliberately ignored — see the body.
    fn coherence_pass(&self, ctx: &str, reconcile: bool) {
        let mods = self.modifier_state.get();
        let intended = to_cgevent_flags(mods).bits() & MANAGED_FLAG_MASK;
        let os = os_flags_state() & MANAGED_FLAG_MASK;

        // Secure input (e.g. a focused password field) makes macOS suppress
        // synthetic keystrokes; log once on the transition into it.
        let secure = secure_input_active();
        if secure && !self.secure_input_prev.get() {
            log::debug!(
                "{ctx}: secure event input active; synthetic keystrokes may be suppressed (password field?)"
            );
        }
        self.secure_input_prev.set(secure);

        let stuck = os & !intended; // OS holds modifiers we do NOT intend — the ghosting bug
        let missing = intended & !os; // we intend modifiers the OS lacks

        // Only the stuck-ON direction is healed. The "missing" direction (we
        // intend a modifier the OS lacks) fires constantly during VM-guest focus —
        // the guest owns the modifier state, so the host session reads 0 even
        // though the modifier was injected correctly — and re-asserting it just
        // spams the guest with FlagsChanged. It is also usually transient on the
        // host, so it is never reconciled.
        if stuck == 0 {
            if missing != 0 {
                log::trace!(
                    "{ctx}: modifier 0x{missing:06x} intended but unapplied (guest focus?)"
                );
            }
            return;
        }
        if !reconcile {
            log::debug!(
                "{ctx}: stuck modifier 0x{stuck:06x} (os=0x{os:06x} intended=0x{intended:06x})"
            );
            return;
        }
        // Re-assert the intended state, which drops the bits the OS holds but we
        // no longer intend, healing the drift in one event.
        let key = representative_keycode(stuck);
        post_flags_changed_event(
            self.event_source.clone(),
            key,
            modifier_flags_changed_flags(mods),
        );
        log::debug!("{ctx}: reconciled stuck modifier 0x{stuck:06x}");
    }

    /// Posts a modifier `FlagsChanged`, choosing the injection path:
    /// - `LAN_MOUSE_HID_MODIFIERS` unset → CGEvent device bits (#460), the default.
    /// - set + native focus → IOHIDPostEvent (smoother, wakes the display).
    /// - set + VM-guest focus → CGEvent device bits (IOHIDPostEvent does not reach
    ///   guests, so fall back to the path that does).
    fn post_modifier(&self, key: u16, depressed: XMods) {
        if self.hid_modifiers {
            if let Some(connect) = self.hid_connect {
                if !self.target_is_vm_guest() {
                    let nx_flags = (modifier_flags_changed_flags(depressed).bits()
                        & !CGEventFlags::CGEventFlagNonCoalesced.bits())
                        as u32;
                    if post_hid_flags_changed(connect, key, nx_flags) {
                        return;
                    }
                }
            }
        }
        modifier_key_event(self.event_source.clone(), key, depressed);
    }

    /// Whether the focused window belongs to a VM hypervisor, cached with a short
    /// TTL (the window lookup is too heavy to run per keystroke). Logs on
    /// transition so the native↔guest switch is visible at the default level.
    fn target_is_vm_guest(&self) -> bool {
        let now = Instant::now();
        if let Some((when, val)) = self.vm_guest_cache.get() {
            if now.duration_since(when) < VM_DETECT_TTL {
                return val;
            }
        }
        let info = frontmost_window_owner();
        let path = info.as_ref().and_then(|(_, pid)| pid_exe_path(*pid));
        let val = match path.as_deref() {
            Some(p) => is_hypervisor_path(p),
            // Focus/owner lookup failed (transient None). Flipping to "native"
            // here would momentarily re-apply host natural-scroll (inverting
            // guest scroll) and bounce modifier routing. Reuse the last known
            // verdict instead; fall back to native only if we have none yet.
            None => self.vm_guest_cache.get().map(|(_, v)| v).unwrap_or(false),
        };
        // Log when the focused window changes — owner name + exe path + route.
        {
            let owner = info.map(|(name, _)| name).unwrap_or_default();
            let mut last = self.last_owner.borrow_mut();
            if last.as_deref() != Some(owner.as_str()) {
                log::debug!(
                    "focus owner={:?} path={:?} → {}",
                    owner,
                    path.as_deref().unwrap_or("<none>"),
                    if val {
                        "VM guest (CGEvent)"
                    } else {
                        "native (HID)"
                    }
                );
                *last = Some(owner);
            }
        }
        self.vm_guest_cache.set(Some((now, val)));
        val
    }
}

impl Drop for MacOSEmulation {
    fn drop(&mut self) {
        // Abort the key-repeat task: dropping a JoinHandle only DETACHES it, so a
        // backend recreation (reconnect) would otherwise leave the old repeat task
        // posting key events forever on the shared LocalSet.
        if let Some(task) = self.repeat_task.take() {
            task.abort();
        }
        // Release the IOHIDSystem connection if we opened one. Process-lifetime
        // ownership means this rarely matters in practice, but it keeps the
        // mach port tidy if the emulation backend is ever recreated.
        if let Some(connect) = self.hid_connect {
            unsafe { IOServiceClose(connect) };
        }
        // Release the power assertion so the Mac can sleep normally again.
        if let Some(id) = self.power_assertion {
            unsafe { IOPMAssertionRelease(id) };
        }
    }
}

fn request_macos_emulation_permissions() -> Result<(), MacOSEmulationCreationError> {
    // Request both permissions up front so the user sees both TCC prompts
    // on the first launch. See the matching comment in crates/input-capture/src/
    // macos.rs::request_macos_capture_permissions for the rationale.
    let accessibility = request_accessibility_permission();
    let input_control = request_input_control_permission();

    if !accessibility {
        guide_to_settings();
        return Err(MacOSEmulationCreationError::AccessibilityPermission);
    }
    if !input_control {
        guide_to_settings();
        return Err(MacOSEmulationCreationError::InputControlPermission);
    }
    Ok(())
}

/// On a missing grant, print an actionable message naming the exact binary and
/// open the right System Settings pane — once per process. A backgrounded CLI's
/// TCC dialog is unreliable, so we steer the user straight to the toggle instead
/// of relying on a prompt that may never surface.
fn guide_to_settings() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let exe = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "the hops binary".into());
        log::error!("──────────────────────────────────────────────────────────");
        log::error!("hops can't inject input: a macOS permission is missing.");
        log::error!("Enable BOTH for this exact binary, then re-run the launcher:");
        log::error!("  • Accessibility");
        log::error!("  • Input Monitoring");
        log::error!("  binary: {exe}");
        log::error!("Opening System Settings → Privacy & Security → Accessibility…");
        log::error!("──────────────────────────────────────────────────────────");
        if let Ok(mut child) = std::process::Command::new("open")
            .arg("x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")
            .spawn()
        {
            let _ = child.wait(); // reap; `open` hands off to launchd and exits promptly
        }
    });
}

fn request_accessibility_permission() -> bool {
    // Fire the one-time system Accessibility prompt if not yet granted, then
    // return the current trust state. Ported from the GUI's macos_privacy so a
    // headless / TUI daemon is self-granting — there's no GUI to own the prompt.
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
    // SAFETY: `options` outlives the synchronous call. Normalize the `Boolean`
    // (u8) result with != 0 — materializing a non-canonical byte as Rust `bool` is UB.
    unsafe { AXIsProcessTrustedWithOptions(options.as_concrete_TypeRef() as *const c_void) != 0 }
}

fn request_input_control_permission() -> bool {
    unsafe { CGPreflightPostEventAccess() }
}

#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGPreflightPostEventAccess() -> bool;
    /// Current modifier flags the session is applying (combined hardware +
    /// synthetic). `state_id` is a `CGEventSourceStateID`.
    fn CGEventSourceFlagsState(state_id: i32) -> u64;
}

#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    // Apple declares this `Boolean` (u8), not C `_Bool`; bind as u8 and normalize.
    fn AXIsProcessTrustedWithOptions(options: *const c_void) -> u8;
}

#[link(name = "Carbon", kind = "framework")]
extern "C" {
    /// True when a focused field has enabled secure input (e.g. a password
    /// field), which makes macOS suppress synthetic keystrokes entirely.
    fn IsSecureEventInputEnabled() -> u8;
}

// ---- IOHIDPostEvent (legacy IOKit HID) modifier path -----------------------
//
// Opt-in via LAN_MOUSE_HID_MODIFIERS. Posts modifier FlagsChanged through the
// lower-level IOKit HID layer, which sets the host session's modifier state
// authoritatively (CGEvent releases are sometimes ignored by macOS, leaving a
// stuck modifier). CGEvent is still posted alongside it for VM-guest coverage
// (#460) — IOHIDPostEvent does NOT reach VZVirtualMachineView guests — so this
// is a hybrid, not a replacement.

const NX_FLAGSCHANGED: u32 = 12; // IOLLEvent.h NX_FLAGSCHANGED
const NX_EVENT_DATA_VERSION: u32 = 2; // kNXEventDataVersion
const KIO_HID_PARAM_CONNECT_TYPE: u32 = 1; // kIOHIDParamConnectType

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)] // FFI layout; fields read by the C side
struct IOGPoint {
    x: i16,
    y: i16,
}

// NXEventData.key (IOLLEvent.h). Only key_code is used for FlagsChanged; the
// modifier state itself travels in IOHIDPostEvent's eventFlags argument.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)] // FFI layout; fields read by the C side
struct NXKeyEventData {
    orig_charset: u16,
    repeat: i16,
    charset: u16,
    char_code: u16,
    key_code: u16,
    orig_char_code: u16,
    reserved1: i32,
    keyboard_type: u32,
    reserved2: i32,
    reserved3: i32,
    reserved4: i32,
    reserved5: [i32; 4],
}

// NXEventData is a union; we only fill `key`. sizeof(NXEventData) is 48 B
// (verified against IOLLEvent.h); IOHIDPostEvent reads eventDataVersion's worth
// of bytes from this pointer, so the buffer only needs to be >= that. The pad
// keeps a comfortable margin.
#[repr(C)]
#[allow(dead_code)] // FFI layout; bytes read by the C side
struct NXEventDataBuf {
    key: NXKeyEventData,
    _pad: [u8; 80],
}

#[link(name = "IOKit", kind = "framework")]
extern "C" {
    fn IOServiceMatching(name: *const c_char) -> *mut c_void;
    fn IOServiceGetMatchingService(main_port: u32, matching: *mut c_void) -> u32;
    fn IOServiceOpen(service: u32, owning_task: u32, connect_type: u32, connect: *mut u32) -> i32;
    fn IOServiceClose(connect: u32) -> i32;
    fn IOObjectRelease(object: u32) -> i32;
    fn IOHIDPostEvent(
        connect: u32,
        event_type: u32,
        location: IOGPoint,
        event_data: *const c_void,
        event_data_version: u32,
        event_flags: u32,
        options: u32,
    ) -> i32;
    // Power management: hold an assertion so this Mac doesn't idle-sleep while it
    // is the KVM receiver — an asleep Mac suspends this process and is unreachable
    // over the network until a hardware wake (lid-lift).
    fn IOPMAssertionCreateWithName(
        assertion_type: core_foundation::string::CFStringRef,
        level: u32,
        name: core_foundation::string::CFStringRef,
        assertion_id: *mut u32,
    ) -> i32;
    fn IOPMAssertionRelease(assertion_id: u32) -> i32;
    // Wake the display + reset the idle-sleep timer on incoming remote input.
    // Synthetic CGEvents deliver input to the system but do NOT wake a sleeping
    // display — only real HID activity or this call does.
    fn IOPMAssertionDeclareUserActivity(
        name: core_foundation::string::CFStringRef,
        user_type: u32,
        assertion_id: *mut u32,
    ) -> i32;
}

extern "C" {
    static mach_task_self_: u32;
}

/// Hold an IOPMAssertion so this Mac doesn't idle-sleep while it is the KVM
/// receiver. A fully-asleep Mac suspends hops and is unreachable over the
/// KVM (only a hardware wake / lid-lift brings it back — the exact symptom).
///
/// Default = prevent SYSTEM idle-sleep (`PreventUserIdleSystemSleep`): the
/// system stays awake + reachable while the DISPLAY is free to blank — so the
/// screen goes black, you cross over, and incoming input wakes it (see
/// `declare_user_activity`). This is the Synergy-equivalent behavior, validated
/// on AC (where `pmset sleep` is 0 anyway). `GRABBR_KEEP_AWAKE=display` keeps the
/// display on too (heavier; screen never blanks); `=off` holds no assertion at
/// all (lets the Mac truly sleep — only useful with a WoL-capable wired NIC,
/// which USB-bridged dock ethernet is not).
fn create_power_assertion() -> Option<u32> {
    use core_foundation::base::TCFType;
    use core_foundation::string::CFString;
    let assertion_type = match std::env::var("GRABBR_KEEP_AWAKE").as_deref() {
        // Opt out entirely (let the Mac truly sleep, e.g. for a WoL-capable NIC).
        Ok("off") => {
            log::info!("GRABBR_KEEP_AWAKE=off — holding no power assertion; the Mac may sleep");
            return None;
        }
        // Keep the display on too — the screen never blanks (heavier; opt-in).
        Ok("display") => "PreventUserIdleDisplaySleep",
        // Default: system stays awake, display free to blank (screen goes black,
        // incoming input wakes it). Synergy-equivalent.
        _ => "PreventUserIdleSystemSleep",
    };
    let kind = CFString::new(assertion_type);
    let name = CFString::new("hops KVM receiver active");
    let mut id: u32 = 0;
    const LEVEL_ON: u32 = 255; // kIOPMAssertionLevelOn
    // SAFETY: the CFStrings outlive the synchronous call; `id` is a valid out-ptr.
    let result = unsafe {
        IOPMAssertionCreateWithName(
            kind.as_concrete_TypeRef(),
            LEVEL_ON,
            name.as_concrete_TypeRef(),
            &mut id,
        )
    };
    if result == 0 {
        log::info!("holding power assertion ({assertion_type}) to keep this Mac reachable over the KVM");
        Some(id)
    } else {
        log::warn!("could not hold a power assertion ({result:#x}); the Mac may sleep and become unreachable");
        None
    }
}

/// Opens a connection to `IOHIDSystem` for `IOHIDPostEvent`.
///
/// Returns None (and logs) if the service is missing or the open is refused — the
/// caller then stays on the CGEvent path. Known risk: this legacy connection may
/// be denied on recent macOS; the log line tells us whether it works here.
fn open_hid_connection() -> Option<u32> {
    unsafe {
        let matching = IOServiceMatching(c"IOHIDSystem".as_ptr());
        if matching.is_null() {
            log::warn!("IOHIDSystem: IOServiceMatching returned null");
            return None;
        }
        // 0 = kIOMainPortDefault. IOServiceGetMatchingService consumes a reference
        // to `matching`, so we must not release the dictionary ourselves.
        let service = IOServiceGetMatchingService(0, matching);
        if service == 0 {
            log::warn!("IOHIDSystem service not found");
            return None;
        }
        let mut connect: u32 = 0;
        let kr = IOServiceOpen(
            service,
            mach_task_self_,
            KIO_HID_PARAM_CONNECT_TYPE,
            &mut connect,
        );
        IOObjectRelease(service);
        if kr == 0 && connect != 0 {
            log::info!("IOHIDSystem connection opened (media keys + HID modifier path)");
            Some(connect)
        } else {
            log::warn!("IOServiceOpen(IOHIDSystem) failed: kr=0x{kr:x}; staying on CGEvent");
            None
        }
    }
}

/// Posts a modifier `FlagsChanged` via IOHIDPostEvent. `nx_flags` is the new
/// modifier mask (same bit layout as `CGEventFlags`). Returns false (and logs)
/// on failure.
fn post_hid_flags_changed(connect: u32, key: u16, nx_flags: u32) -> bool {
    let mut data: NXEventDataBuf = unsafe { std::mem::zeroed() };
    data.key.key_code = key;
    let location = IOGPoint { x: 0, y: 0 };
    let kr = unsafe {
        IOHIDPostEvent(
            connect,
            NX_FLAGSCHANGED,
            location,
            &data as *const NXEventDataBuf as *const c_void,
            NX_EVENT_DATA_VERSION,
            nx_flags,
            0,
        )
    };
    if kr != 0 {
        log::warn!("IOHIDPostEvent(FlagsChanged) failed: kr=0x{kr:x}");
    }
    kr == 0
}

// ---- NX_SYSDEFINED media / consumer keys (volume, play/pause, next/prev) ----
//
// macOS media keys are not regular keycodes; they are system-defined
// aux-control-button events. We post them through the same IOHIDSystem
// connection used for the modifier path.

const NX_SYSDEFINED: u32 = 14; // IOLLEvent.h NX_SYSDEFINED
const NX_SUBTYPE_AUX_CONTROL_BUTTONS: i16 = 8;
const NX_KEYTYPE_SOUND_UP: u8 = 0;
const NX_KEYTYPE_SOUND_DOWN: u8 = 1;
const NX_KEYTYPE_MUTE: u8 = 7;
const NX_KEYTYPE_PLAY: u8 = 16;
const NX_KEYTYPE_NEXT: u8 = 17;
const NX_KEYTYPE_PREVIOUS: u8 = 18;

// NXEventData.compound (IOLLEvent.h) — the union member used by NX_SYSDEFINED.
// Padded past sizeof(NXEventData) (48 B), like NXEventDataBuf.
#[repr(C)]
#[allow(dead_code)] // FFI layout; bytes read by the C side
struct NXCompoundEventData {
    reserved: i16,
    sub_type: i16,
    misc_l0: i32,
    misc_l1: i32,
    _pad: [u8; 116],
}

/// Maps an evdev key code to the macOS `NX_KEYTYPE_*` for a media/consumer key,
/// or None if it isn't one we forward as a system-defined event.
fn evdev_to_nx_keytype(evdev: u32) -> Option<u8> {
    Some(match evdev {
        115 => NX_KEYTYPE_SOUND_UP,   // KEY_VOLUMEUP
        114 => NX_KEYTYPE_SOUND_DOWN, // KEY_VOLUMEDOWN
        113 => NX_KEYTYPE_MUTE,       // KEY_MUTE
        164 => NX_KEYTYPE_PLAY,       // KEY_PLAYPAUSE
        163 => NX_KEYTYPE_NEXT,       // KEY_NEXTSONG
        165 => NX_KEYTYPE_PREVIOUS,   // KEY_PREVIOUSSONG
        _ => return None,
    })
}

/// Posts a system-defined aux-control (media) key event via IOHIDPostEvent.
fn post_hid_media_key(connect: u32, nx_keytype: u8, down: bool) -> bool {
    const NX_KEYDOWN: i32 = 0x0a;
    const NX_KEYUP: i32 = 0x0b;
    let mut data: NXCompoundEventData = unsafe { std::mem::zeroed() };
    data.sub_type = NX_SUBTYPE_AUX_CONTROL_BUTTONS;
    let state = if down { NX_KEYDOWN } else { NX_KEYUP };
    // data1 layout for aux buttons: (keycode << 16) | (event_type << 8).
    data.misc_l0 = (i32::from(nx_keytype) << 16) | (state << 8);
    data.misc_l1 = -1;
    let location = IOGPoint { x: 0, y: 0 };
    let kr = unsafe {
        IOHIDPostEvent(
            connect,
            NX_SYSDEFINED,
            location,
            &data as *const NXCompoundEventData as *const c_void,
            NX_EVENT_DATA_VERSION,
            0,
            0,
        )
    };
    if kr != 0 {
        log::warn!("IOHIDPostEvent(media key {nx_keytype}) failed: kr=0x{kr:x}");
    }
    kr == 0
}

// ---- VM-guest focus detection ----------------------------------------------
//
// IOHIDPostEvent is smooth for native macOS but does NOT reach VM guests; the
// CGEvent device bits (#460) do. We detect whether the focused window belongs to
// a hypervisor and route modifiers accordingly. Detection resolves the focused
// window's owner PID (via CGWindowList) to its executable path (via proc_pidpath)
// and matches known hypervisor app bundles — no Screen Recording needed (that
// only gates window *titles*, not owner PIDs).
//
// Cached briefly so the per-modifier lookup stays cheap; the short TTL bounds how
// long the first chord after a focus switch could take the wrong path.
const VM_DETECT_TTL: Duration = Duration::from_millis(50);

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFArrayGetCount(array: core_foundation::array::CFArrayRef) -> isize;
    fn CFArrayGetValueAtIndex(
        array: core_foundation::array::CFArrayRef,
        idx: isize,
    ) -> *const c_void;
    fn CFDictionaryGetValue(dict: *const c_void, key: *const c_void) -> *const c_void;
    fn CFGetTypeID(cf: *const c_void) -> usize;
    fn CFNumberGetTypeID() -> usize;
    fn CFStringGetTypeID() -> usize;
}

extern "C" {
    // libproc (libSystem): executable path for a process id.
    fn proc_pidpath(pid: i32, buffer: *mut c_void, buffersize: u32) -> i32;
}

/// Whether an executable path belongs to a known macOS hypervisor. We match the
/// *path* (stable) rather than the window owner name — Parallels sets the owner
/// name to the user's VM name (e.g. "macOS VM", "Windows 11"), which is useless
/// for matching.
fn is_hypervisor_path(path: &str) -> bool {
    const MARKERS: [&str; 5] = [
        "Parallels Desktop.app",
        "VMware Fusion.app",
        "VirtualBox",
        "UTM.app",
        "VirtualBuddy.app",
    ];
    MARKERS.iter().any(|m| path.contains(m))
}

/// Executable path of a process id, via libproc.
fn pid_exe_path(pid: i32) -> Option<String> {
    let mut buf = [0u8; 4096];
    let len = unsafe { proc_pidpath(pid, buf.as_mut_ptr() as *mut c_void, buf.len() as u32) };
    if len <= 0 {
        return None;
    }
    std::str::from_utf8(&buf[..len as usize])
        .ok()
        .map(str::to_string)
}

/// System UI processes that can own a layer-0 window but are never the user's
/// foreground application.
fn is_overlay_owner(name: &str) -> bool {
    const OVERLAYS: [&str; 6] = [
        "Window Server",
        "WindowServer",
        "Spotlight",
        "Notification Center",
        "Control Center",
        "Dock",
    ];
    OVERLAYS.contains(&name)
}

/// (owner name, owner pid) of the frontmost on-screen normal window (layer 0),
/// skipping lan-mouse's own windows and system overlays.
///
/// Each CF value is type-checked (`CFGetTypeID`) before it is cast: the
/// CGWindowList schema guarantees the types, but the check keeps a malformed
/// entry from turning a wrong-typed `CFTypeRef` into UB.
fn frontmost_window_owner() -> Option<(String, i32)> {
    use core_foundation::base::TCFType;
    use core_foundation::number::{CFNumber, CFNumberRef};
    use core_foundation::string::{CFString, CFStringRef};
    use core_graphics::window::{
        copy_window_info, kCGNullWindowID, kCGWindowLayer, kCGWindowListOptionOnScreenOnly,
        kCGWindowOwnerName, kCGWindowOwnerPID,
    };

    let own_pid = std::process::id() as i32;
    let windows = copy_window_info(kCGWindowListOptionOnScreenOnly, kCGNullWindowID)?;
    let array = windows.as_concrete_TypeRef();
    let count = unsafe { CFArrayGetCount(array) };
    let number_id = unsafe { CFNumberGetTypeID() };
    let string_id = unsafe { CFStringGetTypeID() };
    for i in 0..count {
        let dict = unsafe { CFArrayGetValueAtIndex(array, i) };
        if dict.is_null() {
            continue;
        }
        // The frontmost *normal* window is layer 0 (skip menubar/dock/overlays).
        let layer_ref = unsafe { CFDictionaryGetValue(dict, kCGWindowLayer as *const c_void) };
        if layer_ref.is_null() || unsafe { CFGetTypeID(layer_ref) } != number_id {
            continue;
        }
        let layer = unsafe { CFNumber::wrap_under_get_rule(layer_ref as CFNumberRef) }.to_i32();
        if layer != Some(0) {
            continue;
        }
        let pid_ref = unsafe { CFDictionaryGetValue(dict, kCGWindowOwnerPID as *const c_void) };
        if pid_ref.is_null() || unsafe { CFGetTypeID(pid_ref) } != number_id {
            continue;
        }
        let pid = match unsafe { CFNumber::wrap_under_get_rule(pid_ref as CFNumberRef) }.to_i32() {
            Some(p) => p,
            None => continue,
        };
        let name_ref = unsafe { CFDictionaryGetValue(dict, kCGWindowOwnerName as *const c_void) };
        let name = if !name_ref.is_null() && unsafe { CFGetTypeID(name_ref) } == string_id {
            unsafe { CFString::wrap_under_get_rule(name_ref as CFStringRef) }.to_string()
        } else {
            String::new()
        };
        // Skip our own windows and system overlays that can also be layer 0, so we
        // report the actual foreground application.
        if pid == own_pid || is_overlay_owner(&name) {
            continue;
        }
        return Some((name, pid));
    }
    None
}

/// Mac virtual key codes for the four arrow keys.
const MAC_KEY_LEFT: u16 = 0x7B;
const MAC_KEY_RIGHT: u16 = 0x7C;
const MAC_KEY_DOWN: u16 = 0x7D;
const MAC_KEY_UP: u16 = 0x7E;

fn is_arrow_key(key: u16) -> bool {
    matches!(
        key,
        MAC_KEY_LEFT | MAC_KEY_RIGHT | MAC_KEY_DOWN | MAC_KEY_UP
    )
}

fn key_event(event_source: CGEventSource, key: u16, state: u8, modifiers: XMods) {
    let event = match CGEvent::new_keyboard_event(event_source, key, state != 0) {
        Ok(e) => e,
        Err(_) => {
            log::warn!("unable to create key event");
            return;
        }
    };
    let mut flags = to_cgevent_flags(modifiers);
    // Hardware-generated arrow keys on macOS carry NumericPad + SecondaryFn.
    // CGEventTap-based hotkey matchers (e.g. tiling window managers) check
    // these flags to recognize navigation keys; without them synthesized
    // arrow chords fall through to the focused app.
    if is_arrow_key(key) {
        flags |= CGEventFlags::CGEventFlagNumericPad | CGEventFlags::CGEventFlagSecondaryFn;
    }
    event.set_flags(flags);
    event.post(CGEventTapLocation::HID);
    log::trace!("key event: {key} {state}");
}

/// Posts a `FlagsChanged` event for a modifier key.
///
/// The event MUST carry the modifier's real virtual keycode. A bare
/// `CGEvent::new()` defaults to keycode 0 (`kVK_ANSI_A`), so every modifier
/// change arrived in apps as a phantom "A" key event — holding Ctrl registered
/// as Ctrl+A and shortcut recorders captured "A" (issue #450).
///
/// Carrying the real keycode also matters for consumers that track *physical*
/// modifier transitions through AppKit's `flagsChanged(with:)` rather than the
/// flags on the key-down event — notably Apple Virtualization.framework guest
/// views (`VZVirtualMachineView`), which derive guest modifier state from these
/// `FlagsChanged` events. The event is built as a key-down so it gets a valid
/// keycode; the type is then overridden to `FlagsChanged` and the *current*
/// modifier flags (already updated by the caller) describe the new state.
fn modifier_key_event(event_source: CGEventSource, key: u16, depressed: XMods) {
    post_flags_changed_event(event_source, key, modifier_flags_changed_flags(depressed));
    log::trace!("modifier key event: {key} {depressed:?}");
}

// CGEventSourceStateID value (CGEventSource.h).
const CG_SOURCE_COMBINED: i32 = 0; // kCGEventSourceStateCombinedSessionState

// Device-independent CGEventFlags modifier bits (CGEventTypes.h).
const FLAG_ALPHASHIFT: u64 = 0x0001_0000; // Caps Lock
const FLAG_SHIFT: u64 = 0x0002_0000;
const FLAG_CONTROL: u64 = 0x0004_0000;
const FLAG_ALTERNATE: u64 = 0x0008_0000; // Option
const FLAG_COMMAND: u64 = 0x0010_0000;
/// The modifier bits lan-mouse manages; the coherence check masks to these.
const MANAGED_FLAG_MASK: u64 =
    FLAG_ALPHASHIFT | FLAG_SHIFT | FLAG_CONTROL | FLAG_ALTERNATE | FLAG_COMMAND;

/// The modifier flags the OS is currently applying to events (combined session).
fn os_flags_state() -> u64 {
    unsafe { CGEventSourceFlagsState(CG_SOURCE_COMBINED) }
}

/// Whether a focused secure-input field is suppressing synthetic keystrokes.
fn secure_input_active() -> bool {
    unsafe { IsSecureEventInputEnabled() != 0 }
}

/// A representative Mac modifier keycode (Events.h `kVK_*`) to stamp on a
/// corrective `FlagsChanged`. It only needs to be *a* modifier key involved in
/// the change (one of the stuck bits being cleared); the resulting state is
/// carried by the flags, not the keycode. Falls back to Caps Lock.
fn representative_keycode(diff: u64) -> u16 {
    if diff & FLAG_COMMAND != 0 {
        0x37 // kVK_Command
    } else if diff & FLAG_SHIFT != 0 {
        0x38 // kVK_Shift
    } else if diff & FLAG_CONTROL != 0 {
        0x3B // kVK_Control
    } else if diff & FLAG_ALTERNATE != 0 {
        0x3A // kVK_Option
    } else {
        0x39 // kVK_CapsLock
    }
}

/// Posts a `FlagsChanged` event with an explicit keycode and flag set.
///
/// The event MUST carry a real modifier keycode: a bare `CGEvent` defaults to
/// keycode 0 (`kVK_ANSI_A`) and arrives in apps as a phantom "A" (issue #450).
/// The event is built as a key-down so it gets a valid keycode; the type is then
/// overridden to `FlagsChanged` and `flags` describes the new modifier state.
fn post_flags_changed_event(event_source: CGEventSource, key: u16, flags: CGEventFlags) {
    let Ok(event) = CGEvent::new_keyboard_event(event_source, key, true) else {
        log::warn!("could not create flags-changed event");
        return;
    };
    event.set_type(CGEventType::FlagsChanged);
    event.set_flags(flags);
    event.post(CGEventTapLocation::HID);
}

/// Builds the flag set for a modifier `FlagsChanged` event.
///
/// Combines the device-INDEPENDENT modifier word (what ordinary AppKit apps
/// read) with the device-DEPENDENT low-word bits (IOKit `NX_DEVICE*KEYMASK` from
/// `IOKit/hidsystem/IOLLEvent.h`) that a real hardware keyboard sets.
///
/// This matters for Apple Virtualization.framework guest views
/// (`VZVirtualMachineView`, used by UTM's Apple backend, Parallels' macOS
/// guests, VirtualBuddy, etc.): they derive the guest's modifier state from the
/// `flagsChanged(with:)` responder method and read the device-dependent low
/// word, not the per-key flags. macOS does NOT synthesize the low-word bits for
/// posted (synthetic) events, so until we set them ourselves Cmd/Ctrl/Shift/Opt
/// chords reached the guest unmodified (Shift+2 → "2", Cmd+C did nothing).
///
/// Ordinary apps mask incoming events to the device-independent word
/// (`deviceIndependentFlagsMask`) and ignore these bits, so emitting them is
/// hardware-faithful and safe for every app — no VM/bundle-id detection is
/// required. See issue #450 and https://developer.apple.com/forums/thread/766014
fn modifier_flags_changed_flags(depressed: XMods) -> CGEventFlags {
    // Device-dependent left/right modifier bits (IOLLEvent.h). lan-mouse collapses
    // left and right modifiers into a single mask, so we emit the left-hand device
    // bit; AltGr (Mod5 / ISO_Level3_Shift) is physically the right Alt, so it maps
    // to the right Option bit.
    const NX_DEVICE_L_CTRL: u64 = 0x0000_0001;
    const NX_DEVICE_L_SHIFT: u64 = 0x0000_0002;
    const NX_DEVICE_L_CMD: u64 = 0x0000_0008;
    const NX_DEVICE_L_ALT: u64 = 0x0000_0020;
    const NX_DEVICE_R_ALT: u64 = 0x0000_0040;

    let mut device_bits: u64 = 0;
    if depressed.contains(XMods::ShiftMask) {
        device_bits |= NX_DEVICE_L_SHIFT;
    }
    if depressed.contains(XMods::ControlMask) {
        device_bits |= NX_DEVICE_L_CTRL;
    }
    if depressed.contains(XMods::Mod1Mask) {
        device_bits |= NX_DEVICE_L_ALT;
    }
    if depressed.contains(XMods::Mod5Mask) {
        device_bits |= NX_DEVICE_R_ALT;
    }
    if depressed.contains(XMods::Mod4Mask) {
        device_bits |= NX_DEVICE_L_CMD;
    }

    // CGEventFlagNonCoalesced is bit 8 (0x100), the marker a real hardware
    // FlagsChanged carries on both press and release; VZ expects it present.
    let flags = to_cgevent_flags(depressed) | CGEventFlags::CGEventFlagNonCoalesced;
    CGEventFlags::from_bits_retain(flags.bits() | device_bits)
}

/// Reads the global "natural scrolling" preference (`com.apple.swipescrolldirection`).
///
/// macOS applies this preference to scroll events from *real* devices but NOT to
/// synthetic `CGEvent`s, so injected scrolling ignores it and feels backwards on
/// a Mac whose owner uses the default (natural) setting. We read the preference
/// ourselves and flip the sign so injected scrolling matches what a physical
/// trackpad/mouse would do on *this* Mac — i.e. we honour the receiver's own
/// preference rather than inheriting the sender's scroll convention.
///
/// An absent or non-boolean key means `true` (the modern macOS default). A change
/// to the setting is picked up on the next scroll event.
fn natural_scroll_enabled() -> bool {
    use core_foundation::base::TCFType;
    use core_foundation::string::CFString;
    use core_foundation_sys::base::Boolean;
    use core_foundation_sys::preferences::{
        CFPreferencesGetAppBooleanValue, kCFPreferencesAnyApplication,
    };

    let key = CFString::new("com.apple.swipescrolldirection");
    let mut exists: Boolean = 0;
    // SAFETY: `key` outlives the call; kCFPreferencesAnyApplication is a CF constant.
    let enabled = unsafe {
        CFPreferencesGetAppBooleanValue(
            key.as_concrete_TypeRef(),
            kCFPreferencesAnyApplication,
            &mut exists,
        )
    };
    // Absent / non-boolean key => modern macOS default is natural scrolling.
    if exists != 0 { enabled != 0 } else { true }
}

/// Applies the receiver's natural-scroll preference to a scroll delta.
///
/// `saturating_neg` guards against a malformed `i32::MIN` arriving from the wire
/// (plain negation of `i32::MIN` would overflow).
fn apply_natural_scroll(value: i32) -> i32 {
    if natural_scroll_enabled() {
        value.saturating_neg()
    } else {
        value
    }
}

fn get_display_at_point(x: CGFloat, y: CGFloat) -> Option<CGDirectDisplayID> {
    let mut displays: [CGDirectDisplayID; 16] = [0; 16];
    let mut display_count: u32 = 0;
    let rect = CGRect::new(&CGPoint::new(x, y), &CGSize::new(0.0, 0.0));

    let error = unsafe {
        CGGetDisplaysWithRect(
            rect,
            1,
            displays.as_mut_ptr(),
            &mut display_count as *mut u32,
        )
    };

    if error != 0 {
        log::warn!("error getting displays at point ({x}, {y}): {error}");
        return Option::None;
    }

    if display_count == 0 {
        log::debug!("no displays found at point ({x}, {y})");
        return Option::None;
    }

    displays.first().copied()
}

fn get_display_bounds(display: CGDirectDisplayID) -> (CGFloat, CGFloat, CGFloat, CGFloat) {
    unsafe {
        let bounds = CGDisplayBounds(display);
        let min_x = bounds.origin.x;
        let max_x = bounds.origin.x + bounds.size.width;
        let min_y = bounds.origin.y;
        let max_y = bounds.origin.y + bounds.size.height;
        (min_x as f64, min_y as f64, max_x as f64, max_y as f64)
    }
}

/// Adaptive edge crossing — rung 1 (intent/momentum) + rung 2 (self-tuning).
///
/// Why: the receiver clamps the injected cursor to the display bounds
/// ([`clamp_to_screen_space`], `max - 1`), so the cursor can never occupy the
/// capture-side barrier coordinate at the union edge (`>= max`) — and macOS
/// suppresses the bridging delta after warps. Live-confirmed 2026-07-07: a
/// hard flick pins the cursor at exactly `max_x - 1` and the barrier never
/// fires. So don't use a position tripwire at all: integrate the *blocked*
/// outward motion — the part of each Motion delta the clamp discards — into a
/// per-edge "pressure". A deliberate push accumulates past the threshold and
/// signals a cross-back; letting go ends the gesture and the pressure resets.
/// Coordinate-free by construction (live display bounds + relative motion
/// only), so it works for any screen size, DPI, or arrangement. Design:
/// nisaba `projects/grabbr-hops/ADAPTIVE-EDGE-CROSSING.md`.
///
/// Rung-1 model (shaped by an adversarial review pass):
/// - **Gesture, not decay**: pressure accumulates linearly while events keep
///   coming; a pause > [`EDGE_GESTURE_GAP_MS`] ends the gesture and resets.
///   (An exponential decay gave a rate *floor* — pushes slower than ~277 px/s
///   could mathematically never fire.)
/// - **Per-side accumulators**: all four edges integrate independently; a
///   corner push feeds both its edges instead of resetting on axis flips.
/// - **Warp-artifact guard**: each event's blocked motion is capped to the
///   requested delta (sign-matched) — a post-wake/reconfig phantom cursor
///   coordinate contributes nothing instead of firing instantly.
/// - **Union gate**: blocked motion only counts when the clamp pinned the
///   cursor on the *desktop union* edge in that direction (1s-cached bounds),
///   matching the capture-side barrier's semantics — an interior display
///   bezel (offset second display) never builds cross-back pressure.
/// - **Per-event cap** of half the threshold: no single-event crossing from a
///   throw at an edge target; a real flick still fires within ~2 events.
/// - **Latch**: one fire per push — after firing, a side stays quiet until
///   the gesture ends (pause or inward motion). Leaning on an edge is one
///   crossing intent, not a fire every 60px (validated live: 19 fires/sec
///   while leaning on a clientless edge before the latch).
///
/// Rung-2 model — per-edge thresholds that learn. A second adversarial pass
/// killed the first design (event-flow-timing regret): a real crossing makes
/// the peer send Leave back, which DESTROYS the emulation handle — so flow
/// timing can't survive a crossing, and dead-edge fires polluted it. The
/// session lifecycle itself is the reliable crossing signal:
/// - **Cross confirmation**: [`Self::on_session_destroyed`] runs when the
///   handle is torn down. If that happens within [`EDGE_CROSS_CONFIRM_MS`] of
///   our fire, that fire verifiably crossed (a fire at a clientless edge
///   never destroys the handle — it can't produce false regret).
/// - **Regret, tentatively**: [`Self::on_session_created`] runs at the first
///   input after re-entry. Returning within [`EDGE_REGRET_WINDOW_MS`] of the
///   crossing means the user barely stayed — record a *pending* raise.
/// - **Deferred commit**: the raise only commits once no same-edge fire has
///   followed within [`EDGE_BOUNCE_CANCEL_MS`] — deliberate bouncing discards
///   the pending raise instead of committing-then-reverting (no clamp
///   asymmetry, and a bounce run costs at most the final return's raise).
/// - **Effort**: a push abandoned at >= half its threshold arms a discount,
///   stamped at the *abandon* time (not the resume — a 10-minute-old
///   near-miss must not discount today's crossing); a fire on that edge
///   within [`EDGE_EFFORT_WINDOW_MS`] of the abandon lowers the threshold.
/// - **One adjustment per fire**: a bounce-discard consumes the fire's
///   learning budget; effort applies only otherwise. Signals compose, never
///   fight.
/// - Thresholds clamp to [[`EDGE_THRESHOLD_MIN`], [`EDGE_THRESHOLD_MAX`]] and
///   are learned in-memory per daemon run (persistence is a later rung once
///   the dynamics are validated). Every adjustment logs at info.
///
/// Confirmed-cross gating (learning only ever touches a REAL crossing):
/// - A fire holds off any *other* side from firing for [`EDGE_CROSS_CONFIRM_MS`]
///   (a corner push pins two edges — without this the second fire
///   misattributes the crossing to a clientless edge).
/// - The effort discount is only *armed* at fire time; it commits in
///   [`Self::on_session_destroyed`] once the teardown confirms the fire crossed.
///
/// Known + accepted (timing-inference limits; the robust fix is an explicit
/// service→backend cross confirmation, deferred until multi-machine is in use):
/// - Crossings won by the redundant position barrier (no detector fire) don't
///   feed learning; a deliberate-bounce run's final return can commit one
///   raise — the effort signal corrects it within a couple of pushes.
/// - A single `pending_regret` slot: with clients on *two* edges, an
///   accidental crossing on one whose raise hasn't committed can be
///   overwritten by a crossing on the other (a legitimate raise is dropped,
///   never a wrong one added). Single-client setups can't hit it.
/// - A non-crossing teardown (peer release-bind / disconnect) within
///   [`EDGE_CROSS_CONFIRM_MS`] of a *clientless-edge* fire can false-confirm a
///   cross → one +25% raise on an edge with no client (a near-no-op: a
///   clientless edge's threshold is never consulted).
///
/// `HOPS_ADAPTIVE_EDGE=off` disables everything (A/B toggle);
/// `HOPS_EDGE_THRESHOLD=<px>` sets the starting threshold;
/// `HOPS_EDGE_LEARN=off` freezes thresholds (rung 1 behavior only).
struct EdgePressureDetector {
    enabled: bool,
    /// rung 2 on/off — when off, thresholds stay at their starting value
    learn: bool,
    /// per-side crossing threshold (px): [Left, Right, Top, Bottom]
    threshold: [f64; 4],
    /// accumulated blocked motion per side: [Left, Right, Top, Bottom]
    pressure: [f64; 4],
    /// side already fired this gesture — one crossing intent per push
    latched: [bool; 4],
    /// timestamp of the previous update, for gesture-gap detection
    last_update: Option<Instant>,
    /// most recent detector fire (side index, at, effort-armed) — consumed by
    /// [`Self::on_session_destroyed`] to recognize our-fire-caused crossings.
    /// `effort-armed` means the fire followed an abandoned near-miss; the
    /// effort discount commits only if the teardown confirms it crossed.
    last_fire: Option<(usize, Instant, bool)>,
    /// a fire that verifiably crossed — the handle was destroyed right after
    /// it: (side index, destroyed at). Deliberately survives the teardown.
    last_cross: Option<(usize, Instant)>,
    /// a regret raise awaiting commit: (side index, returned at). Discarded
    /// by a same-side fire inside the bounce window; committed after it.
    pending_regret: Option<(usize, Instant)>,
    /// abandoned near-miss push: (side index, abandoned at)
    last_attempt: Option<(usize, Instant)>,
    /// cached desktop-union bounds: (xmin, xmax, ymin, ymax, computed_at)
    union: Option<(f64, f64, f64, f64, Instant)>,
    /// where learned thresholds persist across daemon restarts. `None` = don't
    /// persist (no HOME, or `HOPS_EDGE_THRESHOLD` forced an ephemeral A/B value).
    state_path: Option<PathBuf>,
}

/// A pause longer than this (no motion events) ends the push gesture and
/// resets all pressure — deliberateness is *sustained* contact, drift-and-rest
/// never accumulates across pauses.
const EDGE_GESTURE_GAP_MS: f64 = 200.0;
/// Default starting threshold (px of blocked outward push within one gesture).
/// Rung 2 adjusts it per edge from there; `HOPS_EDGE_THRESHOLD` overrides the
/// starting point.
const DEFAULT_EDGE_THRESHOLD: f64 = 60.0;
/// Learned-threshold bounds: the floor keeps effort-lowering from making an
/// edge hair-trigger, the ceiling keeps regret-raising from walling it off.
const EDGE_THRESHOLD_MIN: f64 = 24.0;
const EDGE_THRESHOLD_MAX: f64 = 240.0;
/// Inward motion (px) on a side's axis that counts as "deliberately moving
/// away" — resets that side immediately. Set well above hand wobble (a few px)
/// so a shaky push doesn't self-cancel.
const EDGE_INWARD_RESET: f64 = 8.0;
/// How long the desktop-union bounds cache stays fresh. Enumerating displays
/// per motion event would risk stalling the hot path (the capture side polls
/// at this same 1s cadence for the same reason).
const EDGE_UNION_CACHE: Duration = Duration::from_secs(1);
/// Slack when testing whether the clamped coordinate sits on the union edge
/// (the clamp lands at `max - 1` on max sides and `min` on min sides).
const EDGE_UNION_TOLERANCE: f64 = 1.5;
/// A session teardown within this long of our fire means that fire crossed
/// (the peer's Leave-back destroys the handle a few ms after a real
/// crossing; clientless-edge fires never tear the session down).
const EDGE_CROSS_CONFIRM_MS: f64 = 500.0;
/// Regret: re-entering within this long of the crossing means the user
/// barely stayed. Overlaps deliberate-bounce timing by nature — that's what
/// the deferred commit + bounce discard below are for.
const EDGE_REGRET_WINDOW_MS: f64 = 800.0;
/// A same-edge fire within this long of the return means deliberate
/// bouncing: the pending raise is discarded. Only after this window does a
/// pending raise commit.
const EDGE_BOUNCE_CANCEL_MS: f64 = 1500.0;
/// An abandoned near-miss push followed by a fire on the same edge within
/// this long (measured from the ABANDON) means the threshold made the user
/// work for the crossing — lower it.
const EDGE_EFFORT_WINDOW_MS: f64 = 2000.0;
/// Threshold adjustment factors: regret raises ×1.25, effort lowers ×0.85.
/// Multiplicative so repeated signals converge smoothly.
const EDGE_REGRET_FACTOR: f64 = 1.25;
const EDGE_EFFORT_FACTOR: f64 = 0.85;

const EDGE_SIDES: [EdgeSide; 4] = [
    EdgeSide::Left,
    EdgeSide::Right,
    EdgeSide::Top,
    EdgeSide::Bottom,
];
/// Persisted-thresholds filename, inside the frozen hops state dir.
const EDGE_STATE_FILE: &str = "edge-thresholds.conf";

/// Path to the persisted learned thresholds. Mirrors the rest of hops'
/// state-dir convention (`$XDG_CONFIG_HOME` or `~/.config`, then `/lan-mouse/`
/// — see src/config.rs `default_path`). `None` if there's no home to anchor to.
fn edge_state_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("lan-mouse").join(EDGE_STATE_FILE))
}

/// Serialize the per-side thresholds to the tiny `key = value` file format.
fn format_edge_thresholds(t: &[f64; 4]) -> String {
    format!(
        "# hops adaptive edge crossing — learned per-edge cross thresholds (px).\n\
         # Auto-managed; delete this file to reset learning.\n\
         left = {:.0}\nright = {:.0}\ntop = {:.0}\nbottom = {:.0}\n",
        t[0], t[1], t[2], t[3]
    )
}

/// Load per-side thresholds `[L, R, T, B]` from `path`. Every value is clamped
/// to `[MIN, MAX]`; any missing/blank/garbage line falls back to the default,
/// so a hand-edited or partial file can never produce an unusable threshold.
fn load_edge_thresholds(path: Option<&Path>) -> [f64; 4] {
    let mut t = [DEFAULT_EDGE_THRESHOLD; 4];
    let Some(path) = path else { return t };
    let Ok(contents) = std::fs::read_to_string(path) else { return t };
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let Ok(val) = v.trim().parse::<f64>() else { continue };
        if !val.is_finite() {
            continue;
        }
        let val = val.clamp(EDGE_THRESHOLD_MIN, EDGE_THRESHOLD_MAX);
        match k.trim().to_ascii_lowercase().as_str() {
            "left" => t[0] = val,
            "right" => t[1] = val,
            "top" => t[2] = val,
            "bottom" => t[3] = val,
            _ => {}
        }
    }
    t
}

impl EdgePressureDetector {
    fn from_env() -> Self {
        let off = |v: Result<String, std::env::VarError>| {
            matches!(
                v.as_deref().map(|s| s.to_ascii_lowercase()).as_deref(),
                Ok("off") | Ok("0") | Ok("false") | Ok("no") | Ok("disabled")
            )
        };
        let enabled = !off(std::env::var("HOPS_ADAPTIVE_EDGE"));
        let learn = !off(std::env::var("HOPS_EDGE_LEARN"));
        // HOPS_EDGE_THRESHOLD forces a uniform starting value for A/B testing —
        // ephemeral: it neither reads nor writes the persisted file. Otherwise
        // load the per-edge learned thresholds (or the default per edge).
        let env_forced = std::env::var("HOPS_EDGE_THRESHOLD")
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .filter(|t| *t > 0.0)
            .map(|t| t.clamp(EDGE_THRESHOLD_MIN, EDGE_THRESHOLD_MAX));
        let (threshold, state_path) = match env_forced {
            Some(t) => ([t; 4], None),
            None => {
                let p = edge_state_path();
                (load_edge_thresholds(p.as_deref()), p)
            }
        };
        if enabled {
            log::info!(
                "adaptive edge crossing enabled (self-tuning {}; thresholds L/R/T/B = {:.0}/{:.0}/{:.0}/{:.0}px, {}; HOPS_ADAPTIVE_EDGE=off / HOPS_EDGE_LEARN=off to disable)",
                if learn { "on" } else { "off" },
                threshold[0], threshold[1], threshold[2], threshold[3],
                if state_path.is_some() { "persisted" } else { "env-forced, not persisted" }
            );
        } else {
            log::info!("adaptive edge crossing DISABLED (HOPS_ADAPTIVE_EDGE)");
        }
        Self {
            enabled,
            learn,
            threshold,
            pressure: [0.0; 4],
            latched: [false; 4],
            last_update: None,
            last_fire: None,
            last_cross: None,
            pending_regret: None,
            last_attempt: None,
            union: None,
            state_path,
        }
    }

    /// Set a side's threshold (clamped) and persist the table. The single
    /// mutation point for `threshold`, so every learned change is saved.
    fn set_threshold(&mut self, i: usize, value: f64) {
        self.threshold[i] = value.clamp(EDGE_THRESHOLD_MIN, EDGE_THRESHOLD_MAX);
        self.save();
    }

    /// Persist the learned thresholds (no-op when not persisting). Called only
    /// on the rare learning events, never on the per-motion hot path.
    fn save(&self) {
        let Some(path) = self.state_path.as_deref() else { return };
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Err(e) = std::fs::write(path, format_edge_thresholds(&self.threshold)) {
            log::warn!("could not persist edge thresholds to {}: {e}", path.display());
        }
    }

    /// Feed one motion event: `(dx, dy)` is the requested delta, `(blocked_x,
    /// blocked_y)` the part the clamp discarded, `(clamped_x, clamped_y)` the
    /// position the cursor was actually placed at. Returns the edge to cross
    /// when a side's pressure exceeds its threshold.
    fn update(
        &mut self,
        dx: f64,
        dy: f64,
        blocked_x: f64,
        blocked_y: f64,
        clamped_x: f64,
        clamped_y: f64,
    ) -> Option<EdgeSide> {
        if !self.enabled {
            return None;
        }

        let now = Instant::now();
        if let Some(prev) = self.last_update {
            let gap_ms = now.duration_since(prev).as_secs_f64() * 1000.0;
            if gap_ms > EDGE_GESTURE_GAP_MS {
                // the gesture ended during the silence — effort bookkeeping
                // reads the stale pressure, then start fresh
                self.on_gesture_end(now, gap_ms);
                self.pressure = [0.0; 4];
                self.latched = [false; 4];
            }
        }
        self.last_update = Some(now);

        // a pending regret raise commits once the bounce window has passed
        // without a same-edge fire (checked cheaply on every event)
        if let Some((i, t)) = self.pending_regret {
            if now.duration_since(t).as_secs_f64() * 1000.0 > EDGE_BOUNCE_CANCEL_MS {
                self.pending_regret = None;
                if self.learn {
                    let old = self.threshold[i];
                    self.set_threshold(i, old * EDGE_REGRET_FACTOR);
                    log::info!(
                        "edge learning: {:?} crossing looked accidental — threshold {:.0} -> {:.0}px",
                        EDGE_SIDES[i],
                        old,
                        self.threshold[i]
                    );
                }
            }
        }

        // warp-artifact guard: real clamping never discards more than was
        // asked for; a larger (or sign-flipped) "blocked" means the cursor
        // *started* out of bounds (post-wake / display-reconfig fallback) —
        // that's a settling artifact, not a user push. Contribute nothing.
        let bx = if dx > 0.0 && blocked_x > 0.0 {
            blocked_x.min(dx)
        } else if dx < 0.0 && blocked_x < 0.0 {
            blocked_x.max(dx)
        } else {
            0.0
        };
        let by = if dy > 0.0 && blocked_y > 0.0 {
            blocked_y.min(dy)
        } else if dy < 0.0 && blocked_y < 0.0 {
            blocked_y.max(dy)
        } else {
            0.0
        };

        // inward motion is explicit intent to stay on this screen: reset (and
        // unlatch) the side(s) being moved away from
        if dx > EDGE_INWARD_RESET {
            self.pressure[0] = 0.0; // away from Left
            self.latched[0] = false;
        }
        if dx < -EDGE_INWARD_RESET {
            self.pressure[1] = 0.0; // away from Right
            self.latched[1] = false;
        }
        if dy > EDGE_INWARD_RESET {
            self.pressure[2] = 0.0; // away from Top (CG +y is down)
            self.latched[2] = false;
        }
        if dy < -EDGE_INWARD_RESET {
            self.pressure[3] = 0.0; // away from Bottom
            self.latched[3] = false;
        }

        // union gate: only count blocked motion when the cursor is pinned on
        // the DESKTOP's outer edge in that direction. Interior display bezels
        // clamp too, but must never build cross-back pressure (the capture
        // barrier likewise only exists at the union edge).
        if bx != 0.0 || by != 0.0 {
            let (uxmin, uxmax, uymin, uymax) = self.union_bounds(now)?;
            if !self.latched[0] && bx < 0.0 && (clamped_x - uxmin).abs() <= EDGE_UNION_TOLERANCE {
                self.pressure[0] += bx.abs().min(self.threshold[0] / 2.0);
            }
            if !self.latched[1]
                && bx > 0.0
                && (clamped_x - (uxmax - 1.0)).abs() <= EDGE_UNION_TOLERANCE
            {
                self.pressure[1] += bx.abs().min(self.threshold[1] / 2.0);
            }
            if !self.latched[2] && by < 0.0 && (clamped_y - uymin).abs() <= EDGE_UNION_TOLERANCE {
                self.pressure[2] += by.abs().min(self.threshold[2] / 2.0);
            }
            if !self.latched[3]
                && by > 0.0
                && (clamped_y - (uymax - 1.0)).abs() <= EDGE_UNION_TOLERANCE
            {
                self.pressure[3] += by.abs().min(self.threshold[3] / 2.0);
            }
            log::trace!(
                "edge pressure [L/R/T/B]: {:.0}/{:.0}/{:.0}/{:.0} of {:.0}/{:.0}/{:.0}/{:.0}px",
                self.pressure[0],
                self.pressure[1],
                self.pressure[2],
                self.pressure[3],
                self.threshold[0],
                self.threshold[1],
                self.threshold[2],
                self.threshold[3]
            );
        }

        // fire the strongest unlatched side past its threshold, if any
        let mut best: Option<(usize, f64)> = None;
        for i in 0..4 {
            if !self.latched[i]
                && self.pressure[i] >= self.threshold[i]
                && best.is_none_or(|(_, p)| self.pressure[i] > p)
            {
                best = Some((i, self.pressure[i]));
            }
        }
        if let Some((i, p)) = best {
            // a crossing already in flight? A corner push pins two edges at
            // once; if we fired one side and its Leave round-trip hasn't torn
            // the session down yet, a second side firing here would
            // misattribute the crossing (and emit a spurious EdgePushed the
            // service drops). Hold until the in-flight fire resolves — a real
            // crossing's teardown clears last_fire within the confirm window.
            let in_flight = self.last_fire.is_some_and(|(_, t, _)| {
                now.duration_since(t).as_secs_f64() * 1000.0 <= EDGE_CROSS_CONFIRM_MS
            });
            if in_flight {
                return None;
            }
            let side = EDGE_SIDES[i];
            log::info!(
                "adaptive edge: deliberate push past {side:?} edge ({p:.0}px >= {:.0}px)",
                self.threshold[i]
            );
            // latch: one crossing intent per push
            self.latched[i] = true;
            self.pressure[i] = 0.0;
            // learning is armed at fire time but only COMMITTED once the
            // teardown confirms the fire actually crossed (a clientless-edge
            // fire never destroys the handle, so it never teaches)
            let effort_armed = if self.learn { self.on_fire(i, now) } else { false };
            self.last_fire = Some((i, now, effort_armed));
            return Some(side);
        }
        None
    }

    /// Effort bookkeeping when a gesture ends (observed at the first event
    /// after the silence): the side with the strongest near-miss — pressure
    /// at >= half its threshold — becomes an abandoned attempt, stamped at
    /// the ABANDON time (`now - gap`), so an old near-miss can't discount a
    /// much later crossing.
    fn on_gesture_end(&mut self, now: Instant, gap_ms: f64) {
        let mut best: Option<(usize, f64)> = None;
        for i in 0..4 {
            let ratio = self.pressure[i] / self.threshold[i];
            if !self.latched[i]
                && ratio >= 0.5
                && best.is_none_or(|(_, r)| ratio > r)
            {
                best = Some((i, ratio));
            }
        }
        if let Some((i, _)) = best {
            let abandoned_at = now
                .checked_sub(Duration::from_secs_f64(gap_ms / 1000.0))
                .unwrap_or(now);
            self.last_attempt = Some((i, abandoned_at));
        }
    }

    /// Learning at fire time (only called when `learn` is on). At most one
    /// signal applies per fire: a bounce-discard consumes the fire's learning
    /// budget; effort applies only otherwise.
    /// Learning at fire time (only called when `learn` is on). Returns whether
    /// an effort discount is ARMED — applied later only on a confirmed
    /// crossing. At most one signal per fire: a bounce-discard consumes the
    /// fire's learning budget; effort arms only otherwise.
    fn on_fire(&mut self, i: usize, now: Instant) -> bool {
        // deliberate bounce: the user came back and immediately pushed
        // through again — the pending "regret" raise was wrong, drop it
        if let Some((ri, t_r)) = self.pending_regret {
            if ri == i && now.duration_since(t_r).as_secs_f64() * 1000.0 <= EDGE_BOUNCE_CANCEL_MS {
                log::info!(
                    "edge learning: {:?} was a deliberate bounce — no threshold change",
                    EDGE_SIDES[i]
                );
                self.pending_regret = None;
                return false;
            }
        }
        // effort: this fire follows an abandoned near-miss on the same edge —
        // arm the discount; it commits only if the fire actually crosses
        if let Some((ai, t_a)) = self.last_attempt {
            if ai == i && now.duration_since(t_a).as_secs_f64() * 1000.0 <= EDGE_EFFORT_WINDOW_MS {
                self.last_attempt = None;
                return true;
            }
        }
        false
    }

    /// The emulation session for a peer was torn down. A teardown moments
    /// after our fire means that fire verifiably CROSSED (the peer's
    /// Leave-back destroys the handle); remember it so the re-entry timing
    /// can be judged. Everything gesture-scoped resets.
    fn on_session_destroyed(&mut self) {
        let now = Instant::now();
        if let Some((i, t_fire, effort_armed)) = self.last_fire.take() {
            if now.duration_since(t_fire).as_secs_f64() * 1000.0 <= EDGE_CROSS_CONFIRM_MS {
                self.last_cross = Some((i, now));
                // effort discount commits only now that the crossing is
                // confirmed — a clientless-edge fire never reaches here, so it
                // can't ratchet a dead edge to the floor
                if self.learn && effort_armed {
                    let old = self.threshold[i];
                    self.set_threshold(i, old * EDGE_EFFORT_FACTOR);
                    log::info!(
                        "edge learning: {:?} took repeated pushes — threshold {:.0} -> {:.0}px",
                        EDGE_SIDES[i],
                        old,
                        self.threshold[i]
                    );
                }
            }
        }
        // Resolve any pending regret at the teardown: a crossing this soon
        // after the return is bouncing — whichever barrier detected it (the
        // fire-time discard only sees OUR fires; a crossing won by the
        // redundant position barrier would otherwise slip past and let the
        // raise commit). Past the window, commit rather than silently drop.
        if let Some((i, t_r)) = self.pending_regret.take() {
            if now.duration_since(t_r).as_secs_f64() * 1000.0 <= EDGE_BOUNCE_CANCEL_MS {
                log::info!(
                    "edge learning: {:?} was a deliberate bounce — no threshold change",
                    EDGE_SIDES[i]
                );
            } else if self.learn {
                let old = self.threshold[i];
                self.set_threshold(i, old * EDGE_REGRET_FACTOR);
                log::info!(
                    "edge learning: {:?} crossing looked accidental — threshold {:.0} -> {:.0}px",
                    EDGE_SIDES[i],
                    old,
                    self.threshold[i]
                );
            }
        }
        self.pressure = [0.0; 4];
        self.latched = [false; 4];
        self.last_update = None;
        self.last_attempt = None;
    }

    /// A peer session (re)started — first input after an entry. Re-entering
    /// shortly after a confirmed crossing means the user barely stayed:
    /// record a tentative regret raise (committed later unless a same-edge
    /// fire reveals deliberate bouncing).
    fn on_session_created(&mut self) {
        let now = Instant::now();
        self.pressure = [0.0; 4];
        self.latched = [false; 4];
        self.last_update = None;
        self.last_fire = None;
        self.last_attempt = None;
        if let Some((i, t_cross)) = self.last_cross.take() {
            let away_ms = now.duration_since(t_cross).as_secs_f64() * 1000.0;
            if self.learn && away_ms <= EDGE_REGRET_WINDOW_MS {
                log::info!(
                    "edge learning: returned from {:?} crossing in {:.0}ms — tentative regret (commits in {:.1}s unless bounced)",
                    EDGE_SIDES[i],
                    away_ms,
                    EDGE_BOUNCE_CANCEL_MS / 1000.0
                );
                self.pending_regret = Some((i, now));
            }
        }
    }

    /// Desktop-union bounds, cached for [`EDGE_UNION_CACHE`]. `None` when no
    /// displays are reported (mid-reconfig) — the caller skips accumulation.
    fn union_bounds(&mut self, now: Instant) -> Option<(f64, f64, f64, f64)> {
        if let Some((a, b, c, d, at)) = self.union {
            if now.duration_since(at) < EDGE_UNION_CACHE {
                return Some((a, b, c, d));
            }
        }
        let ids = CGDisplay::active_displays().ok()?;
        if ids.is_empty() {
            return None;
        }
        let (mut xmin, mut xmax, mut ymin, mut ymax) =
            (f64::MAX, f64::MIN, f64::MAX, f64::MIN);
        for id in ids {
            let b = CGDisplay::new(id).bounds();
            xmin = xmin.min(b.origin.x);
            xmax = xmax.max(b.origin.x + b.size.width);
            ymin = ymin.min(b.origin.y);
            ymax = ymax.max(b.origin.y + b.size.height);
        }
        self.union = Some((xmin, xmax, ymin, ymax, now));
        Some((xmin, xmax, ymin, ymax))
    }

    /// Zero pressure and latches (keeps the union cache and all learning
    /// state). Called per drag event by the button guard, so it must stay
    /// cheap.
    fn reset(&mut self) {
        self.pressure = [0.0; 4];
        self.latched = [false; 4];
    }
}

fn clamp_to_screen_space(
    current_x: CGFloat,
    current_y: CGFloat,
    dx: CGFloat,
    dy: CGFloat,
) -> (CGFloat, CGFloat) {
    // Check which display the mouse is currently on
    // Determine what the location of the mouse would be after applying the move
    // Get the display at the new location
    // If the point is not on a display
    //   Clamp the mouse to the current display
    // Else If the point is on a display
    //   Clamp the mouse to the new display
    let current_display = match get_display_at_point(current_x, current_y) {
        Some(display) => display,
        None => {
            // Post-wake the cursor can briefly map to no display while the display
            // topology settles. Fall back to the main display so we clamp onto
            // something real instead of leaving the cursor at a phantom coordinate;
            // this self-heals once CG reports a display under the point again.
            // (debug, not warn: it would otherwise flood one line per motion event.)
            log::debug!("no display under cursor ({current_x}, {current_y}); using main display");
            core_graphics::display::CGDisplay::main().id
        }
    };

    let new_x = current_x + dx;
    let new_y = current_y + dy;

    let final_display = get_display_at_point(new_x, new_y).unwrap_or(current_display);
    let (min_x, min_y, max_x, max_y) = get_display_bounds(final_display);

    (
        new_x.clamp(min_x, max_x - 1.),
        new_y.clamp(min_y, max_y - 1.),
    )
}

#[async_trait]
impl Emulation for MacOSEmulation {
    async fn consume(
        &mut self,
        event: Event,
        _handle: EmulationHandle,
    ) -> Result<(), EmulationError> {
        log::trace!("{event:?}");
        // Wake a sleeping display on any incoming remote input (throttled). The
        // system stays awake via the power assertion, but synthetic CGEvents
        // don't wake the screen by themselves — this does.
        self.declare_user_activity();
        match event {
            Event::Pointer(pointer_event) => {
                match pointer_event {
                    PointerEvent::Motion { time: _, dx, dy } => {
                        // Reject non-finite deltas (NaN/Inf from a malformed/hostile peer)
                        // before they poison the cursor coordinate. The proto also rejects
                        // these at decode; this is defense in depth.
                        if !dx.is_finite() || !dy.is_finite() {
                            log::warn!("ignoring non-finite motion delta ({dx}, {dy})");
                            return Ok(());
                        }
                        let mut mouse_location = match self.get_mouse_location() {
                            Some(l) => l,
                            None => {
                                log::warn!("could not get mouse location!");
                                return Ok(());
                            }
                        };

                        // Trueloop Phase A probe: compare where the cursor actually is
                        // (mouse_location, sampled at the TOP of this event = "did the
                        // previous injection land?") against our running integral of the
                        // UNCLAMPED requested deltas. The gap is the accumulated clamp
                        // discard — the divergence Trueloop will one day servo out.
                        if self.probe_enabled {
                            // per-window travel + speed (the accel fingerprint)
                            let pnow = Instant::now();
                            let dmag = (dx * dx + dy * dy).sqrt();
                            if let Some(last) = self.probe_last_evt.get() {
                                let dt = pnow.duration_since(last).as_secs_f64();
                                if dt > 0.0 {
                                    self.probe_peak_speed
                                        .set(self.probe_peak_speed.get().max(dmag / dt));
                                }
                            }
                            self.probe_last_evt.set(Some(pnow));
                            self.probe_req_travel.set(self.probe_req_travel.get() + dmag);
                            if let Some((px, py)) = self.probe_prev_pos.get() {
                                let amag = ((mouse_location.x - px).powi(2)
                                    + (mouse_location.y - py).powi(2))
                                .sqrt();
                                self.probe_act_travel.set(self.probe_act_travel.get() + amag);
                            }
                            self.probe_prev_pos
                                .set(Some((mouse_location.x, mouse_location.y)));
                            match self.probe_integral.get() {
                                Some((ix, iy)) => {
                                    let div = (ix - mouse_location.x).hypot(iy - mouse_location.y);
                                    self.probe_peak_offset
                                        .set(self.probe_peak_offset.get().max(div));
                                    if self.probe_win_start_div.get().is_none() {
                                        self.probe_win_start_div.set(Some(div));
                                    }
                                    self.probe_last_div.set(div);
                                    self.probe_integral.set(Some((ix + dx, iy + dy)));
                                }
                                None => self
                                    .probe_integral
                                    .set(Some((mouse_location.x + dx, mouse_location.y + dy))),
                            }
                            self.probe_flush();
                        }

                        let (new_mouse_x, new_mouse_y) =
                            clamp_to_screen_space(mouse_location.x, mouse_location.y, dx, dy);

                        // Adaptive edge: whatever the clamp just discarded is
                        // outward motion the user *asked for* and didn't get —
                        // feed it to the intent detector. Uses the network
                        // delta, not the OS-mangled post-warp one, so edge
                        // suppression can't eat the crossing.
                        if self.pressed_buttons.is_empty() {
                            let blocked_x = (mouse_location.x + dx) - new_mouse_x;
                            let blocked_y = (mouse_location.y + dy) - new_mouse_y;
                            if let Some(side) = self.edge_pressure.update(
                                dx,
                                dy,
                                blocked_x,
                                blocked_y,
                                new_mouse_x,
                                new_mouse_y,
                            ) {
                                self.pending_edge_push = Some(side);
                            }
                        } else {
                            // Parity with the capture-side barrier, which only
                            // crosses on plain MouseMoved: never cross mid-drag
                            // (a drag against the edge is aimed at THIS screen's
                            // edge content, and crossing would strand the held
                            // button). Drop any built-up intent too.
                            self.edge_pressure.reset();
                        }

                        mouse_location.x = new_mouse_x;
                        mouse_location.y = new_mouse_y;

                        // If any button is held, emit a drag event for it;
                        // otherwise emit a normal mouse-moved event.
                        let event_type = self
                            .pressed_buttons
                            .iter()
                            .next()
                            .map(|&btn| drag_event_type(btn))
                            .unwrap_or(CGEventType::MouseMoved);
                        let event = match CGEvent::new_mouse_event(
                            self.event_source.clone(),
                            event_type,
                            mouse_location,
                            CGMouseButton::Left,
                        ) {
                            Ok(e) => e,
                            Err(_) => {
                                log::warn!("mouse event creation failed!");
                                return Ok(());
                            }
                        };
                        // Stamp the relative delta unconditionally, exactly like
                        // upstream. The earlier VM-guest delta-gate here was a
                        // misdiagnosis: stock 0.11.0 sets the delta for guests too and
                        // feels correct (verified by running the upstream RC into a
                        // Parallels guest), so the delta was never the over-sensitivity
                        // cause.
                        event.set_integer_value_field(EventField::MOUSE_EVENT_DELTA_X, dx as i64);
                        event.set_integer_value_field(EventField::MOUSE_EVENT_DELTA_Y, dy as i64);
                        // Carry modifier flags ONLY when a modifier is actually held, so
                        // modifier-aware drags (e.g. a Shift/Option-constrained
                        // screenshot-region drag) still see the modifier. Stamping flags
                        // on EVERY plain move (the previous behavior) overrode macOS
                        // pointer scaling and regressed motion feel — slow on the native
                        // host, over-sensitive in a guest — so plain moves now stay
                        // byte-identical to upstream.
                        let flags = to_cgevent_flags(self.modifier_state.get());
                        if !flags.is_empty() {
                            event.set_flags(flags);
                        }
                        event.post(CGEventTapLocation::HID);
                    }
                    PointerEvent::Button {
                        time: _,
                        button,
                        state,
                    } => {
                        // button number for OtherMouse events (3 = back, 4 = forward, etc.)
                        let cg_button_number: Option<i64> = match button {
                            BTN_BACK => Some(3),
                            BTN_FORWARD => Some(4),
                            _ => None,
                        };
                        let (event_type, mouse_button) = match (button, state) {
                            (BTN_LEFT, 1) => (CGEventType::LeftMouseDown, CGMouseButton::Left),
                            (BTN_LEFT, 0) => (CGEventType::LeftMouseUp, CGMouseButton::Left),
                            (BTN_RIGHT, 1) => (CGEventType::RightMouseDown, CGMouseButton::Right),
                            (BTN_RIGHT, 0) => (CGEventType::RightMouseUp, CGMouseButton::Right),
                            (BTN_MIDDLE, 1) => (CGEventType::OtherMouseDown, CGMouseButton::Center),
                            (BTN_MIDDLE, 0) => (CGEventType::OtherMouseUp, CGMouseButton::Center),
                            (BTN_BACK, 1) | (BTN_FORWARD, 1) => {
                                (CGEventType::OtherMouseDown, CGMouseButton::Center)
                            }
                            (BTN_BACK, 0) | (BTN_FORWARD, 0) => {
                                (CGEventType::OtherMouseUp, CGMouseButton::Center)
                            }
                            _ => {
                                log::warn!("invalid button event: {button},{state}");
                                return Ok(());
                            }
                        };
                        // store button state using the evdev button code so
                        // back, forward, and middle are tracked independently
                        if state == 1 {
                            self.pressed_buttons.insert(button);
                        } else {
                            self.pressed_buttons.remove(&button);
                        }

                        // update double-click tracking using the evdev button
                        // code so that back/forward don't alias with middle
                        if state == 1 {
                            if self.previous_button == Some(button)
                                && self
                                    .previous_button_click
                                    .is_some_and(|i| i.elapsed() < DOUBLE_CLICK_INTERVAL)
                            {
                                self.button_click_state += 1;
                            } else {
                                self.button_click_state = 1;
                            }
                            self.previous_button = Some(button);
                            self.previous_button_click = Some(Instant::now());
                        }

                        log::debug!("click_state: {}", self.button_click_state);
                        // Must NOT unwrap: get_mouse_location() is None on a transient
                        // CGEvent failure (display reconfig / lid-dock churn / memory
                        // pressure). With panic=abort a single mistimed button event would
                        // hard-kill the whole receiver. Mirror the Motion arm and skip.
                        let location = match self.get_mouse_location() {
                            Some(l) => l,
                            None => {
                                log::warn!("could not get mouse location for button event!");
                                return Ok(());
                            }
                        };
                        let event = match CGEvent::new_mouse_event(
                            self.event_source.clone(),
                            event_type,
                            location,
                            mouse_button,
                        ) {
                            Ok(e) => e,
                            Err(()) => {
                                log::warn!("mouse event creation failed!");
                                return Ok(());
                            }
                        };
                        event.set_integer_value_field(
                            EventField::MOUSE_EVENT_CLICK_STATE,
                            self.button_click_state,
                        );
                        // Set the button number for extra buttons (back=3, forward=4)
                        if let Some(btn_num) = cg_button_number {
                            event.set_integer_value_field(
                                EventField::MOUSE_EVENT_BUTTON_NUMBER,
                                btn_num,
                            );
                        }
                        // Carry the current modifier flags (e.g. Shift-click,
                        // Cmd-click) so the click isn't seen as flagless.
                        event.set_flags(to_cgevent_flags(self.modifier_state.get()));
                        self.coherence_pass("button", false);
                        event.post(CGEventTapLocation::HID);
                    }
                    PointerEvent::Axis {
                        time: _,
                        axis,
                        value,
                    } => {
                        // Honour the receiver's natural-scroll preference (macOS
                        // doesn't apply it to synthetic events); see
                        // apply_natural_scroll. EXCEPT when the target is a VM
                        // guest: the guest applies its OWN natural-scroll to the
                        // injected scroll, so negating here too double-inverts it
                        // (the "scroll is backwards inside the guest" bug). Let
                        // the guest own it; negate only for native targets.
                        let value = value as i32;
                        let value = if self.target_is_vm_guest() {
                            value
                        } else {
                            apply_natural_scroll(value)
                        };
                        let (count, wheel1, wheel2, wheel3) = match axis {
                            0 => (1, value, 0, 0), // 0 = vertical => 1 scroll wheel device (y axis)
                            1 => (2, 0, value, 0), // 1 = horizontal => 2 scroll wheel devices (y, x) -> (0, x)
                            _ => {
                                log::warn!("invalid scroll event: {axis}, {value}");
                                return Ok(());
                            }
                        };
                        let event = match CGEvent::new_scroll_event(
                            self.event_source.clone(),
                            ScrollEventUnit::PIXEL,
                            count,
                            wheel1,
                            wheel2,
                            wheel3,
                        ) {
                            Ok(e) => e,
                            Err(()) => {
                                log::warn!("scroll event creation failed!");
                                return Ok(());
                            }
                        };
                        event.post(CGEventTapLocation::HID);
                    }
                    PointerEvent::AxisDiscrete120 { axis, value } => {
                        const LINES_PER_STEP: i32 = 3;
                        // Same guest exception as the Axis handler above: don't
                        // double-invert inside a VM guest (it applies its own
                        // natural-scroll to the injected scroll).
                        let value = if self.target_is_vm_guest() {
                            value
                        } else {
                            apply_natural_scroll(value)
                        };
                        let (count, wheel1, wheel2, wheel3) = match axis {
                            0 => (1, value / (120 / LINES_PER_STEP), 0, 0), // 0 = vertical => 1 scroll wheel device (y axis)
                            1 => (2, 0, value / (120 / LINES_PER_STEP), 0), // 1 = horizontal => 2 scroll wheel devices (y, x) -> (0, x)
                            _ => {
                                log::warn!("invalid scroll event: {axis}, {value}");
                                return Ok(());
                            }
                        };
                        let event = match CGEvent::new_scroll_event(
                            self.event_source.clone(),
                            ScrollEventUnit::LINE,
                            count,
                            wheel1,
                            wheel2,
                            wheel3,
                        ) {
                            Ok(e) => e,
                            Err(()) => {
                                log::warn!("scroll event creation failed!");
                                return Ok(());
                            }
                        };
                        event.post(CGEventTapLocation::HID);
                    }
                }

                // reset button click state in case it's not a button event
                if !matches!(pointer_event, PointerEvent::Button { .. }) {
                    self.button_click_state = 0;
                }
            }
            Event::Keyboard(keyboard_event) => match keyboard_event {
                KeyboardEvent::Key {
                    time: _,
                    key,
                    state,
                } => {
                    // Media / consumer keys (volume, play/pause, next/prev) are not
                    // regular macOS keycodes — post them as NX_SYSDEFINED aux events.
                    if let Some(nx_keytype) = evdev_to_nx_keytype(key) {
                        match self.hid_connect {
                            Some(connect) => {
                                post_hid_media_key(connect, nx_keytype, state == 1);
                            }
                            None => {
                                log::debug!("media key {key} dropped: no IOHIDSystem connection")
                            }
                        }
                        return Ok(());
                    }
                    let code = match KeyMap::from_key_mapping(KeyMapping::Evdev(key as u16)) {
                        Ok(k) => k.mac as CGKeyCode,
                        Err(_) => {
                            log::warn!("unable to map key event");
                            return Ok(());
                        }
                    };
                    let is_modifier = update_modifiers(&self.modifier_state, key, state);
                    if is_modifier {
                        // Modifier keys are posted as FlagsChanged events carrying
                        // their real keycode (see modifier_key_event). They must NOT
                        // enter the key-repeat machinery: there is only one repeat
                        // slot, so pressing a second modifier would cancel the first
                        // modifier's repeat task and post a keyUp while it is still
                        // physically held, tearing chords apart (issue #450, #357).
                        self.post_modifier(code, self.modifier_state.get());
                    } else {
                        // Before typing a normal key, make sure no stale modifier
                        // flag the OS still holds turns it into a silent chord (the
                        // "ghosting" / dead-keyboard symptom). Diagnoses and, if
                        // enabled, self-heals the divergence in one event.
                        if state == 1 {
                            self.coherence_pass("key", true);
                        }
                        match state {
                            // pressed
                            1 => self.spawn_repeat_task(code).await,
                            _ => self.cancel_repeat_task().await,
                        }
                    }
                }
                KeyboardEvent::Modifiers {
                    depressed,
                    latched,
                    locked,
                    group,
                } => {
                    // Only update internal modifier state here. The per-key handler
                    // above already posts a FlagsChanged event (with the real
                    // keycode) for each modifier Key event the client sends
                    // alongside this state update. Posting one here as well would
                    // duplicate it — and with the old bare CGEvent it injected a
                    // phantom keycode-0 ("A") key on every modifier change (#450).
                    set_modifiers(&self.modifier_state, depressed, latched, locked, group);
                }
            },
        }
        // FIXME
        Ok(())
    }

    fn take_edge_push(&mut self) -> Option<EdgeSide> {
        self.pending_edge_push.take()
    }

    async fn create(&mut self, _handle: EmulationHandle) {
        // a peer session (re)started — regret bookkeeping lives here: a fast
        // return after a confirmed crossing is the "I didn't mean to leave"
        // signal (learned thresholds survive across sessions)
        self.edge_pressure.on_session_created();
        self.pending_edge_push = None;
        // Trueloop Phase A: re-anchor the divergence integral each visit so a
        // cross-away/return doesn't log a phantom offset.
        self.probe_integral.set(None);
        self.probe_peak_offset.set(0.0);
        self.probe_last_div.set(0.0);
        self.probe_win_start_div.set(None);
        self.probe_report_at.set(None);
        self.probe_req_travel.set(0.0);
        self.probe_act_travel.set(0.0);
        self.probe_prev_pos.set(None);
        self.probe_peak_speed.set(0.0);
        self.probe_last_evt.set(None);
    }

    async fn destroy(&mut self, _handle: EmulationHandle) {
        // A peer leave / watchdog timeout lands here. Stop any running key-repeat —
        // otherwise an abnormal teardown (connection loss mid-keypress, where the
        // matching key-up never arrives) leaves the key auto-repeating forever, and
        // the watchdog's "release keys" path would silently do nothing on macOS.
        // Also clear modifier state so no stale modifier is applied afterwards.
        self.cancel_repeat_task().await;
        self.modifier_state.set(XMods::empty());
        // session teardown: if it follows our fire, that fire verifiably
        // crossed — remember it so the re-entry timing can be judged
        self.edge_pressure.on_session_destroyed();
        self.pending_edge_push = None;
    }

    async fn terminate(&mut self) {
        self.cancel_repeat_task().await;
        self.modifier_state.set(XMods::empty());
    }
}

fn update_modifiers(modifiers: &Cell<XMods>, key: u32, state: u8) -> bool {
    if let Ok(key) = scancode::Linux::try_from(key) {
        // Caps Lock is a LOCKING modifier: a press toggles a persistent state
        // rather than being active only while physically held. Toggle on
        // key-down and ignore key-up, so the AlphaShift flag stays set on every
        // following keystroke until Caps Lock is pressed again. (A synthetic
        // CGEvent can't flip the hardware Caps Lock LED, but carrying the flag
        // produces the correct upper-case output — and, like real Caps Lock,
        // leaves the number-row symbols unshifted.)
        if matches!(key, scancode::Linux::KeyCapsLock) {
            if state == 1 {
                let mut mods = modifiers.get();
                mods.toggle(XMods::LockMask);
                modifiers.set(mods);
            }
            return true;
        }
        let mask = match key {
            scancode::Linux::KeyLeftShift | scancode::Linux::KeyRightShift => XMods::ShiftMask,
            scancode::Linux::KeyLeftCtrl | scancode::Linux::KeyRightCtrl => XMods::ControlMask,
            scancode::Linux::KeyLeftAlt | scancode::Linux::KeyRightalt => XMods::Mod1Mask,
            scancode::Linux::KeyLeftMeta | scancode::Linux::KeyRightmeta => XMods::Mod4Mask,
            _ => XMods::empty(),
        };
        // unchanged
        if mask.is_empty() {
            return false;
        }
        let mut mods = modifiers.get();
        match state {
            1 => mods.insert(mask),
            _ => mods.remove(mask),
        }
        modifiers.set(mods);
        true
    } else {
        false
    }
}

fn set_modifiers(
    active_modifiers: &Cell<XMods>,
    depressed: u32,
    latched: u32,
    locked: u32,
    group: u32,
) {
    let depressed = XMods::from_bits(depressed).unwrap_or_default();
    let _latched = XMods::from_bits(latched).unwrap_or_default();
    let _locked = XMods::from_bits(locked).unwrap_or_default();
    let _group = XMods::from_bits(group).unwrap_or_default();

    // we only care about the depressed modifiers for now
    active_modifiers.replace(depressed);
}

fn to_cgevent_flags(depressed: XMods) -> CGEventFlags {
    let mut flags = CGEventFlags::empty();
    if depressed.contains(XMods::ShiftMask) {
        flags |= CGEventFlags::CGEventFlagShift;
    }
    if depressed.contains(XMods::LockMask) {
        flags |= CGEventFlags::CGEventFlagAlphaShift;
    }
    if depressed.contains(XMods::ControlMask) {
        flags |= CGEventFlags::CGEventFlagControl;
    }
    // Mod1 is Alt. Mod5 is ISO_Level3_Shift (AltGr), which is how the Alt key is
    // reported on many xkb keymaps (including COSMIC's default) in the wholesale
    // Modifiers state events. Map both to Option so Alt/Option chords are not
    // silently dropped (issue #450).
    if depressed.contains(XMods::Mod1Mask) || depressed.contains(XMods::Mod5Mask) {
        flags |= CGEventFlags::CGEventFlagAlternate;
    }
    if depressed.contains(XMods::Mod4Mask) {
        flags |= CGEventFlags::CGEventFlagCommand;
    }
    flags
}

// From X11/X.h
bitflags! {
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    struct XMods: u32 {
        const ShiftMask = (1<<0);
        const LockMask = (1<<1);
        const ControlMask = (1<<2);
        const Mod1Mask = (1<<3);
        const Mod2Mask = (1<<4);
        const Mod3Mask = (1<<5);
        const Mod4Mask = (1<<6);
        const Mod5Mask = (1<<7);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edge_thresholds_round_trip_and_are_robust() {
        let dir = std::env::temp_dir().join(format!("hops-edge-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(EDGE_STATE_FILE);

        // format -> load round-trips exactly for in-range values
        let orig = [30.0, 100.0, 60.0, 88.0];
        std::fs::write(&path, format_edge_thresholds(&orig)).unwrap();
        assert_eq!(load_edge_thresholds(Some(&path)), orig);

        // out-of-range clamps; blank/comment/garbage/unparseable lines are
        // skipped (falling back to default or the last valid value)
        std::fs::write(
            &path,
            "# comment\n\nleft = 5\nright = 999\ntop = notanumber\nbogus line\nbottom = 88\n",
        )
        .unwrap();
        let t = load_edge_thresholds(Some(&path));
        assert_eq!(t[0], EDGE_THRESHOLD_MIN); // 5 clamped up to floor
        assert_eq!(t[1], EDGE_THRESHOLD_MAX); // 999 clamped down to ceiling
        assert_eq!(t[2], DEFAULT_EDGE_THRESHOLD); // unparseable -> default
        assert_eq!(t[3], 88.0);

        // missing file and no path both yield all-defaults
        assert_eq!(
            load_edge_thresholds(Some(&dir.join("nope.conf"))),
            [DEFAULT_EDGE_THRESHOLD; 4]
        );
        assert_eq!(load_edge_thresholds(None), [DEFAULT_EDGE_THRESHOLD; 4]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hypervisor_path_matches_known_apps_only() {
        assert!(is_hypervisor_path(
            "/Applications/Parallels Desktop.app/Contents/MacOS/prl_client_app"
        ));
        // macOS guest binary is nested several bundles deep, still matches.
        assert!(is_hypervisor_path(
            "/Applications/Parallels Desktop.app/Contents/MacOS/Parallels Mac VM.app/Contents/MacOS/prl_macvm_app"
        ));
        assert!(is_hypervisor_path(
            "/Applications/VMware Fusion.app/Contents/MacOS/vmware"
        ));
        assert!(is_hypervisor_path(
            "/Applications/UTM.app/Contents/MacOS/UTM"
        ));
        // Real native apps must not match.
        assert!(!is_hypervisor_path(
            "/Applications/Visual Studio Code.app/Contents/MacOS/Code"
        ));
        assert!(!is_hypervisor_path(
            "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"
        ));
        assert!(!is_hypervisor_path(""));
    }

    #[test]
    fn overlay_owners_are_recognised() {
        assert!(is_overlay_owner("WindowServer"));
        assert!(is_overlay_owner("Dock"));
        assert!(!is_overlay_owner("Parallels Desktop"));
        assert!(!is_overlay_owner("Finder"));
    }

    #[test]
    fn representative_keycode_prioritises_command_then_falls_back() {
        assert_eq!(representative_keycode(FLAG_COMMAND), 0x37);
        assert_eq!(representative_keycode(FLAG_SHIFT), 0x38);
        assert_eq!(representative_keycode(FLAG_CONTROL), 0x3B);
        assert_eq!(representative_keycode(FLAG_ALTERNATE), 0x3A);
        // Command wins when several bits are set.
        assert_eq!(representative_keycode(FLAG_COMMAND | FLAG_SHIFT), 0x37);
        // AlphaShift / empty fall back to Caps Lock.
        assert_eq!(representative_keycode(FLAG_ALPHASHIFT), 0x39);
        assert_eq!(representative_keycode(0), 0x39);
    }

    #[test]
    fn modifier_flags_carry_device_dependent_bits_and_noncoalesced() {
        const NX_DEVICE_L_SHIFT: u64 = 0x2;
        const NX_DEVICE_L_CMD: u64 = 0x8;
        let non_coalesced = CGEventFlags::CGEventFlagNonCoalesced.bits();

        // Shift: device-independent shift + device-dependent left-shift + NonCoalesced.
        let f = modifier_flags_changed_flags(XMods::ShiftMask).bits();
        assert_ne!(f & FLAG_SHIFT, 0);
        assert_ne!(f & NX_DEVICE_L_SHIFT, 0);
        assert_ne!(f & non_coalesced, 0);

        // Empty: NonCoalesced only, no managed modifier bits.
        let e = modifier_flags_changed_flags(XMods::empty()).bits();
        assert_eq!(e & MANAGED_FLAG_MASK, 0);
        assert_ne!(e & non_coalesced, 0);

        // Command -> device-independent command + device-dependent left-command.
        let c = modifier_flags_changed_flags(XMods::Mod4Mask).bits();
        assert_ne!(c & FLAG_COMMAND, 0);
        assert_ne!(c & NX_DEVICE_L_CMD, 0);
    }
}
