#![allow(clashing_extern_declarations)]
//! macOS app-activation helpers for the menu-bar model. The tray icon itself is
//! now Slint's native `SystemTrayIcon`; all that remains here are the two bits of
//! AppKit it doesn't cover:
//!
//! - `set_accessory_policy()` — make this a menu-bar-only app (no Dock icon, no
//!   Cmd-Tab entry), so a `--hidden` login-autostart is truly menu-bar-only
//!   instead of a windowless app squatting a Dock tile.
//! - `activate_app()` — raise the app to the front when the window is shown from a
//!   background single-instance signal (`.show()` alone won't raise an
//!   accessory-policy app above whatever currently has focus).
//!
//! Raw `objc_msgSend` FFI (same hand-rolled approach as the GTK front-end's
//! reference module), kept tiny on purpose.

use std::ffi::{c_char, c_void, CStr};

type Id = *mut c_void;
type Class = *mut c_void;
type Sel = *mut c_void;
type Bool = i8;

/// Make this a menu-bar-only app: no Dock icon, no Cmd-Tab entry. Call once at
/// startup (before showing any window). `NSApplicationActivationPolicyAccessory`
/// is `1`.
pub fn set_accessory_policy() {
    unsafe {
        let ns_app = msg_send_id(class(c"NSApplication"), sel(c"sharedApplication"));
        assert!(!ns_app.is_null(), "NSApplication sharedApplication returned null");
        msg_send_bool_usize(ns_app, sel(c"setActivationPolicy:"), 1);
    }
}

/// Bring the app to the front. `.show()` alone won't raise an accessory-policy app
/// above whatever's currently focused.
pub fn activate_app() {
    unsafe {
        let ns_app = msg_send_id(class(c"NSApplication"), sel(c"sharedApplication"));
        msg_send_void_bool(ns_app, sel(c"activateIgnoringOtherApps:"), 1);
    }
}

unsafe fn class(name: &CStr) -> Class {
    let class = objc_getClass(name.as_ptr());
    assert!(!class.is_null(), "missing Objective-C class {name:?}");
    class
}

unsafe fn sel(name: &CStr) -> Sel {
    sel_registerName(name.as_ptr())
}

#[link(name = "objc")]
extern "C" {
    fn objc_getClass(name: *const c_char) -> Class;
    fn sel_registerName(name: *const c_char) -> Sel;
}

#[link(name = "AppKit", kind = "framework")]
extern "C" {}

#[link(name = "objc")]
extern "C" {
    #[link_name = "objc_msgSend"]
    fn msg_send_id(receiver: Id, selector: Sel) -> Id;
    #[link_name = "objc_msgSend"]
    fn msg_send_void_bool(receiver: Id, selector: Sel, value: Bool);
    #[link_name = "objc_msgSend"]
    fn msg_send_bool_usize(receiver: Id, selector: Sel, value: usize) -> Bool;
}
