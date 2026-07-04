#![allow(clashing_extern_declarations)]
//! macOS menu bar (status item) icon for the Slint GUI — lets you reopen the
//! window without relaunching the app, matching the GTK front-end's existing
//! `macos_status_item` module (its reference implementation; not shared code
//! since the two front-ends' window types are unrelated — see that module for
//! the fuller write-up of the raw-AppKit approach and why it's hand-rolled
//! instead of a crate: this is the same mechanism, ported to a `slint::Weak`).
//!
//! Pairs with `run()` calling `slint::run_event_loop_until_quit()` instead of
//! the generated `ui.run()` (which is just `show + run_event_loop + hide`) —
//! `run_event_loop()` quits as soon as the last window is hidden, which would
//! defeat the whole point of a tray icon (nothing left to click "reopen" on).

use std::{
    cell::RefCell,
    ffi::{c_char, c_void, CStr, CString},
    sync::OnceLock,
};

use slint::{ComponentHandle, Weak};

use crate::AppWindow;

type Id = *mut c_void;
type Class = *mut c_void;
type Sel = *mut c_void;
type Bool = i8;

thread_local! {
    static STATUS_ITEM: RefCell<Option<(Weak<AppWindow>, Id, Id)>> = const { RefCell::new(None) };
}

/// Install the menu bar icon and hide the Dock icon. Call once, after the
/// window exists but it doesn't matter whether it's shown yet.
pub fn setup(window: Weak<AppWindow>) {
    STATUS_ITEM.with(|item| {
        if item.borrow().is_some() {
            return; // already set up (e.g. a future re-entrant call)
        }
        unsafe {
            let ns_app = msg_send_id(class(c"NSApplication"), sel(c"sharedApplication"));
            assert!(!ns_app.is_null(), "NSApplication sharedApplication returned null");
            // Accessory: no Dock icon, no Cmd+Tab entry — a menu-bar-only app.
            msg_send_bool_usize(ns_app, sel(c"setActivationPolicy:"), 1);

            let delegate = new_delegate();
            let menu = menu(&[
                menu_item(c"Open hops", c"showHops:"),
                separator_item(),
                menu_item(c"Quit hops", c"quitHops:"),
            ]);

            let status_bar = msg_send_id(class(c"NSStatusBar"), sel(c"systemStatusBar"));
            assert!(!status_bar.is_null(), "NSStatusBar systemStatusBar returned null");
            let status_item = msg_send_id_f64(status_bar, sel(c"statusItemWithLength:"), -1.0);
            assert!(!status_item.is_null(), "statusItemWithLength returned null");
            let status_item = msg_send_id(status_item, sel(c"retain"));

            let button = msg_send_id(status_item, sel(c"button"));
            assert!(!button.is_null(), "NSStatusItem.button was null");
            // No bundled menu-bar icon asset yet (see the GTK reference for the
            // template-image path this would follow once one exists) — a short
            // text title is the same graceful fallback that module already uses
            // when no image is available.
            msg_send_void_id(button, sel(c"setTitle:"), nsstring(c"hops"));
            msg_send_void_id(button, sel(c"setToolTip:"), nsstring(c"hops"));
            msg_send_void_id(status_item, sel(c"setMenu:"), menu);

            for item in menu_items(menu) {
                msg_send_void_id(item, sel(c"setTarget:"), delegate);
            }

            log::debug!("macos_status_item ready at {status_item:p}");
            item.replace(Some((window, delegate, status_item)));
        }
    });
}

/// Bring the app to the front (used after showing the window from a background
/// signal — a second launch's single-instance ping). `.show()` alone doesn't
/// raise an accessory-policy app above whatever's currently focused.
pub fn activate_app() {
    unsafe {
        let ns_app = msg_send_id(class(c"NSApplication"), sel(c"sharedApplication"));
        msg_send_void_bool(ns_app, sel(c"activateIgnoringOtherApps:"), 1);
    }
}

extern "C" fn show_hops(_this: Id, _cmd: Sel, _sender: Id) {
    present_window();
}

fn present_window() {
    STATUS_ITEM.with(|item| {
        let item = item.borrow();
        let Some((window, ..)) = item.as_ref() else { return };
        if let Some(ui) = window.upgrade() {
            let _ = ui.show();
        }
        // .show() alone doesn't raise the window above other apps if hops
        // isn't the active app — matches the GTK reference's own reasoning.
        unsafe {
            let ns_app = msg_send_id(class(c"NSApplication"), sel(c"sharedApplication"));
            msg_send_void_bool(ns_app, sel(c"activateIgnoringOtherApps:"), 1);
        }
    });
}

extern "C" fn quit_hops(_this: Id, _cmd: Sel, _sender: Id) {
    // stops run_event_loop_until_quit(), letting run() return and the process exit
    let _ = slint::quit_event_loop();
}

unsafe fn menu(items: &[Id]) -> Id {
    let menu = msg_send_id(msg_send_id(class(c"NSMenu"), sel(c"alloc")), sel(c"init"));
    for item in items {
        msg_send_void_id(menu, sel(c"addItem:"), *item);
    }
    menu
}

unsafe fn menu_item(title: &CStr, action: &CStr) -> Id {
    msg_send_id_id_sel_id(
        msg_send_id(class(c"NSMenuItem"), sel(c"alloc")),
        sel(c"initWithTitle:action:keyEquivalent:"),
        nsstring(title),
        sel(action),
        nsstring(c""),
    )
}

unsafe fn separator_item() -> Id {
    msg_send_id(class(c"NSMenuItem"), sel(c"separatorItem"))
}

unsafe fn menu_items(menu: Id) -> Vec<Id> {
    let count = msg_send_usize(menu, sel(c"numberOfItems"));
    (0..count)
        .map(|idx| msg_send_id_usize(menu, sel(c"itemAtIndex:"), idx))
        .collect()
}

unsafe fn new_delegate() -> Id {
    let class = delegate_class();
    msg_send_id(msg_send_id(class, sel(c"alloc")), sel(c"init"))
}

fn delegate_class() -> Class {
    static CLASS: OnceLock<usize> = OnceLock::new();

    *CLASS.get_or_init(|| unsafe {
        let superclass = class(c"NSObject");
        let class_name = CString::new("HopsStatusItemDelegate").unwrap();
        let class = objc_allocateClassPair(superclass, class_name.as_ptr(), 0);
        assert!(!class.is_null(), "failed to allocate status item delegate");

        class_addMethod(class, sel(c"showHops:"), show_hops as *const c_void, c"v@:@".as_ptr());
        class_addMethod(class, sel(c"quitHops:"), quit_hops as *const c_void, c"v@:@".as_ptr());
        objc_registerClassPair(class);
        class as usize
    }) as Class
}

unsafe fn class(name: &CStr) -> Class {
    let class = objc_getClass(name.as_ptr());
    assert!(!class.is_null(), "missing Objective-C class {name:?}");
    class
}

unsafe fn sel(name: &CStr) -> Sel {
    sel_registerName(name.as_ptr())
}

unsafe fn nsstring(value: &CStr) -> Id {
    msg_send_id_ptr(class(c"NSString"), sel(c"stringWithUTF8String:"), value.as_ptr())
}

#[link(name = "objc")]
extern "C" {
    fn objc_allocateClassPair(superclass: Class, name: *const c_char, extra_bytes: usize) -> Class;
    fn objc_getClass(name: *const c_char) -> Class;
    fn objc_registerClassPair(class: Class);
    fn sel_registerName(name: *const c_char) -> Sel;
    fn class_addMethod(class: Class, name: Sel, imp: *const c_void, types: *const c_char) -> Bool;
}

#[link(name = "AppKit", kind = "framework")]
extern "C" {}

#[link(name = "objc")]
extern "C" {
    #[link_name = "objc_msgSend"]
    fn msg_send_id(receiver: Id, selector: Sel) -> Id;
    #[link_name = "objc_msgSend"]
    fn msg_send_id_f64(receiver: Id, selector: Sel, value: f64) -> Id;
    #[link_name = "objc_msgSend"]
    fn msg_send_id_id_sel_id(receiver: Id, selector: Sel, a: Id, b: Sel, c: Id) -> Id;
    #[link_name = "objc_msgSend"]
    fn msg_send_id_ptr(receiver: Id, selector: Sel, value: *const c_char) -> Id;
    #[link_name = "objc_msgSend"]
    fn msg_send_id_usize(receiver: Id, selector: Sel, value: usize) -> Id;
    #[link_name = "objc_msgSend"]
    fn msg_send_usize(receiver: Id, selector: Sel) -> usize;
    #[link_name = "objc_msgSend"]
    fn msg_send_void_bool(receiver: Id, selector: Sel, value: Bool);
    #[link_name = "objc_msgSend"]
    fn msg_send_void_id(receiver: Id, selector: Sel, value: Id);
    #[link_name = "objc_msgSend"]
    fn msg_send_bool_usize(receiver: Id, selector: Sel, value: usize) -> Bool;
}
