//! Guards on the Windows backend that run on every OS.
//!
//! Its behaviour can only run on Windows, and no test there drives a real
//! low-level hook, so these read the source. They are scoped to named
//! functions with comments stripped, and a renamed function fails them.

const EVENT_THREAD: &str = include_str!("windows/event_thread.rs");
const DISPLAY_UTIL: &str = include_str!("windows/display_util.rs");
const WINDOWS: &str = include_str!("windows.rs");

/// Everything the OS can call into while a hook is installed: the hook and
/// window procedures and what they call, by file. A panic in any of them
/// unwinds into a Win32 callback, which with `panic = "abort"` ends the
/// daemon while its hooks are still swallowing the machine's input (#80).
const HOOK_PATH: &[(&str, &[&str])] = &[
    (
        EVENT_THREAD,
        &[
            "mouse_proc",
            "kybrd_proc",
            "window_proc",
            "check_client_activation",
            "push_event",
            "to_mouse_event",
            "to_key_event",
            "media_vk_to_evdev",
            "is_lock_vk",
            "update_display_regions",
            "enumerate_displays",
        ],
    ),
    (
        DISPLAY_UTIL,
        &[
            "is_within_dp_region",
            "is_within_dp_boundary",
            "in_bounds",
            "in_display_region",
            "moved_across_boundary",
            "entered_barrier",
            "clamp_to_display_bounds",
        ],
    ),
];

fn strip_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix("//") {
            rest = after.find('\n').map_or("", |i| &after[i..]);
        } else if let Some(after) = rest.strip_prefix("/*") {
            rest = after.find("*/").map_or("", |i| &after[i + 2..]);
        } else {
            let c = rest.chars().next().unwrap_or_default();
            out.push(c);
            rest = &rest[c.len_utf8()..];
        }
    }
    out
}

/// The body of `fn name(`, braces matched, or a failure naming it: a renamed
/// function must fail the guard, not silently leave the scan.
fn body<'a>(src: &'a str, name: &str) -> &'a str {
    let start = src
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("no fn {name} in the Windows backend: update HOOK_PATH"));
    let open = start + src[start..].find('{').expect("a body");
    let mut depth = 0;
    for (i, c) in src[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &src[open..=open + i];
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced braces in fn {name}");
}

#[test]
fn nothing_the_os_calls_into_while_hooked_can_panic() {
    let forbidden = [
        ".unwrap()",
        ".expect(",
        "panic!(",
        "unreachable!(",
        "todo!(",
        "unimplemented!(",
        // Panics when its bounds are out of order.
        ".clamp(",
        "blocking_send",
        "try_send",
        // `with` panics once the thread's locals are being destroyed.
        "EVENT_TX.with(",
    ];
    for (file, names) in HOOK_PATH {
        let src = strip_comments(file);
        for name in *names {
            let body = body(&src, name);
            for f in forbidden {
                assert!(
                    !body.contains(f),
                    "fn {name} in the hook path contains `{f}`"
                );
            }
        }
    }
}

#[test]
fn the_hook_thread_is_joined_only_once_told_to_exit() {
    let src = strip_comments(EVENT_THREAD);
    let drop = body(&src, "drop");
    let exit = drop
        .find(" = self.exit();")
        .expect("drop keeps whether it told the thread to exit");
    let told = drop[..exit]
        .rsplit("let ")
        .next()
        .expect("a binding")
        .trim();
    let join = drop.find(".join()").expect("drop joins the thread");
    assert!(
        exit < join && drop[exit..join].contains(&format!("if {told} {{")),
        "EventThread::drop joins the hook thread even when it could not tell it to exit, \
         which blocks the daemon's loop for good"
    );
}

#[test]
fn the_hooks_hand_events_to_the_queue_that_keeps_releases() {
    let src = strip_comments(EVENT_THREAD);
    for name in ["mouse_proc", "kybrd_proc", "check_client_activation"] {
        assert!(
            body(&src, name).contains("push_event("),
            "fn {name} does not hand its events to push_event"
        );
    }
    assert!(
        body(&src, "push_event").contains(".push("),
        "push_event does not push onto the event queue"
    );
    let windows = strip_comments(WINDOWS);
    assert!(
        body(&windows, "new").contains("event_queue::channel("),
        "the Windows backend is not built on event_queue"
    );
}

#[test]
fn the_hook_thread_is_joined_before_its_queue_receiver_drops() {
    let src = strip_comments(WINDOWS);
    let fields = &src[src
        .find("pub struct WindowsInputCapture")
        .expect("WindowsInputCapture")..];
    let fields = &fields[..fields.find('}').expect("struct end")];
    let thread = fields.find("event_thread:").expect("event_thread field");
    let receiver = fields.find("events:").expect("events field");
    assert!(
        thread < receiver,
        "WindowsInputCapture must declare event_thread before events: fields drop in \
         declaration order"
    );
}

#[test]
fn the_hook_thread_removes_its_hooks_before_it_returns() {
    let src = strip_comments(EVENT_THREAD);
    let routine = body(&src, "start_routine");
    let hooked = routine.find("SetWindowsHookExW").expect("hooks installed");
    let message_loop = routine.find("get_msg()").expect("message loop");
    let unhooked = routine
        .find("UnhookWindowsHookEx")
        .expect("start_routine never removes its hooks");
    assert!(hooked < message_loop && message_loop < unhooked);
}
