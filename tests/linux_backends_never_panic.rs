//! The Linux input backends read what a compositor, a portal or the
//! environment hands them: barrier ids, cursor positions, outputs, ei events.
//! Much of it is optional by protocol, and the release builds with
//! `panic = "abort"`, so an `.expect()` on it turns a terse but conforming
//! compositor into a daemon that exits (#103).
//!
//! Their behaviour needs a Wayland session, a portal or an EIS server, which
//! CI does not have, so this reads the source. It scans every non-test line
//! of each backend with comments stripped, on every OS. The decisions the
//! backends make on terse data are tested by behaviour next to them.

const BACKENDS: &[(&str, &str)] = &[
    (
        "crates/input-capture/src/libei.rs",
        include_str!("../crates/input-capture/src/libei.rs"),
    ),
    (
        "crates/input-capture/src/layer_shell.rs",
        include_str!("../crates/input-capture/src/layer_shell.rs"),
    ),
    (
        "crates/input-capture/src/x11.rs",
        include_str!("../crates/input-capture/src/x11.rs"),
    ),
    (
        "crates/input-emulation/src/libei.rs",
        include_str!("../crates/input-emulation/src/libei.rs"),
    ),
    (
        "crates/input-emulation/src/wlroots.rs",
        include_str!("../crates/input-emulation/src/wlroots.rs"),
    ),
    (
        "crates/input-emulation/src/x11.rs",
        include_str!("../crates/input-emulation/src/x11.rs"),
    ),
    (
        "crates/input-emulation/src/xdg_desktop_portal.rs",
        include_str!("../crates/input-emulation/src/xdg_desktop_portal.rs"),
    ),
    (
        "crates/input-event/src/libei.rs",
        include_str!("../crates/input-event/src/libei.rs"),
    ),
    (
        "crates/input-event/src/portal.rs",
        include_str!("../crates/input-event/src/portal.rs"),
    ),
];

/// Each of these panics, or aborts the release build, when what it is
/// handed is not what the code assumed.
const FORBIDDEN: &[&str] = &[
    ".unwrap()",
    ".expect(",
    "panic!(",
    "unreachable!(",
    "todo!(",
    "unimplemented!(",
    "assert!(",
    "assert_eq!(",
    "assert_ne!(",
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

/// `src` without any item marked `#[cfg(test)]`: from the attribute to the
/// end of the item's braces, or to its `;` when it has none first.
fn without_test_items(file: &str, src: &str) -> String {
    const MARK: &str = "#[cfg(test)]";
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    while let Some(at) = rest.find(MARK) {
        out.push_str(&rest[..at]);
        let item = &rest[at + MARK.len()..];
        let open = item.find('{');
        let semi = item.find(';');
        let end = match (open, semi) {
            (Some(open), Some(semi)) if semi < open => semi + 1,
            (Some(open), _) => open + closing_brace(file, &item[open..]),
            (None, Some(semi)) => semi + 1,
            (None, None) => panic!("{file}: {MARK} marks nothing"),
        };
        rest = &item[end..];
    }
    out.push_str(rest);
    out
}

/// The length of `block` up to and including the brace that closes its
/// first one.
fn closing_brace(file: &str, block: &str) -> usize {
    let mut depth = 0usize;
    for (i, c) in block.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
    }
    panic!("{file}: unbalanced braces after #[cfg(test)]");
}

// LEDGER | source-text | the non-test source of the Linux backends
#[test]
fn no_linux_backend_panics_on_what_it_is_handed() {
    let mut found = Vec::new();
    for (file, src) in BACKENDS {
        let code = without_test_items(file, &strip_comments(src));
        for line in code.lines() {
            for f in FORBIDDEN {
                if line.contains(f) {
                    found.push(format!("{file}: `{}`", line.trim()));
                }
            }
        }
    }
    assert!(
        found.is_empty(),
        "a Linux backend can panic, which ends the daemon in a release build; \
         handle the case instead:\n{}",
        found.join("\n")
    );
}

/// The scan must reach code: an empty file list, or a stripper that ate
/// everything, would pass the guard above while checking nothing.
#[test]
fn the_scan_sees_the_code_it_guards() {
    for (file, src) in BACKENDS {
        let code = without_test_items(file, &strip_comments(src));
        assert!(
            code.contains("fn "),
            "{file}: nothing left to scan once comments and tests are removed"
        );
    }
    let sample = "fn a() { x.unwrap(); }\n#[cfg(test)]\nmod tests { fn b() { y.unwrap(); } }\n";
    let kept = without_test_items("sample", &strip_comments(sample));
    assert!(kept.contains("x.unwrap()") && !kept.contains("y.unwrap()"));
    let commented = strip_comments("// z.unwrap()\n/* w.expect(\"\") */ fn c() {}");
    assert!(!commented.contains("unwrap") && !commented.contains("expect"));
}
