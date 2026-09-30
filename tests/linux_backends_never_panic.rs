//! The Linux input backends read what a compositor, a portal or the
//! environment hands them: barrier ids, cursor positions, outputs, ei events.
//! Much of it is optional by protocol, and the release builds with
//! `panic = "abort"`, so an `.expect()` on it turns a terse but conforming
//! compositor into a daemon that exits (#103).
//!
//! Their behaviour needs a Wayland session, a portal or an EIS server, which
//! CI does not have, so this reads the source. It scans every non-test line
//! of each backend with comments and the text of literals stripped, on
//! every OS. The decisions the backends make on terse data are tested by
//! behaviour next to them.

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
/// handed is not what the code assumed. A token match: it does not see
/// `.expect (`, `Option::unwrap(x)` or slice indexing, so it is a floor,
/// not a proof.
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

/// `src` with comments removed and the insides of string, raw string and
/// char literals blanked, keeping every line break, so line `n` of the
/// result is line `n` of `src`. A `//` or `/*` inside a literal is text, not
/// a comment, and a brace inside one is not a brace. Panics on an
/// unterminated comment or literal, which compiling source cannot have: the
/// scan would otherwise skip the rest of the file without a word.
fn strip_comments(file: &str, src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < src.len() {
        let rest = &src[i..];
        let c = rest.chars().next().unwrap_or_default();
        if rest.starts_with("//") {
            i += rest.find('\n').unwrap_or(rest.len());
        } else if rest.starts_with("/*") {
            let len = block_comment_len(file, rest);
            push_line_breaks(&mut out, &rest[..len]);
            i += len;
        } else if c == '"' {
            let len = string_len(file, rest);
            out.push('"');
            push_line_breaks(&mut out, &rest[..len]);
            out.push('"');
            i += len;
        } else if c == '\'' {
            match char_literal_len(rest) {
                Some(len) => {
                    out.push_str("' '");
                    i += len;
                }
                // A lifetime or a label.
                None => {
                    out.push('\'');
                    i += 1;
                }
            }
        } else if c == '_' || c.is_ascii_alphanumeric() {
            let len = rest
                .find(|c: char| c != '_' && !c.is_ascii_alphanumeric())
                .unwrap_or(rest.len());
            let word = &rest[..len];
            let after = &rest[len..];
            let hashes = after.len() - after.trim_start_matches('#').len();
            if matches!(word, "r" | "br" | "cr") && after[hashes..].starts_with('"') {
                let close = format!("\"{}", "#".repeat(hashes));
                let body = &after[hashes + 1..];
                let Some(end) = body.find(&close) else {
                    panic!("{file}: unterminated raw string");
                };
                out.push('"');
                push_line_breaks(&mut out, &body[..end]);
                out.push('"');
                i += len + hashes + 1 + end + close.len();
            } else {
                out.push_str(word);
                i += len;
            }
        } else {
            out.push(c);
            i += c.len_utf8();
        }
    }
    out
}

fn push_line_breaks(out: &mut String, text: &str) {
    out.extend(text.matches('\n'));
}

/// The length of the block comment `rest` starts with; they nest.
fn block_comment_len(file: &str, rest: &str) -> usize {
    let mut depth = 0usize;
    let mut i = 0;
    while i < rest.len() {
        if rest[i..].starts_with("/*") {
            depth += 1;
            i += 2;
        } else if rest[i..].starts_with("*/") {
            depth -= 1;
            i += 2;
            if depth == 0 {
                return i;
            }
        } else {
            i += rest[i..].chars().next().map_or(1, char::len_utf8);
        }
    }
    panic!("{file}: unterminated block comment");
}

/// The length of the string literal `rest` starts with, quotes included.
fn string_len(file: &str, rest: &str) -> usize {
    let mut chars = rest.char_indices().skip(1);
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => {
                chars.next();
            }
            '"' => return i + 1,
            _ => {}
        }
    }
    panic!("{file}: unterminated string literal");
}

/// The length of the char literal `rest` starts with, or `None` when the
/// `'` opens a lifetime or a label.
fn char_literal_len(rest: &str) -> Option<usize> {
    let mut chars = rest.char_indices().skip(1);
    let (_, c) = chars.next()?;
    if c == '\\' {
        // `'\n'`, `'\''`, `'\u{1F600}'`: the escaped char, then up to `'`.
        chars.next()?;
        let (end, _) = chars.find(|&(_, c)| c == '\'' || c == '\n')?;
        return rest[end..].starts_with('\'').then_some(end + 1);
    }
    let (end, close) = chars.next()?;
    (close == '\'').then_some(end + 1)
}

/// `src` without its test items: a `#[cfg(test)]`, any further attributes,
/// then a `mod`, `fn`, `impl`, `use`, `const` or `static` item, removed to
/// its `;` or the end of its braces. A `#[cfg(test)]` on anything else, a
/// field, a match arm or a statement, leaves the code in the scan: a false
/// positive is loud, a skipped line is not. Line breaks stay, so lines keep
/// their numbers.
fn without_test_items(file: &str, src: &str) -> String {
    const MARK: &str = "#[cfg(test)]";
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    while let Some(at) = rest.find(MARK) {
        let after = &rest[at + MARK.len()..];
        match test_item_len(file, after) {
            Some(len) => {
                out.push_str(&rest[..at]);
                push_line_breaks(&mut out, &after[..len]);
                rest = &after[len..];
            }
            None => {
                out.push_str(&rest[..at + MARK.len()]);
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The length of the test item `item` starts with, attributes included, or
/// `None` when what follows the `#[cfg(test)]` is not an item that holds
/// test code.
fn test_item_len(file: &str, item: &str) -> Option<usize> {
    let mut i = 0;
    let braced = loop {
        i += item[i..].len() - item[i..].trim_start().len();
        let rest = &item[i..];
        if rest.starts_with("#[") {
            i += 1 + group_len(file, &rest[1..]);
            continue;
        }
        let len = rest
            .find(|c: char| c != '_' && !c.is_ascii_alphanumeric())
            .unwrap_or(rest.len());
        let word = &rest[..len];
        i += len;
        match word {
            "pub" if item[i..].starts_with('(') => i += group_len(file, &item[i..]),
            "pub" | "async" | "unsafe" => {}
            // `const fn` is a function, with a body to skip.
            "const" if item[i..].trim_start().starts_with("fn ") => {}
            "mod" | "fn" | "impl" => break true,
            "use" | "const" | "static" => break false,
            _ => return None,
        }
    };
    // To a `;` outside any brackets or, for an item with a body, the brace
    // that closes the body.
    let mut depth = 0usize;
    for (at, c) in item[i..].char_indices() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 && c == '}' && braced {
                    return Some(i + at + 1);
                }
            }
            ';' if depth == 0 => return Some(i + at + 1),
            _ => {}
        }
    }
    panic!("{file}: unbalanced brackets after #[cfg(test)]");
}

/// The length of `group` up to and including the bracket that closes the
/// one it opens with.
fn group_len(file: &str, group: &str) -> usize {
    let mut depth = 0usize;
    for (i, c) in group.char_indices() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
    }
    panic!("{file}: unbalanced brackets after #[cfg(test)]");
}

/// What the scan reads of `src`: its non-test code, comments stripped.
fn scanned(file: &str, src: &str) -> String {
    without_test_items(file, &strip_comments(file, src))
}

// LEDGER | source-text | the non-test source of the Linux backends
#[test]
fn no_linux_backend_panics_on_what_it_is_handed() {
    let mut found = Vec::new();
    for (file, src) in BACKENDS {
        let original: Vec<&str> = src.lines().collect();
        for (n, line) in scanned(file, src).lines().enumerate() {
            if FORBIDDEN.iter().any(|f| line.contains(f)) {
                let shown = original.get(n).map_or(line, |l| l.trim());
                found.push(format!("{file}:{}: `{shown}`", n + 1));
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
        let code = scanned(file, src);
        assert!(
            code.contains("fn "),
            "{file}: nothing left to scan once comments and tests are removed"
        );
        assert_eq!(
            code.lines().count(),
            src.lines().count(),
            "{file}: the scan lost lines, so it reports the wrong ones"
        );
    }
    let kept = |sample: &str| scanned("sample", sample);

    let sample = "fn a() { x.unwrap(); }\n#[cfg(test)]\nmod tests { fn b() { y.unwrap(); } }\n";
    assert!(kept(sample).contains("x.unwrap()") && !kept(sample).contains("y.unwrap()"));
    let commented = kept("// z.unwrap()\n/* w.expect(\"\") /* nested */ v.unwrap() */ fn c() {}");
    assert!(!commented.contains("unwrap") && !commented.contains("expect"));

    // Text in a literal that looks like a comment, a quote or a brace.
    for (sample, what) in [
        (
            "log::debug!(\"see https://example.org/ {}\", n.checked_add(1).unwrap());",
            "a URL in a string",
        ),
        (
            "let _sockets = \"/run/user/*\";\nlet t = now().unwrap();\n",
            "a glob in a string",
        ),
        ("let q = '\"'; let t = now().unwrap();", "a quote as a char"),
        ("let s = '/'; let d = '/'; t.unwrap();", "slashes as chars"),
        ("let e = '\\''; let t = now().unwrap();", "an escaped quote"),
        (
            "let s = \"a \\\" // b\"; t.unwrap();",
            "an escaped quote in a string",
        ),
        (
            "let r = r#\"say \"hi\" // there\"#; t.unwrap();",
            "a raw string",
        ),
        (
            "let p = r\"C:\\\"; t.unwrap(); let q = \"x\";",
            "a backslash ending a raw string",
        ),
        (
            "fn f<'a>(s: &'a str) -> &'a str { s.get(0..).unwrap() }",
            "lifetimes",
        ),
        (
            "#[cfg(test)]\nmod t { fn b() { let s = \"}\"; y.unwrap(); } }\nfn after() { v.unwrap(); }",
            "a brace in a string in a test",
        ),
        (
            "struct P { #[cfg(test)] a: u8, b: u8 }\nfn c() -> u8 { t.unwrap() }",
            "a test-only field",
        ),
        (
            "let r = match v { #[cfg(test)] 0 => 1, _ => t.unwrap(), };",
            "a test-only match arm",
        ),
        (
            "#[cfg(test)]\n#[allow(dead_code)]\npub(crate) mod t { fn b() { y.unwrap(); } }\nfn a() { x.unwrap(); }",
            "a test module with more attributes",
        ),
        (
            "#[cfg(test)] mod t;\nfn a() { x.unwrap(); }",
            "a test module in its own file",
        ),
        (
            "#[cfg(test)]\nfn h(a: [u8; 2]) { y.unwrap(); }\nfn a() { x.unwrap(); }",
            "a test helper function",
        ),
        (
            "#[cfg(test)]\nimpl S { fn h() { y.unwrap(); } }\n#[cfg(test)]\nuse a::{b, c};\nfn a() { x.unwrap(); }",
            "a test impl and use",
        ),
        (
            "#[cfg(test)]\nconst fn h() -> u8 { y.unwrap(); 1 }\nfn a() { x.unwrap(); }\nconst Z: u8 = 1;",
            "a test const fn",
        ),
    ] {
        let code = kept(sample);
        assert!(
            code.contains(".unwrap()") && !code.contains("y.unwrap()"),
            "the scan misses code after {what}: {code:?}"
        );
    }

    for unterminated in [
        "/* never closed\nx.unwrap();",
        "let s = \"/run/*\nx.unwrap();",
    ] {
        assert!(
            std::panic::catch_unwind(|| kept(unterminated)).is_err(),
            "an unterminated comment or string silently ended the scan: {unterminated:?}"
        );
    }
}

/// Every Linux module the backend crates declare is one the scan reads: a
/// backend added later is otherwise never looked at.
#[test]
fn every_linux_backend_is_scanned() {
    const CRATES: &[(&str, &str, &str)] = &[
        (
            "crates/input-capture",
            include_str!("../crates/input-capture/src/lib.rs"),
            include_str!("../crates/input-capture/build.rs"),
        ),
        (
            "crates/input-emulation",
            include_str!("../crates/input-emulation/src/lib.rs"),
            include_str!("../crates/input-emulation/build.rs"),
        ),
        (
            "crates/input-event",
            include_str!("../crates/input-event/src/lib.rs"),
            "",
        ),
    ];
    let mut checked = 0;
    let mut missing = Vec::new();
    for (dir, lib, build) in CRATES {
        for name in linux_modules(lib, &linux_cfgs(build)) {
            checked += 1;
            let file = format!("{dir}/src/{name}.rs");
            if !BACKENDS.iter().any(|(f, _)| *f == file) {
                missing.push(file);
            }
        }
    }
    assert!(
        checked >= BACKENDS.len(),
        "found {checked} Linux modules, fewer than the {} scanned: the \
         search no longer reads the crates",
        BACKENDS.len()
    );
    assert!(
        missing.is_empty(),
        "Linux backends the panic scan does not read; add them to BACKENDS:\n{}",
        missing.join("\n")
    );

    for (lib, what) in [
        ("#[cfg(unix)]\nmod a;\n", "a cfg on its own line"),
        (
            "#[cfg(target_os = \"linux\")]\npub mod a;\n",
            "target_os = \"linux\"",
        ),
        (
            "#[cfg(all(\n    feature = \"x\",\n    unix,\n))]\nmod a;\n",
            "a cfg over several lines",
        ),
        (
            "#[cfg(unix)] pub(crate) mod a;\n",
            "a cfg and a module on one line",
        ),
        (
            "#[cfg(unix)]\n#[allow(dead_code)]\nmod a;\n",
            "a cfg and a further attribute",
        ),
    ] {
        assert_eq!(
            linux_modules(lib, &linux_cfgs("")),
            ["a"],
            "a Linux module declared with {what} is not found"
        );
    }
}

/// The words that make a `#[cfg(...)]` a Linux one: the cfgs `build` sets
/// for a Linux backend, `unix`, and the `linux` of `target_os = "linux"`.
fn linux_cfgs(build: &str) -> Vec<&str> {
    let mut linux: Vec<&str> = build
        .split("rustc-check-cfg=cfg(")
        .skip(1)
        .filter_map(|s| s.split(')').next())
        .collect();
    linux.extend(["unix", "linux"]);
    linux
}

/// The modules `lib` declares under a `#[cfg(...)]` naming one of `linux`,
/// with the attribute on the module's line, above it, or over several
/// lines. A word such as `not(unix)` counts too: a module listed that is
/// not a backend fails loudly, one missed is never scanned.
fn linux_modules<'a>(lib: &'a str, linux: &[&str]) -> Vec<&'a str> {
    let mut found = Vec::new();
    let mut attrs = Vec::new();
    // An attribute still open at the end of a line, and its bracket depth.
    let mut open = String::new();
    let mut depth = 0i32;
    let brackets = |s: &str| s.matches('[').count() as i32 - s.matches(']').count() as i32;
    for line in lib.lines().map(str::trim) {
        if line.starts_with("//") {
            continue;
        }
        if depth > 0 {
            open.push(' ');
            open.push_str(line);
            depth += brackets(line);
            if depth <= 0 {
                attrs.push(std::mem::take(&mut open));
            }
            continue;
        }
        let mut rest = line;
        while rest.starts_with("#[") {
            // The `]` that closes the attribute's `#[`, if on this line.
            let mut d = 0i32;
            let close = rest.char_indices().skip(1).find(|&(_, c)| {
                d += match c {
                    '[' => 1,
                    ']' => -1,
                    _ => 0,
                };
                d == 0
            });
            match close {
                Some((end, _)) => {
                    attrs.push(rest[..=end].to_string());
                    rest = rest[end + 1..].trim_start();
                }
                None => {
                    open = rest.to_string();
                    depth = brackets(rest);
                    rest = "";
                }
            }
        }
        if rest.is_empty() {
            continue;
        }
        let item = match rest.strip_prefix("pub") {
            Some(vis) if vis.starts_with('(') => vis.find(')').map_or(vis, |i| &vis[i + 1..]),
            Some(vis) => vis,
            None => rest,
        };
        let name = item
            .trim_start()
            .strip_prefix("mod ")
            .and_then(|m| m.strip_suffix(';'));
        let gated = attrs.iter().any(|a| {
            a.starts_with("#[cfg(")
                && a.split(|c: char| c != '_' && !c.is_ascii_alphanumeric())
                    .any(|w| linux.contains(&w))
        });
        if let (Some(name), true) = (name, gated) {
            found.push(name.trim());
        }
        attrs.clear();
    }
    found
}
