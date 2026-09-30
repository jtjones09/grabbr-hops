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

/// `src` without any item marked `#[cfg(test)]`: from the attribute to the
/// end of the item's braces, or to its `;` when it has none first. The
/// item's line breaks stay, so lines keep their numbers.
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
        push_line_breaks(&mut out, &item[..end]);
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
        // The cfgs a build script sets for a Linux backend, and `unix`.
        let mut linux: Vec<&str> = build
            .split("rustc-check-cfg=cfg(")
            .skip(1)
            .filter_map(|s| s.split(')').next())
            .collect();
        linux.push("unix");
        let mut attrs = Vec::new();
        for line in lib.lines().map(str::trim) {
            if line.starts_with("//") {
                continue;
            }
            if line.starts_with("#[") {
                attrs.push(line);
                continue;
            }
            let name = line
                .strip_prefix("pub ")
                .unwrap_or(line)
                .strip_prefix("mod ")
                .and_then(|m| m.strip_suffix(';'));
            let gated = attrs.iter().any(|a| {
                a.starts_with("#[cfg(")
                    && a.split(|c: char| c != '_' && !c.is_ascii_alphanumeric())
                        .any(|w| linux.contains(&w))
            });
            if let (Some(name), true) = (name, gated) {
                checked += 1;
                let file = format!("{dir}/src/{name}.rs");
                if !BACKENDS.iter().any(|(f, _)| *f == file) {
                    missing.push(file);
                }
            }
            attrs.clear();
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
}
