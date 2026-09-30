//! The name hops shows the desktop is its own, in every place it is shown.
//!
//! On Linux the prompt that grants hops the keyboard and mouse is the only
//! thing telling the user who is asking (#113). It is drawn from three
//! places that must agree: `input_event::APP_ID`, which the portal
//! registration and the libei handshake send; the desktop entry of that id,
//! which the portal reads the displayed name from; and the macOS bundle
//! identifier, which is the same identity on the other platform. The
//! handshake itself is observed in input-capture and input-emulation, against
//! a stand-in compositor.

use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn desktop_entry() -> PathBuf {
    repo()
        .join("resources")
        .join(format!("{}.desktop", input_event::APP_ID))
}

// LEDGER T4 | class S | Cargo.toml's bundle metadata against input_event::APP_ID | pair T2, T3
/// One product, one identity: the Linux portal and the macOS signature name
/// the same application.
#[test]
fn the_portal_identity_is_the_macos_bundle_identifier() {
    let manifest: toml_edit::DocumentMut = std::fs::read_to_string(repo().join("Cargo.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let bundle = manifest["package"]["metadata"]["bundle"]["identifier"].as_str();
    assert_eq!(
        bundle,
        Some(input_event::APP_ID),
        "the macOS bundle identifier and the id hops gives the Linux portal differ"
    );
}

// LEDGER T5 | class S | the shipped desktop entry, read by GLib's load rules | pair T6
/// The portal names a registered caller from `<id>.desktop`, and drops an
/// entry GLib will not load: the first group must be `[Desktop Entry]`, the
/// type `Application`, and TryExec, if any, must resolve. A `Hidden` entry
/// counts as deleted; `NoDisplay` keeps it out of menus, which is what an
/// entry that is not a launcher wants.
#[test]
fn the_shipped_desktop_entry_is_the_one_the_portal_looks_up() {
    let path = desktop_entry();
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{} is missing ({e}): the portal finds no name for {}, and the consent \
             prompt asks for an unnamed application",
            path.display(),
            input_event::APP_ID
        )
    });
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    assert_eq!(lines.first(), Some(&"[Desktop Entry]"), "the first group");
    assert!(
        lines.iter().filter(|l| l.starts_with('[')).count() == 1,
        "one group only"
    );
    let key = |k: &str| -> Option<&str> {
        lines
            .iter()
            .find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix('=')))
    };
    assert_eq!(key("Type"), Some("Application"));
    assert_eq!(key("Name"), Some("hops"), "the name the prompt shows");
    assert_eq!(
        key("Exec"),
        Some("hops"),
        "the binary as the release names it"
    );
    assert_eq!(key("NoDisplay"), Some("true"), "not a menu launcher");
    assert_eq!(key("TryExec"), None);
    assert_eq!(key("Hidden"), None, "a hidden entry is a deleted one");
}

/// Every string literal in `src`, which is Rust or Slint: both write strings
/// in double quotes with backslash escapes and comments as `//` and `/* */`.
fn string_literals(src: &str) -> Vec<String> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                i += 2;
            }
            // A char literal, so that '"' does not open a string; otherwise a
            // lifetime.
            b'\'' => {
                if b.get(i + 1) == Some(&b'\\') {
                    i += 2;
                    while i < b.len() && b[i] != b'\'' {
                        i += 1;
                    }
                    i += 1;
                } else if b.get(i + 2) == Some(&b'\'') {
                    i += 3;
                } else {
                    i += 1;
                }
            }
            b'r' if matches!(b.get(i + 1), Some(b'#') | Some(b'"'))
                && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_')) =>
            {
                let hashes = b[i + 1..].iter().take_while(|&&c| c == b'#').count();
                let open = i + 1 + hashes;
                if b.get(open) != Some(&b'"') {
                    i += 1;
                    continue;
                }
                let close = format!("\"{}", "#".repeat(hashes));
                let body = &src[open + 1..];
                let end = body.find(&close).unwrap_or(body.len());
                out.push(body[..end].to_owned());
                i = open + 1 + end + close.len();
            }
            b'"' => {
                let start = i + 1;
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
                out.push(String::from_utf8_lossy(&b[start..i.min(b.len())]).into_owned());
                i += 1;
            }
            _ => i += 1,
        }
    }
    out
}

/// Source a user can be shown: every `.rs` under `src/` and each crate's
/// `src/`, less test modules, and the Slint UI.
fn shipped_sources() -> Vec<(PathBuf, String)> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let p = entry.path();
            if p.is_dir() {
                walk(&p, out);
            } else if matches!(p.extension().and_then(|e| e.to_str()), Some("rs" | "slint")) {
                out.push(p);
            }
        }
    }
    let mut roots = vec![repo().join("src")];
    for c in std::fs::read_dir(repo().join("crates")).unwrap().flatten() {
        roots.push(c.path().join("src"));
        roots.push(c.path().join("ui"));
    }
    let mut files = Vec::new();
    for r in roots.iter().filter(|r| r.is_dir()) {
        walk(r, &mut files);
    }
    // Files that are whole test modules: `#[cfg(test)]` above `mod name;`.
    let mut test_only = Vec::new();
    for f in &files {
        let text = std::fs::read_to_string(f).unwrap();
        let lines: Vec<&str> = text.lines().map(str::trim).collect();
        for w in lines.windows(2) {
            if w[0] == "#[cfg(test)]" {
                let decl = w[1]
                    .trim_start_matches("pub(crate) ")
                    .trim_start_matches("pub ");
                if let Some(name) = decl.strip_prefix("mod ").and_then(|m| m.strip_suffix(';')) {
                    let dir = f.parent().unwrap();
                    test_only.push(dir.join(format!("{name}.rs")));
                    test_only.push(dir.join(name).join("mod.rs"));
                }
            }
        }
    }
    files
        .into_iter()
        .filter(|f| !test_only.contains(f))
        .map(|f| {
            let text = std::fs::read_to_string(&f).unwrap();
            // Test modules at the end of a file. No trailing newline in the
            // pattern, so a CRLF checkout splits too.
            let code = text.split("\n#[cfg(test)]").next().unwrap_or("").to_owned();
            (f, code)
        })
        .collect()
}

/// The upstream application's names. `lan-mouse` is not one of them: it is
/// the state directory, kept on purpose and never shown as an identity.
const UPSTREAM_IDENTITY: [&str; 2] = ["de.feschber", "LanMouse"];

// LEDGER T7 | class S | string literals in shipped source | pair T2, T3
/// Text invariant, because an identity string can reach the user through
/// paths no test drives: a portal, a compositor, a window title.
#[test]
fn no_shipped_string_names_the_upstream_application() {
    let sources = shipped_sources();
    assert!(
        sources.len() > 50,
        "the walk found {} files; it is not reading the tree",
        sources.len()
    );
    let mut found = Vec::new();
    for (file, code) in &sources {
        for s in string_literals(code) {
            if UPSTREAM_IDENTITY.iter().any(|n| s.contains(n)) {
                let rel = file.strip_prefix(repo()).unwrap_or(file);
                found.push(format!("{}: \"{s}\"", rel.display()));
            }
        }
    }
    assert!(
        found.is_empty(),
        "shipped strings name the upstream application, which the desktop may \
         show the user as the identity of whatever asks for their input; use \
         input_event::APP_ID:\n{}",
        found.join("\n")
    );
}

// LEDGER T8 | class B | 1 return value: string_literals, the scanner T7 relies on
/// The scanner finds a literal wherever Rust puts one, and nothing in a
/// comment or an identifier.
#[test]
fn the_string_scanner_reads_literals_and_skips_comments_and_names() {
    let src = r####"
        // "in a comment"
        /* "in a block" */
        let c = '"'; let l: &'a str = "one";
        struct LanMouseThing;
        f(r#"two "quoted""#, "three \" escaped",
          "four
           lines");
    "####;
    assert_eq!(
        string_literals(src),
        [
            "one",
            "two \"quoted\"",
            "three \\\" escaped",
            "four\n           lines"
        ]
    );
}
