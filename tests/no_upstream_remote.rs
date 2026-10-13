//! No tracked script contacts the project this one was forked from.
//!
//! The fork is severed: nothing here fetches from, pulls from or pushes to a
//! lan-mouse remote. `scripts/provenance.sh` ran `git fetch upstream` on
//! every run, with its failure hidden, so the rule held only for as long as
//! nobody had a remote by that name.
//!
//! This reads the scripts because what they would contact is not observable
//! without running them against a network. It reads every tracked script
//! outside a `tests` directory, skipping comment lines, so the prose that
//! explains the rule is not read as breaking it, and reads a command continued
//! with a backslash as one line. `git fetch --all` and `git remote update`
//! count as contact: on a clone with an upstream remote, they reach it.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every tracked file, relative to the top of the checkout.
fn tracked() -> Vec<String> {
    let mut git = Command::new("git");
    // A hook can point git at another repository or index through the
    // environment.
    for (key, _) in std::env::vars_os() {
        let key = key.to_string_lossy().into_owned();
        if key.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("GIT_")) {
            git.env_remove(key);
        }
    }
    let out = git
        .args(["-c", "safe.directory=*", "-C"])
        .arg(repo())
        .args(["ls-files", "-z"])
        .output()
        .expect("this guard lists the files it reads with `git ls-files`; git must run");
    assert!(
        out.status.success(),
        "git ls-files failed, so nothing was checked: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .expect("tracked paths are UTF-8")
        .split('\0')
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect()
}

const SCRIPT_EXTENSIONS: &[&str] = &[
    "sh", "bash", "command", "ps1", "psm1", "cmd", "bat", "py", "yml", "yaml", "nix",
];

/// A script by its extension, or by a `#!` line when it has none.
fn is_script(path: &str, text: &str) -> bool {
    let file = path.rsplit('/').next().unwrap_or(path);
    match Path::new(file).extension().and_then(|e| e.to_str()) {
        Some(ext) => SCRIPT_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()),
        None => text.starts_with("#!") || path.starts_with(".githooks/"),
    }
}

fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    let lower = t.to_ascii_lowercase();
    t.starts_with('#') || t.starts_with("::") || lower.starts_with("rem ") || lower == "rem"
}

/// What names the upstream project or a remote that stands for it.
fn names_upstream(word: &str) -> bool {
    let w = word.to_ascii_lowercase();
    w == "upstream"
        || w.starts_with("upstream/")
        || w.contains("lan-mouse")
        || w.contains("lan_mouse")
        || w.contains("feschber")
}

/// The git verbs that reach a remote, or set one up to be reached.
const CONTACT: &[&str] = &[
    "fetch",
    "pull",
    "push",
    "clone",
    "ls-remote",
    "remote",
    "submodule",
];

/// Why `line` contacts the upstream project, if it does.
fn contacts_upstream(line: &str) -> Option<&'static str> {
    let words: Vec<&str> = line
        .split(|c: char| c.is_whitespace() || ";|&()'\"`".contains(c))
        .filter(|w| !w.is_empty())
        .collect();
    if let Some(git) = words
        .iter()
        .position(|w| *w == "git" || w.ends_with("/git"))
    {
        let rest = &words[git + 1..];
        if rest.iter().any(|w| CONTACT.contains(w)) && rest.iter().any(|w| names_upstream(w)) {
            return Some("a git command that reaches the upstream project");
        }
        let every_remote = rest.iter().any(|w| *w == "--all" || *w == "--multiple")
            && rest.iter().any(|w| *w == "fetch" || *w == "pull");
        let update = rest
            .windows(2)
            .any(|pair| pair[0] == "remote" && pair[1] == "update");
        if every_remote || update {
            return Some("a git command that reaches every remote, an upstream one included");
        }
    }
    let lower = line.to_ascii_lowercase();
    if (lower.contains("uses:") || lower.contains("repository:"))
        && words.iter().any(|w| names_upstream(w))
    {
        return Some("a workflow step that checks out the upstream project");
    }
    None
}

/// The commands in `text` with the line each starts on, a line ending in a
/// backslash joined to the next, and comment lines left out.
fn commands(text: &str) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = Vec::new();
    let mut open: Option<(usize, String)> = None;
    for (n, line) in text.lines().enumerate() {
        let line = line.trim_end_matches('\r');
        let (start, mut command) = match open.take() {
            Some((start, so_far)) => (start, so_far + " "),
            None if is_comment(line) => continue,
            None => (n + 1, String::new()),
        };
        match line.strip_suffix('\\') {
            Some(cut) => {
                command.push_str(cut);
                open = Some((start, command));
            }
            None => {
                command.push_str(line);
                out.push((start, command));
            }
        }
    }
    out.extend(open);
    out
}

// LEDGER T4a | class S | the recogniser below, on sample lines | pair NONE (test code)
#[test]
fn the_check_recognises_contact_and_nothing_else() {
    for line in [
        "git fetch upstream --quiet 2>/dev/null || true",
        "git -C \"$repo\" pull upstream main",
        "git push upstream HEAD",
        "git remote add upstream https://github.com/feschber/lan-mouse",
        "git clone https://github.com/feschber/lan-mouse.git",
        "  - uses: actions/checkout@v4 # repository: feschber/lan-mouse",
        "        repository: feschber/lan-mouse",
        // Every remote, so the upstream one on a clone that has it.
        "git fetch --all --quiet 2>/dev/null || true",
        "git -C \"$repo\" pull --all",
        "git fetch --multiple origin other",
        "git remote update",
    ] {
        assert!(contacts_upstream(line).is_some(), "missed: {line}");
    }
    // A command continued onto the next line is read as one.
    assert_eq!(
        commands("git fetch \\\n  upstream --quiet\necho done"),
        vec![
            (1, "git fetch    upstream --quiet".to_owned()),
            (3, "echo done".to_owned())
        ]
    );
    for line in [
        "BASE=$(git merge-base HEAD upstream/main)",
        "git -C \"$repo\" fetch --quiet",
        "git -C \"$repo\" merge --ff-only --quiet '@{upstream}'",
        "git rev-parse -q --verify \"@{upstream}\" >nul 2>&1",
        "github: [feschber]",
    ] {
        assert!(contacts_upstream(line).is_none(), "misread: {line}");
    }
}

// LEDGER T4 | class S | text of every tracked script | pair NONE (contact needs a network)
#[test]
fn no_tracked_script_contacts_the_upstream_project() {
    let mut read = 0;
    let mut found = Vec::new();
    for path in tracked() {
        if path.split('/').any(|part| part == "tests") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(repo().join(&path)) else {
            continue;
        };
        if !is_script(&path, &text) {
            continue;
        }
        read += 1;
        for (n, command) in commands(&text) {
            if let Some(why) = contacts_upstream(&command) {
                found.push(format!("{path}:{n}: {why}: {}", command.trim()));
            }
        }
    }
    assert!(
        read >= 10,
        "only {read} scripts were read; the listing or the filter is broken"
    );
    assert!(
        found.is_empty(),
        "this repository never fetches from or pushes to the project it was \
         forked from:\n{}",
        found.join("\n")
    );
}
