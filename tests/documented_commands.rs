//! Every `hops` command the user-facing documents tell someone to run is one
//! the binary accepts.
//!
//! The recovery steps in `docs/SECURITY.md` are read at the worst moment: a
//! machine is lost, or one no longer connects. A command there that the
//! binary no longer knows, because a subcommand or flag was renamed, sends
//! that person to an error instead of a fix, and nothing else in the tree
//! would notice. So each command is run, with `--help` appended, against the
//! real binary: clap then checks every subcommand and flag name on the line
//! and exits without doing anything. Placeholders such as `<fingerprint>`
//! are left out, since `--help` needs no arguments; what this cannot check is
//! how many arguments a command takes.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The documents a user is sent to. `docs/SECURITY.md` must exist: it holds
/// the recovery steps this test exists for.
const REQUIRED: &str = "docs/SECURITY.md";

fn documents() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut docs = vec![
        root.join("README.md"),
        root.join("SECURITY.md"),
        root.join("service/README.md"),
    ];
    let mut in_docs: Vec<PathBuf> = std::fs::read_dir(root.join("docs"))
        .expect("the docs directory")
        .map(|e| e.expect("a docs entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "md"))
        .collect();
    in_docs.sort();
    docs.extend(in_docs);
    docs
}

/// Where a shell command ends on a line: a pipe, a list, a redirection or a
/// comment.
fn ends_command(token: &str) -> bool {
    matches!(token, "|" | "||" | "&&" | ";" | "&" | "#")
        || token.starts_with('>')
        || token.starts_with("2>")
        || token.starts_with('#')
}

fn is_placeholder(token: &str) -> bool {
    token.starts_with('<') && token.ends_with('>')
}

/// An environment assignment written before a command, as in
/// `HOPS_LOG_LEVEL=debug hops daemon`.
fn is_assignment(token: &str) -> bool {
    token.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    })
}

/// The arguments after `hops`, if `text` is a `hops` command.
fn hops_arguments(text: &str) -> Option<Vec<String>> {
    let text = text.trim().trim_start_matches("$ ");
    let mut tokens = text
        .split_whitespace()
        .skip_while(|t| is_assignment(t))
        .take_while(|t| !ends_command(t));
    if tokens.next()? != "hops" {
        return None;
    }
    let mut args: Vec<String> = Vec::new();
    for token in tokens {
        if token == "\\" {
            continue;
        }
        if is_placeholder(token) {
            // An option whose value is a placeholder goes with it.
            if args
                .last()
                .is_some_and(|a| a.starts_with('-') && !a.contains('='))
            {
                args.pop();
            }
            continue;
        }
        args.push(token.to_string());
    }
    Some(args)
}

/// Every `hops` command in `markdown`: each inline code span, and each line
/// of a fenced block, with a trailing backslash joining the next line.
fn commands_in(markdown: &str) -> Vec<Vec<String>> {
    let mut found = Vec::new();
    let mut fenced = false;
    let mut pending = String::new();
    for line in markdown.lines() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            pending.clear();
            continue;
        }
        if fenced {
            pending.push_str(line);
            if let Some(joined) = pending.strip_suffix('\\') {
                pending = format!("{joined} ");
                continue;
            }
            found.extend(hops_arguments(&pending));
            pending.clear();
        } else {
            found.extend(
                line.split('`')
                    .skip(1)
                    .step_by(2)
                    .filter_map(hops_arguments),
            );
        }
    }
    found
}

#[test]
fn every_documented_hops_command_is_one_the_binary_accepts() {
    let required = Path::new(env!("CARGO_MANIFEST_DIR")).join(REQUIRED);
    let scratch = std::env::temp_dir().join(format!("hops-doc-commands-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).expect("scratch directory");
    assert!(
        documents().contains(&required),
        "{REQUIRED} is missing: it is where a user is sent to remove a machine or recover one"
    );

    let mut checked = Vec::new();
    let mut rejected = Vec::new();
    for doc in documents() {
        let text = match std::fs::read_to_string(&doc) {
            Ok(text) => text,
            Err(e) => panic!("{}: {e}", doc.display()),
        };
        let commands = commands_in(&text);
        if doc == required {
            assert!(
                commands
                    .iter()
                    .any(|c| c.first().is_some_and(|s| s == "cli")),
                "{REQUIRED} names no `hops cli` command, so its recovery steps are not \
                 checked here; found {commands:?}"
            );
        }
        for args in commands {
            // Nothing runs: `--help` ends the command at parsing. The
            // environment still points everywhere hops could write at the
            // scratch directory, so no real configuration or log is touched.
            let out = Command::new(env!("CARGO_BIN_EXE_hops"))
                .args(&args)
                .arg("--help")
                .env("HOME", &scratch)
                .env("USERPROFILE", &scratch)
                .env("LOCALAPPDATA", &scratch)
                .env("XDG_CONFIG_HOME", &scratch)
                .env("XDG_STATE_HOME", &scratch)
                .env("XDG_RUNTIME_DIR", &scratch)
                .env("HOPS_LOG_FILE", scratch.join("hops.log"))
                .output()
                .expect("run hops");
            let name = doc.strip_prefix(env!("CARGO_MANIFEST_DIR")).unwrap_or(&doc);
            let line = format!("{}: hops {}", name.display(), args.join(" "));
            if out.status.success() {
                checked.push(line);
            } else {
                let err = String::from_utf8_lossy(&out.stderr);
                rejected.push(format!("{line}\n    {}", err.lines().next().unwrap_or("")));
            }
        }
    }
    let _ = std::fs::remove_dir_all(&scratch);

    assert!(
        rejected.is_empty(),
        "documented commands the binary does not accept:\n{}",
        rejected.join("\n")
    );
    assert!(!checked.is_empty(), "no documented hops command was found");
}

#[test]
fn a_command_is_read_as_the_shell_would_split_it() {
    assert_eq!(
        commands_in("run `hops cli remove-authorized-key <fingerprint>` there"),
        vec![vec!["cli".to_string(), "remove-authorized-key".to_string()]]
    );
    assert_eq!(
        commands_in("```sh\nHOPS_LOG_LEVEL=debug hops daemon | tee log\n```"),
        vec![vec!["daemon".to_string()]]
    );
    assert_eq!(
        commands_in("```sh\nhops cli authorize-key \\\n  --controller <which> <name>\n```"),
        vec![vec!["cli".to_string(), "authorize-key".to_string()]]
    );
    assert!(commands_in("`hops-linux-x86_64.tar.gz` and `./target/release/hops`").is_empty());
}
