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
//! are left out, since `--help` needs no arguments. A flag written with a
//! placeholder value goes with it, so its name is looked up in the
//! subcommand's help instead. What this cannot check is how many arguments a
//! command takes.

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

/// A `hops` command as a document writes it.
#[derive(Debug, PartialEq)]
struct Documented {
    /// The arguments after `hops`, placeholders and their flags left out.
    args: Vec<String>,
    /// Flags written with a placeholder value, as in `--controller <which>`.
    /// Left out of `args`, since `--help` would need a real value for them.
    valued: Vec<String>,
}

/// The command, if `text` is a `hops` command.
fn hops_arguments(text: &str) -> Option<Documented> {
    let text = text.trim().trim_start_matches("$ ");
    let mut tokens = text
        .split_whitespace()
        .skip_while(|t| is_assignment(t))
        .take_while(|t| !ends_command(t));
    if tokens.next()? != "hops" {
        return None;
    }
    let mut args: Vec<String> = Vec::new();
    let mut valued: Vec<String> = Vec::new();
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
                valued.extend(args.pop());
            }
            continue;
        }
        args.push(token.to_string());
    }
    Some(Documented { args, valued })
}

/// Every `hops` command in `markdown`: each inline code span, and each line
/// of a fenced block, with a trailing backslash joining the next line.
fn commands_in(markdown: &str) -> Vec<Documented> {
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
                    .any(|c| c.args.first().is_some_and(|s| s == "cli")),
                "{REQUIRED} names no `hops cli` command, so its recovery steps are not \
                 checked here; found {commands:?}"
            );
        }
        for Documented { args, valued } in commands {
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
            if !out.status.success() {
                let err = String::from_utf8_lossy(&out.stderr);
                rejected.push(format!("{line}\n    {}", err.lines().next().unwrap_or("")));
                continue;
            }
            // The help lists each flag the subcommand takes, as a word of
            // its own: `--controller <CONTROLLER>`.
            let help = String::from_utf8_lossy(&out.stdout);
            let listed = |flag: &str| {
                help.split(|c: char| c.is_whitespace() || matches!(c, ',' | '[' | ']' | '='))
                    .any(|w| w == flag)
            };
            let unknown: Vec<&String> = valued.iter().filter(|f| !listed(f)).collect();
            if unknown.is_empty() {
                checked.push(line);
            } else {
                rejected.push(format!("{line}\n    its help lists no {unknown:?}"));
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
    let command = |args: &[&str], valued: &[&str]| Documented {
        args: args.iter().map(|s| s.to_string()).collect(),
        valued: valued.iter().map(|s| s.to_string()).collect(),
    };
    assert_eq!(
        commands_in("run `hops cli remove-client <id>` there"),
        vec![command(&["cli", "remove-client"], &[])]
    );
    assert_eq!(
        commands_in("```sh\nHOPS_LOG_LEVEL=debug hops daemon | tee log\n```"),
        vec![command(&["daemon"], &[])]
    );
    assert_eq!(
        commands_in("```sh\nhops cli authorize-key \\\n  --controller <which> <name>\n```"),
        vec![command(&["cli", "authorize-key"], &["--controller"])]
    );
    assert!(commands_in("`hops-linux-x86_64.tar.gz` and `./target/release/hops`").is_empty());
}

/// The first cell of each row of the table in `markdown` whose header starts
/// with `header`.
#[cfg(any(feature = "tui", feature = "slint"))]
fn first_column(markdown: &str, header: &str) -> Vec<String> {
    markdown
        .lines()
        .skip_while(|l| !l.starts_with(header))
        .skip(2)
        .take_while(|l| l.starts_with('|'))
        .filter_map(|l| l.split('|').nth(1))
        .map(|cell| cell.trim().to_string())
        .collect()
}

/// The recovery table in `docs/SECURITY.md` is looked up by what a device's
/// card says, so each state it names must be words a card shows. A state
/// reworded in the frontends, or written from memory in the document, would
/// leave a user looking for a row that matches nothing on their screen.
#[cfg(any(feature = "tui", feature = "slint"))]
#[test]
fn every_card_state_the_recovery_table_names_is_one_a_card_shows() {
    use hops_frontend_core::Connection;

    let doc = Path::new(env!("CARGO_MANIFEST_DIR")).join(REQUIRED);
    let text = std::fs::read_to_string(&doc).expect("docs/SECURITY.md");
    let named = first_column(&text, "| The card says |");
    assert!(
        !named.is_empty(),
        "{REQUIRED} has no table headed `| The card says |`"
    );
    let shown: Vec<&str> = Connection::ALL.iter().map(|c| c.words()).collect();
    let unknown: Vec<&String> = named
        .iter()
        .filter(|n| !shown.contains(&n.as_str()))
        .collect();
    assert!(
        unknown.is_empty(),
        "{REQUIRED} names card states no card shows: {unknown:?}; a card shows {shown:?}"
    );
}
