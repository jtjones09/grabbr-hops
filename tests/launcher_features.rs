//! Each platform's dev launcher builds the feature set its release does.
//!
//! On Linux the input backends are features, so a launcher that built the
//! macOS/Windows set produced a binary that could neither capture nor inject,
//! and switched the service onto it. The release build is the one that ships;
//! a dev build meant to test it has to be the same build.
//!
//! This compares two files by design: the property is that they agree. A
//! behavioural test would need a Linux desktop to build and run on.
use std::collections::BTreeSet;
use std::path::Path;

fn read(rel: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(rel))
        .unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// The features in the first `"..."` after `marker` in `text`.
fn features_after(text: &str, marker: &str, what: &str) -> BTreeSet<String> {
    let at = text
        .find(marker)
        .unwrap_or_else(|| panic!("{what}: no {marker:?}"));
    let rest = &text[at + marker.len()..];
    let open = rest.find('"').expect("an opening quote") + 1;
    let close = open + rest[open..].find('"').expect("a closing quote");
    rest[open..close]
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

/// The matrix entry for `os`, e.g. `ubuntu-latest`, in the workflow `file`.
fn matrix_features(file: &str, os: &str) -> BTreeSet<String> {
    let workflow = read(file);
    let line = workflow
        .lines()
        .find(|l| l.contains(&format!("os: {os}")) && l.contains("features:"))
        .unwrap_or_else(|| panic!("{file} has no build for {os}"));
    features_after(line, "features:", file)
}

/// The release matrix entry for `os`, e.g. `ubuntu-latest`.
fn release_features(os: &str) -> BTreeSet<String> {
    matrix_features(".github/workflows/release.yml", os)
}

/// The lines of a shell script that are not comments, with runs of blanks
/// collapsed, so a comment that explains a feature string is not read as one.
fn shell_code(text: &str) -> Vec<String> {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|l| !l.is_empty())
        .collect()
}

/// Every feature list written in quotes after `--features ` or `FEATURES=` in
/// `code`; a variable in their place is left to the caller.
fn literal_feature_sets(code: &[String]) -> Vec<BTreeSet<String>> {
    let mut sets = Vec::new();
    for line in code {
        for marker in ["--features ", "FEATURES="] {
            let mut rest = line.as_str();
            while let Some(at) = rest.find(marker) {
                rest = &rest[at + marker.len()..];
                if rest.starts_with('"') && !rest.starts_with("\"$") {
                    sets.push(features_after(rest, "", "a script"));
                }
            }
        }
    }
    sets
}

#[test]
fn every_dev_launcher_builds_what_its_release_ships() {
    for (os, launcher) in [
        ("macos-latest", "service/macos/grabbr-hop-dev.command"),
        ("windows-latest", "service/windows/grabbr-hop-dev.cmd"),
        ("ubuntu-latest", "service/linux/grabbr-hop-dev"),
    ] {
        let dev = features_after(&read(launcher), "--features", launcher);
        let release = release_features(os);
        assert_eq!(
            dev, release,
            "{launcher} builds {dev:?}, but the {os} release builds {release:?}; \
             a dev build that differs is not a test of what ships"
        );
    }
}

/// The installers are the build-from-source path the README gives. The shell
/// installer built "tui slint" on every platform, and on Linux that is a
/// binary with no input backend: it connected, and could neither capture nor
/// inject (#74). tests/installers.rs runs the shell installer on Linux and
/// reads the build it asks for; this reads both installers' text, so a test
/// run on any platform holds them to the releases.
// LEDGER T1 | class S | source text of both installers | pair T2 (tests/installers.rs)
#[test]
fn the_installers_build_what_the_release_ships() {
    let sh = shell_code(&read("install.sh"));
    let macos = release_features("macos-latest");
    let linux = release_features("ubuntu-latest");

    let built = literal_feature_sets(&sh);
    for want in [&macos, &linux] {
        assert!(
            built.contains(want),
            "install.sh names {built:?} and never the release set {want:?}; on \
             Linux the input backends are features, so a build without them can \
             neither capture nor inject"
        );
    }
    for set in &built {
        assert!(
            set == &macos || set == &linux,
            "install.sh builds {set:?}, which no release ships"
        );
    }

    // PowerShell: `--features tui --features slint`, each flag with one word.
    let windows = release_features("windows-latest");
    let ps1 = read("install.ps1");
    let build = ps1
        .lines()
        .find(|l| l.trim_start().starts_with("cargo build"))
        .expect("install.ps1 runs no `cargo build`");
    let words: Vec<&str> = build.split_whitespace().collect();
    let got: BTreeSet<String> = words
        .windows(2)
        .filter(|w| w[0] == "--features")
        .flat_map(|w| {
            w[1].trim_matches(|c| c == '"' || c == '\'')
                .split_whitespace()
        })
        .map(str::to_owned)
        .collect();
    assert_eq!(
        got, windows,
        "install.ps1 builds {got:?}, but the Windows release builds {windows:?}"
    );
}

/// CI's check of the release feature sets is where each set is compiled and
/// tested on its own platform before a tag. Its Linux entry was "tui", a set
/// no release ships and one with no input backend.
// LEDGER T3 | class S | source text of check.yml and release.yml | pair T9 (check.yml's compile step)
#[test]
fn ci_checks_the_feature_sets_the_releases_ship() {
    for os in ["macos-latest", "windows-latest", "ubuntu-latest"] {
        let ci = matrix_features(".github/workflows/check.yml", os);
        let release = release_features(os);
        assert_eq!(
            ci, release,
            "check.yml's release-features job builds {ci:?} on {os}, but the \
             release builds {release:?}"
        );
    }
}
