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

/// The release matrix entry for `os`, e.g. `ubuntu-latest`.
fn release_features(os: &str) -> BTreeSet<String> {
    let release = read(".github/workflows/release.yml");
    let line = release
        .lines()
        .find(|l| l.contains(&format!("os: {os}")) && l.contains("features:"))
        .unwrap_or_else(|| panic!("release.yml has no build for {os}"));
    features_after(line, "features:", "release.yml")
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
