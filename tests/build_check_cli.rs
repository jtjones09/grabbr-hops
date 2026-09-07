//! `build-check` must answer when the config file does not.
//!
//! It is the command someone runs to find out why the others are failing, so it
//! cannot need them to work. It used to: `Config::new()` loaded and validated
//! the config file before any subcommand was dispatched, so one bad line there
//! made the check exit 1 having never run — printing nothing at all. Exit 1 is
//! also what `--strict` used to return for a stale binary, so every launcher
//! read a corrupt config as "stale" and told the user to rebuild, which no
//! rebuild could fix.
//!
//! Only an end-to-end test sees this: the defect was the ORDER of two calls in
//! `main`, and every unit test of the check itself passed throughout.

use std::process::Command;

fn hops() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hops"))
}

#[test]
fn a_broken_config_file_does_not_stop_the_diagnostic() {
    let dir = std::env::temp_dir().join(format!("hops-bc-{}", std::process::id()));
    let cfg = dir.join("lan-mouse");
    std::fs::create_dir_all(&cfg).expect("mkdir");
    // The exact shape the config module documents as having happened: a value
    // of the wrong type, which fails deserialization rather than parsing.
    std::fs::write(cfg.join("config.toml"), "port = \"not-a-number\"\n").expect("write");

    let out = hops()
        .args([
            "build-check",
            "--repo",
            env!("CARGO_MANIFEST_DIR"),
            "--strict",
        ])
        .env("XDG_CONFIG_HOME", &dir)
        .output()
        .expect("run");

    let code = out.status.code();
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert_ne!(
        code,
        Some(1),
        "exit 1 is this process's generic failure. Returning it here means a \
         launcher cannot tell an unparseable config from a stale binary, and \
         tells the user to rebuild for a problem no rebuild fixes. stdout was: \
         {stdout:?}"
    );
    assert!(
        stdout.contains("hops") || stdout.contains("STALE"),
        "the check must actually run and say something; it printed nothing, \
         which is what it did when the config was loaded first. stdout: {stdout:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_path_with_no_checkout_cannot_pass_a_strict_gate() {
    let empty = std::env::temp_dir().join(format!("hops-bc-empty-{}", std::process::id()));
    std::fs::create_dir_all(&empty).expect("mkdir");

    let strict = hops()
        .args(["build-check", "--repo"])
        .arg(&empty)
        .arg("--strict")
        .output()
        .expect("run");
    assert_ne!(
        strict.status.code(),
        Some(0),
        "a --strict gate that found no checkout compared nothing. Reporting \
         success there is a gate that passes having verified nothing, which \
         reads as proof and is worse than having no gate at all."
    );

    let lenient = hops()
        .args(["build-check", "--repo"])
        .arg(&empty)
        .output()
        .expect("run");
    assert_eq!(
        lenient.status.code(),
        Some(0),
        "without --strict nothing may block a launch — a daily binary on a \
         machine with no source tree must still start"
    );

    let _ = std::fs::remove_dir_all(&empty);
}
