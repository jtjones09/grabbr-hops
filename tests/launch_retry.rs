//! How a daemon test's start treats a daemon that exits before its service
//! loop runs (#229): one whose port was taken is started again on another,
//! up to a limit, and one that exits for any other reason fails the test at
//! once. Either way the failure carries what the daemon last logged.
//!
//! A stand-in that logs one line and exits plays the daemon, so the start is
//! seen deciding on what the log says.
#![cfg(unix)]

mod common;

use std::cell::RefCell;

/// Start a stand-in daemon through [`common::launch_on`] that logs `line` to
/// the log and exits at once, every time it is started, and return how many
/// times it was started and what the start failed with.
fn launch_one_that_exits(tag: &str, line: &str) -> (u32, String) {
    // Short, for the same reason as the daemon's (`sun_path`).
    let dir = std::path::PathBuf::from(format!("/tmp/{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let (config, log) = (dir.join("config.toml"), dir.join("daemon.log"));
    let starts = RefCell::new(0u32);
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        common::launch_on(
            common::ports::pick,
            &config,
            |port| format!("port = {port}\n"),
            &log,
            || {
                *starts.borrow_mut() += 1;
                std::process::Command::new("sh")
                    .arg("-c")
                    .arg(r#"printf '%s\n' "$1" > "$2"; exit 1"#)
                    .arg("sh")
                    .arg(line)
                    .arg(&log)
                    .spawn()
                    .expect("sh starts")
            },
        )
    }))
    .expect_err("a daemon that exits never runs");
    let _ = std::fs::remove_dir_all(&dir);
    let message = match failed.downcast_ref::<&str>() {
        Some(text) => text.to_string(),
        None => failed.downcast_ref::<String>().cloned().unwrap_or_default(),
    };
    (starts.into_inner(), message)
}

// LEDGER T229g | class B | 5 process: how often a daemon that exits for another reason is started, and the failure
#[test]
fn a_daemon_that_exits_for_another_reason_is_not_started_again() {
    let (starts, message) = launch_one_that_exits("h-exits", "ERROR hops] no config");
    assert!(
        starts == 1
            && message.contains("before its service loop ran")
            && message.contains("no config"),
        "started {starts} times; failed with: {message}"
    );
}

// LEDGER T229h | class B | 5 process: how often a daemon whose every port is taken is started, and the failure
#[test]
fn a_daemon_whose_every_port_is_taken_fails_with_its_last_log() {
    let line = "ERROR hops] Address already in use (os error 48)";
    let (starts, message) = launch_one_that_exits("h-alltaken", line);
    assert!(
        starts == 10
            && message.contains("every port picked for the daemon was taken")
            && message.contains(line),
        "started {starts} times; failed with: {message}"
    );
}
