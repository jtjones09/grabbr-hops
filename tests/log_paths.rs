//! Where hops' logs land on disk, and that none of them lands in `~/hops`.
//!
//! Earlier builds created `~/hops/logs` for launchd's copy of the daemon's
//! output on macOS, beside the platform log directory the logger itself
//! writes to. Every log now lands in the one directory
//! `input_event::paths::log_dir` names.
//!
//! Runs in its own test binary, with one test, so pointing `HOME` and the
//! directories the logs come from at a scratch directory disturbs nothing.

use std::path::{Path, PathBuf};

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The daemon's log, where this platform keeps it, under `scratch`.
fn expected_daemon_log(scratch: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        scratch.join("home/Library/Logs/hops/daemon.log")
    } else if cfg!(windows) {
        scratch.join("local-app-data/hops/logs/daemon.log")
    } else {
        scratch.join("state/hops/daemon.log")
    }
}

// LEDGER T1 | class B | 4 file on disk: hops::logging::init, and on macOS hops::daemon_start::point_launch_agent_here
#[test]
fn every_log_lands_in_the_platform_log_directory_and_none_in_home_hops() {
    let scratch =
        Scratch(std::env::temp_dir().join(format!("hops-log-paths-{}", std::process::id())));
    let _ = std::fs::remove_dir_all(&scratch.0);
    let home = scratch.0.join("home");
    std::fs::create_dir_all(&home).expect("a scratch home");
    // SAFETY: the only test in this binary, and nothing else runs yet.
    unsafe {
        std::env::remove_var("HOPS_LOG_FILE");
        std::env::set_var("HOME", &home);
        std::env::set_var("XDG_STATE_HOME", scratch.0.join("state"));
        std::env::set_var("LOCALAPPDATA", scratch.0.join("local-app-data"));
    }
    let expected = expected_daemon_log(&scratch.0);

    // The logger: the file it opens and writes.
    hops::logging::init("daemon");
    log::info!(target: "hops", "where does this line land");
    log::logger().flush();
    let written = std::fs::read_to_string(&expected)
        .unwrap_or_else(|e| panic!("the daemon's log is not at {}: {e}", expected.display()));
    assert!(written.contains("where does this line land"), "{written}");

    // launchd's copy of the daemon's output, on macOS: the plist the front
    // door writes sends it to the file the logger writes, created private.
    #[cfg(all(target_os = "macos", any(feature = "tui", feature = "slint")))]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::remove_file(&expected);
        // The app's own HOPS_LOG_FILE is not the daemon's: launchd starts
        // the daemon without it, so the daemon logs to the directory.
        // SAFETY: the only test in this binary; the logger is already open.
        unsafe { std::env::set_var("HOPS_LOG_FILE", scratch.0.join("app.log")) };
        let plist = hops::daemon_start::point_launch_agent_here().expect("a plist");
        assert!(plist.starts_with(&home), "{}", plist.display());
        let out = std::process::Command::new("plutil")
            .args(["-convert", "json", "-o", "-"])
            .arg(&plist)
            .output()
            .expect("plutil");
        let read: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
        for key in ["StandardOutPath", "StandardErrorPath"] {
            assert_eq!(
                read.get(key).and_then(|v| v.as_str()).map(PathBuf::from),
                Some(expected.clone()),
                "launchd sends the daemon's {key} somewhere other than its log: {read}"
            );
        }
        let mode = std::fs::metadata(&expected)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or_else(|e| panic!("no {} before launchd opens it: {e}", expected.display()));
        assert_eq!(mode, 0o600, "{} is {mode:o}", expected.display());
    }

    assert!(
        !home.join("hops").exists(),
        "something created ~/hops, which hops no longer writes to"
    );
}
