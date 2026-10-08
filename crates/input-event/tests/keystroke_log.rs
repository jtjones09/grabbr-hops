//! Where the keystroke log lands: its own file in hops' log directory, and
//! never `~/hops/logs`, where it was written on every platform before.
//!
//! Runs in its own test binary, with one test, so pointing `HOME` and the
//! directories the log comes from at a scratch directory disturbs nothing.

use std::path::PathBuf;

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// LEDGER T2 | class B | 1 return value + 4 file on disk: input_event::keylog::keystroke_log_path, and with `keylog` input_event::keylog::key
#[test]
fn keystrokes_land_in_the_log_directory_and_not_in_home_hops() {
    let scratch = Scratch(std::env::temp_dir().join(format!("hops-keylog-{}", std::process::id())));
    let _ = std::fs::remove_dir_all(&scratch.0);
    let home = scratch.0.join("home");
    std::fs::create_dir_all(&home).expect("a scratch home");
    // SAFETY: the only test in this binary, and nothing else runs yet.
    unsafe {
        std::env::set_var("HOME", &home);
        std::env::set_var("XDG_STATE_HOME", scratch.0.join("state"));
        std::env::set_var("LOCALAPPDATA", scratch.0.join("local-app-data"));
        // Never moves the keystroke log: it is the general log's override.
        std::env::set_var("HOPS_LOG_FILE", scratch.0.join("general.log"));
    }
    let dir = if cfg!(target_os = "macos") {
        home.join("Library/Logs/hops")
    } else if cfg!(windows) {
        scratch.0.join("local-app-data/hops/logs")
    } else {
        scratch.0.join("state/hops")
    };
    let expected = dir.join("keystrokes.log");

    assert_eq!(
        input_event::keylog::keystroke_log_path(),
        Some(expected.clone())
    );
    assert_eq!(input_event::paths::log_dir(), Some(dir.clone()));
    assert!(dir.is_dir(), "{} was not created", dir.display());

    // Armed, the keys go to that file, created readable by this user alone.
    #[cfg(feature = "keylog")]
    {
        unsafe { std::env::set_var("HOPS_LOG_KEYS", "10s") };
        input_event::keylog::key(30, 1, "KeyA");
        assert!(input_event::keylog::is_armed());
        let written = std::fs::read_to_string(&expected)
            .unwrap_or_else(|e| panic!("no keystroke log at {}: {e}", expected.display()));
        assert!(
            written.contains("key=30 state=1 scancode=KeyA"),
            "{written}"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&expected)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{mode:o}");
        }
        assert!(!scratch.0.join("general.log").exists());
    }

    assert!(
        !home.join("hops").exists(),
        "the keystroke log created ~/hops, which hops no longer writes to"
    );
}
