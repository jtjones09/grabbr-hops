//! A daemon that cannot create its token in a directory another user owns
//! says whose directory it is, through the listener a daemon starts.
//!
//! Runs in its own test binary: it points `XDG_CONFIG_HOME`, `HOME` and
//! `XDG_RUNTIME_DIR` at a scratch directory, which must not disturb anything
//! else. The listener binds a socket of its own, never the production one.

#![cfg(unix)]

use std::path::PathBuf;

use hops_ipc::{AsyncFrontendListener, DaemonEndpoint, IpcListenerCreationError};

// LEDGER T46 | class B | 1 return value / error
#[tokio::test(flavor = "current_thread")]
async fn a_token_another_users_directory_refuses_is_reported_as_theirs() {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    if me == 0 {
        eprintln!("not checked: nothing refuses root a file");
        return;
    }
    let scratch = PathBuf::from(format!("/tmp/h-whose-token-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    let config_home = scratch.join("config");
    std::fs::create_dir_all(&config_home).expect("a scratch directory");
    // Only root can make a directory another user owns. A link to one of
    // root's that no one else may write in stands in for the config directory
    // `sudo hops` leaves behind: `/` on Linux, and `/Library` on macOS, where
    // `/` is read-only to root as well, which is a different refusal.
    let theirs = if cfg!(target_os = "macos") {
        "/Library"
    } else {
        "/"
    };
    let config_dir = config_home.join("lan-mouse");
    std::os::unix::fs::symlink(theirs, &config_dir).expect("a link to root's directory");
    // SAFETY: the only test in this binary, and it sets these before it starts
    // anything that reads the environment.
    unsafe {
        std::env::set_var("XDG_CONFIG_HOME", &config_home);
        std::env::set_var("HOME", &scratch);
        std::env::set_var("XDG_RUNTIME_DIR", &scratch);
    }

    let got = AsyncFrontendListener::at(&DaemonEndpoint::Unix(scratch.join("s.sock"))).await;
    let said = match got {
        Err(e @ IpcListenerCreationError::Token { .. }) => e.to_string(),
        Err(other) => format!("not a token error: {other}"),
        Ok(_) => "listening, with a token".to_string(),
    };
    let _ = std::fs::remove_dir_all(&scratch);

    let dir = config_dir.display();
    for part in [
        format!(
            "could not read or create the IPC token {}",
            config_dir.join("ipc-token").display()
        ),
        format!("{dir} belongs to uid 0, not to this user (uid {me})"),
        format!("`sudo chown {me} {dir}`"),
    ] {
        assert!(
            said.contains(&part),
            "a daemon that cannot create its token because another user owns the \
             directory it goes in must name the token, whose directory it is and \
             what to do; `{part}` is missing from: {said}"
        );
    }
}
