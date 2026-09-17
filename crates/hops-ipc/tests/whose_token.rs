//! A daemon that cannot create its token because the config directory is a
//! link to another user's directory names the link, through the listener a
//! daemon starts, and advises no chown.
//!
//! Runs in its own test binary: it points `XDG_CONFIG_HOME`, `HOME` and
//! `XDG_RUNTIME_DIR` at a scratch directory, which must not disturb anything
//! else. The listener binds a socket of its own, never the production one.

#![cfg(unix)]

use std::path::PathBuf;

use hops_ipc::{AsyncFrontendListener, DaemonEndpoint, IpcListenerCreationError};

// LEDGER T46 | class B | 1 return value / error
#[tokio::test(flavor = "current_thread")]
async fn a_token_refused_through_a_linked_config_directory_names_the_link_not_a_chown() {
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
    // Any process of this user can replace the config directory with a link.
    // This one names a directory of root's that no one else may write in: `/`
    // on Linux, and `/Library` on macOS, where `/` is read-only to root as
    // well, which is a different refusal.
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
        format!(
            "{dir} belongs to uid 0, not to this user (uid {me}), and {dir} is a \
             symbolic link to {theirs}."
        ),
    ] {
        assert!(
            said.contains(&part),
            "a daemon that cannot create its token because the config directory \
             is a link to another user's directory must name the token, the link \
             and what it names; `{part}` is missing from: {said}"
        );
    }
    assert!(
        !said.contains("sudo chown"),
        "`chown` follows a link, so advice to chown the config directory would \
         give this user whatever directory the link names: {said}"
    );
}
