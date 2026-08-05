//! End-to-end check of the IPC token handshake over a REAL socket.
//!
//! The unit tests in `listen.rs` drive the server half over an in-memory duplex,
//! which proves the gate refuses attackers but says nothing about whether a
//! legitimate frontend still gets in. If the handshake were wrong — token sent
//! after the first request, missing newline, not flushed — every frontend
//! (GUI, TUI, CLI) would break at once, and the unit tests would stay green.
//!
//! Runs in its own test binary so redirecting `HOME` / `XDG_CONFIG_HOME` to a
//! scratch directory cannot disturb anything else, including a daemon the user
//! has running.

use std::path::PathBuf;
use std::time::Duration;

use futures::StreamExt;
use hops_ipc::{AsyncFrontendListener, FrontendRequest, connect_async};

/// Point this process at a scratch HOME/config so we bind a private socket and
/// mint a private token, never the user's.
fn isolate() -> PathBuf {
    // MUST be short: a unix socket path is capped at SUN_LEN (~104 bytes), and
    // macOS's temp dir alone (/var/folders/<hash>/<hash>/T/) nearly exhausts it.
    let dir = PathBuf::from(format!("/tmp/h-ipc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    // macOS puts the socket under ~/Library/Caches; unix uses XDG_RUNTIME_DIR
    std::fs::create_dir_all(dir.join("Library/Caches")).expect("scratch caches");
    std::fs::create_dir_all(dir.join(".config/lan-mouse")).expect("scratch config");
    unsafe {
        std::env::set_var("HOME", &dir);
        std::env::set_var("XDG_CONFIG_HOME", dir.join(".config"));
        std::env::set_var("XDG_RUNTIME_DIR", &dir);
    }
    dir
}

#[tokio::test(flavor = "current_thread")]
async fn a_real_frontend_authenticates_and_is_heard() {
    let dir = isolate();

    let mut listener = AsyncFrontendListener::new()
        .await
        .expect("listener should bind the scratch socket");

    // the daemon minted a token when it bound
    let token_file = dir.join(".config/lan-mouse/ipc-token");
    assert!(token_file.exists(), "the daemon must mint a token at startup");
    assert_eq!(
        std::fs::read_to_string(&token_file).expect("read token").len(),
        64,
        "32 random bytes, hex encoded"
    );

    let (_reader, mut writer) = tokio::time::timeout(
        Duration::from_secs(5),
        connect_async(Some(Duration::from_secs(5))),
    )
    .await
    .expect("connect must not hang")
    .expect("a frontend must be able to connect");

    writer
        .request(FrontendRequest::Enumerate())
        .await
        .expect("request should send");

    // Drain until the request arrives. `Sync` is emitted on accept, before the
    // token is seen, so it is not evidence of anything — keep reading past it.
    let heard = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match listener.next().await {
                Some(Ok(FrontendRequest::Sync)) => continue,
                other => break other,
            }
        }
    })
    .await
    .expect("the daemon must hear an authenticated request, not hang up on it");

    assert!(
        matches!(heard, Some(Ok(FrontendRequest::Enumerate()))),
        "expected the Enumerate we sent, got {heard:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
