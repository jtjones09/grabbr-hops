//! End-to-end check of the IPC two-way proof over a REAL socket or pipe.
//!
//! The unit tests in `listen.rs` drive the server half over an in-memory duplex,
//! which proves the gate refuses attackers but says nothing about whether a
//! legitimate frontend still gets in. If the handshake were wrong — token sent
//! after the first request, missing newline, not flushed — every frontend
//! (GUI, TUI, CLI) would break at once, and the unit tests would stay green.
//!
//! Runs in its own test binary so redirecting `HOME`, `XDG_CONFIG_HOME` and
//! `LOCALAPPDATA` to a scratch directory cannot disturb anything else. The
//! listener binds an endpoint of its own, never the production socket or port,
//! so the test also runs beside a hops daemon the user has running.

use std::path::PathBuf;
use std::time::Duration;

use futures::StreamExt;
use hops_ipc::{AsyncFrontendListener, DaemonEndpoint, FrontendRequest, connect_async_to};

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
    // SAFETY: the only test in this binary, and it sets these before it starts
    // anything that reads the environment.
    unsafe {
        std::env::set_var("HOME", &dir);
        std::env::set_var("XDG_CONFIG_HOME", dir.join(".config"));
        std::env::set_var("XDG_RUNTIME_DIR", &dir);
        // where the token lives on Windows
        std::env::set_var("LOCALAPPDATA", &dir);
    }
    dir
}

/// An endpoint of this test's own: a socket in the scratch directory, or a
/// pipe named for this process.
fn own_endpoint(dir: &std::path::Path) -> DaemonEndpoint {
    #[cfg(unix)]
    {
        DaemonEndpoint::Unix(dir.join("s.sock"))
    }
    #[cfg(windows)]
    {
        let _ = dir;
        DaemonEndpoint::Pipe(format!(
            r"\\.\pipe\hops-test-roundtrip-{}",
            std::process::id()
        ))
    }
}

// LEDGER T17 | class B | 2 bytes over a real socket + 1 return value
#[tokio::test(flavor = "current_thread")]
async fn a_real_frontend_authenticates_and_is_heard() {
    let dir = isolate();

    let mut listener = AsyncFrontendListener::at(&own_endpoint(&dir))
        .await
        .expect("listener should bind the scratch endpoint");

    // the daemon minted a token when it bound
    let token_file = hops_ipc::token::token_path().expect("a token path");
    assert!(
        token_file.starts_with(&dir),
        "the token must be minted in the scratch directory, not at {token_file:?}"
    );
    assert!(
        token_file.exists(),
        "the daemon must mint a token at startup"
    );
    assert_eq!(
        std::fs::read_to_string(&token_file)
            .expect("read token")
            .len(),
        64,
        "32 random bytes, hex encoded"
    );

    // The daemon answers the frontend's challenge only while its loop runs,
    // so the frontend and the listener are driven together.
    let endpoint = listener.endpoint().clone();
    let frontend = async {
        let (reader, mut writer) =
            connect_async_to(&endpoint, Some(Duration::from_secs(5))).await?;
        writer.request(FrontendRequest::Enumerate()).await?;
        Ok::<_, hops_ipc::IpcError>((std::time::Instant::now(), reader, writer))
    };
    // Drain until the request arrives. `Sync` is emitted once the proof is
    // made, so it is not evidence of the request; keep reading past it.
    let daemon = async {
        loop {
            match listener.next().await {
                Some(Ok(FrontendRequest::Sync)) => continue,
                other => break (other, std::time::Instant::now()),
            }
        }
    };
    let (sent, (heard, heard_at)) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(frontend, daemon)
    })
    .await
    .expect("the daemon must hear an authenticated request, not hang up on it");
    let (sent_at, _reader, _writer) = sent.expect("a frontend must be able to connect and send");
    let took = heard_at.saturating_duration_since(sent_at);

    assert!(
        matches!(heard, Some(Ok(FrontendRequest::Enumerate()))),
        "expected the Enumerate we sent, got {heard:?}"
    );
    // Nothing but the request can wake this listener. Heard only when the
    // timeout's own timer woke it, the request sat unread; in the daemon it
    // waits for whatever wakes the service loop next.
    assert!(
        took < Duration::from_secs(2),
        "the request was heard {took:?} after it was sent, when the timeout's \
         timer woke the listener. A frontend that connects is read only once \
         something else wakes the daemon."
    );

    let _ = std::fs::remove_dir_all(&dir);
}
