//! `DaemonEndpoint::serves` against the daemon's real listener and token.
//!
//! A daemon binds its endpoint before it reads its config and keys, and exits
//! on a failure there a moment later. The front door must not count that as a
//! daemon running, so what it asks is whether the daemon takes the token and
//! sends state, which a daemon does only once its service loop runs.
//!
//! Runs in its own test binary so pointing `HOME`, `XDG_CONFIG_HOME`,
//! `XDG_RUNTIME_DIR` and `LOCALAPPDATA` at a scratch directory cannot disturb
//! anything else. The listener binds an endpoint of its own, never the
//! production socket or port.

use std::path::PathBuf;
use std::time::Duration;

use futures::StreamExt;
use hops_ipc::{AsyncFrontendListener, DaemonEndpoint, FrontendEvent, FrontendRequest};

fn isolate() -> PathBuf {
    #[cfg(unix)]
    let dir = PathBuf::from(format!("/tmp/h-serves-{}", std::process::id()));
    #[cfg(windows)]
    let dir = std::env::temp_dir().join(format!("h-serves-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".config/lan-mouse")).expect("scratch config");
    // SAFETY: the only test in this binary, and it sets these before it starts
    // anything that reads the environment.
    unsafe {
        std::env::set_var("HOME", &dir);
        std::env::set_var("XDG_CONFIG_HOME", dir.join(".config"));
        std::env::set_var("XDG_RUNTIME_DIR", &dir);
        std::env::set_var("LOCALAPPDATA", &dir);
    }
    dir
}

fn own_endpoint(dir: &std::path::Path) -> DaemonEndpoint {
    #[cfg(unix)]
    {
        DaemonEndpoint::Unix(dir.join("s.sock"))
    }
    #[cfg(windows)]
    {
        let _ = dir;
        DaemonEndpoint::Tcp("127.0.0.1:0".parse().expect("a loopback address"))
    }
}

/// Ask `serves` on a blocking thread, so this runtime can go on driving the
/// listener meanwhile.
async fn ask(
    endpoint: &DaemonEndpoint,
    token: &str,
    within: Duration,
) -> tokio::task::JoinHandle<bool> {
    let (endpoint, token) = (endpoint.clone(), token.to_string());
    tokio::task::spawn_blocking(move || endpoint.serves(&token, within))
}

/// Run `listener` the way the service loop does for a frontend that attaches
/// (answer `Sync` with state) until `asked` finishes.
async fn serve_until(
    listener: &mut AsyncFrontendListener,
    asked: tokio::task::JoinHandle<bool>,
) -> bool {
    tokio::pin!(asked);
    loop {
        tokio::select! {
            got = &mut asked => break got.expect("the asking thread"),
            request = listener.next() => {
                if let Some(Ok(FrontendRequest::Sync)) = request {
                    listener.broadcast(FrontendEvent::PortChanged(4242, None)).await;
                }
            }
        }
    }
}

// LEDGER T30 | class B | 2 bytes over a real socket + 1 return value
#[tokio::test(flavor = "current_thread")]
async fn a_daemon_serves_only_once_its_loop_answers_the_token() {
    let dir = isolate();
    let mut listener = AsyncFrontendListener::at(&own_endpoint(&dir))
        .await
        .expect("the listener claims the scratch endpoint");
    let endpoint = listener.endpoint().clone();
    let token = hops_ipc::token::read().expect("the token the listener minted");

    // Bound and holding its token, with no loop running: the moment a daemon
    // can still exit on its config or keys.
    let bound_only = ask(&endpoint, &token, Duration::from_millis(300))
        .await
        .await
        .expect("the asking thread");

    let asked = ask(&endpoint, &token, Duration::from_secs(5)).await;
    let serving = serve_until(&mut listener, asked).await;

    let asked = ask(&endpoint, &"f".repeat(64), Duration::from_millis(500)).await;
    let wrong_token = serve_until(&mut listener, asked).await;

    drop(listener);
    let gone = ask(&endpoint, &token, Duration::from_millis(300))
        .await
        .await
        .expect("the asking thread");
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(
        (bound_only, serving, wrong_token, gone),
        (false, true, false, false),
        "(bound with no loop, loop running, wrong token, nothing bound). Only a \
         daemon whose loop answers the token may count as serving. Counting a \
         bound endpoint reports a daemon that exits on its config a moment later \
         as running."
    );
}
