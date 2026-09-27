//! The front door's probe against the daemon's real IPC listener (#159,
//! decided 2026-09-16: at most one daemon, started only when none answers).
//!
//! The guards in `src/decision_guards.rs` call the decision with endpoints the
//! test builds itself. That cannot show the probe asks the address the daemon
//! actually binds, and a probe asking the wrong one is how every Windows launch
//! used to start a second daemon. This test uses the listener the daemon binds
//! and the connector a frontend uses.
//!
//! It uses the endpoint all three work out for themselves: on macOS and Linux
//! a socket under `HOME` or `XDG_RUNTIME_DIR`, on Windows a pipe named after
//! the token under `LOCALAPPDATA`, each pointed at a scratch directory, so the
//! endpoint is never the one a hops daemon on the machine holds.
//!
//! Runs in its own test binary so pointing `HOME`, `XDG_RUNTIME_DIR`,
//! `XDG_CONFIG_HOME` and `LOCALAPPDATA` at a scratch directory cannot disturb
//! anything else.

use std::cell::Cell;
use std::path::PathBuf;
use std::time::Duration;

use futures::StreamExt;
use hops::daemon_start::{DaemonStart, ThisMachine, Watch};
use hops_ipc::{
    AsyncFrontendListener, DaemonEndpoint, FrontendEvent, FrontendRequest, IpcListenerCreationError,
};

/// Point this process at a scratch directory, so the listener binds a private
/// socket and mints a private token.
fn isolate() -> PathBuf {
    // Short, for `sun_path` (about 104 bytes on macOS).
    #[cfg(unix)]
    let dir = PathBuf::from(format!("/tmp/h-door-{}", std::process::id()));
    #[cfg(windows)]
    let dir = std::env::temp_dir().join(format!("h-door-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("Library/Caches")).expect("scratch caches");
    std::fs::create_dir_all(dir.join(".config/lan-mouse")).expect("scratch config");
    // SAFETY: the only test in this binary, and it sets these before it starts
    // anything that reads the environment.
    unsafe {
        std::env::set_var("HOME", &dir);
        std::env::set_var("XDG_RUNTIME_DIR", &dir);
        std::env::set_var("XDG_CONFIG_HOME", dir.join(".config"));
        std::env::set_var("LOCALAPPDATA", &dir);
    }
    dir
}

/// A started daemon that serves at once, standing in for the process the
/// stand-in start does not really run.
struct ServesAtOnce;

impl Watch for ServesAtOnce {
    fn serves(&mut self, _: &DaemonEndpoint, _: Duration) -> bool {
        true
    }
    fn ended(&mut self, _: u32) -> bool {
        false
    }
    fn log_file(&self) -> Option<PathBuf> {
        None
    }
}

/// Run the front door's decision, counting starts: what `hops` runs,
/// `ensure_running_with`, on the endpoint it works out itself, with a
/// stand-in start and wait.
fn front_door() -> (DaemonStart, u32) {
    let starts = Cell::new(0);
    let start = || {
        starts.set(starts.get() + 1);
        Ok(4242)
    };
    let within = Duration::from_secs(1);
    let outcome = hops::daemon_start::ensure_running_with(start, &mut ServesAtOnce, within);
    (outcome, starts.get())
}

/// Ask whether a daemon serves on `endpoint` the way the front door does after
/// a start, with its own watch, while `daemon` runs the way the service loop
/// does for a frontend that attaches (answering `Sync` with state).
async fn front_door_sees_it_serve(
    daemon: &mut AsyncFrontendListener,
    endpoint: &DaemonEndpoint,
) -> bool {
    let endpoint = endpoint.clone();
    let asked =
        tokio::task::spawn_blocking(move || ThisMachine.serves(&endpoint, Duration::from_secs(5)));
    tokio::pin!(asked);
    loop {
        tokio::select! {
            got = &mut asked => break got.expect("the asking thread"),
            request = daemon.next() => {
                if let Some(Ok(FrontendRequest::Sync)) = request {
                    daemon.broadcast(FrontendEvent::PortChanged(4242, None)).await;
                }
            }
        }
    }
}

/// Claim the daemon's endpoint the way `hops daemon` does.
async fn claim() -> Result<AsyncFrontendListener, IpcListenerCreationError> {
    AsyncFrontendListener::new().await
}

/// Connect the way a frontend does, while `daemon` runs the way the service
/// loop does, and say whether it got through. The daemon answers the
/// frontend's challenge only while its loop runs.
async fn frontend_reaches(daemon: &mut AsyncFrontendListener) -> bool {
    let connecting = tokio::time::timeout(
        Duration::from_secs(10),
        hops_ipc::connect_async(Some(Duration::from_secs(5))),
    );
    tokio::pin!(connecting);
    loop {
        tokio::select! {
            connected = &mut connecting => {
                break connected.map(|c| c.is_ok()).unwrap_or(false)
            }
            _ = daemon.next() => {}
        }
    }
}

// LEDGER T6 | class B | 1 return value
#[tokio::test(flavor = "current_thread")]
async fn the_front_door_asks_the_endpoint_the_daemon_listens_on() {
    let dir = isolate();
    let endpoint = DaemonEndpoint::of_this_platform().expect("the scratch HOME");

    let mut daemon = match claim().await {
        Ok(daemon) => daemon,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&dir);
            panic!("the daemon's listener could not claim its endpoint: {e}");
        }
    };
    let bound = daemon.endpoint().clone();
    let beside_it = front_door();
    let frontend = frontend_reaches(&mut daemon).await;
    let serving_seen = front_door_sees_it_serve(&mut daemon, &bound).await;
    let second = match claim().await {
        Ok(_) => "claimed".to_string(),
        Err(IpcListenerCreationError::AlreadyRunning) => "AlreadyRunning".to_string(),
        Err(e) => format!("{e:?}"),
    };
    drop(daemon);
    let after = front_door();
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(
        bound, endpoint,
        "the daemon bound a different endpoint from the one the front door works out"
    );
    assert_eq!(
        beside_it,
        (DaemonStart::AlreadyRunning, 0),
        "the daemon's listener was bound and the front door still asked for \
         another daemon: its probe does not ask the endpoint the daemon binds, \
         so every launch starts a second one"
    );
    assert!(
        frontend,
        "a frontend could not reach the daemon's listener, so the connector and \
         the listener disagree about where the daemon is"
    );
    assert!(
        serving_seen,
        "the daemon's loop answered a frontend, and the front door's own check \
         did not see it serve: it reads a different token from the one the \
         daemon minted, or asks a different endpoint. Every start would then \
         be logged as a daemon that did not answer."
    );
    assert_eq!(
        second, "AlreadyRunning",
        "a second daemon claimed the endpoint a running daemon holds"
    );
    assert_eq!(
        after,
        (DaemonStart::Started(4242), 1),
        "with the daemon gone, the front door must ask for exactly one start"
    );
}
