//! #115, end to end: a device added and never connected sits at an edge, and
//! the pointer crosses to it. The whole daemon runs in this process with the
//! config a user has in that state; only capture is scripted, and nothing
//! answers at the device's address.
//!
//! What is observed is what a user has: whether the pointer is still held
//! (the scripted backend's grab), and what a frontend connected over the real
//! IPC socket is told.

use super::Service;
use crate::permission_watch::PermissionWatch;
use crate::test_harness::run_local;
use hops_ipc::{AsyncFrontendListener, DaemonEndpoint, FrontendRequest};
use input_capture::{CaptureEvent, Position, scripted::Script};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// What must happen is waited for this long at most.
const DEADLINE: Duration = Duration::from_secs(30);

/// The scratch directory, removed with it.
struct Scratch {
    dir: PathBuf,
    endpoint: DaemonEndpoint,
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A daemon whose one device is at the right edge of this screen, switched
/// on, never connected, at `port` on loopback.
async fn daemon(tag: &str, script: &Script, port: u16) -> (Service, Scratch) {
    // Short, for a socket path in it (`sun_path`).
    let dir = PathBuf::from(format!("/tmp/h-rc-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let config = dir.join("config.toml");
    std::fs::write(
        &config,
        format!(
            "port = 0\ncapture_backend = \"dummy\"\nemulation_backend = \"dummy\"\n\
             discovery = false\n\n[[clients]]\nposition = \"right\"\n\
             activate_on_startup = true\nips = [\"127.0.0.1\"]\nport = {port}\n"
        ),
    )
    .expect("a config");
    let endpoint = DaemonEndpoint::Unix(dir.join("s.sock"));
    let scratch = Scratch {
        dir: dir.clone(),
        endpoint: endpoint.clone(),
    };
    let frontends = AsyncFrontendListener::at_with_token_file(&endpoint, &dir.join("ipc-token"))
        .await
        .expect("the scratch endpoint");
    let config = crate::config::Config::in_scratch(&config, &dir.join("hops.pem"))
        .expect("the scratch config");
    let mut service = Service::with_backends(
        config,
        frontends,
        Some(script.backend()),
        Some(input_emulation::Backend::Dummy),
    )
    .await
    .expect("a daemon in the scratch directory");
    // Not this machine's permissions: nothing here is about them.
    service.permission_watch = PermissionWatch::at_daemon_start(
        Arc::new(|_| false),
        Arc::new(|| false),
        Duration::from_secs(3600),
    );
    (service, scratch)
}

/// A frontend connected to the daemon over its IPC socket.
struct Frontend {
    stream: tokio::io::WriteHalf<tokio::net::UnixStream>,
    lines: tokio::io::Lines<BufReader<tokio::io::ReadHalf<tokio::net::UnixStream>>>,
}

impl Frontend {
    /// Connected, and known to the daemon: it has answered a barrier.
    async fn connect(scratch: &Scratch) -> Self {
        let DaemonEndpoint::Unix(path) = &scratch.endpoint else {
            unreachable!("a unix socket")
        };
        let token = std::fs::read_to_string(scratch.dir.join("ipc-token")).expect("the token");
        let stream = tokio::net::UnixStream::connect(path)
            .await
            .expect("the daemon's socket");
        let (read, mut write) = tokio::io::split(stream);
        write
            .write_all(format!("{}\n", token.trim()).as_bytes())
            .await
            .expect("the token is sent");
        let mut frontend = Self {
            stream: write,
            lines: BufReader::new(read).lines(),
        };
        let barrier = serde_json::to_string(&FrontendRequest::Barrier(115)).expect("json");
        frontend
            .stream
            .write_all(format!("{barrier}\n").as_bytes())
            .await
            .expect("the barrier is sent");
        while let Ok(Some(line)) = frontend.lines.next_line().await {
            let event: serde_json::Value = serde_json::from_str(&line).unwrap_or_default();
            if event.get("Barrier") == Some(&serde_json::json!(115)) {
                return frontend;
            }
        }
        panic!("the daemon hung up before answering the barrier");
    }
}

// LEDGER T115-3 | class B | 2 event over the real IPC socket + 5 capture backend state, the whole daemon in-process
/// The issue's own state: a device added at the right edge, switched on,
/// never paired, nothing answering. Crossing to it must leave the pointer
/// here and tell the user why, which before it did not.
#[test]
fn crossing_to_a_device_that_never_connected_says_why_and_keeps_the_pointer() {
    run_local(async {
        // Bound and silent: a dial to it is never answered.
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("a silent port");
        let port = silent.local_addr().expect("its address").port();
        let script = Script::new();
        let (mut service, scratch) = daemon("never", &script, port).await;
        let handle = service
            .client_manager
            .get_client_states()
            .first()
            .map(|(handle, ..)| *handle)
            .expect("the configured device");

        let told = async {
            let mut frontend = Frontend::connect(&scratch).await;
            loop {
                // A Begin that lands before the barrier exists is dropped:
                // cross again until something is said.
                script.push(Position::Right, CaptureEvent::Begin);
                let line =
                    tokio::time::timeout(Duration::from_millis(20), frontend.lines.next_line())
                        .await;
                match line {
                    Ok(Ok(Some(line))) => {
                        let event: serde_json::Value =
                            serde_json::from_str(&line).unwrap_or_default();
                        if let Some(refused) = event.get("CrossingRefused") {
                            return refused.clone();
                        }
                    }
                    Ok(_) => panic!("the daemon closed the frontend's connection"),
                    Err(_) => {}
                }
            }
        };
        let told = tokio::select! {
            ended = service.run() => panic!("the daemon ended: {ended:?}"),
            told = told => told,
            _ = tokio::time::sleep(DEADLINE) => panic!(
                "no CrossingRefused reached the frontend within {DEADLINE:?} of \
                 crossing to a device that never connected (pointer held: {})",
                script.held()
            ),
        };
        let held = script.held();
        service.capture.terminate().await;
        service.emulation.terminate().await;
        service.resolver.terminate().await;

        assert!(
            !held,
            "the pointer is still held for a device that never connected"
        );
        assert_eq!(
            told,
            serde_json::json!({ "handle": handle, "reason": "NotConnected" }),
            "the frontend must be told which device refused the crossing, and why"
        );
    });
}
