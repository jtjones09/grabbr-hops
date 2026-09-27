//! What a frontend is told when macOS withholds a permission, end to end:
//! the whole daemon runs in this process and a frontend reads it over the
//! real IPC socket. Capture that should run and cannot is reported as
//! failed, with what to change, not as switched off (#91, #79); discovery
//! that hears nobody says so (#149).
//!
//! Every file is in a scratch directory, the QUIC listener is on loopback,
//! capture is a scripted backend that macOS-style permissions can refuse or
//! be taken from, emulation is the dummy backend, and discovery is off or
//! fed by the test. The permission watch never finds anything granted, so
//! nothing restarts.
//!
//! What a frontend is told is read as JSON, as a frontend of any build reads
//! it.

use super::Service;
use crate::discovery::{DiscoveredPeer, Discovery, DiscoveryEvent};
use crate::permission_watch::PermissionWatch;
use crate::test_harness::run_local;
use hops_ipc::{AsyncFrontendListener, DaemonEndpoint};
use input_capture::Permission;
use input_capture::scripted::Script;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// What must happen is waited for this long at most.
const DEADLINE: Duration = Duration::from_secs(30);
/// What must not happen is watched for this long.
const NOTHING_FOR: Duration = Duration::from_millis(500);

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

/// A daemon whose capture reads `script`.
async fn daemon(tag: &str, script: &Script) -> (Service, Scratch) {
    // Short, for a socket path in it (`sun_path`).
    let dir = PathBuf::from(format!("/tmp/h-cf-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let config = dir.join("config.toml");
    std::fs::write(
        &config,
        "port = 0\ncapture_backend = \"dummy\"\nemulation_backend = \"dummy\"\ndiscovery = false\n",
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
    // Never granted and never restarted: this machine's grants and launchd
    // stay out of it.
    service.permission_watch = PermissionWatch::new(
        Arc::new(|_| false),
        Arc::new(|| false),
        Duration::from_secs(3600),
    );
    (service, scratch)
}

/// End a daemon whose loop a test stopped, as the loop's own end does.
async fn shut_down(mut service: Service) {
    service.capture.terminate().await;
    service.emulation.terminate().await;
    service.resolver.terminate().await;
}

/// A frontend connected to the daemon over its IPC socket.
struct Frontend {
    lines: tokio::io::Lines<BufReader<tokio::net::UnixStream>>,
}

impl Frontend {
    async fn connect(scratch: &Scratch) -> Self {
        let DaemonEndpoint::Unix(path) = &scratch.endpoint else {
            unreachable!("a unix socket")
        };
        let token = std::fs::read_to_string(scratch.dir.join("ipc-token")).expect("the token");
        let mut stream = tokio::net::UnixStream::connect(path)
            .await
            .expect("the daemon's socket");
        stream
            .write_all(format!("{}\n", token.trim()).as_bytes())
            .await
            .expect("the token is sent");
        Self {
            lines: BufReader::new(stream).lines(),
        }
    }

    /// Each capture state the daemon tells it, until one `done` accepts,
    /// which is returned; `None` once the daemon hangs up.
    async fn capture_until(
        &mut self,
        seen: &mut Vec<Value>,
        done: impl Fn(&Value) -> bool,
    ) -> Option<Value> {
        self.until("CaptureStatus", seen, done).await
    }

    /// Each `event` the daemon tells it, until one `done` accepts.
    async fn until(
        &mut self,
        event: &str,
        seen: &mut Vec<Value>,
        done: impl Fn(&Value) -> bool,
    ) -> Option<Value> {
        while let Ok(Some(line)) = self.lines.next_line().await {
            let Ok(told) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            if let Some(body) = told.get(event) {
                seen.push(body.clone());
                if done(body) {
                    return Some(body.clone());
                }
            }
        }
        None
    }
}

fn failed(state: &Value) -> bool {
    state.get("Failed").is_some()
}

/// macOS refuses capture for want of Input Monitoring. The frontend is told
/// capture failed, naming the setting, rather than that it is off.
// LEDGER T1 | class B | 2 bytes over the real IPC socket: Service::run with CaptureTask::run
#[test]
fn a_capture_refused_a_permission_is_failed_naming_it_not_off() {
    run_local(async {
        let script = Script::new();
        script.withhold(&[Permission::InputMonitoring]);
        let (mut service, scratch) = daemon("refused", &script).await;
        let mut seen = Vec::new();
        let told = async {
            let mut frontend = Frontend::connect(&scratch).await;
            frontend.capture_until(&mut seen, failed).await
        };
        let told = tokio::select! {
            ended = service.run() => panic!("the daemon ended: {ended:?}"),
            told = told => told,
            _ = tokio::time::sleep(DEADLINE) => None,
        };
        shut_down(service).await;
        assert_eq!(
            told,
            Some(json!({ "Failed": { "Missing": ["InputMonitoring"] } })),
            "macOS refused capture for want of Input Monitoring. A frontend must be \
             told capture failed and which setting to change; \"Disabled\" is what \
             the user sees when capture is merely off. It was told: {seen:?}"
        );
    });
}

/// Accessibility is taken away while capture runs. The frontend, told it
/// was on, is then told it failed, naming Accessibility.
// LEDGER T2 | class B | 2 bytes over the real IPC socket: Service::run with CaptureTask::run
#[test]
fn a_permission_taken_while_capture_runs_is_failed_naming_it() {
    run_local(async {
        let script = Script::new();
        let (mut service, scratch) = daemon("revoked", &script).await;
        let mut seen = Vec::new();
        let told = async {
            let mut frontend = Frontend::connect(&scratch).await;
            frontend
                .capture_until(&mut seen, |s| s == &json!("Enabled"))
                .await?;
            script.revoke(&[Permission::Accessibility]);
            frontend.capture_until(&mut seen, failed).await
        };
        let told = tokio::select! {
            ended = service.run() => panic!("the daemon ended: {ended:?}"),
            told = told => told,
            _ = tokio::time::sleep(DEADLINE) => None,
        };
        shut_down(service).await;
        assert_eq!(
            told,
            Some(json!({ "Failed": { "Missing": ["Accessibility"] } })),
            "Accessibility was taken away while capture ran. A frontend must be told \
             capture failed, naming it, not only that it is off. It was told: {seen:?}"
        );
    });
}

/// Capture that ends without a fault is off, not failed.
// LEDGER T3 | class B | 2 bytes over the real IPC socket: Service::run with CaptureTask::run
#[test]
fn a_capture_that_simply_ends_is_off_not_failed() {
    run_local(async {
        let script = Script::new();
        let (mut service, scratch) = daemon("ended", &script).await;
        let mut seen = Vec::new();
        let mut script = Some(script);
        let told = async {
            let mut frontend = Frontend::connect(&scratch).await;
            frontend
                .capture_until(&mut seen, |s| s == &json!("Enabled"))
                .await?;
            // The backend's stream ends, as it does when capture is closed.
            drop(script.take());
            frontend
                .capture_until(&mut seen, |s| s == &json!("Disabled"))
                .await?;
            // Nothing follows that says it failed.
            let _ =
                tokio::time::timeout(NOTHING_FOR, frontend.capture_until(&mut seen, failed)).await;
            Some(())
        };
        let told = tokio::select! {
            ended = service.run() => panic!("the daemon ended: {ended:?}"),
            told = told => told,
            _ = tokio::time::sleep(DEADLINE) => None,
        };
        shut_down(service).await;
        assert!(
            told.is_some() && !seen.iter().any(failed),
            "capture ended without a fault; a frontend must be told it is off, and \
             nothing that says it failed. It was told: {seen:?}"
        );
    });
}

/// Discovery hears nobody for long enough: the frontend is told, so it can
/// name the Local Network setting; once a machine answers, it is told that
/// too.
// LEDGER T13 | class B | 2 bytes over the real IPC socket: Service::run with Discovery::event
#[test]
fn a_network_that_answers_nothing_is_told_and_an_answer_clears_it() {
    run_local(async {
        let script = Script::new();
        let (mut service, scratch) = daemon("quiet", &script).await;
        let (answers, heard) = local_channel::mpsc::channel();
        service.discovery = Some(Discovery::fed(heard, Duration::from_millis(50)));
        let mut seen = Vec::new();
        let told = async {
            let mut frontend = Frontend::connect(&scratch).await;
            let quiet = frontend
                .until("Discovered", &mut seen, |d| d["quiet"] == json!(true))
                .await?;
            answers
                .send(DiscoveryEvent::Found(DiscoveredPeer {
                    claimed_fingerprint: Some("11:22:33".into()),
                    label: "desk-pc".into(),
                    addrs: vec!["192.0.2.5:4242".parse().expect("addr")],
                }))
                .expect("the daemon reads discovery");
            let answered = frontend
                .until("Discovered", &mut seen, |d| d["quiet"] == json!(false))
                .await?;
            Some((
                quiet["active"].clone(),
                answered["peers"][0]["label"].clone(),
            ))
        };
        let told = tokio::select! {
            ended = service.run() => panic!("the daemon ended: {ended:?}"),
            told = told => told,
            _ = tokio::time::sleep(DEADLINE) => None,
        };
        shut_down(service).await;
        assert_eq!(
            told,
            Some((json!(true), json!("desk-pc"))),
            "discovery ran and heard nobody, then a machine answered. A frontend must \
             be told the first while discovery is active, and then that it is over. \
             It was told: {seen:?}"
        );
    });
}
