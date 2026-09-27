//! What the daemon tells the app when a machine refuses this one, and what a
//! stranger on the network can make it keep (#171, #101). The whole daemon
//! runs in this process.
//!
//! Its every file is in a scratch directory, its QUIC listener is on
//! loopback, emulation is the dummy backend, capture is scripted, and
//! discovery is off. What it tells the app is read the way an app reads it:
//! over the real IPC socket, one JSON event per line.

use super::Service;
use crate::discovery::{DiscoveredPeer, DiscoveryEvent};
use crate::listen::LanMouseListener;
use crate::test_harness::{machine, run_local, trust};
use crate::trust::Caps;
use hops_ipc::{AsyncFrontendListener, DaemonEndpoint};
use input_capture::scripted::Script;
use input_capture::{CaptureEvent, Position};
use std::path::PathBuf;
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

/// A daemon in a scratch directory, with `tables` appended to its config
/// and capture scripted by `script`.
async fn daemon(tag: &str, tables: &str, script: &Script) -> (Service, Scratch) {
    // Short, for a socket path in it (`sun_path`).
    let dir = PathBuf::from(format!("/tmp/h-rf-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let config = dir.join("config.toml");
    std::fs::write(
        &config,
        format!(
            "port = 0\ncapture_backend = \"dummy\"\nemulation_backend = \"dummy\"\n\
             discovery = false\n\n{tables}"
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
    let service = Service::with_backends(
        config,
        frontends,
        Some(script.backend()),
        Some(input_emulation::Backend::Dummy),
    )
    .await
    .expect("a daemon in the scratch directory");
    (service, scratch)
}

/// An app connected over the daemon's IPC socket, reading raw event lines.
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

    /// The next event of kind `kind` (`"Error"`, `"Activity"`, ...) whose
    /// text `want` accepts, noting every error and activity line on the way.
    /// `None` once the daemon hangs up.
    async fn next_text(
        &mut self,
        kind: &str,
        seen: &mut Vec<String>,
        want: impl Fn(&str) -> bool,
    ) -> Option<String> {
        while let Ok(Some(line)) = self.lines.next_line().await {
            let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            for k in ["Error", "Activity"] {
                if let Some(text) = event.get(k).and_then(|t| t.as_str()) {
                    seen.push(format!("{k}: {text}"));
                    if k == kind && want(text) {
                        return Some(text.to_owned());
                    }
                }
            }
        }
        None
    }
}

/// A crossing to a paired machine that refuses this one used to change
/// nothing in the app: the link opened, closed, and only the log said why.
/// The app is told, as an error, since the person here moved the pointer.
// LEDGER T2375 | class B | 2 bytes (IPC events) from the whole daemon in-process, crossing driven by scripted capture
#[test]
fn a_crossing_into_a_machine_that_refuses_this_one_says_so() {
    run_local(async {
        // The desk mac holds no pairing with this machine, as after it
        // removed this one.
        let desk = machine();
        let (clip_tx, _clip_rx) = local_channel::mpsc::channel();
        let (_desk_listener, desk_port) = LanMouseListener::bind_loopback(
            desk.identity.clone(),
            trust(&desk, &[], Caps::INBOUND),
            clip_tx,
        )
        .await
        .expect("the desk mac listens");

        let script = Script::new();
        let (mut service, scratch) = daemon(
            "cross",
            &format!(
                "[authorized_fingerprints]\n\"{fp}\" = \"desk mac\"\n\n\
                 [[clients]]\nposition = \"left\"\nips = [\"127.0.0.1\"]\nport = {desk_port}\n\
                 activate_on_startup = true\nfingerprint = \"{fp}\"\n",
                fp = desk.fingerprint
            ),
            &script,
        )
        .await;
        let mut app = Frontend::connect(&scratch).await;

        let crossing = async {
            loop {
                script.push(Position::Left, CaptureEvent::Begin);
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        };
        let mut seen = Vec::new();
        let told = tokio::select! {
            told = app.next_text("Error", &mut seen, |t| t.contains("desk mac")) => told,
            ended = service.run() => panic!("the daemon ended: {:?}", ended.err()),
            _ = crossing => unreachable!(),
            _ = tokio::time::sleep(DEADLINE) => None,
        };
        let told = told.unwrap_or_else(|| {
            panic!(
                "crossing into a machine that refuses this one told the app nothing \
                 naming it within {DEADLINE:?}; it was told: {seen:?}"
            )
        });
        assert!(
            told.contains("refused the connection") && told.contains("open add device on desk mac"),
            "the notice must say the desk mac refused the connection and how to pair \
             again: {told:?}"
        );
        service.capture.terminate().await;
        service.emulation.terminate().await;
        service.resolver.terminate().await;
    });
}

/// Anything on the network can announce itself, with a fresh fingerprint
/// every time. The daemon's list of machines seen stays bounded (#101).
// LEDGER T2376 | class B | 6 struct state: Service::discovered after its own event handler
#[test]
fn a_flood_of_announcements_cannot_grow_the_daemons_list_without_bound() {
    run_local(async {
        let script = Script::new();
        let (mut service, _scratch) = daemon("mdns", "", &script).await;
        for i in 0..2_000u32 {
            service.handle_discovery_event(Some(DiscoveryEvent::Found(DiscoveredPeer {
                claimed_fingerprint: Some(format!("f1:{i:08x}")),
                label: format!("stranger-{i}"),
                addrs: vec!["192.0.2.66:4242".parse().expect("addr")],
            })));
        }
        assert!(
            service.discovered.len() <= 256,
            "2,000 announcements from strangers left {} machines listed",
            service.discovered.len()
        );
        service.capture.terminate().await;
        service.emulation.terminate().await;
        service.resolver.terminate().await;
    });
}

/// The issue's own case: a device's address now reaches another paired
/// machine. The dial is refused, as it must be, and the app is told which
/// machine answered, rather than only the log (#171).
// LEDGER T2378 | class B | 2 bytes (IPC events) from the whole daemon in-process, crossing driven by scripted capture
#[test]
fn a_crossing_whose_address_reaches_another_paired_machine_says_which() {
    run_local(async {
        // The laptop listens where the desk mac's device points.
        let desk = machine();
        let laptop = machine();
        let (clip_tx, _clip_rx) = local_channel::mpsc::channel();
        let (_laptop_listener, laptop_port) = LanMouseListener::bind_loopback(
            laptop.identity.clone(),
            trust(&laptop, &[], Caps::INBOUND),
            clip_tx,
        )
        .await
        .expect("the laptop listens");

        let script = Script::new();
        let (mut service, scratch) = daemon(
            "pin",
            &format!(
                "[authorized_fingerprints]\n\"{desk}\" = \"desk mac\"\n\"{laptop}\" = \"laptop\"\n\n\
                 [[clients]]\nposition = \"left\"\nips = [\"127.0.0.1\"]\nport = {laptop_port}\n\
                 activate_on_startup = true\nfingerprint = \"{desk}\"\n\n\
                 [[clients]]\nposition = \"right\"\nips = [\"127.0.0.1\"]\nport = {laptop_port}\n\
                 fingerprint = \"{laptop}\"\n",
                desk = desk.fingerprint,
                laptop = laptop.fingerprint,
            ),
            &script,
        )
        .await;
        let mut app = Frontend::connect(&scratch).await;

        let crossing = async {
            loop {
                script.push(Position::Left, CaptureEvent::Begin);
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        };
        let mut seen = Vec::new();
        let told = tokio::select! {
            told = app.next_text("Error", &mut seen, |t| t.contains("desk mac")) => told,
            ended = service.run() => panic!("the daemon ended: {:?}", ended.err()),
            _ = crossing => unreachable!(),
            _ = tokio::time::sleep(DEADLINE) => None,
        };
        let told = told.unwrap_or_else(|| {
            panic!(
                "the desk mac's address answered as the laptop, and the app was told \
                 nothing naming the desk mac within {DEADLINE:?}; it was told: {seen:?}"
            )
        });
        assert!(
            told.contains("answered for desk mac as laptop"),
            "the notice must name the machine that answered: {told:?}"
        );
        service.capture.terminate().await;
        service.emulation.terminate().await;
        service.resolver.terminate().await;
    });
}

/// A crossing is retried each time the pointer reaches the edge, and a
/// device being added is dialled every second: the same refusal says so
/// once a minute, not each time. While the device is being added, its
/// refusal is expected and is activity; any other time it is an error.
// LEDGER T2379 | class B | 6 struct state: the daemon's queue of events for the app
#[test]
fn a_refusal_is_told_once_a_minute_and_as_activity_while_adding() {
    use crate::connect::DialRefusal;
    use hops_ipc::FrontendEvent;
    run_local(async {
        let script = Script::new();
        let (mut service, _scratch) = daemon("once", "", &script).await;
        let desk = service.client_manager.add_client();
        let refused = || DialRefusal::RefusedByPeer {
            handle: desk,
            fingerprint: "de:5k".into(),
            addr: "192.0.2.7:4242".parse().expect("addr"),
        };
        let told = |service: &mut Service| -> Vec<FrontendEvent> {
            service.pending_frontend_events.drain(..).collect()
        };
        let _ = told(&mut service);

        for _ in 0..5 {
            service.handle_dial_refusal(refused());
            service.handle_dial_refusal(DialRefusal::Conflict {
                handle: desk,
                seen: vec![],
            });
        }
        let events = told(&mut service);
        let errors: Vec<&String> = events
            .iter()
            .filter_map(|e| match e {
                FrontendEvent::Error(t) => Some(t),
                _ => None,
            })
            .collect();
        assert_eq!(
            errors.len(),
            2,
            "five refusals and five conflicts in a moment must say so once each: {errors:?}"
        );
        assert!(errors.iter().any(|t| t.contains("refused the connection")));
        assert!(
            errors
                .iter()
                .any(|t| t.contains("answered as different machines"))
        );

        let other = service.client_manager.add_client();
        service.adding.insert(other, std::time::Instant::now());
        service.handle_dial_refusal(DialRefusal::RefusedByPeer {
            handle: other,
            fingerprint: "1a:9b".into(),
            addr: "192.0.2.8:4242".parse().expect("addr"),
        });
        let events = told(&mut service);
        assert!(
            matches!(events.as_slice(), [FrontendEvent::Activity(t)] if t.starts_with("Waiting for")),
            "a refusal while adding must be one activity line and no error: {events:?}"
        );

        service.capture.terminate().await;
        service.emulation.terminate().await;
        service.resolver.terminate().await;
    });
}

/// A machine that has not approved this one still completes this machine's
/// half of the handshake, so the link looks open until its refusal lands.
/// Adding must not end in that moment: it did, the refusal that followed was
/// an error while the device was still being added, and dialling stopped.
// LEDGER T2382 | class B | 6 struct state: the daemon's queue of events for the app after its own tick
#[test]
fn a_link_that_only_looked_open_does_not_end_adding() {
    use crate::connect::DialRefusal;
    use hops_ipc::FrontendEvent;
    run_local(async {
        let script = Script::new();
        let (mut service, _scratch) = daemon("look", "", &script).await;
        let desk = service.client_manager.add_client();
        service.client_manager.activate_client(desk);
        let now = std::time::Instant::now();
        service.prompt_gate.open(now);
        service.adding.insert(desk, now);
        let addr: std::net::SocketAddr = "192.0.2.7:4242".parse().expect("addr");

        // The tick lands while the link looks open, then the refusal ends it.
        service.client_manager.set_active_addr(desk, Some(addr));
        service.retry_adding();
        service.client_manager.set_active_addr(desk, None);
        let _: Vec<FrontendEvent> = service.pending_frontend_events.drain(..).collect();
        service.handle_dial_refusal(DialRefusal::RefusedByPeer {
            handle: desk,
            fingerprint: "de:5k".into(),
            addr,
        });
        let events: Vec<FrontendEvent> = service.pending_frontend_events.drain(..).collect();
        assert!(
            matches!(events.as_slice(), [FrontendEvent::Activity(t)] if t.starts_with("Waiting for")),
            "a refusal after a link that only looked open ended adding: {events:?}"
        );
        assert!(
            service.adding.contains_key(&desk),
            "the device is no longer dialled while it is being added"
        );

        service.capture.terminate().await;
        service.emulation.terminate().await;
        service.resolver.terminate().await;
    });
}
