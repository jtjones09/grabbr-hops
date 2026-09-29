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
use tokio::io::{AsyncBufReadExt, BufReader};

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
    paired_daemon(tag, tables, &[], script).await
}

/// [`daemon`], already paired with each machine in `pairings`
/// ([`crate::test_harness::seed_pairings`]).
async fn paired_daemon(
    tag: &str,
    tables: &str,
    pairings: &[(&str, &str, Caps)],
    script: &Script,
) -> (Service, Scratch) {
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
    if !pairings.is_empty() {
        crate::test_harness::seed_pairings(&dir, &dir.join("hops.pem"), pairings);
    }
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

/// An app that has made the two-way proof, which the daemon's listener
/// answers only while it is polled, and before which it sends an app
/// nothing. Polls the listener alone, not the loop, so nothing the loop
/// says once it runs can come before the app is heard.
async fn attached(service: &mut Service, scratch: &Scratch) -> Frontend {
    use futures::StreamExt;
    let mut app = Frontend::connect(scratch).await;
    {
        let proving = app.prove();
        tokio::pin!(proving);
        let deadline = tokio::time::sleep(DEADLINE);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                () = &mut proving => break,
                _ = service.frontend_listener.next() => {}
                _ = &mut deadline => panic!("the app's two-way proof was never answered"),
            }
        }
    }
    app
}

/// An app connected over the daemon's IPC socket, reading raw event lines.
struct Frontend {
    lines: tokio::io::Lines<BufReader<tokio::net::unix::OwnedReadHalf>>,
    tx: tokio::net::unix::OwnedWriteHalf,
    /// The token, until the proof is made on the first read.
    unproven: Option<String>,
}

impl Frontend {
    async fn connect(scratch: &Scratch) -> Self {
        let DaemonEndpoint::Unix(path) = &scratch.endpoint else {
            unreachable!("a unix socket")
        };
        let token = std::fs::read_to_string(scratch.dir.join("ipc-token")).expect("the token");
        let stream = tokio::net::UnixStream::connect(path)
            .await
            .expect("the daemon's socket");
        let (rx, tx) = stream.into_split();
        Self {
            lines: BufReader::new(rx).lines(),
            tx,
            unproven: Some(token.trim().to_string()),
        }
    }

    /// Make the two-way proof, the first time it is read from. The daemon
    /// answers only while its loop runs, which it does while this is read.
    async fn prove(&mut self) {
        if let Some(token) = self.unproven.take() {
            hops_ipc::prove_to_daemon(self.lines.get_mut(), &mut self.tx, &token)
                .await
                .expect("the two-way proof is made");
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
        self.prove().await;
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

/// Cross into the desk mac, whose store `fill` is given along with this
/// machine's fingerprint, from a daemon holding a pairing with it, and
/// return what the app was told: the first error
/// naming it that `want` accepts, every error and activity line seen, the
/// last state the device was shown in, and whether the daemon still holds
/// its pairing.
async fn cross_into(
    tag: &str,
    fill: impl FnOnce(&mut crate::trust::TrustStore, &str),
    want: impl Fn(&str) -> bool,
) -> (Option<String>, Vec<String>, serde_json::Value, bool) {
    let desk = machine();
    let (clip_tx, _clip_rx) = local_channel::mpsc::channel();
    let script = Script::new();
    // The desk mac's store is filled once this machine's fingerprint is
    // known, which is once its daemon exists; the listener reads it live.
    let shared = trust(&desk, &[], Caps::INBOUND);
    let (_desk_listener, desk_port) =
        LanMouseListener::bind_loopback(desk.identity.clone(), shared.clone(), clip_tx)
            .await
            .expect("the desk mac listens");
    let (mut service, scratch) = paired_daemon(
        tag,
        &format!(
            "[[clients]]\nposition = \"left\"\nips = [\"127.0.0.1\"]\nport = {desk_port}\n\
             activate_on_startup = true\nfingerprint = \"{fp}\"\n",
            fp = desk.fingerprint
        ),
        &[(&desk.fingerprint, "desk mac", Caps::DRIVE)],
        &script,
    )
    .await;
    fill(
        &mut shared.write().expect("lock"),
        &service.public_key_fingerprint,
    );
    let mut app = attached(&mut service, &scratch).await;

    let crossing = async {
        loop {
            script.push(Position::Left, CaptureEvent::Begin);
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    };
    let mut seen = Vec::new();
    let told = tokio::select! {
        told = app.next_text("Error", &mut seen, |t| t.contains("desk mac") && want(t)) => told,
        ended = service.run() => panic!("the daemon ended: {:?}", ended.err()),
        _ = crossing => unreachable!(),
        _ = tokio::time::sleep(DEADLINE) => None,
    };
    let shown = service
        .client_manager
        .get_client_states()
        .first()
        .map(|(_, _, state)| serde_json::to_value(state).expect("json"))
        .unwrap_or_default();
    let still_paired = service
        .trust
        .read()
        .expect("lock")
        .we_may_drive(&desk.fingerprint);
    service.capture.terminate().await;
    service.emulation.terminate().await;
    service.resolver.terminate().await;
    (told, seen, shown, still_paired)
}

/// A crossing into a paired machine that removed this one (#184): the desk
/// mac holds no pairing with this machine, so it refuses the dial as
/// `access_denied`. The app is told the desk mac no longer trusts this
/// machine and to remove it, the device's card is marked so, and this
/// machine keeps its side until someone removes it here.
// LEDGER T2375 | class B | 2 bytes (IPC events) from the whole daemon in-process, crossing driven by scripted capture
#[test]
fn a_crossing_into_a_machine_that_removed_this_one_marks_its_card() {
    run_local(async {
        let (told, seen, shown, still_paired) = cross_into(
            "removed",
            |_, _| {},
            |t| t.contains("no longer trusts this machine"),
        )
        .await;
        let told = told.unwrap_or_else(|| {
            panic!(
                "crossing into a machine that removed this one did not say it no longer \
                 trusts this machine within {DEADLINE:?}; it was told: {seen:?}"
            )
        });
        assert!(
            told.contains("Remove desk mac here"),
            "the notice does not say to remove it here: {told:?}"
        );
        assert_eq!(
            shown.get("removed_by_peer"),
            Some(&serde_json::json!(true)),
            "the device's card is not marked: {shown}"
        );
        assert!(
            still_paired,
            "this machine removed its own pairing unasked; the card should ask"
        );
    });
}

/// A crossing into a paired machine that knows this one but does not let it
/// drive, paired the other way only, is refused as it always was: that
/// machine did not remove this one, and the card is not marked (#171).
// LEDGER R184-12 | class B | 2 bytes (IPC events) from the whole daemon in-process, crossing driven by scripted capture
#[test]
fn a_crossing_into_a_machine_paired_the_other_way_says_it_refused() {
    run_local(async {
        let (told, seen, shown, _) = cross_into(
            "oneway",
            |desk, ours| {
                desk.issue_confirmed(ours, "this machine", Caps::OUTBOUND)
                    .expect("issue");
            },
            |t| t.contains("refused the connection"),
        )
        .await;
        let told = told.unwrap_or_else(|| {
            panic!(
                "crossing into a machine that refuses this one told the app nothing \
                 naming it within {DEADLINE:?}; it was told: {seen:?}"
            )
        });
        assert!(
            told.contains("open add device on desk mac"),
            "the notice must say how to pair again: {told:?}"
        );
        assert_ne!(
            shown.get("removed_by_peer"),
            Some(&serde_json::json!(true)),
            "a machine that did not remove this one was shown as having removed it"
        );
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
        let (mut service, scratch) = paired_daemon(
            "pin",
            &format!(
                "[[clients]]\nposition = \"left\"\nips = [\"127.0.0.1\"]\nport = {laptop_port}\n\
                 activate_on_startup = true\nfingerprint = \"{desk}\"\n\n\
                 [[clients]]\nposition = \"right\"\nips = [\"127.0.0.1\"]\nport = {laptop_port}\n\
                 fingerprint = \"{laptop}\"\n",
                desk = desk.fingerprint,
                laptop = laptop.fingerprint,
            ),
            &[
                (&desk.fingerprint, "desk mac", Caps::DRIVE),
                (&laptop.fingerprint, "laptop", Caps::DRIVE),
            ],
            &script,
        )
        .await;
        let mut app = attached(&mut service, &scratch).await;

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

/// A refusal as a machine the receiver holds no pairing with marks the
/// device's card only when this machine holds a pairing with that receiver
/// and is not adding it (#184). While adding it, that machine may simply not
/// have approved this one yet; a machine never paired with is refused as
/// any other.
// LEDGER R184-13 | class B | 6 struct state: the daemon's queue of events for the app, and the device's state
#[test]
fn only_a_paired_machine_refusing_this_one_outside_adding_marks_its_card() {
    use crate::connect::DialRefusal;
    use hops_ipc::FrontendEvent;
    run_local(async {
        let script = Script::new();
        let (mut service, _scratch) = daemon("mark", "", &script).await;
        let paired = machine().fingerprint;
        service
            .trust
            .write()
            .expect("lock")
            .issue_confirmed(&paired, "desk mac", Caps::OUTBOUND)
            .expect("issue");
        let addr: std::net::SocketAddr = "192.0.2.7:4242".parse().expect("addr");
        let told = |service: &mut Service| -> Vec<FrontendEvent> {
            service.pending_frontend_events.drain(..).collect()
        };
        let marked = |service: &Service, handle| {
            service
                .client_manager
                .get_state(handle)
                .is_some_and(|(_, s)| s.removed_by_peer)
        };
        let _ = told(&mut service);

        // Being added: an activity line, and no mark.
        let adding = service.client_manager.add_client();
        service.adding.insert(adding, std::time::Instant::now());
        service.handle_dial_refusal(DialRefusal::Forgotten {
            handle: adding,
            fingerprint: paired.clone(),
            addr,
        });
        let events = told(&mut service);
        assert!(
            matches!(events.as_slice(), [FrontendEvent::Activity(t)] if t.starts_with("Waiting for")),
            "a refusal while adding must be one activity line and no error: {events:?}"
        );
        assert!(
            !marked(&service, adding),
            "a device being added was marked as removed by its machine"
        );

        // Never paired: refused as before, no mark.
        let stranger = service.client_manager.add_client();
        service.handle_dial_refusal(DialRefusal::Forgotten {
            handle: stranger,
            fingerprint: machine().fingerprint,
            addr,
        });
        let events = told(&mut service);
        assert!(
            events.iter().any(
                |e| matches!(e, FrontendEvent::Error(t) if t.contains("refused the connection"))
            ),
            "a machine never paired with was not refused as before: {events:?}"
        );
        assert!(
            !marked(&service, stranger),
            "a device never paired was marked as removed by its machine"
        );

        // Paired, and not being added: marked, said once, and still paired.
        let desk = service.client_manager.add_client();
        for _ in 0..3 {
            service.handle_dial_refusal(DialRefusal::Forgotten {
                handle: desk,
                fingerprint: paired.clone(),
                addr,
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
        assert!(
            matches!(errors.as_slice(), [t] if t.contains("no longer trusts this machine")),
            "three refusals by a machine that removed this one must say so once: {errors:?}"
        );
        assert!(marked(&service, desk), "the device's card is not marked");
        assert!(
            events.iter().any(
                |e| matches!(e, FrontendEvent::State(h, _, s) if *h == desk && s.removed_by_peer)
            ),
            "the app was not shown the marked card: {events:?}"
        );
        assert!(
            service.trust.read().expect("lock").we_may_drive(&paired),
            "this machine removed its own pairing unasked"
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

// LEDGER R231-10 | class B | 2 bytes (IPC events) from the whole daemon in-process, crossing driven by scripted capture
/// Upgraded from v0.12.0, which listed the desk mac and kept a device for
/// its address with no fingerprint. A crossing dials it, and the app is
/// told the desk mac must be paired again, not that it is not paired
/// (#231).
#[test]
fn a_crossing_into_a_machine_paired_with_an_older_version_says_to_pair_it_again() {
    run_local(async {
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
            "older",
            &format!(
                "[authorized_fingerprints]\n\"{fp}\" = \"desk mac\"\n\n\
                 [[clients]]\nposition = \"left\"\nips = [\"127.0.0.1\"]\nport = {desk_port}\n\
                 activate_on_startup = true\n",
                fp = desk.fingerprint
            ),
            &script,
        )
        .await;
        let mut app = attached(&mut service, &scratch).await;
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
        service.capture.terminate().await;
        service.emulation.terminate().await;
        service.resolver.terminate().await;
        let told = told.unwrap_or_else(|| {
            panic!("the app was told nothing naming the desk mac; it was told: {seen:?}")
        });
        assert!(
            told.contains("paired with an older version of hops") && told.contains("paired again"),
            "the dial to a machine paired with an older version does not say to pair it \
             again: {told:?}"
        );
    });
}
