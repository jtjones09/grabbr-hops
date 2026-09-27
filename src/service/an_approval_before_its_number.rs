//! An approval waiting for its number (#167) holds a pairing open, and only
//! a deliberate act on this machine may put a number card on its screen
//! (#195). What ends that wait, and what a machine mid-pairing is not asked
//! again, observed on a whole daemon run in this process.
//!
//! Its every file is in a scratch directory, its QUIC listener is on
//! loopback, capture and emulation are the dummy backends, and discovery is
//! off. A knock reaches it the way the listener hands one over; approvals,
//! cancels and add device reach it through its own request dispatch. What it
//! does is read where a frontend would read it: the events it sends, over the
//! real IPC socket while its loop runs, and what the TLS doors consult.

use super::{AttemptOrigin, Service};
use crate::emulation::EmulationEvent;
use crate::permission_watch::PermissionWatch;
use crate::prompt_gate::PromptGate;
use crate::test_harness::{machine, run_local};
use crate::trust::Caps;
use hops_ipc::{AsyncFrontendListener, DaemonEndpoint, FrontendEvent, FrontendRequest};
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// What must happen is waited for this long at most.
const DEADLINE: Duration = Duration::from_secs(30);
/// Longer than a machine that raised a prompt stays suppressed as a repeat,
/// so a knock after it would be prompted for, were nothing else stopping it.
const PAST_THE_REPEAT: Duration = Duration::from_millis(2500);

/// Where the other machine knocks from.
fn peer_addr() -> SocketAddr {
    "127.0.0.1:9".parse().expect("an address")
}

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

async fn daemon(tag: &str) -> (Service, Scratch) {
    // Short, for a socket path in it (`sun_path`).
    let dir = PathBuf::from(format!("/tmp/h-ab-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let config = dir.join("config.toml");
    std::fs::write(
        &config,
        "port = 0\ncapture_backend = \"dummy\"\nemulation_backend = \"dummy\"\ndiscovery = false\n",
    )
    .expect("a config");
    let endpoint = DaemonEndpoint::Unix(dir.join("s.sock"));
    let frontends = AsyncFrontendListener::at_with_token_file(&endpoint, &dir.join("ipc-token"))
        .await
        .expect("the scratch endpoint");
    let config = crate::config::Config::in_scratch(&config, &dir.join("hops.pem"))
        .expect("the scratch config");
    let mut service = Service::with_backends(
        config,
        frontends,
        Some(input_capture::Backend::Dummy),
        Some(input_emulation::Backend::Dummy),
    )
    .await
    .expect("a daemon in the scratch directory");
    // Every permission granted, and no launchd: nothing here ends the loop.
    service.permission_watch =
        PermissionWatch::at_daemon_start(Arc::new(|_| true), Arc::new(|| false), DEADLINE);
    (service, Scratch { dir, endpoint })
}

/// End a daemon whose loop is not running, as the loop's own end does, so
/// its tasks do not outlive it.
async fn shut_down(mut service: Service) {
    service.capture.terminate().await;
    service.emulation.terminate().await;
    service.resolver.terminate().await;
}

/// What the daemon has queued for its frontends since last taken, taken.
fn sent(service: &mut Service) -> Vec<FrontendEvent> {
    service.pending_frontend_events.drain(..).collect()
}

fn prompts_for(events: &[FrontendEvent], fp: &str) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, FrontendEvent::ConnectionAttempt { fingerprint, .. } if fingerprint == fp))
        .count()
}

fn notices(events: &[FrontendEvent]) -> Vec<String> {
    events
        .iter()
        .filter_map(|e| match e {
            FrontendEvent::Error(text) => Some(text.clone()),
            _ => None,
        })
        .collect()
}

/// The other machine knocks, the way the listener reports a knock.
fn knock(service: &mut Service, fp: &str) {
    service.handle_emulation_event(EmulationEvent::ConnectionAttempt {
        fingerprint: fp.to_string(),
        addr: peer_addr(),
    });
}

/// Open add device, be asked about `fp` arriving by `origin`, and approve
/// it. Its pairing then waits for a number.
fn approve(service: &mut Service, fp: &str, origin: AttemptOrigin) {
    service.handle_frontend_request(Some(Ok(FrontendRequest::OpenPairing)));
    match origin {
        AttemptOrigin::Inbound => knock(service, fp),
        AttemptOrigin::OutboundDial => {
            service.raise_connection_attempt(fp.to_string(), origin, Some(peer_addr()))
        }
    }
    assert_eq!(
        prompts_for(&sent(service), fp),
        1,
        "add device is open and {fp} was not asked about"
    );
    service.handle_frontend_request(Some(Ok(FrontendRequest::AuthorizeKey(
        "desk b".into(),
        fp.to_string(),
    ))));
    assert!(
        service.trust.read().expect("lock").is_pairing(fp),
        "the approval does not wait for a number: {:?}",
        notices(&sent(service))
    );
    sent(service);
}

/// Knock until the daemon asks about `fp`, or fail after `DEADLINE`.
async fn knock_until_asked(service: &mut Service, fp: &str) -> bool {
    let deadline = Instant::now() + DEADLINE;
    while Instant::now() < deadline {
        knock(service, fp);
        if prompts_for(&sent(service), fp) > 0 {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    false
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

    /// The next event it is sent; `None` once the daemon hangs up.
    async fn next(&mut self) -> Option<FrontendEvent> {
        while let Ok(Some(line)) = self.lines.next_line().await {
            if let Ok(event) = serde_json::from_str(&line) {
                return Some(event);
            }
        }
        None
    }
}

/// Run the daemon's loop until `until` resolves, and fail after `DEADLINE`.
async fn serve<T>(service: &mut Service, until: impl Future<Output = T>, what: &str) -> T {
    tokio::select! {
        ended = service.run() => panic!("the daemon ended ({ended:?}) while waiting: {what}"),
        found = until => found,
        _ = tokio::time::sleep(DEADLINE) => panic!("{what}"),
    }
}

/// `at` moved back by the pairing window: as if it happened that long ago.
fn a_window_before(at: Instant) -> Instant {
    at.checked_sub(PromptGate::WINDOW + Duration::from_secs(1))
        .expect("this machine has been up longer than the pairing window")
}

/// Approved here, and no number within the pairing window: the other
/// machine never approved, or never dialled. The approval is forgotten, so
/// the TLS door stops admitting that machine, and a later knock asks about
/// it afresh instead of heading for a number card nobody here chose.
// LEDGER G-17 | class B | 2 events over the real IPC socket + 1 the trust the TLS door consults
#[test]
fn an_approval_that_shows_no_number_within_the_window_is_forgotten() {
    run_local(async {
        let (mut service, scratch) = daemon("late").await;
        let peer = machine().fingerprint;
        approve(&mut service, &peer, AttemptOrigin::Inbound);
        let when = service
            .approved
            .get_mut(&peer)
            .expect("the approval is held");
        when.0 = a_window_before(when.0);

        let mut frontend = Frontend::connect(&scratch).await;
        let told = serve(
            &mut service,
            async {
                let (mut told, mut forgotten) = (None, false);
                while let Some(event) = frontend.next().await {
                    match event {
                        FrontendEvent::Error(text) if text.contains("did not start") => {
                            told = Some(text)
                        }
                        FrontendEvent::TrustUpdated(map) => forgotten = !map.contains_key(&peer),
                        _ => {}
                    }
                    if told.is_some() && forgotten {
                        break;
                    }
                }
                told
            },
            "an approval that showed no number for longer than the pairing window was \
             not forgotten: no trust update without it, or no notice saying so",
        )
        .await;
        assert!(
            told.as_deref().is_some_and(|t| t.contains("not kept")),
            "the notice does not say the approval was dropped: {told:?}"
        );
        assert!(
            !service
                .trust
                .read()
                .expect("lock")
                .awaits(&peer, Caps::DRIVE_ME),
            "the TLS door still admits the machine whose approval was forgotten"
        );
        assert!(
            knock_until_asked(&mut service, &peer).await,
            "a knock after the approval was forgotten was not asked about afresh"
        );
        shut_down(service).await;
    });
}

/// Approved here and waiting for its number: the machine's next knocks
/// raise no second prompt, and approving it again is refused rather than
/// restarting the two minutes it has to show a number (#195).
// LEDGER G-18 | class B | 1 events the daemon sends + 1 the approval's clock
#[test]
fn a_machine_approved_here_is_not_asked_about_again_while_it_pairs() {
    run_local(async {
        let (mut service, _scratch) = daemon("again").await;
        let peer = machine().fingerprint;
        approve(&mut service, &peer, AttemptOrigin::Inbound);
        let approved_at = service.approved[&peer].0;

        tokio::time::sleep(PAST_THE_REPEAT).await;
        knock(&mut service, &peer);
        knock(&mut service, &peer);
        let events = sent(&mut service);
        assert_eq!(
            prompts_for(&events, &peer),
            0,
            "a machine approved here, waiting for its number, was asked about again"
        );
        assert!(
            notices(&events).is_empty(),
            "a knock from a machine approved to drive this one raised a notice: {events:?}"
        );
        service.handle_frontend_request(Some(Ok(FrontendRequest::AuthorizeKey(
            "desk b".into(),
            peer.clone(),
        ))));
        assert_eq!(
            service.approved.get(&peer).map(|a| a.0),
            Some(approved_at),
            "approving again restarted the time the pairing has to show its number"
        );
        shut_down(service).await;
    });
}

/// "None of these", or a cancel, on the machine being added: the approval
/// is forgotten at once, and the next knock is asked about afresh.
// LEDGER G-19 | class B | 1 events the daemon sends + 1 the trust the TLS door consults
#[test]
fn a_cancel_forgets_the_approval() {
    run_local(async {
        let (mut service, _scratch) = daemon("cancel").await;
        let peer = machine().fingerprint;
        approve(&mut service, &peer, AttemptOrigin::Inbound);

        service.handle_frontend_request(Some(Ok(FrontendRequest::CancelPairing(peer.clone()))));
        let events = sent(&mut service);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, FrontendEvent::TrustUpdated(map) if !map.contains_key(&peer)))
                && notices(&events)
                    .iter()
                    .any(|t| t.contains("cancelled here")),
            "a cancel kept the approval, or did not say so: {events:?}"
        );
        assert!(
            !service
                .trust
                .read()
                .expect("lock")
                .awaits(&peer, Caps::DRIVE_ME),
            "the TLS door still admits the machine whose pairing was cancelled"
        );
        assert!(
            knock_until_asked(&mut service, &peer).await,
            "a knock after the cancel was not asked about afresh"
        );
        shut_down(service).await;
    });
}

/// Both machines adding each other, each approving the dial it made: each
/// approved itself as the machine in control, so neither TLS door admits
/// the other and no number can appear. The other machine's knock says so
/// once, and the add dial that gives up says so too, not that the other
/// machine never approved.
// LEDGER G-20 | class B | 1 events the daemon sends + 2 notice over the real IPC socket
#[test]
fn machines_adding_each_other_are_told_so() {
    run_local(async {
        let (mut service, scratch) = daemon("both").await;
        let peer = machine().fingerprint;
        service.handle_frontend_request(Some(Ok(FrontendRequest::OpenPairing)));
        service.handle_frontend_request(Some(Ok(FrontendRequest::Create)));
        let handle = sent(&mut service)
            .iter()
            .find_map(|e| match e {
                FrontendEvent::Created(handle, _, _) => Some(*handle),
                _ => None,
            })
            .expect("a device is created");
        for request in [
            FrontendRequest::UpdateFixIps(handle, vec![peer_addr().ip()]),
            FrontendRequest::UpdatePort(handle, peer_addr().port()),
            FrontendRequest::Activate(handle, true),
        ] {
            service.handle_frontend_request(Some(Ok(request)));
        }
        assert!(
            service.adding.contains_key(&handle),
            "the add dial did not start"
        );
        approve(&mut service, &peer, AttemptOrigin::OutboundDial);

        knock(&mut service, &peer);
        let first = sent(&mut service);
        tokio::time::sleep(PAST_THE_REPEAT).await;
        knock(&mut service, &peer);
        let again = sent(&mut service);
        let told: Vec<String> = notices(&first)
            .into_iter()
            .filter(|t| t.contains("at the same time"))
            .collect();
        assert_eq!(
            told.len(),
            1,
            "the other machine's knock, while this machine adds it, did not say once \
             that both machines are adding each other: {first:?}"
        );
        assert_eq!(
            (prompts_for(&first, &peer), prompts_for(&again, &peer)),
            (0, 0),
            "a machine approved here was asked about again"
        );
        assert!(
            notices(&again).is_empty(),
            "the same crossing was announced again: {again:?}"
        );

        let started = service.adding.get_mut(&handle).expect("still adding");
        *started = a_window_before(*started);
        // The loop sets up capture for every device switched on as it starts,
        // and this one was switched on before it ran: undo that here.
        service.capture.destroy(handle);
        let mut frontend = Frontend::connect(&scratch).await;
        let gave_up = serve(
            &mut service,
            async {
                while let Some(event) = frontend.next().await {
                    if let FrontendEvent::Error(text) = event {
                        if text.contains("did not finish") {
                            return Some(text);
                        }
                    }
                }
                None
            },
            "an add dial past the pairing window never gave up",
        )
        .await;
        assert!(
            gave_up
                .as_deref()
                .is_some_and(|t| t.contains("at the same time") && !t.contains("never approved")),
            "the add dial's notice blames the other machine for not approving, when \
             both machines approved themselves as the one in control: {gave_up:?}"
        );
        shut_down(service).await;
    });
}

/// Approved here and waiting for its number is not paired (#167): the
/// network list still offers the machine as one to add, and a device pinned
/// to it is not named by the approval's label as the name it was paired
/// under. Once confirmed, both change, so neither check could pass on a
/// daemon that ignored the pairing.
// LEDGER G-19 | class B | 1 events the daemon sends + 1 return value: Service::publish_discovered, Service::device_name
#[test]
fn a_machine_waiting_for_its_number_is_not_treated_as_paired() {
    run_local(async {
        let (mut service, _scratch) = daemon("np").await;
        let (listed, pinned) = (machine().fingerprint, machine().fingerprint);
        approve(&mut service, &listed, AttemptOrigin::Inbound);
        approve(&mut service, &pinned, AttemptOrigin::OutboundDial);

        service.discovered.found(
            crate::discovery::DiscoveredPeer {
                claimed_fingerprint: Some(listed.clone()),
                label: "desk-b.local".into(),
                addrs: vec![peer_addr()],
            },
            Instant::now(),
        );
        let offered = |service: &mut Service| {
            service.publish_discovered();
            sent(service).iter().any(|e| {
                matches!(e, FrontendEvent::Discovered { peers, .. }
                    if peers.iter().any(|p| p.claimed_fingerprint.as_deref() == Some(listed.as_str())))
            })
        };
        assert!(
            offered(&mut service),
            "a machine whose pairing waits for its number was hidden from the \
             network list as if it were paired"
        );

        let handle = service.client_manager.add_client();
        service
            .client_manager
            .set_fix_ips(handle, vec![peer_addr().ip()]);
        service
            .client_manager
            .pin(handle, pinned.clone())
            .expect("the only device for that machine");
        assert_eq!(
            service.device_name(handle),
            peer_addr().ip().to_string(),
            "a device pinned to a machine whose pairing waits for its number was \
             named by the approval, as the name it was paired under"
        );

        for fp in [&listed, &pinned] {
            service
                .trust
                .write()
                .expect("lock")
                .confirm(fp)
                .expect("confirm");
        }
        assert!(
            !offered(&mut service),
            "a paired machine was offered to add again"
        );
        assert_eq!(service.device_name(handle), "desk b", "once paired");
        shut_down(service).await;
    });
}
