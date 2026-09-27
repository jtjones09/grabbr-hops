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
use tokio::io::{AsyncBufReadExt, BufReader};

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
    service.handle_frontend_request(Some(Ok(crate::test_harness::approval(
        "desk b",
        fp,
        hops_ipc::Controller::ThatMachine,
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

    /// The next event it is sent; `None` once the daemon hangs up.
    async fn next(&mut self) -> Option<FrontendEvent> {
        self.prove().await;
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

/// A frontend that has made the two-way proof, which the daemon's listener
/// answers only while it is polled, and before which it sends a frontend
/// nothing. Polls the listener alone, not the loop, so a test can attach
/// before it sets up what the loop will tell frontends about.
async fn attached(service: &mut Service, scratch: &Scratch) -> Frontend {
    use futures::StreamExt;
    let mut frontend = Frontend::connect(scratch).await;
    {
        let proving = frontend.prove();
        tokio::pin!(proving);
        let deadline = tokio::time::sleep(DEADLINE);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                () = &mut proving => break,
                _ = service.frontend_listener.next() => {}
                _ = &mut deadline => panic!("the frontend's two-way proof was never answered"),
            }
        }
    }
    frontend
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
        let mut frontend = attached(&mut service, &scratch).await;
        let when = service
            .approved
            .get_mut(&peer)
            .expect("the approval is held");
        when.at = a_window_before(when.at);

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
        let approved_at = service.approved[&peer].at;

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
        service.handle_frontend_request(Some(Ok(crate::test_harness::approval(
            "desk b",
            &peer,
            hops_ipc::Controller::ThatMachine,
        ))));
        assert_eq!(
            service.approved.get(&peer).map(|a| a.at),
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

/// Removing a device whose approval here waits for its number drops that
/// approval with its lease (#184, #220): what the card answered goes, the
/// TLS door stops admitting the machine, the add dial that gives up does
/// not say this machine approved it, and a knock is asked about afresh, so
/// pairing it again goes through the card again.
// LEDGER R184-19 | class B | 2 events over the real IPC socket + 6 struct state: Service::remove_authorized_key
#[test]
fn a_removal_drops_an_approval_waiting_for_its_number() {
    run_local(async {
        let (mut service, scratch) = daemon("rmap").await;
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
        service.raise_connection_attempt(
            peer.clone(),
            AttemptOrigin::OutboundDial,
            Some(peer_addr()),
        );
        service.handle_frontend_request(Some(Ok(FrontendRequest::AuthorizeKey {
            label: "desk b".into(),
            fingerprint: peer.clone(),
            controller: hops_ipc::Controller::Both,
            clipboard: true,
        })));
        assert!(
            service.trust.read().expect("lock").is_pairing(&peer),
            "precondition: the approval waits for its number: {:?}",
            notices(&sent(&mut service))
        );
        sent(&mut service);

        service
            .handle_frontend_request(Some(Ok(FrontendRequest::RemoveAuthorizedKey(peer.clone()))));
        {
            let trust = service.trust.read().expect("lock");
            assert!(
                !trust.is_known(&peer) && !trust.is_pairing(&peer),
                "the removal left the approval's lease, and the TLS doors still admit \
                 the machine"
            );
        }

        let mut frontend = attached(&mut service, &scratch).await;
        let started = service.adding.get_mut(&handle).expect("still adding");
        *started = a_window_before(*started);
        // The loop sets up capture for every device switched on as it starts,
        // and this one was switched on before it ran: undo that here.
        service.capture.destroy(handle);
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
                .is_some_and(|t| !t.contains("this machine approved")),
            "the add dial says this machine approved a pairing that was removed: \
             the approval outlived the removal: {gave_up:?}"
        );
        assert!(
            knock_until_asked(&mut service, &peer).await,
            "a knock after the removal was not asked about afresh"
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

/// One approval shows one number (#220). An attempt other than the one
/// whose number is on screen ending ends nothing: the pairing goes on there.
/// The one on screen ending ends the pairing, however its connection closed,
/// and forgets the approval, so a number arriving after it shows nothing.
// LEDGER G-23 | class B | 1 events the daemon sends + 1 the trust the TLS door consults: Service::handle_pairing_event
#[test]
fn one_approval_shows_one_number() {
    use crate::pairing::{PairingEvent, Role, Why};
    run_local(async {
        let (mut service, _scratch) = daemon("once").await;
        let peer = machine().fingerprint;
        approve(&mut service, &peer, AttemptOrigin::Inbound);
        let number = |service: &mut Service, attempt: u64| {
            service.handle_pairing_event(PairingEvent::Number {
                fingerprint: peer.clone(),
                addr: peer_addr(),
                role: Role::Pick,
                number: "042917".into(),
                handle: None,
                attempt,
            });
            sent(service)
        };
        let ended = |service: &mut Service, why: Why, attempt: u64| {
            service.handle_pairing_event(PairingEvent::Ended {
                fingerprint: peer.clone(),
                why,
                handle: None,
                attempt,
            });
            sent(service)
        };
        let card_down = |events: &[FrontendEvent]| {
            events.iter().any(|e| {
                matches!(e, FrontendEvent::PairingEnded { fingerprint, paired: false }
                    if *fingerprint == peer)
            })
        };
        let card_up = |events: &[FrontendEvent]| {
            events.iter().any(|e| {
                matches!(e, FrontendEvent::PairingCheck { fingerprint, .. }
                    if *fingerprint == peer)
            })
        };

        assert!(
            card_up(&number(&mut service, 1)),
            "the first number was not shown"
        );
        let events = ended(&mut service, Why::Closed, 2);
        assert!(
            !card_down(&events) && service.trust.read().expect("lock").is_pairing(&peer),
            "an attempt other than the one on screen ended the pairing: {events:?}"
        );

        let events = ended(&mut service, Why::Closed, 1);
        assert!(
            card_down(&events) && !service.trust.read().expect("lock").is_pairing(&peer),
            "the attempt on screen closing did not end the pairing and forget the \
             approval: {events:?}"
        );
        let events = number(&mut service, 3);
        assert!(
            !card_up(&events),
            "a second number was shown from one approval: {events:?}"
        );
        shut_down(service).await;
    });
}
