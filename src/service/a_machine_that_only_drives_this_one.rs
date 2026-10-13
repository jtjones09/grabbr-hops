//! A device for a machine paired to control this one, and not to be
//! controlled from it, has no edge here (#259). It keeps its card, its
//! position and its link; only capture leaves its edge alone, so the pointer
//! that machine moves here crosses back to it without this machine refusing
//! a crossing it never asked to make.
//!
//! Whole daemons in this process. Capture is scripted, and nothing answers
//! at any device's address. What is observed is what a user meets at an
//! edge: a crossing refused toward a device, which a frontend connected over
//! the IPC socket is told, or a crossing no device takes, which the backend
//! gives back at once.

use super::in_process::{DEADLINE, Daemon, Frontend, compare_number, prompt_from, until_paired};
use crate::test_harness::{approval, machine, run_local};
use crate::trust::{Caps, Expiry, Lease, Origin};
use hops_ipc::{ClientHandle, Controller, CrossingRefusal, FrontendEvent, FrontendRequest as R};
use input_capture::{CaptureEvent, Position, scripted::Script};
use std::time::Duration;

/// What a crossing at an edge met.
#[derive(Debug, PartialEq)]
enum Met {
    /// No device has an edge there: the pointer was given back, unclaimed.
    Unclaimed,
    /// Refused toward these devices, for these reasons.
    Refused(Vec<(ClientHandle, CrossingRefusal)>),
}

/// The refusals among `events`.
fn refusals(events: &[FrontendEvent]) -> Vec<(ClientHandle, CrossingRefusal)> {
    events
        .iter()
        .filter_map(|e| match e {
            FrontendEvent::CrossingRefused { handle, reason } => Some((*handle, *reason)),
            _ => None,
        })
        .collect()
}

/// Cross at `at` until the crossing meets something, and say what. Each
/// round asks the daemon for its devices too: an event its loop handles,
/// after which every edge is settled.
async fn crossing_at(app: &mut Frontend, script: &Script, at: Position) -> Met {
    let deadline = tokio::time::Instant::now() + DEADLINE;
    loop {
        let before = script.unclaimed_releases();
        script.push(at, CaptureEvent::Begin);
        let refused = refusals(&app.exchange(&[R::Enumerate()]).await);
        if !refused.is_empty() {
            return Met::Refused(refused);
        }
        if script.unclaimed_releases() > before {
            return Met::Unclaimed;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "a crossing at the {at:?} edge met nothing within {DEADLINE:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Cross at `at` until a crossing there is one no device takes. A crossing
/// refused meanwhile, while the edge is still being taken away, is not it.
async fn until_unclaimed_at(app: &mut Frontend, script: &Script, at: Position) {
    let deadline = tokio::time::Instant::now() + DEADLINE;
    loop {
        let before = script.unclaimed_releases();
        script.push(at, CaptureEvent::Begin);
        let _ = app.exchange(&[R::Enumerate()]).await;
        if script.unclaimed_releases() > before {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "a device kept its edge at {at:?} for {DEADLINE:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A switched-on device named `name` at `pos`, at a port nothing answers,
/// pinned to `fp` when there is one.
fn device(name: &str, pos: &str, fp: Option<&str>) -> String {
    let pin = fp.map_or_else(String::new, |fp| format!("fingerprint = \"{fp}\"\n"));
    format!(
        "[[clients]]\nhostname = \"{name}\"\nposition = \"{pos}\"\nips = [\"127.0.0.1\"]\n\
         port = 9\nactivate_on_startup = true\n{pin}\n"
    )
}

/// The device named `name`.
fn handle_of(clients: &crate::client::ClientManager, name: &str) -> ClientHandle {
    clients
        .get_client_states()
        .into_iter()
        .find(|(_, c, _)| c.hostname.as_deref() == Some(name))
        .map(|(h, _, _)| h)
        .expect("a configured device")
}

// LEDGER T259a | class B | 2 bytes (CrossingRefused over the IPC socket) + 6 struct state (Script::unclaimed_releases): Service::activate_client at start
/// The issue's own state: the desk pc on the left controls this machine
/// and is not controlled from it. It is listed, switched on, on the left,
/// and a crossing at the left edge is given back with nothing said. The
/// media rig, which each controls, and a device added and not yet paired
/// keep their edges: a crossing to either is refused, since nothing answers.
#[test]
fn a_machine_paired_only_to_control_this_one_has_no_edge_here() {
    run_local(async {
        let (pc, rig) = (machine(), machine());
        let script = Script::new();
        // The desk pc first, so its edge, had it one, is made before the
        // others, whose crossings show capture is up.
        let tables = [
            device("desk-pc", "left", Some(&pc.fingerprint)),
            device("media-rig", "right", Some(&rig.fingerprint)),
            device("new-laptop", "top", None),
        ]
        .concat();
        let daemon = Daemon::start_paired(
            "only-drives",
            &tables,
            &[
                (pc.fingerprint.as_str(), "desk pc", Caps::INBOUND),
                (rig.fingerprint.as_str(), "media rig", Caps::DRIVE),
            ],
            script.backend(),
            input_emulation::Backend::Dummy,
        )
        .await;
        let (ipc, clients) = (daemon.ipc(), daemon.clients());
        daemon
            .run_while(async move {
                let mut app = ipc.connect().await;
                let _ = app.exchange(&[R::Sync]).await;
                let (pc_h, rig_h, laptop_h) = (
                    handle_of(&clients, "desk-pc"),
                    handle_of(&clients, "media-rig"),
                    handle_of(&clients, "new-laptop"),
                );
                let met = [
                    crossing_at(&mut app, &script, Position::Right).await,
                    crossing_at(&mut app, &script, Position::Top).await,
                    crossing_at(&mut app, &script, Position::Left).await,
                ];
                assert_eq!(
                    met,
                    [
                        Met::Refused(vec![(rig_h, CrossingRefusal::NotConnected)]),
                        Met::Refused(vec![(laptop_h, CrossingRefusal::NotConnected)]),
                        Met::Unclaimed,
                    ],
                    "(right: the media rig {rig_h}, top: the new laptop {laptop_h}, left: \
                     the desk pc {pc_h}) as crossed to"
                );
                let pc_state = clients
                    .get_client_states()
                    .into_iter()
                    .find(|(h, _, _)| *h == pc_h)
                    .map(|(_, c, s)| (c.pos, s.active));
                assert_eq!(
                    pc_state,
                    Some((hops_ipc::Position::Left, true)),
                    "the desk pc lost its place or was switched off with its edge"
                );
            })
            .await;
    });
}

// LEDGER T259b | class B | 2 bytes (CrossingRefused over the IPC socket) + 6 struct state (Script::unclaimed_releases): Service::settle_edges
/// Each controls the other, so the desk pc has its edge. The direction that
/// lets this machine control it is withdrawn, and the edge goes; given
/// back, and the edge returns. The store is changed directly, as no verb
/// narrows a pairing to one direction; the daemon settles every edge after
/// each event it handles, which is where a change any door makes is seen.
#[test]
fn a_device_gains_and_loses_its_edge_with_the_direction_its_pairing_grants() {
    run_local(async {
        let pc = machine();
        let script = Script::new();
        let daemon = Daemon::start_paired(
            "edge-follows",
            &device("desk-pc", "left", Some(&pc.fingerprint)),
            &[(pc.fingerprint.as_str(), "desk pc", Caps::DRIVE)],
            script.backend(),
            input_emulation::Backend::Dummy,
        )
        .await;
        let (ipc, clients, trust) = (daemon.ipc(), daemon.clients(), daemon.trust());
        daemon
            .run_while(async move {
                let mut app = ipc.connect().await;
                let _ = app.exchange(&[R::Sync]).await;
                let pc_h = handle_of(&clients, "desk-pc");
                let both_ways = crossing_at(&mut app, &script, Position::Left).await;

                trust
                    .write()
                    .expect("lock")
                    .drop_capabilities(&pc.fingerprint, Caps::I_MAY_DRIVE);
                until_unclaimed_at(&mut app, &script, Position::Left).await;

                trust
                    .write()
                    .expect("lock")
                    .issue_confirmed(&pc.fingerprint, "desk pc", Caps::OUTBOUND)
                    .expect("the direction is granted again");
                let deadline = tokio::time::Instant::now() + DEADLINE;
                let again = loop {
                    match crossing_at(&mut app, &script, Position::Left).await {
                        Met::Unclaimed => {
                            assert!(
                                tokio::time::Instant::now() < deadline,
                                "the desk pc never had its edge back"
                            );
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                        refused => break refused,
                    }
                };
                assert_eq!(
                    (both_ways, again),
                    (
                        Met::Refused(vec![(pc_h, CrossingRefusal::NotConnected)]),
                        Met::Refused(vec![(pc_h, CrossingRefusal::NotConnected)]),
                    ),
                    "(before the direction was withdrawn, after it was granted again) \
                     crossing to the desk pc {pc_h}"
                );
            })
            .await;
    });
}

// LEDGER T259c | class B | 2 bytes (CrossingRefused over the IPC socket) + 6 struct state (Script::unclaimed_releases): AuthorizeKey and ConfirmPairing over the IPC socket, the peer comparing its number over loopback QUIC
/// A device added for the desk pc, pinned to it by the dial that reached
/// it and not paired yet, has its edge: crossing to it is how pairing it is
/// asked for. The desk pc
/// knocks, the person here answers that it controls this machine, the two
/// compare their number, and the edge is gone.
#[test]
fn pairing_a_device_as_the_machine_that_controls_this_one_takes_its_edge() {
    run_local(async {
        let pc = machine();
        let script = Script::new();
        let daemon = Daemon::start_capturing(
            "pair-takes",
            &device("desk-pc", "left", None),
            script.backend(),
            input_emulation::Backend::Dummy,
        )
        .await;
        let (ours, port, trust, ipc, clients) = (
            daemon.fingerprint(),
            daemon.port(),
            daemon.trust(),
            daemon.ipc(),
            daemon.clients(),
        );
        // Pinned as the add dial pins a device once it reaches the machine.
        // A pin in the config to a machine the store holds no record of is
        // dropped as the daemon starts, so it is set here instead.
        let pc_h = handle_of(&clients, "desk-pc");
        clients.set_peer_fingerprint(pc_h, Some(pc.fingerprint.clone()));
        daemon
            .run_while(async move {
                let mut app = ipc.connect().await;
                let _ = app.exchange(&[R::Sync]).await;
                let unpaired = crossing_at(&mut app, &script, Position::Left).await;
                assert_eq!(
                    unpaired,
                    Met::Refused(vec![(pc_h, CrossingRefusal::NotPermitted)]),
                    "the desk pc, added and not paired yet, had no edge to cross to"
                );

                app.exchange(&[R::OpenPairing]).await;
                prompt_from(&mut app, &pc, port, &ours).await;
                app.exchange(&[approval(
                    "desk pc",
                    &pc.fingerprint,
                    Controller::ThatMachine,
                )])
                .await;
                let comparing = compare_number(&mut app, &pc, port, &ours).await;
                app.exchange(&[R::ConfirmPairing {
                    fingerprint: pc.fingerprint.clone(),
                    number: comparing.number.clone(),
                }])
                .await;
                until_paired(&trust, &pc.fingerprint).await;
                assert_eq!(
                    trust.read().expect("lock").capabilities(&pc.fingerprint),
                    Caps::DRIVE_ME,
                    "precondition: the pairing lets the desk pc control this machine, only"
                );
                until_unclaimed_at(&mut app, &script, Position::Left).await;
            })
            .await;
    });
}

// LEDGER T259d | class B | 2 bytes (CrossingRefused and its reason over the IPC socket): Service::wants_edge on a lapsed lease
/// The media rig was paired for this machine to control, and the lease
/// lapsed. It keeps its edge, and crossing to it says this machine may no
/// longer control it: it was allowed to, and is not now.
#[test]
fn a_machine_this_one_may_no_longer_control_keeps_its_edge_and_says_so() {
    run_local(async {
        let rig = machine();
        let script = Script::new();
        let daemon = Daemon::start_capturing(
            "lapsed-edge",
            &device("media-rig", "right", None),
            script.backend(),
            input_emulation::Backend::Dummy,
        )
        .await;
        let (ours, ipc, clients, trust) = (
            daemon.fingerprint(),
            daemon.ipc(),
            daemon.clients(),
            daemon.trust(),
        );
        {
            let mut store = trust.write().expect("lock");
            let now = store.now();
            store
                .admit(Lease {
                    peer: rig.fingerprint.clone(),
                    issued_to: ours,
                    label: "media rig".into(),
                    caps: Caps::OUTBOUND,
                    origin: Origin::OutboundDial,
                    issued_at: now - 120,
                    expiry: Expiry::At(now - 60),
                    clipboard_chosen: false,
                    confirmed: true,
                })
                .expect("a lapsed lease");
            assert!(
                !store.we_may_drive(&rig.fingerprint),
                "precondition: the lease has lapsed"
            );
        }
        // Pinned once the store holds the lease, as a daemon that loaded both
        // finds it: a pin to a machine the store did not know as it started
        // was dropped.
        clients.set_peer_fingerprint(
            handle_of(&clients, "media-rig"),
            Some(rig.fingerprint.clone()),
        );
        daemon
            .run_while(async move {
                let mut app = ipc.connect().await;
                let _ = app.exchange(&[R::Sync]).await;
                let rig_h = handle_of(&clients, "media-rig");
                assert_eq!(
                    crossing_at(&mut app, &script, Position::Right).await,
                    Met::Refused(vec![(rig_h, CrossingRefusal::NotPermitted)]),
                    "crossing to the media rig {rig_h}, whose lease lapsed"
                );
            })
            .await;
    });
}
