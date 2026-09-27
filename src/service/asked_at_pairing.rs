//! What the person approving a pairing answers, observed on a whole daemon
//! run in this process: which way control goes (#220), and whether the two
//! machines share a clipboard (#182). A peer knocks while add device is open,
//! the app approves it with the card's answers, the two compare their number,
//! and what the daemon's own store then grants, and what its listener lets
//! the peer do, is read.

use super::in_process::{DEADLINE, Daemon, compare_number, prompt_from, trusting, until_paired};
use crate::test_harness::{NEVER_WITHIN, approval, dialer, machine, run_local};
use crate::trust::{Caps, Origin};
use hops_ipc::{Controller, FrontendRequest as R, Position};
use hops_proto::ProtoEvent;
use input_emulation::recording::{Recorded, Recording};
use input_event::{Event, PointerEvent};

// LEDGER E2b-1 | class B | 3 process-in-test + 1 struct state: AuthorizeKey and ConfirmPairing over the daemon's IPC socket, peers comparing their number over loopback QUIC, the daemon's trust store
/// A pairing shares no clipboard until the person approving it says yes,
/// and a yes shares it only the way control goes (#182).
#[test]
fn a_new_pairing_shares_no_clipboard_unless_someone_said_yes() {
    run_local(async {
        let (quiet, sharing) = (machine(), machine());
        let recording = Recording::new();
        let daemon = Daemon::start("clip", "", recording.backend()).await;
        let (ours, port, trust, ipc) = (
            daemon.fingerprint(),
            daemon.port(),
            daemon.trust(),
            daemon.ipc(),
        );
        daemon
            .run_while(async {
                let mut app = ipc.connect().await;
                app.exchange(&[R::OpenPairing]).await;
                for (peer, yes) in [(&quiet, false), (&sharing, true)] {
                    let fp = peer.fingerprint.clone();
                    prompt_from(&mut app, peer, port, &ours).await;
                    app.exchange(&[R::AuthorizeKey {
                        label: "desk".into(),
                        fingerprint: fp.clone(),
                        controller: Controller::ThatMachine,
                        clipboard: yes,
                    }])
                    .await;
                    let comparing = compare_number(&mut app, peer, port, &ours).await;
                    app.exchange(&[R::ConfirmPairing {
                        fingerprint: fp.clone(),
                        number: comparing.number.clone(),
                    }])
                    .await;
                    until_paired(&trust, &fp).await;
                }
                let t = trust.read().expect("lock");
                assert_eq!(
                    t.capabilities(&quiet.fingerprint),
                    Caps::DRIVE_ME,
                    "a pairing nobody said yes to the clipboard for shares it"
                );
                assert_eq!(
                    t.capabilities(&sharing.fingerprint),
                    Caps::DRIVE_ME | Caps::CLIPBOARD_FROM,
                    "a yes to the clipboard did not share it the way control goes, and \
                     only that way"
                );
            })
            .await;
    });
}

// LEDGER E2b-2 | class B | 3 process-in-test + 1 struct state + 1 injected events: AuthorizeKey over the daemon's IPC socket, a peer knocking and then trying to drive over loopback QUIC, the daemon's store and its recording emulation backend
/// A machine that knocked here is paired in the direction the person here
/// chose, and in no other (#220). Chosen as the machine this one controls,
/// it gains nothing over this machine: its input is not injected.
#[test]
fn a_direction_nobody_chose_is_never_granted() {
    run_local(async {
        let (driven, both) = (machine(), machine());
        let recording = Recording::new();
        let daemon = Daemon::start("dir", "", recording.backend()).await;
        let (ours, port, trust, ipc) = (
            daemon.fingerprint(),
            daemon.port(),
            daemon.trust(),
            daemon.ipc(),
        );
        daemon
            .run_while(async {
                let mut app = ipc.connect().await;
                app.exchange(&[R::OpenPairing]).await;
                for (peer, controller) in [
                    (&driven, Controller::ThisMachine),
                    (&both, Controller::Both),
                ] {
                    let fp = peer.fingerprint.clone();
                    prompt_from(&mut app, peer, port, &ours).await;
                    app.exchange(&[approval("peer", &fp, controller)]).await;
                    let comparing = compare_number(&mut app, peer, port, &ours).await;
                    app.exchange(&[R::ConfirmPairing {
                        fingerprint: fp.clone(),
                        number: comparing.number.clone(),
                    }])
                    .await;
                    until_paired(&trust, &fp).await;
                }
                {
                    let t = trust.read().expect("lock");
                    assert_eq!(
                        (
                            t.capabilities(&driven.fingerprint),
                            t.lease(&driven.fingerprint).map(|l| l.origin)
                        ),
                        (
                            Caps::I_MAY_DRIVE,
                            Some(Origin::Chosen(Controller::ThisMachine))
                        ),
                        "the machine that knocked, chosen as the one this machine \
                         controls, was granted something else, or the choice was not \
                         recorded as the lease's origin"
                    );
                    assert_eq!(
                        t.capabilities(&both.fingerprint),
                        Caps::DRIVE_ME | Caps::I_MAY_DRIVE,
                        "each controlling the other was not granted both ways"
                    );
                }

                // The machine chosen to control this one does: the pointer
                // moves, so the check below could see it move.
                let driver = dialer(&both, trusting(&both, &ours), port, Position::Left);
                driver.until_alive().await;
                let moved = Event::Pointer(PointerEvent::Motion {
                    time: 0,
                    dx: 2.0,
                    dy: 0.0,
                });
                let driving = async {
                    loop {
                        driver
                            .send(ProtoEvent::Enter(hops_proto::Position::Right))
                            .await;
                        driver.send(ProtoEvent::Input(moved)).await;
                        tokio::time::sleep(NEVER_WITHIN / 4).await;
                    }
                };
                let seen = crate::test_harness::wait_until("the pointer moves", DEADLINE, || {
                    recording
                        .calls()
                        .iter()
                        .any(|c| matches!(c, Recorded::Consume(e, _) if *e == moved))
                });
                tokio::select! {
                    () = driving => unreachable!("the driver stops only with the test"),
                    () = seen => {}
                }
                driver.send(ProtoEvent::Leave(0)).await;

                // The machine this one controls tries to drive it anyway.
                let intruder = dialer(&driven, trusting(&driven, &ours), port, Position::Left);
                let motion = Event::Pointer(PointerEvent::Motion {
                    time: 0,
                    dx: 1.0,
                    dy: 0.0,
                });
                let deadline = tokio::time::Instant::now() + NEVER_WITHIN * 4;
                while tokio::time::Instant::now() < deadline {
                    // Each send dials again while no link is up.
                    let _ = intruder
                        .conn
                        .send(
                            ProtoEvent::Enter(hops_proto::Position::Right),
                            intruder.handle,
                        )
                        .await;
                    let _ = intruder
                        .conn
                        .send(ProtoEvent::Input(motion), intruder.handle)
                        .await;
                    tokio::time::sleep(NEVER_WITHIN / 4).await;
                }
                assert!(
                    !recording
                        .calls()
                        .iter()
                        .any(|c| matches!(c, Recorded::Consume(e, _) if *e == motion)),
                    "a machine paired as the one this machine controls moved this \
                     machine's pointer: it was granted a direction nobody chose"
                );
            })
            .await;
    });
}
