//! The controlled machine dials the machine that controls it (#15).
//!
//! Whole daemons in this process, each with its own scratch directory, on
//! loopback, reached the way an app reaches them. The controlled machine is
//! set to only dial out, as a machine behind a client that drops unsolicited
//! inbound connections is. The controlling machine captures from a scripted
//! backend; each injects into a recording one.

use super::in_process::{DEADLINE, Daemon, Frontend};
use crate::test_harness::{NEVER_WITHIN, run_local};
use crate::trust::Caps;
use hops_ipc::{ClientHandle, FrontendEvent, FrontendRequest};
use input_capture::{CaptureEvent, Position, scripted::Script};
use input_emulation::recording::{Recorded, Recording};
use input_event::{Event, KeyboardEvent};
use std::time::Duration;

/// Ask `app` for nothing until an event `pick` makes something of arrives,
/// running `nudge` between asks; panic naming `what` if none does in time.
async fn until<T>(
    app: &mut Frontend,
    what: &str,
    mut nudge: impl FnMut(),
    mut pick: impl FnMut(&FrontendEvent) -> Option<T>,
) -> T {
    let deadline = tokio::time::Instant::now() + DEADLINE;
    let mut seen = Vec::new();
    loop {
        nudge();
        for event in app.exchange(&[]).await {
            if let Some(found) = pick(&event) {
                return found;
            }
            seen.push(event);
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what} did not happen within {DEADLINE:?}; the app was told {seen:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn key(key: u32) -> CaptureEvent {
    CaptureEvent::Input(Event::Keyboard(KeyboardEvent::Key {
        time: 0,
        key,
        state: 1,
    }))
}

fn consumed(recording: &Recording, key: u32) -> bool {
    recording.calls().iter().any(|c| {
        matches!(c, Recorded::Consume(Event::Keyboard(KeyboardEvent::Key { key: k, .. }), _)
            if *k == key)
    })
}

fn capture_pos(pos: hops_ipc::Position) -> Position {
    match pos {
        hops_ipc::Position::Left => Position::Left,
        hops_ipc::Position::Right => Position::Right,
        hops_ipc::Position::Top => Position::Top,
        hops_ipc::Position::Bottom => Position::Bottom,
    }
}

/// The controlled machine's config: it only dials out, and holds a device
/// for the controlling machine at `port` on loopback, pinned to `fp`, which
/// it may drive and which may drive it, as a pairing made before v0.13
/// migrates to.
fn dials_out_to(fp: &str, port: u16) -> String {
    format!(
        "listen = false\n\n[authorized_fingerprints]\n\"{fp}\" = \"desk pc\"\n\n\
         [[clients]]\nposition = \"left\"\nips = [\"127.0.0.1\"]\nport = {port}\n\
         activate_on_startup = true\nfingerprint = \"{fp}\"\n"
    )
}

// LEDGER T1 | class B | 6 struct state: Recording::calls() on the dialling daemon, two whole daemons in-process
// LEDGER T3 | class B | 6 struct state: Recording::calls() on the controlling daemon (same test); an absence over NEVER_WITHIN, a regression check only
// LEDGER T16 | class B | 2 bytes: FrontendEvent::State over the controlling daemon's IPC socket, after an Activate on the dialling daemon's (same test)
/// The desk mac only dials out, and chose the desk pc to control it. It
/// dials the desk pc, which gains a device for it keyed by its fingerprint,
/// and the desk pc's keyboard types on the desk mac over the link the mac
/// opened. Nothing flows the other way: the mac crossing to the pc drives
/// nothing there. Switched off on the mac, the pc's device there closes the
/// link the mac holds to it (#218).
#[test]
fn the_controlled_machine_dials_out_and_is_driven_over_its_own_link() {
    run_local(async {
        let (pc_script, mac_script) = (Script::new(), Script::new());
        let (on_pc, on_mac) = (Recording::new(), Recording::new());
        let pc = Daemon::start_capturing("rv-pc", "", pc_script.backend(), on_pc.backend()).await;
        let (pc_fp, pc_port, pc_trust, pc_ipc) =
            (pc.fingerprint(), pc.port(), pc.trust(), pc.ipc());
        let mac = Daemon::start_capturing(
            "rv-mac",
            &dials_out_to(&pc_fp, pc_port),
            mac_script.backend(),
            on_mac.backend(),
        )
        .await;
        let (mac_fp, mac_trust, mac_ipc) = (mac.fingerprint(), mac.trust(), mac.ipc());
        // The pc controls the mac, and not the other way round.
        mac_trust
            .write()
            .expect("lock")
            .drop_capabilities(&pc_fp, Caps::I_MAY_DRIVE);
        pc_trust
            .write()
            .expect("lock")
            .issue_confirmed(&mac_fp, "desk mac", Caps::OUTBOUND)
            .expect("issue");

        let body = async {
            let mut on_pc_app = pc_ipc.connect().await;
            let (handle, pos) = until(
                &mut on_pc_app,
                "a live device on the pc for the mac that dialled it",
                || {},
                |e| match e {
                    FrontendEvent::State(h, c, s) | FrontendEvent::Created(h, c, s)
                        if s.peer_fingerprint.as_deref() == Some(mac_fp.as_str())
                            && s.active_addr.is_some()
                            && s.alive =>
                    {
                        Some((*h, c.pos))
                    }
                    _ => None,
                },
            )
            .await;
            let _: ClientHandle = handle;

            let pos = capture_pos(pos);
            let deadline = tokio::time::Instant::now() + DEADLINE;
            while !consumed(&on_mac, 30) {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the pc's key never reached the mac over the link the mac dialled: {:?}",
                    on_mac.calls()
                );
                pc_script.push(pos, CaptureEvent::Begin);
                pc_script.push(pos, key(30));
                tokio::time::sleep(Duration::from_millis(50)).await;
            }

            // The wrong way: the mac may not drive the pc.
            mac_script.push(Position::Left, CaptureEvent::Begin);
            mac_script.push(Position::Left, key(48));
            tokio::time::sleep(NEVER_WITHIN).await;
            assert!(
                on_pc.calls().is_empty(),
                "the controlled mac drove the pc over the link it dialled: {:?}",
                on_pc.calls()
            );

            // Off means off on the dialling end too: the mac switches its
            // device for the pc off, and the link it holds to the pc closes.
            let mut on_mac_app = mac_ipc.connect().await;
            let pc_on_mac = on_mac_app
                .exchange(&[FrontendRequest::Enumerate()])
                .await
                .into_iter()
                .find_map(|e| match e {
                    FrontendEvent::Enumerate(all) => all
                        .into_iter()
                        .find(|(_, _, s)| s.peer_fingerprint.as_deref() == Some(pc_fp.as_str()))
                        .map(|(h, _, _)| h),
                    _ => None,
                })
                .expect("the mac's device for the pc");
            on_mac_app
                .exchange(&[FrontendRequest::Activate(pc_on_mac, false)])
                .await;
            until(
                &mut on_pc_app,
                "the link closing once the mac switched the pc off",
                || {},
                |e| match e {
                    FrontendEvent::State(h, _, s) if *h == handle && s.active_addr.is_none() => {
                        Some(())
                    }
                    _ => None,
                },
            )
            .await;
        };
        pc.run_while(mac.run_while(body)).await;
    });
}

// LEDGER T2 | class B | 1 return value: UdpSocket::bind on the daemon's port while Service::run runs
/// A machine set to only dial out binds nothing: its port is free while it
/// runs, so no host can reach a handshake on it.
#[test]
fn a_machine_that_only_dials_out_binds_no_port() {
    run_local(async {
        let listening = Daemon::start("bind-on", "", input_emulation::Backend::Dummy).await;
        let quiet = Daemon::start(
            "bind-off",
            "listen = false\n",
            input_emulation::Backend::Dummy,
        )
        .await;
        let (on_port, off_port) = (listening.port(), quiet.port());
        let body = async {
            assert!(
                std::net::UdpSocket::bind(("127.0.0.1", on_port)).is_err(),
                "precondition: a daemon that listens holds its port"
            );
            assert!(
                std::net::UdpSocket::bind(("127.0.0.1", off_port)).is_ok(),
                "a daemon set to only dial out bound its port"
            );
        };
        listening.run_while(quiet.run_while(body)).await;
    });
}

// LEDGER T4 | class B | 2 bytes: FrontendEvent::State over the controlling daemon's IPC socket
/// The link is the controlled machine's to keep up, and a machine that
/// only dials out keeps one to each machine that may drive it, even one it
/// may drive too. Switched off on the pc, the link closes and the pc's
/// card waits for the mac to dial; switched on again, the mac's next dial
/// is taken. That a device switched off turns the dials away is pinned by
/// `a_device_switched_off_takes_no_link_its_machine_dials`.
#[test]
fn the_controlled_machine_dials_again_until_its_link_is_taken() {
    run_local(async {
        let pc = Daemon::start("again-pc", "", input_emulation::Backend::Dummy).await;
        let (pc_fp, pc_port, pc_trust, pc_ipc) =
            (pc.fingerprint(), pc.port(), pc.trust(), pc.ipc());
        let mac = Daemon::start(
            "again-mac",
            &dials_out_to(&pc_fp, pc_port),
            input_emulation::Backend::Dummy,
        )
        .await;
        // Each controls the other, as the mac's migrated pairing says: a
        // machine that only dials out dials this one too, since nothing can
        // dial it.
        let mac_fp = mac.fingerprint();
        pc_trust
            .write()
            .expect("lock")
            .issue_confirmed(&mac_fp, "desk mac", Caps::OUTBOUND)
            .expect("issue");

        let body = async {
            use FrontendRequest as R;
            let mut app = pc_ipc.connect().await;
            let up = |e: &FrontendEvent| match e {
                FrontendEvent::State(h, _, s) | FrontendEvent::Created(h, _, s)
                    if s.peer_fingerprint.as_deref() == Some(mac_fp.as_str())
                        && s.active_addr.is_some() =>
                {
                    Some(*h)
                }
                _ => None,
            };
            let handle = until(&mut app, "the mac's link", || {}, up).await;

            let closing = |e: &FrontendEvent| match e {
                FrontendEvent::State(h, _, s) if *h == handle && s.active_addr.is_none() => {
                    Some(s.dials_us)
                }
                _ => None,
            };
            // The state that says the link closed can come back with the
            // request that switched the device off, so look there first.
            let answered = app.exchange(&[R::Activate(handle, false)]).await;
            let waiting = match answered.iter().find_map(closing) {
                Some(waiting) => waiting,
                None => until(&mut app, "the link closing", || {}, closing).await,
            };
            assert!(
                waiting,
                "the pc's card for the mac does not say the mac dials it"
            );

            app.exchange(&[R::Activate(handle, true)]).await;
            let again = until(&mut app, "the mac's link again", || {}, up).await;
            assert_eq!(again, handle, "the mac's link went to another device");
        };
        pc.run_while(mac.run_while(body)).await;
    });
}
