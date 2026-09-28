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
use input_event::{Event, KeyboardEvent, PointerEvent};
use std::time::Duration;

/// An app's events not yet looked at, oldest first. Every event an
/// exchange returns is kept, and a wait takes only up to the one it wanted,
/// so no wait misses an event an earlier exchange or wait already read.
struct Heard {
    app: Frontend,
    backlog: std::collections::VecDeque<FrontendEvent>,
}

impl Heard {
    fn new(app: Frontend) -> Self {
        Self {
            app,
            backlog: Default::default(),
        }
    }

    /// Send `requests`, keeping every event they caused.
    async fn exchange(&mut self, requests: &[FrontendRequest]) {
        let events = self.app.exchange(requests).await;
        self.backlog.extend(events);
    }

    /// The first event `pick` makes something of, from those kept and then
    /// those still to come; panic naming `what` if none does in time.
    async fn until<T>(
        &mut self,
        what: &str,
        mut pick: impl FnMut(&FrontendEvent) -> Option<T>,
    ) -> T {
        let deadline = tokio::time::Instant::now() + DEADLINE;
        let mut seen = Vec::new();
        loop {
            while let Some(event) = self.backlog.pop_front() {
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
            self.exchange(&[]).await;
        }
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

fn motion(dx: f64) -> CaptureEvent {
    CaptureEvent::Input(Event::Pointer(PointerEvent::Motion {
        time: 0,
        dx,
        dy: 0.0,
    }))
}

/// How far each motion the recording injected moved, across.
fn motions(recording: &Recording) -> Vec<f64> {
    recording
        .calls()
        .iter()
        .filter_map(|c| match c {
            Recorded::Consume(Event::Pointer(PointerEvent::Motion { dx, .. }), _) => Some(*dx),
            _ => None,
        })
        .collect()
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
            let mut on_pc_app = Heard::new(pc_ipc.connect().await);
            let (handle, pos) = on_pc_app
                .until(
                    "a live device on the pc for the mac that dialled it",
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
            on_pc_app
                .until(
                    "the link closing once the mac switched the pc off",
                    |e| match e {
                        FrontendEvent::State(h, _, s)
                            if *h == handle && s.active_addr.is_none() =>
                        {
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

/// The mac's device for the pc, as the mac's app lists it.
async fn device_for(app: &mut Frontend, fp: &str) -> ClientHandle {
    app.exchange(&[FrontendRequest::Enumerate()])
        .await
        .into_iter()
        .find_map(|e| match e {
            FrontendEvent::Enumerate(all) => all
                .into_iter()
                .find(|(_, _, s)| s.peer_fingerprint.as_deref() == Some(fp))
                .map(|(h, _, _)| h),
            _ => None,
        })
        .expect("the mac's device for the pc")
}

// LEDGER T30 | class B | 6 struct state: Recording::calls() on the dialling daemon and Script::held() on the controlling one, two whole daemons in-process
/// The link the mac dialled drops while the pc's pointer is on the mac,
/// as it does when the mac sleeps or its network reconnects, and the mac
/// dials again. The crossing was acknowledged on the old link; the new one
/// has crossed nothing, so the mac drops what arrives on it until an Enter
/// does. The pc's next input either lands on the mac, the crossing made
/// again over the new link, or the pc gets its pointer back. It is never
/// held with everything typed on it thrown away. A crossing made again
/// moves the mac's pointer by what the pc moves after it, not by what it
/// moved before the link dropped.
#[test]
fn a_redial_while_the_pointer_is_across_lands_its_input_or_gives_it_back() {
    run_local(async {
        let (pc_script, mac_script) = (Script::new(), Script::new());
        let (on_pc, on_mac) = (Recording::new(), Recording::new());
        let pc = Daemon::start_capturing("rd-pc", "", pc_script.backend(), on_pc.backend()).await;
        let (pc_fp, pc_port, pc_trust, pc_ipc) =
            (pc.fingerprint(), pc.port(), pc.trust(), pc.ipc());
        let mac = Daemon::start_capturing(
            "rd-mac",
            &dials_out_to(&pc_fp, pc_port),
            mac_script.backend(),
            on_mac.backend(),
        )
        .await;
        let (mac_fp, mac_trust, mac_ipc) = (mac.fingerprint(), mac.trust(), mac.ipc());
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
            let mut on_pc_app = Heard::new(pc_ipc.connect().await);
            let live = |e: &FrontendEvent| match e {
                FrontendEvent::State(h, c, s) | FrontendEvent::Created(h, c, s)
                    if s.peer_fingerprint.as_deref() == Some(mac_fp.as_str())
                        && s.active_addr.is_some()
                        && s.alive =>
                {
                    Some((*h, c.pos))
                }
                _ => None,
            };
            let (handle, pos) = on_pc_app.until("the mac's link", live).await;
            let pos = capture_pos(pos);
            let deadline = tokio::time::Instant::now() + DEADLINE;
            while !consumed(&on_mac, 30) {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "precondition: the pc's key never reached the mac: {:?}",
                    on_mac.calls()
                );
                pc_script.push(pos, CaptureEvent::Begin);
                pc_script.push(pos, key(30));
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            // Far across the mac, so a crossing made again from where this
            // one left off would show as a jump.
            while motions(&on_mac).is_empty() {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "precondition: the pc's motion never reached the mac: {:?}",
                    on_mac.calls()
                );
                pc_script.push(pos, motion(400.0));
                tokio::time::sleep(Duration::from_millis(50)).await;
            }

            // The mac's link drops and the mac dials again. The pc hears
            // only that the link closed and that another was dialled in.
            let mut on_mac_app = mac_ipc.connect().await;
            let pc_on_mac = device_for(&mut on_mac_app, &pc_fp).await;
            on_mac_app
                .exchange(&[FrontendRequest::Activate(pc_on_mac, false)])
                .await;
            on_pc_app
                .until("the link closing", |e| match e {
                    FrontendEvent::State(h, _, s) if *h == handle && s.active_addr.is_none() => {
                        Some(())
                    }
                    _ => None,
                })
                .await;
            on_mac_app
                .exchange(&[FrontendRequest::Activate(pc_on_mac, true)])
                .await;
            on_pc_app.until("the mac's link again", live).await;
            assert!(
                pc_script.held(),
                "precondition: the pc let go of the pointer when the link dropped"
            );

            // Only input now, as a person typing on the pc: the pointer is
            // held, so the backend yields no new Begin.
            let deadline = tokio::time::Instant::now() + DEADLINE;
            while !consumed(&on_mac, 31) && pc_script.held() {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "after the mac dialled again the pc still holds the pointer, and none of \
                     its input reached the mac: {:?}",
                    on_mac.calls()
                );
                pc_script.push(pos, key(31));
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            if !consumed(&on_mac, 31) {
                return;
            }

            // Made again, the crossing moves the mac's pointer from where the
            // mac anchors it on the new Enter, by what the pc moves now.
            let before = motions(&on_mac).len();
            let deadline = tokio::time::Instant::now() + DEADLINE;
            while motions(&on_mac).len() == before {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "motion after the crossing was made again never reached the mac"
                );
                pc_script.push(pos, motion(3.0));
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let after = motions(&on_mac).split_off(before);
            assert!(
                after.iter().all(|dx| dx.abs() <= 10.0),
                "the mac's pointer jumped by what the pc moved before the link dropped: {after:?}"
            );
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
            let mut app = Heard::new(pc_ipc.connect().await);
            let up = |e: &FrontendEvent| match e {
                FrontendEvent::State(h, _, s) | FrontendEvent::Created(h, _, s)
                    if s.peer_fingerprint.as_deref() == Some(mac_fp.as_str())
                        && s.active_addr.is_some() =>
                {
                    Some(*h)
                }
                _ => None,
            };
            let handle = app.until("the mac's link", up).await;

            app.exchange(&[R::Activate(handle, false)]).await;
            let waiting = app
                .until("the link closing", |e| match e {
                    FrontendEvent::State(h, _, s) if *h == handle && s.active_addr.is_none() => {
                        Some(s.dials_us)
                    }
                    _ => None,
                })
                .await;
            assert!(
                waiting,
                "the pc's card for the mac does not say the mac dials it"
            );

            app.exchange(&[R::Activate(handle, true)]).await;
            let again = app.until("the mac's link again", up).await;
            assert_eq!(again, handle, "the mac's link went to another device");
        };
        pc.run_while(mac.run_while(body)).await;
    });
}

// LEDGER T32 | class B | 2 bytes: FrontendEvent::Enumerate and Error over the dialling daemon's IPC socket
/// The mac dials the pc's address and something that holds no key of the
/// pc's answers there, refusing with the alert the pc refuses a removed
/// machine with. The mac's card does not say the pc removed it, and the
/// person is not told to remove the pc: nothing proved the pc refused.
#[test]
fn a_keyless_endpoint_at_the_controllers_address_does_not_say_it_removed_this_machine() {
    run_local(async {
        let pc = crate::test_harness::machine();
        let (_keyless, port, answered) = crate::test_harness::keyless_listener();
        let mac = Daemon::start(
            "keyless-mac",
            &dials_out_to(&pc.fingerprint, port),
            input_emulation::Backend::Dummy,
        )
        .await;
        let mac_ipc = mac.ipc();
        let body = async {
            let mut app = Heard::new(mac_ipc.connect().await);
            let deadline = tokio::time::Instant::now() + DEADLINE;
            // Two dials, each from a socket of its own: the first one's
            // refusal reached the service a retry's wait before the second
            // began.
            while answered.borrow().len() < 2 {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "precondition: the mac never dialled the pc's address twice"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            // The answer to this Enumerate, not the one sent on connecting.
            app.exchange(&[FrontendRequest::Enumerate()]).await;
            let cards = app
                .backlog
                .iter()
                .rev()
                .find_map(|e| match e {
                    FrontendEvent::Enumerate(all) => Some(all.clone()),
                    _ => None,
                })
                .expect("the mac's devices");
            let removed: Vec<_> = cards
                .iter()
                .filter(|(_, _, s)| s.peer_fingerprint.as_deref() == Some(pc.fingerprint.as_str()))
                .map(|(_, _, s)| s.removed_by_peer)
                .collect();
            assert_eq!(
                removed,
                vec![false],
                "the mac's card for the pc says the pc removed it, on a refusal from a machine \
                 with no key"
            );
            let told: Vec<_> = app
                .backlog
                .iter()
                .filter(|e| matches!(e, FrontendEvent::Error(m) if m.contains("no longer trusts")))
                .collect();
            assert!(told.is_empty(), "the person was told: {told:?}");
        };
        mac.run_while(body).await;
    });
}
