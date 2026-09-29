//! The whole daemon keeps its machine awake only while a paired device may
//! control it, and lets it sleep otherwise. Every Mac running hops used to
//! hold its power assertion for the life of the daemon, paired or not.
//!
//! The assertion is watched through the recording seam; every change is
//! made the way the app or a pairing makes it. The daemon answers the app
//! only after settling the assertion for every request before, so an empty
//! exchange is a barrier and each check waits on the daemon, not a clock.

use super::in_process::{DEADLINE, Daemon, Frontend, trusting};
use crate::keep_awake::recording::{Recording, Seen};
use crate::test_harness::{NEVER_WITHIN, dialer, machine, run_local, wait_until};
use crate::trust::Caps;
use hops_ipc::{FrontendEvent, FrontendRequest as R, Position};
use hops_proto::ProtoEvent;
use input_emulation::recording::{Recorded, Recording as Emulation};
use input_event::{Event, PointerEvent};
use std::rc::Rc;

/// `(held, takes, releases)` once the daemon has handled everything sent.
async fn settled(app: &mut Frontend, seen: &Seen) -> (bool, u32, u32) {
    app.exchange(&[]).await;
    seen.get()
}

// LEDGER KA-5 | class B | 2 PowerAssertion calls made by a running daemon, driven over its IPC socket
/// The desk mac pairs with a pc, first only to control it, then to be
/// controlled by it, and the pc is then removed from the mac's app.
#[test]
fn a_mac_is_kept_awake_only_while_a_machine_that_may_control_it_is_paired() {
    run_local(async {
        let mut mac = Daemon::start("awake-mac", "", input_emulation::Backend::Dummy).await;
        let seen = Rc::new(Seen::default());
        mac.keep_awake_through(Box::new(Recording(seen.clone())));
        let (trust, ipc) = (mac.trust(), mac.ipc());
        let pc = machine();

        let body = async {
            let mut app = ipc.connect().await;
            assert_eq!(
                settled(&mut app, &seen).await,
                (false, 0, 0),
                "(held, takes, releases) with nothing paired"
            );

            trust
                .write()
                .expect("lock")
                .issue_confirmed(&pc.fingerprint, "desk pc", Caps::OUTBOUND)
                .expect("issue");
            assert_eq!(
                settled(&mut app, &seen).await,
                (false, 0, 0),
                "(held, takes, releases) paired only to control the pc"
            );

            trust
                .write()
                .expect("lock")
                .issue_confirmed(&pc.fingerprint, "desk pc", Caps::DRIVE)
                .expect("issue");
            assert_eq!(
                settled(&mut app, &seen).await,
                (true, 1, 0),
                "(held, takes, releases) once the pc may control the mac"
            );

            app.exchange(&[R::RemoveAuthorizedKey(pc.fingerprint.clone())])
                .await;
            assert_eq!(
                settled(&mut app, &seen).await,
                (false, 1, 1),
                "(held, takes, releases) once the pc was removed"
            );
        };
        mac.run_while(body).await;
    });
}

/// The mac's config, as an older build wrote it: the pc paired, and a
/// device for it pinned to it and switched on. The first start moves the
/// pairing into the store, both ways.
fn device_for(fp: &str) -> String {
    format!(
        "[authorized_fingerprints]\n\"{fp}\" = \"desk pc\"\n\n\
         [[clients]]\nposition = \"left\"\nips = [\"127.0.0.1\"]\nport = 9\n\
         activate_on_startup = true\nfingerprint = \"{fp}\"\n"
    )
}

// LEDGER KA-6 | class B | 3 PowerAssertion calls made by a running daemon driven over its IPC socket, a peer driving it over loopback QUIC, its recording emulation backend
/// A pc paired with the mac from its start keeps the mac awake with its
/// device switched off here, because it still controls the mac over a link
/// it opens (#218); a lease that stops granting control lets it sleep.
#[test]
fn a_controlling_machine_switched_off_still_keeps_the_mac_awake() {
    run_local(async {
        let pc = machine();
        let emulation = Emulation::new();
        let mut mac = Daemon::start(
            "awake-off-mac",
            &device_for(&pc.fingerprint),
            emulation.backend(),
        )
        .await;
        let seen = Rc::new(Seen::default());
        mac.keep_awake_through(Box::new(Recording(seen.clone())));
        let (ours, port, trust, ipc) = (mac.fingerprint(), mac.port(), mac.trust(), mac.ipc());
        assert!(
            trust.read().expect("lock").may_drive_us(&pc.fingerprint),
            "precondition: the migrated pairing lets the pc control the mac"
        );

        let body = async {
            let mut app = ipc.connect().await;
            assert_eq!(
                settled(&mut app, &seen).await,
                (true, 1, 0),
                "(held, takes, releases) with the pc paired and switched on"
            );
            let handle = app
                .exchange(&[R::Enumerate()])
                .await
                .into_iter()
                .find_map(|e| match e {
                    FrontendEvent::Enumerate(all) => all
                        .into_iter()
                        .find(|(_, _, s)| {
                            s.peer_fingerprint.as_deref() == Some(pc.fingerprint.as_str())
                        })
                        .map(|(h, _, _)| h),
                    _ => None,
                })
                .expect("the mac's device for the pc");

            app.exchange(&[R::Activate(handle, false)]).await;
            assert_eq!(
                settled(&mut app, &seen).await,
                (true, 1, 0),
                "(held, takes, releases) once the pc was switched off, while it may \
                 still control the mac"
            );

            // Switched off here, the pc still moves the mac's pointer over a
            // link it opens: the mac must still be awake to answer it.
            let driver = dialer(&pc, trusting(&pc, &ours), port, Position::Left);
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
            let arrived = wait_until(
                "the switched-off pc moves the mac's pointer",
                DEADLINE,
                || {
                    emulation
                        .calls()
                        .iter()
                        .any(|c| matches!(c, Recorded::Consume(e, _) if *e == moved))
                },
            );
            tokio::select! {
                () = driving => unreachable!("the driver stops only with the test"),
                () = arrived => {}
            }
            driver.send(ProtoEvent::Leave(0)).await;
            assert_eq!(
                settled(&mut app, &seen).await,
                (true, 1, 0),
                "(held, takes, releases) while the switched-off pc controlled the mac"
            );

            app.exchange(&[R::Activate(handle, true)]).await;
            assert_eq!(
                settled(&mut app, &seen).await,
                (true, 1, 0),
                "(held, takes, releases) once the pc was switched on again"
            );

            trust
                .write()
                .expect("lock")
                .drop_capabilities(&pc.fingerprint, Caps::DRIVE_ME);
            assert_eq!(
                settled(&mut app, &seen).await,
                (false, 1, 1),
                "(held, takes, releases) once the pc may no longer control the mac"
            );
        };
        mac.run_while(body).await;
    });
}
