//! Removing a device reaches the machine it was paired with (#184, #161).
//!
//! Connected, the link it was using closes as `removed`, and that machine
//! forgets its side. Not connected, it learns on its next dial, refused as a
//! machine the other holds no pairing with, and its card says so and offers
//! to remove it, rather than it deleting its own pairing unasked.
//!
//! Whole daemons in this process, each with its own scratch directory, on
//! loopback, reached the way an app reaches them. The machine that crosses
//! captures from a scripted backend.

use super::in_process::{Daemon, Frontend, trusting};
use crate::test_harness::{machine, run_local};
use crate::trust::Caps;
use hops_ipc::{ClientHandle, FrontendEvent, FrontendRequest};
use input_capture::{CaptureEvent, Position, scripted::Script};
use std::time::Duration;

/// What must happen is waited for this long at most.
const DEADLINE: Duration = Duration::from_secs(30);

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

/// The desk machine removes the laptop while their link is down. The laptop
/// crosses to it: the dial is refused, the laptop's card for the desk says
/// it no longer trusts this machine, and the laptop keeps its pairing until
/// someone removes it there, which forgets it.
// LEDGER R184-14 | class B | 2 IPC events from two whole daemons in-process + 6 struct state: each daemon's trust store
#[test]
fn a_machine_removed_while_apart_learns_it_on_its_next_dial() {
    run_local(async {
        let script = Script::new();
        let desk = Daemon::start("apart-desk", "", input_emulation::Backend::Dummy).await;
        let (desk_fp, desk_port, desk_trust, desk_ipc) =
            (desk.fingerprint(), desk.port(), desk.trust(), desk.ipc());
        let laptop = Daemon::start_capturing(
            "apart-laptop",
            &format!(
                "[authorized_fingerprints]\n\"{desk_fp}\" = \"desk\"\n\n\
                 [[clients]]\nposition = \"right\"\nips = [\"127.0.0.1\"]\nport = {desk_port}\n\
                 activate_on_startup = true\nfingerprint = \"{desk_fp}\"\n"
            ),
            script.backend(),
            input_emulation::Backend::Dummy,
        )
        .await;
        let (laptop_fp, laptop_trust, laptop_ipc) =
            (laptop.fingerprint(), laptop.trust(), laptop.ipc());
        // Paired both ways round: the laptop drives the desk.
        desk_trust
            .write()
            .expect("lock")
            .issue_confirmed(&laptop_fp, "laptop", Caps::INBOUND)
            .expect("issue");
        assert!(
            laptop_trust.read().expect("lock").we_may_drive(&desk_fp),
            "precondition: the laptop may drive the desk"
        );

        let body = async {
            use FrontendRequest as R;
            let mut on_laptop = laptop_ipc.connect().await;
            let mut on_desk = desk_ipc.connect().await;
            let cross = || script.push(Position::Right, CaptureEvent::Begin);
            let handle: ClientHandle = until(
                &mut on_laptop,
                "a link from the laptop to the desk",
                cross,
                |e| match e {
                    FrontendEvent::State(h, _, s) if s.active_addr.is_some() => Some(*h),
                    _ => None,
                },
            )
            .await;

            // Apart: the laptop switches the desk off, which closes the link.
            on_laptop.exchange(&[R::Activate(handle, false)]).await;
            until(
                &mut on_laptop,
                "the link closing",
                || {},
                |e| match e {
                    FrontendEvent::State(h, _, s) if *h == handle && s.active_addr.is_none() => {
                        Some(())
                    }
                    _ => None,
                },
            )
            .await;
            assert!(
                laptop_trust.read().expect("lock").we_may_drive(&desk_fp),
                "switching a device off took its pairing"
            );

            // The desk removes the laptop.
            on_desk
                .exchange(&[R::RemoveAuthorizedKey(laptop_fp.clone())])
                .await;
            assert!(
                !desk_trust.read().expect("lock").is_known(&laptop_fp),
                "the desk kept a record of the laptop it removed"
            );

            // The laptop crosses again, and learns.
            on_laptop.exchange(&[R::Activate(handle, true)]).await;
            until(
                &mut on_laptop,
                "the laptop's card saying the desk no longer trusts it",
                cross,
                |e| match e {
                    FrontendEvent::State(h, _, s) if *h == handle && s.removed_by_peer => Some(()),
                    _ => None,
                },
            )
            .await;
            assert!(
                laptop_trust.read().expect("lock").we_may_drive(&desk_fp),
                "the laptop deleted its own pairing unasked; its card should ask"
            );

            // Removing it there forgets it there too.
            on_laptop
                .exchange(&[R::Delete {
                    handle,
                    fingerprint: Some(desk_fp.clone()),
                }])
                .await;
            assert!(
                !laptop_trust.read().expect("lock").is_known(&desk_fp),
                "removing the desk on the laptop kept a record of it"
            );
        };
        desk.run_while(laptop.run_while(body)).await;
    });
}

/// A paired machine that closes its link as `removed` is forgotten here, and
/// no other: the message only drops the pairing with the machine whose link
/// it came on. A link closed for any other reason drops nothing.
// LEDGER R184-15 | class B | 2 IPC events + 6 struct state: the daemon's trust store, peers over loopback QUIC
#[test]
fn only_the_machine_that_says_it_removed_this_one_is_forgotten() {
    run_local(async {
        let (removing, leaving, staying) = (machine(), machine(), machine());
        let daemon = Daemon::start("told", "", input_emulation::Backend::Dummy).await;
        let (ours, port, trust, ipc) = (
            daemon.fingerprint(),
            daemon.port(),
            daemon.trust(),
            daemon.ipc(),
        );
        for peer in [&removing, &leaving, &staying] {
            trust
                .write()
                .expect("lock")
                .issue_confirmed(&peer.fingerprint, "peer", Caps::INBOUND)
                .expect("issue");
        }
        let body = async {
            let mut app = ipc.connect().await;
            crate::transport::install_crypto_provider();
            for (peer, reason) in [
                (&leaving, &b"bye"[..]),
                (&removing, crate::transport::REMOVED),
            ] {
                let mut endpoint =
                    quinn::Endpoint::client("127.0.0.1:0".parse().expect("loopback"))
                        .expect("an endpoint");
                endpoint.set_default_client_config(crate::test_harness::raw_client_config(
                    peer,
                    trusting(peer, &ours),
                    1 << 20,
                ));
                let at = std::net::SocketAddr::from(([127, 0, 0, 1], port));
                let conn = endpoint
                    .connect(at, "grabbr")
                    .expect("a dial")
                    .await
                    .expect("the daemon admits a paired machine");
                let mut send = conn.open_uni().await.expect("an input stream");
                crate::transport::write_frame(&mut send, hops_proto::ProtoEvent::Ping)
                    .await
                    .expect("a frame");
                let fp = peer.fingerprint.clone();
                until(
                    &mut app,
                    "the link being admitted",
                    || {},
                    |e| match e {
                        FrontendEvent::DeviceConnected { fingerprint, .. }
                            if *fingerprint == fp =>
                        {
                            Some(())
                        }
                        _ => None,
                    },
                )
                .await;
                conn.close(0u32.into(), reason);
                until(
                    &mut app,
                    "the link closing",
                    || {},
                    |e| match e {
                        FrontendEvent::IncomingDisconnected(_) => Some(()),
                        _ => None,
                    },
                )
                .await;
            }
            // The removal is handled before the link's end is reported, so
            // by now its effect, if any, is in the store.
            let t = trust.read().expect("lock");
            assert!(
                !t.is_known(&removing.fingerprint),
                "the machine that removed this one is still paired here"
            );
            assert!(
                t.may_drive_us(&leaving.fingerprint),
                "a link closed for another reason dropped its pairing"
            );
            assert!(
                t.may_drive_us(&staying.fingerprint),
                "a machine that said it removed this one dropped another's pairing"
            );
        };
        daemon.run_while(body).await;
    });
}
