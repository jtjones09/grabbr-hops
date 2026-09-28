//! What an app shows of this machine's pairings, read the way an app reads
//! it: the whole daemon in this process, its events folded into the model
//! both frontends render.
//!
//! Every pairing is one card, whichever way control goes, and a card can be
//! removed. A pairing this machine only controls used to be on no card, so
//! a lost machine stayed trusted with nothing in the app to remove.

use super::in_process::{DEADLINE, Daemon, Frontend, trusting};
use crate::test_harness::{dialer, machine, run_local};
use crate::trust::Caps;
use hops_frontend_core::{AppModel, Device};
use hops_ipc::{FrontendEvent, FrontendRequest, Position};
use hops_proto::ProtoEvent;
use std::time::Duration;

/// A fresh model of what `app` is told when it asks for everything.
async fn synced(app: &mut Frontend) -> AppModel {
    let mut model = AppModel::default();
    model.connected = true;
    for event in app.exchange(&[FrontendRequest::Sync]).await {
        model.apply(event);
    }
    model
}

/// The cards the app lists for the machine `fp`.
fn cards_for(model: &AppModel, fp: &str) -> Vec<Device> {
    model
        .devices()
        .into_iter()
        .filter(|d| d.is_listable() && d.fingerprint.as_deref() == Some(fp))
        .collect()
}

// LEDGER B8-1 | class B | 2 bytes over the real IPC socket, folded by AppModel::apply into AppModel::devices
/// The desk pc controls the desk mac, and the mac never dialled in, so no
/// device is pinned to it. The pc's app shows the pairing as one card,
/// named as it was paired, and removing that card forgets the pairing.
#[test]
fn a_pairing_this_machine_only_controls_is_one_card_that_removes_it() {
    run_local(async {
        let pc = Daemon::start("listed-pc", "", input_emulation::Backend::Dummy).await;
        let (pc_trust, pc_ipc) = (pc.trust(), pc.ipc());
        let mac = machine();
        pc_trust
            .write()
            .expect("lock")
            .issue_confirmed(&mac.fingerprint, "desk mac", Caps::OUTBOUND)
            .expect("issue");

        let body = async {
            let mut app = pc_ipc.connect().await;
            let model = synced(&mut app).await;
            let cards = cards_for(&model, &mac.fingerprint);
            assert_eq!(
                cards.iter().map(|d| d.label.as_str()).collect::<Vec<_>>(),
                ["desk mac"],
                "a pairing this machine only controls must be one card, named as it \
                 was paired; the app listed {:?}",
                model.devices()
            );
            assert!(
                cards[0].send.is_none(),
                "the card says this machine controls it and holds a pairing: {:?}",
                cards[0]
            );

            // What both frontends send to remove a card with no device
            // this machine dials.
            app.exchange(&[FrontendRequest::RemoveAuthorizedKey(
                mac.fingerprint.clone(),
            )])
            .await;
            assert!(
                !pc_trust.read().expect("lock").is_known(&mac.fingerprint),
                "removing the card left the pairing in the trust store"
            );
            let model = synced(&mut app).await;
            assert!(
                cards_for(&model, &mac.fingerprint).is_empty(),
                "the removed pairing is still listed: {:?}",
                model.devices()
            );
        };
        pc.run_while(body).await;
    });
}

// LEDGER B8-2 | class B | 2 bytes over the real IPC socket, folded by AppModel::apply into AppModel::devices
/// A pairing either way alone, and one that goes both ways, is each one
/// card: never none, and never two for one machine.
#[test]
fn a_pairing_in_either_direction_or_both_is_exactly_one_card() {
    run_local(async {
        let pc = Daemon::start("listed-dirs", "", input_emulation::Backend::Dummy).await;
        let (pc_trust, pc_ipc) = (pc.trust(), pc.ipc());
        let (controls, controlled_by, both) = (machine(), machine(), machine());
        for (m, caps) in [
            (&controls, Caps::OUTBOUND),
            (&controlled_by, Caps::INBOUND),
            (&both, Caps::DRIVE),
        ] {
            pc_trust
                .write()
                .expect("lock")
                .issue_confirmed(&m.fingerprint, "peer", caps)
                .expect("issue");
        }
        let body = async {
            let mut app = pc_ipc.connect().await;
            let model = synced(&mut app).await;
            let counts: Vec<usize> = [&controls, &controlled_by, &both]
                .iter()
                .map(|m| cards_for(&model, &m.fingerprint).len())
                .collect();
            assert_eq!(
                counts,
                [1, 1, 1],
                "cards for (this machine controls it, it controls this machine, both): \
                 {:?}",
                model.devices()
            );
        };
        pc.run_while(body).await;
    });
}

/// The pc's config, as an older build wrote it: the machine `fp` paired as
/// "desk mac", and a device for it, pinned to it and switched off. A pin
/// survives the start only for a machine the trust store knows, and the
/// first start moves this pairing into the store.
fn switched_off_device_for(fp: &str) -> String {
    format!(
        "[authorized_fingerprints]\n\"{fp}\" = \"desk mac\"\n\n\
         [[clients]]\nposition = \"left\"\nips = [\"127.0.0.1\"]\nport = 9\n\
         activate_on_startup = false\nfingerprint = \"{fp}\"\n"
    )
}

// LEDGER B8-3 | class B | 2 a real QUIC dial refused by the daemon, and the FrontendEvent::Activity line its app is sent
/// The pc controls the desk mac and has switched its device for the mac
/// off. The mac dials the pc to control it, which its pairing does not
/// allow. The pc's app names the mac and says its device is switched off,
/// and does not say to open add device: the mac is paired, and opening add
/// device would do nothing for it.
#[test]
fn a_refused_machine_that_is_paired_is_named_and_its_switch_is_said() {
    run_local(async {
        let mac = machine();
        let pc = Daemon::start(
            "off-pc",
            &switched_off_device_for(&mac.fingerprint),
            input_emulation::Backend::Dummy,
        )
        .await;
        let (pc_fp, pc_port, pc_trust, pc_ipc) =
            (pc.fingerprint(), pc.port(), pc.trust(), pc.ipc());
        // This machine controls the mac, and the mac may not control it.
        pc_trust
            .write()
            .expect("lock")
            .drop_capabilities(&mac.fingerprint, Caps::DRIVE_ME);

        let body = async {
            let mut app = pc_ipc.connect().await;
            // The mac dials as a machine that drives the one it reaches.
            let mac_dials = dialer(&mac, trusting(&mac, &pc_fp), pc_port, Position::Left);
            let deadline = tokio::time::Instant::now() + DEADLINE;
            let mut told = Vec::new();
            loop {
                let _ = mac_dials
                    .conn
                    .send(ProtoEvent::Ping, mac_dials.handle)
                    .await;
                for event in app.exchange(&[]).await {
                    if let FrontendEvent::Activity(line) | FrontendEvent::Error(line) = event {
                        told.push(line);
                    }
                }
                if told.iter().any(|l| l.starts_with("Refused")) {
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the pc's app was never told a dial was refused: {told:?}"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let refused: Vec<&String> = told.iter().filter(|l| l.starts_with("Refused")).collect();
            assert!(
                refused.iter().all(|l| l.contains("desk mac")
                    && l.contains("switched off")
                    && !l.contains("add device")),
                "the mac is paired, this machine controls it, and its device here is \
                 switched off; the app was told: {refused:?}"
            );
        };
        pc.run_while(body).await;
    });
}
