//! What an app shows of this machine's pairings, read the way an app reads
//! it: the whole daemon in this process, its events folded into the model
//! both frontends render.
//!
//! Every pairing is one card, whichever way control goes, and a card can be
//! removed. A pairing this machine only controls used to be on no card, so
//! a lost machine stayed trusted with nothing in the app to remove.

use super::in_process::{DEADLINE, Daemon, Frontend, Ipc, trusting};
use crate::test_harness::{Machine, dialer, machine, run_local};
use crate::trust::{Caps, Term};
use hops_frontend_core::{AppModel, Connection, Device, TrustState};
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
            assert_eq!(
                (
                    cards[0].send.is_none(),
                    cards[0].controls,
                    cards[0].receive,
                    cards[0].connection,
                ),
                (true, true, false, Connection::AwaitingItsDial),
                "(no device pinned, this machine controls it, it does not control \
                 this machine, waiting for it to dial): {:?}",
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
            // Which way each goes, as the daemon published it.
            let ways: Vec<(bool, bool)> = [&controls, &controlled_by, &both]
                .iter()
                .map(|m| {
                    let card = &cards_for(&model, &m.fingerprint)[0];
                    (card.controls, card.receive)
                })
                .collect();
            assert_eq!(
                ways,
                [(true, false), (false, true), (true, true)],
                "(this machine controls it, it controls this machine) for each card"
            );
        };
        pc.run_while(body).await;
    });
}

// LEDGER B8-4 | class B | 2 bytes over the real IPC socket, folded by AppModel::apply into AppModel::devices
/// The pc approved the desk mac, and the number has not been compared on
/// both machines. The app shows the mac only as pairing (#167): no card
/// that holds a pairing, to rename or revoke, for a machine whose pairing
/// grants nothing yet.
#[test]
fn a_pairing_waiting_for_its_number_is_no_card() {
    run_local(async {
        let pc = Daemon::start("listed-pending", "", input_emulation::Backend::Dummy).await;
        let (pc_trust, pc_ipc) = (pc.trust(), pc.ipc());
        let mac = machine();
        pc_trust
            .write()
            .expect("lock")
            .issue(&mac.fingerprint, "desk mac", Caps::OUTBOUND)
            .expect("issue");

        let body = async {
            let model = synced(&mut pc_ipc.connect().await).await;
            assert!(
                model.is_pairing(&mac.fingerprint),
                "precondition: the app was told the mac is mid-pairing"
            );
            let held: Vec<Device> = cards_for(&model, &mac.fingerprint)
                .into_iter()
                .filter(|d| d.paired || d.trust == TrustState::Trusted)
                .collect();
            assert!(
                held.is_empty(),
                "a machine mid-pairing must be on no card that holds a pairing: {held:?}"
            );
        };
        pc.run_while(body).await;
    });
}

/// The lines the app at `ipc` is told refusing `mac`, which dials the
/// machine `fp` at `port` as one that drives the machine it reaches.
async fn refusals(ipc: &Ipc, mac: &Machine, fp: &str, port: u16) -> Vec<String> {
    let mut app = ipc.connect().await;
    let mac_dials = dialer(mac, trusting(mac, fp), port, Position::Left);
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
            return told
                .into_iter()
                .filter(|l| l.starts_with("Refused"))
                .collect();
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the app was never told a dial was refused: {told:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The pc's config: a device for the machine `fp`, pinned to it and
/// switched off. A pin survives the start only for a machine the trust
/// store knows, so the pc starts paired with it as "desk mac".
fn switched_off_device_for(fp: &str) -> String {
    format!(
        "[[clients]]\nposition = \"left\"\nips = [\"127.0.0.1\"]\nport = 9\n\
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
        // This machine controls the mac, and the mac may not control it.
        let pc = Daemon::start_paired(
            "off-pc",
            &switched_off_device_for(&mac.fingerprint),
            &[(&mac.fingerprint, "desk mac", Caps::OUTBOUND)],
            input_capture::Backend::Dummy,
            input_emulation::Backend::Dummy,
        )
        .await;
        let (pc_fp, pc_port, pc_ipc) = (pc.fingerprint(), pc.port(), pc.ipc());

        let body = async {
            let refused = refusals(&pc_ipc, &mac, &pc_fp, pc_port).await;
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

// LEDGER B8-5 | class B | 2 a real QUIC dial refused by the daemon, and the FrontendEvent::Activity line its app is sent
/// The pc's pairing with the desk mac has lapsed. The mac knocks as any
/// stranger does and can pair again only through add device, so the pc's
/// app says that, and does not name the mac as a machine it is paired
/// with.
#[test]
fn a_refused_machine_whose_pairing_lapsed_is_told_as_a_stranger() {
    run_local(async {
        const HOUR: u64 = 3600;
        let pc = Daemon::start("lapsed-pc", "", input_emulation::Backend::Dummy).await;
        let (pc_fp, pc_port, pc_trust, pc_ipc) =
            (pc.fingerprint(), pc.port(), pc.trust(), pc.ipc());
        let mac = machine();
        {
            let mut trust = pc_trust.write().expect("lock");
            trust
                .issue_with_term(
                    &mac.fingerprint,
                    "desk mac",
                    Caps::OUTBOUND,
                    Term::Secs(HOUR),
                )
                .expect("issue");
            let now = trust.now();
            trust.sweep(now + 2 * HOUR);
            assert!(
                trust.is_known(&mac.fingerprint) && !trust.has_live_lease(&mac.fingerprint),
                "precondition: the pc still holds the mac's lapsed lease"
            );
        }

        let body = async {
            let refused = refusals(&pc_ipc, &mac, &pc_fp, pc_port).await;
            assert!(
                refused
                    .iter()
                    .all(|l| l.contains("add device is not open here") && !l.contains("desk mac")),
                "the mac's pairing lapsed, so it pairs again through add device; the app \
                 was told: {refused:?}"
            );
        };
        pc.run_while(body).await;
    });
}
