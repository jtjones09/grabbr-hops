//! A machine upgraded from v0.12.0, whose pairings were one flat list in
//! `config.toml` that said nothing of which way control goes (#231).
//!
//! The whole daemon in this process, started for the first time on the
//! config v0.12.0 shipped as its example, read the way an app reads it.

use super::in_process::{
    DEADLINE, Daemon, Frontend, compare_number, prompt_from, trusting, until_paired,
};
use crate::test_harness::{approval, dialer, machine, run_local};
use crate::trust::Caps;
use hops_frontend_core::{Connection, TrustState};
use hops_ipc::{Controller, FrontendEvent, FrontendRequest, Position};
use hops_proto::ProtoEvent;
use std::time::Duration;

/// `config.example.toml` as v0.12.0 shipped it, byte for byte.
const V0_12_0_EXAMPLE: &str = include_str!("fixtures/v0.12.0-config.example.toml");

/// The fingerprint that config lists in `[authorized_fingerprints]`.
const LISTED: &str = "bc:05:ab:7a:a4:de:88:8c:2f:92:ac:bc:b8:49:b8:24:0d:44:b3:e6:a4:ef:d7:0b:6c:69:6d:77:53:0b:14:80";

/// The v0.12.0 example with its devices left switched off, so starting it
/// looks no hostname up on the network. Nothing about trust is changed.
fn v0_12_0_config() -> String {
    let quiet =
        V0_12_0_EXAMPLE.replace("activate_on_startup = true", "activate_on_startup = false");
    assert_ne!(
        quiet, V0_12_0_EXAMPLE,
        "precondition: the v0.12.0 example no longer switches a device on at startup"
    );
    assert!(
        quiet.contains(LISTED),
        "precondition: the v0.12.0 example no longer lists the fingerprint this test reads"
    );
    quiet
}

/// A fresh model of what `app` is told when it asks for everything.
async fn synced(app: &mut Frontend) -> hops_frontend_core::AppModel {
    let mut model = hops_frontend_core::AppModel::default();
    model.connected = true;
    for event in app.exchange(&[FrontendRequest::Sync]).await {
        model.apply(event);
    }
    model
}

// LEDGER R231-1 | class B | 1 return value: TrustStore::capabilities on the store Service startup migrated, and the model AppModel::apply folds from the real IPC socket
/// v0.12.0 kept one list of fingerprints and fed it to both directions,
/// so it cannot say which machine controls which. The upgrade grants
/// nothing from it, in either direction, and the app lists the machine
/// once, as one to pair again, which removing forgets.
#[test]
fn a_v0_12_pairing_grants_nothing_after_the_upgrade() {
    run_local(async {
        let daemon = Daemon::upgraded_from("v012", &v0_12_0_config()).await;
        let (trust, ipc) = (daemon.trust(), daemon.ipc());
        let granted = trust.read().expect("lock").capabilities(LISTED);
        assert_eq!(
            granted,
            Caps::NONE,
            "the upgrade from v0.12.0 granted {granted:?} to a machine its config listed. \
             That list said nothing about which way control goes, so any direction \
             granted from it is a guess (#231)"
        );

        let body = async {
            let mut app = ipc.connect().await;
            let model = synced(&mut app).await;
            // Every card, not only the listed fingerprint's. Each of the
            // config's [[clients]] entries is its own card, pinned to no
            // machine: nothing measured says which fingerprint answers at
            // its address until that machine is paired again, so the
            // iridium entry is not folded into the listing by its name.
            let every: Vec<_> = model
                .devices()
                .into_iter()
                .filter(|d| d.is_listable())
                .collect();
            let mut shown: Vec<_> = every
                .iter()
                .map(|d| {
                    (
                        d.label.as_str(),
                        d.fingerprint.as_deref(),
                        d.trust,
                        d.connection,
                        d.pair_again,
                    )
                })
                .collect();
            shown.sort_by_key(|c| (c.0, c.1.is_some()));
            assert_eq!(
                shown,
                [
                    (
                        "iridium",
                        None,
                        TrustState::Provisional,
                        Connection::Off,
                        false
                    ),
                    (
                        "iridium",
                        Some(LISTED),
                        TrustState::PairAgain,
                        Connection::PairAgain,
                        true
                    ),
                    (
                        "thorium",
                        None,
                        TrustState::Provisional,
                        Connection::Off,
                        false
                    ),
                ],
                "the cards the app lists after the upgrade from v0.12.0: the machine \
                 v0.12.0 paired must be listed once, as one to pair again, and no card \
                 may be paired (#231)"
            );
            assert!(
                every.iter().all(|d| !d.controls && !d.receive && !d.paired)
                    && model.clipboard(LISTED).is_none(),
                "a card claims a direction, a pairing or a clipboard: {every:?}"
            );

            let model = {
                app.exchange(&[FrontendRequest::RemoveAuthorizedKey(LISTED.to_string())])
                    .await;
                synced(&mut app).await
            };
            assert!(
                !model
                    .devices()
                    .iter()
                    .any(|d| d.fingerprint.as_deref() == Some(LISTED)),
                "removing the card left it listed"
            );
            assert!(
                trust.read().expect("lock").to_pair_again(LISTED).is_none(),
                "removing the card left the machine on the store's list"
            );
        };
        daemon.run_while(body).await;
    });
}

// LEDGER R231-7 | class B | 2 bytes: FrontendEvent::Activity over the real IPC socket, after a knock from a real dialer
/// A machine the v0.12 config listed knocks after the upgrade. It is
/// refused, and the app says it must be paired again, not that it is a
/// stranger.
#[test]
fn a_knock_from_a_v0_12_pairing_says_to_pair_it_again() {
    run_local(async {
        let desk = machine();
        let daemon = Daemon::upgraded_from(
            "v012k",
            &format!(
                "port = 4242\n\n[authorized_fingerprints]\n\"{}\" = \"desk mac\"\n",
                desk.fingerprint
            ),
        )
        .await;
        let (ours, port, ipc) = (daemon.fingerprint(), daemon.port(), daemon.ipc());
        let body = async {
            let mut app = ipc.connect().await;
            let knocker = dialer(&desk, trusting(&desk, &ours), port, Position::Left);
            let deadline = tokio::time::Instant::now() + DEADLINE;
            let mut seen = Vec::new();
            loop {
                let _ = knocker.conn.send(ProtoEvent::Ping, knocker.handle).await;
                for event in app.exchange(&[]).await {
                    if let FrontendEvent::Activity(t) | FrontendEvent::Error(t) = event {
                        seen.push(t);
                    }
                }
                if let Some(told) = seen.iter().find(|t| t.contains("desk mac")) {
                    assert!(
                        told.contains("paired with an older version of hops")
                            && told.contains("paired again")
                            && !told.contains("not paired"),
                        "the refusal of a v0.12 pairing does not say to pair it again: {told:?}"
                    );
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the knock from a v0.12 pairing was not told about; the app heard {seen:?}"
                );
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        };
        daemon.run_while(body).await;
    });
}

// LEDGER R231-10 | class B | 3 process-in-test + 1 struct state: OpenPairing, AuthorizeKey and ConfirmPairing over the daemon's IPC socket, a peer knocking and comparing its number over loopback QUIC, and every FrontendEvent the app is sent
/// A machine the v0.12 config listed is added again: approved here, then
/// its number confirmed. Each step is saved as it happens, and the app is
/// never told that a change to trusted devices could not be saved.
#[test]
fn a_v0_12_pairing_added_again_is_saved_at_every_step() {
    run_local(async {
        let desk = machine();
        let fp = desk.fingerprint.clone();
        let daemon = Daemon::upgraded_from(
            "v012a",
            &format!("port = 4242\n\n[authorized_fingerprints]\n\"{fp}\" = \"desk mac\"\n"),
        )
        .await;
        let (ours, port, trust, ipc) = (
            daemon.fingerprint(),
            daemon.port(),
            daemon.trust(),
            daemon.ipc(),
        );
        let body = async {
            let mut app = ipc.connect().await;
            let mut told = Vec::new();
            let mut heard = |events: Vec<FrontendEvent>| {
                told.extend(events.into_iter().filter_map(|e| match e {
                    FrontendEvent::Error(t) => Some(t),
                    _ => None,
                }))
            };
            heard(app.exchange(&[FrontendRequest::OpenPairing]).await);
            prompt_from(&mut app, &desk, port, &ours).await;
            heard(
                app.exchange(&[approval("desk mac", &fp, Controller::ThatMachine)])
                    .await,
            );
            let comparing = compare_number(&mut app, &desk, port, &ours).await;
            heard(
                app.exchange(&[FrontendRequest::ConfirmPairing {
                    fingerprint: fp.clone(),
                    number: comparing.number.clone(),
                }])
                .await,
            );
            until_paired(&trust, &fp).await;
            heard(app.exchange(&[]).await);
            assert!(
                !told.iter().any(|t| t.contains(hops_ipc::TRUST_NOT_SAVED)),
                "adding a v0.12 pairing again could not be saved: {told:?}"
            );
            let t = trust.read().expect("lock");
            assert_eq!(
                (t.capabilities(&fp), t.to_pair_again(&fp).is_some()),
                (Caps::DRIVE_ME, false),
                "added again as the machine that controls this one"
            );
        };
        daemon.run_while(body).await;
    });
}

// LEDGER R231-11 | class B | 1 struct state + 1 return value: the store Service startup built from a trust file already present, and the model AppModel::apply folds from the real IPC socket
/// The upgrade lists the old config's machines once, on the first start,
/// when there is no trust file yet. A machine removed after that is not
/// listed again by a later start, though `config.toml` may still name it.
#[test]
fn a_later_start_does_not_list_the_old_config_again() {
    run_local(async {
        let (removed, paired) = (machine(), machine());
        let daemon = Daemon::start_paired(
            "v012r",
            &format!(
                "[authorized_fingerprints]\n\"{}\" = \"desk mac\"\n",
                removed.fingerprint
            ),
            &[(&paired.fingerprint, "laptop", Caps::INBOUND)],
            input_capture::Backend::Dummy,
            input_emulation::Backend::Dummy,
        )
        .await;
        let (trust, ipc) = (daemon.trust(), daemon.ipc());
        let body = async {
            let listed = trust
                .read()
                .expect("lock")
                .to_pair_again(&removed.fingerprint)
                .cloned();
            assert!(
                listed.is_none(),
                "a start with a trust file listed a machine from the old config again: \
                 {listed:?}"
            );
            let mut app = ipc.connect().await;
            let model = synced(&mut app).await;
            let cards: Vec<_> = model
                .devices()
                .into_iter()
                .filter(|d| d.is_listable())
                .map(|d| d.label)
                .collect();
            assert_eq!(cards, ["laptop"], "the cards a later start lists");
        };
        daemon.run_while(body).await;
    });
}
