//! A machine upgraded from v0.12.0, whose pairings were one flat list in
//! `config.toml` that said nothing of which way control goes (#231).
//!
//! The whole daemon in this process, started for the first time on the
//! config v0.12.0 shipped as its example, read the way an app reads it.

use super::in_process::{DEADLINE, Daemon, Frontend, trusting};
use crate::test_harness::{dialer, machine, run_local};
use crate::trust::Caps;
use hops_frontend_core::{Connection, TrustState};
use hops_ipc::{FrontendEvent, FrontendRequest, Position};
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
            let cards: Vec<_> = model
                .devices()
                .into_iter()
                .filter(|d| d.is_listable() && d.fingerprint.as_deref() == Some(LISTED))
                .collect();
            assert_eq!(
                cards
                    .iter()
                    .map(|d| (d.label.as_str(), d.trust, d.connection, d.pair_again))
                    .collect::<Vec<_>>(),
                [(
                    "iridium",
                    TrustState::PairAgain,
                    Connection::PairAgain,
                    true
                )],
                "the app must list the machine v0.12.0 paired once, as one to pair \
                 again (#231); it listed {cards:?}"
            );
            assert!(
                !cards[0].controls && !cards[0].receive && model.clipboard(LISTED).is_none(),
                "the card claims a direction or a clipboard: {:?}",
                cards[0]
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
