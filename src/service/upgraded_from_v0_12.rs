//! A machine upgraded from v0.12.0, whose pairings were one flat list in
//! `config.toml` that said nothing of which way control goes (#231).
//!
//! The whole daemon in this process, started for the first time on the
//! config v0.12.0 shipped as its example, read the way an app reads it.

use super::in_process::{
    DEADLINE, Daemon, Frontend, compare_number, keep_files, prompt_from, trusting, until_paired,
};
use crate::test_harness::{
    Door, Machine, NEVER_WITHIN, approval, dialer, door, machine, run_local,
};
use crate::trust::Caps;
use hops_frontend_core::{Connection, TrustState};
use hops_ipc::{Controller, FrontendEvent, FrontendRequest, Position};
use hops_proto::ProtoEvent;
use input_capture::{CaptureEvent, scripted::Script};
use input_emulation::recording::{Recorded, Recording};
use input_event::{Event, PointerEvent};
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

/// The v0.12.0 example, with the machine it lists and dials as iridium made
/// `iridium`, a machine this test holds the key of, answering at `port` on
/// loopback. Its hostname line goes, so that starting it looks no name up.
/// Nothing about trust is changed, and thorium stays switched off.
fn v0_12_0_config_for(iridium: &Machine, port: u16) -> String {
    let config = V0_12_0_EXAMPLE
        .replace(LISTED, &iridium.fingerprint)
        .replace("hostname = \"iridium\"\n", "")
        .replace(
            "ips = [\"192.168.178.156\"]",
            &format!("ips = [\"127.0.0.1\"]\nport = {port}"),
        );
    assert!(
        config.contains(&iridium.fingerprint)
            && config.contains(&format!("port = {port}"))
            && !config.contains("hostname = \"iridium\""),
        "precondition: the v0.12.0 example no longer has the lines this test changes"
    );
    config
}

/// A card as the app lists it: its name, its machine, its trust, what its
/// dot says, whether it is to be paired again, and whether it has a device.
type Card = (String, Option<String>, TrustState, Connection, bool, bool);

/// Every card the app lists, sorted.
fn cards(model: &hops_frontend_core::AppModel) -> Vec<Card> {
    let mut cards: Vec<Card> = model
        .devices()
        .into_iter()
        .filter(|d| d.is_listable())
        .map(|d| {
            (
                d.label,
                d.fingerprint,
                d.trust,
                d.connection,
                d.pair_again,
                d.send.is_some(),
            )
        })
        .collect();
    cards.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    cards
}

/// What the app lists for iridium once its device and its listing are one
/// card, folded by the first handshake with iridium's address (#231).
fn folded(iridium: &Machine) -> Vec<Card> {
    vec![
        (
            "iridium".into(),
            Some(iridium.fingerprint.clone()),
            TrustState::PairAgain,
            Connection::PairAgain,
            true,
            true,
        ),
        (
            "thorium".into(),
            None,
            TrustState::Provisional,
            Connection::Off,
            false,
            true,
        ),
    ]
}

/// Do `nudge` until the app lists a card for `fp` that has a device, and
/// return the model then: the device and its listing are one card.
async fn until_folded(app: &mut Frontend, fp: &str, mut nudge: impl FnMut()) -> AppModelNow {
    let deadline = tokio::time::Instant::now() + DEADLINE;
    loop {
        nudge();
        let model = synced(app).await;
        if model
            .devices()
            .iter()
            .any(|d| d.fingerprint.as_deref() == Some(fp) && d.send.is_some())
        {
            return model;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the device iridium's address reached is not folded into iridium's listing \
             to pair again: one machine, and the app lists {:?}",
            cards(&model)
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

type AppModelNow = hops_frontend_core::AppModel;

// LEDGER R231-1 | class B | 1 return value + 2 bytes: TrustStore::capabilities on the store Service startup migrated, the model AppModel::apply folds from the real IPC socket, and a crossing to a loopback receiver holding the listed key
/// v0.12.0 kept one list of fingerprints and fed it to both directions,
/// so it cannot say which machine controls which. The upgrade grants
/// nothing from it, in either direction, and the app lists the machine
/// once, as one to pair again, which removing forgets.
///
/// Once, from the first handshake with the machine's address. Before it
/// there are two cards for iridium, and that cannot be avoided: v0.12.0
/// wrote no fingerprint on a `[[clients]]` entry, so nothing says which
/// machine answers at the device's address until one proves its key there,
/// and folding the two by name would be a guess about identity.
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
            let every: Vec<_> = model
                .devices()
                .into_iter()
                .filter(|d| d.is_listable())
                .collect();
            // Before any handshake: the iridium entry is pinned to no
            // machine, so it is a card of its own beside the listing.
            assert_eq!(
                cards(&model),
                [
                    (
                        "iridium".into(),
                        None,
                        TrustState::Provisional,
                        Connection::Off,
                        false,
                        true
                    ),
                    (
                        "iridium".into(),
                        Some(LISTED.into()),
                        TrustState::PairAgain,
                        Connection::PairAgain,
                        true,
                        false
                    ),
                    (
                        "thorium".into(),
                        None,
                        TrustState::Provisional,
                        Connection::Off,
                        false,
                        true
                    ),
                ],
                "the cards the app lists after the upgrade from v0.12.0, before any \
                 handshake: the machine v0.12.0 paired must be listed as one to pair \
                 again, its [[clients]] entry as a device pinned to no machine, and no \
                 card may be paired (#231)"
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

        // The first handshake: the same config, with iridium a machine whose
        // key this test holds, answering at the device's address. Crossing
        // to it folds the two cards into one, and grants nothing.
        let iridium = machine();
        let receiver = door(&iridium);
        receiver.open();
        let script = Script::new();
        let daemon = Daemon::upgraded_with(
            "v012f",
            &v0_12_0_config_for(&iridium, receiver.port),
            script.backend(),
            input_emulation::Backend::Dummy,
        )
        .await;
        let (trust, ipc) = (daemon.trust(), daemon.ipc());
        let body = async {
            let mut app = ipc.connect().await;
            let model = until_folded(&mut app, &iridium.fingerprint, || {
                script.push(input_capture::Position::Right, CaptureEvent::Begin)
            })
            .await;
            assert_eq!(
                cards(&model),
                folded(&iridium),
                "after the first handshake the machine v0.12.0 paired must be one card, \
                 to pair again, holding its device (#231)"
            );
        };
        daemon.run_while(body).await;
        assert_eq!(
            (
                trust
                    .read()
                    .expect("lock")
                    .capabilities(&iridium.fingerprint),
                receiver.streams()
            ),
            (Caps::NONE, 0),
            "folding the card granted iridium something, or a stream was opened to it"
        );
    });
}

// LEDGER R231-12 | class B | 3 process-in-test + 1 struct state + 1 injected events: a crossing and a knock over loopback QUIC, ConfirmPairing over the daemon's IPC socket, the daemon's store, its recording emulation backend, and a second start on the files the first left
/// The pin that folds a device into its listing is a measured identity, not
/// trust (#231). With it, iridium is driven by nothing from here, drives
/// nothing here, and shares no clipboard; this machine does not dial it to
/// be driven (`dial_back`'s own test holds that case). It survives a
/// restart. Adding iridium again through the card pairs it the way the
/// pairing card says, and leaves one card.
#[test]
fn a_device_folded_into_its_listing_gains_nothing_and_is_added_again_as_one_card() {
    run_local(async {
        let iridium = machine();
        let receiver = door(&iridium);
        receiver.open();
        let script = Script::new();
        let recording = Recording::new();
        let daemon = Daemon::upgraded_with(
            "v012g",
            &v0_12_0_config_for(&iridium, receiver.port),
            script.backend(),
            recording.backend(),
        )
        .await;
        let (ours, port, trust, ipc) = (
            daemon.fingerprint(),
            daemon.port(),
            daemon.trust(),
            daemon.ipc(),
        );
        let dir = daemon
            .config_file()
            .parent()
            .expect("its directory")
            .to_path_buf();
        let kept = std::path::PathBuf::from(format!("/tmp/h-kept-v012g-{}", std::process::id()));
        let fp = iridium.fingerprint.clone();
        let cross = || script.push(input_capture::Position::Right, CaptureEvent::Begin);
        let body = async {
            let mut app = ipc.connect().await;
            until_folded(&mut app, &fp, cross).await;
            keep_files(&dir, &kept);

            // Crossing on, and iridium driving: neither gets through.
            let intruder = dialer(&iridium, trusting(&iridium, &ours), port, Position::Left);
            let motion = Event::Pointer(PointerEvent::Motion {
                time: 0,
                dx: 1.0,
                dy: 0.0,
            });
            let deadline = tokio::time::Instant::now() + NEVER_WITHIN * 4;
            while tokio::time::Instant::now() < deadline {
                cross();
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
            let model = synced(&mut app).await;
            let card = model
                .devices()
                .into_iter()
                .find(|d| d.fingerprint.as_deref() == Some(fp.as_str()))
                .expect("iridium's card");
            {
                let t = trust.read().expect("lock");
                assert_eq!(
                    (
                        t.capabilities(&fp),
                        t.we_may_drive(&fp),
                        t.may_drive_us(&fp),
                        t.clipboard_from(&fp),
                        t.clipboard_to(&fp),
                        receiver.streams(),
                        recording
                            .calls()
                            .iter()
                            .any(|c| matches!(c, Recorded::Consume(e, _) if *e == motion)),
                        (card.controls, card.receive, card.paired),
                        model.clipboard(&fp),
                    ),
                    (
                        Caps::NONE,
                        false,
                        false,
                        false,
                        false,
                        0,
                        false,
                        (false, false, false),
                        None
                    ),
                    "a device pinned to a machine listed to pair again gained something \
                     from the pin: (capabilities, may drive it, may drive this one, \
                     clipboard from it, clipboard to it, input streams opened to it, its \
                     input injected here, the card's (controls, receive, paired), the \
                     card's clipboard). The pin is a measured identity and grants \
                     nothing until the machine is paired again (#231)."
                );
            }

            // Add it again, as the card's button does, choosing that this
            // machine controls it.
            app.exchange(&[FrontendRequest::OpenPairing]).await;
            prompt_from(&mut app, &iridium, port, &ours).await;
            app.exchange(&[approval("iridium", &fp, Controller::ThisMachine)])
                .await;
            let comparing = compare_number(&mut app, &iridium, port, &ours).await;
            app.exchange(&[FrontendRequest::ConfirmPairing {
                fingerprint: fp.clone(),
                number: comparing.number.clone(),
            }])
            .await;
            until_paired(&trust, &fp).await;
            let model = synced(&mut app).await;
            let listed = cards(&model);
            let t = trust.read().expect("lock");
            assert_eq!(
                (
                    listed
                        .iter()
                        .filter(|c| c.0 == "iridium" || c.1.as_deref() == Some(fp.as_str()))
                        .map(|c| (c.1.clone(), c.2, c.4, c.5))
                        .collect::<Vec<_>>(),
                    t.capabilities(&fp),
                    t.lease(&fp).is_some_and(|l| l.confirmed),
                    t.to_pair_again(&fp).is_some(),
                ),
                (
                    vec![(Some(fp.clone()), TrustState::Trusted, false, true)],
                    Caps::I_MAY_DRIVE,
                    true,
                    false
                ),
                "adding iridium again through its card must leave one card, paired, \
                 holding its device, with a confirmed lease granting what the pairing \
                 card chose and no listing left; the app lists {listed:?}"
            );
        };
        daemon.run_while(body).await;

        // Started again on the files the fold left: still one card.
        let daemon = Daemon::restarted("v012h", &kept, input_emulation::Backend::Dummy).await;
        let ipc = daemon.ipc();
        let listed = daemon
            .run_while(async {
                let mut app = ipc.connect().await;
                cards(&synced(&mut app).await)
            })
            .await;
        let _ = std::fs::remove_dir_all(&kept);
        assert_eq!(
            listed,
            folded(&iridium),
            "after a restart the device folded into its listing is a card of its own \
             again: its pin was dropped at start (#231)"
        );
    });
}

// LEDGER R231-13 | class B | 2 bytes + 1 struct state: a knock over loopback QUIC from a machine listed to pair again, the model AppModel::apply folds from the real IPC socket, and Delete over it
/// The other order: the listed machine knocks first, from the address a
/// device pinned to no machine names. The knock proves nothing by itself,
/// so it has this machine dial that device, and the dial measures which
/// machine answers there. The two cards fold into one, and deleting that
/// card removes both.
#[test]
fn a_listed_machine_that_knocks_first_is_folded_into_its_device() {
    run_local(async {
        let iridium = machine();
        let receiver: Door = door(&iridium);
        receiver.open();
        let daemon = Daemon::upgraded_with(
            "v012k2",
            &v0_12_0_config_for(&iridium, receiver.port),
            input_capture::Backend::Dummy,
            input_emulation::Backend::Dummy,
        )
        .await;
        let (ours, port, trust, ipc) = (
            daemon.fingerprint(),
            daemon.port(),
            daemon.trust(),
            daemon.ipc(),
        );
        let fp = iridium.fingerprint.clone();
        let body = async {
            let mut app = ipc.connect().await;
            let knocker = dialer(&iridium, trusting(&iridium, &ours), port, Position::Left);
            let knocking = tokio::task::spawn_local(async move {
                loop {
                    let _ = knocker.conn.send(ProtoEvent::Ping, knocker.handle).await;
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            });
            let model = until_folded(&mut app, &fp, || {}).await;
            knocking.abort();
            assert_eq!(
                cards(&model),
                folded(&iridium),
                "a knock from the listed machine did not fold its device's card into \
                 its listing"
            );
            assert_eq!(receiver.streams(), 0, "a stream was opened to iridium");

            let handle = model
                .devices()
                .into_iter()
                .find_map(|d| d.send.filter(|_| d.fingerprint.as_deref() == Some(&fp)))
                .map(|s| s.handle)
                .expect("the folded card's device");
            app.exchange(&[FrontendRequest::Delete {
                handle,
                fingerprint: Some(fp.clone()),
            }])
            .await;
            let model = synced(&mut app).await;
            assert!(
                !model
                    .devices()
                    .iter()
                    .any(|d| d.fingerprint.as_deref() == Some(fp.as_str()))
                    && trust.read().expect("lock").to_pair_again(&fp).is_none(),
                "deleting the folded card left part of it: {:?}",
                cards(&model)
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
