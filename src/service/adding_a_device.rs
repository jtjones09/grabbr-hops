//! Adding a device adds all of it or none of it (#32).
//!
//! Adding used to be a blank device that the frontend filled in with
//! later requests, so a window closed or a connection lost in between left
//! a device with no address saved for good. The request now carries the
//! whole device, and the daemon adds it whole, switched on and dialled, or
//! adds nothing and says why.

use super::in_process::Daemon;
use crate::test_harness::{door, machine, run_local, wait_until};
use hops_ipc::{ClientConfig, FrontendEvent, FrontendRequest, NewDevice, Position};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::time::Duration;

/// Every `[[clients]]` entry saved in the config at `file`.
fn saved_devices(file: &Path) -> Vec<toml_edit::Table> {
    let text = std::fs::read_to_string(file).expect("the config");
    let doc: toml_edit::DocumentMut = text.parse().expect("the saved config parses");
    doc.get("clients")
        .and_then(|c| c.as_array_of_tables())
        .map(|a| a.iter().cloned().collect())
        .unwrap_or_default()
}

fn created(events: &[FrontendEvent]) -> Vec<ClientConfig> {
    events
        .iter()
        .filter_map(|e| match e {
            FrontendEvent::Created(_, c, _) => Some(c.clone()),
            _ => None,
        })
        .collect()
}

// LEDGER T1 | class B | 2 bytes (IPC events) + 4 file on disk: Service::handle_frontend_request, Service::add_device
/// The device's first announcement and its saved entry already hold the
/// address, port and edge it was added with, and it is dialled at once.
#[test]
fn an_added_device_is_whole_from_its_first_announcement() {
    run_local(async {
        let daemon = Daemon::start("add1", "", input_emulation::Backend::Dummy).await;
        let (ipc, file) = (daemon.ipc(), daemon.config_file());
        let desk = door(&machine());
        let port = desk.port;
        daemon
            .run_while(async move {
                let mut app = ipc.connect().await;
                let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
                let events = app
                    .exchange(&[
                        // What opening add device sends first.
                        FrontendRequest::OpenPairing,
                        FrontendRequest::Create(NewDevice {
                            hostname: Some(" localhost ".into()),
                            fix_ips: vec![loopback],
                            port,
                            pos: Position::Right,
                        }),
                    ])
                    .await;
                let announced = created(&events);
                let [config] = announced.as_slice() else {
                    panic!("one add did not announce exactly one device: {events:?}");
                };
                assert_eq!(
                    (
                        config.hostname.as_deref(),
                        config.fix_ips.as_slice(),
                        config.port,
                        config.pos
                    ),
                    (Some("localhost"), &[loopback][..], port, Position::Right),
                    "the device was first announced without what it was added with"
                );
                let saved = saved_devices(&file);
                let [entry] = saved.as_slice() else {
                    panic!("one add did not save exactly one device: {saved:?}");
                };
                assert_eq!(
                    (
                        entry.get("hostname").and_then(|v| v.as_str()),
                        entry.get("port").and_then(|v| v.as_integer()),
                        entry.get("position").and_then(|v| v.as_str()),
                        entry.get("activate_on_startup").and_then(|v| v.as_bool()),
                    ),
                    (
                        Some("localhost"),
                        Some(i64::from(port)),
                        Some("right"),
                        Some(true)
                    ),
                    "the saved device is not the one added, switched on: {entry:?}"
                );
                wait_until(
                    "the added device is dialled",
                    Duration::from_secs(30),
                    || desk.knocks() > 0,
                )
                .await;
            })
            .await;
    });
}

// LEDGER T2 | class B | 2 bytes (IPC events) + 4 file on disk: Service::handle_frontend_request, NewDevice::refusal
/// A device with nowhere to dial, or no port, is not added at all: nothing
/// is announced, nothing is saved, and the person adding it is told why.
#[test]
fn a_device_that_cannot_be_dialled_is_not_added() {
    run_local(async {
        let daemon = Daemon::start("add2", "", input_emulation::Backend::Dummy).await;
        let (ipc, file) = (daemon.ipc(), daemon.config_file());
        daemon
            .run_while(async move {
                let mut app = ipc.connect().await;
                for (device, why) in [
                    (
                        NewDevice {
                            hostname: Some("   ".into()),
                            fix_ips: vec![],
                            port: 4242,
                            pos: Position::Left,
                        },
                        "hostname or IP address",
                    ),
                    (
                        NewDevice {
                            hostname: Some("desk-mac.local".into()),
                            fix_ips: vec![],
                            port: 0,
                            pos: Position::Left,
                        },
                        "port is not valid",
                    ),
                ] {
                    let events = app.exchange(&[FrontendRequest::Create(device)]).await;
                    assert!(
                        created(&events).is_empty(),
                        "a device that cannot be dialled was added: {events:?}"
                    );
                    assert!(
                        events.iter().any(|e| matches!(
                            e,
                            FrontendEvent::Error(text)
                                if text.starts_with("Nothing was added.") && text.contains(why)
                        )),
                        "a refused add did not say why ({why}): {events:?}"
                    );
                    assert!(
                        saved_devices(&file).is_empty(),
                        "a refused add saved a device: {:?}",
                        saved_devices(&file)
                    );
                }
            })
            .await;
    });
}

/// The network list add device shows, as `fp`'s presence in each list the
/// app was sent, in order.
fn listed(events: &[FrontendEvent], fp: &str) -> Vec<bool> {
    events
        .iter()
        .filter_map(|e| match e {
            FrontendEvent::Discovered { peers, .. } => Some(
                peers
                    .iter()
                    .any(|p| p.claimed_fingerprint.as_deref() == Some(fp)),
            ),
            _ => None,
        })
        .collect()
}

/// `machine` announcing itself on the local network.
fn announcing(machine: &crate::test_harness::Machine) -> crate::discovery::DiscoveredPeer {
    crate::discovery::DiscoveredPeer {
        claimed_fingerprint: Some(machine.fingerprint.clone()),
        label: "desk-pc.local".into(),
        addrs: vec!["127.0.0.1:9".parse().expect("an address")],
    }
}

/// Wait until the app is sent a network list, and say whether `fp` is in
/// the last one sent.
async fn next_list(app: &mut super::in_process::Frontend, fp: &str) -> bool {
    let deadline = tokio::time::Instant::now() + super::in_process::DEADLINE;
    loop {
        let events = app.exchange(&[]).await;
        if let Some(&last) = listed(&events, fp).last() {
            return last;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the app was sent no network list"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// LEDGER T257-12 | class B | 2 bytes: FrontendEvent::Discovered over the daemon's IPC socket, a peer pairing with it over loopback QUIC
/// A machine on the network list is paired while add device is open: the
/// list is sent again without it, with nothing more found on the network,
/// so it is not offered to add a second time (#257).
#[test]
fn a_machine_paired_while_add_device_is_open_leaves_the_network_list() {
    use super::in_process::{compare_number, prompt_from, until_paired};
    run_local(async {
        let pc = machine();
        let mut daemon = Daemon::start("listed-pair", "", input_emulation::Backend::Dummy).await;
        daemon.found_on_the_network(announcing(&pc));
        let (ours, port, trust, ipc) = (
            daemon.fingerprint(),
            daemon.port(),
            daemon.trust(),
            daemon.ipc(),
        );
        daemon
            .run_while(async move {
                let mut app = ipc.connect().await;
                // What an app sends as it attaches, then opening add device.
                let opened = app
                    .exchange(&[FrontendRequest::Sync, FrontendRequest::OpenPairing])
                    .await;
                assert_eq!(
                    listed(&opened, &pc.fingerprint).last(),
                    Some(&true),
                    "precondition: the pc is on the network list"
                );
                prompt_from(&mut app, &pc, port, &ours).await;
                app.exchange(&[FrontendRequest::AuthorizeKey {
                    label: "desk pc".into(),
                    fingerprint: pc.fingerprint.clone(),
                    controller: hops_ipc::Controller::ThisMachine,
                    clipboard: false,
                }])
                .await;
                let comparing = compare_number(&mut app, &pc, port, &ours).await;
                app.exchange(&[FrontendRequest::ConfirmPairing {
                    fingerprint: pc.fingerprint.clone(),
                    number: comparing.number.clone(),
                }])
                .await;
                until_paired(&trust, &pc.fingerprint).await;
                assert!(
                    !next_list(&mut app, &pc.fingerprint).await,
                    "the pc, paired, was still offered on the network list"
                );
            })
            .await;
    });
}

// LEDGER T257-13 | class B | 2 bytes: FrontendEvent::Discovered over the daemon's IPC socket, after its own dial to a real loopback door
/// A machine on the network list, listed to pair again (#231), is reached
/// by a device added for it, which is pinned to it: the list is sent again
/// without it, with nothing more found on the network.
#[test]
fn a_machine_a_device_is_pinned_to_leaves_the_network_list() {
    run_local(async {
        let desk = machine();
        let at_its_address = door(&desk);
        at_its_address.open();
        let mut daemon = Daemon::start("listed-pin", "", input_emulation::Backend::Dummy).await;
        daemon.found_on_the_network(announcing(&desk));
        daemon
            .trust()
            .write()
            .expect("lock")
            .list_to_pair_again(&desk.fingerprint, "desk", 0)
            .expect("listed");
        let (ipc, clients) = (daemon.ipc(), daemon.clients());
        daemon
            .run_while(async move {
                let mut app = ipc.connect().await;
                let opened = app
                    .exchange(&[
                        FrontendRequest::Sync,
                        FrontendRequest::OpenPairing,
                        FrontendRequest::Create(NewDevice {
                            hostname: None,
                            fix_ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
                            port: at_its_address.port,
                            pos: Position::Right,
                        }),
                    ])
                    .await;
                assert_eq!(
                    listed(&opened, &desk.fingerprint).first(),
                    Some(&true),
                    "precondition: the desk is on the network list"
                );
                wait_until(
                    "the device to be pinned to the desk",
                    super::in_process::DEADLINE,
                    || !clients.every_pinned_to(&desk.fingerprint).is_empty(),
                )
                .await;
                assert!(
                    !next_list(&mut app, &desk.fingerprint).await,
                    "the desk, which a device is pinned to, was still offered on the network list"
                );
            })
            .await;
    });
}
