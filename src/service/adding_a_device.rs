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
