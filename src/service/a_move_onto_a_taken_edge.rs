//! Moving a device onto an edge another switched-on device uses trades
//! their edges (#174). One device per edge still holds, but the move no
//! longer switches the other device off: the arrange canvas moves devices
//! by dropping them, and a drop that stopped another machine from working
//! would be a trap.

use super::in_process::Daemon;
use crate::test_harness::run_local;
use hops_ipc::{FrontendEvent, FrontendRequest, Position};
use std::path::Path;

/// Two devices, switched on: the desk pc on the left, the media rig on the
/// right. Nothing answers on port 9, and nothing needs to.
const TWO_DEVICES: &str = "[[clients]]\nhostname = \"desk-pc\"\nposition = \"left\"\n\
    ips = [\"127.0.0.1\"]\nport = 9\nactivate_on_startup = true\n\n\
    [[clients]]\nhostname = \"media-rig\"\nposition = \"right\"\n\
    ips = [\"127.0.0.1\"]\nport = 9\nactivate_on_startup = true\n";

/// Each saved device's hostname, edge and whether it starts switched on.
fn saved(file: &Path) -> Vec<(String, String, bool)> {
    let text = std::fs::read_to_string(file).expect("the config");
    let doc: toml_edit::DocumentMut = text.parse().expect("the saved config parses");
    let mut out: Vec<_> = doc
        .get("clients")
        .and_then(|c| c.as_array_of_tables())
        .map(|a| {
            a.iter()
                .map(|t| {
                    let s = |k: &str| t.get(k).and_then(|v| v.as_str()).unwrap_or("").to_owned();
                    let on = t.get("activate_on_startup").and_then(|v| v.as_bool());
                    (s("hostname"), s("position"), on == Some(true))
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

// LEDGER T174d | class B | 2 bytes (IPC events) + 4 file on disk + 6 ClientManager state: Service::update_pos driven over the IPC socket
/// The desk pc is moved to the right edge the media rig uses. Both stay
/// switched on, the rig takes the left edge the pc left, nothing is
/// reported as switched off, and the saved config says the same.
#[test]
fn a_device_moved_onto_a_taken_edge_trades_edges_and_switches_nothing_off() {
    run_local(async {
        let daemon =
            Daemon::start("trade-edges", TWO_DEVICES, input_emulation::Backend::Dummy).await;
        let (ipc, file, clients) = (daemon.ipc(), daemon.config_file(), daemon.clients());
        daemon
            .run_while(async move {
                let mut app = ipc.connect().await;
                let now = || {
                    let mut v: Vec<_> = clients
                        .get_client_states()
                        .into_iter()
                        .map(|(_, c, s)| (c.hostname.unwrap_or_default(), c.pos, s.active))
                        .collect();
                    v.sort_by(|a, b| a.0.cmp(&b.0));
                    v
                };
                let _ = app.exchange(&[FrontendRequest::Sync]).await;
                assert_eq!(
                    now(),
                    [
                        ("desk-pc".to_owned(), Position::Left, true),
                        ("media-rig".to_owned(), Position::Right, true),
                    ],
                    "the two devices did not start switched on, one per edge"
                );
                let pc = clients
                    .get_client_states()
                    .into_iter()
                    .find(|(_, c, _)| c.hostname.as_deref() == Some("desk-pc"))
                    .map(|(h, _, _)| h)
                    .expect("the desk pc");

                let events = app
                    .exchange(&[FrontendRequest::UpdatePosition(pc, Position::Right)])
                    .await;

                let switched_off: Vec<_> = events
                    .iter()
                    .filter(|e| matches!(e, FrontendEvent::Error(t) if t.contains("Switched off")))
                    .collect();
                assert_eq!(
                    (now(), switched_off.len()),
                    (
                        vec![
                            ("desk-pc".to_owned(), Position::Right, true),
                            ("media-rig".to_owned(), Position::Left, true),
                        ],
                        0
                    ),
                    "(devices, switch-off notices) after the move: {events:?}"
                );
                assert_eq!(
                    saved(&file),
                    [
                        ("desk-pc".to_owned(), "right".to_owned(), true),
                        ("media-rig".to_owned(), "left".to_owned(), true),
                    ],
                    "the saved config does not show the traded edges"
                );
            })
            .await;
    });
}

// LEDGER T174e | class B | 2 bytes (IPC events) + 6 ClientManager state: Service::update_pos driven over the IPC socket
/// A switched-off device holds no edge, so moving it next to a switched-on
/// one moves nothing else: the media rig keeps its edge and stays on.
#[test]
fn a_switched_off_device_moved_beside_another_moves_only_itself() {
    run_local(async {
        let daemon = Daemon::start("off-move", TWO_DEVICES, input_emulation::Backend::Dummy).await;
        let (ipc, clients) = (daemon.ipc(), daemon.clients());
        daemon
            .run_while(async move {
                let mut app = ipc.connect().await;
                let _ = app.exchange(&[FrontendRequest::Sync]).await;
                let pc = clients
                    .get_client_states()
                    .into_iter()
                    .find(|(_, c, _)| c.hostname.as_deref() == Some("desk-pc"))
                    .map(|(h, _, _)| h)
                    .expect("the desk pc");
                let _ = app
                    .exchange(&[
                        FrontendRequest::Activate(pc, false),
                        FrontendRequest::UpdatePosition(pc, Position::Right),
                    ])
                    .await;
                let mut now: Vec<_> = clients
                    .get_client_states()
                    .into_iter()
                    .map(|(_, c, s)| (c.hostname.unwrap_or_default(), c.pos, s.active))
                    .collect();
                now.sort_by(|a, b| a.0.cmp(&b.0));
                assert_eq!(
                    now,
                    [
                        ("desk-pc".to_owned(), Position::Right, false),
                        ("media-rig".to_owned(), Position::Right, true),
                    ],
                    "moving a switched-off device moved or switched off another"
                );
            })
            .await;
    });
}
