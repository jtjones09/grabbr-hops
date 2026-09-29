//! Moving a device onto an edge another switched-on device uses trades
//! their edges (#174). One device per edge still holds, but the move no
//! longer switches the other device off: the arrange canvas moves devices
//! by dropping them, and a drop that stopped another machine from working
//! would be a trap.

use super::in_process::{Daemon, Frontend};
use crate::test_harness::run_local;
use hops_ipc::{FrontendEvent, FrontendRequest, Position};
use input_capture::scripted::Script;
use std::path::Path;

/// Two devices, switched on: the desk pc on the left, the media rig on the
/// right, each with the canvas spot it was dropped at on its side. Nothing
/// answers on port 9, and nothing needs to.
const TWO_DEVICES: &str = "[[clients]]\nhostname = \"desk-pc\"\nposition = \"left\"\n\
    ips = [\"127.0.0.1\"]\nport = 9\nactivate_on_startup = true\n\
    geometry = { x = 16, y = 108, width = 96, height = 64 }\n\n\
    [[clients]]\nhostname = \"media-rig\"\nposition = \"right\"\n\
    ips = [\"127.0.0.1\"]\nport = 9\nactivate_on_startup = true\n\
    geometry = { x = 368, y = 108, width = 96, height = 64 }\n";

/// Each saved device's hostname, edge, whether it starts switched on, and
/// whether it keeps a saved canvas spot.
fn saved(file: &Path) -> Vec<(String, String, bool, bool)> {
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
                    let spot = t.get("geometry").is_some();
                    (s("hostname"), s("position"), on == Some(true), spot)
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
/// reported as switched off, the user is told the rig moved, and the saved
/// config says the same. Neither keeps its canvas spot, which was on the
/// side it left.
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

                let notices = |what: &str| {
                    events
                        .iter()
                        .filter(|e| matches!(e, FrontendEvent::Error(t) if t.starts_with(what)))
                        .count()
                };
                assert_eq!(
                    (now(), notices("Switched off"), notices("Moved \"media-rig\" to the left edge")),
                    (
                        vec![
                            ("desk-pc".to_owned(), Position::Right, true),
                            ("media-rig".to_owned(), Position::Left, true),
                        ],
                        0,
                        1
                    ),
                    "(devices, switch-off notices, notices the rig moved) after the move: {events:?}"
                );
                assert_eq!(
                    saved(&file),
                    [
                        ("desk-pc".to_owned(), "right".to_owned(), true, false),
                        ("media-rig".to_owned(), "left".to_owned(), true, false),
                    ],
                    "(hostname, edge, on, keeps a canvas spot) saved after the trade"
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

/// Every device a crossing pushed at `at` is refused toward: pushed until
/// one is, then one more round for any other the same crossing reached.
/// None if nothing is said within the deadline.
async fn refused_at(
    app: &mut Frontend,
    script: &Script,
    at: input_capture::Position,
) -> Vec<hops_ipc::ClientHandle> {
    let refused = |events: Vec<FrontendEvent>| -> Vec<_> {
        events
            .into_iter()
            .filter_map(|e| match e {
                FrontendEvent::CrossingRefused { handle, .. } => Some(handle),
                _ => None,
            })
            .collect()
    };
    let deadline = tokio::time::Instant::now() + DEADLINE;
    let mut heard = Vec::new();
    while heard.is_empty() && tokio::time::Instant::now() < deadline {
        script.push(at, input_capture::CaptureEvent::Begin);
        heard = refused(app.exchange(&[]).await);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    heard.extend(refused(app.exchange(&[]).await));
    heard.sort();
    heard.dedup();
    heard
}

// LEDGER T174l | class B | 2 bytes (CrossingRefused over the IPC socket) + 5 capture backend: which device a crossing at each edge is toward, after the trade
/// After the desk pc takes the right edge from the media rig, the pointer
/// crossing at the right edge is toward the desk pc and at the left edge
/// toward the media rig: the capture each device is reached through moved
/// with its edge, not only the stored edge. Neither answers, so each
/// crossing is refused, and the refusal names the device it was toward.
#[test]
fn after_a_trade_each_edge_crosses_to_the_device_now_on_it() {
    run_local(async {
        let script = Script::new();
        let daemon = Daemon::start_capturing(
            "trade-cross",
            TWO_DEVICES,
            script.backend(),
            input_emulation::Backend::Dummy,
        )
        .await;
        let (ipc, clients) = (daemon.ipc(), daemon.clients());
        daemon
            .run_while(async move {
                let mut app = ipc.connect().await;
                let _ = app.exchange(&[FrontendRequest::Sync]).await;
                let handle_of = |name: &str| {
                    clients
                        .get_client_states()
                        .into_iter()
                        .find(|(_, c, _)| c.hostname.as_deref() == Some(name))
                        .map(|(h, _, _)| h)
                        .expect("a configured device")
                };
                let (pc, rig) = (handle_of("desk-pc"), handle_of("media-rig"));
                // Capture is up and idle before the trade: a crossing it
                // took while still starting could be routed before the
                // trade's own requests reached it.
                assert_eq!(
                    refused_at(&mut app, &script, input_capture::Position::Left).await,
                    [pc],
                    "before the trade, a crossing at the left edge was not toward the desk pc"
                );

                let _ = app
                    .exchange(&[FrontendRequest::UpdatePosition(pc, Position::Right)])
                    .await;

                let mut toward = Vec::new();
                for (edge, at) in [
                    ("right", input_capture::Position::Right),
                    ("left", input_capture::Position::Left),
                ] {
                    toward.push((edge, refused_at(&mut app, &script, at).await));
                }
                assert_eq!(
                    toward,
                    [("right", vec![pc]), ("left", vec![rig])],
                    "(edge crossed at, devices it was toward) after the trade; \
                     the desk pc is {pc}, the media rig {rig}"
                );
            })
            .await;
    });
}

/// What must happen is waited for this long at most.
const DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);
