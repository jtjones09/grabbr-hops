//! A pairing that goes both ways, between two machines that both listen
//! (#232). Each dials the other to be driven by it, as well as to drive it,
//! so a machine that cannot be dialled is still reached, and one link
//! carries each direction.
//!
//! Whole daemons in this process, each with its own scratch directory, on
//! loopback. Each captures from a scripted backend and injects into a
//! recording one.

use super::in_process::{DEADLINE, Daemon};
use crate::test_harness::{NEVER_WITHIN, run_local};
use crate::trust::Caps;
use hops_ipc::Position;
use input_capture::{CaptureEvent, scripted::Script};
use input_emulation::recording::{Recorded, Recording};
use input_event::{Event, KeyboardEvent};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

fn key(key: u32) -> CaptureEvent {
    CaptureEvent::Input(Event::Keyboard(KeyboardEvent::Key {
        time: 0,
        key,
        state: 1,
    }))
}

fn consumed(recording: &Recording, key: u32) -> bool {
    recording.calls().iter().any(|c| {
        matches!(c, Recorded::Consume(Event::Keyboard(KeyboardEvent::Key { key: k, .. }), _)
            if *k == key)
    })
}

/// Cross from `script` at `pos` and type `k` until `on` has injected it.
async fn typed(script: &Script, pos: Position, k: u32, on: &Recording, what: &str) {
    let pos = match pos {
        Position::Left => input_capture::Position::Left,
        Position::Right => input_capture::Position::Right,
        Position::Top => input_capture::Position::Top,
        Position::Bottom => input_capture::Position::Bottom,
    };
    let deadline = tokio::time::Instant::now() + DEADLINE;
    while !consumed(on, k) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what}: the key never arrived; the other machine injected {:?}",
            on.calls()
        );
        script.push(pos, CaptureEvent::Begin);
        script.push(pos, key(k));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Where the pc's device for the mac points.
enum MacIs {
    /// At the mac's port: the pc can dial it.
    Reachable,
    /// At a port where something takes every datagram and answers none, as a
    /// client that drops incoming connections does.
    DroppingInbound,
}

/// The desk pc and the desk mac, paired so that each controls the other,
/// both listening. The mac's device for the pc points at the pc; the pc's
/// device for the mac is pinned to it and points where `mac` says. Each
/// types on the other, and then, for as long as the dials take to settle
/// several times over, exactly one link carries each direction and neither
/// is replaced.
async fn each_controls_the_other(tag: &str, mac: MacIs) {
    let (pc_script, mac_script) = (Script::new(), Script::new());
    let (on_pc, on_mac) = (Recording::new(), Recording::new());
    let pc = Daemon::start_capturing(
        &format!("{tag}-pc"),
        "",
        pc_script.backend(),
        on_pc.backend(),
    )
    .await;
    let (pc_fp, pc_port) = (pc.fingerprint(), pc.port());
    let mac_daemon = Daemon::start_paired(
        &format!("{tag}-mac"),
        &format!(
            "[[clients]]\nposition = \"left\"\nips = [\"127.0.0.1\"]\nport = {pc_port}\n\
             activate_on_startup = true\nfingerprint = \"{pc_fp}\"\n"
        ),
        &[(&pc_fp, "desk pc", Caps::DRIVE)],
        mac_script.backend(),
        on_mac.backend(),
    )
    .await;
    let (mac_fp, mac_port) = (mac_daemon.fingerprint(), mac_daemon.port());
    pc.trust()
        .write()
        .expect("lock")
        .issue_confirmed(&mac_fp, "desk mac", Caps::DRIVE)
        .expect("issue");
    // Bound for the whole test, so nothing else answers at its port.
    let dropping = std::net::UdpSocket::bind(("127.0.0.1", 0)).expect("a socket that answers none");
    let pc_dials = match mac {
        MacIs::Reachable => mac_port,
        MacIs::DroppingInbound => dropping.local_addr().expect("its port").port(),
    };
    {
        let clients = pc.clients();
        let handle = clients.add_client();
        clients.set_fix_ips(handle, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        clients.set_port(handle, pc_dials);
        clients.set_pos(handle, Position::Right);
        clients.pin(handle, mac_fp.clone()).expect("the pin");
        clients.activate_client(handle);
    }
    let (into_pc, into_mac) = (pc.links_in(), mac_daemon.links_in());

    let body = async {
        typed(
            &pc_script,
            Position::Right,
            30,
            &on_mac,
            "the pc typing on the mac",
        )
        .await;
        typed(
            &mac_script,
            Position::Left,
            48,
            &on_pc,
            "the mac typing on the pc",
        )
        .await;

        // Past several rounds of every dial and retry: a direction carried
        // twice, or a link replaced and dialled again, shows here.
        let settle = crate::dial_back::FIRST_RETRY * 6;
        let until = tokio::time::Instant::now() + settle.max(NEVER_WITHIN);
        while tokio::time::Instant::now() < until {
            let (pc_drives_mac, mac_drives_pc) = (
                into_mac.links_from(&pc_fp).await,
                into_pc.links_from(&mac_fp).await,
            );
            assert_eq!(
                (pc_drives_mac, mac_drives_pc),
                (1, 1),
                "(links carrying the pc's input to the mac, and the mac's to the pc): \
                 each direction must be carried by exactly one link, the first up, \
                 with the other dial stopped rather than kept or flapping"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // And input still flows both ways over the links that were kept.
        typed(
            &pc_script,
            Position::Right,
            31,
            &on_mac,
            "the pc typing again",
        )
        .await;
        typed(
            &mac_script,
            Position::Left,
            49,
            &on_pc,
            "the mac typing again",
        )
        .await;
    };
    pc.run_while(mac_daemon.run_while(body)).await;
}

// LEDGER R232-1 | class B | 6 struct state: Recording::calls() on both daemons, and each listener's links in, two whole daemons in-process
/// The mac listens, but nothing reaches it: whatever is at the address the
/// pc holds for it takes each dial and answers none. The pc still controls
/// the mac, over the link the mac opens to it, and the mac controls the pc
/// over its own dial, with no setting changed on either (#232).
#[test]
fn a_machine_that_cannot_be_dialled_is_controlled_over_the_link_it_opens() {
    run_local(each_controls_the_other("bw-drop", MacIs::DroppingInbound));
}

// LEDGER R232-2 | class B | 6 struct state: Recording::calls() on both daemons, and each listener's links in, two whole daemons in-process
/// Both machines can be dialled, and each dials the other for both
/// directions. One link carries each direction, the first to come up, and
/// the other attempt stops without replacing it.
#[test]
fn when_both_can_be_dialled_one_link_carries_each_direction() {
    run_local(each_controls_the_other("bw-both", MacIs::Reachable));
}

// LEDGER R232-6 | class B | 6 struct state + 1 return value: Recording::calls() on the dialling daemon, and UdpSocket::bind on its port while it runs
/// A machine set to only dial out, paired so that each controls the other,
/// is controlled over the link it opens and still binds no port: dialling
/// out for a pairing both ways opens nothing to dial in to.
#[test]
fn dialling_out_for_a_pairing_both_ways_opens_no_port() {
    run_local(async {
        let (pc_script, on_mac) = (Script::new(), Recording::new());
        let pc = Daemon::start_capturing(
            "np-pc",
            "",
            pc_script.backend(),
            input_emulation::Backend::Dummy,
        )
        .await;
        let (pc_fp, pc_port) = (pc.fingerprint(), pc.port());
        let mac = Daemon::start_paired(
            "np-mac",
            &format!(
                "listen = false\n\n[[clients]]\nposition = \"left\"\nips = [\"127.0.0.1\"]\n\
                 port = {pc_port}\nactivate_on_startup = true\nfingerprint = \"{pc_fp}\"\n"
            ),
            &[(&pc_fp, "desk pc", Caps::DRIVE)],
            input_capture::Backend::Dummy,
            on_mac.backend(),
        )
        .await;
        let (mac_fp, mac_port) = (mac.fingerprint(), mac.port());
        pc.trust()
            .write()
            .expect("lock")
            .issue_confirmed(&mac_fp, "desk mac", Caps::DRIVE)
            .expect("issue");
        let body = async {
            // The pc's device for the mac is the one its dial-in added, at
            // the first free edge.
            typed(
                &pc_script,
                Position::Right,
                30,
                &on_mac,
                "the pc typing on the mac",
            )
            .await;
            assert!(
                std::net::UdpSocket::bind(("127.0.0.1", mac_port)).is_ok(),
                "a machine set to only dial out bound its port to dial out for a \
                 pairing both ways"
            );
        };
        pc.run_while(mac.run_while(body)).await;
    });
}

// LEDGER R232-7 | class B | 2 bytes: FrontendEvent over both daemons' IPC sockets; the absence is over a fixed window, a regression check only
/// The mac holds a pairing that lets the pc drive it, and the pc holds
/// none with the mac: it removed it. With add device open on the pc, the
/// mac's dial to be driven is refused and raises no pairing request there:
/// only a dial that drives is a request to pair. The dial is the one a
/// pairing both ways now makes too (#232); which way the mac may drive is
/// not read on it. A pairing that also lets the mac drive the pc dials to
/// drive as well, and that dial, from a machine the pc removed, raises a
/// request while add device is open, as any stranger's does (#184, #195).
#[test]
fn a_dial_to_be_driven_raises_no_prompt_even_with_add_device_open() {
    run_local(async {
        let pc = Daemon::start("pr-pc", "", input_emulation::Backend::Dummy).await;
        let (pc_fp, pc_port, pc_ipc) = (pc.fingerprint(), pc.port(), pc.ipc());
        let mac = Daemon::start_paired(
            "pr-mac",
            &format!(
                "[[clients]]\nposition = \"left\"\nips = [\"127.0.0.1\"]\nport = {pc_port}\n\
                 activate_on_startup = true\nfingerprint = \"{pc_fp}\"\n"
            ),
            &[(&pc_fp, "desk pc", Caps::INBOUND)],
            input_capture::Backend::Dummy,
            input_emulation::Backend::Dummy,
        )
        .await;
        let mac_ipc = mac.ipc();
        let body = async {
            use hops_ipc::{FrontendEvent, FrontendRequest};
            let mut on_pc = pc_ipc.connect().await;
            on_pc.exchange(&[FrontendRequest::OpenPairing]).await;
            let mut on_mac = mac_ipc.connect().await;
            // The mac dialled, and was refused as a machine the pc holds no
            // pairing with.
            let deadline = tokio::time::Instant::now() + DEADLINE;
            loop {
                let refused = on_mac
                    .exchange(&[FrontendRequest::Enumerate()])
                    .await
                    .iter()
                    .any(|e| {
                        matches!(e, FrontendEvent::Enumerate(all)
                        if all.iter().any(|(_, _, s)| s.removed_by_peer))
                    });
                if refused {
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "precondition: the mac's dial to be driven was never refused by the pc"
                );
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            tokio::time::sleep(NEVER_WITHIN).await;
            let prompts: Vec<_> = on_pc
                .exchange(&[])
                .await
                .into_iter()
                .filter(|e| matches!(e, FrontendEvent::ConnectionAttempt { .. }))
                .collect();
            assert!(
                prompts.is_empty(),
                "a dial to be driven raised a pairing request: {prompts:?}"
            );
        };
        pc.run_while(mac.run_while(body)).await;
    });
}
