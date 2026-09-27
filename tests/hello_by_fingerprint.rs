//! A machine's build and capabilities, as it announces them when it dials in,
//! are recorded on the device whose pin its connection proved, and on no other.
//!
//! Two machines can dial from one address: two virtual machines behind one
//! host's NAT, or anything else sharing it. Matched by address, the second
//! machine's Hello wrote its build onto the first machine's device, and its
//! Capability decided what this machine sends the first one.
//!
//! Runs the built daemon. Both machines are QUIC clients that speak the wire
//! protocol directly from 127.0.0.1, trusted through the config tables an
//! upgrade reads. The frontend is the real IPC connector.
#![cfg(unix)]

mod common;

use std::time::Duration;

use hops_ipc::{ClientState, FrontendEvent, FrontendRequest};
use hops_proto::ProtoEvent;

const DESK_COMMIT: [u8; 8] = *b"deskmac1";
const DESK_CAPS: u32 = 0x4000_0002;
const LAPTOP_COMMIT: [u8; 8] = *b"laptop01";
const LAPTOP_CAPS: u32 = 0x8000_0001;

/// Dial in as `who`, announce `commit` and `caps`, and return once the daemon
/// has answered a Ping sent after them, so both announcements have been
/// handled. The connection is returned to be kept open.
async fn announce(
    who: &common::Identity,
    port: u16,
    commit: [u8; 8],
    caps: u32,
    daemon: &common::Daemon,
) -> (quinn::Endpoint, quinn::Connection) {
    let (endpoint, conn) = who
        .dial(port)
        .await
        .unwrap_or_else(|| panic!("a paired machine was refused; log:\n{}", daemon.log()));
    let mut send = conn.open_uni().await.expect("input stream");
    common::write(&mut send, ProtoEvent::Hello { commit }).await;
    common::write(&mut send, ProtoEvent::Capability { flags: caps }).await;
    common::write(&mut send, ProtoEvent::Ping).await;
    let mut replies = tokio::time::timeout(Duration::from_secs(10), conn.accept_uni())
        .await
        .expect("the daemon opens its reply stream")
        .expect("reply stream");
    let answered = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(event) = common::read(&mut replies).await {
            if matches!(event, ProtoEvent::Pong(_)) {
                return true;
            }
        }
        false
    })
    .await;
    assert_eq!(
        answered,
        Ok(true),
        "the daemon never answered the Ping; log:\n{}",
        daemon.log()
    );
    (endpoint, conn)
}

// LEDGER T2370 | class B | 2 bytes (IPC events) from the built daemon: FrontendEvent::State of a pinned device
#[tokio::test(flavor = "current_thread")]
async fn a_machine_sharing_an_address_cannot_set_another_devices_build_or_capabilities() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let desk = common::Identity::new();
    let laptop = common::Identity::new();
    // The device dials nowhere during the test: nothing crosses to it.
    let unused = std::net::UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .expect("a free port")
        .port();
    let (daemon, port) = common::start(
        "h-hello",
        &format!(
            "[authorized_fingerprints]\n\"{desk_fp}\" = \"desk mac\"\n\"{laptop_fp}\" = \"laptop\"\n\n\
             [[clients]]\nposition = \"left\"\nips = [\"127.0.0.1\"]\nport = {unused}\n\
             activate_on_startup = true\nfingerprint = \"{desk_fp}\"\n",
            desk_fp = desk.fingerprint(),
            laptop_fp = laptop.fingerprint(),
        ),
    );
    let (mut events, mut requests) = hops_ipc::connect_async(Some(Duration::from_secs(10)))
        .await
        .expect("a frontend connects");
    requests
        .request(FrontendRequest::Sync)
        .await
        .expect("sync sent");
    let desk_fp = desk.fingerprint();
    let handle = common::next_matching(&mut events, Duration::from_secs(10), |e| match e {
        FrontendEvent::Enumerate(clients) => clients
            .into_iter()
            .find(|(_, _, s)| s.peer_fingerprint.as_deref() == Some(desk_fp.as_str()))
            .map(|(h, _, _)| h),
        _ => None,
    })
    .await
    .unwrap_or_else(|| {
        panic!(
            "the device pinned to the desk mac was never listed; log:\n{}",
            daemon.log()
        )
    });

    // The laptop dials first, from the address the desk mac's device names.
    let _laptop_link = announce(&laptop, port, LAPTOP_COMMIT, LAPTOP_CAPS, &daemon).await;
    // Then the desk mac itself. Its announcement is handled after the
    // laptop's: the daemon answered the laptop's Ping before this dial began.
    let _desk_link = announce(&desk, port, DESK_COMMIT, DESK_CAPS, &daemon).await;

    let mut shown: Vec<ClientState> = Vec::new();
    let reached = common::next_matching(&mut events, Duration::from_secs(20), |e| match e {
        FrontendEvent::State(h, _, state) if h == handle => {
            let done = state.peer_commit == Some(DESK_COMMIT);
            shown.push(state);
            done.then_some(())
        }
        _ => None,
    })
    .await;
    let wrong: Vec<_> = shown
        .iter()
        .filter(|s| s.peer_commit == Some(LAPTOP_COMMIT) || s.peer_caps == Some(LAPTOP_CAPS))
        .map(|s| {
            (
                s.peer_commit
                    .map(|c| String::from_utf8_lossy(&c).into_owned()),
                s.peer_caps,
            )
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "the laptop, dialling from the same address, set the desk mac's device to \
         (build, capabilities) {wrong:?}; log:\n{}",
        daemon.log()
    );
    assert!(
        reached.is_some(),
        "the desk mac's own Hello never reached its device; states shown: {:?}; log:\n{}",
        shown
            .iter()
            .map(|s| (s.peer_commit, s.peer_caps))
            .collect::<Vec<_>>(),
        daemon.log()
    );
}
