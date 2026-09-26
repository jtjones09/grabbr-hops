//! A machine driving this one closes its link, and the app says so within a
//! second, whether or not it had crossed onto this machine (#156, #34).
//!
//! Runs the built daemon. The driving machine is a QUIC client that speaks
//! the wire protocol directly, trusted through the config tables an upgrade
//! reads. The frontend is the real IPC connector.
#![cfg(unix)]

mod common;

use std::time::{Duration, Instant};

use hops_ipc::FrontendEvent;
use hops_proto::{Position, ProtoEvent};

const AT_ONCE: Duration = Duration::from_secs(1);

// LEDGER T66 | class B | 5 process: FrontendEvent::IncomingDisconnected from the built daemon over IPC
#[tokio::test(flavor = "current_thread")]
async fn a_closed_inbound_link_is_shown_down_within_a_second() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let peer = common::Identity::new();
    let fingerprint = peer.fingerprint();
    let (daemon, port) = common::start(
        "h-live-in",
        &format!("[authorized_fingerprints]\n\"{fingerprint}\" = \"driver\"\n"),
    );
    let (mut events, _requests) = hops_ipc::connect_async(Some(Duration::from_secs(10)))
        .await
        .expect("a frontend connects");

    for crossed in [true, false] {
        let (_endpoint, conn) = peer
            .dial(port)
            .await
            .unwrap_or_else(|| panic!("the paired machine was refused; log:\n{}", daemon.log()));
        let mut input = conn.open_uni().await.expect("input stream");
        common::write(
            &mut input,
            if crossed {
                ProtoEvent::Enter(Position::Right)
            } else {
                ProtoEvent::Ping
            },
        )
        .await;
        let fp = fingerprint.clone();
        let addr = common::next_matching(&mut events, Duration::from_secs(10), |e| match e {
            FrontendEvent::DeviceEntered {
                addr, fingerprint, ..
            } if crossed && fingerprint == fp => Some(addr),
            FrontendEvent::DeviceConnected { addr, fingerprint }
                if !crossed && fingerprint == fp =>
            {
                Some(addr)
            }
            _ => None,
        })
        .await
        .unwrap_or_else(|| {
            panic!(
                "the app never showed the machine (crossed: {crossed}); log:\n{}",
                daemon.log()
            )
        });

        conn.close(0u32.into(), b"bye");
        let closed = Instant::now();
        let shown = common::next_matching(&mut events, AT_ONCE, |e| match e {
            FrontendEvent::IncomingDisconnected(gone) if gone == addr => Some(()),
            _ => None,
        })
        .await;
        assert!(
            shown.is_some(),
            "a machine that {} closed its link, and the app was not told within \
             {AT_ONCE:?} ({:?} so far); log:\n{}",
            if crossed {
                "had crossed onto this one"
            } else {
                "never crossed onto this one"
            },
            closed.elapsed(),
            daemon.log()
        );
    }
}
