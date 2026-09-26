//! A machine this one drives closes the link, and the app stops showing it as
//! up within a second (#156, #34).
//!
//! Runs the built daemon. The receiver is a QUIC server that answers pings as
//! a receiver whose input emulation works, trusted through the config tables
//! an upgrade reads. The frontend is the real IPC connector.
#![cfg(unix)]

mod common;

use std::time::{Duration, Instant};

use hops_ipc::{FrontendEvent, FrontendRequest, Position};
use hops_proto::ProtoEvent;

const AT_ONCE: Duration = Duration::from_secs(1);

/// A receiver that answers every ping with "my input emulation is on".
fn receiver(identity: &common::Identity) -> quinn::Endpoint {
    let ep = quinn::Endpoint::server(
        identity.server_config(),
        "127.0.0.1:0".parse().expect("addr"),
    )
    .expect("server");
    let accepting = ep.clone();
    tokio::task::spawn_local(async move {
        while let Some(incoming) = accepting.accept().await {
            tokio::task::spawn_local(async move {
                let Ok(conn) = incoming.await else { return };
                let Ok(mut input) = conn.accept_uni().await else {
                    return;
                };
                let Ok(mut replies) = conn.open_uni().await else {
                    return;
                };
                while let Some(event) = common::read(&mut input).await {
                    if matches!(event, ProtoEvent::Ping) {
                        common::write(&mut replies, ProtoEvent::Pong(true)).await;
                    }
                }
            });
        }
    });
    ep
}

// LEDGER T67 | class B | 5 process: FrontendEvent::State from the built daemon over IPC
#[test]
fn a_closed_outbound_link_is_shown_down_within_a_second() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    tokio::task::LocalSet::new().block_on(&rt, async {
        let identity = common::Identity::new();
        let receiver = receiver(&identity);
        let port = receiver.local_addr().expect("local addr").port();
        let fp = identity.fingerprint();
        // The first client, pinned to the receiver, is what makes the upgrade
        // grant driving it. The second, not yet pinned, is the one switched on:
        // a device being added is dialled at once, without waiting for the
        // pointer to cross to it.
        let (daemon, _) = common::start(
            "h-live-out",
            &format!(
                "[authorized_fingerprints]\n\"{fp}\" = \"receiver\"\n\n\
                 [[clients]]\nposition = \"top\"\nips = [\"127.0.0.1\"]\nport = {port}\n\
                 fingerprint = \"{fp}\"\n\n\
                 [[clients]]\nposition = \"right\"\nips = [\"127.0.0.1\"]\nport = {port}\n"
            ),
        );
        let (mut events, mut requests) = hops_ipc::connect_async(Some(Duration::from_secs(10)))
            .await
            .expect("a frontend connects");

        requests
            .request(FrontendRequest::Enumerate())
            .await
            .expect("enumerate");
        let handle = common::next_matching(&mut events, Duration::from_secs(10), |e| match e {
            FrontendEvent::Enumerate(clients) => clients
                .into_iter()
                .find(|(_, c, _)| c.pos == Position::Right)
                .map(|(h, _, _)| h),
            _ => None,
        })
        .await
        .expect("the configured device is listed");
        requests
            .request(FrontendRequest::OpenPairing)
            .await
            .expect("open pairing");
        requests
            .request(FrontendRequest::Activate(handle, true))
            .await
            .expect("switch on");
        common::next_matching(&mut events, Duration::from_secs(10), |e| match e {
            FrontendEvent::State(h, _, s) if h == handle && s.alive => Some(()),
            _ => None,
        })
        .await
        .unwrap_or_else(|| panic!("the receiver never showed as up; log:\n{}", daemon.log()));

        // The receiver ends every connection and takes no more.
        receiver.close(0u32.into(), b"gone");
        let closed = Instant::now();
        let shown = common::next_matching(&mut events, AT_ONCE, |e| match e {
            FrontendEvent::State(h, _, s) if h == handle && !s.alive && s.active_addr.is_none() => {
                Some(())
            }
            _ => None,
        })
        .await;
        assert!(
            shown.is_some(),
            "the receiver closed the link, and the app was not told within \
             {AT_ONCE:?} ({:?} so far); log:\n{}",
            closed.elapsed(),
            daemon.log()
        );
    });
}
