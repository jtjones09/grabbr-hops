//! Switching a device off closes the link this machine dialled to it, and
//! switching it back on dials it again (#218).
//!
//! Runs the built daemon. Its dummy capture crosses at the left edge a
//! thousand times a second, so a device on the left that is switched on is
//! dialled the way any device the pointer crosses to is. The receiver is a
//! QUIC server that answers pings as a machine whose input emulation works,
//! trusted through the config tables an upgrade reads. The frontend is the
//! real IPC connector.
#![cfg(unix)]

mod common;

use std::cell::Cell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use hops_ipc::{FrontendEvent, FrontendRequest, Position};
use hops_proto::{MAX_EVENT_SIZE, ProtoEvent};

/// Generous: a daemon started under a loaded test run can be slow to dial.
const PATIENCE: Duration = Duration::from_secs(20);

/// How many links the receiver has seen open, and how many of them closed.
#[derive(Clone, Default)]
struct Links {
    opened: Rc<Cell<u32>>,
    closed: Rc<Cell<u32>>,
}

/// A receiver that answers every ping with "my input emulation is on", and
/// counts the links made to it.
fn receiver(identity: &common::Identity) -> (quinn::Endpoint, Links) {
    let ep = quinn::Endpoint::server(
        identity.server_config(),
        "127.0.0.1:0".parse().expect("addr"),
    )
    .expect("server");
    let links = Links::default();
    let (accepting, counting) = (ep.clone(), links.clone());
    tokio::task::spawn_local(async move {
        while let Some(incoming) = accepting.accept().await {
            let links = counting.clone();
            tokio::task::spawn_local(async move {
                let Ok(conn) = incoming.await else { return };
                links.opened.set(links.opened.get() + 1);
                let answering = conn.clone();
                tokio::task::spawn_local(async move {
                    let Ok(mut input) = answering.accept_uni().await else {
                        return;
                    };
                    let Ok(mut replies) = answering.open_uni().await else {
                        return;
                    };
                    let (pong, len): ([u8; MAX_EVENT_SIZE], usize) = ProtoEvent::Pong(true).into();
                    let mut frame = vec![len as u8];
                    frame.extend_from_slice(&pong[..len]);
                    while let Some(event) = common::read(&mut input).await {
                        if matches!(event, ProtoEvent::Ping)
                            && replies.write_all(&frame).await.is_err()
                        {
                            return;
                        }
                    }
                });
                conn.closed().await;
                links.closed.set(links.closed.get() + 1);
            });
        }
    });
    (ep, links)
}

async fn wait_for(what: &str, log: impl Fn() -> String, done: impl Fn() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while !done() {
        assert!(
            Instant::now() < deadline,
            "timed out after {PATIENCE:?} waiting for {what}; log:\n{}",
            log()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// LEDGER T2184 | class B | 5 process: the built daemon over IPC; 2 links opened and closed at a QUIC receiver
#[test]
fn switching_a_device_off_closes_its_link_and_switching_it_on_dials_again() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    tokio::task::LocalSet::new().block_on(&rt, async {
        let identity = common::Identity::new();
        let (receiver, links) = receiver(&identity);
        let port = receiver.local_addr().expect("local addr").port();
        let fp = identity.fingerprint();
        // A second device on the same edge, switched off, pointing at a port
        // nothing answers on.
        let nowhere = std::net::UdpSocket::bind("127.0.0.1:0")
            .and_then(|s| s.local_addr())
            .expect("a free port")
            .port();
        let (daemon, _) = common::start(
            "h-switch",
            &format!(
                "[authorized_fingerprints]\n\"{fp}\" = \"receiver\"\n\n\
                 [[clients]]\nposition = \"left\"\nips = [\"127.0.0.1\"]\nport = {port}\n\
                 fingerprint = \"{fp}\"\nactivate_on_startup = true\n\n\
                 [[clients]]\nposition = \"left\"\nips = [\"127.0.0.1\"]\nport = {nowhere}\n"
            ),
        );
        let log = || daemon.log();
        let (mut events, mut requests) = hops_ipc::connect_async(Some(Duration::from_secs(10)))
            .await
            .expect("a frontend connects");
        requests
            .request(FrontendRequest::Enumerate())
            .await
            .expect("enumerate");
        let (handle, other) = common::next_matching(&mut events, Duration::from_secs(10), |e| {
            let FrontendEvent::Enumerate(clients) = e else {
                return None;
            };
            let at = |p: u16| {
                clients
                    .iter()
                    .find(|(_, c, _)| c.pos == Position::Left && c.port == p)
                    .map(|(h, _, _)| *h)
            };
            Some((at(port)?, at(nowhere)?))
        })
        .await
        .expect("the configured devices are listed");

        wait_for("the device to be dialled", log, || links.opened.get() > 0).await;

        // Switched off: the link it dialled closes at the receiver.
        requests
            .request(FrontendRequest::Activate(handle, false))
            .await
            .expect("switch off");
        wait_for("the link to the switched-off device to close", log, || {
            links.closed.get() >= links.opened.get()
        })
        .await;
        let shown_down = common::next_matching(&mut events, PATIENCE, |e| match e {
            FrontendEvent::State(h, _, s)
                if h == handle && !s.active && s.active_addr.is_none() =>
            {
                Some(())
            }
            _ => None,
        })
        .await;
        assert!(
            shown_down.is_some(),
            "the link to the switched-off device closed and the app was not told; log:\n{}",
            log()
        );

        // Nothing dials it while it is off, though the pointer keeps crossing
        // that edge.
        let at_off = links.opened.get();
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(
            links.opened.get(),
            at_off,
            "a switched-off device was dialled again; log:\n{}",
            log()
        );

        // Switched back on: dialled again, as any device that is on is.
        requests
            .request(FrontendRequest::Activate(handle, true))
            .await
            .expect("switch on");
        wait_for("the device to be dialled again", log, || {
            links.opened.get() > at_off && links.closed.get() < links.opened.get()
        })
        .await;

        // Another device switched on at the same edge switches this one off,
        // which closes its link too.
        requests
            .request(FrontendRequest::Activate(other, true))
            .await
            .expect("switch the other device on");
        wait_for(
            "the link to the device switched off for another to close",
            log,
            || links.closed.get() >= links.opened.get(),
        )
        .await;
    });
}
