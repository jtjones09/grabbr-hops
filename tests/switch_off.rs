//! Switching a device off closes the link this machine dialled to it, even
//! after an edit made the device forget which machine it reached, and
//! switching it back on dials it again. The session that machine opened to
//! this one stays up, and none of its clipboard is applied here (#218).
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

use hops_ipc::{
    AsyncFrontendEventReader, AsyncFrontendRequestWriter, FrontendEvent, FrontendRequest, Position,
};
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

/// The daemon's reason for dropping clipboard text from a machine switched
/// off here.
const DROPPED: &str = "clipboard text dropped: its sender is switched off on this machine";

/// Wait until the app shows `handle`'s link up, which is when the daemon
/// holds it, not only when the receiver has counted it.
async fn shown_up(
    events: &mut AsyncFrontendEventReader,
    requests: &mut AsyncFrontendRequestWriter,
    handle: u64,
    log: impl Fn() -> String,
) {
    requests
        .request(FrontendRequest::Enumerate())
        .await
        .expect("enumerate");
    let up = common::next_matching(events, PATIENCE, |e| match e {
        FrontendEvent::State(h, _, s) if h == handle && s.active_addr.is_some() => Some(()),
        FrontendEvent::Enumerate(clients)
            if clients
                .iter()
                .any(|(h, _, s)| *h == handle && s.active_addr.is_some()) =>
        {
            Some(())
        }
        _ => None,
    })
    .await;
    assert!(
        up.is_some(),
        "the app never showed the device's link up; log:\n{}",
        log()
    );
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

// LEDGER T2184 | class B | 5 process: the built daemon over IPC, and its log; 2 links opened and closed at a QUIC receiver, and a session it opened to the daemon
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
        let (daemon, daemon_port) = common::start_paired(
            "h-switch",
            &format!(
                "[[clients]]\nposition = \"left\"\nips = [\"127.0.0.1\"]\nport = {port}\n\
                 fingerprint = \"{fp}\"\nactivate_on_startup = true\n\n\
                 [[clients]]\nposition = \"left\"\nips = [\"127.0.0.1\"]\nport = {nowhere}\n"
            ),
            &[(&fp, "receiver", common::BOTH_WAYS)],
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

        // The same machine also drives this one, over a session it opened.
        let (_its_endpoint, its_session) = identity
            .dial(daemon_port)
            .await
            .unwrap_or_else(|| panic!("the paired machine was refused; log:\n{}", log()));
        let mut its_input = its_session.open_uni().await.expect("input stream");
        common::write(&mut its_input, ProtoEvent::Ping).await;
        let connected = common::next_matching(&mut events, PATIENCE, |e| match e {
            FrontendEvent::DeviceConnected { fingerprint, .. } if fingerprint == fp => Some(()),
            _ => None,
        })
        .await;
        assert!(
            connected.is_some(),
            "the app never showed the session the machine opened; log:\n{}",
            log()
        );

        shown_up(&mut events, &mut requests, handle, log).await;

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

        // The session that machine opened is the pairing's, not the
        // switch's: still up. Its clipboard is the switch's: not applied.
        assert_eq!(
            its_session.close_reason(),
            None,
            "switching a device off closed the session its machine opened to this \
             one; log:\n{}",
            log()
        );
        let mut text = its_session.open_uni().await.expect("clipboard stream");
        text.write_all(b"its, switched off")
            .await
            .expect("clipboard text");
        text.finish().expect("finish");
        wait_for(
            "the text from the switched-off machine to be dropped",
            log,
            || log().contains(DROPPED),
        )
        .await;

        // Switched back on: dialled again, as any device that is on is.
        requests
            .request(FrontendRequest::Activate(handle, true))
            .await
            .expect("switch on");
        wait_for("the device to be dialled again", log, || {
            links.opened.get() > at_off && links.closed.get() < links.opened.get()
        })
        .await;
        shown_up(&mut events, &mut requests, handle, log).await;

        // Renamed while its link is up, the device forgets the machine it
        // reached until it dials again. Switched off then, its link still
        // closes.
        requests
            .request(FrontendRequest::UpdateHostname {
                handle,
                hostname: Some("127.0.0.1".into()),
                fingerprint: Some(fp.clone()),
            })
            .await
            .expect("rename");
        requests
            .request(FrontendRequest::Activate(handle, false))
            .await
            .expect("switch off");
        wait_for(
            "the link to the device renamed and switched off to close",
            log,
            || links.closed.get() >= links.opened.get(),
        )
        .await;

        // Switched on again, and then off by another device switched on at
        // the same edge: that closes its link too.
        let at_rename = links.opened.get();
        requests
            .request(FrontendRequest::Activate(handle, true))
            .await
            .expect("switch on");
        wait_for("the renamed device to be dialled again", log, || {
            links.opened.get() > at_rename && links.closed.get() < links.opened.get()
        })
        .await;
        shown_up(&mut events, &mut requests, handle, log).await;
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

        // Through all of it, the machine switched off here still drives this
        // one over the session it opened.
        common::write(
            &mut its_input,
            ProtoEvent::Enter(hops_proto::Position::Right),
        )
        .await;
        let entered = common::next_matching(&mut events, PATIENCE, |e| match e {
            FrontendEvent::DeviceEntered { fingerprint, .. } if fingerprint == fp => Some(()),
            _ => None,
        })
        .await;
        assert!(
            entered.is_some(),
            "a machine switched off here could no longer cross onto this one over \
             the session it opened; log:\n{}",
            log()
        );
    });
}
