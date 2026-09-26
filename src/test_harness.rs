//! Two machines in one test process, talking over loopback QUIC.
//!
//! Everything here is the production code path except the device ends: the
//! receiver injects into [`input_emulation::recording::Recording`] and the
//! sender captures from [`input_capture::scripted::Script`]. The listener binds
//! 127.0.0.1 on a port the OS picks, so a test neither listens on the network
//! nor collides with a daemon running on the same machine. No test here reads
//! or writes the real config, token or trust files.

use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, RwLock},
    time::Duration,
};

use hops_ipc::{ClientHandle, Position};
use hops_proto::ProtoEvent;
use local_channel::mpsc::{Receiver, channel};

use crate::{
    client::ClientManager,
    connect::LanMouseConnection,
    crypto::Identity,
    transport::{self, Trust},
    trust::{Caps, TrustStore},
};

/// Run `f` the way the daemon runs: one thread, inside a `LocalSet`.
pub(crate) fn run_local<F: Future>(f: F) -> F::Output {
    transport::install_crypto_provider();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    tokio::task::LocalSet::new().block_on(&rt, f)
}

/// One machine's identity.
pub(crate) struct Machine {
    pub(crate) identity: Arc<Identity>,
    pub(crate) fingerprint: String,
}

pub(crate) fn machine() -> Machine {
    let key_pair = rcgen::KeyPair::generate().expect("keypair");
    let mut params = rcgen::CertificateParams::new(vec!["grabbr".to_owned()]).expect("params");
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "grabbr-hop");
    let cert = params.self_signed(&key_pair).expect("self signed");
    let identity = Identity {
        cert: cert.der().clone(),
        key: rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der()).expect("key der"),
    };
    let fingerprint = transport::fingerprint_of(&identity.cert);
    Machine {
        identity: Arc::new(identity),
        fingerprint,
    }
}

/// `us`'s store, granting each of `peers` exactly `caps` and nothing else.
pub(crate) fn trust(us: &Machine, peers: &[&Machine], caps: Caps) -> Trust {
    let mut store = TrustStore::new(&us.fingerprint, 0).expect("our fingerprint");
    for peer in peers {
        store.issue(&peer.fingerprint, "peer", caps).expect("issue");
    }
    Arc::new(RwLock::new(store))
}

/// A client config for a test that dials the listener itself, with a stream
/// receive window it chooses.
///
/// The real dialler's window is far larger than a test can fill, and a test
/// about a peer that stops reading has to fill one.
pub(crate) fn raw_client_config(
    me: &Machine,
    trust: Trust,
    stream_window: u32,
) -> quinn::ClientConfig {
    let verifier = Arc::new(transport::FpServerVerifier::new(
        trust,
        Arc::new(std::sync::Mutex::new(None)),
    ));
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![me.identity.cert.clone()], me.identity.key.clone_key())
        .expect("client auth");
    crypto.alpn_protocols = vec![transport::ALPN.to_vec()];
    let mut config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("quic client"),
    ));
    let mut transport_config = quinn::TransportConfig::default();
    // MUST be > 0 or the receiver's reply stream is never accepted.
    transport_config.max_concurrent_uni_streams(8u8.into());
    transport_config.stream_receive_window(stream_window.into());
    config.transport_config(Arc::new(transport_config));
    config
}

/// Poll `look` until it answers, and give that answer; panic naming `what` if
/// it does not within `limit`.
pub(crate) async fn wait_for<T, F: Future<Output = Option<T>>>(
    what: &str,
    limit: Duration,
    mut look: impl FnMut() -> F,
) -> T {
    let deadline = std::time::Instant::now() + limit;
    loop {
        if let Some(found) = look().await {
            return found;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Poll `done` until it holds; panic naming `what` if it does not within `limit`.
pub(crate) async fn wait_until(what: &str, limit: Duration, mut done: impl FnMut() -> bool) {
    let started = tokio::time::Instant::now();
    while !done() {
        assert!(
            started.elapsed() < limit,
            "timed out after {limit:?} waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// The dialling half: one active client at 127.0.0.1:`port`, and the real
/// connection that dials it on first send.
pub(crate) struct Dialer {
    pub(crate) conn: LanMouseConnection,
    pub(crate) clients: ClientManager,
    pub(crate) handle: ClientHandle,
    /// Where the connection's notifications go. Keep it alive for as long as
    /// the connection is.
    pub(crate) notices: Notices,
}

pub(crate) struct Notices {
    /// Clipboard text this machine's transport received and queued for the
    /// service.
    pub(crate) clipboard: Receiver<crate::transport::PeerClipboard>,
    _untrusted: Receiver<(String, std::net::SocketAddr)>,
    _persist: Receiver<ClientHandle>,
    _state: Receiver<ClientHandle>,
}

pub(crate) fn dialer(me: &Machine, trust: Trust, port: u16, pos: Position) -> Dialer {
    let clients = ClientManager::default();
    let handle = clients.add_client();
    clients.set_fix_ips(handle, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    clients.set_port(handle, port);
    clients.set_pos(handle, pos);
    clients.activate_client(handle);
    let (clipboard_tx, clipboard) = channel();
    let (untrusted_tx, untrusted) = channel();
    let (persist_tx, persist) = channel();
    let (state_tx, state) = channel();
    let conn = LanMouseConnection::new(
        me.identity.clone(),
        clients.clone(),
        trust,
        clipboard_tx,
        untrusted_tx,
        persist_tx,
        state_tx,
    )
    .expect("client endpoint");
    Dialer {
        conn,
        clients,
        handle,
        notices: Notices {
            clipboard,
            _untrusted: untrusted,
            _persist: persist,
            _state: state,
        },
    }
}

impl Dialer {
    /// Dial, and wait until the receiver has answered that it is injecting.
    pub(crate) async fn until_alive(&self) {
        let limit = Duration::from_secs(20);
        let started = tokio::time::Instant::now();
        while !self.clients.alive(self.handle) {
            assert!(
                started.elapsed() < limit,
                "the receiver never reported emulation active within {limit:?}"
            );
            // The first send starts the dial; the ones after it return
            // NotConnected or TargetEmulationDisabled until the Pong lands.
            let _ = self.conn.send(ProtoEvent::Ping, self.handle).await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Send one event, which must reach the wire.
    pub(crate) async fn send(&self, event: ProtoEvent) {
        self.conn
            .send(event, self.handle)
            .await
            .unwrap_or_else(|e| panic!("sending {event}: {e}"));
    }
}

/// Two paired machines with a link up between them: `driver` dialled
/// `driven`, as a pairing's first crossing does. Each end's clipboard
/// broadcast is the production one, and each end's queue is what its
/// transport handed on towards the service.
pub(crate) struct ClipboardPair {
    pub(crate) driven: Machine,
    pub(crate) driven_trust: Trust,
    pub(crate) driven_sends: crate::listen::ClipboardSenderListen,
    /// What the driven machine's transport queued for its service.
    pub(crate) driven_heard: Receiver<crate::transport::PeerClipboard>,
    _listener: crate::listen::LanMouseListener,
    pub(crate) driver: Machine,
    pub(crate) driver_trust: Trust,
    pub(crate) driver_sends: crate::connect::ClipboardSender,
    pub(crate) dialer: Dialer,
}

/// [`ClipboardPair`], each machine holding the store given for it.
pub(crate) async fn clipboard_pair(
    driven: Machine,
    driven_store: TrustStore,
    driver: Machine,
    driver_store: TrustStore,
) -> ClipboardPair {
    use futures::StreamExt;
    let driven_trust: Trust = Arc::new(RwLock::new(driven_store));
    let driver_trust: Trust = Arc::new(RwLock::new(driver_store));
    let (heard_tx, driven_heard) = channel();
    let (mut listener, port) = crate::listen::LanMouseListener::bind_loopback(
        driven.identity.clone(),
        driven_trust.clone(),
        heard_tx,
    )
    .await
    .expect("listener");
    let driven_sends = listener.clipboard_sender();
    let dialer = dialer(&driver, driver_trust.clone(), port, Position::Left);
    dialer.conn.dial(dialer.handle).await;
    let accepted = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(event) = listener.next().await {
            if let crate::listen::ListenEvent::Accept { .. } = event {
                return true;
            }
        }
        false
    })
    .await;
    assert!(
        matches!(accepted, Ok(true)),
        "the driven machine never accepted the driver's link"
    );
    wait_until(
        "the driver to hold its link",
        Duration::from_secs(10),
        || dialer.conn.active_addr(dialer.handle).is_some(),
    )
    .await;
    let driver_sends = dialer.conn.clipboard_sender();
    ClipboardPair {
        driven,
        driven_trust,
        driven_sends,
        driven_heard,
        _listener: listener,
        driver,
        driver_trust,
        driver_sends,
        dialer,
    }
}

/// How long a test waits for text that must arrive.
pub(crate) const ARRIVES_WITHIN: Duration = Duration::from_secs(5);
/// How long a test waits before concluding text that must not arrive did not.
/// Loopback delivers in well under a millisecond.
pub(crate) const NEVER_WITHIN: Duration = Duration::from_secs(1);

/// The next item on `rx`, or `None` if nothing came within `limit`.
pub(crate) async fn next_within<T>(rx: &mut Receiver<T>, limit: Duration) -> Option<T> {
    tokio::time::timeout(limit, rx.recv()).await.ok().flatten()
}

/// The text of the next transfer queued on `rx`, and whose it says it is.
pub(crate) async fn heard_within(
    rx: &mut Receiver<crate::transport::PeerClipboard>,
    limit: Duration,
) -> Option<(String, String)> {
    next_within(rx, limit).await.map(|c| (c.text, c.from))
}

impl ClipboardPair {
    /// Each machine's queue behind the check the service makes before it
    /// applies text, driven machine first. Takes the queues: what the
    /// transports hand on is then only seen through the check.
    pub(crate) fn inboxes(
        &mut self,
    ) -> (
        crate::clipboard::ClipboardInbox,
        crate::clipboard::ClipboardInbox,
    ) {
        let driven = std::mem::replace(&mut self.driven_heard, channel().1);
        let driver = std::mem::replace(&mut self.dialer.notices.clipboard, channel().1);
        (
            crate::clipboard::ClipboardInbox::new(driven, self.driven_trust.clone()),
            crate::clipboard::ClipboardInbox::new(driver, self.driver_trust.clone()),
        )
    }
}

/// The next text `inbox` lets through, or `None` if nothing did within `limit`.
pub(crate) async fn applied_within(
    inbox: &mut crate::clipboard::ClipboardInbox,
    limit: Duration,
) -> Option<String> {
    tokio::time::timeout(limit, inbox.next())
        .await
        .ok()
        .flatten()
}
