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
    _clipboard: Receiver<String>,
    _untrusted: Receiver<(String, std::net::SocketAddr)>,
    _persist: Receiver<ClientHandle>,
    /// Which client's live state changed: what the service republishes to
    /// the frontend.
    pub(crate) state: Receiver<ClientHandle>,
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
            _clipboard: clipboard,
            _untrusted: untrusted,
            _persist: persist,
            state,
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
