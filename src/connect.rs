use crate::client::ClientManager;
use crate::config::{local_caps, local_commit};
use crate::crypto::Identity;
use crate::transport::{self, Authorized, FpServerVerifier};
use hops_ipc::{ClientHandle, DEFAULT_PORT};
use hops_proto::ProtoEvent;
use local_channel::mpsc::{Receiver, Sender, channel};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Connection, Endpoint, SendStream, TransportConfig};
use rustls::pki_types::CertificateDer;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    io,
    net::SocketAddr,
    rc::Rc,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};
use thiserror::Error;
use tokio::{
    sync::Mutex,
    task::{JoinSet, spawn_local},
};

#[derive(Debug, Error)]
pub(crate) enum LanMouseConnectionError {
    #[error(transparent)]
    Bind(#[from] io::Error),
    #[error(transparent)]
    Connect(#[from] quinn::ConnectError),
    #[error(transparent)]
    Connection(#[from] quinn::ConnectionError),
    #[error(transparent)]
    Frame(#[from] transport::FrameError),
    #[error("not connected")]
    NotConnected,
    #[error("emulation is disabled on the target device")]
    TargetEmulationDisabled,
    #[error("connection timed out")]
    Timeout,
    #[error("receiver fingerprint did not match the expected identity")]
    FingerprintMismatch,
}

const DEFAULT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
const KEEP_ALIVE: Duration = Duration::from_secs(8);
const MAX_IDLE: Duration = Duration::from_secs(20);

/// A live connection to one peer: the quinn connection plus our long-lived
/// reliable outbound stream (one uni stream per direction).
#[derive(Clone)]
struct PeerLink {
    conn: Connection,
    send: Arc<Mutex<SendStream>>,
}

fn client_config(
    identity: &Identity,
    authorized: Authorized,
    observed: Arc<StdMutex<Option<String>>>,
) -> ClientConfig {
    let verifier = Arc::new(FpServerVerifier::new(authorized, observed));
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![identity.cert.clone()], identity.key.clone_key())
        .expect("client auth cert");
    crypto.alpn_protocols = vec![transport::ALPN.to_vec()];
    let mut config = ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto).expect("quic client config"),
    ));
    let mut transport_config = TransportConfig::default();
    // MUST be > 0 or the receiver's reply uni stream is never accepted.
    transport_config.max_concurrent_uni_streams(8u8.into());
    transport_config.keep_alive_interval(Some(KEEP_ALIVE));
    transport_config.max_idle_timeout(Some(MAX_IDLE.try_into().expect("idle timeout")));
    config.transport_config(Arc::new(transport_config));
    config
}

/// Fingerprint of the peer's leaf cert from a completed handshake. quinn hands
/// the presented chain as `Vec<CertificateDer>`. Reading it off the specific
/// connection is race-free, unlike the shared `observed` slot (which concurrent
/// dials to other handles can clobber). Mirrors `listen::peer_fingerprint`.
fn peer_fingerprint(conn: &Connection) -> Option<String> {
    let identity = conn.peer_identity()?;
    let certs = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    certs.first().map(transport::fingerprint_of)
}

async fn connect(
    endpoint: Endpoint,
    addr: SocketAddr,
    expected_fp: Option<String>,
) -> Result<(PeerLink, SocketAddr), (SocketAddr, LanMouseConnectionError)> {
    log::info!("connecting to {addr} ...");
    // server_name is the SNI label; trust is by fingerprint, so it is not
    // trust-relevant — a fixed label is fine.
    let connecting = endpoint.connect(addr, "grabbr").map_err(|e| (addr, e.into()))?;
    let conn = match tokio::time::timeout(DEFAULT_CONNECTION_TIMEOUT, connecting).await {
        Err(_) => return Err((addr, LanMouseConnectionError::Timeout)),
        Ok(Err(e)) => return Err((addr, e.into())),
        Ok(Ok(conn)) => conn,
    };
    // Fail-closed fingerprint pin. `FpServerVerifier` only proves the receiver
    // is *some* allowlisted peer; when this client's identity is already known
    // (a prior handshake, or later a pairing code), the raced address MUST
    // present that exact leaf-cert fingerprint — otherwise a poisoned or
    // ambiguous address that completes an allowlisted handshake could win the
    // race and receive input meant for a different machine.
    if let Some(expected) = &expected_fp {
        let actual = peer_fingerprint(&conn);
        if actual.as_deref() != Some(expected.as_str()) {
            log::warn!(
                "{addr}: receiver fingerprint {} != expected {expected}; rejecting",
                actual.as_deref().unwrap_or("<none>")
            );
            conn.close(0u32.into(), b"fingerprint mismatch");
            return Err((addr, LanMouseConnectionError::FingerprintMismatch));
        }
    }
    let send = conn.open_uni().await.map_err(|e| (addr, e.into()))?;
    Ok((
        PeerLink {
            conn,
            send: Arc::new(Mutex::new(send)),
        },
        addr,
    ))
}

async fn connect_any(
    endpoint: &Endpoint,
    addrs: &[SocketAddr],
    expected_fp: Option<String>,
) -> Result<(PeerLink, SocketAddr), LanMouseConnectionError> {
    let mut joinset = JoinSet::new();
    for &addr in addrs {
        let endpoint = endpoint.clone();
        let expected = expected_fp.clone();
        joinset.spawn_local(connect(endpoint, addr, expected));
    }
    // if every candidate failed the identity pin (not a transport error), surface
    // that distinctly so the caller logs the right recovery guidance.
    let mut only_mismatch = !addrs.is_empty();
    loop {
        match joinset.join_next().await {
            None => {
                return Err(if only_mismatch {
                    LanMouseConnectionError::FingerprintMismatch
                } else {
                    LanMouseConnectionError::NotConnected
                });
            }
            Some(r) => match r.expect("join error") {
                Ok(conn) => return Ok(conn),
                Err((a, e)) => {
                    if !matches!(e, LanMouseConnectionError::FingerprintMismatch) {
                        only_mismatch = false;
                    }
                    log::warn!("failed to connect to {a}: `{e}`");
                }
            },
        };
    }
}

pub(crate) struct LanMouseConnection {
    endpoint: Endpoint,
    client_manager: ClientManager,
    conns: Rc<Mutex<HashMap<SocketAddr, PeerLink>>>,
    connecting: Rc<Mutex<HashSet<ClientHandle>>>,
    recv_rx: Receiver<(ClientHandle, ProtoEvent)>,
    recv_tx: Sender<(ClientHandle, ProtoEvent)>,
    ping_response: Rc<RefCell<HashSet<SocketAddr>>>,
    /// last receiver fingerprint observed during a handshake, for logging.
    observed: Arc<StdMutex<Option<String>>>,
    /// inbound clipboard text received from peers, forwarded to the service.
    clipboard_in: Sender<String>,
    /// signals the service that this client's peer_fingerprint was just learned,
    /// so it can persist it AND push the new state to the frontend. Without this
    /// the join key is in-memory only and never reaches the UI, so every device
    /// renders as two cards -- one client row, one trusted row.
    persist_tx: Sender<ClientHandle>,
    /// fingerprint of a receiver we tried to dial but do not trust. The service
    /// turns this into a `ConnectionAttempt` so the UI can offer to authorize it
    /// — without this, an untrusted RECEIVER is only ever a log line and the user
    /// has no in-app way to trust it (the inbound path has had a prompt all
    /// along; the outbound path never did).
    untrusted_tx: Sender<String>,
}

impl LanMouseConnection {
    pub(crate) fn new(
        identity: Arc<Identity>,
        client_manager: ClientManager,
        authorized: Authorized,
        clipboard_in: Sender<String>,
        untrusted_tx: Sender<String>,
        persist_tx: Sender<ClientHandle>,
    ) -> Result<Self, LanMouseConnectionError> {
        transport::install_crypto_provider();
        let observed = Arc::new(StdMutex::new(None));
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().expect("valid addr"))?;
        endpoint.set_default_client_config(client_config(&identity, authorized, observed.clone()));
        let (recv_tx, recv_rx) = channel();
        Ok(Self {
            endpoint,
            client_manager,
            conns: Default::default(),
            connecting: Default::default(),
            recv_rx,
            recv_tx,
            ping_response: Default::default(),
            observed,
            clipboard_in,
            untrusted_tx,
            persist_tx,
        })
    }

    pub(crate) async fn recv(&mut self) -> (ClientHandle, ProtoEvent) {
        self.recv_rx.recv().await.expect("channel closed")
    }

    /// Whether the peer for `handle` advertised support for `cap` (a
    /// [`hops_proto::caps`] bit) via the Capability handshake. False if no
    /// Capability was received (older peer, or not yet negotiated), so
    /// capability-gated emissions fall back to the pre-capability behavior.
    pub(crate) fn peer_supports(&self, handle: ClientHandle, cap: u32) -> bool {
        self.client_manager.peer_caps(handle) & cap != 0
    }

    /// A handle for broadcasting local clipboard changes to all connected
    /// peers. Grabbed before this connection is moved into `Capture` so the
    /// service can drive it directly.
    pub(crate) fn clipboard_sender(&self) -> ClipboardSender {
        ClipboardSender {
            conns: self.conns.clone(),
        }
    }

    pub(crate) async fn send(
        &self,
        event: ProtoEvent,
        handle: ClientHandle,
    ) -> Result<(), LanMouseConnectionError> {
        if let Some(addr) = self.client_manager.active_addr(handle) {
            let link = {
                let conns = self.conns.lock().await;
                conns.get(&addr).cloned()
            };
            if let Some(link) = link {
                if !self.client_manager.alive(handle) {
                    return Err(LanMouseConnectionError::TargetEmulationDisabled);
                }
                let result = {
                    let mut send = link.send.lock().await;
                    transport::write_frame(&mut send, event).await
                };
                if let Err(e) = result {
                    log::warn!("client {handle} failed to send: {e}");
                    disconnect(&self.client_manager, handle, addr, &self.conns).await;
                } else {
                    log::trace!("{event} >->->->->- {addr}");
                }
                return Ok(());
            }
        }

        // not connected yet — connect in the background (lazy connect)
        let mut connecting = self.connecting.lock().await;
        if !connecting.contains(&handle) {
            connecting.insert(handle);
            spawn_local(connect_to_handle(
                self.endpoint.clone(),
                self.client_manager.clone(),
                handle,
                self.conns.clone(),
                self.connecting.clone(),
                self.recv_tx.clone(),
                self.ping_response.clone(),
                self.observed.clone(),
                self.clipboard_in.clone(),
                self.untrusted_tx.clone(),
                self.persist_tx.clone(),
            ));
        }
        Err(LanMouseConnectionError::NotConnected)
    }
}

/// Broadcasts clipboard text to every connected peer, each on its own
/// ephemeral uni stream. Cloneable handle over the shared connection map.
#[derive(Clone)]
pub(crate) struct ClipboardSender {
    conns: Rc<Mutex<HashMap<SocketAddr, PeerLink>>>,
}

impl ClipboardSender {
    pub(crate) async fn broadcast(&self, text: String) {
        let conns: Vec<Connection> = {
            let conns = self.conns.lock().await;
            conns.values().map(|l| l.conn.clone()).collect()
        };
        for conn in conns {
            let text = text.clone();
            spawn_local(async move {
                match tokio::time::timeout(
                    transport::CLIPBOARD_IO_TIMEOUT,
                    transport::send_clipboard(&conn, &text),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => log::debug!("clipboard broadcast failed: {e}"),
                    // dropping the send future on timeout abandons a stuck
                    // open_uni/write instead of pinning the task indefinitely
                    Err(_) => log::debug!("clipboard broadcast timed out"),
                }
            });
        }
    }
}

/// Rebind the client endpoint to a fresh OS-chosen UDP socket. quinn pins a
/// per-path source IP at the QUIC handshake; after a sleep/wake or interface
/// bounce that IP can vanish, and every send then fails with EADDRNOTAVAIL —
/// which quinn-udp silently swallows (treats UDP loss as non-fatal), so the
/// reconnect machinery never sees it and the reused endpoint keeps selecting the
/// dead source IP. Swapping in a fresh socket before each (re)connect forces
/// quinn to re-select the source address against the current interface table.
/// Idempotent + cheap on cold start; on bind error the old socket is retained.
fn rebind_endpoint(endpoint: &Endpoint) {
    match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(sock) => match endpoint.rebind(sock) {
            Ok(()) => {
                log::info!("rebound client endpoint to a fresh socket (interface/wake recovery)")
            }
            Err(e) => log::warn!("endpoint rebind failed, keeping existing socket: {e}"),
        },
        Err(e) => log::warn!("could not bind a fresh socket to rebind endpoint: {e}"),
    }
}

#[allow(clippy::too_many_arguments)]
async fn connect_to_handle(
    endpoint: Endpoint,
    client_manager: ClientManager,
    handle: ClientHandle,
    conns: Rc<Mutex<HashMap<SocketAddr, PeerLink>>>,
    connecting: Rc<Mutex<HashSet<ClientHandle>>>,
    tx: Sender<(ClientHandle, ProtoEvent)>,
    ping_response: Rc<RefCell<HashSet<SocketAddr>>>,
    observed: Arc<StdMutex<Option<String>>>,
    clipboard_in: Sender<String>,
    untrusted_tx: Sender<String>,
    persist_tx: Sender<ClientHandle>,
) -> Result<(), LanMouseConnectionError> {
    log::info!("client {handle} connecting ...");
    // Swap in a fresh UDP socket before every (re)connect so a sleep/wake or
    // interface change can't strand us on a dead source IP (see rebind_endpoint).
    rebind_endpoint(&endpoint);
    if let Some(addrs) = client_manager.get_ips(handle) {
        let port = client_manager.get_port(handle).unwrap_or(DEFAULT_PORT);
        let addrs = addrs
            .into_iter()
            .map(|a| SocketAddr::new(a, port))
            .collect::<Vec<_>>();
        log::info!("client ({handle}) connecting ... (ips: {addrs:?})");
        // Pin to the client's known identity (if any) so the parallel race
        // fails closed against a wrong-but-allowlisted receiver at a raced addr.
        let expected_fp = client_manager.peer_fingerprint(handle);
        let (link, addr) = match connect_any(&endpoint, &addrs, expected_fp).await {
            Ok(c) => c,
            Err(e) => {
                connecting.lock().await.remove(&handle);
                match e {
                    // handshake succeeded but the identity didn't match the pin —
                    // NOT an authorization failure (the presented fp IS allowlisted).
                    LanMouseConnectionError::FingerprintMismatch => log::warn!(
                        "client {handle}: the receiver answered but its fingerprint did \
                         not match the pinned identity — the target address may point at \
                         a different machine, or the receiver re-keyed (reinstall). If it \
                         re-keyed, remove the old fingerprint from authorized_fingerprints \
                         and authorize the new one."
                    ),
                    _ => {
                        if let Some(fp) = observed.lock().expect("lock").take() {
                            log::warn!(
                                "client {handle}: receiver fingerprint {fp} is not \
                                 authorized — prompting to trust it"
                            );
                            // Hand it to the service, which checks it against the
                            // allowlist and raises a ConnectionAttempt if it really
                            // is untrusted. Filtering lives there because that is
                            // where the allowlist lives.
                            let _ = untrusted_tx.send(fp);
                        }
                    }
                }
                return Err(e);
            }
        };
        log::info!("client ({handle}) connected @ {addr}");
        // Stamp the receiver's leaf-cert fingerprint from THIS connection — the
        // pin identity + the key the frontend uses to correlate this client with
        // its authorized_fingerprints entry. Only overwrite on a real read: a
        // None from an accepted handshake (shouldn't happen) must NOT wipe a good
        // prior pin — that would fail OPEN on the next dial.
        match peer_fingerprint(&link.conn) {
            Some(fp) => {
                let is_new = client_manager.peer_fingerprint(handle).as_deref() != Some(fp.as_str());
                log::info!("client {handle} receiver fingerprint: {fp}");
                client_manager.set_peer_fingerprint(handle, Some(fp));
                // persist it so the device view can join from a cold start
                if is_new {
                    let _ = persist_tx.send(handle);
                }
            }
            None => log::warn!(
                "client {handle}: connected but could not read the receiver's \
                 leaf-cert fingerprint; keeping any prior pin"
            ),
        }
        client_manager.set_active_addr(handle, Some(addr));
        conns.lock().await.insert(addr, link.clone());
        connecting.lock().await.remove(&handle);

        // Best-effort version + capability handshake (see ProtoEvent::Hello and
        // ProtoEvent::Capability docs). Both writes share the one send guard so
        // the ping_pong task (spawned just below) can't wedge a Ping between
        // them — the peer observes Hello then Capability, in order.
        {
            let mut send = link.send.lock().await;
            if let Err(e) = transport::write_frame(
                &mut send,
                ProtoEvent::Hello {
                    commit: local_commit(),
                },
            )
            .await
            {
                log::debug!("hello send to {addr} failed: {e}");
            }
            if let Err(e) =
                transport::write_frame(&mut send, ProtoEvent::Capability { flags: local_caps() })
                    .await
            {
                log::debug!("capability send to {addr} failed: {e}");
            }
        }

        spawn_local(ping_pong(
            client_manager.clone(),
            handle,
            addr,
            link.clone(),
            conns.clone(),
            ping_response.clone(),
        ));
        spawn_local(receive_loop(
            client_manager,
            handle,
            addr,
            link,
            conns,
            tx,
            ping_response.clone(),
            clipboard_in,
        ));
        return Ok(());
    }
    connecting.lock().await.remove(&handle);
    Err(LanMouseConnectionError::NotConnected)
}

async fn ping_pong(
    client_manager: ClientManager,
    handle: ClientHandle,
    addr: SocketAddr,
    link: PeerLink,
    conns: Rc<Mutex<HashMap<SocketAddr, PeerLink>>>,
    ping_response: Rc<RefCell<HashSet<SocketAddr>>>,
) {
    loop {
        // send 4 pings, at least one must be answered
        for _ in 0..4 {
            let result = {
                let mut send = link.send.lock().await;
                transport::write_frame(&mut send, ProtoEvent::Ping).await
            };
            if let Err(e) = result {
                log::warn!("{addr}: send error `{e}`, closing connection");
                disconnect(&client_manager, handle, addr, &conns).await;
                return;
            }
            log::trace!("PING >->->->->- {addr}");
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        // Liveness is QUIC's job now (keep-alive + idle timeout). A missed pong
        // under load — e.g. the Pong head-of-line-blocked behind input on the
        // shared reliable stream — must NOT tear down the connection; that false
        // teardown was triggering release_keys and the stuck-key cascade. We
        // keep pinging only to refresh the Pong's emulation-enabled bit; a truly
        // dead link surfaces as a write error above (and a read error in the
        // receive loop).
        let _ = ping_response.borrow_mut().remove(&addr);
    }
}

async fn receive_loop(
    client_manager: ClientManager,
    handle: ClientHandle,
    addr: SocketAddr,
    link: PeerLink,
    conns: Rc<Mutex<HashMap<SocketAddr, PeerLink>>>,
    tx: Sender<(ClientHandle, ProtoEvent)>,
    ping_response: Rc<RefCell<HashSet<SocketAddr>>>,
    clipboard_in: Sender<String>,
) {
    // the peer's reliable inbound stream (their uni stream to us)
    let mut recv = match link.conn.accept_uni().await {
        Ok(recv) => recv,
        Err(e) => {
            log::warn!("{addr}: no inbound stream: {e}");
            disconnect(&client_manager, handle, addr, &conns).await;
            return;
        }
    };
    // The reply stream above is accepted first (opened at connection setup);
    // clipboard transfers ride the subsequent uni streams on this connection.
    spawn_local(clipboard_accept_loop(link.conn.clone(), addr, clipboard_in));
    loop {
        match transport::read_frame(&mut recv).await {
            Ok(Some(event)) => {
                log::trace!("{addr} <==<==<== {event}");
                match event {
                    ProtoEvent::Pong(b) => {
                        client_manager.set_active_addr(handle, Some(addr));
                        client_manager.set_alive(handle, b);
                        ping_response.borrow_mut().insert(addr);
                    }
                    ProtoEvent::Hello { commit } => {
                        client_manager.set_peer_commit(handle, Some(commit));
                    }
                    ProtoEvent::Capability { flags } => {
                        client_manager.set_peer_caps(handle, Some(flags));
                    }
                    event => {
                        let _ = tx.send((handle, event));
                    }
                }
            }
            // clean stream end
            Ok(None) => break,
            // unknown/forward-compat event: framing is intact, keep going
            Err(transport::FrameError::Protocol(e)) => {
                log::debug!("ignoring undecodable event from {addr}: {e}")
            }
            // anything else means the stream is dead/desynced
            Err(e) => {
                log::warn!("{addr}: recv error: {e}");
                break;
            }
        }
    }
    disconnect(&client_manager, handle, addr, &conns).await;
}

async fn disconnect(
    client_manager: &ClientManager,
    handle: ClientHandle,
    addr: SocketAddr,
    conns: &Mutex<HashMap<SocketAddr, PeerLink>>,
) {
    log::warn!("client ({handle}) @ {addr} connection closed");
    if let Some(link) = conns.lock().await.remove(&addr) {
        link.conn.close(0u32.into(), b"bye");
    }
    client_manager.set_active_addr(handle, None);
    client_manager.set_peer_commit(handle, None);
    client_manager.set_peer_caps(handle, None);
    // NB: peer_fingerprint is deliberately NOT cleared here — it's the client's
    // last-known identity (process-local), used to pin the reconnect dial + join
    // the device view, not a per-connection value. It's cleared only when the
    // target address config changes (set_hostname / set_fix_ips) or trust in it
    // is revoked (remove_authorized_key).
    let active: Vec<SocketAddr> = conns.lock().await.keys().copied().collect();
    log::info!("active connections: {active:?}");
}

/// Accepts the peer's ephemeral clipboard uni streams (everything after the
/// primary reply stream) and forwards each payload to the service.
async fn clipboard_accept_loop(conn: Connection, addr: SocketAddr, clipboard_in: Sender<String>) {
    loop {
        match conn.accept_uni().await {
            Ok(recv) => {
                let clipboard_in = clipboard_in.clone();
                spawn_local(async move {
                    match tokio::time::timeout(
                        transport::CLIPBOARD_IO_TIMEOUT,
                        transport::recv_clipboard(recv),
                    )
                    .await
                    {
                        Ok(Ok(text)) => {
                            let _ = clipboard_in.send(text);
                        }
                        Ok(Err(e)) => log::debug!("{addr}: bad clipboard transfer: {e}"),
                        // dropping the recv future on timeout stops the stream
                        // and frees the uni-stream slot (never reaped otherwise)
                        Err(_) => log::debug!("{addr}: clipboard transfer timed out"),
                    }
                });
            }
            // connection closed — the input receive_loop handles disconnect
            Err(_) => break,
        }
    }
}
