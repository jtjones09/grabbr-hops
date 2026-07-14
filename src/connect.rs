use crate::client::ClientManager;
use crate::config::{local_caps, local_commit};
use crate::crypto::Identity;
use crate::transport::{self, Authorized, FpServerVerifier};
use hops_ipc::{ClientHandle, DEFAULT_PORT};
use hops_proto::ProtoEvent;
use local_channel::mpsc::{Receiver, Sender, channel};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Connection, Endpoint, SendStream, TransportConfig};
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

async fn connect(
    endpoint: Endpoint,
    addr: SocketAddr,
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
) -> Result<(PeerLink, SocketAddr), LanMouseConnectionError> {
    let mut joinset = JoinSet::new();
    for &addr in addrs {
        let endpoint = endpoint.clone();
        joinset.spawn_local(connect(endpoint, addr));
    }
    loop {
        match joinset.join_next().await {
            None => return Err(LanMouseConnectionError::NotConnected),
            Some(r) => match r.expect("join error") {
                Ok(conn) => return Ok(conn),
                Err((a, e)) => log::warn!("failed to connect to {a}: `{e}`"),
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
}

impl LanMouseConnection {
    pub(crate) fn new(
        identity: Arc<Identity>,
        client_manager: ClientManager,
        authorized: Authorized,
        clipboard_in: Sender<String>,
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
        let (link, addr) = match connect_any(&endpoint, &addrs).await {
            Ok(c) => c,
            Err(e) => {
                connecting.lock().await.remove(&handle);
                if let Some(fp) = observed.lock().expect("lock").take() {
                    log::warn!(
                        "client {handle}: receiver fingerprint {fp} is not authorized — \
                         add it to authorized_fingerprints to trust this receiver"
                    );
                }
                return Err(e);
            }
        };
        log::info!("client ({handle}) connected @ {addr}");
        if let Some(fp) = observed.lock().expect("lock").clone() {
            log::info!("client {handle} receiver fingerprint: {fp}");
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
