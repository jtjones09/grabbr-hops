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
    // Same hazard, mirrored: a resumed CLIENT handshake skips server-certificate
    // verification, so `FpServerVerifier` and the fail-closed fingerprint pin would
    // both be bypassed when redialing a receiver we have since revoked. Refuse
    // resumption so every dial re-proves the receiver's identity.
    crypto.resumption = rustls::client::Resumption::disabled();
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
    cfg: ClientConfig,
    addr: SocketAddr,
    expected_fp: Option<String>,
) -> Result<(PeerLink, SocketAddr), (SocketAddr, LanMouseConnectionError)> {
    log::info!("connecting to {addr} ...");
    // server_name is the SNI label; trust is by fingerprint, so it is not
    // trust-relevant — a fixed label is fine.
    let connecting = endpoint
        .connect_with(cfg, addr, "grabbr")
        .map_err(|e| (addr, e.into()))?;
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
    cfg: &ClientConfig,
    addrs: &[SocketAddr],
    expected_fp: Option<String>,
) -> Result<(PeerLink, SocketAddr), LanMouseConnectionError> {
    let mut joinset = JoinSet::new();
    for &addr in addrs {
        let endpoint = endpoint.clone();
        let cfg = cfg.clone();
        let expected = expected_fp.clone();
        joinset.spawn_local(connect(endpoint, cfg, addr, expected));
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
    /// Material for building a FRESH client config per dial. The observed-
    /// fingerprint slot MUST NOT be shared: it is written by the TLS verifier and
    /// read by the failing dial's error path, so one process-wide slot let a
    /// concurrent dial to another peer overwrite it — losing the trust prompt, or
    /// raising it for the wrong machine.
    identity: Arc<Identity>,
    authorized: Authorized,
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
        let endpoint = Endpoint::client("0.0.0.0:0".parse().expect("valid addr"))?;
        // deliberately NO set_default_client_config — every dial builds its own so
        // each carries a private observed-fingerprint slot (see the field docs).
        let (recv_tx, recv_rx) = channel();
        Ok(Self {
            endpoint,
            client_manager,
            conns: Default::default(),
            connecting: Default::default(),
            recv_rx,
            recv_tx,
            ping_response: Default::default(),
            identity,
            authorized,
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

    /// A handle for force-closing outgoing sessions when trust is revoked.
    /// Grabbed before this connection is moved into `Capture`.
    pub(crate) fn revoker(&self) -> OutboundRevoker {
        OutboundRevoker {
            conns: self.conns.clone(),
            client_manager: self.client_manager.clone(),
        }
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
                self.identity.clone(),
                self.authorized.clone(),
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
    identity: Arc<Identity>,
    authorized: Authorized,
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
        // One slot per dial attempt. Every address raced below is the SAME
        // intended peer, so they may share it; a concurrent dial for a different
        // handle gets its own and cannot clobber this one.
        let observed = Arc::new(StdMutex::new(None));
        let cfg = client_config(&identity, authorized.clone(), observed.clone());
        let (link, addr) = match connect_any(&endpoint, &cfg, &addrs, expected_fp).await {
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
                let is_new =
                    client_manager.peer_fingerprint(handle).as_deref() != Some(fp.as_str());
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
            if let Err(e) = transport::write_frame(
                &mut send,
                ProtoEvent::Capability {
                    flags: local_caps(),
                },
            )
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

/// Force-closes outgoing sessions when we revoke trust in the receiver.
///
/// The mirror of `listen::ConnRevoker`: our own dial is authenticated once, at
/// handshake, so revoking a receiver we are actively driving must also tear the
/// session down — otherwise we keep sending it input we no longer trust it to
/// receive.
#[derive(Clone)]
pub(crate) struct OutboundRevoker {
    conns: Rc<Mutex<HashMap<SocketAddr, PeerLink>>>,
    client_manager: ClientManager,
}

impl OutboundRevoker {
    /// Disconnect each handle's active session. Handles are resolved by the
    /// caller BEFORE it clears the pins, since clearing erases the fingerprint
    /// the match is made on.
    pub(crate) async fn close_handles(&self, handles: &[ClientHandle]) -> usize {
        let mut closed = 0;
        for &handle in handles {
            if let Some(addr) = self.client_manager.active_addr(handle) {
                disconnect(&self.client_manager, handle, addr, &self.conns).await;
                closed += 1;
            }
        }
        closed
    }
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
    // `alive` is only ever SET from the pong path, so without clearing it here
    // the dot stays green after a real disconnect — the device list telling the
    // user a dead peer is up. Every other per-connection value is cleared below;
    // this one was simply missed.
    client_manager.set_alive(handle, false);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Identity;
    use quinn::Endpoint;
    use quinn::crypto::rustls::QuicServerConfig;
    use std::collections::HashMap;
    use std::sync::RwLock;

    fn identity() -> Identity {
        let key_pair = rcgen::KeyPair::generate().expect("keypair");
        let mut params = rcgen::CertificateParams::new(vec!["grabbr".to_owned()]).expect("params");
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "grabbr-hop");
        let cert = params.self_signed(&key_pair).expect("self signed");
        Identity {
            cert: cert.der().clone(),
            key: rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der())
                .expect("key der"),
        }
    }

    /// A server that accepts anyone — we are testing the CLIENT's verification of
    /// the SERVER, so client auth is deliberately not required here.
    fn open_server(server: &Identity) -> quinn::ServerConfig {
        let mut crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server.cert.clone()], server.key.clone_key())
            .expect("server cert");
        crypto.alpn_protocols = vec![transport::ALPN.to_vec()];
        quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(crypto).expect("quic server"),
        ))
    }

    async fn dials_ok(endpoint: &Endpoint, addr: SocketAddr) -> bool {
        let Ok(connecting) = endpoint.connect(addr, "grabbr") else {
            return false;
        };
        match tokio::time::timeout(Duration::from_secs(5), connecting).await {
            Ok(Ok(conn)) => {
                // a rejected SERVER cert surfaces as the connection dying, not as
                // connect() erroring — so test survival, not the initial future
                let survived = tokio::time::timeout(Duration::from_millis(1500), conn.closed())
                    .await
                    .is_err();
                conn.close(0u32.into(), b"done");
                survived
            }
            _ => false,
        }
    }

    /// Two dials in flight at once must each learn THEIR OWN receiver's
    /// fingerprint. The slot is written by the TLS verifier and read by the
    /// failing dial's error path to raise the trust prompt, so a single
    /// process-wide slot (what this replaced) let one dial overwrite another's —
    /// losing the prompt, or offering to trust the wrong machine.
    #[test]
    fn concurrent_dials_keep_their_own_observed_fingerprint() {
        transport::install_crypto_provider();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            let client = identity();
            // trust NEITHER receiver, so both handshakes are rejected and both
            // verifiers record what they saw
            let empty: Authorized = Arc::new(RwLock::new(HashMap::new()));

            let mut addrs = vec![];
            let mut fps = vec![];
            for _ in 0..2 {
                let server = identity();
                fps.push(transport::fingerprint_of(&server.cert));
                let ep =
                    Endpoint::server(open_server(&server), "127.0.0.1:0".parse().expect("addr"))
                        .expect("server endpoint");
                addrs.push(ep.local_addr().expect("local addr"));
                spawn_local(async move {
                    while let Some(incoming) = ep.accept().await {
                        spawn_local(async move {
                            let _ = incoming.await;
                        });
                    }
                });
            }

            let client_ep =
                Endpoint::client("127.0.0.1:0".parse().expect("addr")).expect("client endpoint");

            // one slot per dial — this is the fix
            let slots: Vec<Arc<StdMutex<Option<String>>>> =
                (0..2).map(|_| Arc::new(StdMutex::new(None))).collect();
            let cfgs: Vec<ClientConfig> = slots
                .iter()
                .map(|s| client_config(&client, empty.clone(), s.clone()))
                .collect();

            // genuinely concurrent
            let _ = tokio::join!(
                connect(client_ep.clone(), cfgs[0].clone(), addrs[0], None),
                connect(client_ep.clone(), cfgs[1].clone(), addrs[1], None),
            );

            for (i, slot) in slots.iter().enumerate() {
                let seen = slot.lock().expect("lock").clone();
                assert_eq!(
                    seen.as_deref(),
                    Some(fps[i].as_str()),
                    "dial {i} must observe ITS OWN receiver — a shared slot would \
                     leave both holding whichever handshake finished last"
                );
            }
        });
    }

    /// The outbound mirror of `listen::tests::revoked_peer_cannot_resume_its_way_back_in`.
    /// A resumed CLIENT handshake skips SERVER-certificate verification, so without
    /// `Resumption::disabled()` we would keep driving a receiver we had just revoked
    /// -- `FpServerVerifier` and the fail-closed pin both silently bypassed.
    #[test]
    fn revoked_receiver_cannot_be_redialed_by_resuming() {
        transport::install_crypto_provider();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            let server = identity();
            let client = identity();
            let server_fp = transport::fingerprint_of(&server.cert);

            let server_ep =
                Endpoint::server(open_server(&server), "127.0.0.1:0".parse().expect("addr"))
                    .expect("server endpoint");
            let addr = server_ep.local_addr().expect("local addr");
            spawn_local(async move {
                while let Some(incoming) = server_ep.accept().await {
                    spawn_local(async move {
                        if let Ok(conn) = incoming.await {
                            // outlive the client's survival probe
                            tokio::time::sleep(Duration::from_secs(4)).await;
                            drop(conn);
                        }
                    });
                }
            });

            // we trust this receiver (as if just approved)
            let trusted: Authorized = Arc::new(RwLock::new(HashMap::from([(
                server_fp.clone(),
                "receiver".to_string(),
            )])));
            let observed = Arc::new(StdMutex::new(None));

            // ONE endpoint + config across both dials, so a ticket can be cached
            let mut client_ep =
                Endpoint::client("127.0.0.1:0".parse().expect("addr")).expect("client endpoint");
            client_ep.set_default_client_config(client_config(&client, trusted.clone(), observed));

            assert!(
                dials_ok(&client_ep, addr).await,
                "a trusted receiver must be dialable"
            );

            // revoke the receiver — what remove_authorized_key does to the shared map
            trusted.write().expect("lock").remove(&server_fp);

            assert!(
                !dials_ok(&client_ep, addr).await,
                "REGRESSION: kept driving a REVOKED receiver — the outbound handshake \
                 resumed and skipped FpServerVerifier"
            );
        });
    }
}
