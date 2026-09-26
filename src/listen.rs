use futures::{Stream, StreamExt};
use hops_proto::ProtoEvent;
use local_channel::mpsc::{Receiver, Sender, channel};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Connection, Endpoint, SendStream, TransportConfig};
use rustls::pki_types::CertificateDer;
use std::{
    cell::RefCell,
    collections::VecDeque,
    io,
    net::SocketAddr,
    rc::Rc,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};
use thiserror::Error;
use tokio::{
    sync::{Mutex as AsyncMutex, Notify},
    task::{JoinHandle, spawn_local},
};

use crate::client::ClientManager;
use crate::crypto::Identity;
use crate::transport::{self, ClipboardInlet, FpClientVerifier, PeerClipboard, Trust};

const KEEP_ALIVE: Duration = Duration::from_secs(8);
const MAX_IDLE: Duration = Duration::from_secs(20);

#[derive(Error, Debug)]
pub enum ListenerCreationError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Rustls(#[from] rustls::Error),
    #[error(transparent)]
    NoInitialCipherSuite(#[from] quinn::crypto::rustls::NoInitialCipherSuite),
}

/// How much unsent reply and clipboard data this machine will hold for one
/// peer before its writer waits. See [`server_config`].
const REPLY_BUFFER_PER_PEER: u32 = 256 * 1024;

/// Which peers must stop sending until injection catches up with them (#82).
///
/// Injection drains each peer's queue in turn. A peer whose queue is full is
/// held here, and its read loop stops taking frames off the network until it
/// is released, so QUIC's own flow control slows that peer and no other.
#[derive(Default)]
pub(crate) struct InputPressure {
    held: RefCell<std::collections::HashSet<SocketAddr>>,
    released: Notify,
}

impl InputPressure {
    pub(crate) fn hold(&self, addr: SocketAddr) {
        self.held.borrow_mut().insert(addr);
    }

    pub(crate) fn release(&self, addr: SocketAddr) {
        if self.held.borrow_mut().remove(&addr) {
            self.released.notify_waiters();
        }
    }

    fn is_held(&self, addr: SocketAddr) -> bool {
        self.held.borrow().contains(&addr)
    }

    /// Wait until `addr` is not held.
    async fn until_released(&self, addr: SocketAddr) {
        loop {
            // Registered before the check, so a release between the check and
            // the wait is not missed.
            let released = self.released.notified();
            tokio::pin!(released);
            released.as_mut().enable();
            if !self.is_held(addr) {
                return;
            }
            released.await;
        }
    }
}

pub(crate) enum ListenEvent {
    Msg {
        event: ProtoEvent,
        addr: SocketAddr,
    },
    Accept {
        addr: SocketAddr,
        fingerprint: String,
    },
    Rejected {
        fingerprint: String,
    },
}

/// A live inbound connection plus the queue its replies wait in and the
/// fingerprint captured at accept time (so we never re-derive it).
struct ConnEntry {
    addr: SocketAddr,
    conn: Connection,
    replies: Rc<RefCell<PendingReplies>>,
    /// Wakes this connection's writer task when a reply is queued.
    ready: Rc<Notify>,
    fingerprint: String,
}

/// Ends a connection's writer task when its read loop ends: the queue is
/// marked closed and the task woken, so it stops once it has written what is
/// already waiting.
struct ReplyQueueGuard {
    replies: Rc<RefCell<PendingReplies>>,
    ready: Rc<Notify>,
}

impl Drop for ReplyQueueGuard {
    fn drop(&mut self) {
        self.replies.borrow_mut().closed = true;
        self.ready.notify_one();
    }
}

/// Replies waiting for one connection's writer task.
///
/// The receiver used to write every reply from the one task that also handles
/// every peer's input, awaiting a QUIC stream whose window a peer that stopped
/// reading can fill. That peer then held up input from all the others (#82).
/// Writing happens on a task per connection, and this is where a reply waits.
///
/// At most one of each kind is kept: the sender re-sends Enter until it sees an
/// Ack, so a second queued Ack tells it nothing the first does not, and a peer
/// that has stopped reading cannot grow this without bound. The oldest waiting
/// reply of a kind keeps its place in the queue and carries the newest value.
#[derive(Default)]
struct PendingReplies {
    queue: VecDeque<ProtoEvent>,
    /// The connection is gone: the writer task stops once the queue is empty.
    closed: bool,
}

impl PendingReplies {
    fn push(&mut self, event: ProtoEvent) {
        if let Some(waiting) = self
            .queue
            .iter_mut()
            .find(|q| std::mem::discriminant(*q) == std::mem::discriminant(&event))
        {
            *waiting = event;
            return;
        }
        self.queue.push_back(event);
    }
}

/// Writes one connection's replies, in the order they were queued.
///
/// Its own task: a write that blocks on this peer's window blocks nothing else.
async fn reply_loop(
    addr: SocketAddr,
    replies: Rc<RefCell<PendingReplies>>,
    ready: Rc<Notify>,
    mut send: SendStream,
) {
    loop {
        let next = replies.borrow_mut().queue.pop_front();
        match next {
            Some(event) => {
                log::trace!("reply {event} >=>=>=>=>=> {addr}");
                if let Err(e) = transport::write_frame(&mut send, event).await {
                    log::debug!("{addr}: reply stream closed: {e}");
                    break;
                }
            }
            None => {
                if replies.borrow().closed {
                    break;
                }
                ready.notified().await;
            }
        }
    }
}

pub(crate) struct LanMouseListener {
    listen_rx: Receiver<ListenEvent>,
    listen_tx: Sender<ListenEvent>,
    listen_task: JoinHandle<()>,
    conns: Rc<AsyncMutex<Vec<ConnEntry>>>,
    pressure: Rc<InputPressure>,
    request_port_change: Sender<u16>,
    port_changed: Receiver<Result<u16, ListenerCreationError>>,
    /// Asked before this machine's clipboard goes to a peer.
    trust: Trust,
    /// Where the first endpoint bound, so a test that asked for port 0 can dial it.
    #[cfg(test)]
    local_addr: SocketAddr,
}

fn server_config(
    identity: &Identity,
    trust: Trust,
    attempts: Arc<StdMutex<VecDeque<String>>>,
) -> Result<quinn::ServerConfig, ListenerCreationError> {
    let verifier = Arc::new(FpClientVerifier::new(trust, attempts));
    let mut crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![identity.cert.clone()], identity.key.clone_key())?;
    crypto.alpn_protocols = vec![transport::ALPN.to_vec()];
    // REFUSE TLS 1.3 resumption. rustls only calls `verify_client_cert` from the
    // ExpectCertificate state, which a resumed handshake never enters: it restores
    // the peer's cert chain from the ticket and sets doing_client_auth = false. So
    // a resumed connection SKIPS `FpClientVerifier` entirely — the allowlist is
    // never consulted, and a peer trusted once could reconnect forever, refreshing
    // its own tickets on every resumption. rustls documents that it enforces no
    // policy here; enforcing it is our job. Observed on the rig: a revoked peer
    // reconnected 1s after its session was cut and was accepted.
    crypto.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    crypto.send_tls13_tickets = 0;
    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));
    let mut transport_config = TransportConfig::default();
    // MUST be > 0 or the peer's single uni stream is never accepted.
    transport_config.max_concurrent_uni_streams(8u8.into());
    // What one peer can make this machine hold. quinn buffers what it cannot
    // send yet, and its default runs to megabytes per connection: a peer that
    // stops reading its replies had this machine holding all of them, and the
    // task that wrote them was the one task handling every peer's input (#82).
    // A reply is a handful of bytes, so this is thousands of them; a clipboard
    // transfer on the same connection is chunked and flow-controlled anyway.
    transport_config.send_window(REPLY_BUFFER_PER_PEER as u64);
    transport_config.keep_alive_interval(Some(KEEP_ALIVE));
    transport_config.max_idle_timeout(Some(MAX_IDLE.try_into().expect("idle timeout")));
    server_config.transport_config(Arc::new(transport_config));
    Ok(server_config)
}

/// Fingerprint of the peer's leaf certificate, taken from the completed
/// handshake. quinn hands the presented chain as `Vec<CertificateDer>`.
fn peer_fingerprint(conn: &Connection) -> Option<String> {
    let identity = conn.peer_identity()?;
    let certs = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    certs.first().map(transport::fingerprint_of)
}

impl LanMouseListener {
    pub(crate) async fn new(
        port: u16,
        identity: Arc<Identity>,
        trust: Trust,
        clipboard_in: Sender<PeerClipboard>,
    ) -> Result<Self, ListenerCreationError> {
        let listen_addr = SocketAddr::new("0.0.0.0".parse().expect("invalid ip"), port);
        Self::bind(listen_addr, identity, trust, clipboard_in).await
    }

    /// [`Self::new`] on a chosen address. Tests bind 127.0.0.1 port 0, so they
    /// neither listen on the network nor collide with a running daemon.
    async fn bind(
        listen_addr: SocketAddr,
        identity: Arc<Identity>,
        trust: Trust,
        clipboard_in: Sender<PeerClipboard>,
    ) -> Result<Self, ListenerCreationError> {
        transport::install_crypto_provider();
        let (listen_tx, listen_rx) = channel();
        let (request_port_change, mut request_port_change_rx) = channel();
        let (port_changed_tx, port_changed) = channel();
        let attempts: Arc<StdMutex<VecDeque<String>>> = Default::default();

        let cfg = server_config(&identity, trust.clone(), attempts.clone())?;
        let mut endpoint = Endpoint::server(cfg, listen_addr)?;
        #[cfg(test)]
        let local_addr = endpoint.local_addr()?;

        let conns: Rc<AsyncMutex<Vec<ConnEntry>>> = Rc::new(AsyncMutex::new(Vec::new()));
        let conns_clone = conns.clone();
        let clipboard_trust = trust.clone();
        let pressure: Rc<InputPressure> = Default::default();
        let pressure_clone = pressure.clone();

        let listen_task: JoinHandle<()> = {
            let listen_tx = listen_tx.clone();
            let attempts = attempts.clone();
            let authorized_accept = trust.clone();
            spawn_local(async move {
                loop {
                    tokio::select! {
                        incoming = endpoint.accept() => {
                            let Some(incoming) = incoming else { break };
                            // Drive each handshake on its own task so one slow
                            // peer can't head-of-line-block all other accepts.
                            let conns = conns_clone.clone();
                            let pressure = pressure_clone.clone();
                            let listen_tx = listen_tx.clone();
                            let attempts = attempts.clone();
                            let clipboard_in = clipboard_in.clone();
                            let trust = authorized_accept.clone();
                            spawn_local(async move {
                                let remote = incoming.remote_address();
                                match incoming.await {
                                    Ok(conn) => {
                                        let addr = conn.remote_address();
                                        log::info!("client connected, ip: {addr}");
                                        // Defense in depth: re-check the peer against the
                                        // live allowlist HERE, after the handshake, instead of
                                        // trusting the TLS layer to have done it. The verifier
                                        // is skipped on any resumed handshake, and a peer whose
                                        // identity we cannot even derive must never be admitted
                                        // -- it was previously accepted as "unknown", which no
                                        // revocation could ever match.
                                        let Some(fingerprint) = peer_fingerprint(&conn) else {
                                            log::warn!(
                                                "{addr}: rejecting — no peer certificate presented"
                                            );
                                            conn.close(0u32.into(), b"unauthorized");
                                            return;
                                        };
                                        // The receiver's question. A lease that
                                        // lapsed between the TLS check and here
                                        // is refused, which is why the check is
                                        // repeated rather than assumed.
                                        if !trust
                                            .read()
                                            .expect("lock")
                                            .may_drive_us(&fingerprint)
                                        {
                                            log::warn!(
                                                "{addr}: rejecting {fingerprint} — no live lease permits it to drive this machine"
                                            );
                                            conn.close(0u32.into(), b"unauthorized");
                                            let _ = listen_tx
                                                .send(ListenEvent::Rejected { fingerprint });
                                            return;
                                        }
                                        let send = match conn.open_uni().await {
                                            Ok(s) => s,
                                            Err(e) => {
                                                log::warn!("{addr}: opening reply stream failed: {e}");
                                                return;
                                            }
                                        };
                                        let replies: Rc<RefCell<PendingReplies>> = Default::default();
                                        let ready = Rc::new(Notify::new());
                                        spawn_local(reply_loop(addr, replies.clone(), ready.clone(), send));
                                        conns.lock().await.push(ConnEntry {
                                            addr,
                                            conn: conn.clone(),
                                            replies: replies.clone(),
                                            ready: ready.clone(),
                                            fingerprint: fingerprint.clone(),
                                        });
                                        let closer = ReplyQueueGuard { replies, ready };
                                        let clipboard = ClipboardInlet {
                                            from: fingerprint.clone(),
                                            trust: trust.clone(),
                                            tx: clipboard_in,
                                        };
                                        let _ = listen_tx.send(ListenEvent::Accept { addr, fingerprint });
                                        spawn_local(read_loop(conns.clone(), addr, conn, listen_tx.clone(), clipboard, closer, pressure));
                                    }
                                    Err(e) => {
                                        log::warn!("handshake from {remote} failed: {e}");
                                        if let Some(fingerprint) =
                                            attempts.lock().expect("lock").pop_front()
                                        {
                                            let _ = listen_tx.send(ListenEvent::Rejected { fingerprint });
                                        }
                                    }
                                }
                            });
                        },
                        port = request_port_change_rx.recv() => {
                            // None => the listener handle was dropped (shutdown); end the task.
                            let Some(port) = port else { break };
                            let listen_addr = SocketAddr::new("0.0.0.0".parse().expect("invalid ip"), port);
                            // A dropped port_changed receiver (requester gone) must NOT panic
                            // this long-running accept loop — ignore the send result instead.
                            match server_config(&identity, trust.clone(), attempts.clone()) {
                                Ok(cfg) => match Endpoint::server(cfg, listen_addr) {
                                    Ok(new_endpoint) => {
                                        endpoint.close(0u32.into(), b"port change");
                                        endpoint = new_endpoint;
                                        let _ = port_changed_tx.send(Ok(port));
                                    }
                                    Err(e) => {
                                        log::warn!("unable to change port: {e}");
                                        let _ = port_changed_tx.send(Err(e.into()));
                                    }
                                },
                                Err(e) => {
                                    log::warn!("unable to rebuild server config: {e}");
                                    let _ = port_changed_tx.send(Err(e));
                                }
                            };
                        },
                    };
                }
            })
        };

        Ok(Self {
            conns,
            pressure,
            listen_rx,
            listen_tx,
            listen_task,
            port_changed,
            request_port_change,
            trust: clipboard_trust,
            #[cfg(test)]
            local_addr,
        })
    }

    /// A listener on 127.0.0.1 at a port the OS picks, and that port.
    #[cfg(test)]
    pub(crate) async fn bind_loopback(
        identity: Arc<Identity>,
        trust: Trust,
        clipboard_in: Sender<PeerClipboard>,
    ) -> Result<(Self, u16), ListenerCreationError> {
        let addr = SocketAddr::new("127.0.0.1".parse().expect("loopback"), 0);
        let listener = Self::bind(addr, identity, trust, clipboard_in).await?;
        let port = listener.local_addr.port();
        Ok((listener, port))
    }

    pub(crate) fn request_port_change(&mut self, port: u16) {
        self.request_port_change.send(port).expect("channel closed");
    }

    pub(crate) async fn port_changed(&mut self) -> Result<u16, ListenerCreationError> {
        self.port_changed.recv().await.expect("channel closed")
    }

    pub(crate) async fn terminate(&mut self) {
        self.listen_task.abort();
        let conns = self.conns.lock().await;
        for entry in conns.iter() {
            entry.conn.close(0u32.into(), b"shutdown");
        }
        self.listen_tx.close();
    }

    /// Queue a reply for `addr`. Never waits for the peer to read it: that wait
    /// belongs to this connection's own writer task (#82).
    pub(crate) async fn reply(&self, addr: SocketAddr, event: ProtoEvent) {
        let conns = self.conns.lock().await;
        if let Some(entry) = conns.iter().find(|e| e.addr == addr) {
            entry.replies.borrow_mut().push(event);
            entry.ready.notify_one();
        }
    }

    pub(crate) async fn get_certificate_fingerprint(&self, addr: SocketAddr) -> Option<String> {
        self.conns
            .lock()
            .await
            .iter()
            .find(|e| e.addr == addr)
            .map(|e| e.fingerprint.clone())
    }

    /// Which peers must stop sending until injection catches up. Given to the
    /// emulation task, which holds and releases them (#82).
    pub(crate) fn pressure(&self) -> Rc<InputPressure> {
        self.pressure.clone()
    }

    /// A handle for force-closing live inbound sessions when trust is revoked.
    /// Grabbed before this listener is moved into `Emulation`.
    pub(crate) fn revoker(&self) -> ConnRevoker {
        ConnRevoker {
            conns: self.conns.clone(),
        }
    }

    /// A handle for broadcasting local clipboard changes to the connected
    /// peers the pairing shares it with. Grabbed before this listener is moved
    /// into `Emulation` so the service can drive it directly. `clients` says
    /// which devices are switched off.
    pub(crate) fn clipboard_sender(&self, clients: ClientManager) -> ClipboardSenderListen {
        ClipboardSenderListen {
            conns: self.conns.clone(),
            trust: self.trust.clone(),
            clients,
        }
    }
}

/// Force-closes live inbound sessions by peer fingerprint.
///
/// Peer identity is verified ONCE, during the TLS handshake — so dropping a
/// fingerprint from the allowlist does not stop a session that is already
/// established. Without this, "revoke" only removed the card while the peer
/// kept injecting input. Revocation MUST cut the live session too.
#[derive(Clone)]
pub(crate) struct ConnRevoker {
    conns: Rc<AsyncMutex<Vec<ConnEntry>>>,
}

impl ConnRevoker {
    /// Close every live inbound session whose peer presented `fp`. Returns how
    /// many were cut. The read loop's own cleanup is idempotent, so removing the
    /// entries here does not race it.
    pub(crate) async fn close_fingerprint(&self, fp: &str) -> usize {
        let mut conns = self.conns.lock().await;
        let mut closed = 0;
        conns.retain(|e| {
            if e.fingerprint == fp {
                log::warn!("closing session with {} — trust revoked", e.addr);
                e.conn.close(0u32.into(), b"trust revoked");
                closed += 1;
                false
            } else {
                true
            }
        });
        closed
    }
}

/// Broadcasts clipboard text to each connected peer the pairing shares it
/// with, each on its own ephemeral uni stream. Cloneable handle over the
/// shared connection list.
#[derive(Clone)]
pub(crate) struct ClipboardSenderListen {
    conns: Rc<AsyncMutex<Vec<ConnEntry>>>,
    trust: Trust,
    clients: ClientManager,
}

/// One clipboard-failure line a minute is enough to tell you it is dropping,
/// without a persistently unreachable peer flooding the log.
const CLIP_LOG_DEBOUNCE: std::time::Duration = std::time::Duration::from_secs(60);
thread_local! {
    static PREV_CLIP_LOG: std::cell::Cell<Option<std::time::Instant>> =
        const { std::cell::Cell::new(None) };
}

impl ClipboardSenderListen {
    pub(crate) async fn broadcast(&self, text: String) {
        let conns: Vec<Connection> = {
            let conns = self.conns.lock().await;
            let trust = self.trust.read().expect("lock");
            // Every open link used to get it. A peer that connected in is one
            // that drives this machine, and the pairing sends it this
            // machine's clipboard only if its lease says so (#186), and not
            // while its card here is switched off.
            conns
                .iter()
                .filter(|e| trust.clipboard_to(&e.fingerprint))
                .filter(|e| !self.clients.switched_off(&e.fingerprint))
                .map(|e| e.conn.clone())
                .collect()
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
                    // WARN, not debug. Every failure here was invisible on a
                    // normal install: the launchers run at HOPS_LOG_LEVEL=info,
                    // so a clipboard that silently stopped working left no trace
                    // at all -- reported from the rig as "copy paste is now
                    // broken", then "now its working again", with 69 MB of log
                    // and not one clipboard line in it.
                    //
                    // Debounced because a peer that is persistently unreachable
                    // would otherwise flood; one line a minute is enough to tell
                    // you the clipboard is dropping.
                    Ok(Err(e)) => {
                        crate::debounce!(
                            PREV_CLIP_LOG,
                            CLIP_LOG_DEBOUNCE,
                            log::warn!("clipboard not shared with a peer: {e}")
                        );
                    }
                    // dropping the send future on timeout abandons a stuck
                    // open_uni/write instead of pinning the task indefinitely
                    Err(_) => {
                        crate::debounce!(
                            PREV_CLIP_LOG,
                            CLIP_LOG_DEBOUNCE,
                            log::warn!(
                                "clipboard not shared with a peer: it did not accept the \
                             text within {:?}",
                                transport::CLIPBOARD_IO_TIMEOUT
                            )
                        );
                    }
                }
            });
        }
    }
}

impl Stream for LanMouseListener {
    type Item = ListenEvent;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.listen_rx.poll_next_unpin(cx)
    }
}

async fn remove_conn(conns: &Rc<AsyncMutex<Vec<ConnEntry>>>, addr: SocketAddr) {
    let mut conns = conns.lock().await;
    if let Some(index) = conns.iter().position(|e| e.addr == addr) {
        conns.remove(index);
    }
}

async fn read_loop(
    conns: Rc<AsyncMutex<Vec<ConnEntry>>>,
    addr: SocketAddr,
    conn: Connection,
    listen_tx: Sender<ListenEvent>,
    clipboard: ClipboardInlet,
    // Dropped when this loop ends, which ends the connection's writer task.
    _replies: ReplyQueueGuard,
    pressure: Rc<InputPressure>,
) {
    // the peer's reliable inbound stream (their uni stream to us)
    let mut recv = match conn.accept_uni().await {
        Ok(recv) => recv,
        Err(e) => {
            log::info!("{addr}: no inbound stream: {e}");
            remove_conn(&conns, addr).await;
            return;
        }
    };
    // The input stream above is accepted first (opened at connection setup);
    // clipboard transfers ride the subsequent uni streams on this connection.
    spawn_local(transport::clipboard_accept_loop(
        conn.clone(),
        addr,
        clipboard,
    ));
    loop {
        // A peer whose injection queue is full reads nothing more until it
        // drains, so its own flow control slows it and no other peer (#82).
        pressure.until_released(addr).await;
        match transport::read_frame(&mut recv).await {
            Ok(Some(event)) => {
                let _ = listen_tx.send(ListenEvent::Msg { event, addr });
            }
            Ok(None) => break,
            // unknown/forward-compat event: framing intact, keep listening
            Err(transport::FrameError::Protocol(e)) => {
                log::debug!("ignoring undecodable event from {addr}: {e}")
            }
            Err(e) => {
                log::warn!("{addr}: recv error: {e}");
                break;
            }
        }
    }
    log::info!("client disconnected {addr:?}");
    // Close the connection so the spawned clipboard_accept_loop's accept_uni
    // errors and the loop (and this connection's remaining clones) are
    // released. Mirrors connect.rs::disconnect; without it a half-closed-but-
    // alive connection (primary input stream finished/reset while keep-alive
    // holds the connection up) would leak the clipboard task and the connection.
    conn.close(0u32.into(), b"bye");
    remove_conn(&conns, addr).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Identity;
    use crate::transport::FpServerVerifier;
    use quinn::{ClientConfig, Endpoint};

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

    /// A store granting each fingerprint the INBOUND half only — which is what
    /// a receiver's allowlist ever meant.
    fn allow(us: &str, fps: &[&str]) -> Trust {
        let mut store = crate::trust::TrustStore::new(us, 0).expect("our fingerprint");
        for f in fps {
            store
                .issue(f, "peer", crate::trust::Caps::INBOUND)
                .expect("issue");
        }
        Arc::new(RwLock::new(store))
    }

    /// The mirror of [`allow`] for the dialling side: we may drive these peers.
    /// Two helpers rather than one, because the whole point of the store is
    /// that these are different grants.
    fn permit_drive(us: &str, fps: &[&str]) -> Trust {
        let mut store = crate::trust::TrustStore::new(us, 0).expect("our fingerprint");
        for f in fps {
            store
                .issue(f, "peer", crate::trust::Caps::OUTBOUND)
                .expect("issue");
        }
        Arc::new(RwLock::new(store))
    }

    /// One client config, reused across dials — this is what makes the test
    /// meaningful: rustls caches session tickets per ClientConfig, so the second
    /// dial offers a PSK and would RESUME if the server allowed it.
    fn client_config(client: &Identity, trusts: Trust) -> ClientConfig {
        let observed = Arc::new(StdMutex::new(None));
        let verifier = Arc::new(FpServerVerifier::new(trusts, observed));
        let mut crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(vec![client.cert.clone()], client.key.clone_key())
            .expect("client auth");
        crypto.alpn_protocols = vec![transport::ALPN.to_vec()];
        ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("quic client"),
        ))
    }

    /// Full handshake against the listener's real server config. `true` = admitted.
    ///
    /// NB: `open_uni()` is NOT an admission test — QUIC opens streams locally with
    /// no round trip, so it succeeds even against a server that rejected us. A
    /// client-cert rejection also lands AFTER `connecting.await` resolves (0.5-RTT),
    /// so the honest signal is whether the connection SURVIVES: a rejected peer's
    /// connection closes almost immediately, an admitted one stays up.
    async fn dials_ok(endpoint: &Endpoint, addr: SocketAddr) -> bool {
        let Ok(connecting) = endpoint.connect(addr, "grabbr") else {
            return false;
        };
        match tokio::time::timeout(Duration::from_secs(5), connecting).await {
            Ok(Ok(conn)) => {
                let survived = tokio::time::timeout(Duration::from_millis(1500), conn.closed())
                    .await
                    .is_err();
                conn.close(0u32.into(), b"done");
                survived
            }
            _ => false,
        }
    }

    /// A peer that stops reading its replies must not make this machine wait.
    ///
    /// Until the writer task, every reply was written by the one task that also
    /// handles every peer's input, and a peer whose receive window filled
    /// blocked it: on main this call pends after about 170 replies, and nothing
    /// else on this machine takes input again (#82).
    ///
    /// The peer here dials the real listener and never reads the stream this
    /// machine opens back to it. Its window is deliberately small, because the
    /// point is the block, not the size of a buffer.
    // LEDGER T26 | class B | 1 return value + elapsed: LanMouseListener::reply
    #[test]
    fn replies_to_a_peer_that_stopped_reading_never_wait() {
        crate::test_harness::run_local(async {
            let receiver = crate::test_harness::machine();
            let peer = crate::test_harness::machine();
            let trust_in =
                crate::test_harness::trust(&receiver, &[&peer], crate::trust::Caps::INBOUND);
            let (clip_tx, _clip_rx) = local_channel::mpsc::channel();
            let (listener, port) =
                LanMouseListener::bind_loopback(receiver.identity.clone(), trust_in, clip_tx)
                    .await
                    .expect("listener");
            let config = crate::test_harness::raw_client_config(
                &peer,
                crate::test_harness::trust(&peer, &[&receiver], crate::trust::Caps::OUTBOUND),
                1024,
            );
            let mut endpoint =
                Endpoint::client("127.0.0.1:0".parse().expect("loopback")).expect("endpoint");
            endpoint.set_default_client_config(config);
            let conn = endpoint
                .connect(
                    SocketAddr::new("127.0.0.1".parse().expect("loopback"), port),
                    "grabbr",
                )
                .expect("dial")
                .await
                .expect("handshake");
            // The stream this machine replies on is opened by the listener; the
            // peer never accepts or reads it.
            let _input = conn.open_uni().await.expect("input stream");
            let peer_addr = crate::test_harness::wait_for(
                "the listener to register the connection",
                Duration::from_secs(5),
                || async { listener.conns.lock().await.first().map(|e| e.addr) },
            )
            .await;

            for i in 0..5_000u32 {
                if tokio::time::timeout(
                    Duration::from_millis(500),
                    listener.reply(peer_addr, ProtoEvent::Ack(0)),
                )
                .await
                .is_err()
                {
                    panic!(
                        "reply {i} waited for a peer that stopped reading; \
                         input from every other peer waits with it"
                    );
                }
            }
            let waiting = listener
                .conns
                .lock()
                .await
                .first()
                .map(|e| e.replies.borrow().queue.len())
                .expect("one connection");
            assert!(
                waiting <= 1,
                "5000 acks left {waiting} waiting: one of each kind is the bound"
            );
        });
    }

    /// The rig bug: a peer trusted ONCE could reconnect after revocation because a
    /// resumed TLS handshake never re-runs `FpClientVerifier`. Observed live —
    /// the revoked sender was back in 1s after its session was cut.
    #[test]
    fn revoked_peer_cannot_resume_its_way_back_in() {
        transport::install_crypto_provider();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async {
            let server = identity();
            let client = identity();
            let client_fp = transport::fingerprint_of(&client.cert);
            let server_fp = transport::fingerprint_of(&server.cert);

            // server trusts the client (as if just approved)
            let trust = allow(&server_fp, &[&client_fp]);
            let attempts: Arc<StdMutex<VecDeque<String>>> = Default::default();
            let cfg = server_config(&server, trust.clone(), attempts).expect("server config");
            let listen_addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
            let server_ep = Endpoint::server(cfg, listen_addr).expect("endpoint");
            let addr = server_ep.local_addr().expect("local addr");

            // accept loop: mirrors the real listener closely enough to admit peers
            spawn_local(async move {
                while let Some(incoming) = server_ep.accept().await {
                    spawn_local(async move {
                        if let Ok(conn) = incoming.await {
                            // hold well past the client's survival probe, so only a
                            // REJECTION can close the connection early
                            tokio::time::sleep(Duration::from_secs(4)).await;
                            drop(conn);
                        }
                    });
                }
            });

            // ONE endpoint + config for both dials, so a ticket can be cached
            let mut client_ep =
                Endpoint::client("127.0.0.1:0".parse().expect("addr")).expect("client endpoint");
            client_ep.set_default_client_config(client_config(
                &client,
                permit_drive(&client_fp, &[&server_fp]),
            ));

            assert!(
                dials_ok(&client_ep, addr).await,
                "an trust peer must be admitted"
            );

            // revoke — exactly what remove_authorized_key does to the shared map
            trust.write().expect("lock").revoke(&client_fp);

            assert!(
                !dials_ok(&client_ep, addr).await,
                "REGRESSION: a revoked peer got back in — the allowlist was not \
                 consulted, almost certainly because the handshake resumed and \
                 skipped FpClientVerifier"
            );
        });
    }
}

#[cfg(test)]
mod clipboard_failures_are_visible {
    //! A clipboard that stops working must leave a trace.
    //!
    //! Both broadcast paths logged failures at `debug`, and every launcher runs
    //! at `HOPS_LOG_LEVEL=info`. So a clipboard that silently stopped sharing
    //! produced NOTHING in the log — reported from the rig as "copy paste is
    //! now broken", then "now its working again", against a 69 MB daemon log
    //! containing not one clipboard line.
    //!
    //! Undiagnosable is the same failure this project keeps shipping: the probe
    //! that printed silence, the discovery section that rendered nothing, the
    //! dot that said "fine". A transient fault you cannot see is one you cannot
    //! fix, so the level is the fix.

    fn production(src: &str) -> String {
        let head = src.split("\n#[cfg(test)]").next().unwrap_or(src);
        head.lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn neither_broadcast_path_hides_a_failure_at_debug() {
        for (name, src) in [
            ("listen.rs", production(include_str!("listen.rs"))),
            ("connect.rs", production(include_str!("connect.rs"))),
        ] {
            assert!(
                !src.contains(r#"log::debug!("clipboard broadcast"#),
                "{name} logs a clipboard broadcast failure at debug. Every \
                 launcher runs at info, so that is invisible — which is how a \
                 clipboard silently stopped sharing on the rig and left no \
                 evidence at all."
            );
            assert!(
                src.contains("clipboard not shared with a peer"),
                "{name} must WARN when the clipboard does not reach a peer"
            );
        }
    }

    /// Debounced, or a persistently unreachable peer floods the log — the other
    /// way this project has hurt itself (a 69 MB log, a 4.4 GB one before that).
    #[test]
    fn the_warning_is_debounced() {
        for (name, src) in [
            ("listen.rs", production(include_str!("listen.rs"))),
            ("connect.rs", production(include_str!("connect.rs"))),
        ] {
            // Two separate substrings, not one literal: rustfmt wraps the
            // macro call across lines, and a guard that breaks on formatting
            // gets deleted rather than fixed.
            assert!(
                src.contains("crate::debounce!") && src.contains("PREV_CLIP_LOG"),
                "{name} must debounce the clipboard warning, or an unreachable \
                 peer floods the log — the failure mode that produced a 69 MB \
                 daemon log and a 4.4 GB keystroke log before it"
            );
        }
    }
}
