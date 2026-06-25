use futures::{Stream, StreamExt};
use lan_mouse_proto::ProtoEvent;
use local_channel::mpsc::{Receiver, Sender, channel};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Connection, Endpoint, SendStream, TransportConfig};
use rustls::pki_types::CertificateDer;
use std::{
    collections::VecDeque,
    io,
    net::SocketAddr,
    rc::Rc,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};
use thiserror::Error;
use tokio::{
    sync::Mutex as AsyncMutex,
    task::{JoinHandle, spawn_local},
};

use crate::crypto::Identity;
use crate::transport::{self, Authorized, FpClientVerifier};

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

pub(crate) enum ListenEvent {
    Msg { event: ProtoEvent, addr: SocketAddr },
    Accept { addr: SocketAddr, fingerprint: String },
    Rejected { fingerprint: String },
}

/// A live inbound connection plus the reply stream we opened back to the peer
/// and the fingerprint captured at accept time (so we never re-derive it).
struct ConnEntry {
    addr: SocketAddr,
    conn: Connection,
    send: Arc<AsyncMutex<SendStream>>,
    fingerprint: String,
}

pub(crate) struct LanMouseListener {
    listen_rx: Receiver<ListenEvent>,
    listen_tx: Sender<ListenEvent>,
    listen_task: JoinHandle<()>,
    conns: Rc<AsyncMutex<Vec<ConnEntry>>>,
    request_port_change: Sender<u16>,
    port_changed: Receiver<Result<u16, ListenerCreationError>>,
}

fn server_config(
    identity: &Identity,
    authorized: Authorized,
    attempts: Arc<StdMutex<VecDeque<String>>>,
) -> Result<quinn::ServerConfig, ListenerCreationError> {
    let verifier = Arc::new(FpClientVerifier::new(authorized, attempts));
    let mut crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![identity.cert.clone()], identity.key.clone_key())?;
    crypto.alpn_protocols = vec![transport::ALPN.to_vec()];
    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto)?));
    let mut transport_config = TransportConfig::default();
    // MUST be > 0 or the peer's single uni stream is never accepted.
    transport_config.max_concurrent_uni_streams(8u8.into());
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
        authorized: Authorized,
        clipboard_in: Sender<String>,
    ) -> Result<Self, ListenerCreationError> {
        transport::install_crypto_provider();
        let (listen_tx, listen_rx) = channel();
        let (request_port_change, mut request_port_change_rx) = channel();
        let (port_changed_tx, port_changed) = channel();
        let attempts: Arc<StdMutex<VecDeque<String>>> = Default::default();

        let cfg = server_config(&identity, authorized.clone(), attempts.clone())?;
        let listen_addr = SocketAddr::new("0.0.0.0".parse().expect("invalid ip"), port);
        let mut endpoint = Endpoint::server(cfg, listen_addr)?;

        let conns: Rc<AsyncMutex<Vec<ConnEntry>>> = Rc::new(AsyncMutex::new(Vec::new()));
        let conns_clone = conns.clone();

        let listen_task: JoinHandle<()> = {
            let listen_tx = listen_tx.clone();
            let attempts = attempts.clone();
            spawn_local(async move {
                loop {
                    tokio::select! {
                        incoming = endpoint.accept() => {
                            let Some(incoming) = incoming else { break };
                            // Drive each handshake on its own task so one slow
                            // peer can't head-of-line-block all other accepts.
                            let conns = conns_clone.clone();
                            let listen_tx = listen_tx.clone();
                            let attempts = attempts.clone();
                            let clipboard_in = clipboard_in.clone();
                            spawn_local(async move {
                                let remote = incoming.remote_address();
                                match incoming.await {
                                    Ok(conn) => {
                                        let addr = conn.remote_address();
                                        log::info!("client connected, ip: {addr}");
                                        let fingerprint = peer_fingerprint(&conn)
                                            .unwrap_or_else(|| "unknown".to_owned());
                                        let send = match conn.open_uni().await {
                                            Ok(s) => Arc::new(AsyncMutex::new(s)),
                                            Err(e) => {
                                                log::warn!("{addr}: opening reply stream failed: {e}");
                                                return;
                                            }
                                        };
                                        conns.lock().await.push(ConnEntry {
                                            addr,
                                            conn: conn.clone(),
                                            send,
                                            fingerprint: fingerprint.clone(),
                                        });
                                        let _ = listen_tx.send(ListenEvent::Accept { addr, fingerprint });
                                        spawn_local(read_loop(conns.clone(), addr, conn, listen_tx.clone(), clipboard_in));
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
                            let port = port.expect("channel closed");
                            let listen_addr = SocketAddr::new("0.0.0.0".parse().expect("invalid ip"), port);
                            match server_config(&identity, authorized.clone(), attempts.clone()) {
                                Ok(cfg) => match Endpoint::server(cfg, listen_addr) {
                                    Ok(new_endpoint) => {
                                        endpoint.close(0u32.into(), b"port change");
                                        endpoint = new_endpoint;
                                        port_changed_tx.send(Ok(port)).expect("channel closed");
                                    }
                                    Err(e) => {
                                        log::warn!("unable to change port: {e}");
                                        port_changed_tx.send(Err(e.into())).expect("channel closed");
                                    }
                                },
                                Err(e) => {
                                    log::warn!("unable to rebuild server config: {e}");
                                    port_changed_tx.send(Err(e)).expect("channel closed");
                                }
                            };
                        },
                    };
                }
            })
        };

        Ok(Self {
            conns,
            listen_rx,
            listen_tx,
            listen_task,
            port_changed,
            request_port_change,
        })
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

    pub(crate) async fn reply(&self, addr: SocketAddr, event: ProtoEvent) {
        log::trace!("reply {event} >=>=>=>=>=> {addr}");
        let send = {
            let conns = self.conns.lock().await;
            conns
                .iter()
                .find(|e| e.addr == addr)
                .map(|e| e.send.clone())
        };
        if let Some(send) = send {
            let mut send = send.lock().await;
            let _ = transport::write_frame(&mut send, event).await;
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

    /// A handle for broadcasting local clipboard changes to all connected
    /// peers. Grabbed before this listener is moved into `Emulation` so the
    /// service can drive it directly.
    pub(crate) fn clipboard_sender(&self) -> ClipboardSenderListen {
        ClipboardSenderListen {
            conns: self.conns.clone(),
        }
    }
}

/// Broadcasts clipboard text to every connected peer, each on its own
/// ephemeral uni stream. Cloneable handle over the shared connection list.
#[derive(Clone)]
pub(crate) struct ClipboardSenderListen {
    conns: Rc<AsyncMutex<Vec<ConnEntry>>>,
}

impl ClipboardSenderListen {
    pub(crate) async fn broadcast(&self, text: String) {
        let conns: Vec<Connection> = {
            let conns = self.conns.lock().await;
            conns.iter().map(|e| e.conn.clone()).collect()
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
    clipboard_in: Sender<String>,
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
    spawn_local(clipboard_accept_loop(conn.clone(), addr, clipboard_in));
    loop {
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

/// Accepts the peer's ephemeral clipboard uni streams (everything after the
/// primary input stream) and forwards each payload to the service.
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
            // connection closed — the input read_loop handles cleanup
            Err(_) => break,
        }
    }
}
