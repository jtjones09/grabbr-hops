use futures::{Stream, StreamExt, stream::SelectAll};
#[cfg(unix)]
use std::path::PathBuf;
use std::{
    io::ErrorKind,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
use tokio_stream::wrappers::LinesStream;

#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(unix)]
use tokio::net::UnixStream;

#[cfg(windows)]
use tokio::net::TcpListener;
#[cfg(windows)]
use tokio::net::TcpStream;

use crate::{FrontendEvent, FrontendRequest, IpcError, IpcListenerCreationError, token};

/// The frontend transport. One alias instead of paired `cfg` attributes on every
/// field, so the two platforms cannot drift apart silently.
#[cfg(unix)]
type Sock = UnixStream;
#[cfg(windows)]
type Sock = TcpStream;

/// How long a single frontend may stall a broadcast before it is dropped.
///
/// The daemon writes to frontends from inside its main `select!`, so an
/// un-timeouted write to a client that has stopped reading freezes EVERYTHING —
/// revocation and Ctrl-C included. A healthy local frontend reads immediately;
/// anything that cannot manage 250 ms is disconnected rather than tolerated.
///
/// This bounds the damage, it does not eliminate it: one stalled broadcast still
/// costs 250 ms before the client is dropped. The durable fix is a bounded queue
/// and a writer task per client so the service never awaits a socket at all.
const WRITE_STALL_LIMIT: Duration = Duration::from_millis(250);

/// State shared between the two halves of one frontend connection.
///
/// `tokio::io::split` gives the halves a single underlying socket, so dropping
/// the read half does NOT close the connection while the write half is still
/// held — the previous code believed it did. These flags are how the read half
/// tells the listener to stop writing to, and let go of, its partner.
#[derive(Default)]
struct ConnState {
    /// set once the token has been presented; until then the connection is
    /// written to by nobody
    authed: AtomicBool,
    /// set when the read half hangs up, so the write half goes with it
    closed: AtomicBool,
}

/// A frontend connection that must present the IPC token before anything it says
/// is honoured — or anything is said TO it — and that is HUNG UP on rather than
/// tolerated when it sends something unparseable.
struct AuthedLines<R> {
    lines: LinesStream<BufReader<R>>,
    token: std::sync::Arc<str>,
    authed: bool,
    state: Arc<ConnState>,
}

impl<R: tokio::io::AsyncRead + Unpin> Stream for AuthedLines<R> {
    type Item = Result<FrontendRequest, IpcError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            let line = match this.lines.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    this.state.closed.store(true, Ordering::Release);
                    return Poll::Ready(None);
                }
                Poll::Ready(Some(Err(e))) => {
                    log::debug!("frontend connection read error: {e}");
                    this.state.closed.store(true, Ordering::Release);
                    return Poll::Ready(None);
                }
                Poll::Ready(Some(Ok(l))) => l,
            };
            if !this.authed {
                if !token::matches(&this.token, line.trim()) {
                    log::warn!(
                        "frontend connection presented a bad IPC token — closing it. \
                         A local process tried to drive the daemon without being able \
                         to read the token file."
                    );
                    this.state.closed.store(true, Ordering::Release);
                    return Poll::Ready(None);
                }
                this.authed = true;
                this.state.authed.store(true, Ordering::Release);
                continue;
            }
            match serde_json::from_str(line.as_str()) {
                Ok(request) => return Poll::Ready(Some(Ok(request))),
                Err(e) => {
                    // Hang up rather than skip. Tolerating junk let an attacker
                    // prepend arbitrary lines (e.g. HTTP headers) before a real
                    // request.
                    log::warn!("frontend sent an unparseable request ({e}) — closing it");
                    this.state.closed.store(true, Ordering::Release);
                    return Poll::Ready(None);
                }
            }
        }
    }
}

/// The write half of one frontend connection, plus the state its read half
/// publishes. `synced` records whether this connection has already been sent the
/// initial state dump, so authenticating emits exactly one `Sync`.
struct TxStream {
    tx: WriteHalf<Sock>,
    state: Arc<ConnState>,
    synced: bool,
}

/// Decide the fate of one frontend on one broadcast. Returns whether to keep it.
///
/// Separate from [`AsyncFrontendListener::broadcast`] so the three rules it
/// encodes can be tested without standing up a socket listener.
async fn write_one(entry: &mut TxStream, bytes: &[u8]) -> bool {
    // The read half hung up. `tokio::io::split` shares one socket, so holding
    // this write half is what kept the connection alive.
    if entry.state.closed.load(Ordering::Acquire) {
        return false;
    }
    // Never write to a connection that has not presented the token. `Sync`
    // carries the entire trust store, this machine's own fingerprint and its
    // pairing code; before this gate existed, a bare connect was enough to
    // receive all of it.
    if !entry.state.authed.load(Ordering::Acquire) {
        return true;
    }
    // `write_all`, not `write`: a short write used to be treated as a full one,
    // silently truncating the event mid-JSON. And bounded, or one client that
    // stops reading freezes the whole daemon.
    match tokio::time::timeout(WRITE_STALL_LIMIT, entry.tx.write_all(bytes)).await {
        Ok(Ok(())) => true,
        Ok(Err(e)) => {
            log::debug!("frontend write failed ({e}) — dropping it");
            false
        }
        Err(_) => {
            log::warn!(
                "a frontend stopped reading for {WRITE_STALL_LIMIT:?} — dropping it rather \
                 than letting it stall the daemon"
            );
            false
        }
    }
}

pub struct AsyncFrontendListener {
    #[cfg(windows)]
    listener: TcpListener,
    #[cfg(unix)]
    listener: UnixListener,
    #[cfg(unix)]
    socket_path: PathBuf,
    line_streams: SelectAll<AuthedLines<ReadHalf<Sock>>>,
    tx_streams: Vec<TxStream>,
    /// the secret every frontend must present as its first line
    token: std::sync::Arc<str>,
}

impl AsyncFrontendListener {
    pub async fn new() -> Result<Self, IpcListenerCreationError> {
        #[cfg(unix)]
        let (socket_path, listener) = {
            let socket_path = crate::default_socket_path()?;

            log::debug!("remove socket: {socket_path:?}");
            if socket_path.exists() {
                // try to connect to see if some other instance
                // of lan-mouse is already running
                match UnixStream::connect(&socket_path).await {
                    // connected -> lan-mouse is already running
                    Ok(_) => return Err(IpcListenerCreationError::AlreadyRunning),
                    // lan-mouse is not running but a socket was left behind
                    Err(e) => {
                        log::debug!("{socket_path:?}: {e} - removing left behind socket");
                        let _ = std::fs::remove_file(&socket_path);
                    }
                }
            }
            let listener = match UnixListener::bind(&socket_path) {
                Ok(ls) => ls,
                // some other lan-mouse instance has bound the socket in the meantime
                Err(e) if e.kind() == ErrorKind::AddrInUse => {
                    return Err(IpcListenerCreationError::AlreadyRunning);
                }
                Err(e) => return Err(IpcListenerCreationError::Bind(e)),
            };
            (socket_path, listener)
        };

        #[cfg(windows)]
        let listener = match TcpListener::bind("127.0.0.1:5252").await {
            Ok(ls) => ls,
            // some other lan-mouse instance has bound the socket in the meantime
            Err(e) if e.kind() == ErrorKind::AddrInUse => {
                return Err(IpcListenerCreationError::AlreadyRunning);
            }
            Err(e) => return Err(IpcListenerCreationError::Bind(e)),
        };

        let adapter = Self {
            listener,
            token: token::load_or_create()
                .map_err(IpcListenerCreationError::Bind)?
                .into(),
            #[cfg(unix)]
            socket_path,
            line_streams: SelectAll::new(),
            tx_streams: vec![],
        };

        Ok(adapter)
    }

    pub async fn broadcast(&mut self, notify: FrontendEvent) {
        // encode event
        let mut json = serde_json::to_string(&notify).unwrap();
        json.push('\n');

        let mut keep = Vec::with_capacity(self.tx_streams.len());
        for entry in self.tx_streams.iter_mut() {
            keep.push(write_one(entry, json.as_bytes()).await);
        }

        let mut keep = keep.into_iter();
        self.tx_streams.retain(|_| keep.next().unwrap());
    }
}

#[cfg(unix)]
impl Drop for AsyncFrontendListener {
    fn drop(&mut self) {
        log::debug!("remove socket: {:?}", self.socket_path);
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

impl Stream for AsyncFrontendListener {
    type Item = Result<FrontendRequest, IpcError>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Poll::Ready(Some(request)) = self.line_streams.poll_next_unpin(cx) {
            return Poll::Ready(Some(request));
        }
        while let Poll::Ready(Ok((stream, _))) = self.listener.poll_accept(cx) {
            let (rx, tx) = tokio::io::split(stream);
            let lines = LinesStream::new(BufReader::new(rx).lines());
            let token = self.token.clone();
            let state = Arc::new(ConnState::default());
            self.line_streams.push(AuthedLines {
                lines,
                token,
                authed: false,
                state: state.clone(),
            });
            // Registered, but not yet spoken to. Accepting is not authenticating.
            self.tx_streams.push(TxStream {
                tx,
                state,
                synced: false,
            });
        }

        // Let go of write halves whose read half hung up, and emit the initial
        // state dump for connections that have just authenticated. `Sync` is
        // global — one is enough no matter how many authenticated at once.
        self.tx_streams
            .retain(|e| !e.state.closed.load(Ordering::Acquire));
        let mut sync = false;
        for entry in self.tx_streams.iter_mut() {
            if !entry.synced && entry.state.authed.load(Ordering::Acquire) {
                entry.synced = true;
                sync = true;
            }
        }
        if sync {
            Poll::Ready(Some(Ok(FrontendRequest::Sync)))
        } else {
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AuthedLines;
    use crate::FrontendRequest;
    use futures::StreamExt;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio_stream::wrappers::LinesStream;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// Feed `script` to a fresh connection and collect what the daemon accepts.
    async fn drive(script: &str) -> Vec<FrontendRequest> {
        let (mut client, server) = tokio::io::duplex(4096);
        client.write_all(script.as_bytes()).await.expect("write");
        client.shutdown().await.expect("shutdown");
        let mut stream = AuthedLines {
            lines: LinesStream::new(BufReader::new(server).lines()),
            token: TOKEN.into(),
            authed: false,
            state: std::sync::Arc::new(super::ConnState::default()),
        };
        let mut out = vec![];
        while let Some(Ok(req)) = stream.next().await {
            out.push(req);
        }
        out
    }

    #[tokio::test]
    async fn the_token_admits_a_request() {
        let got = drive(&format!("{TOKEN}\n{{\"Enumerate\":[]}}\n")).await;
        assert_eq!(got.len(), 1, "an authenticated request must be honoured");
    }

    #[tokio::test]
    async fn no_token_means_no_requests() {
        let got = drive("{\"Enumerate\":[]}\n").await;
        assert!(got.is_empty(), "a request with no token must be refused");
    }

    #[tokio::test]
    async fn a_wrong_token_hangs_up_before_anything_is_honoured() {
        let got = drive(&format!("{}\n{{\"Enumerate\":[]}}\n", "f".repeat(64))).await;
        assert!(got.is_empty(), "a bad token must close the connection");
    }

    /// THE attack: a web page can POST to 127.0.0.1:5252 because `text/plain` is
    /// CORS-safelisted (no preflight). It cannot read the response, but the side
    /// effect would land. This must die on the HTTP request line, long before the
    /// body — and the body here is a REAL AuthorizeKey, so a regression is loud.
    #[tokio::test]
    async fn an_http_post_from_a_browser_is_refused() {
        let body = r#"{"AuthorizeKey":["attacker","aa:bb:cc:dd"]}"#;
        let got = drive(&format!(
            "POST / HTTP/1.1\r\nHost: 127.0.0.1:5252\r\n\
             Content-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}\n",
            body.len()
        ))
        .await;
        assert!(
            got.is_empty(),
            "a browser-shaped POST must never reach the daemon — it got: {got:?}"
        );
    }

    /// Junk after a GOOD token must also hang up, not be skipped: tolerating it
    /// is what let an attacker prepend arbitrary lines to a real request.
    #[tokio::test]
    async fn garbage_after_a_good_token_closes_the_connection() {
        let got = drive(&format!("{TOKEN}\nnot json at all\n{{\"Enumerate\":[]}}\n")).await;
        assert!(
            got.is_empty(),
            "the connection must close on the junk line, not skip it"
        );
    }
}

#[cfg(all(test, unix))]
mod preauth_and_liveness {
    //! The three rules `write_one` encodes, one test each.
    //!
    //! Before 2026-08-31 the write half of every accepted socket went into
    //! `tx_streams` unconditionally and `poll_next` emitted `Sync` on accept, so
    //! a bare connect — no token, or a WRONG token — received the entire trust
    //! store, this machine's fingerprint and its pairing code (#70). And
    //! `broadcast` awaited `tx.write()` with no timeout inside the service's main
    //! `select!`, so one client that stopped reading froze the daemon, revocation
    //! and Ctrl-C included (#65, #71).

    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::UnixStream;

    /// A connection whose peer we keep, so we can control whether it reads.
    fn conn() -> (TxStream, UnixStream) {
        let (a, b) = UnixStream::pair().expect("socketpair");
        let (_rx, tx) = tokio::io::split(a);
        (
            TxStream {
                tx,
                state: Arc::new(ConnState::default()),
                synced: false,
            },
            b,
        )
    }

    #[tokio::test]
    async fn an_unauthenticated_connection_is_never_written_to() {
        let (mut entry, mut peer) = conn();
        assert!(
            write_one(&mut entry, b"{\"AuthorizedUpdated\":{}}\n").await,
            "an unauthenticated connection is kept, just not spoken to"
        );

        // Nothing may have reached the peer. Read with a timeout: a successful
        // read of even one byte is the bug.
        let mut buf = [0u8; 64];
        let got = tokio::time::timeout(Duration::from_millis(150), peer.read(&mut buf)).await;
        assert!(
            got.is_err(),
            "an unauthenticated frontend received {:?} — that payload is the trust store",
            got.map(|r| r.map(|n| String::from_utf8_lossy(&buf[..n]).to_string()))
        );
    }

    #[tokio::test]
    async fn an_authenticated_connection_receives_the_whole_payload() {
        let (mut entry, mut peer) = conn();
        entry.state.authed.store(true, Ordering::Release);
        assert!(write_one(&mut entry, b"hello\n").await);

        let mut buf = [0u8; 6];
        tokio::time::timeout(Duration::from_millis(500), peer.read_exact(&mut buf))
            .await
            .expect("no stall")
            .expect("read");
        assert_eq!(&buf, b"hello\n", "write_all must deliver every byte");
    }

    #[tokio::test]
    async fn a_client_that_stops_reading_is_dropped_not_tolerated() {
        let (mut entry, peer) = conn();
        entry.state.authed.store(true, Ordering::Release);
        // Never read from `peer`. The socket buffer fills and the write pends.
        let big = vec![b'x'; 8 * 1024 * 1024];

        let started = tokio::time::Instant::now();
        let keep = write_one(&mut entry, &big).await;
        let waited = started.elapsed();

        assert!(!keep, "a frontend that stalls the daemon must be dropped");
        assert!(
            waited < WRITE_STALL_LIMIT * 4,
            "broadcast blocked for {waited:?} — it must be bounded, not open-ended"
        );
        drop(peer);
    }

    #[tokio::test]
    async fn a_hung_up_read_half_releases_its_write_half() {
        // tokio::io::split shares one socket between the halves, so dropping the
        // read half does NOT close the connection while the write half is held.
        // The close flag is what actually lets go.
        let (mut entry, _peer) = conn();
        entry.state.authed.store(true, Ordering::Release);
        entry.state.closed.store(true, Ordering::Release);
        assert!(
            !write_one(&mut entry, b"x\n").await,
            "a connection whose read half hung up must be released"
        );
    }
}
