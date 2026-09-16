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

use crate::{FrontendEvent, FrontendRequest, IpcError, IpcListenerCreationError, ownership, token};

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

/// A daemon's exclusive hold on its IPC endpoint: the single-instance check.
///
/// The daemon takes it after opening its own log and before it reads or
/// writes anything else: the config, the token, the identity key and the trust
/// store all come later. A second daemon, started beside a running one or
/// racing another through startup, stops here with
/// [`IpcListenerCreationError::AlreadyRunning`].
///
/// On Unix the claim is a lock on a file beside the socket, taken before the
/// socket is checked, removed or bound. What it does not cover:
///
/// * **A lock that cannot be taken stops the daemon.** If the filesystem
///   refuses file locks, the daemon exits with
///   [`IpcListenerCreationError::Lock`] rather than run without the check.
/// * **The lock goes when the socket's directory is cleared.** Something that
///   deletes both files while a daemon runs (a clean-up of `~/Library/Caches`,
///   which macOS may purge, or of `$XDG_RUNTIME_DIR`, whose files the XDG base
///   directory specification lets a clean-up remove after six hours
///   untouched) leaves that daemon unreachable, and a second daemon can then
///   claim a new lock and socket and read the config and keys. It stops when
///   it binds the peer port the first still holds. On macOS the front door
///   does not start that second daemon, since launchd names the running
///   job's process instead.
///
///   The lock stays beside the socket anyway. `$XDG_RUNTIME_DIR` is the one
///   directory the specification requires to be local and to support file
///   locks; the config directory, which is not purged, may be a network home
///   where locks fail, and there the lock would stop the daemon starting at
///   all. A lock kept elsewhere would also leave the first daemon unreachable.
/// * **A daemon from before the lock takes none,** wherever the lock is kept.
///   It still refuses to start beside a socket that answers, and a newer
///   daemon refuses beside it, but the two starting at the same moment beside
///   a stale socket can both bind.
struct Claim {
    #[cfg(windows)]
    listener: TcpListener,
    #[cfg(unix)]
    listener: UnixListener,
    /// Where the listener is bound. For a TCP endpoint asked for on port 0,
    /// the port the system picked.
    endpoint: crate::DaemonEndpoint,
    /// An exclusive lock on `<socket>.lock`, held for the life of the listener.
    ///
    /// Without it, two daemons that both find a stale socket file can both
    /// bind: the second removes the file the first has just bound, and the
    /// first keeps a listener no frontend can reach. Holding the lock while
    /// checking, removing and binding makes those three steps one. The lock
    /// file is never deleted, since deleting it would let a later daemon lock
    /// a new file while this one still holds the old.
    #[cfg(unix)]
    _lock: std::fs::File,
}

impl Claim {
    #[cfg(unix)]
    async fn take(endpoint: &crate::DaemonEndpoint) -> Result<Self, IpcListenerCreationError> {
        let socket_path = match endpoint {
            crate::DaemonEndpoint::Unix(path) => path.clone(),
            crate::DaemonEndpoint::Tcp(_) => {
                return Err(IpcListenerCreationError::Bind {
                    endpoint: endpoint.clone(),
                    source: std::io::Error::new(
                        ErrorKind::Unsupported,
                        "the daemon listens on a Unix socket on this platform",
                    ),
                });
            }
        };
        let lock = lock_beside_with(&socket_path, ownership::foreign_owner)?;

        // `symlink_metadata`, not `exists`: a dangling link at the path would
        // otherwise pass as absent and fail the bind as if a daemon held it.
        if std::fs::symlink_metadata(&socket_path).is_ok() {
            // A daemon that predates the lock holds none, so ask the socket too.
            match UnixStream::connect(&socket_path).await {
                Ok(_) => return Err(IpcListenerCreationError::AlreadyRunning),
                // Nothing listens, and the lock says no other daemon is
                // starting, so the file is left over from one that is gone.
                Err(e) => {
                    log::debug!("{socket_path:?}: {e} - removing left behind socket");
                    match std::fs::remove_file(&socket_path) {
                        Err(source) if source.kind() != ErrorKind::NotFound => {
                            // Going on would fail the bind on the file still
                            // there, and report a daemon that is not running.
                            return Err(IpcListenerCreationError::StaleSocket {
                                path: socket_path,
                                source,
                            });
                        }
                        _ => {}
                    }
                }
            }
        }
        let listener = match UnixListener::bind(&socket_path) {
            Ok(ls) => ls,
            // A daemon that takes no lock bound the path since the check above.
            // Linux reports that as EADDRINUSE, macOS as EEXIST.
            Err(e) if matches!(e.kind(), ErrorKind::AddrInUse | ErrorKind::AlreadyExists) => {
                return Err(IpcListenerCreationError::AlreadyRunning);
            }
            Err(source) => {
                return Err(IpcListenerCreationError::Bind {
                    endpoint: endpoint.clone(),
                    source,
                });
            }
        };
        Ok(Self {
            listener,
            endpoint: endpoint.clone(),
            _lock: lock,
        })
    }

    #[cfg(windows)]
    async fn take(endpoint: &crate::DaemonEndpoint) -> Result<Self, IpcListenerCreationError> {
        let crate::DaemonEndpoint::Tcp(addr) = endpoint;
        let bind_error = |source| IpcListenerCreationError::Bind {
            endpoint: endpoint.clone(),
            source,
        };
        // A port has one listener, so the bind is the whole claim.
        let listener = match TcpListener::bind(*addr).await {
            Ok(listener) => listener,
            Err(e) if e.kind() == ErrorKind::AddrInUse => {
                return Err(IpcListenerCreationError::AlreadyRunning);
            }
            Err(e) => return Err(bind_error(e)),
        };
        let bound = listener.local_addr().map_err(bind_error)?;
        Ok(Self {
            listener,
            endpoint: crate::DaemonEndpoint::Tcp(bound),
        })
    }
}

/// Lock `<socket_path>.lock` exclusively, without waiting.
///
/// `whose` says who owns the lock file when opening it failed, as
/// [`ownership::foreign_owner`] does, so the error can say what to do.
#[cfg(unix)]
fn lock_beside_with(
    socket_path: &std::path::Path,
    whose: impl FnOnce(&std::path::Path, &std::io::Error) -> Option<ownership::Foreign>,
) -> Result<std::fs::File, IpcListenerCreationError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut name = socket_path.as_os_str().to_owned();
    name.push(".lock");
    let path = PathBuf::from(name);
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)
    {
        Ok(file) => file,
        Err(source) => {
            let hint = ownership::hint(
                whose(&path, &source),
                "hops keeps this file beside its socket so that a second daemon \
                 cannot start. Check that this user can create and write it.",
            );
            return Err(IpcListenerCreationError::Lock { path, source, hint });
        }
    };
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(IpcListenerCreationError::AlreadyRunning),
        Err(std::fs::TryLockError::Error(source)) => Err(IpcListenerCreationError::Lock {
            path,
            source,
            hint: "The filesystem that holds it may not support file locks, and \
                   hops does not run a daemon without this lock."
                .to_string(),
        }),
    }
}

/// Read the token frontends must present, or mint it. An error names the
/// file.
fn load_token() -> Result<String, IpcListenerCreationError> {
    let path = token::token_path().map_err(IpcListenerCreationError::TokenPath)?;
    load_token_with(&path, ownership::foreign_owner)
}

/// [`load_token`] for the token at `path`, with `whose` saying who owns it
/// when it cannot be used, as [`ownership::foreign_owner`] does.
fn load_token_with(
    path: &std::path::Path,
    whose: impl FnOnce(&std::path::Path, &std::io::Error) -> Option<ownership::Foreign>,
) -> Result<String, IpcListenerCreationError> {
    token::load_or_create_at(path).map_err(|source| {
        let hint = ownership::hint(
            whose(path, &source),
            "Frontends present this token to reach the daemon. Check that this \
             user can read and write it, and create files in its directory.",
        );
        IpcListenerCreationError::Token {
            path: path.to_path_buf(),
            source,
            hint,
        }
    })
}

#[cfg(unix)]
impl Drop for Claim {
    fn drop(&mut self) {
        // Still under the lock: fields are dropped after this body runs.
        log::debug!("remove socket: {}", self.endpoint);
        if let crate::DaemonEndpoint::Unix(path) = &self.endpoint {
            let _ = std::fs::remove_file(path);
        }
    }
}

pub struct AsyncFrontendListener {
    claim: Claim,
    line_streams: SelectAll<AuthedLines<ReadHalf<Sock>>>,
    tx_streams: Vec<TxStream>,
    /// the secret every frontend must present as its first line
    token: std::sync::Arc<str>,
}

impl AsyncFrontendListener {
    /// Claim this platform's endpoint, [`crate::DaemonEndpoint::of_this_platform`].
    pub async fn new() -> Result<Self, IpcListenerCreationError> {
        Self::at(&crate::DaemonEndpoint::of_this_platform()?).await
    }

    /// Claim `endpoint`, then load the token frontends must present.
    ///
    /// Returns [`IpcListenerCreationError::AlreadyRunning`] when another daemon
    /// holds the endpoint or is part-way through claiming it. Nothing but the
    /// claim's own lock file is read or written until the claim is held.
    pub async fn at(endpoint: &crate::DaemonEndpoint) -> Result<Self, IpcListenerCreationError> {
        let claim = Claim::take(endpoint).await?;
        Ok(Self {
            claim,
            token: load_token()?.into(),
            line_streams: SelectAll::new(),
            tx_streams: vec![],
        })
    }

    /// Where this listener is bound: the endpoint it was given, with the port
    /// filled in when that was a TCP endpoint on port 0.
    pub fn endpoint(&self) -> &crate::DaemonEndpoint {
        &self.claim.endpoint
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

impl Stream for AsyncFrontendListener {
    type Item = Result<FrontendRequest, IpcError>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Accept before reading. A connection's lines are read only once they
        // have been polled, which is also what asks to be woken when its token
        // arrives; accepted after the read, a new frontend waited unheard
        // until something else woke the daemon.
        while let Poll::Ready(Ok((stream, _))) = self.claim.listener.poll_accept(cx) {
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
        if let Poll::Ready(Some(request)) = self.line_streams.poll_next_unpin(cx) {
            return Poll::Ready(Some(request));
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

#[cfg(all(test, unix))]
mod at_most_one_daemon {
    //! **Decided 2026-09-16 (#159):** at most one daemon runs. The front door
    //! starts one only when none answers, but its probe and its start are two
    //! steps, and a login service can start one at any time. What keeps a
    //! second daemon from running beside the first is its claim on the IPC
    //! endpoint, so these tests take real claims on real sockets.

    use super::Claim;
    use crate::ownership::{Foreign, another_users};
    use crate::{DaemonEndpoint, IpcListenerCreationError};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Barrier};

    /// A socket path short enough for `sun_path`, unique to this test.
    fn socket_path(tag: &str) -> PathBuf {
        PathBuf::from(format!("/tmp/h-claim-{tag}-{}.sock", std::process::id()))
    }

    fn remove(path: &Path) {
        let _ = std::fs::remove_file(path);
        let mut lock = path.as_os_str().to_owned();
        lock.push(".lock");
        let _ = std::fs::remove_file(PathBuf::from(lock));
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("a runtime")
    }

    fn describe(got: &Result<Claim, IpcListenerCreationError>) -> String {
        match got {
            Ok(_) => "claimed".to_string(),
            Err(e) => format!("{e:?}"),
        }
    }

    /// Take `threads` claims on `endpoint` at once, holding every claim until
    /// all have answered. Returns what each one got.
    fn contend(endpoint: &DaemonEndpoint, threads: usize) -> Vec<String> {
        let start = Arc::new(Barrier::new(threads));
        let answered = Arc::new(Barrier::new(threads));
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let (start, answered, endpoint) =
                    (start.clone(), answered.clone(), endpoint.clone());
                std::thread::spawn(move || {
                    let rt = runtime();
                    start.wait();
                    let got = rt.block_on(Claim::take(&endpoint));
                    answered.wait();
                    let outcome = describe(&got);
                    drop(got);
                    outcome
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("a claiming thread"))
            .collect()
    }

    // LEDGER T7 | class B | 1 return value / error
    #[test]
    fn a_daemon_starting_beside_a_running_one_is_refused() {
        let path = socket_path("live");
        remove(&path);
        let endpoint = DaemonEndpoint::Unix(path.clone());
        let rt = runtime();

        let running = rt
            .block_on(Claim::take(&endpoint))
            .expect("the first daemon claims a free endpoint");
        let second = rt.block_on(Claim::take(&endpoint));
        let (second, socket_kept) = (describe(&second), path.exists());
        drop(running);
        assert_eq!(
            (second.as_str(), socket_kept),
            ("AlreadyRunning", true),
            "a second daemon claimed an endpoint a running daemon holds, or \
             removed its socket. Two daemons would then load the same identity \
             key and trust store, and frontends could reach only one of them."
        );

        // A daemon that predates the lock holds none; its socket still answers.
        remove(&path);
        let older = std::os::unix::net::UnixListener::bind(&path).expect("a unix listener");
        let second = describe(&rt.block_on(Claim::take(&endpoint)));
        let still_answers = std::os::unix::net::UnixStream::connect(&path).is_ok();
        drop(older);
        remove(&path);
        assert_eq!(
            (second.as_str(), still_answers),
            ("AlreadyRunning", true),
            "a daemon started beside one that holds no lock took over its socket"
        );
    }

    // LEDGER T8 | class B | 1 return value / error
    #[test]
    fn of_daemons_starting_together_beside_a_stale_socket_exactly_one_runs() {
        const ROUNDS: usize = 40;
        const DAEMONS: usize = 8;
        let path = socket_path("stale");
        let endpoint = DaemonEndpoint::Unix(path.clone());
        for round in 0..ROUNDS {
            remove(&path);
            // Dropping a listener leaves its file behind, as a crashed daemon does.
            drop(std::os::unix::net::UnixListener::bind(&path).expect("a socket file"));

            let got = contend(&endpoint, DAEMONS);
            let claimed = got.iter().filter(|g| *g == "claimed").count();
            let refused = got.iter().filter(|g| *g == "AlreadyRunning").count();
            if (claimed, refused) != (1, DAEMONS - 1) {
                remove(&path);
            }
            assert_eq!(
                (claimed, refused),
                (1, DAEMONS - 1),
                "round {round}: {got:?}. Each daemon found the stale socket, and \
                 more than one went on to bind. A later one removes the file an \
                 earlier one has bound, so the earlier daemon keeps running with \
                 a listener no frontend can reach: a device removed in the app is \
                 never removed there."
            );
        }
        remove(&path);
    }

    // LEDGER T15 | class B | 1 return value / error
    #[test]
    fn a_lock_file_that_cannot_be_opened_is_named_in_the_error() {
        let path = socket_path("lockdir");
        remove(&path);
        let mut lock = path.as_os_str().to_owned();
        lock.push(".lock");
        let lock = PathBuf::from(lock);
        let _ = std::fs::remove_dir_all(&lock);
        // A directory where the lock file belongs fails the open for any user,
        // root included, as a file this user may not write does for most.
        std::fs::create_dir(&lock).expect("a directory in the lock file's place");

        let got = runtime().block_on(Claim::take(&DaemonEndpoint::Unix(path.clone())));
        let _ = std::fs::remove_dir_all(&lock);
        remove(&path);

        let Err(e @ IpcListenerCreationError::Lock { .. }) = got else {
            panic!(
                "expected a lock error naming {lock:?}, got {}. A daemon that \
                 cannot open its lock file must say which file, or the user is \
                 left with an OS error and nothing to act on.",
                describe(&got)
            );
        };
        let IpcListenerCreationError::Lock { path: named, .. } = &e else {
            unreachable!()
        };
        assert_eq!(named, &lock, "the error names a different file: {e}");
        assert!(
            e.to_string().contains(&lock.display().to_string()),
            "the message does not name the lock file: {e}"
        );
    }

    // LEDGER T25 | class B | 1 return value / error
    #[test]
    fn a_lock_file_another_user_owns_is_reported_as_theirs() {
        let path = socket_path("lockowner");
        remove(&path);
        let mut lock = path.as_os_str().to_owned();
        lock.push(".lock");
        let lock = PathBuf::from(lock);
        let _ = std::fs::remove_dir_all(&lock);
        // A directory in the lock file's place fails the open for any user.
        // Only root can make a file another user owns, so the owner is given.
        std::fs::create_dir(&lock).expect("a directory in the lock file's place");
        let root_owns_it = Foreign {
            path: lock.clone(),
            owner: 0,
            me: 501,
        };
        let asked = std::cell::RefCell::new(None);
        let theirs = super::lock_beside_with(&path, |at, _| {
            *asked.borrow_mut() = Some(at.to_path_buf());
            Some(root_owns_it.clone())
        });
        let mine = super::lock_beside_with(&path, |_, _| None);
        let _ = std::fs::remove_dir_all(&lock);
        remove(&path);

        let hint_of = |got: Result<std::fs::File, IpcListenerCreationError>| match got {
            Err(IpcListenerCreationError::Lock { hint, .. }) => hint,
            other => format!("not a lock error: {other:?}"),
        };
        assert_eq!(
            (asked.into_inner(), hint_of(theirs)),
            (Some(lock.clone()), another_users(&root_owns_it)),
            "a lock file that belongs to another user must be reported as theirs, \
             with what to do, or a daemon left behind by `sudo hops` stops every \
             later start with only an OS error"
        );
        assert!(
            hint_of(mine).contains("Check that this user can create and write it"),
            "a lock file this user owns must get the ordinary hint"
        );
    }

    // LEDGER T19 | class B | 1 return value / error
    #[test]
    fn a_leftover_socket_that_cannot_be_removed_is_not_reported_as_a_running_daemon() {
        let path = socket_path("stuck");
        remove(&path);
        let _ = std::fs::remove_dir_all(&path);
        // Nothing can listen on a directory, and removing a file cannot remove it.
        std::fs::create_dir(&path).expect("a directory in the socket's place");
        std::fs::write(path.join("keep"), b"").expect("a file inside it");

        let got = runtime().block_on(Claim::take(&DaemonEndpoint::Unix(path.clone())));
        let outcome = describe(&got);
        let message = got
            .as_ref()
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        let _ = std::fs::remove_dir_all(&path);
        remove(&path);

        assert!(
            matches!(got, Err(IpcListenerCreationError::StaleSocket { .. }))
                && message.contains(&path.display().to_string()),
            "got {outcome}: {message}. Nothing answered on the socket path and it \
             could not be cleared. Reporting that as a running daemon makes the \
             daemon exit 0, which launchd does not restart, with no daemon running."
        );
    }
}

#[cfg(test)]
mod the_token_error_names_the_file {
    //! The daemon cannot start without the token frontends present. When it
    //! cannot read or create it, the error names the file and says what to do.

    use super::load_token_with;
    use crate::IpcListenerCreationError;
    use crate::ownership::{Foreign, another_users};

    // LEDGER T27 | class B | 1 return value / error
    #[test]
    fn a_token_that_cannot_be_read_or_created_is_named_with_its_owner() {
        let dir = std::env::temp_dir().join(format!("hops-token-error-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("ipc-token");
        // A directory in the token's place can be neither read nor written as a
        // file, by any user.
        std::fs::create_dir_all(&path).expect("a directory in the token's place");
        let root_owns_it = Foreign {
            path: path.clone(),
            owner: 0,
            me: 501,
        };

        let asked = std::cell::RefCell::new(None);
        let theirs = load_token_with(&path, |at, _| {
            *asked.borrow_mut() = Some(at.to_path_buf());
            Some(root_owns_it.clone())
        });
        let mine = load_token_with(&path, |_, _| None);
        let _ = std::fs::remove_dir_all(&dir);

        let (named, message, hint) = match theirs {
            Err(e @ IpcListenerCreationError::Token { .. }) => {
                let message = e.to_string();
                let IpcListenerCreationError::Token { path, hint, .. } = e else {
                    unreachable!()
                };
                (path, message, hint)
            }
            other => panic!("expected a token error, got {other:?}"),
        };
        assert_eq!(
            (asked.into_inner(), named, hint),
            (
                Some(path.clone()),
                path.clone(),
                another_users(&root_owns_it)
            ),
            "the token error must name the token file and, when another user owns \
             it, say so. Before, a token left behind by `sudo hops` stopped the \
             daemon with only \"Permission denied\", and launchd restarted it every \
             ten seconds."
        );
        assert!(
            message.contains(&path.display().to_string()),
            "the message does not name the token file: {message}"
        );
        assert!(
            matches!(&mine, Err(IpcListenerCreationError::Token { hint, .. })
                if hint.contains("Check that this user can read and write it")),
            "a token this user owns must get the ordinary hint: {mine:?}"
        );
    }
}
