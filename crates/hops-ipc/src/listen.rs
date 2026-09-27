use futures::{
    Stream, StreamExt,
    stream::{FuturesUnordered, SelectAll},
};
#[cfg(unix)]
use std::path::PathBuf;
use std::{
    future::Future,
    io::ErrorKind,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use tokio::io::{
    AsyncBufRead, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadHalf, WriteHalf,
};

#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(unix)]
use tokio::net::UnixStream;

use crate::{
    FrontendEvent, FrontendRequest, IpcError, IpcListenerCreationError, ownership, proof, token,
};

/// The frontend transport. One alias instead of paired `cfg` attributes on every
/// field, so the two platforms cannot drift apart silently.
#[cfg(unix)]
type Sock = UnixStream;
#[cfg(windows)]
type Sock = tokio::net::windows::named_pipe::NamedPipeServer;

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
    /// set once the frontend has made the two-way proof; until then nothing
    /// but the proof's answer is written to the connection
    authed: AtomicBool,
    /// set when either half ends the connection: the read half hanging up,
    /// so the write half goes with it, or a write that did not finish, so
    /// nothing more is read from it either
    closed: AtomicBool,
}

/// The longest line a connection may send before it has proven it holds the
/// token.
///
/// The only lines accepted before then are the two-way proof's challenge and
/// proof ([`crate::proof`]), each a word and 64 hex digits. Twice the token's
/// length leaves room for those and the whitespace the parsing trims, and for
/// nothing else. There was no cap: a client that never sent a newline was
/// read into memory until the daemon was killed, and on Windows any signed-in
/// user could reach the port the daemon listened on then (#175).
pub(crate) const PREAUTH_LINE_MAX: usize = 2 * token::TOKEN_CHARS;

/// How long a connection may stay open without proving it holds the token.
///
/// Every frontend starts the proof the moment it connects, and finishes it
/// as soon as the daemon answers. Before this there was no deadline, so a
/// connection that sent a few bytes and then nothing was held, with its read
/// buffer, until the client closed it (#175).
pub const PREAUTH_DEADLINE: Duration = Duration::from_secs(10);

/// How many connections may be part-way through the proof at once. A
/// connection accepted beyond this is closed at once.
///
/// Each costs a read buffer and its bookkeeping, about 9 KiB. There was no
/// limit: thousands of idle connections grew the daemon by tens of MiB
/// (#175). Frontends that have made the proof do not count.
pub const PREAUTH_CONNECTIONS_MAX: usize = 32;

/// Why a line could not be read.
#[derive(Debug)]
enum LineError {
    /// More than this many bytes arrived without a newline.
    TooLong(usize),
    Io(std::io::Error),
}

/// Newline-terminated lines, refusing any longer than a maximum.
///
/// `tokio`'s own `lines()` extends its buffer until a newline arrives, with no
/// maximum. This reads the same lines: a trailing `\r` is dropped, and a last
/// line with no newline before the end of the stream is still returned.
struct Lines<R> {
    reader: BufReader<R>,
    /// The line read so far. Never longer than `max`.
    line: Vec<u8>,
    /// The longest line accepted; `None` for no limit.
    max: Option<usize>,
}

impl<R: AsyncRead + Unpin> Lines<R> {
    fn new(reader: R, max: Option<usize>) -> Self {
        Self {
            reader: BufReader::new(reader),
            line: Vec::new(),
            max,
        }
    }

    fn poll_next_line(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<String, LineError>>> {
        loop {
            let available = match Pin::new(&mut self.reader).poll_fill_buf(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(LineError::Io(e)))),
                Poll::Ready(Ok(available)) => available,
            };
            if available.is_empty() {
                if self.line.is_empty() {
                    return Poll::Ready(None);
                }
                return Poll::Ready(Some(self.take_line()));
            }
            let newline = available.iter().position(|&b| b == b'\n');
            let kept = newline.unwrap_or(available.len());
            // Checked before anything is kept, so the line never outgrows it.
            if let Some(max) = self.max {
                if self.line.len() + kept > max {
                    return Poll::Ready(Some(Err(LineError::TooLong(max))));
                }
            }
            self.line.extend_from_slice(&available[..kept]);
            let used = newline.map_or(kept, |at| at + 1);
            Pin::new(&mut self.reader).consume(used);
            if newline.is_some() {
                return Poll::Ready(Some(self.take_line()));
            }
        }
    }

    fn take_line(&mut self) -> Result<String, LineError> {
        let mut line = std::mem::take(&mut self.line);
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        String::from_utf8(line)
            .map_err(|e| LineError::Io(std::io::Error::new(ErrorKind::InvalidData, e)))
    }
}

/// A frontend connection that has made the two-way proof. What it sends is
/// honoured, and it is HUNG UP on rather than tolerated when it sends
/// something unparseable.
struct AuthedLines<R> {
    lines: Lines<R>,
    state: Arc<ConnState>,
}

impl<R: AsyncRead + Unpin> AuthedLines<R> {
    /// The requests on a connection [`admit`] returned.
    fn admitted(lines: Lines<R>, state: Arc<ConnState>) -> Self {
        state.authed.store(true, Ordering::Release);
        Self { lines, state }
    }
}

impl<R: AsyncRead + Unpin> Stream for AuthedLines<R> {
    type Item = Result<FrontendRequest, IpcError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        // The write half closed the connection: nothing more is read from it.
        if this.state.closed.load(Ordering::Acquire) {
            return Poll::Ready(None);
        }
        let line = match this.lines.poll_next_line(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Some(Ok(l))) => l,
            Poll::Ready(None) => {
                this.state.closed.store(true, Ordering::Release);
                return Poll::Ready(None);
            }
            Poll::Ready(Some(Err(e))) => {
                log::debug!("frontend connection read error: {e:?}");
                this.state.closed.store(true, Ordering::Release);
                return Poll::Ready(None);
            }
        };
        match serde_json::from_str(line.as_str()) {
            Ok(request) => Poll::Ready(Some(Ok(request))),
            Err(e) => {
                // Hang up rather than skip. Tolerating junk let an attacker
                // prepend arbitrary lines (e.g. HTTP headers) before a real
                // request.
                log::warn!("frontend sent an unparseable request ({e}) — closing it");
                this.state.closed.store(true, Ordering::Release);
                Poll::Ready(None)
            }
        }
    }
}

/// The next line of a connection that has not made the proof, or `None`
/// once it has ended or sent more than [`PREAUTH_LINE_MAX`] bytes of one.
async fn preauth_line<R: AsyncRead + Unpin>(lines: &mut Lines<R>) -> Option<String> {
    match std::future::poll_fn(|cx| lines.poll_next_line(cx)).await {
        Some(Ok(line)) => Some(line),
        // Closed before the proof: a probe asking whether anything listens.
        None => None,
        Some(Err(LineError::TooLong(max))) => {
            log::warn!(
                "a frontend connection sent more than {max} bytes without a newline \
                 before proving it holds the IPC token — closing it"
            );
            None
        }
        Some(Err(LineError::Io(e))) => {
            log::debug!("frontend connection read error: {e}");
            None
        }
    }
}

/// Make the daemon's half of the two-way proof ([`crate::proof`]) on a
/// connection just accepted.
///
/// Returns the connection once the frontend has proven it holds `token`,
/// or `None` when it has not, which closes it. Before then no line longer
/// than [`PREAUTH_LINE_MAX`] is read, and the only thing written is the
/// answer to a well-formed challenge. The caller bounds the whole of it by
/// [`PREAUTH_DEADLINE`].
async fn admit<R, W>(rx: R, mut tx: W, token: Arc<str>) -> Option<(Lines<R>, W)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut lines = Lines::new(rx, Some(PREAUTH_LINE_MAX));
    let first = preauth_line(&mut lines).await?;
    let Some(nf) = proof::challenge_in(&first).map(str::to_string) else {
        if token::matches(&token, first.trim()) {
            log::warn!(
                "a frontend from before the two-way proof sent the IPC token itself — \
                 closing it. Update that frontend to this build."
            );
        } else {
            log::warn!(
                "a frontend connection opened with something other than the proof's \
                 challenge — closing it. A local process tried to drive the daemon \
                 without holding the IPC token."
            );
        }
        return None;
    };
    let nd = match proof::nonce() {
        Ok(nd) => nd,
        Err(e) => {
            log::warn!("could not answer a frontend's challenge: {e}");
            return None;
        }
    };
    let answer = proof::answer_line(&token, &nf, &nd);
    match tokio::time::timeout(WRITE_STALL_LIMIT, tx.write_all(answer.as_bytes())).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            log::debug!("could not answer a frontend's challenge ({e}) — closing it");
            return None;
        }
        Err(_) => {
            log::warn!(
                "a frontend did not read the answer to its challenge within \
                 {WRITE_STALL_LIMIT:?} — closing it"
            );
            return None;
        }
    }
    let second = preauth_line(&mut lines).await?;
    if !proof::frontend_proven(&token, &nf, &nd, &second) {
        log::warn!(
            "a frontend connection did not prove it holds the IPC token — closing it. \
             A local process tried to drive the daemon without being able to read \
             the token file."
        );
        return None;
    }
    // A frontend that holds the token may send requests of any length.
    lines.max = None;
    Some((lines, tx))
}

/// [`admit`], given up on after [`PREAUTH_DEADLINE`].
async fn admit_in_time<R, W>(rx: R, tx: W, token: Arc<str>) -> Option<(Lines<R>, W)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match tokio::time::timeout(PREAUTH_DEADLINE, admit(rx, tx, token)).await {
        Ok(admitted) => admitted,
        Err(_) => {
            log::warn!(
                "a frontend connection did not prove it holds the IPC token within \
                 {PREAUTH_DEADLINE:?} — closing it"
            );
            None
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
    // carries the entire trust store and this machine's own fingerprint;
    // before this gate existed, a bare connect was enough to receive all of
    // it.
    if !entry.state.authed.load(Ordering::Acquire) {
        return true;
    }
    // `write_all`, not `write`: a short write used to be treated as a full one,
    // silently truncating the event mid-JSON. And bounded, or one client that
    // stops reading freezes the whole daemon.
    match tokio::time::timeout(WRITE_STALL_LIMIT, entry.tx.write_all(bytes)).await {
        Ok(Ok(())) => return true,
        Ok(Err(e)) => log::debug!("frontend write failed ({e}) — closing it"),
        Err(_) => log::warn!(
            "a frontend stopped reading for {WRITE_STALL_LIMIT:?} — closing it rather \
             than letting it stall the daemon"
        ),
    }
    close(entry).await;
    false
}

/// End a connection whose write did not finish (#95).
///
/// Part of an event may have been written, and the rest never will be.
/// Letting go of the write half alone left the connection open, since the
/// read half shares the socket: the frontend kept a cut-off line and waited
/// for events that never came, showing a list that no longer changed. Shut
/// down the sending side, so the frontend reads to the end, sees the
/// connection close and connects again for a full state, and stop reading
/// requests from it.
async fn close(entry: &mut TxStream) {
    entry.state.closed.store(true, Ordering::Release);
    // A shutdown asks nothing of the peer; bounded anyway, since the daemon
    // loop waits on it.
    if let Ok(Err(e)) = tokio::time::timeout(WRITE_STALL_LIMIT, entry.tx.shutdown()).await {
        log::debug!("frontend connection shutdown failed ({e})");
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
///   deletes both files while a daemon runs leaves that daemon unreachable,
///   and a second daemon can then claim a new lock and socket and read the
///   config and keys. It stops when it binds the peer port the first still
///   holds.
///
///   On macOS the socket is in `~/Library/Caches`, which macOS may purge. The
///   front door does not start that second daemon there, since launchd names
///   the running job's process instead. Elsewhere it is in `$XDG_RUNTIME_DIR`,
///   whose files the XDG base directory specification lets a periodic
///   clean-up remove unless each has the sticky bit set or its access time
///   updated every six hours. On Linux the lock and the socket get the sticky
///   bit, which `systemd-tmpfiles` honours. A clean-up that ignores it, or
///   someone removing the files, still leaves the gap.
///
///   The lock stays beside the socket anyway. `$XDG_RUNTIME_DIR` is the one
///   directory the specification requires to be local and to support file
///   locks; the config directory, which is not purged, may be a network home
///   where locks fail, and there the lock would stop the daemon starting at
///   all. A lock kept elsewhere would also leave the first daemon unreachable.
/// * **A daemon from before the lock takes none,** wherever the lock is kept.
///   It still refuses to start beside a socket that answers, and a newer
///   daemon refuses beside it, but the two starting at the same moment beside
///   a stale socket can both bind. On macOS a connect to a listener whose
///   queue of connections not yet accepted is full is refused as if nothing
///   listened, so a newer daemon also takes over the socket of an older one
///   that has stopped accepting.
struct Claim {
    #[cfg(windows)]
    listener: crate::windows::PipeListener,
    #[cfg(unix)]
    listener: UnixListener,
    /// Where the listener is bound.
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
        Self::take_with(endpoint, ownership::foreign_owner).await
    }

    /// [`Claim::take`], with `whose` saying who owns a file in the way, as
    /// [`ownership::foreign_owner`] does, so the error can say what to do.
    #[cfg(unix)]
    async fn take_with(
        endpoint: &crate::DaemonEndpoint,
        whose: impl Fn(&std::path::Path, &std::io::Error) -> Option<ownership::Foreign>,
    ) -> Result<Self, IpcListenerCreationError> {
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
        let lock = lock_beside_with(&socket_path, &whose)?;
        #[cfg(target_os = "linux")]
        say_if_not_kept(&lock_path(&socket_path), mark_to_keep(&lock));

        // `symlink_metadata`, not `exists`: a dangling link at the path would
        // otherwise pass as absent and fail the bind as if a daemon held it.
        if std::fs::symlink_metadata(&socket_path).is_ok() {
            // A daemon that predates the lock holds none, so ask the socket too.
            match UnixStream::connect(&socket_path).await {
                Ok(_) => return Err(IpcListenerCreationError::AlreadyRunning),
                // On Linux, a connect that does not wait gets WouldBlock
                // from a listener whose queue of connections not yet
                // accepted is full. Something listens.
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    return Err(IpcListenerCreationError::AlreadyRunning);
                }
                // Nothing listens, and the lock says no other daemon is
                // starting, so the file is left over from one that is gone.
                Err(e) if nothing_listens(&e) => {
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
                // Anything else, such as a socket this user may not connect
                // to, cannot say whether a daemon listens there. The file is
                // left alone. A socket a daemon run under sudo left behind is
                // another user's, and the hint says so.
                Err(source) => {
                    // Before the owner: `chown` follows a link, so its advice
                    // would change whatever the link names.
                    let is_a_link = std::fs::symlink_metadata(&socket_path)
                        .is_ok_and(|meta| meta.file_type().is_symlink());
                    let hint = if is_a_link {
                        SOCKET_IS_A_LINK.to_string()
                    } else {
                        ownership::hint(
                            whose(&socket_path, &source),
                            "A daemon may be listening on it, so hops leaves it \
                             where it is. If no hops daemon is running, remove it, \
                             then start hops again.",
                        )
                    };
                    return Err(IpcListenerCreationError::SocketUnchecked {
                        path: socket_path,
                        source,
                        hint,
                    });
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
        #[cfg(target_os = "linux")]
        say_if_not_kept(&socket_path, mark_socket_to_keep(&socket_path));
        Ok(Self {
            listener,
            endpoint: endpoint.clone(),
            _lock: lock,
        })
    }

    /// The next frontend to connect.
    #[cfg(unix)]
    fn poll_accept(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<Sock>> {
        self.listener.poll_accept(cx).map_ok(|(stream, _)| stream)
    }

    /// The next frontend to connect.
    #[cfg(windows)]
    fn poll_accept(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<Sock>> {
        self.listener.poll_accept(cx)
    }

    /// Create the daemon's pipe as its first instance.
    ///
    /// A pipe has no lock file to take first: creating the first instance
    /// fails when any pipe of that name exists, whoever made it, which makes
    /// the create the whole claim. What holds the name is then asked of the
    /// system, and only a process of this user counts as a daemon already
    /// running. Anything else is named in the error, and the daemon exits
    /// with it rather than leave frontends to whatever holds the pipe (#96).
    #[cfg(windows)]
    async fn take(endpoint: &crate::DaemonEndpoint) -> Result<Self, IpcListenerCreationError> {
        let bind_error = |source| IpcListenerCreationError::Bind {
            endpoint: endpoint.clone(),
            source,
        };
        let crate::DaemonEndpoint::Pipe(name) = endpoint else {
            return Err(bind_error(std::io::Error::new(
                ErrorKind::Unsupported,
                "the daemon listens on a named pipe on this platform",
            )));
        };
        match crate::windows::PipeListener::first(name) {
            Ok(listener) => Ok(Self {
                listener,
                endpoint: endpoint.clone(),
            }),
            Err(e) if crate::windows::taken(&e) => match crate::windows::who_holds(name).await {
                crate::windows::Holder::ThisUser => Err(IpcListenerCreationError::AlreadyRunning),
                crate::windows::Holder::Other(why) => Err(IpcListenerCreationError::Held {
                    endpoint: endpoint.clone(),
                    why,
                    hint: held_hint(),
                }),
            },
            Err(e) => Err(bind_error(e)),
        }
    }
}

/// What to do about an endpoint something else holds.
#[cfg(windows)]
fn held_hint() -> String {
    let token = token::token_path()
        .map(|path| format!(" ({})", path.display()))
        .unwrap_or_default();
    format!(
        "The daemon's pipe is named after the IPC token{token}. Delete that file and \
         start hops again, and the daemon and the app use a new name"
    )
}

/// `<socket_path>.lock`, the file a daemon locks to claim `socket_path`.
#[cfg(unix)]
fn lock_path(socket_path: &std::path::Path) -> PathBuf {
    let mut name = socket_path.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

/// Whether a failed connect to a Unix socket path says that nothing listens
/// there: no listener on the socket, nothing at the path, or a file that is
/// not a socket, which Linux reports as a refused connection and macOS as
/// `ENOTSOCK`.
#[cfg(unix)]
fn nothing_listens(e: &std::io::Error) -> bool {
    matches!(e.kind(), ErrorKind::ConnectionRefused | ErrorKind::NotFound)
        || e.raw_os_error() == Some(libc::ENOTSOCK)
}

/// The sticky bit.
///
/// The XDG base directory specification names it as what keeps a file in
/// `$XDG_RUNTIME_DIR` from a periodic clean-up, and `systemd-tmpfiles` skips
/// files that have it. It means nothing else on a file on Linux.
#[cfg(target_os = "linux")]
const STICKY: u32 = 0o1000;

/// Set the sticky bit on the file `lock` is open on, keeping its other mode
/// bits.
///
/// Through the descriptor, so the mode read and the mode set are those of the
/// file that was locked, whatever is at its path by then.
#[cfg(target_os = "linux")]
fn mark_to_keep(lock: &std::fs::File) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = lock.metadata()?.permissions().mode() & 0o7777;
    lock.set_permissions(std::fs::Permissions::from_mode(mode | STICKY))
}

/// Set the sticky bit on the socket at `path`, keeping its other mode bits.
///
/// Another process of this user can replace what is at `path` at any moment.
/// A link there is not followed and anything but a socket is left as it is:
/// following a link would let that process choose which file's mode a daemon
/// run as root changes.
///
/// The path is opened only to name what is there (`O_PATH`), since a socket
/// cannot be opened to read. `fchmod` does not take such a descriptor, so the
/// mode is set through its `/proc/self/fd` entry, which names the same file.
#[cfg(target_os = "linux")]
fn mark_socket_to_keep(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
    let named = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
        .open(path)?;
    let meta = named.metadata()?;
    if !meta.file_type().is_socket() {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "what is there is not a socket",
        ));
    }
    let mode = meta.permissions().mode() & 0o7777;
    std::fs::set_permissions(
        format!("/proc/self/fd/{}", named.as_raw_fd()),
        std::fs::Permissions::from_mode(mode | STICKY),
    )
}

/// Log that `path` could not be given the sticky bit, if `marked` says so. A
/// daemon that cannot set it still runs.
#[cfg(target_os = "linux")]
fn say_if_not_kept(path: &std::path::Path, marked: std::io::Result<()>) {
    if let Err(e) = marked {
        log::warn!(
            "could not set the sticky bit on {} ({e}). A clean-up of its \
             directory may remove it while the daemon runs, and frontends would \
             then no longer reach the daemon.",
            path.display()
        );
    }
}

/// The hint for a lock path that holds a symbolic link.
#[cfg(unix)]
const LOCK_IS_A_LINK: &str = "It is a symbolic link, which hops does not follow \
     there. Remove the link, then start hops again.";

/// The hint for a socket path that holds a symbolic link the daemon could not
/// connect through. A daemon binds its socket at that path itself, so none
/// listens through a link there, and removing the link leaves whatever it
/// names alone.
#[cfg(unix)]
const SOCKET_IS_A_LINK: &str = "It is a symbolic link, and hops keeps only its \
     own socket there. Remove the link, then start hops again.";

/// Lock `<socket_path>.lock` exclusively, without waiting.
///
/// `whose` says who owns the lock file when opening it failed, as
/// [`ownership::foreign_owner`] does, so the error can say what to do.
///
/// A link at the lock path is not followed. Its directory may be written by
/// any process of this user, and a daemon run as root would otherwise create,
/// lock and mark whatever file the link names.
#[cfg(unix)]
fn lock_beside_with(
    socket_path: &std::path::Path,
    whose: impl FnOnce(&std::path::Path, &std::io::Error) -> Option<ownership::Foreign>,
) -> Result<std::fs::File, IpcListenerCreationError> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = lock_path(socket_path);
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(file) => file,
        Err(source) => {
            // Before the owner: `chown` follows a link, so its advice would
            // be wrong here.
            let is_a_link =
                std::fs::symlink_metadata(&path).is_ok_and(|meta| meta.file_type().is_symlink());
            let hint = if is_a_link {
                LOCK_IS_A_LINK.to_string()
            } else {
                ownership::hint(
                    whose(&path, &source),
                    "hops keeps this file beside its socket so that a second daemon \
                     cannot start. Check that this user can create and write it.",
                )
            };
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

/// A connection part-way through the two-way proof, which ends with the
/// connection when the frontend has made it.
type Admitting =
    Pin<Box<dyn Future<Output = Option<(Lines<ReadHalf<Sock>>, WriteHalf<Sock>)>> + Send>>;

pub struct AsyncFrontendListener {
    claim: Claim,
    /// connections that have not yet made the two-way proof
    admitting: FuturesUnordered<Admitting>,
    line_streams: SelectAll<AuthedLines<ReadHalf<Sock>>>,
    tx_streams: Vec<TxStream>,
    /// the secret every frontend must prove it holds
    token: std::sync::Arc<str>,
    /// set while connections are being closed on accept because
    /// [`PREAUTH_CONNECTIONS_MAX`] are part-way through the proof, so that is
    /// logged once
    refusing: bool,
}

impl AsyncFrontendListener {
    /// Claim this platform's endpoint, [`crate::DaemonEndpoint::of_this_platform`].
    ///
    /// On Windows that reads the token first, or mints it, since the token
    /// names the pipe.
    pub async fn new() -> Result<Self, IpcListenerCreationError> {
        Self::at(&crate::DaemonEndpoint::of_this_platform()?).await
    }

    /// Claim `endpoint`, then load the token frontends must prove they hold.
    ///
    /// Returns [`IpcListenerCreationError::AlreadyRunning`] when another daemon
    /// holds the endpoint or is part-way through claiming it, and on Windows
    /// [`IpcListenerCreationError::Held`] when something else holds it.
    /// Nothing but the claim's own lock file is read or written until the
    /// claim is held.
    pub async fn at(endpoint: &crate::DaemonEndpoint) -> Result<Self, IpcListenerCreationError> {
        Self::claim_then_token(endpoint, load_token).await
    }

    /// [`Self::at`], with the token kept in `token_file` rather than beside
    /// the user's config: for a daemon a test runs whole in its own process,
    /// which must neither read nor mint the user's token.
    pub async fn at_with_token_file(
        endpoint: &crate::DaemonEndpoint,
        token_file: &std::path::Path,
    ) -> Result<Self, IpcListenerCreationError> {
        Self::claim_then_token(endpoint, || {
            load_token_with(token_file, ownership::foreign_owner)
        })
        .await
    }

    async fn claim_then_token(
        endpoint: &crate::DaemonEndpoint,
        token: impl FnOnce() -> Result<String, IpcListenerCreationError>,
    ) -> Result<Self, IpcListenerCreationError> {
        let claim = Claim::take(endpoint).await?;
        Ok(Self {
            claim,
            token: token()?.into(),
            admitting: FuturesUnordered::new(),
            line_streams: SelectAll::new(),
            tx_streams: vec![],
            refusing: false,
        })
    }

    /// Where this listener is bound.
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

/// Tell a connection the daemon will not take that it is busy, rather than
/// only hang up: a daemon from before the two-way proof hangs up on the
/// challenge, and an ask for the build reads that as an older daemon, which
/// the app restarts (#222).
///
/// Written straight to the new socket, which has room for it: the runtime
/// has not yet seen the socket writable, so its own write would not try.
#[cfg(unix)]
fn say_busy(stream: &Sock) {
    use std::os::fd::AsRawFd;
    let line = proof::BUSY_LINE.as_bytes();
    #[cfg(target_os = "linux")]
    let flags = libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL;
    #[cfg(not(target_os = "linux"))]
    let flags = libc::MSG_DONTWAIT;
    // SAFETY: the descriptor is open while `stream` lives, and `line`
    // outlives the call.
    let _ = unsafe { libc::send(stream.as_raw_fd(), line.as_ptr().cast(), line.len(), flags) };
}

/// On Windows the app never restarts a daemon it did not see started, so a
/// hang-up is all a refused connection gets.
#[cfg(windows)]
fn say_busy(_: &Sock) {}

impl Stream for AsyncFrontendListener {
    type Item = Result<FrontendRequest, IpcError>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Accept before reading. A connection's lines are read only once they
        // have been polled, which is also what asks to be woken when its proof
        // arrives; accepted after the read, a new frontend waited unheard
        // until something else woke the daemon.
        while let Poll::Ready(Ok(stream)) = self.claim.poll_accept(cx) {
            let waiting = self.admitting.len();
            if waiting >= PREAUTH_CONNECTIONS_MAX {
                if !self.refusing {
                    log::warn!(
                        "{waiting} frontend connections are part-way through proving \
                         they hold the IPC token — closing new ones until they finish \
                         or time out"
                    );
                    self.refusing = true;
                }
                say_busy(&stream);
                drop(stream);
                continue;
            }
            self.refusing = false;
            let (rx, tx) = tokio::io::split(stream);
            // Accepted, but not yet heard or sent anything but the proof's
            // answer. Accepting is not authenticating.
            self.admitting
                .push(Box::pin(admit_in_time(rx, tx, self.token.clone())));
        }
        // Registered once the proof is made; `Sync` below sends it state.
        while let Poll::Ready(Some(admitted)) = self.admitting.poll_next_unpin(cx) {
            let Some((lines, tx)) = admitted else {
                continue;
            };
            let state = Arc::new(ConnState::default());
            self.line_streams
                .push(AuthedLines::admitted(lines, state.clone()));
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
    //! The daemon's half of the two-way proof, and the requests after it,
    //! over an in-memory connection. `tests/two_way_proof.rs` drives the real
    //! listener and connector over this platform's transport.

    use super::{AuthedLines, ConnState, admit};
    use crate::{FrontendRequest, proof};
    use futures::StreamExt;
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OTHER: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    /// The daemon's side of one connection: the proof, then what it honours.
    async fn daemon_side(server: DuplexStream) -> Vec<FrontendRequest> {
        let (rx, tx) = tokio::io::split(server);
        let Some((lines, _tx)) = admit(rx, tx, TOKEN.into()).await else {
            return vec![];
        };
        let mut stream = AuthedLines::admitted(lines, Arc::new(ConnState::default()));
        let mut out = vec![];
        while let Some(Ok(req)) = stream.next().await {
            out.push(req);
        }
        out
    }

    /// A client that challenges the daemon, reads its answer, and replies
    /// with the line `reply` makes from the two nonces and the answer, then
    /// sends `script`.
    async fn client(
        conn: DuplexStream,
        reply: impl FnOnce(&str, &str, &str) -> String,
        script: &str,
    ) {
        let (rx, mut tx) = tokio::io::split(conn);
        let mut rx = BufReader::new(rx);
        let nf = proof::nonce().expect("a nonce");
        tx.write_all(proof::challenge_line(&nf).as_bytes())
            .await
            .expect("the challenge");
        let mut answer = String::new();
        rx.read_line(&mut answer).await.expect("the answer");
        let nd = answer.split(' ').nth(1).unwrap_or_default().to_string();
        let _ = tx.write_all(reply(&nf, &nd, &answer).as_bytes()).await;
        let _ = tx.write_all(script.as_bytes()).await;
        let _ = tx.shutdown().await;
    }

    /// What the daemon honours from a client that replies with `reply`.
    async fn drive(
        reply: impl FnOnce(&str, &str, &str) -> String,
        script: &str,
    ) -> Vec<FrontendRequest> {
        let (conn, server) = tokio::io::duplex(4096);
        let (_, got) = tokio::join!(client(conn, reply, script), daemon_side(server));
        got
    }

    /// What the daemon honours from a client that sends `script` and nothing
    /// else.
    async fn drive_raw(script: &str) -> Vec<FrontendRequest> {
        let (mut conn, server) = tokio::io::duplex(4096);
        conn.write_all(script.as_bytes()).await.expect("write");
        conn.shutdown().await.expect("shutdown");
        daemon_side(server).await
    }

    fn proves(nf: &str, nd: &str, _: &str) -> String {
        proof::proof_line(TOKEN, nf, nd)
    }

    // LEDGER T9613 | class B | 6 requests the daemon side yields over a duplex
    #[tokio::test]
    async fn a_frontend_that_proves_the_token_is_heard() {
        let got = drive(proves, "{\"Enumerate\":[]}\n").await;
        assert_eq!(got.len(), 1, "a proven frontend's request must be honoured");
    }

    // LEDGER T9614 | class B | 6 requests the daemon side yields over a duplex
    #[tokio::test]
    async fn no_proof_means_no_requests() {
        let got = drive_raw("{\"Enumerate\":[]}\n").await;
        assert!(got.is_empty(), "a request with no proof must be refused");
    }

    /// A frontend from before the proof sends the token itself. That is not
    /// a challenge, and admits nothing: a token such a frontend handed to
    /// whatever held the endpoint must not open the daemon.
    // LEDGER T9615 | class B | 6 requests the daemon side yields over a duplex
    #[tokio::test]
    async fn the_token_itself_admits_nothing() {
        let got = drive_raw(&format!("{TOKEN}\n{{\"Enumerate\":[]}}\n")).await;
        assert!(got.is_empty(), "the bare token was accepted: {got:?}");
    }

    // LEDGER T9616 | class B | 6 requests the daemon side yields over a duplex
    #[tokio::test]
    async fn a_proof_made_with_another_token_admits_nothing() {
        let got = drive(
            |nf, nd, _| proof::proof_line(OTHER, nf, nd),
            "{\"Enumerate\":[]}\n",
        )
        .await;
        assert!(got.is_empty(), "a proof of another token was accepted");
    }

    /// The daemon's own answer, sent back to it as the proof, admits nothing.
    // LEDGER T9617 | class B | 6 requests the daemon side yields over a duplex
    #[tokio::test]
    async fn the_daemons_own_answer_sent_back_admits_nothing() {
        let got = drive(
            |_, _, answer| {
                let mac = answer.trim().rsplit(' ').next().unwrap_or_default();
                format!("proof {mac}\n")
            },
            "{\"Enumerate\":[]}\n",
        )
        .await;
        assert!(
            got.is_empty(),
            "echoing the daemon's answer back admitted a client that holds no \
             token: {got:?}"
        );
    }

    /// A web page may POST to a loopback port because `text/plain` is
    /// CORS-safelisted (no preflight). It cannot read the response, but the
    /// side effect would land. This must die on the HTTP request line, long
    /// before the body, and the body here is a REAL AuthorizeKey, so a
    /// regression is loud.
    // LEDGER T9618 | class B | 6 requests the daemon side yields over a duplex
    #[tokio::test]
    async fn an_http_post_from_a_browser_is_refused() {
        let body = r#"{"AuthorizeKey":["attacker","aa:bb:cc:dd"]}"#;
        let got = drive_raw(&format!(
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

    /// The cap on what a client may send before the proof must not reach the
    /// requests that follow it: a real request is routinely longer.
    // LEDGER T63 | class B | 1 return value / error
    #[tokio::test]
    async fn after_the_proof_a_request_longer_than_the_proof_line_is_honoured() {
        let request = format!(
            "{{\"UpdateHostname\":{{\"handle\":0,\"hostname\":\"{}\",\"fingerprint\":null}}}}",
            "h".repeat(1024)
        );
        let got = drive(proves, &format!("{request}\n")).await;
        assert!(
            matches!(got.as_slice(), [FrontendRequest::UpdateHostname { handle: 0, hostname: Some(name), .. }]
                if name.len() == 1024),
            "an authenticated request of {} bytes was refused ({} requests honoured). \
             The pre-authentication cap must lift once the proof is made.",
            request.len(),
            got.len()
        );
    }

    /// Junk after a GOOD proof must also hang up, not be skipped: tolerating
    /// it is what let an attacker prepend arbitrary lines to a real request.
    // LEDGER T9619 | class B | 6 requests the daemon side yields over a duplex
    #[tokio::test]
    async fn garbage_after_a_good_proof_closes_the_connection() {
        let got = drive(proves, "not json at all\n{\"Enumerate\":[]}\n").await;
        assert!(
            got.is_empty(),
            "the connection must close on the junk line, not skip it"
        );
    }

    /// The frontend's half: an answer made with another token is refused,
    /// and nothing follows the challenge.
    // LEDGER T9620 | class B | 1 return value of proof::prove_to_daemon + 2 bytes over a duplex
    #[tokio::test]
    async fn a_frontend_refuses_an_answer_made_with_another_token() {
        let (conn, server) = tokio::io::duplex(4096);
        let impostor = async move {
            let (rx, mut tx) = tokio::io::split(server);
            let mut rx = BufReader::new(rx);
            let mut challenge = String::new();
            rx.read_line(&mut challenge).await.expect("the challenge");
            let nf = proof::challenge_in(&challenge)
                .expect("a challenge")
                .to_string();
            let nd = proof::nonce().expect("a nonce");
            tx.write_all(proof::answer_line(OTHER, &nf, &nd).as_bytes())
                .await
                .expect("the answer");
            let mut rest = String::new();
            let _ = tokio::io::AsyncReadExt::read_to_string(&mut rx, &mut rest).await;
            rest
        };
        let frontend = async move {
            let (rx, mut tx) = tokio::io::split(conn);
            let mut rx = BufReader::new(rx);
            let proven = proof::prove_to_daemon(&mut rx, &mut tx, TOKEN).await;
            drop((rx, tx));
            proven
        };
        let (after_challenge, proven) = tokio::join!(impostor, frontend);
        assert!(
            matches!(proven, Err(crate::ConnectionError::Unproven(_)))
                && after_challenge.is_empty(),
            "the frontend took an answer made with another token ({proven:?}), or \
             sent more than its challenge: {after_challenge:?}"
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
    use crate::ownership::{Foreign, Link, another_users};
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
            through: None,
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

    // LEDGER T45 | class B | 1 return value / error
    #[test]
    fn a_daemon_refused_its_lock_by_another_users_directory_says_whose_it_is() {
        // SAFETY: geteuid has no preconditions and cannot fail.
        let me = unsafe { libc::geteuid() };
        if me == 0 {
            eprintln!("not checked: nothing refuses root a file");
            return;
        }
        // Root's, and not writable by anyone else. `/` on macOS is read-only
        // to root as well, which is a different refusal.
        let theirs = PathBuf::from(if cfg!(target_os = "macos") {
            "/Library"
        } else {
            "/"
        });
        let path = theirs.join(format!("h-whose-{}.sock", std::process::id()));

        let got = runtime().block_on(crate::AsyncFrontendListener::at(&DaemonEndpoint::Unix(
            path.clone(),
        )));
        let said = match got {
            Err(IpcListenerCreationError::Lock { hint, .. }) => hint,
            Err(other) => format!("not a lock error: {other}"),
            Ok(listener) => {
                drop(listener);
                remove(&path);
                format!("listening on {}", path.display())
            }
        };
        assert_eq!(
            said,
            another_users(&Foreign {
                path: theirs,
                owner: 0,
                me,
                through: None,
            }),
            "a daemon that another user's directory refuses its lock file must say \
             whose directory it is and what to do, or a directory left behind by \
             `sudo hops` stops every later start with only an OS error"
        );
    }

    // LEDGER T57 | class B | 1 return value / error
    #[test]
    fn a_daemon_refused_its_lock_through_a_link_names_the_link_and_advises_no_chown() {
        // SAFETY: geteuid has no preconditions and cannot fail.
        let me = unsafe { libc::geteuid() };
        if me == 0 {
            eprintln!("not checked: nothing refuses root a file");
            return;
        }
        // A directory of root's that no one else may write in, as in T45.
        let theirs = if cfg!(target_os = "macos") {
            "Library"
        } else {
            "usr"
        };
        let scratch = PathBuf::from(format!("/tmp/h-claim-linkdir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir(&scratch).expect("a scratch directory");
        // Any process of this user can put such a link in place of the
        // socket's directory, or of a directory above it.
        let (linked, up) = (scratch.join("linked"), scratch.join("up"));
        let target = Path::new("/").join(theirs);
        std::os::unix::fs::symlink(&target, &linked).expect("a link to root's directory");
        std::os::unix::fs::symlink("/", &up).expect("a link to /");

        let rt = runtime();
        let refused = |dir: &Path| {
            let path = dir.join(format!("h-{}.sock", std::process::id()));
            match rt.block_on(crate::AsyncFrontendListener::at(&DaemonEndpoint::Unix(
                path.clone(),
            ))) {
                Err(e @ IpcListenerCreationError::Lock { .. }) => e.to_string(),
                Err(other) => format!("not a lock error: {other}"),
                Ok(listener) => {
                    drop(listener);
                    remove(&path);
                    format!("listening on {}", path.display())
                }
            }
        };
        let said = [refused(&linked), refused(&up.join(theirs))];
        for link in [&linked, &up] {
            let _ = std::fs::remove_file(link);
        }
        let _ = std::fs::remove_dir(&scratch);

        let expected = |dir: PathBuf, at: &Path, to: &Path| {
            format!(
                "could not lock {}: Permission denied (os error 13). {}",
                dir.join(format!("h-{}.sock.lock", std::process::id()))
                    .display(),
                another_users(&Foreign {
                    path: dir,
                    owner: 0,
                    me,
                    through: Some(Link {
                        at: at.to_path_buf(),
                        to: to.to_path_buf(),
                    }),
                })
            )
        };
        assert_eq!(
            said,
            [
                expected(linked.clone(), &linked, &target),
                expected(up.join(theirs), &up, Path::new("/")),
            ],
            "(the socket's directory is a link, a directory above it is a link). \
             A daemon refused its lock must name the link and its target."
        );
        for (said, link) in said.iter().zip([&linked, &up]) {
            assert!(
                said.contains(&format!("{} is a symbolic link to /", link.display()))
                    && !said.contains("sudo chown"),
                "`chown` follows a link, so advice to chown a path reached through \
                 one gives this user whatever directory the link names: {said}"
            );
        }
    }

    // LEDGER T47 | class B | 4 file on disk
    #[cfg(target_os = "linux")]
    #[test]
    fn the_lock_and_the_socket_are_marked_to_be_kept_through_clean_ups() {
        use std::os::unix::fs::PermissionsExt;
        let path = socket_path("sticky");
        remove(&path);
        let claim = runtime()
            .block_on(Claim::take(&DaemonEndpoint::Unix(path.clone())))
            .expect("a claim on a free endpoint");
        let mode = |p: &Path| {
            std::fs::symlink_metadata(p)
                .map(|m| m.permissions().mode() & 0o7777)
                .unwrap_or(0)
        };
        let (socket, lock) = (mode(&path), mode(&super::lock_path(&path)));
        drop(claim);
        remove(&path);
        assert_eq!(
            (socket & 0o1000, lock),
            (0o1000, 0o1600),
            "(sticky bit on the socket, mode of the lock file), socket mode \
             {socket:o}. `$XDG_RUNTIME_DIR` may be cleaned of files that have \
             neither the sticky bit nor a recent access time, which leaves a \
             running daemon that no frontend can reach and a second daemon free \
             to start."
        );
    }

    /// The inode at `path`, without following a link; 0 when nothing is there.
    fn inode(path: &Path) -> u64 {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(path).map_or(0, |m| m.ino())
    }

    /// The permission bits at `path` in octal, without following a link;
    /// "nothing" when nothing is there.
    fn mode(path: &Path) -> String {
        use std::os::unix::fs::PermissionsExt;
        std::fs::symlink_metadata(path).map_or("nothing".to_string(), |m| {
            format!("{:o}", m.permissions().mode() & 0o7777)
        })
    }

    // LEDGER T49 | class B | 1 return value / error + 4 file on disk
    #[test]
    fn a_link_in_the_lock_files_place_is_not_followed() {
        use std::os::unix::fs::PermissionsExt;
        let path = socket_path("locklink");
        remove(&path);
        let lock = super::lock_path(&path);
        let pid = std::process::id();
        let linked = PathBuf::from(format!("/tmp/h-claim-linked-{pid}"));
        let nowhere = PathBuf::from(format!("/tmp/h-claim-nowhere-{pid}"));
        let _ = std::fs::remove_file(&nowhere);
        std::fs::write(&linked, b"not hops's").expect("a file to link to");
        std::fs::set_permissions(&linked, std::fs::Permissions::from_mode(0o600))
            .expect("its mode");
        let rt = runtime();
        let claim = || match rt.block_on(Claim::take(&DaemonEndpoint::Unix(path.clone()))) {
            Err(IpcListenerCreationError::Lock { path, hint, .. }) => {
                format!("Lock on {}: {hint}", path.display())
            }
            other => describe(&other),
        };

        std::os::unix::fs::symlink(&linked, &lock).expect("a link to a file");
        let to_a_file = claim();
        let linked_after = (
            mode(&linked),
            std::fs::read_to_string(&linked).unwrap_or_default(),
        );
        let _ = std::fs::remove_file(&lock);
        std::os::unix::fs::symlink(&nowhere, &lock).expect("a link to nothing");
        let to_nothing = claim();
        let created = std::fs::symlink_metadata(&nowhere).is_ok();
        for leftover in [&lock, &linked, &nowhere] {
            let _ = std::fs::remove_file(leftover);
        }
        remove(&path);

        let refused = format!("Lock on {}: {}", lock.display(), super::LOCK_IS_A_LINK);
        assert_eq!(
            (to_a_file, linked_after, to_nothing, created),
            (
                refused.clone(),
                ("600".to_string(), "not hops's".to_string()),
                refused,
                false
            ),
            "(claim beside a link to a file, that file's (mode, contents), claim \
             beside a link to nothing, whether the claim created what it names). \
             Any process of this user can put a link where the lock goes. A \
             daemon that follows it, run as root, locks, creates or changes the \
             mode of whatever file the link names."
        );
    }

    // LEDGER T50 | class B | 4 file on disk + 1 return value
    #[cfg(target_os = "linux")]
    #[test]
    fn only_a_socket_is_marked_to_be_kept_and_a_link_is_not_followed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = PathBuf::from(format!("/tmp/h-sticky-links-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).expect("a scratch directory");
        let chmod = |p: &Path, mode: u32| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).expect("a mode");
        };
        let file = dir.join("file");
        std::fs::write(&file, b"").expect("a file");
        chmod(&file, 0o600);
        let socket = dir.join("s.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).expect("a socket");
        chmod(&socket, 0o700);
        let (to_file, to_socket) = (dir.join("to-file"), dir.join("to-socket"));
        std::os::unix::fs::symlink(&file, &to_file).expect("a link to the file");
        std::os::unix::fs::symlink(&socket, &to_socket).expect("a link to the socket");

        let marked = |p: &Path| super::mark_socket_to_keep(p).is_ok();
        let refused = [marked(&to_file), marked(&to_socket), marked(&file)];
        let untouched = (mode(&file), mode(&socket));
        let socket_marked = (marked(&socket), mode(&socket));
        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(
            (refused, untouched, socket_marked),
            (
                [false, false, false],
                ("600".to_string(), "700".to_string()),
                (true, "1700".to_string())
            ),
            "((marked through a link to a file, through a link to a socket, a \
             file), (file mode, socket mode) after those, (socket marked, its \
             mode)). A link where the socket was, followed as root, sets the \
             mode of the file it names."
        );
    }

    // LEDGER T51 | class B | 1 return value / error + 4 file on disk
    #[cfg(target_os = "linux")]
    #[test]
    fn a_daemon_starting_beside_a_listener_with_a_full_queue_leaves_its_socket() {
        use std::os::fd::AsRawFd;
        let path = socket_path("fullqueue");
        remove(&path);
        let older = std::os::unix::net::UnixListener::bind(&path).expect("a unix listener");
        // SAFETY: plain values on an open socket. Linux takes a second
        // `listen` as a new queue length; with 0, one waiting connection
        // fills the queue.
        let listened = unsafe { libc::listen(older.as_raw_fd(), 0) };
        let waiting = std::os::unix::net::UnixStream::connect(&path).expect("a waiting connection");
        let before = inode(&path);

        let got = runtime().block_on(Claim::take(&DaemonEndpoint::Unix(path.clone())));
        let after = inode(&path);
        let outcome = describe(&got);
        drop(got);
        drop((waiting, older));
        remove(&path);

        assert_eq!(listened, 0, "the stand-in could not shorten its queue");
        assert_eq!(
            (outcome.as_str(), after),
            ("AlreadyRunning", before),
            "(outcome, inode at the socket path; it was {before}). A listener that \
             has not accepted yet still holds its socket. Removing it leaves that \
             daemon unreachable beside a second one."
        );
    }

    // LEDGER T52 | class B | 1 return value / error + 4 file on disk
    #[test]
    fn a_socket_this_user_may_not_connect_to_is_left_where_it_is() {
        use std::os::unix::fs::PermissionsExt;
        // SAFETY: geteuid has no preconditions and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("not checked: nothing refuses root a connection");
            return;
        }
        let path = socket_path("refused");
        remove(&path);
        let other = std::os::unix::net::UnixListener::bind(&path).expect("a unix listener");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))
            .expect("a socket no one may connect to");
        let before = inode(&path);

        let got = runtime().block_on(Claim::take(&DaemonEndpoint::Unix(path.clone())));
        let after = inode(&path);
        let outcome = match &got {
            Err(IpcListenerCreationError::SocketUnchecked {
                path: named,
                source,
                hint,
            }) => format!(
                "SocketUnchecked {}: {:?}. {hint}",
                named.display(),
                source.kind()
            ),
            other => describe(other),
        };
        drop(got);
        drop(other);
        remove(&path);

        assert_eq!(
            (outcome, after),
            (
                format!(
                    "SocketUnchecked {}: PermissionDenied. A daemon may be \
                     listening on it, so hops leaves it where it is. If no hops \
                     daemon is running, remove it, then start hops again.",
                    path.display()
                ),
                before
            ),
            "(outcome, inode at the socket path; it was {before}). A refused \
             connection does not say that nothing listens. The socket may be a \
             running daemon's, which removing it leaves unreachable."
        );
    }

    // LEDGER T55 | class B | 1 return value / error + 4 file on disk
    #[test]
    fn a_socket_another_user_left_that_cannot_be_asked_is_reported_as_theirs() {
        use std::os::unix::fs::PermissionsExt;
        // SAFETY: geteuid has no preconditions and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("not checked: nothing refuses root a connection");
            return;
        }
        let path = socket_path("theirs");
        remove(&path);
        // A daemon run under sudo that ended without removing its socket, by
        // a kill or a panic, left it here. Only root can make a file root
        // owns, so the owner is given, and the refusal comes from the
        // socket's mode.
        drop(std::os::unix::net::UnixListener::bind(&path).expect("a socket file"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))
            .expect("a socket this user may not connect to");
        let before = inode(&path);
        let root_owns_it = Foreign {
            path: path.clone(),
            owner: 0,
            me: 501,
            through: None,
        };
        let asked = std::sync::Mutex::new(Vec::new());
        let whose = |at: &Path, _: &std::io::Error| {
            asked.lock().expect("the list").push(at.to_path_buf());
            (at == path).then(|| root_owns_it.clone())
        };

        let got = runtime().block_on(Claim::take_with(&DaemonEndpoint::Unix(path.clone()), whose));
        let after = inode(&path);
        let said = match &got {
            Err(e @ IpcListenerCreationError::SocketUnchecked { .. }) => e.to_string(),
            other => describe(other),
        };
        drop(got);
        remove(&path);

        assert_eq!(
            (asked.into_inner().expect("the list"), after),
            (vec![path.clone()], before),
            "(files whose owner was asked, inode at the socket path; it was \
             {before}). The owner of the socket that could not be asked must be \
             looked up, and the socket left where it is."
        );
        assert_eq!(
            said,
            format!(
                "could not tell whether a daemon listens on {}: Permission denied \
                 (os error 13). {}",
                path.display(),
                another_users(&root_owns_it)
            ),
            "a socket another user left, which this user may not connect to, \
             must be reported as theirs with what to do. Otherwise a socket left \
             by `sudo hops` stops every later start with only \"Permission \
             denied\"."
        );
    }

    // LEDGER T56 | class B | 1 return value / error + 4 file on disk
    #[test]
    fn a_link_at_the_socket_path_that_cannot_be_asked_gets_no_chown_advice() {
        use std::os::unix::fs::PermissionsExt;
        // SAFETY: geteuid has no preconditions and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("not checked: nothing refuses root a connection");
            return;
        }
        let path = socket_path("sockettolink");
        remove(&path);
        let named = PathBuf::from(format!("/tmp/h-claim-named-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&named);
        // The link names a socket this user may not connect to. Only root can
        // make a link root owns, so the owner is given for every path asked.
        drop(std::os::unix::net::UnixListener::bind(&named).expect("a socket file"));
        std::fs::set_permissions(&named, std::fs::Permissions::from_mode(0o000))
            .expect("a socket this user may not connect to");
        std::os::unix::fs::symlink(&named, &path).expect("a link at the socket path");
        let files = || (inode(&path), mode(&named), inode(&named));
        let before = files();
        let root_owns = |at: &Path, _: &std::io::Error| {
            Some(Foreign {
                path: at.to_path_buf(),
                owner: 0,
                me: 501,
                through: None,
            })
        };

        let got = runtime().block_on(Claim::take_with(
            &DaemonEndpoint::Unix(path.clone()),
            root_owns,
        ));
        let still_a_link = std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_symlink());
        let after = files();
        let said = match &got {
            Err(e @ IpcListenerCreationError::SocketUnchecked { .. }) => e.to_string(),
            other => describe(other),
        };
        drop(got);
        let _ = std::fs::remove_file(&named);
        remove(&path);

        assert_eq!(
            (still_a_link, after),
            (true, before.clone()),
            "(a link still at the socket path, (link inode, mode and inode of \
             the socket it names); they were {before:?}). Neither the link nor \
             what it names may be changed."
        );
        assert_eq!(
            said,
            format!(
                "could not tell whether a daemon listens on {}: Permission denied \
                 (os error 13). {}",
                path.display(),
                super::SOCKET_IS_A_LINK
            ),
            "a link at the socket path must be reported as a link to remove. \
             `chown` follows a link, so advice to chown it would give away \
             whatever file the link names."
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
            through: None,
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

#[cfg(all(test, unix))]
mod an_unauthenticated_client_cannot_grow_memory {
    //! Before the two-way proof is made, the only lines the daemon accepts are
    //! the proof's. A client that sends anything longer is hung up on, rather
    //! than read into memory until it chooses to send a newline (#175).

    use super::*;
    use tokio::io::AsyncWriteExt;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// A real listener on a real socket, holding `TOKEN`.
    async fn listener(tag: &str) -> (AsyncFrontendListener, PathBuf) {
        let path = PathBuf::from(format!("/tmp/h-cap-{tag}-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let claim = Claim::take(&crate::DaemonEndpoint::Unix(path.clone()))
            .await
            .expect("a claim on a fresh socket path");
        let listener = AsyncFrontendListener {
            claim,
            token: TOKEN.into(),
            admitting: FuturesUnordered::new(),
            line_streams: SelectAll::new(),
            tx_streams: vec![],
            refusing: false,
        };
        (listener, path)
    }

    /// Write `total` bytes with no newline, and return how many were accepted
    /// before the daemon hung up, or `None` if all of them were.
    async fn stream_one_line(client: &mut UnixStream, total: usize) -> Option<usize> {
        let chunk = vec![b'x'; 64 * 1024];
        let mut sent = 0;
        while sent < total {
            match client.write(&chunk).await {
                Ok(0) | Err(_) => return Some(sent),
                Ok(n) => sent += n,
            }
        }
        None
    }

    // LEDGER T61 | class B | 2 bytes written to a socket
    #[tokio::test]
    async fn a_client_without_the_token_is_hung_up_on_before_it_can_fill_memory() {
        const TOTAL: usize = 64 * 1024 * 1024;
        let (mut listener, path) = listener("line").await;
        let mut client = UnixStream::connect(&path).await.expect("connect");

        let outcome = tokio::time::timeout(Duration::from_secs(30), async {
            tokio::select! {
                _ = async { while listener.next().await.is_some() {} } => {
                    unreachable!("the listener stream never ends")
                }
                refused = stream_one_line(&mut client, TOTAL) => refused,
            }
        })
        .await;
        drop(listener);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(lock_path(&path));

        let refused = outcome.expect("the daemon neither read nor refused the line in 30 s");
        assert!(
            refused.is_some_and(|sent| sent < 4 * 1024 * 1024),
            "a client that never presented the token wrote {} bytes of one \
             unterminated line and was not hung up on. Without the cap the daemon \
             keeps every byte of such a line until a newline arrives, so any local \
             process that can reach the socket can grow it until it is killed.",
            refused.map_or(format!("all {TOTAL}"), |sent| sent.to_string())
        );
    }

    /// Whether the daemon has closed `client`, without waiting. What it said
    /// first, a refusal, is read past.
    fn hung_up(client: &UnixStream) -> bool {
        let mut buf = [0u8; 64];
        loop {
            match client.try_read(&mut buf) {
                Ok(0) => return true,
                Ok(_) => continue,
                Err(e) => return e.kind() != ErrorKind::WouldBlock,
            }
        }
    }

    /// Serve `listener` for `how_long`.
    async fn serve_for(listener: &mut AsyncFrontendListener, how_long: Duration) {
        let _ = tokio::time::timeout(how_long, async { while listener.next().await.is_some() {} })
            .await;
    }

    fn remove(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(lock_path(path));
    }

    /// Make the two-way proof on `frontend` while serving `listener` for
    /// `how_long`. Whether the proof was made.
    async fn prove_while_serving(
        listener: &mut AsyncFrontendListener,
        frontend: &mut UnixStream,
        how_long: Duration,
    ) -> bool {
        let proving = async {
            let (rx, mut tx) = frontend.split();
            let mut rx = BufReader::new(rx);
            crate::proof::prove_to_daemon(&mut rx, &mut tx, TOKEN).await
        };
        let (proven, ()) = tokio::join!(proving, serve_for(listener, how_long));
        proven.is_ok()
    }

    // LEDGER T70 | class B | 2 connections on a socket, virtual clock
    #[tokio::test(start_paused = true)]
    async fn a_connection_that_never_presents_the_token_is_closed_at_the_deadline() {
        let (mut listener, path) = listener("late").await;
        let idle = UnixStream::connect(&path).await.expect("connect");
        idle.try_write(&[b'x'; 100])
            .expect("100 bytes, under the cap");
        let mut frontend = UnixStream::connect(&path).await.expect("connect");
        let proven = prove_while_serving(&mut listener, &mut frontend, PREAUTH_DEADLINE / 2).await;
        let early = hung_up(&idle);
        serve_for(&mut listener, PREAUTH_DEADLINE * 2).await;
        let late = hung_up(&idle);
        let frontend_closed = hung_up(&frontend);
        drop(listener);
        remove(&path);

        assert!(proven, "precondition: the frontend made the two-way proof");
        assert!(!early, "an idle connection was closed before the deadline");
        assert!(
            late,
            "a connection that sent 100 bytes and never a proof was still open \
             {:?} later. Without a deadline the daemon holds such a connection, and \
             its read buffer, for as long as the client likes.",
            PREAUTH_DEADLINE * 5 / 2
        );
        assert!(
            !frontend_closed,
            "a frontend that made the proof was closed at the deadline"
        );
    }

    /// A daemon holding as many connections part-way through the proof as
    /// it may tells the next one it is busy, rather than hang up on it as a
    /// daemon from before the two-way proof does (#222).
    // LEDGER T9628 | class B | 2 bytes a refused connection reads from the real listener
    #[tokio::test(flavor = "current_thread")]
    async fn a_connection_past_the_cap_is_told_the_daemon_is_busy() {
        let (mut listener, path) = listener("busy").await;
        let mut idle = vec![];
        for _ in 0..PREAUTH_CONNECTIONS_MAX {
            idle.push(UnixStream::connect(&path).await.expect("connect"));
        }
        serve_for(&mut listener, Duration::from_millis(100)).await;
        let mut refused = UnixStream::connect(&path).await.expect("connect");
        let challenge = proof::challenge_line(&proof::nonce().expect("a nonce"));
        refused
            .write_all(challenge.as_bytes())
            .await
            .expect("the challenge is written");
        let reading = async {
            let mut said = Vec::new();
            let _ = tokio::io::AsyncReadExt::read_to_end(&mut refused, &mut said).await;
            said
        };
        let (said, ()) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(20), reading),
            serve_for(&mut listener, Duration::from_millis(500)),
        );
        drop(idle);
        drop(listener);
        remove(&path);
        let said = said.map(|s| String::from_utf8_lossy(&s).into_owned());
        assert_eq!(
            said.as_deref(),
            Ok(proof::BUSY_LINE),
            "a connection the daemon would not take was told this. Hung up on \
             without a word, it reads as a daemon from before the two-way proof, \
             and the app restarts a daemon of its own build."
        );
    }

    // LEDGER T71 | class B | 2 connections on a socket, virtual clock
    #[tokio::test(start_paused = true)]
    async fn connections_waiting_for_the_token_are_capped() {
        const EXTRA: usize = 8;
        let (mut listener, path) = listener("many").await;
        let mut idle = vec![];
        for _ in 0..PREAUTH_CONNECTIONS_MAX + EXTRA {
            idle.push(UnixStream::connect(&path).await.expect("connect"));
        }

        serve_for(&mut listener, Duration::from_millis(100)).await;
        let closed = idle.iter().filter(|c| hung_up(c)).count();

        // Once those time out, a frontend is admitted again.
        serve_for(&mut listener, PREAUTH_DEADLINE * 2).await;
        let mut frontend = UnixStream::connect(&path).await.expect("connect");
        let proven =
            prove_while_serving(&mut listener, &mut frontend, Duration::from_millis(100)).await;
        let admitted = proven
            && listener
                .tx_streams
                .iter()
                .any(|e| e.state.authed.load(Ordering::Acquire));
        drop(listener);
        remove(&path);

        assert_eq!(
            closed,
            EXTRA,
            "of {} idle connections without a proof, {closed} were closed at \
             once; at most {PREAUTH_CONNECTIONS_MAX} may wait. Without a cap every \
             one is held with its read buffer, and any local process can open \
             thousands.",
            PREAUTH_CONNECTIONS_MAX + EXTRA
        );
        assert!(
            admitted,
            "after the waiting connections timed out, a frontend that proves the \
             token was not admitted"
        );
    }
}

#[cfg(all(test, unix))]
mod a_write_that_did_not_finish_closes_the_connection {
    //! A broadcast that cannot be written in full ends that frontend's
    //! connection, rather than leaving it open with part of an event and
    //! nothing after it (#95).
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// A real listener on a real socket, holding `TOKEN`, and a frontend on
    /// it that has made the two-way proof and been answered with `Sync`.
    async fn attached(tag: &str) -> (AsyncFrontendListener, PathBuf, UnixStream) {
        let path = PathBuf::from(format!("/tmp/h-short-{tag}-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let claim = Claim::take(&crate::DaemonEndpoint::Unix(path.clone()))
            .await
            .expect("a claim on a fresh socket path");
        let mut listener = AsyncFrontendListener {
            claim,
            token: TOKEN.into(),
            admitting: FuturesUnordered::new(),
            line_streams: SelectAll::new(),
            tx_streams: vec![],
            refusing: false,
        };
        let mut frontend = UnixStream::connect(&path).await.expect("connect");
        let proving = async {
            let (rx, mut tx) = frontend.split();
            let mut rx = BufReader::new(rx);
            crate::proof::prove_to_daemon(&mut rx, &mut tx, TOKEN).await
        };
        let (proven, first) = tokio::join!(
            proving,
            tokio::time::timeout(Duration::from_secs(10), listener.next())
        );
        proven.expect("the frontend makes the two-way proof");
        let first = first.expect("the listener answers the proof within 10 s");
        assert!(
            matches!(first, Some(Ok(FrontendRequest::Sync))),
            "precondition: an authenticated frontend is synced, got {first:?}"
        );
        (listener, path, frontend)
    }

    fn remove(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(lock_path(path));
    }

    /// An event far larger than any socket buffer, to a frontend that is
    /// not reading: the write cannot finish within the stall limit.
    fn too_big() -> (FrontendEvent, usize) {
        let event = FrontendEvent::Error("x".repeat(8 * 1024 * 1024));
        let len = serde_json::to_string(&event).expect("json").len() + 1;
        (event, len)
    }

    // LEDGER T526 | class B | 2 bytes read from a real socket after AsyncFrontendListener::broadcast
    #[tokio::test]
    async fn a_frontend_sent_part_of_an_event_is_hung_up_on() {
        let (mut listener, path, mut frontend) = attached("eof").await;
        let (event, len) = too_big();
        listener.broadcast(event).await;

        // Everything written is still readable; after it must come the end.
        let mut got = Vec::new();
        let ended =
            tokio::time::timeout(Duration::from_secs(10), frontend.read_to_end(&mut got)).await;
        drop(listener);
        remove(&path);

        assert!(
            got.len() < len,
            "precondition: the write was cut short, and {} of {len} bytes arrived",
            got.len()
        );
        assert!(
            matches!(ended, Ok(Ok(_))),
            "the frontend read {} bytes of a {len}-byte event and the connection \
             stayed open: it holds a cut-off line and waits for events that never \
             come ({ended:?})",
            got.len()
        );
    }

    // LEDGER T527 | class B | 2 bytes written to a real socket, requests read by AsyncFrontendListener
    #[tokio::test]
    async fn a_closed_connection_is_not_read_from() {
        let (mut listener, path, mut frontend) = attached("read").await;
        let (event, _) = too_big();
        listener.broadcast(event).await;

        // The frontend sends a request before it notices the end.
        frontend
            .write_all(b"{\"Activate\":[0,false]}\n")
            .await
            .expect("the daemon still holds the read half");
        let mut honoured = vec![];
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            while let Some(request) = listener.next().await {
                honoured.push(request);
            }
        })
        .await;
        drop(listener);
        remove(&path);

        assert!(
            honoured.is_empty(),
            "a connection the daemon closed on a failed write still had its \
             requests honoured: {honoured:?}"
        );
    }
}

#[cfg(all(test, windows))]
mod the_pipe {
    //! The daemon's named pipe on Windows: one daemon per user, a name
    //! something else holds reported rather than taken for a daemon, and
    //! nothing granted to anyone but this user (#110, #96).

    use super::*;
    use std::os::windows::io::AsRawHandle;

    fn endpoint(tag: &str) -> crate::DaemonEndpoint {
        crate::DaemonEndpoint::Pipe(format!(r"\\.\pipe\hops-test-{tag}-{}", std::process::id()))
    }

    fn describe(got: &Result<Claim, IpcListenerCreationError>) -> String {
        match got {
            Ok(_) => "claimed".to_string(),
            Err(IpcListenerCreationError::AlreadyRunning) => "AlreadyRunning".to_string(),
            Err(IpcListenerCreationError::Held { .. }) => "Held".to_string(),
            Err(e) => format!("{e:?}"),
        }
    }

    /// A second daemon of this user beside a running one is told one runs.
    // LEDGER T9622 | class B | 1 return value of Claim::take on a real pipe
    #[tokio::test(flavor = "current_thread")]
    async fn a_daemon_beside_one_of_this_user_is_already_running() {
        let endpoint = endpoint("twice");
        let first = Claim::take(&endpoint).await;
        let second = Claim::take(&endpoint).await;
        assert_eq!(
            (describe(&first), describe(&second)),
            ("claimed".to_string(), "AlreadyRunning".to_string()),
            "(first daemon, second daemon) on one pipe"
        );
    }

    /// A pipe under the daemon's name that this user may not open, as one
    /// another user made first would be, is reported as held, and not taken
    /// for a running daemon: the daemon used to exit quietly as "already
    /// running" beside anything that held its endpoint.
    // LEDGER T9623 | class B | 1 return value of Claim::take on a real pipe
    #[tokio::test(flavor = "current_thread")]
    async fn a_pipe_this_user_may_not_open_is_held_not_a_running_daemon() {
        let endpoint = endpoint("held");
        let crate::DaemonEndpoint::Pipe(name) = &endpoint else {
            unreachable!("a pipe")
        };
        let _squatter =
            crate::windows::testing::pipe_no_one_may_open(name).expect("a pipe no one may open");
        let got = Claim::take(&endpoint).await;
        let message = match &got {
            Err(e @ IpcListenerCreationError::Held { .. }) => e.to_string(),
            _ => String::new(),
        };
        assert!(
            describe(&got) == "Held" && message.contains(name.as_str()),
            "a daemon starting beside a pipe it may not open got {}, saying {message:?}. \
             It must say what holds its endpoint, and exit unsuccessfully.",
            describe(&got)
        );
    }

    /// Only a pipe a process of this user holds answers the front door. One
    /// held by anything else, however it lets this user in, is no daemon of
    /// this user's: nothing answers, so the front door starts one, which
    /// says what holds its pipe (#96).
    // LEDGER T9625 | class B | 3 return values of DaemonEndpoint::answers on real pipes
    #[tokio::test(flavor = "current_thread")]
    async fn only_a_pipe_this_user_holds_answers() {
        let ours = endpoint("answers-ours");
        let _claim = Claim::take(&ours).await.expect("a claim on a fresh pipe");
        let held = endpoint("answers-held");
        let crate::DaemonEndpoint::Pipe(name) = &held else {
            unreachable!("a pipe")
        };
        let _squatter =
            crate::windows::testing::pipe_no_one_may_open(name).expect("a pipe no one may open");
        let none = endpoint("answers-none");
        assert_eq!(
            (ours.answers(), held.answers(), none.answers()),
            (true, false, false),
            "(this user's pipe, a pipe this user may not open, no pipe)"
        );
    }

    /// The pipe grants this user, and no one else, anything.
    // LEDGER T9624 | class B | 6 security descriptor the system reports for the daemon's pipe
    #[tokio::test(flavor = "current_thread")]
    async fn the_daemons_pipe_grants_this_user_alone() {
        let endpoint = endpoint("dacl");
        let crate::DaemonEndpoint::Pipe(name) = &endpoint else {
            unreachable!("a pipe")
        };
        let _claim = Claim::take(&endpoint)
            .await
            .expect("a claim on a fresh pipe");
        let client = crate::windows::open_pipe_now(name).expect("this user opens the pipe");
        let dacl = crate::windows::testing::dacl_of(client.as_raw_handle()).expect("its DACL");
        let me = crate::windows::this_user().expect("this user's SID");
        let aces: Vec<&str> = dacl
            .split('(')
            .skip(1)
            .map(|ace| ace.trim_end_matches(')'))
            .collect();
        assert!(
            dacl.starts_with("D:P")
                && !aces.is_empty()
                && aces
                    .iter()
                    .all(|ace| ace.starts_with("A;") && ace.ends_with(&format!(";{me}"))),
            "the daemon's pipe grants more than this user ({me}): {dacl}"
        );
    }
}
