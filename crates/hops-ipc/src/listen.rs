use futures::{Stream, StreamExt, stream::SelectAll};
#[cfg(unix)]
use std::path::PathBuf;
use std::{
    io::ErrorKind,
    pin::Pin,
    task::{Context, Poll},
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

/// A frontend connection that must present the IPC token before anything it says
/// is honoured, and that is HUNG UP on rather than tolerated when it sends
/// something unparseable.
///
/// Terminating the stream (`Poll::Ready(None)`) makes `SelectAll` drop it, which
/// closes the connection. That is the whole defence against the HTTP-preamble
/// route: a browser's `POST / HTTP/1.1` is the first line, it is not the token,
/// and the connection dies before any request body is ever read.
struct AuthedLines<R> {
    lines: LinesStream<BufReader<R>>,
    token: std::sync::Arc<str>,
    authed: bool,
}

impl<R: tokio::io::AsyncRead + Unpin> Stream for AuthedLines<R> {
    type Item = Result<FrontendRequest, IpcError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            let line = match this.lines.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(Err(e))) => {
                    log::debug!("frontend connection read error: {e}");
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
                    return Poll::Ready(None);
                }
                this.authed = true;
                continue;
            }
            match serde_json::from_str(line.as_str()) {
                Ok(request) => return Poll::Ready(Some(Ok(request))),
                Err(e) => {
                    // Hang up rather than skip. Tolerating junk let an attacker
                    // prepend arbitrary lines (e.g. HTTP headers) before a real
                    // request.
                    log::warn!("frontend sent an unparseable request ({e}) — closing it");
                    return Poll::Ready(None);
                }
            }
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
    tx_streams: Vec<WriteHalf<Sock>>,
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

        let mut keep = vec![];
        // TODO do simultaneously
        for tx in self.tx_streams.iter_mut() {
            // write len + payload
            if tx.write(json.as_bytes()).await.is_err() {
                keep.push(false);
                continue;
            }
            keep.push(true);
        }

        // could not find a better solution because async
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
        let mut sync = false;
        while let Poll::Ready(Ok((stream, _))) = self.listener.poll_accept(cx) {
            let (rx, tx) = tokio::io::split(stream);
            let lines = LinesStream::new(BufReader::new(rx).lines());
            let token = self.token.clone();
            self.line_streams.push(AuthedLines {
                lines,
                token,
                authed: false,
            });
            self.tx_streams.push(tx);
            sync = true;
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
        let got = drive(&format!(
            "{TOKEN}\nnot json at all\n{{\"Enumerate\":[]}}\n"
        ))
        .await;
        assert!(
            got.is_empty(),
            "the connection must close on the junk line, not skip it"
        );
    }
}
