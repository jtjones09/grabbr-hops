use crate::{ConnectionError, DaemonEndpoint, FrontendEvent, FrontendRequest, IpcError};
use std::{
    cmp::min,
    task::{Poll, ready},
    time::Duration,
};

use futures::{Stream, StreamExt};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
use tokio_stream::wrappers::LinesStream;

#[cfg(unix)]
type Conn = tokio::net::UnixStream;
#[cfg(windows)]
type Conn = tokio::net::windows::named_pipe::NamedPipeClient;

pub struct AsyncFrontendEventReader {
    lines_stream: LinesStream<BufReader<ReadHalf<Conn>>>,
}

pub struct AsyncFrontendRequestWriter {
    tx: WriteHalf<Conn>,
}

impl Stream for AsyncFrontendEventReader {
    type Item = Result<FrontendEvent, IpcError>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let line = ready!(self.lines_stream.poll_next_unpin(cx));
        let event = line.map(|l| {
            l.map_err(Into::<IpcError>::into)
                .and_then(|l| serde_json::from_str(l.as_str()).map_err(|e| e.into()))
        });
        Poll::Ready(event)
    }
}

impl AsyncFrontendRequestWriter {
    pub async fn request(&mut self, request: FrontendRequest) -> Result<(), IpcError> {
        let mut json = serde_json::to_string(&request).unwrap();
        log::debug!("requesting: {json}");
        json.push('\n');
        self.tx.write_all(json.as_bytes()).await?;
        Ok(())
    }
}

/// Connect to the daemon on this platform's endpoint,
/// [`DaemonEndpoint::of_this_platform`], and make the two-way proof.
pub async fn connect_async(
    timeout: Option<Duration>,
) -> Result<(AsyncFrontendEventReader, AsyncFrontendRequestWriter), ConnectionError> {
    connect_async_to(&DaemonEndpoint::of_this_platform()?, timeout).await
}

/// Connect to the daemon listening on `endpoint`, and make the two-way proof
/// ([`crate::proof`]).
///
/// Waits for the endpoint to come up, for at most `timeout` if one is given,
/// then for at most [`crate::PROOF_WITHIN`] for the daemon to prove it holds
/// the token. Fails with [`ConnectionError::Unproven`] when what answers
/// does not: nothing but a random challenge has been sent to it then.
pub async fn connect_async_to(
    endpoint: &DaemonEndpoint,
    timeout: Option<Duration>,
) -> Result<(AsyncFrontendEventReader, AsyncFrontendRequestWriter), ConnectionError> {
    let stream = if let Some(duration) = timeout {
        tokio::select! {
            s = wait_for_service(endpoint) => s?,
            _ = tokio::time::sleep(duration) => return Err(ConnectionError::Timeout),
        }
    } else {
        wait_for_service(endpoint).await?
    };
    let token = crate::token::read()?;
    let (rx, mut tx) = tokio::io::split(stream);
    let mut buf_reader = BufReader::new(rx);
    crate::proof::prove_to_daemon(&mut buf_reader, &mut tx, &token).await?;
    let lines_stream = LinesStream::new(buf_reader.lines());
    Ok((
        AsyncFrontendEventReader { lines_stream },
        AsyncFrontendRequestWriter { tx },
    ))
}

/// wait for the daemon's socket to come online
#[cfg(unix)]
async fn wait_for_service(endpoint: &DaemonEndpoint) -> Result<Conn, ConnectionError> {
    let DaemonEndpoint::Unix(socket_path) = endpoint else {
        return Err(ConnectionError::UnsupportedEndpoint(endpoint.clone()));
    };
    let mut duration = Duration::from_millis(10);
    loop {
        if let Ok(stream) = tokio::net::UnixStream::connect(socket_path).await {
            break Ok(stream);
        }
        // a signaling mechanism or inotify could be used to
        // improve this
        tokio::time::sleep(exponential_back_off(&mut duration)).await;
    }
}

/// wait for the daemon's pipe to come online
#[cfg(windows)]
async fn wait_for_service(endpoint: &DaemonEndpoint) -> Result<Conn, ConnectionError> {
    let DaemonEndpoint::Pipe(name) = endpoint else {
        return Err(ConnectionError::UnsupportedEndpoint(endpoint.clone()));
    };
    let mut duration = Duration::from_millis(10);
    loop {
        if let Ok(pipe) = crate::windows::open_pipe_now(name) {
            break Ok(pipe);
        }
        tokio::time::sleep(exponential_back_off(&mut duration)).await;
    }
}

fn exponential_back_off(duration: &mut Duration) -> Duration {
    let new = duration.saturating_mul(2);
    *duration = min(new, Duration::from_secs(1));
    *duration
}
