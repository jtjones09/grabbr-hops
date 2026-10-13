//! A frontend and the daemon each prove they hold the IPC token, and neither
//! sends it (#96).
//!
//! The token used to be sent as the first line of every connection, to
//! whatever held the endpoint. Something that took the endpoint before the
//! daemon collected it from every frontend, and a frontend then believed
//! whatever it was told. These tests drive the real frontend connector and
//! the real listener over this platform's transport, with an endpoint the
//! test holds itself standing in for an impostor.
//!
//! Runs in its own test binary: it points `HOME`, `XDG_CONFIG_HOME` and
//! `LOCALAPPDATA` at a scratch directory, and binds endpoints of its own.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::StreamExt;
use hops_ipc::{AsyncFrontendListener, DaemonEndpoint, FrontendRequest, connect_async_to};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

/// Point this process at a scratch directory, so the token is minted there.
fn isolate(tag: &str) -> PathBuf {
    // Short, for `sun_path` (about 104 bytes on macOS).
    #[cfg(unix)]
    let dir = PathBuf::from(format!("/tmp/h-2w-{tag}-{}", std::process::id()));
    #[cfg(windows)]
    let dir = std::env::temp_dir().join(format!("h-2w-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(dir.join(".config/lan-mouse")).expect("scratch config");
    dir
}

/// Every test here sets the same variables to the same directory, so tests
/// running at once in this binary agree on where the token is.
fn scratch_environment() -> PathBuf {
    static DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let dir = isolate("env");
        // SAFETY: set once, before any test reads the environment, and never
        // changed afterwards.
        unsafe {
            std::env::set_var("HOME", &dir);
            std::env::set_var("XDG_CONFIG_HOME", dir.join(".config"));
            std::env::set_var("XDG_RUNTIME_DIR", &dir);
            std::env::set_var("LOCALAPPDATA", &dir);
        }
        dir
    })
    .clone()
}

/// An endpoint of this test's own, named `tag`.
fn own_endpoint(dir: &std::path::Path, tag: &str) -> DaemonEndpoint {
    #[cfg(unix)]
    {
        DaemonEndpoint::Unix(dir.join(format!("{tag}.sock")))
    }
    #[cfg(windows)]
    {
        let _ = dir;
        DaemonEndpoint::Pipe(format!(r"\\.\pipe\hops-test-{tag}-{}", std::process::id()))
    }
}

/// A connection to or from an endpoint the test holds itself.
#[cfg(unix)]
type Raw = tokio::net::UnixStream;
#[cfg(windows)]
type Raw = Box<dyn RawIo>;

#[cfg(windows)]
trait RawIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
#[cfg(windows)]
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> RawIo for T {}

/// Hold `endpoint` as an impostor would, and accept one connection on it.
/// Returns once the endpoint is held; the connection comes from the task.
#[cfg(unix)]
fn impostor(endpoint: &DaemonEndpoint) -> tokio::task::JoinHandle<Raw> {
    let DaemonEndpoint::Unix(path) = endpoint else {
        unreachable!("a socket")
    };
    let _ = std::fs::remove_file(path);
    let listener = tokio::net::UnixListener::bind(path).expect("the impostor's socket");
    tokio::spawn(async move { listener.accept().await.expect("a connection").0 })
}

#[cfg(windows)]
fn impostor(endpoint: &DaemonEndpoint) -> tokio::task::JoinHandle<Raw> {
    let DaemonEndpoint::Pipe(name) = endpoint else {
        unreachable!("a pipe")
    };
    let server = tokio::net::windows::named_pipe::ServerOptions::new()
        .first_pipe_instance(true)
        .create(name)
        .expect("the impostor's pipe");
    tokio::spawn(async move {
        server.connect().await.expect("a connection");
        Box::new(server) as Raw
    })
}

/// Connect to `endpoint` directly, without the frontend's connector.
#[cfg(unix)]
async fn dial(endpoint: &DaemonEndpoint) -> Raw {
    let DaemonEndpoint::Unix(path) = endpoint else {
        unreachable!("a socket")
    };
    tokio::net::UnixStream::connect(path)
        .await
        .expect("a raw connection")
}

#[cfg(windows)]
async fn dial(endpoint: &DaemonEndpoint) -> Raw {
    let DaemonEndpoint::Pipe(name) = endpoint else {
        unreachable!("a pipe")
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::net::windows::named_pipe::ClientOptions::new().open(name) {
            Ok(client) => return Box::new(client),
            Err(e) if Instant::now() < deadline => {
                let _ = e;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(e) => panic!("a raw connection to {name}: {e}"),
        }
    }
}

/// Everything `conn` sends until it hangs up or `within` passes, after
/// answering its first line with `answer`, when there is one.
async fn collect(conn: Raw, answer: Option<String>, within: Duration) -> Vec<u8> {
    let (rx, mut tx) = tokio::io::split(conn);
    let mut rx = BufReader::new(rx);
    let mut got = Vec::new();
    let deadline = tokio::time::Instant::now() + within;
    let first = tokio::time::timeout_at(deadline, rx.read_until(b'\n', &mut got)).await;
    if matches!(first, Ok(Ok(n)) if n > 0) {
        if let Some(answer) = answer {
            let _ = tx.write_all(answer.as_bytes()).await;
        }
        let mut rest = Vec::new();
        let _ = tokio::time::timeout_at(deadline, rx.read_to_end(&mut rest)).await;
        got.extend(rest);
    }
    got
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

/// What the listener yields within `within`, other than `Sync`.
async fn heard(listener: &mut AsyncFrontendListener, within: Duration) -> Vec<FrontendRequest> {
    let mut got = Vec::new();
    let deadline = tokio::time::Instant::now() + within;
    while let Ok(Some(request)) = tokio::time::timeout_at(deadline, listener.next()).await {
        match request {
            Ok(FrontendRequest::Sync) => {}
            Ok(request) => got.push(request),
            Err(_) => {}
        }
    }
    got
}

/// What the listener yields, other than `Sync`, until it yields one that
/// is `enough` or `within` passes.
async fn heard_until(
    listener: &mut AsyncFrontendListener,
    within: Duration,
    enough: impl Fn(&FrontendRequest) -> bool,
) -> Vec<FrontendRequest> {
    let mut got = Vec::new();
    let deadline = tokio::time::Instant::now() + within;
    while let Ok(Some(request)) = tokio::time::timeout_at(deadline, listener.next()).await {
        match request {
            Ok(FrontendRequest::Sync) | Err(_) => {}
            Ok(request) => {
                let done = enough(&request);
                got.push(request);
                if done {
                    break;
                }
            }
        }
    }
    got
}

/// An endpoint held by something that answers the first line with a proof
/// made without the token: the frontend refuses it, and sends it nothing it
/// could present to the daemon.
// LEDGER T9601 | class B | 2 bytes over this platform's transport + 1 return value of connect_async_to
#[tokio::test(flavor = "current_thread")]
async fn a_frontend_gives_an_impostor_nothing_and_refuses_it() {
    let dir = scratch_environment();
    hops_ipc::token::load_or_create().expect("a scratch token");
    let endpoint = own_endpoint(&dir, "impostor");
    let held = impostor(&endpoint);

    let forged = format!("answer {} {}\n", "0".repeat(64), "1".repeat(64));
    let impostor_side = async move {
        let conn = held.await.expect("the impostor");
        collect(conn, Some(forged), Duration::from_secs(20)).await
    };
    let frontend_side = tokio::time::timeout(
        Duration::from_secs(20),
        connect_async_to(&endpoint, Some(Duration::from_secs(5))),
    );
    let (received, connected) = tokio::join!(impostor_side, frontend_side);
    let connected = connected.map(|c| c.map(|_| ()).map_err(|e| e.to_string()));
    let token = hops_ipc::token::read().expect("the scratch token");

    assert!(
        !contains(&received, &token),
        "the frontend sent the IPC token to an endpoint that never proved it holds \
         it. Whatever holds the endpoint can present it to the real daemon later. \
         It received: {:?}",
        String::from_utf8_lossy(&received)
    );
    assert!(
        matches!(connected, Ok(Err(_))),
        "the frontend accepted an endpoint whose answer was made without the token, \
         and would believe every event it sent: {connected:?}"
    );
}

/// An endpoint that accepts and says nothing: the frontend gives up on it in
/// bounded time, having sent it nothing it could present to the daemon.
// LEDGER T9602 | class B | 2 bytes over this platform's transport + 1 return value of connect_async_to
#[tokio::test(flavor = "current_thread")]
async fn a_frontend_gives_up_on_an_endpoint_that_never_answers() {
    let dir = scratch_environment();
    hops_ipc::token::load_or_create().expect("a scratch token");
    let endpoint = own_endpoint(&dir, "silent");
    let held = impostor(&endpoint);

    let impostor_side = async move {
        let conn = held.await.expect("the impostor");
        collect(conn, None, Duration::from_secs(30)).await
    };
    let began = Instant::now();
    let frontend_side = tokio::time::timeout(
        Duration::from_secs(30),
        connect_async_to(&endpoint, Some(Duration::from_secs(5))),
    );
    let (received, connected) = tokio::join!(impostor_side, frontend_side);
    let took = began.elapsed();
    let connected = connected.map(|c| c.map(|_| ()).map_err(|e| e.to_string()));
    let token = hops_ipc::token::read().expect("the scratch token");

    assert!(
        !contains(&received, &token),
        "the frontend sent the IPC token to an endpoint that never answered: {:?}",
        String::from_utf8_lossy(&received)
    );
    assert!(
        matches!(connected, Ok(Err(_))) && took < Duration::from_secs(25),
        "a frontend connecting to an endpoint that never proves itself must fail, \
         and not wait forever; got {connected:?} after {took:?}"
    );
    // Slow is not shown to be an impostor: a daemon may be starting.
    assert!(
        matches!(&connected, Ok(Err(e)) if !e.contains("did not prove")),
        "an endpoint that only took its time was called one that is not this \
         user's daemon: {connected:?}"
    );
}

/// Bytes a real frontend sent on one connection admit nothing on another:
/// a proof is bound to the connection it was made for.
// LEDGER T9603 | class B | 2 bytes over this platform's transport + 6 requests the real listener yields
#[tokio::test(flavor = "current_thread")]
async fn what_one_frontend_sent_admits_nothing_on_another_connection() {
    let dir = scratch_environment();
    let daemon_endpoint = own_endpoint(&dir, "daemon");
    let mut listener = AsyncFrontendListener::at(&daemon_endpoint)
        .await
        .expect("the listener claims the scratch endpoint");
    let daemon_endpoint = listener.endpoint().clone();

    // A relay between the frontend and the daemon that keeps everything the
    // frontend sends.
    let relay_endpoint = own_endpoint(&dir, "relay");
    let held = impostor(&relay_endpoint);
    let sent = Arc::new(Mutex::new(Vec::new()));
    let kept = sent.clone();
    let to_daemon = daemon_endpoint.clone();
    let relay = tokio::spawn(async move {
        let frontend = held.await.expect("the relay's connection");
        let daemon = dial(&to_daemon).await;
        let (mut from_frontend, mut to_frontend) = tokio::io::split(frontend);
        let (mut from_daemon, mut to_daemon) = tokio::io::split(daemon);
        let up = async move {
            let mut buf = [0u8; 4096];
            loop {
                match from_frontend.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        kept.lock()
                            .expect("the record")
                            .extend_from_slice(&buf[..n]);
                        if to_daemon.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        };
        let down = async move {
            let _ = tokio::io::copy(&mut from_daemon, &mut to_frontend).await;
        };
        tokio::join!(up, down);
    });

    let (was_heard, heard_it) = tokio::sync::oneshot::channel::<()>();
    let frontend = async {
        let (_events, mut requests) =
            connect_async_to(&relay_endpoint, Some(Duration::from_secs(5)))
                .await
                .expect("a frontend reaches the daemon through the relay");
        requests
            .request(FrontendRequest::Enumerate())
            .await
            .expect("the request is sent");
        // Held open until the daemon has heard it.
        let _ = tokio::time::timeout(Duration::from_secs(30), heard_it).await;
    };
    let daemon = async {
        let first = heard_until(&mut listener, Duration::from_secs(30), |request| {
            matches!(request, FrontendRequest::Enumerate())
        })
        .await;
        let _ = was_heard.send(());
        first
    };
    let (_, first) = tokio::join!(frontend, daemon);
    relay.abort();
    let recorded = sent.lock().expect("the record").clone();

    let mut replay = dial(&daemon_endpoint).await;
    replay
        .write_all(&recorded)
        .await
        .expect("the replay is written");
    let second = heard(&mut listener, Duration::from_secs(3)).await;
    drop(replay);
    drop(listener);

    assert!(
        matches!(first.as_slice(), [FrontendRequest::Enumerate()]),
        "the frontend's own request through a transparent relay was not heard: \
         {first:?}"
    );
    assert!(
        second.is_empty(),
        "the {} bytes a frontend sent on one connection, replayed on another, \
         were honoured as {second:?}. Anything that saw one connection could \
         drive the daemon.",
        recorded.len()
    );
}
