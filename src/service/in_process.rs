//! The whole daemon in this process, reached the way a frontend and a peer
//! reach it, for a test about what either can make it do.
//!
//! Every file is in a scratch directory, its QUIC listener is on loopback (a
//! test build binds 127.0.0.1), capture is the dummy backend, emulation is the
//! backend the test hands it, and discovery is off. A frontend is a real
//! connection to its IPC socket, token and all; a peer is a real dialer from
//! `crate::test_harness`. Nothing here reads or writes the real config, token
//! or trust files.

use super::Service;
use crate::test_harness::{Machine, dialer};
use crate::transport::Trust;
use crate::trust::{Caps, TrustStore};
use hops_ipc::{AsyncFrontendListener, DaemonEndpoint, FrontendEvent, FrontendRequest, Position};
use hops_proto::ProtoEvent;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

/// What must happen is waited for this long at most.
pub(crate) const DEADLINE: Duration = Duration::from_secs(30);

/// A daemon whose loop is not running yet.
pub(crate) struct Daemon {
    service: Service,
    scratch: Scratch,
    port: u16,
}

/// The scratch directory, removed with it.
struct Scratch {
    dir: PathBuf,
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Daemon {
    /// A daemon whose config also holds `tables`, injecting into `emulation`.
    pub(crate) async fn start(
        tag: &str,
        tables: &str,
        emulation: input_emulation::Backend,
    ) -> Self {
        // Short, for a socket path in it (`sun_path`).
        let dir = PathBuf::from(format!("/tmp/h-ip-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .and_then(|s| s.local_addr())
            .expect("a free port")
            .port();
        let config = dir.join("config.toml");
        std::fs::write(
            &config,
            format!(
                "port = {port}\ncapture_backend = \"dummy\"\nemulation_backend = \"dummy\"\n\
                 discovery = false\n\n{tables}"
            ),
        )
        .expect("a config");
        let endpoint = DaemonEndpoint::Unix(dir.join("s.sock"));
        let frontends =
            AsyncFrontendListener::at_with_token_file(&endpoint, &dir.join("ipc-token"))
                .await
                .expect("the scratch endpoint");
        let config = crate::config::Config::in_scratch(&config, &dir.join("hops.pem"))
            .expect("the scratch config");
        let service = Service::with_backends(
            config,
            frontends,
            Some(input_capture::Backend::Dummy),
            Some(emulation),
        )
        .await
        .expect("a daemon in the scratch directory");
        Self {
            service,
            scratch: Scratch { dir },
            port,
        }
    }

    /// This machine's fingerprint.
    pub(crate) fn fingerprint(&self) -> String {
        self.service.public_key_fingerprint.clone()
    }

    /// The daemon's own trust store: what its doors wrote, read directly.
    pub(crate) fn trust(&self) -> Trust {
        self.service.trust.clone()
    }

    /// The port its listener is on, on loopback.
    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    /// The clock its pairing window is timed by, to move on while it runs.
    pub(crate) fn pairing_clock(&self) -> PairingClock {
        PairingClock(self.service.pairing_skew.clone())
    }

    /// Where a frontend reaches it.
    pub(crate) fn ipc(&self) -> Ipc {
        Ipc {
            dir: self.scratch.dir.clone(),
        }
    }

    /// Run the daemon's loop until `body` ends, then stop its tasks.
    pub(crate) async fn run_while<T>(mut self, body: impl std::future::Future<Output = T>) -> T {
        let out = tokio::select! {
            ended = self.service.run() => {
                panic!("the daemon's loop ended while the test ran: {ended:?}")
            }
            out = body => out,
        };
        self.service.capture.terminate().await;
        self.service.emulation.terminate().await;
        self.service.resolver.terminate().await;
        out
    }
}

/// The clock a daemon's pairing window is timed by.
#[derive(Clone)]
pub(crate) struct PairingClock(Arc<std::sync::atomic::AtomicU64>);

impl PairingClock {
    /// Move it on by `by`, as if that much time had passed.
    pub(crate) fn advance(&self, by: Duration) {
        let ms = u64::try_from(by.as_millis()).expect("a short step");
        self.0.fetch_add(ms, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Where a frontend connects.
#[derive(Clone)]
pub(crate) struct Ipc {
    dir: PathBuf,
}

impl Ipc {
    /// A frontend on the daemon's socket, past the two-way proof.
    pub(crate) async fn connect(&self) -> Frontend {
        let token = std::fs::read_to_string(self.dir.join("ipc-token")).expect("the token");
        let stream = tokio::net::UnixStream::connect(self.dir.join("s.sock"))
            .await
            .expect("the daemon's socket");
        let (rx, mut tx) = stream.into_split();
        let mut rx = BufReader::new(rx);
        hops_ipc::prove_to_daemon(&mut rx, &mut tx, token.trim())
            .await
            .expect("the two-way proof is made");
        Frontend {
            lines: rx.lines(),
            tx,
            barrier: 0,
        }
    }
}

/// A frontend connected to the daemon.
pub(crate) struct Frontend {
    lines: tokio::io::Lines<BufReader<OwnedReadHalf>>,
    tx: OwnedWriteHalf,
    barrier: u64,
}

impl Frontend {
    /// Send `requests` and return every event the daemon sent until it had
    /// handled them all: they are followed by a barrier, answered once every
    /// request before it was handled and every event it caused was sent.
    pub(crate) async fn exchange(&mut self, requests: &[FrontendRequest]) -> Vec<FrontendEvent> {
        self.barrier += 1;
        let n = self.barrier;
        for request in requests.iter().chain([&FrontendRequest::Barrier(n)]) {
            let mut line = serde_json::to_string(request).expect("a request serialises");
            line.push('\n');
            self.tx
                .write_all(line.as_bytes())
                .await
                .expect("the request is sent");
        }
        let deadline = tokio::time::Instant::now() + DEADLINE;
        let mut events = Vec::new();
        loop {
            let line = tokio::time::timeout_at(deadline, self.lines.next_line())
                .await
                .unwrap_or_else(|_| {
                    panic!("the daemon never answered barrier {n}; it sent {events:?}")
                })
                .expect("the socket reads")
                .unwrap_or_else(|| panic!("the daemon hung up before answering barrier {n}"));
            match serde_json::from_str::<FrontendEvent>(&line) {
                Ok(FrontendEvent::Barrier(m)) if m == n => return events,
                Ok(event) => events.push(event),
                Err(_) => {}
            }
        }
    }
}

/// A store for `me` that may drive the daemon, as a peer's would be.
pub(crate) fn trusting(me: &Machine, daemon: &str) -> Trust {
    let mut store = TrustStore::new(&me.fingerprint, 0).expect("our fingerprint");
    store
        .issue_confirmed(daemon, "the daemon", Caps::OUTBOUND)
        .expect("issue");
    Arc::new(RwLock::new(store))
}

/// Ask until the daemon has admitted `stranger`'s knock as a prompt.
pub(crate) async fn prompt_from(app: &mut Frontend, stranger: &Machine, port: u16, daemon: &str) {
    let knocker = dialer(stranger, trusting(stranger, daemon), port, Position::Left);
    let deadline = tokio::time::Instant::now() + DEADLINE;
    loop {
        let _ = knocker.conn.send(ProtoEvent::Ping, knocker.handle).await;
        let events = app.exchange(&[]).await;
        let prompted = events.iter().any(|e| {
            matches!(e, FrontendEvent::ConnectionAttempt { fingerprint, .. }
                if *fingerprint == stranger.fingerprint)
        });
        if prompted {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "a machine knocking while add device was open raised no prompt"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A pairing the daemon approved, part way (#167): the machine it approved
/// dialled again, both arrived at a number, and the daemon put its three
/// choices in front of the app. That machine has already sent its
/// confirmation, which the daemon reads only once the app picks the number.
pub(crate) struct Comparing {
    /// The number both machines arrived at.
    pub(crate) number: String,
    // Held so the connection stays up while the test runs.
    _conn: quinn::Connection,
    _send: quinn::SendStream,
    _endpoint: quinn::Endpoint,
}

/// Dial the daemon as `stranger` does once its knock was approved there, and
/// compare the number: the machine that knocked is the one adding, so it
/// shows the number, and the daemon asks the app which of three it is.
pub(crate) async fn compare_number(
    app: &mut Frontend,
    stranger: &Machine,
    port: u16,
    daemon: &str,
) -> Comparing {
    crate::transport::install_crypto_provider();
    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("loopback")).expect("an endpoint");
    endpoint.set_default_client_config(crate::test_harness::raw_client_config(
        stranger,
        trusting(stranger, daemon),
        1 << 20,
    ));
    let at = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let conn = tokio::time::timeout(DEADLINE, endpoint.connect(at, "grabbr").expect("a dial"))
        .await
        .expect("the daemon answers in time")
        .expect("the daemon admits a machine it approved, to compare a number");
    let number = crate::pair_ceremony::as_initiator(&conn, &stranger.fingerprint, daemon)
        .await
        .expect("the two machines compare a number");

    let deadline = tokio::time::Instant::now() + DEADLINE;
    loop {
        let events = app.exchange(&[]).await;
        let offered = events.iter().find_map(|e| match e {
            FrontendEvent::PairingCheck {
                fingerprint,
                check: hops_ipc::PairingCheck::Pick(choices),
                ..
            } if *fingerprint == stranger.fingerprint => Some(choices.clone()),
            _ => None,
        });
        if let Some(choices) = offered {
            assert!(
                choices.contains(&number),
                "the daemon offered {choices:?}, and not the number both machines \
                 arrived at, {number}"
            );
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the daemon never asked the app which number the other machine shows"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // The machine that knocked confirms: its first frame, on its input stream.
    let mut send = conn.open_uni().await.expect("an input stream");
    crate::transport::write_frame(
        &mut send,
        ProtoEvent::Hello {
            commit: crate::config::local_commit(),
        },
    )
    .await
    .expect("its confirmation is sent");
    Comparing {
        number,
        _conn: conn,
        _send: send,
        _endpoint: endpoint,
    }
}

/// Wait until the daemon's store holds a pairing for `fp`.
pub(crate) async fn until_paired(trust: &Trust, fp: &str) {
    crate::test_harness::wait_until("the pairing is confirmed", DEADLINE, || {
        !trust.read().expect("lock").capabilities(fp).is_empty()
    })
    .await;
}
