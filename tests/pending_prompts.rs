//! What the daemon does with a pairing request it admitted: which address the
//! prompt names (#83), whether the knock is logged (#114), whether a frontend
//! that attaches afterwards is shown it (#114), and which machine an approval
//! then trusts (#168).
//!
//! Runs the built binary with dummy capture and emulation, discovery off, a
//! free port, and every path it could touch in a scratch directory. Each
//! stranger is a QUIC client with a certificate the daemon has never seen. The
//! frontends are the real IPC connector.
//!
//! Runs in its own test binary, so pointing `HOME` and the XDG directories at
//! the scratch directory cannot disturb anything else.
#![cfg(unix)]

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use hops_ipc::{AsyncFrontendEventReader, AttemptOrigin, FrontendEvent, FrontendRequest};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};

struct Daemon {
    child: Child,
    dir: PathBuf,
    log: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Daemon {
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

fn start() -> (Daemon, u16) {
    // Short, for `sun_path` (about 104 bytes on macOS).
    let dir = PathBuf::from(format!("/tmp/h-pend-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let config_dir = dir.join(".config/lan-mouse");
    std::fs::create_dir_all(&config_dir).expect("a scratch config directory");
    std::fs::create_dir_all(dir.join("Library/Caches")).expect("scratch caches");
    // SAFETY: the only test in this binary, and it sets these before it starts
    // anything that reads the environment. The frontend connector finds the
    // daemon's socket and token through them.
    unsafe {
        std::env::set_var("HOME", &dir);
        std::env::set_var("XDG_RUNTIME_DIR", &dir);
        std::env::set_var("XDG_CONFIG_HOME", dir.join(".config"));
    }
    let port = UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .expect("a free port")
        .port();
    let config = config_dir.join("config.toml");
    std::fs::write(
        &config,
        format!(
            "port = {port}\ncapture_backend = \"dummy\"\nemulation_backend = \"dummy\"\ndiscovery = false\n"
        ),
    )
    .expect("a config");
    let log = dir.join("daemon.log");
    let child = Command::new(env!("CARGO_BIN_EXE_hops"))
        .arg("--config")
        .arg(&config)
        .arg("--cert-path")
        .arg(config_dir.join("lan-mouse.pem"))
        .arg("daemon")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", &dir)
        .env("XDG_RUNTIME_DIR", &dir)
        .env("XDG_CONFIG_HOME", dir.join(".config"))
        .env("XDG_STATE_HOME", &dir)
        .env("HOPS_LOG_FILE", &log)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the hops binary starts");
    let daemon = Daemon { child, dir, log };
    let deadline = Instant::now() + Duration::from_secs(60);
    while !daemon.log().contains("service running; stops on") {
        assert!(
            Instant::now() < deadline,
            "the daemon never reported its service loop running; log:\n{}",
            daemon.log()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    (daemon, port)
}

/// Accepts any server certificate: the stranger does not care who answers.
#[derive(Debug)]
struct AnyServer;

impl ServerCertVerifier for AnyServer {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A machine the daemon has never seen: its certificate's fingerprint, in the
/// daemon's format, and the address it dials from.
struct Stranger {
    fingerprint: String,
    from: SocketAddr,
    endpoint: quinn::Endpoint,
    config: quinn::ClientConfig,
}

fn stranger() -> Stranger {
    let key = rcgen::KeyPair::generate().expect("keypair");
    let cert = rcgen::CertificateParams::new(vec!["grabbr".to_owned()])
        .expect("params")
        .self_signed(&key)
        .expect("self signed");
    let fingerprint = Sha256::digest(cert.der())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyServer))
        .with_client_auth_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::try_from(key.serialize_der()).expect("key der"),
        )
        .expect("client auth");
    crypto.alpn_protocols = vec![b"grabbr-hop/1".to_vec()];
    let config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("quic client"),
    ));
    let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("addr")).expect("endpoint");
    let from = endpoint.local_addr().expect("the stranger's address");
    Stranger {
        fingerprint,
        from,
        endpoint,
        config,
    }
}

impl Stranger {
    /// Dial the daemon once. It refuses the handshake; what matters is what it
    /// does with the attempt.
    async fn knock(&self, port: u16) {
        let at: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
        if let Ok(connecting) = self
            .endpoint
            .connect_with(self.config.clone(), at, "grabbr")
        {
            if let Ok(Ok(conn)) = tokio::time::timeout(Duration::from_secs(5), connecting).await {
                let _ = tokio::time::timeout(Duration::from_secs(2), conn.closed()).await;
            }
        }
    }
}

/// Every event a frontend receives within `within`.
async fn events_for(events: &mut AsyncFrontendEventReader, within: Duration) -> Vec<FrontendEvent> {
    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + within;
    while let Ok(Some(event)) = tokio::time::timeout_at(deadline, events.next()).await {
        if let Ok(event) = event {
            seen.push(event);
        }
    }
    seen
}

/// The pairing prompts among `events`: fingerprint, origin, address.
fn prompts(events: &[FrontendEvent]) -> Vec<(String, AttemptOrigin, Option<SocketAddr>)> {
    events
        .iter()
        .filter_map(|e| match e {
            FrontendEvent::ConnectionAttempt {
                fingerprint,
                origin,
                addr,
            } => Some((fingerprint.clone(), *origin, *addr)),
            _ => None,
        })
        .collect()
}

// LEDGER T2 T3 T4 T5 T6 | class B | 2 bytes (IPC events) + 5 process log line: the hops daemon binary
#[tokio::test(flavor = "current_thread")]
async fn an_admitted_pairing_request_names_its_address_is_logged_and_survives_a_new_frontend() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (daemon, port) = start();
    let (mut first, mut requests) = hops_ipc::connect_async(Some(Duration::from_secs(10)))
        .await
        .expect("a frontend connects");
    // Every property is checked and reported together, so one run says which
    // of them hold rather than stopping at the first.
    let mut failures: Vec<String> = Vec::new();

    // Refused: add device is not open yet.
    let refused = stranger();
    refused.knock(port).await;
    let _ = events_for(&mut first, Duration::from_secs(2)).await;

    requests
        .request(FrontendRequest::OpenPairing)
        .await
        .expect("request sent");
    let laptop = stranger();
    laptop.knock(port).await;
    let seen = prompts(&events_for(&mut first, Duration::from_secs(4)).await);

    // T2: the prompt names the address the knock came from (#83).
    if seen
        != vec![(
            laptop.fingerprint.clone(),
            AttemptOrigin::Inbound,
            Some(laptop.from),
        )]
    {
        failures.push(format!(
            "T2: the prompt for a knock from {} ({}) arrived as {seen:?}; it must carry that \
             fingerprint and that address",
            laptop.from, laptop.fingerprint
        ));
    }

    // T3: the admitted knock is in the log with its fingerprint and address (#114).
    let log = daemon.log();
    let logged = log
        .lines()
        .any(|l| l.contains(&laptop.fingerprint) && l.contains(&laptop.from.to_string()));
    if !logged {
        failures.push(format!(
            "T3: no log line names the admitted knock's fingerprint {} and address {}",
            laptop.fingerprint, laptop.from
        ));
    }

    // T4 and T5: a frontend that attaches now is shown the admitted request, and
    // never the refused one (#114, #209).
    let (mut second, mut second_requests) = hops_ipc::connect_async(Some(Duration::from_secs(10)))
        .await
        .expect("a second frontend connects");
    second_requests
        .request(FrontendRequest::Sync)
        .await
        .expect("sync sent");
    let replayed = prompts(&events_for(&mut second, Duration::from_secs(3)).await);
    if !replayed.iter().any(|(fp, origin, addr)| {
        fp == &laptop.fingerprint && *origin == AttemptOrigin::Inbound && *addr == Some(laptop.from)
    }) {
        failures.push(format!(
            "T4: a frontend attaching after the knock was not shown it; it received {replayed:?}"
        ));
    }
    if replayed.iter().any(|(fp, ..)| fp == &refused.fingerprint) {
        failures.push(format!(
            "T5: a knock refused while add device was closed was shown to the new \
             frontend: {replayed:?}"
        ));
    }

    // T6: another machine knocks before the approval lands. The approval names
    // the first; only the first is trusted (#168).
    let other = stranger();
    other.knock(port).await;
    let _ = events_for(&mut first, Duration::from_secs(2)).await;
    requests
        .request(FrontendRequest::AuthorizeKey(
            "laptop".to_owned(),
            laptop.fingerprint.clone(),
        ))
        .await
        .expect("approval sent");
    let trusted: Option<HashMap<String, String>> = events_for(&mut first, Duration::from_secs(3))
        .await
        .into_iter()
        .filter_map(|e| match e {
            FrontendEvent::AuthorizedUpdated(map) => Some(map),
            _ => None,
        })
        .next_back();
    match trusted {
        Some(map)
            if map.get(&laptop.fingerprint).map(String::as_str) == Some("laptop")
                && !map.contains_key(&other.fingerprint) => {}
        other_state => failures.push(format!(
            "T6: approving {} as \"laptop\" left the trusted set as {other_state:?}",
            laptop.fingerprint
        )),
    }

    assert!(
        failures.is_empty(),
        "{} propert(ies) failed:\n{}\nlog:\n{}",
        failures.len(),
        failures.join("\n"),
        daemon.log()
    );
}
